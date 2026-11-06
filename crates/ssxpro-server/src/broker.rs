//! Privileged session broker. It is forked before worker threads exist and is
//! deliberately separate from the seccomp-restricted TLS monitor: creating a
//! login shell requires fork/exec and therefore must not inherit the monitor's
//! syscall allowlist.

use crate::ipc::{
    verify_session_token, ChannelEvent, ReceivedMessage, SessionChannel, VerifiedSession,
};
use crate::session::{signal_to_libc, spawn_login_session, SpawnedSession};
use ssxpro_io::RuntimeRing;
use ssxpro_proto::{
    decode_broker_request, encode_broker_exit, encode_broker_open_result, BrokerRequest,
    BrokerStatus, MAX_BROKER_FRAME,
};
use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const BROKER_POLL_INTERVAL: Duration = Duration::from_millis(50);
const CLOSE_GRACE: Duration = Duration::from_millis(150);
const BROKER_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const MAX_USED_TOKENS: usize = 8192;

static BROKER_SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn request_broker_shutdown(_: libc::c_int) {
    BROKER_SHUTDOWN.store(true, Ordering::Relaxed);
}

pub struct SessionBrokerProcess {
    pid: libc::pid_t,
}

impl Drop for SessionBrokerProcess {
    fn drop(&mut self) {
        // The broker installs its own SIGTERM handler, so this requests its
        // teardown path (kill session groups and reap them) instead of leaving
        // orphaned descendants behind. Fall back to SIGKILL if it wedges.
        // SAFETY: pid is the broker child created by start_session_broker.
        unsafe {
            libc::kill(self.pid, libc::SIGTERM);
        }
        let deadline = Instant::now() + BROKER_SHUTDOWN_GRACE;
        let mut status = 0;
        loop {
            // SAFETY: pid is our child and status is writable.
            let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if result == self.pid {
                return;
            }
            if result < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: the broker did not exit within the grace period and is still
        // our unreaped child.
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
        }
        loop {
            // SAFETY: pid is our child and status is writable.
            let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if result == self.pid {
                break;
            }
            if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
    }
}

struct BrokerSession {
    worker_index: usize,
    process: SpawnedSession,
    closing_at: Option<Instant>,
}

pub fn start_session_broker(
    secret: [u8; 32],
    worker_count: usize,
) -> io::Result<(SessionBrokerProcess, Vec<SessionChannel>)> {
    let mut secret = Zeroizing::new(secret);
    let mut broker_channels = Vec::with_capacity(worker_count);
    let mut worker_channels = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let (broker, worker) = SessionChannel::pair()?;
        broker_channels.push(broker);
        worker_channels.push(worker);
    }
    let parent_pid = unsafe { libc::getpid() };
    // SAFETY: this fork happens before any worker thread is created. The child
    // immediately narrows its descriptor set and enters the broker loop.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        drop(worker_channels);
        BROKER_SHUTDOWN.store(false, Ordering::Relaxed);
        if install_shutdown_handler().is_err() {
            // SAFETY: _exit is async-signal-safe and skips inherited destructors.
            unsafe { libc::_exit(1) }
        }
        // SAFETY: scalar prctl arguments; the parent check closes the race.
        let setup_ok = unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) == 0
                && libc::getppid() == parent_pid
        };
        if !setup_ok {
            // SAFETY: _exit is async-signal-safe and skips inherited destructors.
            unsafe { libc::_exit(1) }
        }
        let keep = broker_channels
            .iter()
            .map(SessionChannel::as_raw_fd)
            .collect::<Vec<_>>();
        if let Err(error) = close_inherited_fds(&keep) {
            eprintln!("ssxd: session broker could not close inherited descriptors: {error}");
            // SAFETY: forked child must not run inherited destructors.
            unsafe { libc::_exit(1) }
        }
        let result = run_broker(*secret, broker_channels);
        if let Err(error) = &result {
            eprintln!("ssxd: session broker failed: {error}");
        }
        // SAFETY: the broker is a forked helper and must not run inherited destructors.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) }
    }
    secret.zeroize();
    drop(broker_channels);
    Ok((SessionBrokerProcess { pid }, worker_channels))
}

fn close_inherited_fds(keep: &[RawFd]) -> io::Result<()> {
    let mut fds = Vec::new();
    match std::fs::read_dir("/proc/self/fd") {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(fd) = name.parse::<RawFd>() {
                        fds.push(fd);
                    }
                }
            }
        }
        Err(_) => fds.extend(3..1024),
    }
    for fd in fds {
        if fd > 2 && !keep.contains(&fd) {
            // SAFETY: fd was inherited from the parent and is not one of the
            // broker's control channels.
            unsafe {
                libc::close(fd);
            }
        }
    }
    Ok(())
}

fn install_shutdown_handler() -> io::Result<()> {
    // SAFETY: the handler only performs a lock-free atomic store, which is safe
    // to run from a signal handler.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = request_broker_shutdown as *const () as usize;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn run_broker(
    secret: [u8; 32],
    channels: Vec<SessionChannel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let secret = Zeroizing::new(secret);
    let mut ring = RuntimeRing::new(64, false, [1, 1])?;
    let mut channels = channels.into_iter().map(Some).collect::<Vec<_>>();
    let mut sessions: HashMap<u64, BrokerSession> = HashMap::new();
    let mut used_tokens: HashMap<[u8; ssxpro_proto::SESSION_TOKEN_NONCE_LEN], u64> = HashMap::new();
    let mut next_session_id: u64 = 1;
    let mut buffer = [0u8; MAX_BROKER_FRAME];
    loop {
        if BROKER_SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }
        let mut did_work = false;
        for (index, slot) in channels.iter_mut().enumerate() {
            let mut closed = false;
            while let Some(channel) = slot.as_ref() {
                match channel.recv(&mut buffer)? {
                    ChannelEvent::Empty => break,
                    ChannelEvent::Closed => {
                        closed = true;
                        break;
                    }
                    ChannelEvent::Message(message) => {
                        did_work = true;
                        handle_message(
                            index,
                            channel,
                            message,
                            &secret,
                            &mut sessions,
                            &mut used_tokens,
                            &mut next_session_id,
                        )?;
                    }
                }
            }
            if closed {
                let closed_sessions = sessions
                    .iter()
                    .filter(|(_, session)| session.worker_index == index)
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>();
                let mut removed = Vec::with_capacity(closed_sessions.len());
                for session_id in closed_sessions {
                    if let Some(session) = sessions.remove(&session_id) {
                        removed.push(session);
                    }
                }
                // No worker remains to consume a graceful exit, so kill every
                // group before dropping any session and waiting on its leader.
                for session in &removed {
                    let _ = session.process.kill_group();
                }
                drop(removed);
                *slot = None;
                did_work = true;
            }
        }

        let now = Instant::now();
        let mut exited = Vec::new();
        for (session_id, session) in &mut sessions {
            match session.process.try_wait_status() {
                Ok(Some((kind, value))) => {
                    // The leader is reaped. Kill any remaining members of its
                    // process group so they cannot keep the PTY or outlive the
                    // session after the worker releases the master descriptor.
                    let _ = session.process.kill_group();
                    if let Some(channel) = channels[session.worker_index].as_ref() {
                        let mut frame = [0u8; MAX_BROKER_FRAME];
                        let length = encode_broker_exit(*session_id, kind, value, &mut frame)?;
                        // A closed worker means nobody will consume the status;
                        // the session is reaped and dropped either way.
                        let _ = channel.send(&frame[..length], &[]);
                    }
                    exited.push(*session_id);
                    did_work = true;
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!("ssxd: session broker waitid failed: {error}");
                    exited.push(*session_id);
                    did_work = true;
                }
            }
        }
        for session_id in exited {
            sessions.remove(&session_id);
        }

        let now_secs = unix_now().unwrap_or(0);
        used_tokens.retain(|_, expires_at| *expires_at >= now_secs);
        for session in sessions.values_mut() {
            if session.closing_at.is_some_and(|deadline| now >= deadline) {
                let _ = session.process.signal_group(libc::SIGKILL);
                session.closing_at = None;
                did_work = true;
            }
        }

        if channels.iter().all(Option::is_none) {
            break;
        }
        if !did_work {
            match ring.wait_timeout(BROKER_POLL_INTERVAL) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(Box::new(error)),
            }
        }
    }
    for session in sessions.values() {
        let _ = session.process.kill_group();
    }
    drop(sessions);
    Ok(())
}

fn handle_message(
    worker_index: usize,
    channel: &SessionChannel,
    message: ReceivedMessage,
    secret: &[u8; 32],
    sessions: &mut HashMap<u64, BrokerSession>,
    used_tokens: &mut HashMap<[u8; ssxpro_proto::SESSION_TOKEN_NONCE_LEN], u64>,
    next_session_id: &mut u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Workers never send descriptors. Closing them here also makes a
    // compromised worker unable to leak an inherited descriptor through us.
    if !message.fds.is_empty() {
        return Err("worker sent unexpected SCM_RIGHTS descriptors".into());
    }
    let request = decode_broker_request(&message.data)?;
    match request {
        BrokerRequest::OpenSession {
            request_id,
            token,
            term,
            rows,
            cols,
        } => {
            let Some(verified) = verify_session_token(secret, token) else {
                send_open_result(channel, request_id, BrokerStatus::Denied, 0)?;
                return Ok(());
            };
            if used_tokens.contains_key(&verified.nonce) || used_tokens.len() >= MAX_USED_TOKENS {
                send_open_result(channel, request_id, BrokerStatus::Denied, 0)?;
                return Ok(());
            }
            used_tokens.insert(verified.nonce, verified.expires_at);
            match spawn_session(verified, term, rows, cols) {
                Ok(mut process) => {
                    let session_id = *next_session_id;
                    *next_session_id = (*next_session_id).wrapping_add(1).max(1);
                    let Some(master) = process.take_master() else {
                        send_open_result(channel, request_id, BrokerStatus::InternalError, 0)?;
                        return Ok(());
                    };
                    let result = send_open_result_with_fd(
                        channel,
                        request_id,
                        session_id,
                        master.as_raw_fd(),
                    );
                    if result.is_err() {
                        let _ = process.signal_group(libc::SIGKILL);
                        return Ok(());
                    }
                    sessions.insert(
                        session_id,
                        BrokerSession {
                            worker_index,
                            process,
                            closing_at: None,
                        },
                    );
                }
                Err(_) => {
                    send_open_result(channel, request_id, BrokerStatus::InternalError, 0)?;
                }
            }
        }
        BrokerRequest::SignalSession { session_id, signal } => {
            if let Some(session) = sessions.get(&session_id) {
                if session.worker_index == worker_index {
                    let _ = session.process.signal_group(signal_to_libc(signal));
                }
            }
        }
        BrokerRequest::CloseSession { session_id } => {
            if let Some(session) = sessions.get_mut(&session_id) {
                if session.worker_index == worker_index && session.closing_at.is_none() {
                    let _ = session.process.signal_group(libc::SIGHUP);
                    session.closing_at = Some(Instant::now() + CLOSE_GRACE);
                }
            }
        }
    }
    Ok(())
}

fn spawn_session(
    verified: VerifiedSession,
    term: &str,
    rows: u16,
    cols: u16,
) -> Result<SpawnedSession, crate::session::SessionError> {
    spawn_login_session(&verified.identity, term, rows, cols)
}

fn send_open_result(
    channel: &SessionChannel,
    request_id: u32,
    status: BrokerStatus,
    session_id: u64,
) -> io::Result<()> {
    let mut frame = [0u8; MAX_BROKER_FRAME];
    let length = encode_broker_open_result(request_id, status, session_id, &mut frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid broker response"))?;
    channel.send(&frame[..length], &[])
}

fn send_open_result_with_fd(
    channel: &SessionChannel,
    request_id: u32,
    session_id: u64,
    master_fd: RawFd,
) -> io::Result<()> {
    let mut frame = [0u8; MAX_BROKER_FRAME];
    let length = encode_broker_open_result(request_id, BrokerStatus::Ok, session_id, &mut frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid broker response"))?;
    channel.send(&frame[..length], &[master_fd])
}

fn unix_now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}
