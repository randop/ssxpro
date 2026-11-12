use boring::hash::hmac_sha256;
use ssxpro_compression::{Decoder as CompressionDecoder, Encoder as CompressionEncoder};
use ssxpro_crypto::{constant_time_eq, getrandom, sha256};
use ssxpro_io::{RuntimeRing, UdpEndpoint};
use ssxpro_proto::{
    decode_broker_response, encode, encode_broker_close_request, encode_broker_open_request,
    encode_broker_signal_request, BrokerResponse, BrokerStatus, Compression, FrameDecoder, Message,
    ServerState, MAX_BROKER_FRAME, MAX_WIRE_FRAME, PROTOCOL_VERSION, SUPPORTED_FEATURES,
};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

macro_rules! debug1 {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose >= 1 {
            eprintln!("debug1: {}", format_args!($($arg)*));
        }
    };
}

macro_rules! debug2 {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose >= 2 {
            eprintln!("debug2: {}", format_args!($($arg)*));
        }
    };
}

macro_rules! debug3 {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose >= 3 {
            eprintln!("debug3: {}", format_args!($($arg)*));
        }
    };
}

struct PeerSession {
    conn: quiche::Connection,
    peer_ip: IpAddr,
    state: ServerState,
    decoder: FrameDecoder,
    compression: Compression,
    compression_encoder: Option<CompressionEncoder>,
    compression_decoder: Option<CompressionDecoder>,
    server_nonce: Option<[u8; 32]>,
    authenticated: bool,
    send_failed: bool,
    pending_auth: Option<Receiver<std::io::Result<Option<crate::tls::AuthorizedLogin>>>>,
    identity: Option<crate::session::LoginIdentity>,
    session_token: Option<Vec<u8>>,
    session_request_id: Option<u32>,
    pty: Option<crate::session::PtySession>,
    pty_output: Option<Receiver<Result<Vec<u8>, String>>>,
    stream4_opened: bool,
    pty_pending: VecDeque<Vec<u8>>,
    pty_pending_bytes: usize,
    pty_input: VecDeque<u8>,
    input_fin: bool,
    pty_fin: bool,
    exit_observed_at: Option<Instant>,
    max_rows: u16,
    max_columns: u16,
    created_at: std::time::Instant,
    last_activity_at: std::time::Instant,
    hello_at: Option<std::time::Instant>,
    hello_grace: Duration,
    auth_timeout: Duration,
    login_grace: Duration,
}

type PtyReader = (
    Receiver<Result<Vec<u8>, String>>,
    std::thread::JoinHandle<()>,
);

struct WorkerContext {
    worker_id: usize,
    connection_limit: usize,
    session_limit: usize,
    endpoint: UdpEndpoint,
    tls_identity: crate::tls::TlsIdentity,
    tls_signer: crate::tls::IpcSigner,
    retry_secret: [u8; 32],
    initial_rate_limiter: Arc<Mutex<InitialRateLimiter>>,
    auth_failure_limiter: Arc<Mutex<AuthFailureLimiter>>,
    session_channel: crate::ipc::SessionChannel,
    verbose: u8,
}

enum WorkerEvent {
    Ready(usize),
    Failed(String),
}

struct InitialRateLimiter {
    sources: HashMap<IpAddr, (Instant, u16)>,
}

struct AuthFailureLimiter {
    sources: HashMap<IpAddr, (Instant, u8)>,
}

impl AuthFailureLimiter {
    const WINDOW: Duration = Duration::from_secs(60);
    const MAX_FAILURES: u8 = 5;
    const MAX_SOURCES: usize = 4096;

    fn new() -> Self {
        Self {
            sources: HashMap::new(),
        }
    }

    fn allow(&mut self, source: IpAddr) -> bool {
        let now = Instant::now();
        self.sources
            .retain(|_, (started, _)| now.duration_since(*started) < Self::WINDOW);
        match self.sources.get(&source) {
            Some((_, failures)) => *failures < Self::MAX_FAILURES,
            None => self.sources.len() < Self::MAX_SOURCES,
        }
    }

    fn record_failure(&mut self, source: IpAddr) {
        let now = Instant::now();
        self.sources
            .retain(|_, (started, _)| now.duration_since(*started) < Self::WINDOW);
        let entry = self.sources.entry(source).or_insert((now, 0));
        entry.1 = entry.1.saturating_add(1);
    }
}

impl InitialRateLimiter {
    fn new() -> Self {
        Self {
            sources: HashMap::new(),
        }
    }

    fn allow(&mut self, source: IpAddr) -> bool {
        let now = Instant::now();
        self.sources
            .retain(|_, (started, _)| now.duration_since(*started) < Duration::from_secs(10));
        let Some((started, count)) = self.sources.get_mut(&source) else {
            if self.sources.len() >= 4096 {
                if let Some(oldest) = self
                    .sources
                    .iter()
                    .min_by_key(|(_, (at, _))| *at)
                    .map(|(ip, _)| *ip)
                {
                    self.sources.remove(&oldest);
                }
            }
            self.sources.insert(source, (now, 1));
            return true;
        };
        if now.duration_since(*started) >= Duration::from_secs(10) {
            *started = now;
            *count = 1;
            return true;
        }
        if *count >= 20 {
            return false;
        }
        *count += 1;
        true
    }
}

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_shutdown(_: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

pub fn serve(
    config: &ssxpro_config::ServerConfig,
    verbose: u8,
    skip_permission_checks: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    debug1!(verbose, "ssxd starting on {}", config.listen);
    debug2!(
        verbose,
        "workers={} max_connections={} max_sessions={}",
        config.workers,
        config.quic.max_connections,
        config.session.max_sessions
    );
    // SAFETY: the handler only performs a lock-free atomic store.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = request_shutdown as *const () as usize;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0
        {
            return Err(Box::new(std::io::Error::last_os_error()));
        }
        let mut ignore_pipe: libc::sigaction = std::mem::zeroed();
        ignore_pipe.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut ignore_pipe.sa_mask);
        if libc::sigaction(libc::SIGPIPE, &ignore_pipe, std::ptr::null_mut()) != 0 {
            return Err(Box::new(std::io::Error::last_os_error()));
        }
    }
    let worker_count = config
        .workers
        .min(config.quic.max_connections as usize)
        .min(config.session.max_sessions as usize);
    let mut token_secret = Zeroizing::new([0u8; 32]);
    getrandom(&mut *token_secret)?;
    let (tls_identity, tls_signer, tls_monitor) =
        start_tls_monitor(config, *token_secret, skip_permission_checks)?;
    let (_session_broker, session_channels) =
        crate::broker::start_session_broker(*token_secret, worker_count)?;
    token_secret.zeroize();
    let mut retry_secret = Zeroizing::new([0u8; 32]);
    getrandom(&mut *retry_secret)?;
    let stop = Arc::new(AtomicBool::new(false));
    let initial_rate_limiter = Arc::new(Mutex::new(InitialRateLimiter::new()));
    let auth_failure_limiter = Arc::new(Mutex::new(AuthFailureLimiter::new()));
    let mut listen = config.listen.parse::<SocketAddr>()?;
    let mut endpoints = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let endpoint = UdpEndpoint::bind(listen, worker_count > 1)?;
        endpoint.set_receive_timeout(Duration::from_millis(100))?;
        if config.io.gro {
            endpoint.enable_gro()?;
        }
        if listen.port() == 0 && endpoints.is_empty() {
            listen = endpoint.local_addr()?;
        }
        endpoints.push(endpoint);
    }
    let _reuseport_selector = ssxpro_io::UdpEndpoint::attach_reuseport_cid_selector(
        &endpoints.iter().collect::<Vec<_>>(),
    )?;
    let (sender, receiver) = mpsc::channel::<WorkerEvent>();
    let result = std::thread::scope(|scope| {
        for (worker_id, (endpoint, session_channel)) in
            endpoints.into_iter().zip(session_channels).enumerate()
        {
            let stop = Arc::clone(&stop);
            let sender = sender.clone();
            let connection_limit = distributed_limit(
                config.quic.max_connections as usize,
                worker_count,
                worker_id,
            );
            let session_limit = distributed_limit(
                config.session.max_sessions as usize,
                worker_count,
                worker_id,
            );
            let tls_identity = tls_identity.clone();
            let tls_signer = tls_signer.clone();
            let retry_secret = *retry_secret;
            let initial_rate_limiter = Arc::clone(&initial_rate_limiter);
            let auth_failure_limiter = Arc::clone(&auth_failure_limiter);
            scope.spawn(move || {
                let result = std::panic::catch_unwind(|| {
                    serve_worker(
                        config,
                        WorkerContext {
                            worker_id,
                            connection_limit,
                            session_limit,
                            endpoint,
                            tls_identity,
                            tls_signer,
                            retry_secret,
                            initial_rate_limiter,
                            auth_failure_limiter,
                            session_channel,
                            verbose,
                        },
                        &stop,
                        &sender,
                    )
                });
                if result
                    .as_ref()
                    .is_ok_and(|worker_result| worker_result.is_ok())
                    && stop.load(Ordering::Acquire)
                {
                    return;
                }
                let message = match result {
                    Ok(Ok(())) => format!("worker {worker_id} stopped unexpectedly"),
                    Ok(Err(error)) => format!("worker {worker_id}: {error}"),
                    Err(_) => format!("worker {worker_id} panicked"),
                };
                stop.store(true, Ordering::Release);
                let _ = sender.send(WorkerEvent::Failed(message));
            });
        }
        drop(sender);
        let mut ready_workers = 0;
        let mut failure = None;
        while ready_workers < worker_count {
            match receiver.recv() {
                Ok(WorkerEvent::Ready(worker_id)) => {
                    eprintln!("ssxd: worker {worker_id} ready");
                    ready_workers += 1;
                }
                Ok(WorkerEvent::Failed(message)) => {
                    failure = Some(message);
                    break;
                }
                Err(_) => {
                    failure = Some("workers exited before becoming ready".to_owned());
                    break;
                }
            }
        }
        if failure.is_none() {
            if let Err(error) = notify_systemd("READY=1") {
                failure = Some(format!("systemd readiness notification failed: {error}"));
            }
        }
        if failure.is_some() {
            stop.store(true, Ordering::Release);
        } else {
            loop {
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(WorkerEvent::Failed(message)) => {
                        failure = Some(message);
                        stop.store(true, Ordering::Release);
                        break;
                    }
                    Ok(WorkerEvent::Ready(_)) => {}
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        }
        let _ = notify_systemd("STOPPING=1");
        stop.store(true, Ordering::Release);
        failure.map_or(Ok(()), |message| Err(std::io::Error::other(message)))
    })
    .map_err(|error| Box::new(error) as Box<dyn std::error::Error>);
    drop(tls_signer);
    drop(tls_monitor);
    result
}

struct TlsMonitorProcess {
    pid: libc::pid_t,
    control: UnixStream,
}

impl Drop for TlsMonitorProcess {
    fn drop(&mut self) {
        let _ = self.control.shutdown(Shutdown::Both);
        let mut status = 0;
        loop {
            // SAFETY: pid is the child process created by start_tls_monitor.
            let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if result == self.pid {
                break;
            }
            if result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            break;
        }
    }
}

fn start_tls_monitor(
    config: &ssxpro_config::ServerConfig,
    token_secret: [u8; 32],
    skip_permission_checks: bool,
) -> Result<
    (
        crate::tls::TlsIdentity,
        crate::tls::IpcSigner,
        TlsMonitorProcess,
    ),
    Box<dyn std::error::Error>,
> {
    let mut token_secret = Zeroizing::new(token_secret);
    let authorized_keys_name = config
        .auth
        .authorized_keys
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or("auth.authorized_keys must name a UTF-8 basename")?
        .to_owned();
    if config.auth.authorized_keys.components().count() != 1
        || config.auth.authorized_keys.as_os_str() != authorized_keys_name.as_str()
    {
        return Err("auth.authorized_keys must be a basename inside ~/.ssx".into());
    }
    let mut seed =
        Zeroizing::new(crate::read_host_key_seed(&config.host_key).map_err(std::io::Error::other)?);
    let (mut worker_stream, monitor_stream) = UnixStream::pair()?;
    let (worker_auth, monitor_auth) = UnixStream::pair()?;
    // SAFETY: ssxd starts this monitor before creating worker threads, so fork
    // cannot inherit locked Rust or BoringSSL runtime state.
    let parent_pid = unsafe { libc::getpid() };
    // SAFETY: fork has no pointer arguments; both socket endpoints are owned.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }
    if pid == 0 {
        drop(worker_stream);
        drop(worker_auth);
        // SAFETY: scalar prctl arguments; the parent check closes the race before
        // the monitor blocks on its signing socket.
        let setup_ok = unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) == 0
                && libc::getppid() == parent_pid
        };
        if !setup_ok {
            // SAFETY: _exit is async-signal-safe and avoids running inherited destructors.
            unsafe { libc::_exit(1) }
        }
        let settings = crate::tls::AuthSettings {
            allow_root: config.auth.allow_root,
            server_authorized_keys: config.auth.server_authorized_keys.clone(),
            authorized_keys_name,
            allow_insecure_permissions: skip_permission_checks,
        };
        let result = crate::tls::serve_signing_requests(
            monitor_stream,
            monitor_auth,
            seed,
            settings,
            *token_secret,
        );
        // SAFETY: the forked monitor must not run inherited process destructors.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) }
    }
    token_secret.zeroize();
    drop(monitor_stream);
    drop(monitor_auth);
    seed.zeroize();
    let control = match worker_stream.try_clone() {
        Ok(control) => control,
        Err(error) => {
            drop(worker_stream);
            let mut status = 0;
            // SAFETY: pid is the monitor child created above.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            return Err(Box::new(error));
        }
    };
    let monitor = TlsMonitorProcess { pid, control };
    let identity = match crate::tls::read_signing_identity(&mut worker_stream) {
        Ok(identity) => identity,
        Err(error) => {
            drop(worker_stream);
            drop(monitor);
            return Err(error);
        }
    };
    Ok((
        identity,
        crate::tls::IpcSigner::new(worker_stream, worker_auth),
        monitor,
    ))
}

fn serve_worker(
    config: &ssxpro_config::ServerConfig,
    context: WorkerContext,
    stop: &AtomicBool,
    events: &mpsc::Sender<WorkerEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let WorkerContext {
        worker_id,
        connection_limit,
        session_limit,
        mut endpoint,
        tls_identity,
        tls_signer,
        retry_secret,
        initial_rate_limiter,
        auth_failure_limiter,
        session_channel,
        verbose,
    } = context;
    let retry_secret = Zeroizing::new(retry_secret);
    // Set no_new_privs and disable dumpability for each worker thread before
    // packet processing starts. The monitor was forked before workers exist,
    // so these process attributes cannot weaken or alter the privileged monitor.
    ssxpro_io::harden_worker_process()?;
    if config.io.pin_cpus {
        pin_worker(worker_id)?;
    }
    debug1!(verbose, "worker {worker_id} starting (connection_limit={connection_limit}, session_limit={session_limit})");
    // Cap the registered fixed-file table to the process file-descriptor limit.
    // `IORING_REGISTER_FILES2` (sparse) still bounds the table size by
    // `RLIMIT_NOFILE`, so requesting more slots than the limit allows fails with
    // `EMFILE` on hosts with a low default `ulimit -n` (e.g. 1024). Session PTY
    // master descriptors are registered lazily, so a smaller pre-allocated table
    // only reduces the maximum concurrent sessions, never leaks descriptors.
    let fixed_file_slots = safe_fixed_file_slots(session_limit);
    let mut ring = RuntimeRing::new_with_files(
        config.io.ring_entries,
        config.io.restrict_ring,
        [4, 4],
        fixed_file_slots,
    )?;
    let (mut tls, spki_der) = crate::tls::server_config_with_signer(
        &tls_identity,
        tls_signer.clone(),
        u64::from(config.quic.idle_timeout_secs) * 1000,
    )?;
    let (auth_sender, auth_receiver) = mpsc::sync_channel::<AuthJob>(8);
    let authorizer = tls_signer.clone();
    std::thread::Builder::new()
        .name("ssxd-authorize".to_owned())
        .spawn(move || {
            while let Ok(job) = auth_receiver.recv() {
                let result = authorizer.authorize(
                    &job.user,
                    &job.public_key,
                    &job.server_nonce,
                    &job.client_nonce,
                    &job.spki_hash,
                    &job.signature,
                );
                let _ = job.response.send(result);
            }
        })?;
    let spki_hash = sha256(&spki_der)?;
    let configured_compression = match config.compression {
        ssxpro_config::CompressionMode::Off => Compression::Off,
        ssxpro_config::CompressionMode::Fast => Compression::Fast,
        ssxpro_config::CompressionMode::Standard => Compression::Standard,
        ssxpro_config::CompressionMode::High => Compression::High,
    };
    debug1!(
        verbose,
        "worker {worker_id} compression mode: {configured_compression:?}"
    );
    let local = endpoint.local_addr()?;
    let mut sessions: HashMap<Vec<u8>, PeerSession> = HashMap::new();
    let mut connection_ids: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut pending_sessions: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut next_request_id: u32 = 1;
    let mut packet = [0u8; 65536];
    let mut output = [0u8; 65536];
    events
        .send(WorkerEvent::Ready(worker_id))
        .map_err(|_| "server coordinator exited before worker readiness")?;
    let mut draining = false;
    let mut drain_deadline = None;
    // Server-side keepalive ("TCPKeepAlive yes" analogue): send an
    // ack-eliciting PING when a session has been completely quiet for the
    // configured interval. 0 disables it.
    let keep_alive_interval = Duration::from_secs(u64::from(config.quic.keep_alive_interval_secs));
    loop {
        for peer in sessions.values_mut() {
            if let Err(error) = complete_authorization(peer, &auth_failure_limiter) {
                eprintln!("ssxd: authorization failed: {error}");
                let _ = peer.conn.close(true, 2, b"authentication failed");
            }
        }
        poll_broker(
            &session_channel,
            &mut ring,
            &mut sessions,
            &mut pending_sessions,
            verbose,
        )?;
        let shutdown_requested =
            stop.load(Ordering::Acquire) || SHUTDOWN_REQUESTED.load(Ordering::Relaxed);
        if shutdown_requested && !draining {
            draining = true;
            drain_deadline = Some(Instant::now() + Duration::from_secs(5));
            eprintln!("ssxd: worker {worker_id} draining active sessions");
            for peer_session in sessions
                .values_mut()
                .filter(|session| session.pty.is_none())
            {
                let _ = peer_session.conn.close(true, 0, b"server shutdown");
                let _ = flush_quic(peer_session, &endpoint, &mut ring, &mut output, verbose);
            }
        }
        if draining && sessions.is_empty() {
            break;
        }
        if drain_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            for peer_session in sessions.values_mut() {
                if !peer_session.conn.is_closed() {
                    let _ = peer_session.conn.close(true, 0, b"server shutdown");
                    let _ = flush_quic(peer_session, &endpoint, &mut ring, &mut output, verbose);
                }
                close_peer_session(
                    peer_session,
                    &mut ring,
                    &session_channel,
                    &mut pending_sessions,
                );
            }
            break;
        }
        // A bounded batch of one datagram prevents busy peers starving timers.
        maintain_sessions(
            &mut sessions,
            &mut connection_ids,
            &mut pending_sessions,
            &mut ring,
            &endpoint,
            &mut output,
            &session_channel,
            keep_alive_interval,
            verbose,
        )?;
        let receive_timeout = sessions
            .values()
            .filter_map(|peer| peer.conn.timeout())
            .min()
            .unwrap_or(Duration::from_millis(100))
            .min(Duration::from_millis(100));
        endpoint.set_receive_timeout(receive_timeout)?;
        match endpoint.recv_from(&mut ring, &mut packet) {
            Ok((length, peer)) => {
                debug3!(
                    verbose,
                    "server recv_from Ok {} bytes from {}",
                    length,
                    peer.ip()
                );
                let header = match quiche::Header::from_slice(
                    &mut packet[..length],
                    quiche::MAX_CONN_ID_LEN,
                ) {
                    Ok(header) => header,
                    Err(_) => continue,
                };
                // Short-header (1-RTT) packets report version 0 in quiche's
                // parsed Header; only actual Version Negotiation is dropped.
                if header.ty == quiche::Type::VersionNegotiation {
                    continue;
                }
                let datagram_dcid = header.dcid.clone();
                let mut connection_key = connection_ids.get(datagram_dcid.as_ref()).cloned();
                let is_new_connection = connection_key.is_none();
                if connection_key.is_none() {
                    if draining
                        || header.ty != quiche::Type::Initial
                        || sessions.len() >= connection_limit
                    {
                        continue;
                    }
                    if config.quic.retry {
                        let token = header.token.as_deref().unwrap_or_default();
                        if token.is_empty() {
                            if !initial_rate_limiter
                                .lock()
                                .map_err(|_| "initial rate limiter lock poisoned")?
                                .allow(peer.ip())
                            {
                                continue;
                            }

                            let token = mint_retry_token(&retry_secret, &peer, &datagram_dcid)?;
                            debug2!(verbose, "sent QUIC retry to {} (new connection)", peer.ip());
                            let mut retry_scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
                            getrandom(&mut retry_scid_bytes)?;
                            retry_scid_bytes[0] = worker_id as u8;
                            let retry_scid = quiche::ConnectionId::from_ref(&retry_scid_bytes);
                            let retry_length = quiche::retry(
                                &header.scid,
                                &header.dcid,
                                &retry_scid,
                                &token,
                                header.version,
                                &mut output,
                            )?;
                            drop(header);
                            if let Err(error) =
                                endpoint.send_to(&mut ring, &output[..retry_length], peer)
                            {
                                if !peer_send_error(&error) {
                                    return Err(error.into());
                                }
                            }
                            continue;
                        }
                        if validate_retry_token(&retry_secret, &peer, token).is_none() {
                            continue;
                        }
                    }
                    if !config.quic.retry
                        && !initial_rate_limiter
                            .lock()
                            .map_err(|_| "initial rate limiter lock poisoned")?
                            .allow(peer.ip())
                    {
                        continue;
                    }
                    let original_dcid = if config.quic.retry {
                        validate_retry_token(
                            &retry_secret,
                            &peer,
                            header.token.as_deref().unwrap_or_default(),
                        )
                    } else {
                        None
                    };
                    drop(header);
                    let accepted = match original_dcid {
                        Some(original) => {
                            let original = quiche::ConnectionId::from_ref(&original);
                            let retry_source = datagram_dcid.clone();
                            let retry_ids = quiche::RetryConnectionIds {
                                original_destination_cid: &original,
                                retry_source_cid: &retry_source,
                            };
                            quiche::accept_with_retry(
                                &retry_source,
                                retry_ids,
                                local,
                                peer,
                                &mut tls,
                            )
                        }
                        None => {
                            let mut server_scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
                            getrandom(&mut server_scid_bytes)?;
                            server_scid_bytes[0] = worker_id as u8;
                            let server_scid = quiche::ConnectionId::from_ref(&server_scid_bytes);
                            quiche::accept(&server_scid, None, local, peer, &mut tls)
                        }
                    };
                    let conn = match accepted {
                        Ok(conn) => conn,
                        Err(_) => continue,
                    };
                    let key = conn.source_id().as_ref().to_vec();
                    connection_ids.insert(datagram_dcid.as_ref().to_vec(), key.clone());
                    for source_id in conn.source_ids() {
                        connection_ids.insert(source_id.as_ref().to_vec(), key.clone());
                    }
                    sessions.insert(
                        key.clone(),
                        PeerSession {
                            conn,
                            state: ServerState::Start,
                            peer_ip: peer.ip(),
                            decoder: FrameDecoder::new(),
                            compression: Compression::Off,
                            compression_encoder: None,
                            compression_decoder: None,
                            server_nonce: None,
                            authenticated: false,
                            pending_auth: None,
                            send_failed: false,
                            identity: None,
                            session_token: None,
                            session_request_id: None,
                            pty: None,
                            stream4_opened: false,
                            pty_output: None,
                            pty_pending: VecDeque::new(),
                            pty_pending_bytes: 0,
                            pty_input: VecDeque::new(),
                            input_fin: false,
                            pty_fin: false,
                            exit_observed_at: None,
                            max_rows: config.session.max_rows,
                            max_columns: config.session.max_columns,
                            created_at: std::time::Instant::now(),
                            last_activity_at: std::time::Instant::now(),
                            hello_at: None,
                            hello_grace: Duration::from_secs(u64::from(
                                config.proto.hello_grace_secs,
                            )),
                            auth_timeout: Duration::from_secs(u64::from(
                                config.proto.auth_timeout_secs,
                            )),
                            login_grace: Duration::from_secs(u64::from(
                                config.session.login_grace_secs,
                            )),
                        },
                    );
                    connection_key = Some(key.clone());
                    let key_hex = short_hex(&key);
                    debug1!(
                        verbose,
                        "new QUIC connection from {} (session {})",
                        peer.ip(),
                        key_hex
                    );
                    // quiche::accept() already consumed this Initial packet.
                    // conn.recv() is skipped below for new connections to avoid
                    // reprocessing it (which causes TlsFail). flush_quic() will
                    // emit the server's first flight (ServerHello, etc.).
                }
                let Some(connection_key) = connection_key else {
                    continue;
                };
                let active_sessions = sessions
                    .values()
                    .filter(|session| session.pty.is_some() || session.session_request_id.is_some())
                    .count();
                let Some(peer_session) = sessions.get_mut(&connection_key) else {
                    continue;
                };
                // A datagram from the peer is activity; QUIC keepalives are
                // only sent while a session is completely quiet.
                peer_session.last_activity_at = Instant::now();
                // Feed each received datagram to QUIC exactly once.
                match peer_session.conn.recv(
                    &mut packet[..length],
                    quiche::RecvInfo {
                        from: peer,
                        to: local,
                    },
                ) {
                    Ok(n) => debug3!(
                        verbose,
                        "server recv processed {n} bytes, established={}",
                        peer_session.conn.is_established()
                    ),
                    Err(e) if is_new_connection => {
                        debug3!(verbose, "server recv after accept (expected): {e}");
                    }
                    Err(e) => debug3!(verbose, "server recv error: {e}"),
                }
                let peer_work = (|| -> Result<(), Box<dyn std::error::Error>> {
                    if peer_session.conn.is_established() {
                        process_control(
                            peer_session,
                            &spki_hash,
                            active_sessions,
                            session_limit,
                            configured_compression,
                            &auth_sender,
                            &auth_failure_limiter,
                            &connection_key,
                            &session_channel,
                            &mut pending_sessions,
                            &mut next_request_id,
                            verbose,
                        )?;
                        process_data(peer_session, &mut ring)?;
                    }
                    pump_pty(peer_session)?;
                    Ok(())
                })();
                if let Err(error) = peer_work {
                    eprintln!("ssxd: closing invalid session: {error}");
                    let _ = peer_session
                        .conn
                        .close(true, 1, b"protocol or session error");
                }
                flush_quic(peer_session, &endpoint, &mut ring, &mut output, verbose)?;
                if peer_session.conn.is_closed() || peer_session.send_failed {
                    close_peer_session(
                        peer_session,
                        &mut ring,
                        &session_channel,
                        &mut pending_sessions,
                    );
                    sessions.remove(&connection_key);
                    connection_ids.retain(|_, owner| owner != &connection_key);
                } else {
                    for source_id in peer_session.conn.source_ids() {
                        connection_ids.insert(source_id.as_ref().to_vec(), connection_key.clone());
                    }
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                debug3!(verbose, "server recv_from WouldBlock/TimedOut");
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::Interrupted
                    && SHUTDOWN_REQUESTED.load(Ordering::Relaxed) =>
            {
                continue;
            }
            Err(error) => return Err(Box::new(error)),
        }
    }
    stop.store(true, Ordering::Release);
    eprintln!("ssxd: worker {worker_id} stopping");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn maintain_sessions(
    sessions: &mut HashMap<Vec<u8>, PeerSession>,
    connection_ids: &mut HashMap<Vec<u8>, Vec<u8>>,
    pending_sessions: &mut HashMap<u32, Vec<u8>>,
    ring: &mut RuntimeRing,
    endpoint: &UdpEndpoint,
    output: &mut [u8],
    session_channel: &crate::ipc::SessionChannel,
    keep_alive_interval: Duration,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut closed = Vec::new();
    for (connection_key, peer_session) in sessions.iter_mut() {
        let now = std::time::Instant::now();
        let expired = match peer_session.state {
            ServerState::Start => {
                now.duration_since(peer_session.created_at) >= peer_session.hello_grace
            }
            ServerState::AwaitAuth | ServerState::AuthPending => peer_session
                .hello_at
                .is_some_and(|at| now.duration_since(at) >= peer_session.auth_timeout),
            ServerState::AwaitOpen => peer_session.hello_at.is_some_and(|at| {
                now.duration_since(at) >= peer_session.login_grace + peer_session.auth_timeout
            }),
            ServerState::Running | ServerState::Closed => false,
        };
        if expired {
            let _ = peer_session.conn.close(true, 3, b"login timeout");
        }
        if peer_session
            .conn
            .timeout()
            .is_some_and(|timeout| timeout.is_zero())
        {
            peer_session.conn.on_timeout();
        }
        if !keep_alive_interval.is_zero()
            && peer_session.conn.is_established()
            && !peer_session.conn.is_closed()
            && peer_session.last_activity_at.elapsed() >= keep_alive_interval
        {
            let _ = peer_session.conn.send_ack_eliciting();
            peer_session.last_activity_at = now;
        }
        if let Err(error) = process_data(peer_session, ring).and_then(|_| pump_pty(peer_session)) {
            eprintln!("ssxd: closing failed PTY session: {error}");
            let _ = peer_session.conn.close(true, 2, b"session failure");
        }
        flush_quic(peer_session, endpoint, ring, output, verbose)?;
        if peer_session.conn.is_closed() || peer_session.send_failed {
            close_peer_session(peer_session, ring, session_channel, pending_sessions);
            closed.push(connection_key.clone());
        } else {
            for source_id in peer_session.conn.source_ids() {
                connection_ids.insert(source_id.as_ref().to_vec(), connection_key.clone());
            }
        }
    }
    for connection_key in closed {
        sessions.remove(&connection_key);
        connection_ids.retain(|_, owner| owner != &connection_key);
    }
    Ok(())
}

fn pin_worker(worker_id: usize) -> std::io::Result<()> {
    // SAFETY: affinity calls use initialized cpu_set_t values and the current thread ID (0).
    unsafe {
        let mut available: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of_val(&available), &mut available) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let cpus = (0..libc::CPU_SETSIZE as usize)
            .filter(|cpu| libc::CPU_ISSET(*cpu, &available))
            .collect::<Vec<_>>();
        if cpus.is_empty() {
            return Err(std::io::Error::other("process has no allowed CPUs"));
        }
        let cpu = cpus[worker_id % cpus.len()];
        let mut selected: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut selected);
        libc::CPU_SET(cpu, &mut selected);
        if libc::sched_setaffinity(0, std::mem::size_of_val(&selected), &selected) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn notify_systemd(state: &str) -> std::io::Result<()> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let path = path.as_os_str().as_bytes();
    let abstract_socket = path.first() == Some(&b'@');
    let path_offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    // SAFETY: socket has scalar arguments and returns a new owned descriptor.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_len = if abstract_socket {
        path.len()
    } else {
        path.len().saturating_add(1)
    };
    if path_len == 0 || path_len > address.sun_path.len() {
        unsafe { libc::close(fd) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET path exceeds sockaddr_un capacity",
        ));
    }
    // SAFETY: sun_path is a fixed byte array with path_len validated above.
    let socket_path = unsafe {
        std::slice::from_raw_parts_mut(address.sun_path.as_mut_ptr().cast::<u8>(), path_len)
    };
    if abstract_socket {
        socket_path[0] = 0;
        socket_path[1..].copy_from_slice(&path[1..]);
    } else {
        socket_path[..path.len()].copy_from_slice(path);
        socket_path[path.len()] = 0;
    }
    let address_len = (path_offset + path_len) as libc::socklen_t;
    let bytes = state.as_bytes();
    // SAFETY: fd and address are valid; bytes is readable for its exact length.
    let sent = unsafe {
        libc::sendto(
            fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::MSG_NOSIGNAL,
            (&address as *const libc::sockaddr_un).cast(),
            address_len,
        )
    };
    let error = if sent < 0 {
        Some(std::io::Error::last_os_error())
    } else if sent as usize != bytes.len() {
        Some(std::io::Error::other("short systemd notification"))
    } else {
        None
    };
    // SAFETY: fd was created above and is closed exactly once here.
    unsafe { libc::close(fd) };
    error.map_or(Ok(()), Err)
}

fn short_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn distributed_limit(total: usize, workers: usize, worker_id: usize) -> usize {
    let base = total / workers;
    base + usize::from(worker_id < total % workers)
}

/// Cap the pre-allocated fixed-file table size to the process `RLIMIT_NOFILE`.
/// `IORING_REGISTER_FILES2` (sparse registration) still bounds the table size by
/// `RLIMIT_NOFILE`, so requesting more slots than the limit allows fails with
/// `EMFILE` on hosts whose default `ulimit -n` is below `session_limit + 1`.
/// Session PTY master descriptors are registered lazily, so a smaller table only
/// reduces the maximum concurrent sessions rather than leaking descriptors.
fn safe_fixed_file_slots(session_limit: usize) -> u32 {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let limit = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } == 0 {
        rlim.rlim_cur as usize
    } else {
        session_limit.saturating_add(1)
    };
    const RESERVED: usize = 16;
    let slots = limit.saturating_sub(RESERVED).max(1);
    let requested = session_limit.saturating_add(1);
    u32::try_from(requested.min(slots)).unwrap_or(u32::MAX)
}

#[allow(clippy::too_many_arguments)]
fn process_control(
    peer: &mut PeerSession,
    spki_hash: &[u8; 32],
    active_sessions: usize,
    session_limit: usize,
    configured_compression: Compression,
    auth_sender: &mpsc::SyncSender<AuthJob>,
    auth_failures: &Mutex<AuthFailureLimiter>,
    connection_key: &[u8],
    session_channel: &crate::ipc::SessionChannel,
    pending_sessions: &mut HashMap<u32, Vec<u8>>,
    next_request_id: &mut u32,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = [0u8; MAX_WIRE_FRAME];
    while let Ok((length, _fin)) = peer.conn.stream_recv(0, &mut input) {
        if length == 0 {
            break;
        }
        if peer.decoder.feed(&input[..length]) != length {
            return Err("control stream frame buffer exceeded".into());
        }
        while let Some(message) = peer.decoder.decode_next()? {
            peer.state.accept(&message)?;
            match message {
                Message::Hello {
                    version: PROTOCOL_VERSION,
                    features,
                } => {
                    let selected = negotiate_compression(configured_compression, features)?;
                    peer.compression = selected;
                    if selected == Compression::Off {
                        peer.compression_encoder = None;
                        peer.compression_decoder = None;
                    } else {
                        peer.compression_encoder = Some(CompressionEncoder::new(selected)?);
                        peer.compression_decoder = Some(CompressionDecoder::new(selected)?);
                    }
                    peer.hello_at = Some(std::time::Instant::now());
                    debug1!(
                        verbose,
                        "received Hello from {} (session {}, compression={selected:?})",
                        peer.peer_ip,
                        short_hex(connection_key)
                    );
                    let mut nonce = [0; 32];
                    getrandom(&mut nonce)?;
                    peer.server_nonce = Some(nonce);
                    let response = Message::Challenge {
                        server_nonce: nonce,
                        compression: selected,
                    };
                    send_control(&mut peer.conn, &response)?;
                    peer.state.sent(&response)?;
                    debug2!(
                        verbose,
                        "sent Challenge to {} (session {})",
                        peer.peer_ip,
                        short_hex(connection_key)
                    );
                }
                Message::AuthRequest {
                    user,
                    user_len,
                    public_key,
                    client_nonce,
                    signature,
                } => {
                    let name = std::str::from_utf8(&user[..usize::from(user_len)])?;
                    debug1!(
                        verbose,
                        "received AuthRequest from {} for user={name} (session {})",
                        peer.peer_ip,
                        short_hex(connection_key)
                    );
                    if !auth_failures
                        .lock()
                        .map_err(|_| "auth failure limiter lock poisoned")?
                        .allow(peer.peer_ip)
                    {
                        return Err("authentication rate limit exceeded".into());
                    }
                    let nonce = peer
                        .server_nonce
                        .take()
                        .ok_or("missing or replayed server challenge")?;
                    let (sender, receiver) = mpsc::sync_channel(1);
                    auth_sender
                        .try_send(AuthJob {
                            user: name.to_owned(),
                            public_key,
                            server_nonce: nonce,
                            client_nonce,
                            spki_hash: *spki_hash,
                            signature,
                            response: sender,
                        })
                        .map_err(|_| "authorization queue is full")?;
                    peer.pending_auth = Some(receiver);
                }
                Message::OpenShell {
                    term,
                    term_len,
                    rows,
                    cols,
                } if peer.authenticated => {
                    let name = peer
                        .identity
                        .as_ref()
                        .map(|i| i.name.as_str())
                        .unwrap_or("?");
                    debug1!(
                        verbose,
                        "received OpenShell from user={name} from {} (session {})",
                        peer.peer_ip,
                        short_hex(connection_key)
                    );
                    if peer.pty.is_some() || peer.session_request_id.is_some() {
                        return Err("shell session is already open".into());
                    }
                    if active_sessions >= session_limit {
                        return Err("server session limit reached".into());
                    }
                    if rows > peer.max_rows || cols > peer.max_columns {
                        return Err("requested terminal dimensions exceed server policy".into());
                    }
                    if peer.identity.is_none() {
                        return Err("authenticated identity is missing".into());
                    }
                    let term = std::str::from_utf8(&term[..usize::from(term_len)])?;
                    let token = Zeroizing::new(
                        peer.session_token
                            .take()
                            .ok_or("authenticated session token is missing")?,
                    );
                    let request_id = allocate_request_id(next_request_id, pending_sessions);
                    let mut frame = [0u8; MAX_BROKER_FRAME];
                    let length = encode_broker_open_request(
                        request_id,
                        token.as_slice(),
                        term,
                        rows,
                        cols,
                        &mut frame,
                    )?;
                    session_channel.send(&frame[..length], &[])?;
                    peer.session_request_id = Some(request_id);
                    pending_sessions.insert(request_id, connection_key.to_vec());
                }
                Message::Resize { rows, cols } if peer.authenticated => {
                    if rows > peer.max_rows || cols > peer.max_columns {
                        return Err("requested terminal dimensions exceed server policy".into());
                    }
                    if let Some(session) = &peer.pty {
                        session.resize(rows, cols)?;
                    }
                }
                Message::Signal { signal } if peer.authenticated => {
                    if let Some(session) = &peer.pty {
                        let mut frame = [0u8; MAX_BROKER_FRAME];
                        let length =
                            encode_broker_signal_request(session.session_id(), signal, &mut frame)?;
                        session_channel.send(&frame[..length], &[])?;
                    }
                }
                Message::Close { .. } => {
                    debug1!(
                        verbose,
                        "received Close from {} (session {})",
                        peer.peer_ip,
                        short_hex(connection_key)
                    );
                    peer.conn.close(true, 0, b"closed")?;
                }
                _ => return Err("protocol message is invalid in this session state".into()),
            }
        }
    }
    Ok(())
}

fn negotiate_compression(
    configured: Compression,
    client_features: u32,
) -> Result<Compression, Box<dyn std::error::Error>> {
    if client_features & !SUPPORTED_FEATURES != 0 {
        return Err("Hello advertises unknown feature bits".into());
    }
    if configured.is_supported_by(client_features) {
        Ok(configured)
    } else {
        Err(format!("client does not support server-required compression {configured:?}").into())
    }
}

fn allocate_request_id(next_request_id: &mut u32, pending_sessions: &HashMap<u32, Vec<u8>>) -> u32 {
    let mut request_id = (*next_request_id).max(1);
    while pending_sessions.contains_key(&request_id) {
        request_id = request_id.wrapping_add(1).max(1);
    }
    *next_request_id = request_id.wrapping_add(1).max(1);
    request_id
}

fn request_session_close(channel: &crate::ipc::SessionChannel, session_id: u64) {
    let mut frame = [0u8; MAX_BROKER_FRAME];
    if let Ok(length) = encode_broker_close_request(session_id, &mut frame) {
        let _ = channel.send(&frame[..length], &[]);
    }
}

fn poll_broker(
    channel: &crate::ipc::SessionChannel,
    ring: &mut RuntimeRing,
    sessions: &mut HashMap<Vec<u8>, PeerSession>,
    pending_sessions: &mut HashMap<u32, Vec<u8>>,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = [0u8; MAX_BROKER_FRAME];
    loop {
        match channel.recv(&mut buffer)? {
            crate::ipc::ChannelEvent::Empty => return Ok(()),
            crate::ipc::ChannelEvent::Closed => {
                return Err("session broker closed the worker channel".into())
            }
            crate::ipc::ChannelEvent::Message(message) => {
                match decode_broker_response(&message.data)? {
                    BrokerResponse::OpenResult {
                        request_id,
                        status,
                        session_id,
                    } => {
                        let connection_key = pending_sessions.remove(&request_id);
                        if status != BrokerStatus::Ok {
                            debug1!(
                                verbose,
                                "session open rejected by broker for request {request_id}"
                            );
                            if !message.fds.is_empty() {
                                return Err(
                                    "session broker sent descriptors for a failed open".into()
                                );
                            }
                            if let Some(peer) = connection_key
                                .as_ref()
                                .and_then(|key| sessions.get_mut(key))
                            {
                                if peer.session_request_id == Some(request_id) {
                                    peer.session_request_id = None;
                                    let _ = peer.conn.close(true, 1, b"session open failed");
                                }
                            }
                            continue;
                        }
                        debug1!(
                            verbose,
                            "session {session_id} opened for request {request_id}"
                        );
                        let Some(connection_key) = connection_key else {
                            request_session_close(channel, session_id);
                            continue;
                        };
                        if session_id == 0 || message.fds.len() != 1 {
                            request_session_close(channel, session_id);
                            return Err("session broker sent an invalid open result".into());
                        }
                        let Some(peer) = sessions.get_mut(&connection_key) else {
                            request_session_close(channel, session_id);
                            continue;
                        };
                        if peer.session_request_id != Some(request_id) {
                            request_session_close(channel, session_id);
                            continue;
                        }
                        peer.session_request_id = None;
                        let master = message.fds.into_iter().next().expect("one descriptor");
                        let session = crate::session::PtySession::from_broker(master, session_id);
                        if let Err(error) = ring.register_fd(session.master_fd()) {
                            request_session_close(channel, session_id);
                            let _ = peer.conn.close(true, 2, b"PTY registration failure");
                            eprintln!("ssxd: could not register PTY descriptor: {error}");
                            continue;
                        }
                        match pty_reader(session.master_fd()) {
                            Ok((receiver, worker)) => {
                                drop(worker); // Detaches the read pump; channel closure ends it.
                                peer.pty = Some(session);
                                peer.pty_output = Some(receiver);
                            }
                            Err(error) => {
                                let _ = ring.unregister_fd(session.master_fd());
                                request_session_close(channel, session_id);
                                let _ = peer.conn.close(true, 2, b"PTY reader failure");
                                eprintln!("ssxd: could not start PTY reader: {error}");
                                continue;
                            }
                        }
                    }
                    BrokerResponse::Exit {
                        session_id,
                        kind,
                        value,
                    } => {
                        debug1!(
                            verbose,
                            "session {session_id} exited (kind={kind:?}, value={value})"
                        );
                        if !message.fds.is_empty() {
                            return Err("session broker sent unexpected descriptors".into());
                        }
                        if let Some(peer) = sessions.values_mut().find(|peer| {
                            peer.pty
                                .as_ref()
                                .is_some_and(|pty| pty.session_id() == session_id)
                        }) {
                            if let Some(pty) = &mut peer.pty {
                                pty.set_exit(kind, value);
                            }
                            peer.exit_observed_at.get_or_insert_with(Instant::now);
                        }
                    }
                }
            }
        }
    }
}

fn close_peer_session(
    peer: &mut PeerSession,
    ring: &mut RuntimeRing,
    channel: &crate::ipc::SessionChannel,
    pending_sessions: &mut HashMap<u32, Vec<u8>>,
) {
    if let Some(request_id) = peer.session_request_id.take() {
        pending_sessions.remove(&request_id);
    }
    if let Some(pty) = peer.pty.take() {
        let _ = ring.unregister_fd(pty.master_fd());
        request_session_close(channel, pty.session_id());
    }
    peer.pty_output = None;
    peer.pty_pending.clear();
    peer.pty_pending_bytes = 0;
    peer.pty_fin = false;
    peer.input_fin = false;
    peer.exit_observed_at = None;
    if let Some(mut token) = peer.session_token.take() {
        token.zeroize();
    }
}

fn process_data(
    peer: &mut PeerSession,
    _ring: &mut RuntimeRing,
) -> Result<(), Box<dyn std::error::Error>> {
    if !peer.authenticated || peer.state != ServerState::Running || peer.pty.is_none() {
        return Ok(());
    }
    drain_pty_input(peer)?;
    if !decode_pty_input(peer, &[])? {
        return Ok(());
    }
    if peer.input_fin {
        finish_pty_input(peer)?;
        return Ok(());
    }
    let mut input = [0u8; 16 * 1024];
    for stream in peer.conn.readable().collect::<Vec<_>>() {
        if stream != 4 {
            continue;
        }
        loop {
            // Reserve one byte for the terminal EOF character on FIN.
            let capacity = (256 * 1024usize)
                .saturating_sub(peer.pty_input.len() + 1)
                .min(input.len());
            if capacity == 0 {
                break;
            }
            let (length, fin) = match peer.conn.stream_recv(stream, &mut input[..capacity]) {
                Ok(value) => value,
                Err(quiche::Error::Done) => break,
                Err(error) => return Err(error.into()),
            };
            if length == 0 && !fin {
                break;
            }
            let mut data: &[u8] = &input[..length];
            if !peer.stream4_opened {
                // The client opens the data stream with a single 0x00 marker
                // so the server can send PTY output before the user types.
                let Some((&marker, rest)) = data.split_first() else {
                    return Err("stream 4 FIN before the open marker".into());
                };
                if marker != 0x00 {
                    return Err("stream 4 open marker must be 0x00".into());
                }
                peer.stream4_opened = true;
                data = rest;
            }
            peer.input_fin = fin;
            if !decode_pty_input(peer, data)? {
                break;
            }
            if fin {
                finish_pty_input(peer)?;
                break;
            }
            drain_pty_input(peer)?;
        }
    }
    Ok(())
}

// Retry retained frames even when QUIC no longer reports stream 4 readable.
fn decode_pty_input(
    peer: &mut PeerSession,
    data: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    let capacity = (256 * 1024usize).saturating_sub(peer.pty_input.len() + 1);
    if let Some(decoder) = peer.compression_decoder.as_mut() {
        let mut decoded = Vec::new();
        let blocked = decoder.push_bounded(data, &mut decoded, capacity)?;
        peer.pty_input.extend(decoded);
        Ok(!blocked)
    } else {
        peer.pty_input.extend(data);
        Ok(true)
    }
}

fn finish_pty_input(peer: &mut PeerSession) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(decoder) = peer.compression_decoder.as_ref() {
        decoder.finish()?;
    }
    peer.input_fin = false;
    peer.pty_input.push_back(0x04);
    drain_pty_input(peer)
}

fn pty_reader(master_fd: RawFd) -> Result<PtyReader, Box<dyn std::error::Error>> {
    let mut nonblocking: libc::c_int = 1;
    // SAFETY: the PTY is open and the ioctl takes a pointer to an int.
    if unsafe { libc::ioctl(master_fd, libc::FIONBIO, &mut nonblocking) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fcntl duplicates an open PTY master into a new owned descriptor.
    let duplicate = unsafe { libc::fcntl(master_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }
    // SAFETY: fcntl returned a newly owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let (sender, receiver) = mpsc::sync_channel::<Result<Vec<u8>, String>>(8);
    let worker = std::thread::Builder::new()
        .name("ssxd-pty-pump".to_owned())
        .spawn(move || {
            let Ok(mut ring) = RuntimeRing::new(64, true, [1, 1]) else {
                let _ = sender.send(Err("could not create restricted PTY io_uring".to_owned()));
                return;
            };
            let Ok(pty_fd) = ring.register_fd(fd.as_raw_fd()) else {
                let _ = sender.send(Err("could not register PTY descriptor".to_owned()));
                return;
            };
            if let Err(error) = ssxpro_io::sandbox_worker() {
                let _ = sender.send(Err(format!("could not sandbox PTY pump: {error}")));
                return;
            }
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let entry =
                    io_uring::opcode::Read::new(pty_fd, buffer.as_mut_ptr(), buffer.len() as _)
                        .build()
                        .flags(io_uring::squeue::Flags::FIXED_FILE)
                        .user_data(1);
                match ring.submit_wait(&entry) {
                    Ok(0) => break,
                    Ok(length) => {
                        if sender.send(Ok(buffer[..length as usize].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) => {
                        let _ = sender.send(Err(error.to_string()));
                        break;
                    }
                }
            }
        })?;
    Ok((receiver, worker))
}

fn drain_pty_input(peer: &mut PeerSession) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pty) = &peer.pty else {
        return Ok(());
    };
    drain_pty_queue(pty.master_fd(), &mut peer.pty_input)
}

fn drain_pty_queue(
    fd: RawFd,
    pending: &mut VecDeque<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    while !pending.is_empty() {
        let (bytes, _) = pending.as_slices();
        // SAFETY: the descriptor is nonblocking and bytes remains live for the write.
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                break;
            }
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if written == 0 {
            return Err("PTY write returned zero bytes".into());
        }
        pending.drain(..written as usize);
    }
    Ok(())
}

fn pump_pty(peer: &mut PeerSession) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(receiver) = &peer.pty_output {
        loop {
            if peer.pty_pending_bytes >= 256 * 1024 {
                break;
            }
            match receiver.try_recv() {
                Ok(Ok(data)) => {
                    let data = if let Some(encoder) = peer.compression_encoder.as_mut() {
                        encoder.encode(&data)?
                    } else {
                        data
                    };
                    peer.pty_pending_bytes += data.len();
                    peer.pty_pending.push_back(data);
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    peer.pty_fin = true;
                    break;
                }
            }
        }
    }
    while !peer.pty_pending.is_empty() && peer.conn.stream_capacity(4).unwrap_or(0) > 0 {
        let data = peer.pty_pending.front().expect("queue is nonempty").clone();
        match peer.conn.stream_send(4, &data, false) {
            Ok(length) if length == data.len() => {
                peer.pty_pending_bytes -= length;
                peer.pty_pending.pop_front();
            }
            Ok(length) if length > 0 => {
                peer.pty_pending_bytes -= length;
                peer.pty_pending.front_mut().unwrap().drain(..length);
                break;
            }
            Ok(_) | Err(quiche::Error::Done) => break,
            Err(error) => return Err(Box::new(error)),
        }
    }
    let exit = peer.pty.as_ref().and_then(|session| session.exit_status());
    let exit_grace_expired = peer
        .exit_observed_at
        .is_some_and(|observed| observed.elapsed() >= Duration::from_secs(2));
    if let Some((kind, value)) = exit {
        if (peer.pty_fin || exit_grace_expired)
            && peer.pty_pending.is_empty()
            && !peer.conn.is_closed()
        {
            let exit = Message::Exit { kind, value };
            send_control(&mut peer.conn, &exit)?;
            peer.state.sent(&exit)?;
            peer.conn.stream_send(4, &[], true)?;
            peer.pty_fin = false;
            peer.exit_observed_at = None;
            peer.pty_output = None;
        }
    }
    Ok(())
}

fn send_control(
    conn: &mut quiche::Connection,
    message: &Message,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut frame = [0; MAX_WIRE_FRAME];
    let length = encode(message, &mut frame)?;
    conn.stream_send(0, &frame[..length], false)?;
    Ok(())
}

fn mint_retry_token(
    seed: &[u8; 32],
    peer: &SocketAddr,
    dcid: &quiche::ConnectionId,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut token = Vec::with_capacity(128);
    token.extend_from_slice(b"SSR1");
    token.extend_from_slice(&now.to_be_bytes());
    match peer.ip() {
        std::net::IpAddr::V4(address) => {
            token.push(4);
            token.extend_from_slice(&address.octets());
        }
        std::net::IpAddr::V6(address) => {
            token.push(6);
            token.extend_from_slice(&address.octets());
        }
    }
    token.extend_from_slice(&peer.port().to_be_bytes());
    token.push(dcid.len() as u8);
    token.extend_from_slice(dcid);
    let mac = hmac_sha256(seed, &token)?;
    token.extend_from_slice(&mac);
    Ok(token)
}

fn validate_retry_token(seed: &[u8; 32], peer: &SocketAddr, token: &[u8]) -> Option<Vec<u8>> {
    if token.len() < 4 + 8 + 1 + 4 + 2 + 1 + 1 + 32 || &token[..4] != b"SSR1" {
        return None;
    }
    let timestamp = u64::from_be_bytes(token[4..12].try_into().ok()?);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    if timestamp > now || now - timestamp > 10 {
        return None;
    }
    let mut cursor = 12;
    let family = *token.get(cursor)?;
    cursor += 1;
    let ip_len = match family {
        4 => 4,
        6 => 16,
        _ => return None,
    };
    let ip = token.get(cursor..cursor + ip_len)?;
    cursor += ip_len;
    let port = u16::from_be_bytes(token.get(cursor..cursor + 2)?.try_into().ok()?);
    cursor += 2;
    if port != peer.port() {
        return None;
    }
    let peer_matches = match peer.ip() {
        std::net::IpAddr::V4(address) => family == 4 && ip == address.octets(),
        std::net::IpAddr::V6(address) => family == 6 && ip == address.octets(),
    };
    if !peer_matches {
        return None;
    }
    let cid_len = usize::from(*token.get(cursor)?);
    cursor += 1;
    if cid_len == 0 || cid_len > quiche::MAX_CONN_ID_LEN {
        return None;
    }
    let mac_offset = cursor.checked_add(cid_len)?;
    if token.len() != mac_offset + 32 {
        return None;
    }
    let expected = hmac_sha256(seed, &token[..mac_offset]).ok()?;
    if !constant_time_eq(&expected, &token[mac_offset..]) {
        return None;
    }
    Some(token[cursor..mac_offset].to_vec())
}

fn flush_quic(
    peer: &mut PeerSession,
    endpoint: &UdpEndpoint,
    ring: &mut RuntimeRing,
    output: &mut [u8],
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        if peer.conn.timeout().is_some_and(|timeout| timeout.is_zero()) {
            peer.conn.on_timeout();
        }
        match peer.conn.send(output) {
            Ok((length, info)) => {
                debug2!(
                    verbose,
                    "flush_quic sending {} bytes to {}",
                    length,
                    info.to
                );
                if let Err(error) = endpoint.send_to(ring, &output[..length], info.to) {
                    if !peer_send_error(&error) {
                        return Err(error.into());
                    }
                    peer.send_failed = true;
                    let _ = peer.conn.close(false, 0, b"peer routing failure");
                    return Ok(());
                }
            }
            Err(quiche::Error::Done) => {
                debug2!(
                    verbose,
                    "flush_quic done, established={}",
                    peer.conn.is_established()
                );
                break;
            }
            Err(error) => return Err(Box::new(error)),
        }
    }
    Ok(())
}

fn peer_send_error(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::ENETUNREACH
                | libc::EHOSTUNREACH
                | libc::ECONNREFUSED
                | libc::EHOSTDOWN
                | libc::ENETDOWN
                | libc::EMSGSIZE
        )
    )
}

struct AuthJob {
    user: String,
    public_key: [u8; 32],
    server_nonce: [u8; 32],
    client_nonce: [u8; 32],
    spki_hash: [u8; 32],
    signature: [u8; 64],
    response: mpsc::SyncSender<std::io::Result<Option<crate::tls::AuthorizedLogin>>>,
}

fn complete_authorization(
    peer: &mut PeerSession,
    failures: &Arc<Mutex<AuthFailureLimiter>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(receiver) = &peer.pending_auth else {
        return Ok(());
    };
    let result = match receiver.try_recv() {
        Ok(result) => result,
        Err(TryRecvError::Empty) => return Ok(()),
        Err(TryRecvError::Disconnected) => return Err("authorization service disconnected".into()),
    };
    peer.pending_auth = None;
    if peer.conn.is_closed()
        || peer.conn.is_draining()
        || peer.conn.local_error().is_some()
        || peer.state != ServerState::AuthPending
    {
        return Ok(());
    }
    let Some(login) = result? else {
        failures
            .lock()
            .map_err(|_| "auth limiter lock poisoned")?
            .record_failure(peer.peer_ip);
        return Err("login authorization rejected".into());
    };
    peer.authenticated = true;
    peer.identity = Some(login.identity);
    peer.session_token = Some(login.token);
    send_control(&mut peer.conn, &Message::AuthOk)?;
    peer.state.sent(&Message::AuthOk)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn initial_limiter_full_table_admits_new_source() {
        let mut limiter = super::InitialRateLimiter::new();
        for ip in 0..4096u32 {
            assert!(limiter.allow(std::net::IpAddr::V4(ip.into())));
        }
        assert!(limiter.allow(std::net::IpAddr::V4(5000u32.into())));
        assert_eq!(limiter.sources.len(), 4096);
    }

    use super::{mint_retry_token, validate_retry_token};
    use std::net::SocketAddr;

    #[test]
    fn compression_negotiation_enforces_server_configuration() {
        use super::{negotiate_compression, Compression, SUPPORTED_FEATURES};

        assert_eq!(
            negotiate_compression(Compression::Off, 0).unwrap(),
            Compression::Off
        );
        assert_eq!(
            negotiate_compression(Compression::Fast, SUPPORTED_FEATURES).unwrap(),
            Compression::Fast
        );
        assert_eq!(
            negotiate_compression(Compression::High, SUPPORTED_FEATURES).unwrap(),
            Compression::High
        );
        assert!(negotiate_compression(Compression::High, 0).is_err());
        assert!(negotiate_compression(Compression::Fast, SUPPORTED_FEATURES | (1 << 31)).is_err());
    }

    #[test]
    fn pty_backpressure_retains_every_byte() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        let mut term = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut term) }, 0);
        unsafe {
            libc::cfmakeraw(&mut term);
        }
        assert_eq!(
            unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &term) },
            0
        );
        for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
            let mut enabled = 1;
            assert_eq!(unsafe { libc::ioctl(fd, libc::FIONBIO, &mut enabled) }, 0);
        }
        let expected: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let mut pending = expected.iter().copied().collect();
        super::drain_pty_queue(master.as_raw_fd(), &mut pending).unwrap();
        assert!(!pending.is_empty());
        let mut received = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while received.len() < expected.len() && std::time::Instant::now() < deadline {
            let mut buffer = [0u8; 4096];
            let n =
                unsafe { libc::read(slave.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
            if n > 0 {
                received.extend_from_slice(&buffer[..n as usize]);
            }
            super::drain_pty_queue(master.as_raw_fd(), &mut pending).unwrap();
            std::thread::yield_now();
        }
        assert!(pending.is_empty());
        assert_eq!(received, expected);
    }

    #[test]
    fn retry_token_binds_address_port_cid_and_mac() {
        let seed = [0x5a; 32];
        let peer: SocketAddr = "192.0.2.10:43210".parse().unwrap();
        let cid = quiche::ConnectionId::from_ref(b"original-cid");
        let token = mint_retry_token(&seed, &peer, &cid).unwrap();
        assert_eq!(
            validate_retry_token(&seed, &peer, &token).unwrap(),
            b"original-cid"
        );
        assert!(
            validate_retry_token(&seed, &"192.0.2.11:43210".parse().unwrap(), &token).is_none()
        );
        assert!(
            validate_retry_token(&seed, &"192.0.2.10:43211".parse().unwrap(), &token).is_none()
        );
        assert!(validate_retry_token(&[0xa5; 32], &peer, &token).is_none());
        let mut changed = token;
        changed[20] ^= 1;
        assert!(validate_retry_token(&seed, &peer, &changed).is_none());
    }

    #[test]
    fn retry_token_rejects_truncation_and_unknown_family() {
        let seed = [0x5a; 32];
        let peer: SocketAddr = "[2001:db8::1]:43210".parse().unwrap();
        let cid = quiche::ConnectionId::from_ref(b"cid");
        let token = mint_retry_token(&seed, &peer, &cid).unwrap();
        assert!(validate_retry_token(&seed, &peer, &token[..token.len() - 1]).is_none());
        let mut changed = token;
        changed[12] = 9;
        assert!(validate_retry_token(&seed, &peer, &changed).is_none());
    }
}
