use crate::terminal::{take_resize_pending, EscapeAction, EscapeDecoder, RawMode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use boring::x509::X509;
use ssxpro_crypto::{
    append_user_file, auth_signing_bytes, fingerprint_spki, getrandom, parse_known_hosts,
    read_private_key, read_user_file, sha256, verify_known_host, CryptoError, Ed25519Keypair,
    HostKeyError,
};
use ssxpro_io::{RuntimeRing, UdpEndpoint};
use ssxpro_proto::{encode, ClientState, ExitKind, FrameDecoder, Message, MAX_WIRE_FRAME};
use std::collections::VecDeque;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

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

pub fn connect_and_echo(
    target: &str,
    identity_path: Option<&Path>,
    port_override: Option<u16>,
    accept_new: bool,
    verbose: u8,
    client_config: &ssxpro_config::ClientConfig,
) -> Result<u8, Box<dyn std::error::Error>> {
    let (user, host) = target.split_once('@').ok_or("target must be USER@HOST")?;
    if user.is_empty() || host.is_empty() {
        return Err("target must be USER@HOST".into());
    }
    let alias = client_config.hosts.get(host);
    let hostname = alias.map_or(host, |entry| {
        if entry.host.is_empty() {
            host
        } else {
            &entry.host
        }
    });
    let port = port_override
        .or_else(|| alias.and_then(|entry| entry.port))
        .unwrap_or(client_config.port);
    let identity = identity_path
        .or_else(|| alias.and_then(|entry| entry.identity.as_deref()))
        .unwrap_or(&client_config.identity);
    let peer = (hostname, port)
        .to_socket_addrs()?
        .next()
        .ok_or("host resolved to no addresses")?;
    debug1!(verbose, "connecting to {hostname}:{port} user={user}");
    if client_config.hosts.contains_key(host) {
        debug2!(verbose, "using config alias '{host}' -> {hostname}:{port}");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set")?;
    debug1!(verbose, "identity loaded from {identity:?}");
    let seed = load_identity(&home, identity)?;
    let key = Ed25519Keypair::from_seed(seed)?;
    debug2!(verbose, "Ed25519 keypair derived from seed");
    let mut ring = RuntimeRing::new(256, false, [2, 2])?;
    let mut endpoint = UdpEndpoint::bind(
        if peer.is_ipv4() {
            "0.0.0.0:0".parse()?
        } else {
            "[::]:0".parse()?
        },
        false,
    )?;
    endpoint.set_receive_timeout(Duration::from_millis(100))?;
    let local = endpoint.local_addr()?;
    // BoringSSL's default verify (client-advertised) signature algorithms omit
    // Ed25519, while the server identity is an Ed25519 certificate. Without an
    // explicit preference list the server fails the handshake with
    // NO_COMMON_SIGNATURE_ALGORITHMS.
    let mut ssl = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())?;
    ssl.set_verify_algorithm_prefs(&[boring::ssl::SslSignatureAlgorithm::ED25519])?;
    let mut tls = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl)?;
    tls.verify_peer(false);
    tls.set_application_protos(&[ssxpro_proto::ALPN])?;
    // QUIC idle timeout: 0 means the peer's timeout is not capped locally.
    // This is intentionally separate from handshake_timeout_secs; reusing the
    // handshake timeout here dropped idle sessions after 15 seconds.
    tls.set_max_idle_timeout(u64::from(client_config.idle_timeout_secs) * 1000);
    tls.set_initial_max_data(4 * 1024 * 1024);
    tls.set_initial_max_stream_data_bidi_local(1024 * 1024);
    tls.set_initial_max_stream_data_bidi_remote(1024 * 1024);
    tls.set_initial_max_streams_bidi(64);
    let mut scid = [0u8; 16];
    getrandom(&mut scid)?;
    let scid = quiche::ConnectionId::from_ref(&scid);
    let mut conn = quiche::connect(Some(hostname), &scid, local, peer, &mut tls)?;
    debug1!(verbose, "TLS handshake initiated to {hostname}:{port}");
    let mut packet = [0u8; 65536];
    let mut output = [0u8; 65536];
    let deadline =
        Instant::now() + Duration::from_secs(u64::from(client_config.handshake_timeout_secs));
    let mut pin_checked = false;
    let mut sent_hello = false;
    let mut state = ClientState::Start;
    let mut decoder = FrameDecoder::new();
    let mut auth_ok = false;

    // Send the initial ClientHello before entering the receive loop.
    flush(&mut conn, &endpoint, &mut ring, &mut output, verbose)?;
    // --- Handshake phase: keep exchanging QUIC packets until established ---
    while Instant::now() < deadline && !conn.is_established() {
        match endpoint.recv_from(&mut ring, &mut packet) {
            Ok((length, from)) if from == peer => {
                debug3!(verbose, "client received {} bytes from {}", length, from);
                match conn.recv(&mut packet[..length], quiche::RecvInfo { from, to: local }) {
                    Ok(n) => debug3!(verbose, "conn.recv processed {n} bytes"),
                    Err(e) => {
                        debug3!(verbose, "conn.recv error: {e}");
                        return Err(Box::new(e));
                    }
                }
                conn.on_timeout();
                // Poll conn.recv() with empty buffers to let quiche finalize
                // its handshake state after processing the server's flight,
                // BEFORE attempting to send the client's Finished.
                for _ in 0..3 {
                    let mut extra = [0u8; 1];
                    let _ = conn.recv(&mut extra, quiche::RecvInfo { from, to: local });
                    conn.on_timeout();
                }
                flush(&mut conn, &endpoint, &mut ring, &mut output, verbose)?;
                continue;
            }
            Ok(_) => {
                flush(&mut conn, &endpoint, &mut ring, &mut output, verbose)?;
                continue;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                if conn.timeout().is_some_and(|duration| duration.is_zero()) {
                    conn.on_timeout();
                    flush(&mut conn, &endpoint, &mut ring, &mut output, verbose)?;
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                }
                continue;
            }
            Err(error) => return Err(Box::new(error)),
        }
    }
    if !conn.is_established() {
        return Err("handshake did not complete before deadline".into());
    }
    debug1!(verbose, "TLS handshake established with {hostname}:{port}");
    if !pin_checked {
        if let Some(cert_der) = conn.peer_cert() {
            let cert = X509::from_der(cert_der)?;
            let spki = cert.public_key()?.public_key_to_der()?;
            debug1!(
                verbose,
                "server certificate received ({} bytes)",
                cert_der.len()
            );
            debug2!(
                verbose,
                "server SPKI: {}",
                ssxpro_crypto::fingerprint_spki(&spki).unwrap_or_default()
            );
            check_or_trust_host(
                &home,
                &client_config.known_hosts,
                &format!("{hostname}:{port}"),
                &spki,
                accept_new
                    || matches!(
                        client_config.known_hosts_policy,
                        ssxpro_config::KnownHostsPolicy::AcceptNew
                    ),
            )?;
        }
        pin_checked = true;
        debug1!(verbose, "host key verified for {hostname}:{port}");
    }
    // --- Control phase: Hello -> AuthChallenge -> AuthRequest -> AuthOk.
    // The handshake may have consumed part of the original deadline, so
    // authentication gets its own window.
    let auth_deadline =
        Instant::now() + Duration::from_secs(u64::from(client_config.handshake_timeout_secs));
    while Instant::now() < auth_deadline {
        if conn.is_closed() {
            if let Some(error) = conn.peer_error() {
                return Err(format!("connection closed: {error:?}").into());
            }
            return Err("connection closed".into());
        }
        if pin_checked && !sent_hello {
            let hello = Message::Hello {
                version: 1,
                features: 0,
            };
            send_control(&mut conn, &hello)?;
            state.sent(&hello)?;
            sent_hello = true;
            debug1!(verbose, "sent client hello (version=1)");
        }
        flush(&mut conn, &endpoint, &mut ring, &mut output, verbose)?;
        match endpoint.recv_from(&mut ring, &mut packet) {
            Ok((length, from)) if from == peer => {
                conn.recv(&mut packet[..length], quiche::RecvInfo { from, to: local })?;
                conn.on_timeout();
            }
            Ok(_) => continue,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                if conn.timeout().is_some_and(|duration| duration.is_zero()) {
                    conn.on_timeout();
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                }
                continue;
            }
            Err(error) => return Err(Box::new(error)),
        }
        let mut control = [0; MAX_WIRE_FRAME];
        while let Ok((length, _)) = conn.stream_recv(0, &mut control) {
            if decoder.feed(&control[..length]) != length {
                return Err("control frame buffer overflow".into());
            }
            while let Some(message) = decoder.decode_next()? {
                state.accept(&message)?;
                match message {
                    Message::Challenge { server_nonce } => {
                        debug1!(verbose, "received authentication challenge from server");
                        let client_nonce = {
                            let mut nonce = [0; 32];
                            getrandom(&mut nonce)?;
                            nonce
                        };
                        debug2!(verbose, "client nonce generated");
                        let user_bytes = user.as_bytes();
                        if user_bytes.is_empty() || user_bytes.len() > 256 {
                            return Err("username length must be 1..=256 bytes".into());
                        }
                        let public = key.public_key();
                        let spki =
                            X509::from_der(conn.peer_cert().ok_or("server certificate missing")?)?
                                .public_key()?
                                .public_key_to_der()?;
                        let input = auth_signing_bytes(
                            &server_nonce,
                            &client_nonce,
                            &sha256(&spki)?,
                            user_bytes,
                            &public,
                        )?;
                        let signature = key.sign(&input)?;
                        let mut user_field = [0; 256];
                        user_field[..user_bytes.len()].copy_from_slice(user_bytes);
                        let request = Message::AuthRequest {
                            user: user_field,
                            user_len: user_bytes.len() as u16,
                            public_key: public.0,
                            client_nonce,
                            signature: signature.0,
                        };
                        send_control(&mut conn, &request)?;
                        state.sent(&request)?;
                        debug1!(verbose, "sent authentication request for user={user}");
                    }
                    Message::AuthOk => {
                        auth_ok = true;
                        debug1!(verbose, "authentication succeeded");
                        let (rows, cols) = terminal_size();
                        let mut term = [0; 64];
                        let term_value =
                            std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned());
                        let term_bytes = term_value.as_bytes();
                        let length = term_bytes.len().min(64);
                        term[..length].copy_from_slice(&term_bytes[..length]);
                        let open = Message::OpenShell {
                            term,
                            term_len: length as u8,
                            rows,
                            cols,
                        };
                        send_control(&mut conn, &open)?;
                        state.sent(&open)?;
                        debug1!(verbose, "shell opened (TERM={term_value}, {rows}x{cols})");
                    }
                    Message::AuthFail { reason_class } => {
                        return Err(format!(
                            "server rejected authentication (class {reason_class})"
                        )
                        .into())
                    }
                    _ => {}
                }
            }
        }
        if auth_ok {
            // Flush the OpenShell queued when AuthOk was processed.
            flush(&mut conn, &endpoint, &mut ring, &mut output, verbose)?;
            break;
        }
    }
    if !auth_ok {
        return Err("connection or authentication timed out".into());
    }

    // The TTY guard lives across the entire network loop and restores attributes on return/unwind.
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Err("ssx requires a terminal on stdin".into());
    }
    let mut raw_mode = RawMode::enter(libc::STDIN_FILENO)?;
    let (input_rx, _input_thread) = start_input_reader()?;
    let mut escapes = EscapeDecoder::default();
    let mut input_pending = VecDeque::new();
    let mut input_eof = false;
    let mut input_fin = false;
    let mut stream4_opened = false;
    let mut data_finished = false;
    let mut exit_received = false;
    let mut remote_status = 255;
    let mut last_size = terminal_size();
    // SSH-style ServerAlive: send a QUIC PING (an ack-eliciting frame) when
    // nothing has been received for a full interval, and give up after
    // server_alive_count_max unanswered probes.
    let keep_alive_interval =
        Duration::from_secs(u64::from(client_config.server_alive_interval_secs));
    let mut last_activity_at = Instant::now();
    let mut keepalives_outstanding: u32 = 0;
    while !(data_finished && exit_received) && !conn.is_closed() {
        if !keep_alive_interval.is_zero() && last_activity_at.elapsed() >= keep_alive_interval {
            if keepalives_outstanding >= client_config.server_alive_count_max {
                return Err(format!(
                    "server did not answer {keepalives_outstanding} keepalives; disconnecting"
                )
                .into());
            }
            conn.send_ack_eliciting()?;
            keepalives_outstanding += 1;
            last_activity_at = Instant::now();
            debug1!(verbose, "sent keepalive #{keepalives_outstanding}");
        }
        loop {
            match input_rx.try_recv() {
                Ok(InputEvent::Data(bytes)) => {
                    let mut encoded = vec![0u8; bytes.len() + 1];
                    let (length, action) = escapes.process(&bytes, &mut encoded);
                    input_pending.extend(&encoded[..length]);
                    match action {
                        Some(EscapeAction::Disconnect) => {
                            let close = Message::Close { code: 0 };
                            send_control(&mut conn, &close)?;
                            state.sent(&close)?;
                            input_eof = true;
                        }
                        Some(EscapeAction::Suspend) => {
                            raw_mode.restore()?;
                            // SAFETY: SIGSTOP is process-directed and has no handler.
                            unsafe {
                                libc::raise(libc::SIGSTOP);
                            }
                            drop(raw_mode);
                            raw_mode = RawMode::enter(libc::STDIN_FILENO)?;
                        }
                        Some(EscapeAction::Help) => ring_write_all(
                            &mut ring,
                            libc::STDOUT_FILENO,
                            b"~. disconnect  ~^Z suspend  ~? help\r\n",
                        )?,
                        None => {}
                    }
                }
                Ok(InputEvent::Eof) => {
                    input_eof = true;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    input_eof = true;
                    break;
                }
            }
        }
        if take_resize_pending() {
            let current_size = terminal_size();
            if current_size != last_size {
                let resize = Message::Resize {
                    rows: current_size.0,
                    cols: current_size.1,
                };
                send_control(&mut conn, &resize)?;
                state.sent(&resize)?;
                last_size = current_size;
            }
        }
        if !stream4_opened {
            // Open the PTY data stream with a single 0x00 marker before any
            // input. QUIC has no empty stream-open frame, so without this the
            // server cannot send the initial prompt until the first keystroke.
            match conn.stream_send(4, &[0x00], false) {
                Ok(1) => {
                    stream4_opened = true;
                    debug1!(verbose, "opened PTY data stream 4");
                }
                Ok(_) | Err(quiche::Error::Done) => {}
                Err(error) => return Err(Box::new(error)),
            }
        }
        if stream4_opened && !input_pending.is_empty() {
            // stream_send() creates stream 4 if it does not exist yet and
            // returns Done when flow control gives it no room.
            let contiguous = input_pending.make_contiguous();
            let length = contiguous.len().min(16 * 1024);
            match conn.stream_send(4, &contiguous[..length], false) {
                Ok(written) => {
                    input_pending.drain(..written);
                    debug3!(verbose, "sent {written} bytes to server stream 4");
                }
                Err(quiche::Error::Done) => {}
                Err(error) => return Err(Box::new(error)),
            }
        }
        if stream4_opened && input_eof && input_pending.is_empty() && !input_fin {
            conn.stream_send(4, &[], true)?;
            input_fin = true;
            debug3!(verbose, "sent EOF to server stream 4");
        }
        flush(&mut conn, &endpoint, &mut ring, &mut output, verbose)?;
        match endpoint.recv_from(&mut ring, &mut packet) {
            Ok((length, from)) if from == peer => {
                let processed =
                    conn.recv(&mut packet[..length], quiche::RecvInfo { from, to: local })?;
                if processed > 0 {
                    last_activity_at = Instant::now();
                    keepalives_outstanding = 0;
                }
            }
            Ok(_) => continue,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                if conn.timeout().is_some_and(|duration| duration.is_zero()) {
                    conn.on_timeout();
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                }
                continue;
            }
            Err(error) => return Err(Box::new(error)),
        }
        while let Ok((length, fin)) = conn.stream_recv(4, &mut packet) {
            if length > 0 {
                ring_write_all(&mut ring, libc::STDOUT_FILENO, &packet[..length])?;
                debug3!(verbose, "received {length} bytes from server stream 4");
            }
            data_finished |= fin;
        }
        let mut control = [0u8; MAX_WIRE_FRAME];
        while let Ok((length, _)) = conn.stream_recv(0, &mut control) {
            if decoder.feed(&control[..length]) != length {
                return Err("control frame buffer overflow".into());
            }
            while let Some(message) = decoder.decode_next()? {
                state.accept(&message)?;
                debug3!(verbose, "received control message: {message:?}");
                if let Message::Exit { kind, value } = message {
                    remote_status = if kind == ExitKind::Status {
                        value
                    } else {
                        128u8.saturating_add(value)
                    };
                    exit_received = true;
                    debug1!(
                        verbose,
                        "received exit status from server (kind={kind:?}, value={value})"
                    );
                }
            }
        }
    }
    Ok(remote_status)
}

enum InputEvent {
    Data(Vec<u8>),
    Eof,
}

fn start_input_reader(
) -> Result<(Receiver<InputEvent>, std::thread::JoinHandle<()>), Box<dyn std::error::Error>> {
    let (sender, receiver) = mpsc::sync_channel(8);
    let worker = std::thread::Builder::new()
        .name("ssx-stdin".to_owned())
        .spawn(move || {
            let Ok(mut ring) = RuntimeRing::new(64, false, [1, 1]) else {
                let _ = sender.send(InputEvent::Eof);
                return;
            };
            let mut buffer = [0u8; 256];
            let stdin_fd = match ring.register_fd(libc::STDIN_FILENO) {
                Ok(f) => f,
                Err(error)
                    if error.raw_os_error() == Some(libc::EACCES)
                        || error.raw_os_error() == Some(libc::EPERM) =>
                {
                    // io_uring registration blocked for unprivileged users on this
                    // host; fall back to blocking reads on stdin.
                    loop {
                        let length = unsafe {
                            libc::read(
                                libc::STDIN_FILENO,
                                buffer.as_mut_ptr() as *mut libc::c_void,
                                buffer.len(),
                            )
                        };
                        if length < 0 {
                            let error = std::io::Error::last_os_error();
                            if error.kind() == std::io::ErrorKind::Interrupted {
                                continue;
                            }
                            break;
                        }
                        if length == 0 {
                            break;
                        }
                        if sender
                            .send(InputEvent::Data(buffer[..length as usize].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                    return;
                }
                Err(_) => return,
            };
            loop {
                let entry =
                    io_uring::opcode::Read::new(stdin_fd, buffer.as_mut_ptr(), buffer.len() as _)
                        .build()
                        .flags(io_uring::squeue::Flags::FIXED_FILE)
                        .user_data(1);
                match ring.submit_wait(&entry) {
                    Ok(0) => {
                        let _ = sender.send(InputEvent::Eof);
                        break;
                    }
                    Ok(length) => {
                        if sender
                            .send(InputEvent::Data(buffer[..length as usize].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error)
                        if error.raw_os_error() == Some(libc::EACCES)
                            || error.raw_os_error() == Some(libc::EPERM) =>
                    {
                        // io_uring submission is blocked for unprivileged users
                        // on this host; fall back to a blocking read on stdin.
                        loop {
                            let length = unsafe {
                                libc::read(
                                    libc::STDIN_FILENO,
                                    buffer.as_mut_ptr() as *mut libc::c_void,
                                    buffer.len(),
                                )
                            };
                            if length < 0 {
                                let error = std::io::Error::last_os_error();
                                if error.kind() == std::io::ErrorKind::Interrupted {
                                    continue;
                                }
                                let _ = sender.send(InputEvent::Eof);
                                break;
                            }
                            if length == 0 {
                                let _ = sender.send(InputEvent::Eof);
                                break;
                            }
                            if sender
                                .send(InputEvent::Data(buffer[..length as usize].to_vec()))
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    Err(_) => {
                        let _ = sender.send(InputEvent::Eof);
                        break;
                    }
                }
            }
        })?;
    Ok((receiver, worker))
}

fn ring_write_all(ring: &mut RuntimeRing, fd: RawFd, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let fixed_fd = match ring.register_fd(fd) {
            Ok(f) => f,
            Err(error)
                if error.raw_os_error() == Some(libc::EACCES)
                    || error.raw_os_error() == Some(libc::EPERM) =>
            {
                // io_uring registration blocked for unprivileged users on this
                // host; fall back to a blocking write.
                while !bytes.is_empty() {
                    let written = unsafe {
                        libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len())
                    };
                    if written < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if written == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "short terminal write",
                        ));
                    }
                    bytes = &bytes[written as usize..];
                }
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let entry = io_uring::opcode::Write::new(fixed_fd, bytes.as_ptr(), bytes.len() as _)
            .build()
            .flags(io_uring::squeue::Flags::FIXED_FILE)
            .user_data(2);
        match ring.submit_wait(&entry) {
            Ok(written) => {
                if written == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "short terminal write",
                    ));
                }
                bytes = &bytes[written as usize..];
            }
            Err(error)
                if error.raw_os_error() == Some(libc::EACCES)
                    || error.raw_os_error() == Some(libc::EPERM) =>
            {
                // io_uring submission is blocked for unprivileged users on this
                // host; fall back to a blocking write.
                while !bytes.is_empty() {
                    let written = unsafe {
                        libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len())
                    };
                    if written < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if written == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "short terminal write",
                        ));
                    }
                    bytes = &bytes[written as usize..];
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn load_identity(home: &Path, path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let data = if path_equals(home, path) {
        read_user_file(home, "id_ed25519", 256)?
    } else {
        read_private_key(path, 256)?
    };
    Ok(data
        .try_into()
        .map_err(|_| "private identity must be a 32-byte Ed25519 seed")?)
}

fn path_equals(home: &Path, path: &Path) -> bool {
    path == home.join(".ssx/id_ed25519")
}

fn check_or_trust_host(
    home: &Path,
    configured_path: &Path,
    host: &str,
    spki: &[u8],
    accept_new: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let known_path = if configured_path.to_string_lossy().starts_with("~/") {
        home.join(configured_path.to_string_lossy().trim_start_matches("~/"))
    } else {
        configured_path.to_path_buf()
    };
    let known = if known_path == home.join(".ssx/known_hosts") {
        match read_user_file(home, "known_hosts", 1024 * 1024) {
            Ok(bytes) => String::from_utf8(bytes)?,
            Err(CryptoError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                String::new()
            }
            Err(error) => return Err(Box::new(error)),
        }
    } else {
        match read_private_key(&known_path, 1024 * 1024) {
            Ok(bytes) => String::from_utf8(bytes)?,
            Err(CryptoError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                String::new()
            }
            Err(error) => return Err(Box::new(error)),
        }
    };
    let entries = parse_known_hosts(&known)?;
    match verify_known_host(&entries, host, spki) {
        Ok(()) => Ok(()),
        Err(HostKeyError::Mismatch) => Err(HostKeyError::Mismatch.into()),
        Err(HostKeyError::UnknownHost) => {
            let fingerprint = fingerprint_spki(spki)?;
            let accepted = if accept_new {
                true
            } else {
                eprintln!("The authenticity of {host} cannot be established.\nServer key fingerprint: {fingerprint}");
                eprint!("Trust this host key? (yes/no) ");
                std::io::stderr().flush()?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                answer.trim().eq_ignore_ascii_case("yes")
            };
            if !accepted {
                return Err("host key was not accepted".into());
            }
            let hash = sha256(spki)?;
            let line = format!("{host} spki-sha256 {}\n", STANDARD.encode(hash));
            if known_path == home.join(".ssx/known_hosts") {
                append_user_file(home, "known_hosts", line.as_bytes(), 1024 * 1024)?;
            } else {
                return Err(
                    "custom known_hosts files must already contain the accepted pin".into(),
                );
            }
            Ok(())
        }
    }
}

fn terminal_size() -> (u16, u16) {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: size is writable and stdin is the caller's terminal descriptor.
    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ as _, &mut size) } == 0
        && size.ws_row > 0
        && size.ws_col > 0
    {
        (size.ws_row, size.ws_col)
    } else {
        (24, 80)
    }
}

fn send_control(
    conn: &mut quiche::Connection,
    message: &Message,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0; MAX_WIRE_FRAME];
    let length = encode(message, &mut bytes)?;
    conn.stream_send(0, &bytes[..length], false)?;
    Ok(())
}

fn flush(
    conn: &mut quiche::Connection,
    endpoint: &UdpEndpoint,
    ring: &mut RuntimeRing,
    output: &mut [u8],
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        match conn.send(output) {
            Ok((length, info)) => {
                debug3!(verbose, "flush sending {} bytes to {}", length, info.to);
                endpoint.send_to(ring, &output[..length], info.to)?;
            }
            Err(quiche::Error::Done) => {
                debug3!(verbose, "flush done, established={}", conn.is_established());
                return Ok(());
            }
            Err(error) => return Err(Box::new(error)),
        }
    }
}
