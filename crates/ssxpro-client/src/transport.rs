use crate::terminal::{take_resize_pending, EscapeAction, EscapeDecoder, RawMode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use boring::x509::X509;
use ssxpro_compression::{
    Decoder as CompressionDecoder, Encoder as CompressionEncoder, MAX_BLOCK_SIZE,
};
use ssxpro_config::KnownHostsPolicy;
use ssxpro_crypto::{
    append_user_file, auth_signing_bytes, getrandom, parse_known_hosts, read_private_key,
    read_user_file, sha256, verify_known_host, CryptoError, Ed25519Keypair, HostKeyError,
};
use ssxpro_io::{RuntimeRing, UdpEndpoint};
use ssxpro_proto::{
    encode, ClientState, Compression, ExitKind, FrameDecoder, Message, MAX_WIRE_FRAME,
    PROTOCOL_VERSION, RESERVED_EXTENSION, SUPPORTED_FEATURES,
};
use std::collections::VecDeque;
use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target<'a> {
    pub user: &'a str,
    pub host: &'a str,
    pub port: Option<u16>,
}

/// Parse `USER@HOST[:PORT]`. Bracket the host to give an IPv6 literal a port,
/// for example `alice@[2001:db8::1]:2222`.
pub fn parse_target(target: &str) -> Result<Target<'_>, Box<dyn std::error::Error>> {
    let (user, destination) = target
        .split_once('@')
        .ok_or("target must be USER@HOST:PORT")?;
    if user.is_empty()
        || user.len() > 256
        || user
            .chars()
            .any(|ch| ch == '\0' || ch.is_ascii_whitespace())
    {
        return Err("target user must be 1 to 256 bytes without whitespace or NUL".into());
    }
    if destination.is_empty() || destination.contains('@') {
        return Err("target must be USER@HOST:PORT".into());
    }
    let (host, port) = parse_host_and_port(destination)?;
    if host.is_empty()
        || host.len() > 253
        || host
            .chars()
            .any(|ch| ch == '\0' || ch.is_ascii_whitespace())
    {
        return Err("target host must be 1 to 253 bytes without whitespace or NUL".into());
    }
    Ok(Target { user, host, port })
}

fn parse_host_and_port(
    destination: &str,
) -> Result<(&str, Option<u16>), Box<dyn std::error::Error>> {
    if let Some(bracketed) = destination.strip_prefix('[') {
        let (host, rest) = bracketed
            .split_once(']')
            .ok_or("target has an unterminated '['")?;
        let port = match rest {
            "" => None,
            rest => Some(parse_port(
                rest.strip_prefix(':')
                    .ok_or("target must be USER@[HOST]:PORT or USER@HOST:PORT")?,
            )?),
        };
        return Ok((host, port));
    }
    match destination.rsplit_once(':') {
        None => Ok((destination, None)),
        Some((host, port)) if !host.contains(':') => Ok((host, Some(parse_port(port)?))),
        // Unbracketed IPv6 literal: all colons belong to the address. A port
        // on an IPv6 host requires the bracket form.
        Some(_) => Ok((destination, None)),
    }
}

fn parse_port(value: &str) -> Result<u16, Box<dyn std::error::Error>> {
    match value.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err("target port must be between 1 and 65535".into()),
    }
}

pub fn connect_and_echo(
    target: Target<'_>,
    identity_path: Option<&Path>,
    port_override: Option<u16>,
    verbose: u8,
    client_config: &ssxpro_config::ClientConfig,
) -> Result<u8, Box<dyn std::error::Error>> {
    let Target {
        user,
        host,
        port: target_port,
    } = target;
    let alias = client_config.hosts.get(host);
    let hostname = alias.map_or(host, |entry| {
        if entry.host.is_empty() {
            host
        } else {
            &entry.host
        }
    });
    let port = port_override
        .or(target_port)
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
    // The server leaf key is Ed25519, while a CA may sign the leaf with a
    // mainstream RSA or ECDSA key. Advertise modern SHA-2 certificate-chain
    // signature algorithms as well as Ed25519 so CA mode works with common
    // private PKIs without permitting SHA-1/MD5 signatures.
    let mut ssl = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())?;
    ssl.set_verify_algorithm_prefs(&[
        boring::ssl::SslSignatureAlgorithm::ED25519,
        boring::ssl::SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        boring::ssl::SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        boring::ssl::SslSignatureAlgorithm::ECDSA_SECP521R1_SHA512,
        boring::ssl::SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        boring::ssl::SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        boring::ssl::SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        boring::ssl::SslSignatureAlgorithm::RSA_PKCS1_SHA256,
        boring::ssl::SslSignatureAlgorithm::RSA_PKCS1_SHA384,
        boring::ssl::SslSignatureAlgorithm::RSA_PKCS1_SHA512,
    ])?;
    ssl.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_3))?;
    ssl.set_max_proto_version(Some(boring::ssl::SslVersion::TLS1_3))?;
    ssl.set_options(boring::ssl::SslOptions::NO_TICKET);
    ssl.set_session_cache_mode(boring::ssl::SslSessionCacheMode::OFF);
    // Determine SNI: for IP addresses, don't set SNI (RFC 6066 forbids IP
    // literals). The SAN check performed below uses the connection target.
    let sni = if hostname.parse::<std::net::IpAddr>().is_ok() {
        debug2!(
            verbose,
            "hostname {hostname} is an IP literal; SNI omitted, IP SAN verification applies"
        );
        None
    } else {
        Some(hostname)
    };
    let mut tls = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl)?;
    let ca_bundle = client_config
        .tls
        .ca_bundle
        .as_ref()
        .map(|path| expand_tilde(&home, path));
    debug2!(
        verbose,
        "TLS policy: ca_bundle={:?} known_hosts_policy={:?}",
        ca_bundle.as_deref().map(|path| path.display().to_string()),
        client_config.known_hosts_policy
    );
    if let Some(path) = &ca_bundle {
        let path = path
            .to_str()
            .ok_or("TLS CA bundle path is not valid UTF-8")?;
        debug2!(verbose, "loading CA bundle {path}");
        tls.load_verify_locations_from_file(path)?;
        tls.verify_peer(true);
        debug1!(verbose, "TLS certificate-chain verification enabled");
    } else {
        // Legacy self-signed deployments use the mandatory SPKI known-hosts
        // pin as their trust anchor. Unknown pins are rejected by default.
        tls.verify_peer(false);
        debug1!(
            verbose,
            "TLS CA verification disabled; strict SPKI pinning is required"
        );
    }
    debug2!(
        verbose,
        "peer verification {}; ALPN {:?}",
        if ca_bundle.is_some() {
            "enabled"
        } else {
            "disabled"
        },
        String::from_utf8_lossy(ssxpro_proto::ALPN)
    );
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
    let mut conn = quiche::connect(sni, &scid, local, peer, &mut tls)?;
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
    let mut compression = Compression::Off;

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
                        debug2!(
                            verbose,
                            "TLS handshake failed after {length} bytes from {from}: {e} (peer alert: {:?})",
                            conn.peer_error()
                        );
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
        debug2!(
            verbose,
            "handshake unfinished after {}s (established=false, closed={}, peer_error={:?})",
            client_config.handshake_timeout_secs,
            conn.is_closed(),
            conn.peer_error()
        );
        return Err("handshake did not complete before deadline".into());
    }
    debug1!(verbose, "TLS handshake established with {hostname}:{port}");
    debug2!(
        verbose,
        "negotiated ALPN: {:?}",
        String::from_utf8_lossy(conn.application_proto())
    );
    if !pin_checked {
        let cert_der = conn
            .peer_cert()
            .ok_or("server did not present a TLS certificate")?;
        let cert = X509::from_der(cert_der)?;
        if ca_bundle.is_some() {
            debug2!(verbose, "verifying certificate SAN against '{hostname}'");
            verify_server_certificate_name(&cert, hostname)?;
            debug2!(verbose, "certificate SAN matched '{hostname}'");
        }
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
            client_config.known_hosts_policy,
            verbose,
        )?;
        pin_checked = true;
        debug1!(
            verbose,
            "host certificate and SPKI identity verified for {hostname}:{port}"
        );
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
                version: PROTOCOL_VERSION,
                features: SUPPORTED_FEATURES,
                extension: RESERVED_EXTENSION,
            };
            send_control(&mut conn, &hello)?;
            state.sent(&hello)?;
            sent_hello = true;
            debug1!(verbose, "sent client hello (version={PROTOCOL_VERSION})");
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
                    Message::Challenge {
                        server_nonce,
                        compression: selected,
                        ..
                    } => {
                        if !selected.is_supported_by(SUPPORTED_FEATURES) {
                            return Err(format!(
                                "server selected unsupported compression {selected:?}"
                            )
                            .into());
                        }
                        compression = selected;
                        debug1!(
                            verbose,
                            "received authentication challenge from server (compression={selected:?})"
                        );
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
                            extension: RESERVED_EXTENSION,
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
                    Message::AuthOk { extension: _ } => {
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
                            extension: RESERVED_EXTENSION,
                            term,
                            term_len: length as u8,
                            rows,
                            cols,
                        };
                        send_control(&mut conn, &open)?;
                        state.sent(&open)?;
                        debug1!(verbose, "shell opened (TERM={term_value}, {rows}x{cols})");
                    }
                    Message::AuthFail { reason_class, .. } => {
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
    let mut compression_encoder = None;
    let mut compression_decoder = None;
    if compression != Compression::Off {
        compression_encoder = Some(CompressionEncoder::new(compression)?);
        compression_decoder = Some(CompressionDecoder::new(compression)?);
        debug1!(verbose, "stream compression enabled ({compression:?})");
    }

    // The TTY guard lives across the entire network loop and restores attributes on return/unwind.
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Err("ssx requires a terminal on stdin".into());
    }
    let mut raw_mode = RawMode::enter(libc::STDIN_FILENO)?;
    debug1!(verbose, "terminal raw mode enabled");
    let (input_rx, _input_thread) = start_input_reader()?;
    let mut escapes = EscapeDecoder::default();
    let mut input_pending = VecDeque::new();
    let mut input_encoded = VecDeque::new();
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
                    extension: RESERVED_EXTENSION,
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
        if stream4_opened && input_encoded.is_empty() && !input_pending.is_empty() {
            // Frame raw terminal input first, then feed the encoded bytes to
            // QUIC so a partially sent frame can resume on the next tick.
            let contiguous = input_pending.make_contiguous();
            let take = contiguous.len().min(MAX_BLOCK_SIZE);
            if let Some(encoder) = compression_encoder.as_mut() {
                input_encoded.extend(encoder.encode(&contiguous[..take])?);
            } else {
                input_encoded.extend(&contiguous[..take]);
            }
            input_pending.drain(..take);
        }
        if stream4_opened && !input_encoded.is_empty() {
            // stream_send() creates stream 4 if it does not exist yet and
            // returns Done when flow control gives it no room.
            let contiguous = input_encoded.make_contiguous();
            let length = contiguous.len().min(16 * 1024);
            match conn.stream_send(4, &contiguous[..length], false) {
                Ok(written) => {
                    input_encoded.drain(..written);
                    debug3!(verbose, "sent {written} bytes to server stream 4");
                }
                Err(quiche::Error::Done) => {}
                Err(error) => return Err(Box::new(error)),
            }
        }
        if stream4_opened
            && input_eof
            && input_pending.is_empty()
            && input_encoded.is_empty()
            && !input_fin
        {
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
                if let Some(stream_decoder) = compression_decoder.as_mut() {
                    let mut decoded = Vec::new();
                    let mut input = &packet[..length];
                    loop {
                        let blocked =
                            stream_decoder.push_bounded(input, &mut decoded, MAX_BLOCK_SIZE)?;

                        ring_write_all(&mut ring, libc::STDOUT_FILENO, &decoded)?;
                        if !blocked {
                            break;
                        }
                        // Drain retained frames before receiving more stream data.
                        decoded.clear();
                        input = &[];
                    }
                } else {
                    ring_write_all(&mut ring, libc::STDOUT_FILENO, &packet[..length])?;
                }
                debug3!(verbose, "received {length} bytes from server stream 4");
            }
            if fin {
                if let Some(stream_decoder) = compression_decoder.as_ref() {
                    stream_decoder.finish()?;
                }
                data_finished = true;
            }
        }
        let mut control = [0u8; MAX_WIRE_FRAME];
        while let Ok((length, _)) = conn.stream_recv(0, &mut control) {
            if decoder.feed(&control[..length]) != length {
                return Err("control frame buffer overflow".into());
            }
            while let Some(message) = decoder.decode_next()? {
                state.accept(&message)?;
                debug3!(verbose, "received control message: {message:?}");
                if let Message::Exit { kind, value, .. } = message {
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
    let expanded = path
        .as_os_str()
        .as_encoded_bytes()
        .starts_with(b"~/")
        .then(|| home.join(path.strip_prefix("~").expect("tilde path prefix")));
    let path = expanded.as_deref().unwrap_or(path);
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

fn expand_tilde(home: &Path, path: &Path) -> PathBuf {
    match path.to_string_lossy().strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => path.to_path_buf(),
    }
}

fn read_known_hosts(home: &Path, path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = if path == home.join(".ssx/known_hosts") {
        match read_user_file(home, "known_hosts", 1024 * 1024) {
            Ok(bytes) => bytes,
            Err(CryptoError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(String::new())
            }
            Err(error) => return Err(Box::new(error)),
        }
    } else {
        match read_private_key(path, 1024 * 1024) {
            Ok(bytes) => bytes,
            Err(CryptoError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(String::new())
            }
            Err(error) => return Err(Box::new(error)),
        }
    };
    Ok(String::from_utf8(bytes)?)
}

fn verify_server_certificate_name(
    certificate: &X509,
    hostname: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // RFC 9525 service identity checks are based on SAN identifiers, not the
    // legacy subject commonName. Require SAN explicitly before checking DNS/IP.
    let sans = certificate
        .subject_alt_names()
        .ok_or("CA-verified server certificate has no subjectAltName extension")?;
    if sans.is_empty() {
        return Err("CA-verified server certificate has an empty subjectAltName extension".into());
    }
    // Match only the relevant SAN GeneralName type. In particular, do not let
    // the deprecated subject CN satisfy DNS verification when a certificate
    // also contains an unrelated SAN entry.
    let matches = match hostname.parse::<IpAddr>() {
        Ok(IpAddr::V4(expected)) => {
            let expected_octets = expected.octets();
            sans.iter().any(|name| {
                name.ipaddress()
                    .is_some_and(|address| address == expected_octets.as_slice())
            })
        }
        Ok(IpAddr::V6(expected)) => {
            let expected_octets = expected.octets();
            sans.iter().any(|name| {
                name.ipaddress()
                    .is_some_and(|address| address == expected_octets.as_slice())
            })
        }
        Err(_) => sans.iter().any(|name| {
            name.dnsname()
                .is_some_and(|dns_name| dns_name_matches_host(dns_name, hostname))
        }),
    };
    if !matches {
        return Err(
            format!("server certificate subjectAltName does not match '{hostname}'").into(),
        );
    }
    Ok(())
}

fn dns_name_matches_host(pattern: &str, hostname: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let hostname = hostname.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if suffix.is_empty() || suffix.contains('*') {
            return false;
        }
        return hostname.ends_with(&format!(".{suffix}"))
            && hostname
                .strip_suffix(&format!(".{suffix}"))
                .is_some_and(|leftmost| !leftmost.is_empty() && !leftmost.contains('.'));
    }
    !pattern.contains('*') && pattern == hostname
}

fn prompt_to_trust_host(host: &str, fingerprint: &str) -> Result<bool, Box<dyn std::error::Error>> {
    eprintln!("The authenticity of host '{host}' cannot be established.");
    eprintln!("Server SPKI SHA-256 (base64): {fingerprint}");
    eprintln!("Compare this exact value with `ssxd --print-host-pin` obtained through a trusted, independent channel.");
    eprint!("Type the full base64 fingerprint to enroll this host (anything else rejects): ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer)? == 0 {
        return Ok(false);
    }
    Ok(answer.trim() == fingerprint)
}

fn check_or_trust_host(
    home: &Path,
    configured_path: &Path,
    host: &str,
    spki: &[u8],
    policy: KnownHostsPolicy,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let default_known_path = home.join(".ssx/known_hosts");
    let known_path = expand_tilde(home, configured_path);
    debug2!(
        verbose,
        "checking known_hosts pin for {host} in {}",
        known_path.display()
    );
    let known = read_known_hosts(home, &known_path)?;
    let entries = parse_known_hosts(&known)?;
    debug2!(verbose, "loaded {} known_hosts entr(ies)", entries.len());
    match verify_known_host(&entries, host, spki) {
        Ok(()) => {
            debug2!(verbose, "SPKI pin matched for {host}");
            Ok(())
        }
        Err(HostKeyError::Mismatch) => {
            debug2!(verbose, "SPKI pin mismatch for {host}; refusing connection");
            Err(HostKeyError::Mismatch.into())
        }
        Err(HostKeyError::UnknownHost) => {
            if known_path != default_known_path {
                debug2!(
                    verbose,
                    "{host} is not pinned and {} is a custom known_hosts file",
                    known_path.display()
                );
                return Err(format!(
                    "host {host} is not pinned in {}; custom known_hosts files are never modified automatically",
                    known_path.display()
                )
                .into());
            }
            debug2!(
                verbose,
                "{host} is unknown; applying known_hosts_policy={policy:?}"
            );
            // Match `ssxd --print-host-pin` and the known_hosts wire format:
            // standard padded base64 of SHA-256(DER SubjectPublicKeyInfo).
            let fingerprint = STANDARD.encode(sha256(spki)?);
            match policy {
                KnownHostsPolicy::Deny => {
                    return Err(format!(
                        "host key for {host} is unknown and known_hosts_policy is deny (fingerprint {fingerprint}); provision this pin out of band or use --trust-new-host after independent verification"
                    )
                    .into())
                }
                KnownHostsPolicy::Ask => {
                    if !prompt_to_trust_host(host, &fingerprint)? {
                        return Err("host key fingerprint was not confirmed".into());
                    }
                }
            }
            let hash = sha256(spki)?;
            let line = format!("{host} spki-sha256 {}\n", STANDARD.encode(hash));
            append_user_file(home, "known_hosts", line.as_bytes(), 1024 * 1024)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_home(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home = std::env::temp_dir().join(format!(
            "ssxpro-client-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        home
    }

    #[test]
    fn target_parsing_supports_ports_and_ipv6() {
        assert_eq!(
            parse_target("alice@example.test").unwrap(),
            Target {
                user: "alice",
                host: "example.test",
                port: None,
            }
        );
        assert_eq!(
            parse_target("alice@example.test:2222").unwrap(),
            Target {
                user: "alice",
                host: "example.test",
                port: Some(2222),
            }
        );
        assert_eq!(
            parse_target("alice@[2001:db8::1]:2222").unwrap(),
            Target {
                user: "alice",
                host: "2001:db8::1",
                port: Some(2222),
            }
        );
        assert_eq!(
            parse_target("alice@2001:db8::1").unwrap(),
            Target {
                user: "alice",
                host: "2001:db8::1",
                port: None,
            }
        );
        for target in [
            "example.test",
            "alice@",
            "@example.test",
            "alice@example.test:0",
            "alice@example.test:notaport",
            "alice@[2001:db8::1",
            "alice@[2001:db8::1]suffix",
            "alice@exa mple.test:22",
        ] {
            assert!(
                parse_target(target).is_err(),
                "{target:?} should be rejected"
            );
        }
    }

    #[test]
    fn dns_san_matching_is_exact_or_single_label_wildcard() {
        assert!(dns_name_matches_host(
            "shell.example.test",
            "SHELL.EXAMPLE.TEST"
        ));
        assert!(dns_name_matches_host("*.example.test", "node.example.test"));
        assert!(!dns_name_matches_host(
            "*.example.test",
            "a.node.example.test"
        ));
        assert!(!dns_name_matches_host("*.example.test", "example.test"));
        assert!(!dns_name_matches_host(
            "shell.example.test",
            "other.example.test"
        ));
        assert!(!dns_name_matches_host(
            "s*.example.test",
            "shell.example.test"
        ));
    }

    #[test]
    fn san_verification_rejects_wrong_names_on_e2e_leaf_certificate() {
        // Use the bootstrap-generated leaf certificate when present; the
        // check is skipped otherwise so unit tests run on a clean checkout.
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        let cert_path = repo.join("target/e2e/server_cert.pem");
        if !cert_path.exists() {
            eprintln!("skipping: {} not present", cert_path.display());
            return;
        }
        let pem = std::fs::read(&cert_path).unwrap();
        let cert = X509::from_pem(&pem).unwrap();

        // A name that is definitely not in the SAN must be rejected.
        assert!(
            verify_server_certificate_name(&cert, "absolutely-not-a-san.invalid").is_err(),
            "a non-SAN name must fail verification"
        );

        // Every SAN entry in the bootstrap certificate must verify.
        let sans = cert.subject_alt_names().expect("e2e leaf has SAN");
        assert!(!sans.is_empty());
        for name in sans.iter() {
            let expected = name.dnsname().map(str::to_owned).or_else(|| {
                name.ipaddress().map(|raw| match raw.len() {
                    4 => std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string(),
                    16 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(raw);
                        std::net::Ipv6Addr::from(octets).to_string()
                    }
                    _ => unreachable!("IP SAN must be 4 or 16 bytes"),
                })
            });
            if let Some(expected) = expected {
                verify_server_certificate_name(&cert, &expected)
                    .unwrap_or_else(|error| panic!("SAN {expected:?} must verify, got: {error}"));
            }
        }
    }

    #[test]
    fn deny_policy_does_not_enroll_unknown_host() {
        let home = temp_home("known-hosts-deny");
        let key = Ed25519Keypair::from_seed([9; 32]).unwrap();
        let spki = key.public_key().to_spki_der();
        let configured = Path::new("~/.ssx/known_hosts");

        assert!(check_or_trust_host(
            &home,
            configured,
            "example.test:22",
            &spki,
            KnownHostsPolicy::Deny,
            0,
        )
        .is_err());
        assert!(!home.join(".ssx/known_hosts").exists());
        std::fs::remove_dir_all(home).unwrap();
    }
}
