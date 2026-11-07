use boring::asn1::{Asn1Integer, Asn1Time};
use boring::bn::BigNum;
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::ssl::{
    PrivateKeyMethod, PrivateKeyMethodError, SslContextBuilder, SslMethod, SslRef,
    SslSignatureAlgorithm,
};
use boring::x509::{X509NameBuilder, X509};
use ssxpro_crypto::{
    auth_signing_bytes, constant_time_eq, parse_authorized_keys, Ed25519Keypair, Ed25519PublicKey,
    Ed25519Signature,
};
use ssxpro_proto::{
    decode_monitor_request, decode_monitor_response, encode_monitor_auth_request,
    encode_monitor_identity_response, encode_monitor_sign_request, encode_monitor_token_response,
    MonitorRequest, MonitorResponse, MAX_MONITOR_AUTH_FRAME, MAX_MONITOR_FRAME,
    MAX_MONITOR_RESPONSE, MAX_MONITOR_SIGN_INPUT, MAX_SESSION_TOKEN,
};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const IDENTITY_MESSAGE: u8 = 0x80;
const AUTH_CHECK_TIMEOUT: Duration = Duration::from_secs(3);

struct AuthCheck {
    user: String,
    public_key: [u8; 32],
    server_nonce: [u8; 32],
    client_nonce: [u8; 32],
    spki_hash: [u8; 32],
    signature: [u8; 64],
}

struct AuthCheckJob {
    request: AuthCheck,
    response: SyncSender<Option<crate::session::LoginIdentity>>,
}

pub struct AuthSettings {
    pub allow_root: bool,
    pub server_authorized_keys: PathBuf,
    pub authorized_keys_name: String,
    pub allow_insecure_permissions: bool,
}

#[derive(Clone)]
pub struct TlsIdentity {
    pub certificate_der: Vec<u8>,
    pub spki_der: Vec<u8>,
}

#[derive(Clone)]
pub struct IpcSigner {
    stream: Arc<Mutex<UnixStream>>,
    auth_stream: Arc<Mutex<UnixStream>>,
}

pub struct AuthorizedLogin {
    pub identity: crate::session::LoginIdentity,
    pub token: Vec<u8>,
}

impl IpcSigner {
    pub fn new(stream: UnixStream, auth_stream: UnixStream) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
            auth_stream: Arc::new(Mutex::new(auth_stream)),
        }
    }

    pub fn authorize(
        &self,
        user: &str,
        public_key: &[u8; 32],
        server_nonce: &[u8; 32],
        client_nonce: &[u8; 32],
        spki_hash: &[u8; 32],
        signature: &[u8; 64],
    ) -> io::Result<Option<AuthorizedLogin>> {
        let stream = self
            .auth_stream
            .lock()
            .map_err(|_| io::Error::other("monitor IPC lock poisoned"))?;
        let mut request = [0u8; MAX_MONITOR_AUTH_FRAME];
        let request_len = encode_monitor_auth_request(
            user,
            public_key,
            server_nonce,
            client_nonce,
            spki_hash,
            signature,
            &mut request,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid auth IPC request"))?;
        write_all_fd(stream.as_raw_fd(), &request[..request_len])?;
        let mut frame = [0u8; MAX_MONITOR_RESPONSE];
        read_exact_fd(stream.as_raw_fd(), &mut frame[..1])?;
        if frame[0] == 1 {
            return match decode_monitor_response(&frame[..1]) {
                Ok(MonitorResponse::AuthDenied) => Ok(None),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid monitor response",
                )),
            };
        }
        if frame[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown monitor response type",
            ));
        }
        read_exact_fd(stream.as_raw_fd(), &mut frame[1..17])?;
        let name_len = usize::from(u16::from_be_bytes([frame[1], frame[2]]));
        let home_len = usize::from(u16::from_be_bytes([frame[11], frame[12]]));
        let shell_len = usize::from(u16::from_be_bytes([frame[13], frame[14]]));
        let group_count = usize::from(u16::from_be_bytes([frame[15], frame[16]]));
        let total = 17usize
            .checked_add(name_len)
            .and_then(|n| n.checked_add(home_len))
            .and_then(|n| n.checked_add(shell_len))
            .and_then(|n| n.checked_add(group_count.checked_mul(4)?))
            .filter(|n| *n <= MAX_MONITOR_RESPONSE)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "oversized monitor response")
            })?;
        read_exact_fd(stream.as_raw_fd(), &mut frame[17..total])?;
        let identity = match decode_monitor_response(&frame[..total])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid monitor response"))?
        {
            MonitorResponse::LoginIdentity {
                name,
                uid,
                gid,
                home,
                shell,
                groups,
            } => {
                let (group_chunks, remainder) = groups.as_chunks::<4>();
                debug_assert!(remainder.is_empty());
                crate::session::LoginIdentity {
                    name: name.to_owned(),
                    uid,
                    gid,
                    home: home.into(),
                    shell: shell.into(),
                    supplementary_groups: group_chunks
                        .iter()
                        .map(|chunk| u32::from_be_bytes(*chunk))
                        .collect(),
                }
            }
            MonitorResponse::AuthDenied | MonitorResponse::LoginToken { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid monitor identity response",
                ));
            }
        };
        let mut token_header = [0u8; 3];
        read_exact_fd(stream.as_raw_fd(), &mut token_header)?;
        if token_header[0] != 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "monitor did not send a session token",
            ));
        }
        let token_len = usize::from(u16::from_be_bytes([token_header[1], token_header[2]]));
        if token_len == 0 || token_len > MAX_SESSION_TOKEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid monitor session-token length",
            ));
        }
        let mut token = vec![0u8; token_len];
        read_exact_fd(stream.as_raw_fd(), &mut token)?;
        Ok(Some(AuthorizedLogin { identity, token }))
    }
}

impl PrivateKeyMethod for IpcSigner {
    fn sign(
        &self,
        _ssl: &mut SslRef,
        input: &[u8],
        signature_algorithm: SslSignatureAlgorithm,
        output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError> {
        if signature_algorithm != SslSignatureAlgorithm::ED25519 || output.len() < 64 {
            return Err(PrivateKeyMethodError::FAILURE);
        }
        let Ok(stream) = self.stream.lock() else {
            return Err(PrivateKeyMethodError::FAILURE);
        };
        let mut request = [0u8; MAX_MONITOR_FRAME];
        let request_len = encode_monitor_sign_request(input, &mut request)
            .map_err(|_| PrivateKeyMethodError::FAILURE)?;
        write_all_fd(stream.as_raw_fd(), &request[..request_len])
            .map_err(|_| PrivateKeyMethodError::FAILURE)?;

        let mut response = [0u8; 3];
        read_exact_fd(stream.as_raw_fd(), &mut response)
            .map_err(|_| PrivateKeyMethodError::FAILURE)?;
        let signature_len = usize::from(u16::from_be_bytes([response[1], response[2]]));
        if response[0] != 0 || signature_len != 64 {
            return Err(PrivateKeyMethodError::FAILURE);
        }
        read_exact_fd(stream.as_raw_fd(), &mut output[..signature_len])
            .map_err(|_| PrivateKeyMethodError::FAILURE)?;
        Ok(signature_len)
    }

    fn decrypt(
        &self,
        _ssl: &mut SslRef,
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError> {
        Err(PrivateKeyMethodError::FAILURE)
    }

    fn complete(
        &self,
        _ssl: &mut SslRef,
        _output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError> {
        Err(PrivateKeyMethodError::FAILURE)
    }
}

/// Construct only the public TLS identity. The private seed remains with the
/// caller and is not placed in the worker's SSL context.
pub fn identity_from_seed(mut seed: [u8; 32]) -> Result<TlsIdentity, Box<dyn std::error::Error>> {
    let pair_result = Ed25519Keypair::from_seed(seed);
    seed.zeroize();
    let pair = pair_result?;
    let private_der = pair.private_key_pkcs8_der();
    let private = boring::pkey::PKey::private_key_from_der(&private_der)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, "ssxpro")?;
    let name = name.build();
    let mut cert = X509::builder()?;
    cert.set_version(2)?;
    let serial_bn = BigNum::from_u32(1)?;
    let serial = Asn1Integer::from_bn(&serial_bn)?;
    cert.set_serial_number(&serial)?;
    cert.set_subject_name(&name)?;
    cert.set_issuer_name(&name)?;
    cert.set_pubkey(&private)?;
    let start = Asn1Time::days_from_now(0)?;
    let end = Asn1Time::days_from_now(365)?;
    cert.set_not_before(&start)?;
    cert.set_not_after(&end)?;
    // SAFETY: BoringSSL's X509_sign requires a null digest for Ed25519.
    let ed25519_digest = unsafe { MessageDigest::from_ptr(std::ptr::null()) };
    cert.sign(&private, ed25519_digest)?;
    let cert = cert.build();
    let spki_der = cert.public_key()?.public_key_to_der()?;
    Ok(TlsIdentity {
        certificate_der: cert.to_der()?,
        spki_der,
    })
}

pub fn server_config_with_signer(
    identity: &TlsIdentity,
    signer: IpcSigner,
    idle_timeout_ms: u64,
) -> Result<(quiche::Config, Vec<u8>), Box<dyn std::error::Error>> {
    let certificate = X509::from_der(&identity.certificate_der)?;
    let mut ssl = SslContextBuilder::new(SslMethod::tls())?;
    ssl.set_certificate(&certificate)?;
    ssl.set_private_key_method(signer);
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl)?;
    config.set_application_protos(&[ssxpro_proto::ALPN])?;
    config.set_max_idle_timeout(idle_timeout_ms);
    config.set_initial_max_data(4 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(1024 * 1024);
    config.set_initial_max_streams_bidi(8);
    Ok((config, identity.spki_der.clone()))
}

/// The monitor side of the private-key and login-authorization IPC. The public
/// identity is sent once; all subsequent messages are bounded and validated.
pub fn serve_signing_requests(
    stream: UnixStream,
    auth_stream: UnixStream,
    mut seed: Zeroizing<[u8; 32]>,
    settings: AuthSettings,
    token_secret: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let token_secret = Zeroizing::new(token_secret);
    let identity = identity_from_seed(*seed)?;
    let cert_len = u32::try_from(identity.certificate_der.len())?;
    let spki_len = u16::try_from(identity.spki_der.len())?;
    write_all_fd(stream.as_raw_fd(), &[IDENTITY_MESSAGE])?;
    write_all_fd(stream.as_raw_fd(), &cert_len.to_be_bytes())?;
    write_all_fd(stream.as_raw_fd(), &spki_len.to_be_bytes())?;
    write_all_fd(stream.as_raw_fd(), &identity.certificate_der)?;
    write_all_fd(stream.as_raw_fd(), &identity.spki_der)?;

    let mut signing_seed = *seed;
    let pair_result = Ed25519Keypair::from_seed(signing_seed);
    signing_seed.zeroize();
    let pair = pair_result?;
    // `_exit` bypasses Rust destructors, so clear the inherited host seed now.
    seed.zeroize();
    if settings.authorized_keys_name.is_empty()
        || settings.authorized_keys_name.contains('/')
        || settings.authorized_keys_name == "."
        || settings.authorized_keys_name == ".."
    {
        return Err("authorized_keys must be a basename".into());
    }
    let (auth_sender, auth_receiver) = mpsc::sync_channel::<AuthCheckJob>(8);
    spawn_auth_check_thread(auth_receiver, settings)?;
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("ssxd-monitor-auth".to_owned())
        .spawn(move || {
            // Set no_new_privs before the monitor applies its TSYNC filter.
            let ready = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0;
            let _ = ready_sender.send(ready);
            if !ready {
                return;
            }
            let stream = auth_stream;
            let _ = (|| -> Result<(), Box<dyn std::error::Error>> {
                loop {
                    let mut first = [0u8; 1];
                    read_exact_fd(stream.as_raw_fd(), &mut first)?;
                    if first[0] != 2 {
                        return Err("invalid auth request".into());
                    }

                    let mut frame = [0u8; MAX_MONITOR_AUTH_FRAME];
                    frame[0] = 2;
                    read_exact_fd(stream.as_raw_fd(), &mut frame[1..3])?;
                    let user_len = usize::from(u16::from_be_bytes([frame[1], frame[2]]));
                    if user_len == 0 || user_len > ssxpro_proto::MAX_MONITOR_USER {
                        return Err("invalid authentication IPC frame".into());
                    }
                    let frame_len = 3 + user_len + 32 * 4 + 64;
                    read_exact_fd(stream.as_raw_fd(), &mut frame[3..frame_len])?;
                    let request = decode_monitor_request(&frame[..frame_len])
                        .map_err(|_| "invalid authentication IPC frame")?;
                    let MonitorRequest::Authenticate {
                        user,
                        public_key,
                        server_nonce,
                        client_nonce,
                        spki_hash,
                        signature,
                    } = request
                    else {
                        return Err("invalid authentication IPC type".into());
                    };
                    let (response_sender, response_receiver) = mpsc::sync_channel(1);
                    let check = AuthCheckJob {
                        request: AuthCheck {
                            user: user.to_owned(),
                            public_key,
                            server_nonce,
                            client_nonce,
                            spki_hash,
                            signature,
                        },
                        response: response_sender,
                    };
                    let identity = match auth_sender.try_send(check) {
                        Ok(()) => response_receiver
                            .recv_timeout(AUTH_CHECK_TIMEOUT)
                            .unwrap_or(None),
                        Err(_) => None,
                    };
                    if let Some(identity) = identity {
                        let token = match crate::ipc::mint_session_token(&token_secret, &identity) {
                            Ok(token) => token,
                            Err(_) => {
                                write_all_fd(stream.as_raw_fd(), &[1])?;
                                continue;
                            }
                        };
                        if write_login_identity(stream.as_raw_fd(), &identity).is_err() {
                            write_all_fd(stream.as_raw_fd(), &[1])?;
                        } else {
                            write_session_token(stream.as_raw_fd(), &token)?;
                        }
                    } else {
                        write_all_fd(stream.as_raw_fd(), &[1])?;
                    }
                }
            })();
        })?;
    if !ready_receiver.recv().unwrap_or(false) {
        return Err("could not restrict authorization thread".into());
    }
    ssxpro_io::sandbox_tls_monitor()?;
    loop {
        let mut first = [0u8; 1];
        match read_once_fd(stream.as_raw_fd(), &mut first) {
            Ok(0) => return Ok(()),
            Ok(1) => {}
            Ok(_) => unreachable!("one-byte read cannot exceed buffer"),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Box::new(error)),
        }
        match first[0] {
            1 => {
                let mut frame = [0u8; MAX_MONITOR_FRAME];
                frame[0] = 1;
                read_exact_fd(stream.as_raw_fd(), &mut frame[1..7])?;
                let length = u32::from_be_bytes(frame[3..7].try_into()?) as usize;
                if length > MAX_MONITOR_SIGN_INPUT {
                    return Err("invalid TLS signing IPC frame".into());
                }
                read_exact_fd(stream.as_raw_fd(), &mut frame[7..7 + length])?;
                let request = decode_monitor_request(&frame[..7 + length])
                    .map_err(|_| "invalid TLS signing IPC frame")?;
                let MonitorRequest::TlsEd25519Sign { input } = request else {
                    return Err("invalid TLS signing IPC type".into());
                };
                match pair.sign(input) {
                    Ok(Ed25519Signature(signature)) => {
                        write_all_fd(stream.as_raw_fd(), &[0, 0, 64])?;
                        write_all_fd(stream.as_raw_fd(), &signature)?;
                    }
                    Err(_) => write_all_fd(stream.as_raw_fd(), &[1, 0, 0])?,
                }
            }
            _ => return Err("unknown monitor IPC request".into()),
        }
    }
}

fn spawn_auth_check_thread(
    receiver: Receiver<AuthCheckJob>,
    settings: AuthSettings,
) -> io::Result<()> {
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("ssxd-monitor-nss".to_owned())
        .spawn(move || {
            // Set the privilege-restriction prerequisite in the helper before
            // the parent installs a TSYNC seccomp filter.
            // SAFETY: PR_SET_NO_NEW_PRIVS uses scalar arguments only.
            let ready = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0;
            let _ = ready_sender.send(ready);
            if !ready {
                return;
            }
            while let Ok(job) = receiver.recv() {
                let identity = verify_login_request(job.request, &settings);
                let _ = job.response.send(identity);
            }
        })?;
    if !ready_receiver.recv().unwrap_or(false) {
        return Err(io::Error::other(
            "could not restrict monitor NSS helper privileges",
        ));
    }
    Ok(())
}

const MAX_AUTHORIZED_KEYS_BYTES: usize = 1024 * 1024;

fn parse_keys_file(path: &Path, bytes: &[u8]) -> Result<Vec<Ed25519PublicKey>, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| format!("{}: not valid UTF-8", path.display()))?;
    parse_authorized_keys(text).map_err(|error| format!("{}: {error}", path.display()))
}

/// Load the server-wide key list configured in `ssxd.yaml`. `Ok(None)` means
/// the setting is empty or the file does not exist (both are non-fatal).
fn load_server_authorized_keys(
    path: &Path,
    allow_insecure_permissions: bool,
) -> Result<Option<Vec<Ed25519PublicKey>>, String> {
    if path.as_os_str().is_empty() {
        return Ok(None);
    }
    let read = if allow_insecure_permissions {
        ssxpro_crypto::read_server_file_allow_insecure(path, MAX_AUTHORIZED_KEYS_BYTES)
    } else {
        ssxpro_crypto::read_server_file(path, MAX_AUTHORIZED_KEYS_BYTES)
    };
    match read {
        Ok(bytes) => Ok(Some(parse_keys_file(path, &bytes)?)),
        Err(ssxpro_crypto::CryptoError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Load the per-user key list at `$HOME/.ssx/<name>`. Missing or insecure
/// files are errors (and therefore deny the login).
fn load_user_authorized_keys(
    home: &Path,
    owner_uid: u32,
    name: &str,
    allow_insecure_permissions: bool,
) -> Result<Vec<Ed25519PublicKey>, String> {
    let path = home.join(".ssx").join(name);
    let read = if allow_insecure_permissions {
        ssxpro_crypto::read_user_file_as_allow_insecure(
            home,
            owner_uid,
            name,
            MAX_AUTHORIZED_KEYS_BYTES,
        )
    } else {
        ssxpro_crypto::read_user_file_as(home, owner_uid, name, MAX_AUTHORIZED_KEYS_BYTES)
    };
    let bytes = read.map_err(|error| format!("{}: {error}", path.display()))?;
    parse_keys_file(&path, &bytes)
}

fn verify_login_request(
    request: AuthCheck,
    settings: &AuthSettings,
) -> Option<crate::session::LoginIdentity> {
    // The peer only ever sees the coarse AuthFail/close; the specific reason is
    // a local log line for the operator (SPEC.md: details are logged locally by
    // the monitor). Escape the attacker-controlled name so it cannot inject
    // control characters or newlines into the log stream.
    let user = request.user.escape_default().to_string();
    let result = || -> Result<Option<crate::session::LoginIdentity>, Box<dyn std::error::Error>> {
        let identity = crate::session::lookup_login_identity(&request.user, settings.allow_root)?;
        let presented = Ed25519PublicKey(request.public_key);
        // Server-wide keys from ssxd.yaml are checked first; the per-user
        // file is only consulted when the server-wide list does not match.
        let server_match = match load_server_authorized_keys(
            &settings.server_authorized_keys,
            settings.allow_insecure_permissions,
        )? {
            Some(keys) => keys
                .iter()
                .any(|key| constant_time_eq(&key.0, &presented.0)),
            None => false,
        };
        if !server_match {
            let trusted = load_user_authorized_keys(
                &identity.home,
                identity.uid,
                &settings.authorized_keys_name,
                settings.allow_insecure_permissions,
            )?;
            if !trusted
                .iter()
                .any(|key| constant_time_eq(&key.0, &presented.0))
            {
                eprintln!(
                    "ssxd: monitor: auth denied for user '{user}': \
                     public key is not listed in authorized_keys"
                );
                return Ok(None);
            }
        }
        let input = auth_signing_bytes(
            &request.server_nonce,
            &request.client_nonce,
            &request.spki_hash,
            request.user.as_bytes(),
            &presented,
        )?;
        if presented.verify(&input, &Ed25519Signature(request.signature))? {
            Ok(Some(identity))
        } else {
            eprintln!(
                "ssxd: monitor: auth denied for user '{user}': \
                 Ed25519 signature verification failed"
            );
            Ok(None)
        }
    };
    match result() {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("ssxd: monitor: auth denied for user '{user}': {error}");
            None
        }
    }
}

fn write_login_identity(
    fd: libc::c_int,
    identity: &crate::session::LoginIdentity,
) -> io::Result<()> {
    let home = identity.home.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "monitor home path is not UTF-8")
    })?;
    let shell = identity.shell.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "monitor shell path is not UTF-8",
        )
    })?;
    let mut frame = [0u8; MAX_MONITOR_RESPONSE];
    let length = encode_monitor_identity_response(
        &identity.name,
        identity.uid,
        identity.gid,
        home,
        shell,
        &identity.supplementary_groups,
        &mut frame,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "login identity exceeds limits"))?;
    write_all_fd(fd, &frame[..length])
}

fn write_session_token(fd: libc::c_int, token: &[u8]) -> io::Result<()> {
    let mut frame = [0u8; MAX_MONITOR_RESPONSE];
    let length = encode_monitor_token_response(token, &mut frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "session token exceeds limits"))?;
    write_all_fd(fd, &frame[..length])
}

pub fn read_signing_identity(
    stream: &mut UnixStream,
) -> Result<TlsIdentity, Box<dyn std::error::Error>> {
    let mut header = [0u8; 7];
    read_exact_fd(stream.as_raw_fd(), &mut header)?;
    if header[0] != IDENTITY_MESSAGE {
        return Err("monitor sent an invalid TLS identity frame".into());
    }
    let cert_len = u32::from_be_bytes(header[1..5].try_into()?) as usize;
    let spki_len = usize::from(u16::from_be_bytes([header[5], header[6]]));
    if cert_len > 16 * 1024 || spki_len > 4096 {
        return Err("monitor TLS identity frame exceeds limits".into());
    }
    let mut certificate_der = vec![0u8; cert_len];
    let mut spki_der = vec![0u8; spki_len];
    read_exact_fd(stream.as_raw_fd(), &mut certificate_der)?;
    read_exact_fd(stream.as_raw_fd(), &mut spki_der)?;
    let certificate = X509::from_der(&certificate_der)?;
    if certificate.public_key()?.public_key_to_der()? != spki_der {
        return Err("monitor certificate and SPKI disagree".into());
    }
    Ok(TlsIdentity {
        certificate_der,
        spki_der,
    })
}

fn read_once_fd(fd: libc::c_int, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: buffer is writable for its declared length and fd remains owned by UnixStream.
        let result = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if result >= 0 {
            return Ok(result as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn read_exact_fd(fd: libc::c_int, mut buffer: &mut [u8]) -> io::Result<()> {
    while !buffer.is_empty() {
        match read_once_fd(fd, buffer)? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            length => buffer = &mut buffer[length..],
        }
    }
    Ok(())
}

fn write_all_fd(fd: libc::c_int, mut buffer: &[u8]) -> io::Result<()> {
    while !buffer.is_empty() {
        // SAFETY: buffer is readable for its declared length and fd remains owned by UnixStream.
        let result = unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) };
        if result > 0 {
            buffer = &buffer[result as usize..];
            continue;
        }
        if result == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_authorization_does_not_lock_signing_channel() {
        let (signing, _signing_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (auth, _auth_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let signer = super::IpcSigner::new(signing, auth);
        let _pending_authorization = signer.auth_stream.lock().unwrap();
        assert!(signer.stream.try_lock().is_ok());
    }

    #[test]
    fn makes_a_certificate_from_the_host_seed() {
        let identity = identity_from_seed([7; 32]).unwrap();
        assert!(!identity.certificate_der.is_empty());
        assert!(!identity.spki_der.is_empty());
    }

    #[test]
    fn authorized_keys_sources_load_server_then_user() {
        use std::os::unix::fs::PermissionsExt;
        const SERVER_KEY: &str = "ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
        const USER_KEY: &str = "ed25519 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n";

        let base = std::env::temp_dir().join(format!("ssxpro-auth-sources-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        std::fs::create_dir_all(home.join(".ssx")).unwrap();
        for dir in [&base, &home, &home.join(".ssx")] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let server_path = base.join("server_authorized_keys");
        std::fs::write(&server_path, SERVER_KEY).unwrap();
        std::fs::set_permissions(&server_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Server-wide file: loaded when configured, skipped when absent or empty.
        let server = load_server_authorized_keys(&server_path, false)
            .unwrap()
            .unwrap();
        assert_eq!(server.len(), 1);
        assert_eq!(server[0].0, [0u8; 32]);
        assert!(load_server_authorized_keys(&base.join("missing"), false)
            .unwrap()
            .is_none());
        assert!(load_server_authorized_keys(Path::new(""), false)
            .unwrap()
            .is_none());

        // Per-user file: loaded from $HOME/.ssx/<name> with strict metadata.
        std::fs::write(home.join(".ssx/authorized_keys"), USER_KEY).unwrap();
        std::fs::set_permissions(
            home.join(".ssx/authorized_keys"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        // SAFETY: geteuid has no arguments or side effects.
        let uid = unsafe { libc::geteuid() };
        let user = load_user_authorized_keys(&home, uid, "authorized_keys", false).unwrap();
        assert_eq!(user.len(), 1);
        assert_eq!(user[0].0, [1u8; 32]);
        assert!(load_user_authorized_keys(&home, uid, "missing", false).is_err());

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn authorized_keys_allow_insecure_skips_permission_checks() {
        use std::os::unix::fs::PermissionsExt;
        const SERVER_KEY: &str = "ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
        const USER_KEY: &str = "ed25519 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n";

        let base =
            std::env::temp_dir().join(format!("ssxpro-auth-insecure-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        std::fs::create_dir_all(home.join(".ssx")).unwrap();
        // Permissive directories and files that the strict checks reject.
        for dir in [&base, &home, &home.join(".ssx")] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let server_path = base.join("server_authorized_keys");
        std::fs::write(&server_path, SERVER_KEY).unwrap();
        std::fs::set_permissions(&server_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_server_authorized_keys(&server_path, false).is_err());
        let server = load_server_authorized_keys(&server_path, true)
            .unwrap()
            .unwrap();
        assert_eq!(server.len(), 1);

        let user_path = home.join(".ssx/authorized_keys");
        std::fs::write(&user_path, USER_KEY).unwrap();
        std::fs::set_permissions(&user_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        // SAFETY: geteuid has no arguments or side effects.
        let uid = unsafe { libc::geteuid() };
        assert!(load_user_authorized_keys(&home, uid, "authorized_keys", false).is_err());
        let user = load_user_authorized_keys(&home, uid, "authorized_keys", true).unwrap();
        assert_eq!(user.len(), 1);

        std::fs::remove_dir_all(&base).unwrap();
    }
}
