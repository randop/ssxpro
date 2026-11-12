#![forbid(unsafe_code)]

//! Bounded sans-I/O control protocol codec and role state machines.

pub const MAX_FRAME: usize = 4096;
pub const MAX_WIRE_FRAME: usize = MAX_FRAME + 10;
pub const ALPN: &[u8] = b"ssxpro/2";
pub const MAX_MONITOR_SIGN_INPUT: usize = 8192;
pub const MAX_MONITOR_FRAME: usize = 7 + MAX_MONITOR_SIGN_INPUT;
pub const MAX_MONITOR_USER: usize = 256;
pub const MAX_MONITOR_AUTH_FRAME: usize = 1 + 2 + MAX_MONITOR_USER + 32 * 4 + 64;
pub const MAX_MONITOR_IDENTITY_PATH: usize = 4096;
pub const MAX_MONITOR_IDENTITY_GROUPS: usize = 1024;
pub const SESSION_TOKEN_MAGIC: &[u8; 4] = b"SSX1";
pub const SESSION_TOKEN_NONCE_LEN: usize = 16;
pub const SESSION_TOKEN_MAC_LEN: usize = 32;
pub const MAX_SESSION_TOKEN: usize = 52
    + SESSION_TOKEN_MAC_LEN
    + MAX_MONITOR_USER
    + 2 * MAX_MONITOR_IDENTITY_PATH
    + 4 * MAX_MONITOR_IDENTITY_GROUPS;
pub const MAX_MONITOR_IDENTITY_RESPONSE: usize =
    17 + MAX_MONITOR_USER + 2 * MAX_MONITOR_IDENTITY_PATH + 4 * MAX_MONITOR_IDENTITY_GROUPS;
pub const MAX_MONITOR_RESPONSE: usize = 3 + MAX_SESSION_TOKEN;
pub const MAX_BROKER_TERM: usize = 64;
pub const MAX_BROKER_FRAME: usize = 16 * 1024;
pub const MAX_TERMINAL_DIMENSION: u16 = 4096;

/// Client feature bit: supports LZ4 framed stream compression.
pub const FEATURE_COMPRESSION_LZ4: u32 = 1 << 0;
/// Client feature bit: supports Snappy framed stream compression.
pub const FEATURE_COMPRESSION_SNAPPY: u32 = 1 << 1;
/// Client feature bit: supports Zstd framed stream compression.
pub const FEATURE_COMPRESSION_ZSTD: u32 = 1 << 2;
/// Every feature bit understood by protocol version 1.
pub const SUPPORTED_FEATURES: u32 =
    FEATURE_COMPRESSION_LZ4 | FEATURE_COMPRESSION_SNAPPY | FEATURE_COMPRESSION_ZSTD;

/// Compression selected by the server in `AuthChallenge`. The server
/// configuration is authoritative; the client only advertises which algorithms
/// its build supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Compression {
    Off = 0,
    /// LZ4, optimized for low CPU utilization.
    Fast = 1,
    /// Snappy.
    Standard = 2,
    /// Zstd level 19.
    High = 3,
}

impl Compression {
    pub const fn feature_bit(self) -> u32 {
        match self {
            Self::Off => 0,
            Self::Fast => FEATURE_COMPRESSION_LZ4,
            Self::Standard => FEATURE_COMPRESSION_SNAPPY,
            Self::High => FEATURE_COMPRESSION_ZSTD,
        }
    }

    pub fn is_supported_by(self, features: u32) -> bool {
        self == Self::Off || features & self.feature_bit() != 0
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Off,
            1 => Self::Fast,
            2 => Self::Standard,
            3 => Self::High,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorFrameError {
    Truncated,
    UnknownType,
    UnsupportedAlgorithm,
    Oversize,
    LengthMismatch,
    InvalidUser,
}

impl std::fmt::Display for MonitorFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated monitor frame",
            Self::UnknownType => "unknown monitor frame type",
            Self::UnsupportedAlgorithm => "unsupported monitor frame algorithm",
            Self::Oversize => "monitor frame exceeds maximum size",
            Self::LengthMismatch => "monitor frame length mismatch",
            Self::InvalidUser => "invalid monitor frame payload",
        })
    }
}
impl std::error::Error for MonitorFrameError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorRequest<'a> {
    TlsEd25519Sign {
        input: &'a [u8],
    },
    Authenticate {
        user: &'a str,
        public_key: [u8; 32],
        server_nonce: [u8; 32],
        client_nonce: [u8; 32],
        spki_hash: [u8; 32],
        signature: [u8; 64],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorResponse<'a> {
    AuthDenied,
    LoginIdentity {
        name: &'a str,
        uid: u32,
        gid: u32,
        home: &'a str,
        shell: &'a str,
        groups: &'a [u8],
    },
    LoginToken {
        token: &'a [u8],
    },
}

pub fn decode_monitor_response(frame: &[u8]) -> Result<MonitorResponse<'_>, MonitorFrameError> {
    if frame.is_empty() {
        return Err(MonitorFrameError::Truncated);
    }
    match frame[0] {
        1 if frame.len() == 1 => return Ok(MonitorResponse::AuthDenied),
        1 => return Err(MonitorFrameError::LengthMismatch),
        3 => {
            if frame.len() < 3 {
                return Err(MonitorFrameError::Truncated);
            }
            let token_len = usize::from(u16::from_be_bytes([frame[1], frame[2]]));
            if token_len == 0 || token_len > MAX_SESSION_TOKEN {
                return Err(MonitorFrameError::Oversize);
            }
            if frame.len() < 3 + token_len {
                return Err(MonitorFrameError::Truncated);
            }
            if frame.len() != 3 + token_len {
                return Err(MonitorFrameError::LengthMismatch);
            }
            return Ok(MonitorResponse::LoginToken { token: &frame[3..] });
        }
        0 => {}
        _ => return Err(MonitorFrameError::UnknownType),
    }
    if frame.len() < 17 {
        return Err(MonitorFrameError::Truncated);
    }
    if frame.len() > MAX_MONITOR_IDENTITY_RESPONSE {
        return Err(MonitorFrameError::Oversize);
    }
    let name_len = usize::from(u16::from_be_bytes([frame[1], frame[2]]));
    let uid = u32::from_be_bytes(frame[3..7].try_into().expect("four-byte uid"));
    let gid = u32::from_be_bytes(frame[7..11].try_into().expect("four-byte gid"));
    let home_len = usize::from(u16::from_be_bytes([frame[11], frame[12]]));
    let shell_len = usize::from(u16::from_be_bytes([frame[13], frame[14]]));
    let group_count = usize::from(u16::from_be_bytes([frame[15], frame[16]]));
    if name_len == 0
        || name_len > MAX_MONITOR_USER
        || home_len == 0
        || home_len > MAX_MONITOR_IDENTITY_PATH
        || shell_len == 0
        || shell_len > MAX_MONITOR_IDENTITY_PATH
        || group_count > MAX_MONITOR_IDENTITY_GROUPS
    {
        return Err(MonitorFrameError::Oversize);
    }
    let expected = 17 + name_len + home_len + shell_len + group_count * 4;
    if frame.len() < expected {
        return Err(MonitorFrameError::Truncated);
    }
    if frame.len() != expected {
        return Err(MonitorFrameError::LengthMismatch);
    }
    let mut offset = 17;
    let name = std::str::from_utf8(&frame[offset..offset + name_len])
        .map_err(|_| MonitorFrameError::InvalidUser)?;
    offset += name_len;
    if name
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return Err(MonitorFrameError::InvalidUser);
    }
    let home = std::str::from_utf8(&frame[offset..offset + home_len])
        .map_err(|_| MonitorFrameError::InvalidUser)?;
    offset += home_len;
    let shell = std::str::from_utf8(&frame[offset..offset + shell_len])
        .map_err(|_| MonitorFrameError::InvalidUser)?;
    offset += shell_len;
    if !std::path::Path::new(home).is_absolute() || !std::path::Path::new(shell).is_absolute() {
        return Err(MonitorFrameError::InvalidUser);
    }
    Ok(MonitorResponse::LoginIdentity {
        name,
        uid,
        gid,
        home,
        shell,
        groups: &frame[offset..],
    })
}

pub fn encode_monitor_identity_response(
    name: &str,
    uid: u32,
    gid: u32,
    home: &str,
    shell: &str,
    groups: &[u32],
    output: &mut [u8],
) -> Result<usize, MonitorFrameError> {
    if name.is_empty()
        || name.len() > MAX_MONITOR_USER
        || name
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return Err(MonitorFrameError::InvalidUser);
    }
    if home.is_empty()
        || home.len() > MAX_MONITOR_IDENTITY_PATH
        || shell.is_empty()
        || shell.len() > MAX_MONITOR_IDENTITY_PATH
        || groups.len() > MAX_MONITOR_IDENTITY_GROUPS
        || !std::path::Path::new(home).is_absolute()
        || !std::path::Path::new(shell).is_absolute()
    {
        return Err(MonitorFrameError::Oversize);
    }
    let length = 17 + name.len() + home.len() + shell.len() + groups.len() * 4;
    if output.len() < length {
        return Err(MonitorFrameError::Truncated);
    }
    output[0] = 0;
    output[1..3].copy_from_slice(&(name.len() as u16).to_be_bytes());
    output[3..7].copy_from_slice(&uid.to_be_bytes());
    output[7..11].copy_from_slice(&gid.to_be_bytes());
    output[11..13].copy_from_slice(&(home.len() as u16).to_be_bytes());
    output[13..15].copy_from_slice(&(shell.len() as u16).to_be_bytes());
    output[15..17].copy_from_slice(&(groups.len() as u16).to_be_bytes());
    let mut offset = 17;
    for field in [name.as_bytes(), home.as_bytes(), shell.as_bytes()] {
        output[offset..offset + field.len()].copy_from_slice(field);
        offset += field.len();
    }
    for group in groups {
        output[offset..offset + 4].copy_from_slice(&group.to_be_bytes());
        offset += 4;
    }
    Ok(length)
}

/// Decode the complete bounded monitor request frame:
/// `type:u8, algorithm:u16be, length:u32be, input[length]`.
pub fn decode_monitor_request(frame: &[u8]) -> Result<MonitorRequest<'_>, MonitorFrameError> {
    if frame.is_empty() {
        return Err(MonitorFrameError::Truncated);
    }
    if frame[0] == 2 {
        if frame.len() < 3 {
            return Err(MonitorFrameError::Truncated);
        }
        let user_len = usize::from(u16::from_be_bytes([frame[1], frame[2]]));
        if user_len == 0 || user_len > MAX_MONITOR_USER {
            return Err(MonitorFrameError::InvalidUser);
        }
        let expected = 3 + user_len + 32 * 4 + 64;
        if frame.len() < expected {
            return Err(MonitorFrameError::Truncated);
        }
        if frame.len() != expected {
            return Err(MonitorFrameError::LengthMismatch);
        }
        let user = std::str::from_utf8(&frame[3..3 + user_len])
            .map_err(|_| MonitorFrameError::InvalidUser)?;
        if user
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_whitespace())
        {
            return Err(MonitorFrameError::InvalidUser);
        }
        let mut offset = 3 + user_len;
        let public_key = take_monitor_array::<32>(frame, &mut offset);
        let server_nonce = take_monitor_array::<32>(frame, &mut offset);
        let client_nonce = take_monitor_array::<32>(frame, &mut offset);
        let spki_hash = take_monitor_array::<32>(frame, &mut offset);
        let signature = take_monitor_array::<64>(frame, &mut offset);
        return Ok(MonitorRequest::Authenticate {
            user,
            public_key,
            server_nonce,
            client_nonce,
            spki_hash,
            signature,
        });
    }
    if frame.len() < 7 {
        return Err(MonitorFrameError::Truncated);
    }
    if frame[0] != 1 {
        return Err(MonitorFrameError::UnknownType);
    }
    if u16::from_be_bytes([frame[1], frame[2]]) != 1 {
        return Err(MonitorFrameError::UnsupportedAlgorithm);
    }
    let length = u32::from_be_bytes(frame[3..7].try_into().expect("four-byte field")) as usize;
    if length > MAX_MONITOR_SIGN_INPUT {
        return Err(MonitorFrameError::Oversize);
    }
    if frame.len() != 7 + length {
        return Err(MonitorFrameError::LengthMismatch);
    }
    Ok(MonitorRequest::TlsEd25519Sign { input: &frame[7..] })
}

fn take_monitor_array<const N: usize>(frame: &[u8], offset: &mut usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&frame[*offset..*offset + N]);
    *offset += N;
    value
}

pub fn encode_monitor_auth_request(
    user: &str,
    public_key: &[u8; 32],
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
    spki_hash: &[u8; 32],
    signature: &[u8; 64],
    output: &mut [u8],
) -> Result<usize, MonitorFrameError> {
    if user.is_empty()
        || user.len() > MAX_MONITOR_USER
        || user.bytes().any(|b| b == 0 || b.is_ascii_whitespace())
    {
        return Err(MonitorFrameError::InvalidUser);
    }
    let length = 3 + user.len() + 32 * 4 + 64;
    if output.len() < length {
        return Err(MonitorFrameError::Truncated);
    }
    output[0] = 2;
    output[1..3].copy_from_slice(&(user.len() as u16).to_be_bytes());
    let mut offset = 3;
    output[offset..offset + user.len()].copy_from_slice(user.as_bytes());
    offset += user.len();
    for field in [
        public_key.as_slice(),
        server_nonce.as_slice(),
        client_nonce.as_slice(),
        spki_hash.as_slice(),
        signature.as_slice(),
    ] {
        output[offset..offset + field.len()].copy_from_slice(field);
        offset += field.len();
    }
    Ok(length)
}

pub fn encode_monitor_sign_request(
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, MonitorFrameError> {
    if input.len() > MAX_MONITOR_SIGN_INPUT {
        return Err(MonitorFrameError::Oversize);
    }
    let length = 7 + input.len();
    if output.len() < length {
        return Err(MonitorFrameError::Truncated);
    }
    output[0] = 1;
    output[1..3].copy_from_slice(&1u16.to_be_bytes());
    output[3..7].copy_from_slice(&(input.len() as u32).to_be_bytes());
    output[7..length].copy_from_slice(input);
    Ok(length)
}

pub fn encode_monitor_token_response(
    token: &[u8],
    output: &mut [u8],
) -> Result<usize, MonitorFrameError> {
    if token.is_empty() || token.len() > MAX_SESSION_TOKEN {
        return Err(MonitorFrameError::Oversize);
    }
    let length = 3 + token.len();
    if output.len() < length {
        return Err(MonitorFrameError::Truncated);
    }
    output[0] = 3;
    output[1..3].copy_from_slice(&(token.len() as u16).to_be_bytes());
    output[3..length].copy_from_slice(token);
    Ok(length)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionToken<'a> {
    pub nonce: [u8; SESSION_TOKEN_NONCE_LEN],
    pub issued_at: u64,
    pub expires_at: u64,
    pub name: &'a str,
    pub uid: u32,
    pub gid: u32,
    pub home: &'a str,
    pub shell: &'a str,
    pub groups: &'a [u8],
    pub mac: &'a [u8],
}

#[allow(clippy::too_many_arguments)] // Wire encoder mirrors the flat token layout.
pub fn encode_session_token(
    nonce: &[u8; SESSION_TOKEN_NONCE_LEN],
    issued_at: u64,
    expires_at: u64,
    name: &str,
    uid: u32,
    gid: u32,
    home: &str,
    shell: &str,
    groups: &[u32],
    mac: &[u8; SESSION_TOKEN_MAC_LEN],
    output: &mut [u8],
) -> Result<usize, MonitorFrameError> {
    if name.is_empty()
        || name.len() > MAX_MONITOR_USER
        || name
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return Err(MonitorFrameError::InvalidUser);
    }
    if home.is_empty()
        || home.len() > MAX_MONITOR_IDENTITY_PATH
        || shell.is_empty()
        || shell.len() > MAX_MONITOR_IDENTITY_PATH
        || groups.len() > MAX_MONITOR_IDENTITY_GROUPS
        || !std::path::Path::new(home).is_absolute()
        || !std::path::Path::new(shell).is_absolute()
    {
        return Err(MonitorFrameError::Oversize);
    }
    let length =
        52 + name.len() + home.len() + shell.len() + groups.len() * 4 + SESSION_TOKEN_MAC_LEN;
    if output.len() < length {
        return Err(MonitorFrameError::Truncated);
    }
    output[..4].copy_from_slice(SESSION_TOKEN_MAGIC);
    output[4..20].copy_from_slice(nonce);
    output[20..28].copy_from_slice(&issued_at.to_be_bytes());
    output[28..36].copy_from_slice(&expires_at.to_be_bytes());
    output[36..38].copy_from_slice(&(name.len() as u16).to_be_bytes());
    output[38..42].copy_from_slice(&uid.to_be_bytes());
    output[42..46].copy_from_slice(&gid.to_be_bytes());
    output[46..48].copy_from_slice(&(home.len() as u16).to_be_bytes());
    output[48..50].copy_from_slice(&(shell.len() as u16).to_be_bytes());
    output[50..52].copy_from_slice(&(groups.len() as u16).to_be_bytes());
    let mut offset = 52;
    for field in [name.as_bytes(), home.as_bytes(), shell.as_bytes()] {
        output[offset..offset + field.len()].copy_from_slice(field);
        offset += field.len();
    }
    for group in groups {
        output[offset..offset + 4].copy_from_slice(&group.to_be_bytes());
        offset += 4;
    }
    output[offset..offset + SESSION_TOKEN_MAC_LEN].copy_from_slice(mac);
    Ok(length)
}

pub fn decode_session_token(token: &[u8]) -> Result<SessionToken<'_>, MonitorFrameError> {
    if token.len() < 52 + SESSION_TOKEN_MAC_LEN {
        return Err(MonitorFrameError::Truncated);
    }
    if token.len() > MAX_SESSION_TOKEN {
        return Err(MonitorFrameError::Oversize);
    }
    if &token[..4] != SESSION_TOKEN_MAGIC {
        return Err(MonitorFrameError::UnknownType);
    }
    let mut nonce = [0u8; SESSION_TOKEN_NONCE_LEN];
    nonce.copy_from_slice(&token[4..20]);
    let issued_at = u64::from_be_bytes(token[20..28].try_into().expect("eight-byte timestamp"));
    let expires_at = u64::from_be_bytes(token[28..36].try_into().expect("eight-byte timestamp"));
    let name_len = usize::from(u16::from_be_bytes([token[36], token[37]]));
    let uid = u32::from_be_bytes(token[38..42].try_into().expect("four-byte uid"));
    let gid = u32::from_be_bytes(token[42..46].try_into().expect("four-byte gid"));
    let home_len = usize::from(u16::from_be_bytes([token[46], token[47]]));
    let shell_len = usize::from(u16::from_be_bytes([token[48], token[49]]));
    let group_count = usize::from(u16::from_be_bytes([token[50], token[51]]));
    if name_len == 0
        || name_len > MAX_MONITOR_USER
        || home_len == 0
        || home_len > MAX_MONITOR_IDENTITY_PATH
        || shell_len == 0
        || shell_len > MAX_MONITOR_IDENTITY_PATH
        || group_count > MAX_MONITOR_IDENTITY_GROUPS
    {
        return Err(MonitorFrameError::Oversize);
    }
    let expected = 52 + name_len + home_len + shell_len + group_count * 4 + SESSION_TOKEN_MAC_LEN;
    if token.len() < expected {
        return Err(MonitorFrameError::Truncated);
    }
    if token.len() != expected {
        return Err(MonitorFrameError::LengthMismatch);
    }
    let mut offset = 52;
    let name = std::str::from_utf8(&token[offset..offset + name_len])
        .map_err(|_| MonitorFrameError::InvalidUser)?;
    offset += name_len;
    if name
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return Err(MonitorFrameError::InvalidUser);
    }
    let home = std::str::from_utf8(&token[offset..offset + home_len])
        .map_err(|_| MonitorFrameError::InvalidUser)?;
    offset += home_len;
    let shell = std::str::from_utf8(&token[offset..offset + shell_len])
        .map_err(|_| MonitorFrameError::InvalidUser)?;
    offset += shell_len;
    if !std::path::Path::new(home).is_absolute() || !std::path::Path::new(shell).is_absolute() {
        return Err(MonitorFrameError::InvalidUser);
    }
    let groups = &token[offset..offset + group_count * 4];
    offset += group_count * 4;
    if expires_at <= issued_at {
        return Err(MonitorFrameError::InvalidUser);
    }
    Ok(SessionToken {
        nonce,
        issued_at,
        expires_at,
        name,
        uid,
        gid,
        home,
        shell,
        groups,
        mac: &token[offset..],
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerRequest<'a> {
    OpenSession {
        request_id: u32,
        token: &'a [u8],
        term: &'a str,
        rows: u16,
        cols: u16,
    },
    SignalSession {
        session_id: u64,
        signal: Signal,
    },
    CloseSession {
        session_id: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerStatus {
    Ok = 0,
    Denied = 1,
    InternalError = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerResponse {
    OpenResult {
        request_id: u32,
        status: BrokerStatus,
        session_id: u64,
    },
    Exit {
        session_id: u64,
        kind: ExitKind,
        value: u8,
    },
}

pub fn encode_broker_open_request(
    request_id: u32,
    token: &[u8],
    term: &str,
    rows: u16,
    cols: u16,
    output: &mut [u8],
) -> Result<usize, MonitorFrameError> {
    if token.is_empty() || token.len() > MAX_SESSION_TOKEN {
        return Err(MonitorFrameError::Oversize);
    }
    if term.len() > MAX_BROKER_TERM
        || !term.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        || !valid_window(rows, cols)
    {
        return Err(MonitorFrameError::InvalidUser);
    }
    let length = 1 + 4 + 2 + token.len() + 1 + term.len() + 2 + 2;
    if output.len() < length {
        return Err(MonitorFrameError::Truncated);
    }
    output[0] = 1;
    output[1..5].copy_from_slice(&request_id.to_be_bytes());
    output[5..7].copy_from_slice(&(token.len() as u16).to_be_bytes());
    output[7..7 + token.len()].copy_from_slice(token);
    let mut offset = 7 + token.len();
    output[offset] = term.len() as u8;
    offset += 1;
    output[offset..offset + term.len()].copy_from_slice(term.as_bytes());
    offset += term.len();
    output[offset..offset + 2].copy_from_slice(&rows.to_be_bytes());
    output[offset + 2..offset + 4].copy_from_slice(&cols.to_be_bytes());
    Ok(length)
}

pub fn encode_broker_signal_request(
    session_id: u64,
    signal: Signal,
    output: &mut [u8],
) -> Result<usize, MonitorFrameError> {
    let length = 1 + 8 + 1;
    if output.len() < length {
        return Err(MonitorFrameError::Truncated);
    }
    output[0] = 2;
    output[1..9].copy_from_slice(&session_id.to_be_bytes());
    output[9] = signal as u8;
    Ok(length)
}

pub fn encode_broker_close_request(
    session_id: u64,
    output: &mut [u8],
) -> Result<usize, MonitorFrameError> {
    let length = 1 + 8;
    if output.len() < length {
        return Err(MonitorFrameError::Truncated);
    }
    output[0] = 3;
    output[1..9].copy_from_slice(&session_id.to_be_bytes());
    Ok(length)
}

pub fn decode_broker_request(frame: &[u8]) -> Result<BrokerRequest<'_>, MonitorFrameError> {
    if frame.is_empty() {
        return Err(MonitorFrameError::Truncated);
    }
    if frame.len() > MAX_BROKER_FRAME {
        return Err(MonitorFrameError::Oversize);
    }
    match frame[0] {
        1 => {
            if frame.len() < 7 {
                return Err(MonitorFrameError::Truncated);
            }
            let request_id =
                u32::from_be_bytes(frame[1..5].try_into().expect("four-byte request id"));
            let token_len = usize::from(u16::from_be_bytes([frame[5], frame[6]]));
            if token_len == 0 || token_len > MAX_SESSION_TOKEN {
                return Err(MonitorFrameError::Oversize);
            }
            let token_end = 7 + token_len;
            if frame.len() < token_end + 1 {
                return Err(MonitorFrameError::Truncated);
            }
            let term_len = usize::from(frame[token_end]);
            if term_len > MAX_BROKER_TERM {
                return Err(MonitorFrameError::Oversize);
            }
            let expected = token_end + 1 + term_len + 2 + 2;
            if frame.len() < expected {
                return Err(MonitorFrameError::Truncated);
            }
            if frame.len() != expected {
                return Err(MonitorFrameError::LengthMismatch);
            }
            let term = std::str::from_utf8(&frame[token_end + 1..token_end + 1 + term_len])
                .map_err(|_| MonitorFrameError::InvalidUser)?;
            if !term.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
                return Err(MonitorFrameError::InvalidUser);
            }
            let rows = u16::from_be_bytes(
                frame[token_end + 1 + term_len..token_end + 3 + term_len]
                    .try_into()
                    .expect("two-byte rows"),
            );
            let cols = u16::from_be_bytes(
                frame[token_end + 3 + term_len..token_end + 5 + term_len]
                    .try_into()
                    .expect("two-byte cols"),
            );
            if !valid_window(rows, cols) {
                return Err(MonitorFrameError::InvalidUser);
            }
            Ok(BrokerRequest::OpenSession {
                request_id,
                token: &frame[7..token_end],
                term,
                rows,
                cols,
            })
        }
        2 if frame.len() == 10 => {
            let session_id =
                u64::from_be_bytes(frame[1..9].try_into().expect("eight-byte session id"));
            let signal = decode_signal(frame[9]).ok_or(MonitorFrameError::InvalidUser)?;
            Ok(BrokerRequest::SignalSession { session_id, signal })
        }
        2 => Err(MonitorFrameError::LengthMismatch),
        3 if frame.len() == 9 => {
            let session_id =
                u64::from_be_bytes(frame[1..9].try_into().expect("eight-byte session id"));
            Ok(BrokerRequest::CloseSession { session_id })
        }
        3 => Err(MonitorFrameError::LengthMismatch),
        _ => Err(MonitorFrameError::UnknownType),
    }
}

pub fn encode_broker_open_result(
    request_id: u32,
    status: BrokerStatus,
    session_id: u64,
    output: &mut [u8],
) -> Result<usize, MonitorFrameError> {
    let length = 1 + 4 + 1 + 8;
    if output.len() < length {
        return Err(MonitorFrameError::Truncated);
    }
    output[0] = 0x80;
    output[1..5].copy_from_slice(&request_id.to_be_bytes());
    output[5] = status as u8;
    output[6..14].copy_from_slice(&session_id.to_be_bytes());
    Ok(length)
}

pub fn encode_broker_exit(
    session_id: u64,
    kind: ExitKind,
    value: u8,
    output: &mut [u8],
) -> Result<usize, MonitorFrameError> {
    if !valid_exit(kind, value) {
        return Err(MonitorFrameError::UnknownType);
    }
    let length = 1 + 8 + 1 + 1;
    if output.len() < length {
        return Err(MonitorFrameError::Truncated);
    }
    output[0] = 0x81;
    output[1..9].copy_from_slice(&session_id.to_be_bytes());
    output[9] = kind as u8;
    output[10] = value;
    Ok(length)
}

pub fn decode_broker_response(frame: &[u8]) -> Result<BrokerResponse, MonitorFrameError> {
    if frame.is_empty() {
        return Err(MonitorFrameError::Truncated);
    }
    if frame.len() > MAX_BROKER_FRAME {
        return Err(MonitorFrameError::Oversize);
    }
    match frame[0] {
        0x80 if frame.len() == 14 => {
            let request_id =
                u32::from_be_bytes(frame[1..5].try_into().expect("four-byte request id"));
            let status = match frame[5] {
                0 => BrokerStatus::Ok,
                1 => BrokerStatus::Denied,
                2 => BrokerStatus::InternalError,
                _ => return Err(MonitorFrameError::UnknownType),
            };
            let session_id =
                u64::from_be_bytes(frame[6..14].try_into().expect("eight-byte session id"));
            if status != BrokerStatus::Ok && session_id != 0 {
                return Err(MonitorFrameError::InvalidUser);
            }
            Ok(BrokerResponse::OpenResult {
                request_id,
                status,
                session_id,
            })
        }
        0x80 => Err(MonitorFrameError::LengthMismatch),
        0x81 if frame.len() == 11 => {
            let session_id =
                u64::from_be_bytes(frame[1..9].try_into().expect("eight-byte session id"));
            let kind = match frame[9] {
                0 => ExitKind::Status,
                1 => ExitKind::Signal,
                _ => return Err(MonitorFrameError::UnknownType),
            };
            if !valid_exit(kind, frame[10]) {
                return Err(MonitorFrameError::UnknownType);
            }
            Ok(BrokerResponse::Exit {
                session_id,
                kind,
                value: frame[10],
            })
        }
        0x81 => Err(MonitorFrameError::LengthMismatch),
        _ => Err(MonitorFrameError::UnknownType),
    }
}

pub fn decode_signal(value: u8) -> Option<Signal> {
    Some(match value {
        1 => Signal::Hup,
        2 => Signal::Int,
        3 => Signal::Quit,
        4 => Signal::Term,
        5 => Signal::Kill,
        6 => Signal::Tstp,
        7 => Signal::Cont,
        8 => Signal::Winch,
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FrameType {
    Hello = 0,
    Challenge = 1,
    AuthRequest = 2,
    AuthOk = 3,
    AuthFail = 4,
    OpenShell = 5,
    Resize = 6,
    Signal = 7,
    Exit = 8,
    Close = 9,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // Fixed-size fields avoid hot-path allocation.
pub enum Message {
    Hello {
        version: u16,
        features: u32,
    },
    Challenge {
        server_nonce: [u8; 32],
        compression: Compression,
    },
    AuthRequest {
        user: [u8; 256],
        user_len: u16,
        public_key: [u8; 32],
        client_nonce: [u8; 32],
        signature: [u8; 64],
    },
    AuthOk,
    AuthFail {
        reason_class: u8,
    },
    OpenShell {
        term: [u8; 64],
        term_len: u8,
        rows: u16,
        cols: u16,
    },
    Resize {
        rows: u16,
        cols: u16,
    },
    Signal {
        signal: Signal,
    },
    Exit {
        kind: ExitKind,
        value: u8,
    },
    Close {
        code: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Signal {
    Hup = 1,
    Int = 2,
    Quit = 3,
    Term = 4,
    Kill = 5,
    Tstp = 6,
    Cont = 7,
    Winch = 8,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitKind {
    Status = 0,
    Signal = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    Truncated,
    Oversize,
    UnknownType,
    NonCanonicalVarint,
    InvalidPayload,
    InvalidState,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated control frame",
            Self::Oversize => "control frame exceeds maximum size",
            Self::UnknownType => "unknown control frame type",
            Self::NonCanonicalVarint => "non-canonical protocol varint",
            Self::InvalidPayload => "invalid control frame payload",
            Self::InvalidState => "out-of-order control frame",
        })
    }
}
impl std::error::Error for ProtocolError {}

pub fn encode(message: &Message, out: &mut [u8; MAX_WIRE_FRAME]) -> Result<usize, ProtocolError> {
    let (kind, payload_len) = match message {
        Message::Hello { .. } => (0, 6),
        Message::Challenge { .. } => (1, 33),
        Message::AuthRequest { user, user_len, .. }
            if usize::from(*user_len) <= 256 && valid_user(&user[..usize::from(*user_len)]) =>
        {
            (2, 2 + usize::from(*user_len) + 32 + 32 + 64)
        }
        Message::AuthRequest { .. } => return Err(ProtocolError::InvalidPayload),
        Message::AuthOk => (3, 0),
        Message::AuthFail { .. } => (4, 1),
        Message::OpenShell {
            term,
            term_len,
            rows,
            cols,
        } if usize::from(*term_len) <= 64
            && valid_term(&term[..usize::from(*term_len)])
            && valid_window(*rows, *cols) =>
        {
            (5, 1 + *term_len as usize + 4)
        }
        Message::OpenShell { .. } => return Err(ProtocolError::InvalidPayload),
        Message::Resize { rows, cols } if valid_window(*rows, *cols) => (6, 4),
        Message::Resize { .. } => return Err(ProtocolError::InvalidPayload),
        Message::Signal { .. } => (7, 1),
        Message::Exit { kind, value } if valid_exit(*kind, *value) => (8, 2),
        Message::Exit { .. } => return Err(ProtocolError::InvalidPayload),
        Message::Close { .. } => (9, 2),
    };
    if payload_len > MAX_FRAME {
        return Err(ProtocolError::Oversize);
    }
    let mut cursor = put_varint(kind, out);
    out[cursor..cursor + 2].copy_from_slice(&(payload_len as u16).to_be_bytes());
    cursor += 2;
    let p = &mut out[cursor..cursor + payload_len];
    match message {
        Message::Hello { version, features } => {
            p[..2].copy_from_slice(&version.to_be_bytes());
            p[2..].copy_from_slice(&features.to_be_bytes());
        }
        Message::Challenge {
            server_nonce,
            compression,
        } => {
            p[..32].copy_from_slice(server_nonce);
            p[32] = *compression as u8;
        }
        Message::AuthRequest {
            user,
            user_len,
            public_key,
            client_nonce,
            signature,
        } => {
            let n = *user_len as usize;
            p[..2].copy_from_slice(&user_len.to_be_bytes());
            p[2..2 + n].copy_from_slice(&user[..n]);
            p[2 + n..34 + n].copy_from_slice(public_key);
            p[34 + n..66 + n].copy_from_slice(client_nonce);
            p[66 + n..].copy_from_slice(signature);
        }
        Message::AuthOk => {}
        Message::AuthFail { reason_class } => p[0] = *reason_class,
        Message::OpenShell {
            term,
            term_len,
            rows,
            cols,
        } => {
            let n = *term_len as usize;
            p[0] = *term_len;
            p[1..1 + n].copy_from_slice(&term[..n]);
            p[1 + n..3 + n].copy_from_slice(&rows.to_be_bytes());
            p[3 + n..].copy_from_slice(&cols.to_be_bytes());
        }
        Message::Resize { rows, cols } => {
            p[..2].copy_from_slice(&rows.to_be_bytes());
            p[2..].copy_from_slice(&cols.to_be_bytes());
        }
        Message::Signal { signal } => p[0] = *signal as u8,
        Message::Exit { kind, value } => {
            p[0] = *kind as u8;
            p[1] = *value;
        }
        Message::Close { code } => p.copy_from_slice(&code.to_be_bytes()),
    }
    Ok(cursor + payload_len)
}

fn put_varint(v: u64, out: &mut [u8]) -> usize {
    if v < 64 {
        out[0] = v as u8;
        1
    } else if v < 16384 {
        out[..2].copy_from_slice(&((v as u16) | 0x4000).to_be_bytes());
        2
    } else if v < (1 << 30) {
        out[..4].copy_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
        4
    } else {
        out[..8].copy_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
        8
    }
}

pub fn decode(input: &[u8]) -> Result<(Message, usize), ProtocolError> {
    let (kind, head) = get_varint(input)?;
    if input.len() < head + 2 {
        return Err(ProtocolError::Truncated);
    }
    let len = u16::from_be_bytes([input[head], input[head + 1]]) as usize;
    if len > MAX_FRAME {
        return Err(ProtocolError::Oversize);
    }
    if input.len() < head + 2 + len {
        return Err(ProtocolError::Truncated);
    }
    let p = &input[head + 2..head + 2 + len];
    let msg = match kind {
        0 if len == 6 => Message::Hello {
            version: u16::from_be_bytes([p[0], p[1]]),
            features: u32::from_be_bytes(p[2..6].try_into().unwrap()),
        },
        1 if len == 33 => Message::Challenge {
            server_nonce: p[..32].try_into().unwrap(),
            compression: Compression::from_u8(p[32]).ok_or(ProtocolError::InvalidPayload)?,
        },
        2 if len >= 130 => {
            let n = u16::from_be_bytes([p[0], p[1]]) as usize;
            if n > 256 || len != 130 + n || !valid_user(&p[2..2 + n]) {
                return Err(ProtocolError::InvalidPayload);
            }
            let mut user = [0; 256];
            user[..n].copy_from_slice(&p[2..2 + n]);
            Message::AuthRequest {
                user,
                user_len: n as u16,
                public_key: p[2 + n..34 + n].try_into().unwrap(),
                client_nonce: p[34 + n..66 + n].try_into().unwrap(),
                signature: p[66 + n..].try_into().unwrap(),
            }
        }
        3 if len == 0 => Message::AuthOk,
        4 if len == 1 => Message::AuthFail { reason_class: p[0] },
        5 if len >= 5 => {
            let n = p[0] as usize;
            if n > 64 || len != 5 + n || !valid_term(&p[1..1 + n]) {
                return Err(ProtocolError::InvalidPayload);
            }
            let rows = u16::from_be_bytes([p[n + 1], p[n + 2]]);
            let cols = u16::from_be_bytes([p[n + 3], p[n + 4]]);
            if !valid_window(rows, cols) {
                return Err(ProtocolError::InvalidPayload);
            }
            let mut term = [0; 64];
            term[..n].copy_from_slice(&p[1..1 + n]);
            Message::OpenShell {
                term,
                term_len: n as u8,
                rows,
                cols,
            }
        }
        6 if len == 4 => {
            let rows = u16::from_be_bytes([p[0], p[1]]);
            let cols = u16::from_be_bytes([p[2], p[3]]);
            if !valid_window(rows, cols) {
                return Err(ProtocolError::InvalidPayload);
            }
            Message::Resize { rows, cols }
        }
        7 if len == 1 => Message::Signal {
            signal: match p[0] {
                1 => Signal::Hup,
                2 => Signal::Int,
                3 => Signal::Quit,
                4 => Signal::Term,
                5 => Signal::Kill,
                6 => Signal::Tstp,
                7 => Signal::Cont,
                8 => Signal::Winch,
                _ => return Err(ProtocolError::InvalidPayload),
            },
        },
        8 if len == 2 && (p[0] == 0 || (p[0] == 1 && (1..=64).contains(&p[1]))) => Message::Exit {
            kind: match p[0] {
                0 => ExitKind::Status,
                1 => ExitKind::Signal,
                _ => return Err(ProtocolError::InvalidPayload),
            },
            value: p[1],
        },
        9 if len == 2 => Message::Close {
            code: u16::from_be_bytes([p[0], p[1]]),
        },
        0..=9 => return Err(ProtocolError::InvalidPayload),
        _ => return Err(ProtocolError::UnknownType),
    };
    Ok((msg, head + 2 + len))
}

fn valid_user(user: &[u8]) -> bool {
    !user.is_empty()
        && user.len() <= 256
        && std::str::from_utf8(user).is_ok()
        && user.iter().all(|byte| !byte.is_ascii_control())
}

fn valid_term(term: &[u8]) -> bool {
    term.iter().all(|byte| (0x20..=0x7e).contains(byte))
}

fn valid_exit(kind: ExitKind, value: u8) -> bool {
    kind == ExitKind::Status || (1..=64).contains(&value)
}

fn valid_window(rows: u16, cols: u16) -> bool {
    (1..=MAX_TERMINAL_DIMENSION).contains(&rows) && (1..=MAX_TERMINAL_DIMENSION).contains(&cols)
}

/// Fixed-capacity incremental decoder for stream reads. It performs no heap allocation.
pub struct FrameDecoder {
    bytes: [u8; MAX_WIRE_FRAME],
    len: usize,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDecoder {
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_WIRE_FRAME],
            len: 0,
        }
    }

    /// Add as many bytes as fit. Drain complete frames with `next`, then feed the remainder.
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        let copied = bytes.len().min(self.bytes.len() - self.len);
        self.bytes[self.len..self.len + copied].copy_from_slice(&bytes[..copied]);
        self.len += copied;
        copied
    }

    pub fn decode_next(&mut self) -> Result<Option<Message>, ProtocolError> {
        if self.len == 0 {
            return Ok(None);
        }
        let (message, consumed) = match decode(&self.bytes[..self.len]) {
            Ok(frame) => frame,
            Err(ProtocolError::Truncated) => return Ok(None),
            Err(error) => return Err(error),
        };
        self.bytes.copy_within(consumed..self.len, 0);
        self.len -= consumed;
        Ok(Some(message))
    }

    pub fn buffered_len(&self) -> usize {
        self.len
    }
}

fn get_varint(input: &[u8]) -> Result<(u64, usize), ProtocolError> {
    if input.is_empty() {
        return Err(ProtocolError::Truncated);
    }
    let n = 1usize << (input[0] >> 6);
    if input.len() < n {
        return Err(ProtocolError::Truncated);
    }
    let value = match n {
        1 => (input[0] & 0x3f) as u64,
        2 => u16::from_be_bytes(input[..2].try_into().unwrap()) as u64 & 0x3fff,
        4 => u32::from_be_bytes(input[..4].try_into().unwrap()) as u64 & 0x3fff_ffff,
        _ => u64::from_be_bytes(input[..8].try_into().unwrap()) & 0x3fff_ffff_ffff_ffff,
    };
    if (n == 2 && value < 64) || (n == 4 && value < 16384) || (n == 8 && value < (1 << 30)) {
        return Err(ProtocolError::NonCanonicalVarint);
    }
    Ok((value, n))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Start,
    AwaitChallenge,
    AwaitAuth,
    AwaitAuthResult,
    Ready,
    Running,
    Closed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    Start,
    AwaitAuth,
    AuthPending,
    AwaitOpen,
    Running,
    Closed,
}

impl ClientState {
    pub fn sent(&mut self, m: &Message) -> Result<(), ProtocolError> {
        *self = match (*self, m) {
            (Self::Start, Message::Hello { version: 2, .. }) => Self::AwaitChallenge,
            (Self::AwaitAuth, Message::AuthRequest { .. }) => Self::AwaitAuthResult,
            (Self::Ready, Message::OpenShell { .. }) => Self::Running,
            (Self::Running, Message::Resize { .. } | Message::Signal { .. }) => Self::Running,
            (Self::Running, Message::Close { .. }) => Self::Closed,
            _ => return Err(ProtocolError::InvalidState),
        };
        Ok(())
    }

    pub fn accept(&mut self, m: &Message) -> Result<(), ProtocolError> {
        *self = match (*self, m) {
            (Self::AwaitChallenge, Message::Challenge { .. }) => Self::AwaitAuth,
            (Self::AwaitAuthResult, Message::AuthOk) => Self::Ready,
            (Self::AwaitAuthResult, Message::AuthFail { .. } | Message::Close { .. }) => {
                Self::Closed
            }
            (Self::Ready, Message::Exit { .. } | Message::Close { .. }) => Self::Closed,
            (
                Self::Running,
                Message::Resize { .. } | Message::Exit { .. } | Message::Close { .. },
            ) => {
                if matches!(m, Message::Exit { .. } | Message::Close { .. }) {
                    Self::Closed
                } else {
                    Self::Running
                }
            }
            _ => return Err(ProtocolError::InvalidState),
        };
        Ok(())
    }
}
impl ServerState {
    pub fn sent(&mut self, m: &Message) -> Result<(), ProtocolError> {
        *self = match (*self, m) {
            (Self::AwaitAuth, Message::Challenge { .. }) => Self::AwaitAuth,
            (Self::AuthPending, Message::AuthOk) => Self::AwaitOpen,
            (Self::AuthPending, Message::AuthFail { .. } | Message::Close { .. }) => Self::Closed,
            (Self::AwaitOpen, Message::Close { .. }) => Self::Closed,
            (Self::AwaitAuth, Message::AuthFail { .. } | Message::Close { .. }) => Self::Closed,
            (Self::Running, Message::Exit { .. } | Message::Close { .. }) => Self::Closed,
            _ => return Err(ProtocolError::InvalidState),
        };
        Ok(())
    }

    pub fn accept(&mut self, m: &Message) -> Result<(), ProtocolError> {
        *self = match (*self, m) {
            (Self::Start, Message::Hello { version: 2, .. }) => Self::AwaitAuth,
            (Self::AwaitAuth, Message::AuthRequest { .. }) => Self::AuthPending,
            (Self::AwaitOpen, Message::OpenShell { .. }) => Self::Running,
            (Self::Running, Message::Resize { .. } | Message::Signal { .. }) => Self::Running,
            (Self::Running, Message::Close { .. }) => Self::Closed,
            _ => return Err(ProtocolError::InvalidState),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compression_feature_bits_match_server_selection() {
        assert_eq!(
            SUPPORTED_FEATURES,
            FEATURE_COMPRESSION_LZ4 | FEATURE_COMPRESSION_SNAPPY | FEATURE_COMPRESSION_ZSTD
        );
        for compression in [Compression::Fast, Compression::Standard, Compression::High] {
            assert!(compression.is_supported_by(SUPPORTED_FEATURES));
            assert!(!compression.is_supported_by(0));
            assert!(!compression.is_supported_by(SUPPORTED_FEATURES & !compression.feature_bit()));
        }
        assert!(Compression::Off.is_supported_by(0));
        assert_eq!(Compression::from_u8(0), Some(Compression::Off));
        assert_eq!(Compression::from_u8(3), Some(Compression::High));
        assert_eq!(Compression::from_u8(4), None);
    }

    #[test]
    fn compression_protocol_has_a_distinct_version() {
        assert_eq!(ALPN, b"ssxpro/2");
        let legacy = Message::Hello {
            version: 1,
            features: 0,
        };
        assert!(ServerState::Start.accept(&legacy).is_err());
        assert!(ClientState::Start.sent(&legacy).is_err());
    }

    #[test]
    fn invalid_compression_id_is_rejected() {
        let message = Message::Challenge {
            server_nonce: [0; 32],
            compression: Compression::Fast,
        };
        let mut frame = [0u8; MAX_WIRE_FRAME];
        let length = encode(&message, &mut frame).unwrap();
        assert_eq!(length, 3 + 33);
        frame[length - 1] = 4;
        assert_eq!(
            decode(&frame[..length]).unwrap_err(),
            ProtocolError::InvalidPayload
        );
    }

    #[test]
    fn usernames_require_utf8_and_no_controls() {
        assert!(valid_user("josé".as_bytes()));
        for user in [&b""[..], &b"bad\0name"[..], &b"bad\nname"[..], &[0xff][..]] {
            assert!(!valid_user(user));
        }
    }

    #[test]
    fn server_waits_for_authorization_before_open() {
        let mut server = ServerState::AwaitAuth;
        let auth = Message::AuthRequest {
            user: [0; 256],
            user_len: 1,
            public_key: [0; 32],
            client_nonce: [0; 32],
            signature: [0; 64],
        };
        server.accept(&auth).unwrap();
        assert_eq!(server, ServerState::AuthPending);
        let open = Message::OpenShell {
            term: [0; 64],
            term_len: 0,
            rows: 24,
            cols: 80,
        };
        assert!(server.accept(&open).is_err());
        assert!(server.accept(&auth).is_err());
        let mut denied = server;
        denied.sent(&Message::AuthFail { reason_class: 1 }).unwrap();
        assert_eq!(denied, ServerState::Closed);
        server.sent(&Message::AuthOk).unwrap();
        assert_eq!(server, ServerState::AwaitOpen);
        server.sent(&Message::Close { code: 0 }).unwrap();
        assert_eq!(server, ServerState::Closed);
    }

    #[test]
    fn message_round_trips() {
        let messages = [
            Message::Hello {
                version: 2,
                features: 0,
            },
            Message::Challenge {
                server_nonce: [7; 32],
                compression: Compression::High,
            },
            Message::AuthOk,
            Message::AuthFail { reason_class: 2 },
            Message::OpenShell {
                term: [0; 64],
                term_len: 0,
                rows: 24,
                cols: 80,
            },
            Message::Resize { rows: 25, cols: 90 },
            Message::Signal {
                signal: Signal::Term,
            },
            Message::Exit {
                kind: ExitKind::Status,
                value: 0,
            },
            Message::Close { code: 4 },
        ];
        for m in messages {
            let mut buf = [0; MAX_WIRE_FRAME];
            let n = encode(&m, &mut buf).unwrap();
            assert_eq!(decode(&buf[..n]).unwrap(), (m, n));
        }
    }
    #[test]
    fn session_token_round_trips_and_rejects_malformed_frames() {
        let nonce = [0x33; SESSION_TOKEN_NONCE_LEN];
        let groups = [10u32, 20];
        let mac = [0x44; SESSION_TOKEN_MAC_LEN];
        let mut buffer = [0u8; MAX_SESSION_TOKEN];
        let length = encode_session_token(
            &nonce,
            100,
            130,
            "alice",
            1000,
            1000,
            "/home/alice",
            "/bin/sh",
            &groups,
            &mac,
            &mut buffer,
        )
        .unwrap();
        let token = decode_session_token(&buffer[..length]).unwrap();
        assert_eq!(token.nonce, nonce);
        assert_eq!(token.issued_at, 100);
        assert_eq!(token.expires_at, 130);
        assert_eq!(token.name, "alice");
        assert_eq!(token.uid, 1000);
        assert_eq!(token.gid, 1000);
        assert_eq!(token.home, "/home/alice");
        assert_eq!(token.shell, "/bin/sh");
        assert_eq!(token.groups, &[0, 0, 0, 10, 0, 0, 0, 20]);
        assert_eq!(token.mac, &mac);
        assert!(decode_session_token(&buffer[..length - 1]).is_err());
        let mut changed = buffer;
        changed[0] ^= 1;
        assert!(decode_session_token(&changed[..length]).is_err());
    }

    #[test]
    fn broker_frames_round_trip() {
        let mut buffer = [0u8; MAX_BROKER_FRAME];
        let token = [0x55u8; 96];
        let length =
            encode_broker_open_request(7, &token, "xterm-256color", 24, 80, &mut buffer).unwrap();
        match decode_broker_request(&buffer[..length]).unwrap() {
            BrokerRequest::OpenSession {
                request_id,
                token: decoded,
                term,
                rows,
                cols,
            } => {
                assert_eq!(request_id, 7);
                assert_eq!(decoded, token.as_slice());
                assert_eq!(term, "xterm-256color");
                assert_eq!((rows, cols), (24, 80));
            }
            _ => panic!("unexpected broker request"),
        }
        let length = encode_broker_signal_request(9, Signal::Term, &mut buffer).unwrap();
        assert_eq!(
            decode_broker_request(&buffer[..length]).unwrap(),
            BrokerRequest::SignalSession {
                session_id: 9,
                signal: Signal::Term,
            }
        );
        let length = encode_broker_close_request(9, &mut buffer).unwrap();
        assert_eq!(
            decode_broker_request(&buffer[..length]).unwrap(),
            BrokerRequest::CloseSession { session_id: 9 }
        );
        let length = encode_broker_open_result(7, BrokerStatus::Ok, 9, &mut buffer).unwrap();
        assert_eq!(
            decode_broker_response(&buffer[..length]).unwrap(),
            BrokerResponse::OpenResult {
                request_id: 7,
                status: BrokerStatus::Ok,
                session_id: 9,
            }
        );
        let length = encode_broker_exit(9, ExitKind::Signal, 15, &mut buffer).unwrap();
        assert_eq!(
            decode_broker_response(&buffer[..length]).unwrap(),
            BrokerResponse::Exit {
                session_id: 9,
                kind: ExitKind::Signal,
                value: 15,
            }
        );
        assert!(decode_broker_request(&buffer[..length]).is_err());
    }

    #[test]
    fn rejects_noncanonical_and_oversize() {
        assert_eq!(
            decode(&[0x40, 0, 0]),
            Err(ProtocolError::NonCanonicalVarint)
        );
        assert_eq!(decode(&[0, 0x10, 1]), Err(ProtocolError::Oversize));
    }
    #[test]
    fn strict_client_state() {
        let mut s = ClientState::Start;
        assert_eq!(s.accept(&Message::AuthOk), Err(ProtocolError::InvalidState));
    }

    #[test]
    fn incremental_decoder_handles_fragmented_frame() {
        let message = Message::Close { code: 9 };
        let mut encoded = [0; MAX_WIRE_FRAME];
        let n = encode(&message, &mut encoded).unwrap();
        let mut decoder = FrameDecoder::new();
        assert_eq!(decoder.feed(&encoded[..1]), 1);
        assert_eq!(decoder.decode_next().unwrap(), None);
        assert_eq!(decoder.feed(&encoded[1..n]), n - 1);
        assert_eq!(decoder.decode_next().unwrap(), Some(message));
    }

    #[test]
    fn client_state_tracks_both_directions() {
        let mut state = ClientState::Start;
        state
            .sent(&Message::Hello {
                version: 2,
                features: 0,
            })
            .unwrap();
        state
            .accept(&Message::Challenge {
                server_nonce: [0; 32],
                compression: Compression::Off,
            })
            .unwrap();
        let auth = Message::AuthRequest {
            user: [0; 256],
            user_len: 0,
            public_key: [0; 32],
            client_nonce: [0; 32],
            signature: [0; 64],
        };
        state.sent(&auth).unwrap();
        state.accept(&Message::AuthOk).unwrap();
        state
            .sent(&Message::OpenShell {
                term: [0; 64],
                term_len: 0,
                rows: 24,
                cols: 80,
            })
            .unwrap();
        assert_eq!(state, ClientState::Running);
    }

    #[test]
    fn wire_contract_boundaries() {
        let mut out = [0u8; MAX_WIRE_FRAME];
        for value in [1, 9, 15, 64] {
            let message = Message::Exit {
                kind: ExitKind::Signal,
                value,
            };
            let length = encode(&message, &mut out).unwrap();
            assert_eq!(decode(&out[..length]).unwrap().0, message);
        }
        for value in [0, 65, 255] {
            assert!(encode(
                &Message::Exit {
                    kind: ExitKind::Signal,
                    value
                },
                &mut out
            )
            .is_err());
            assert!(decode(&[8, 0, 2, 1, value]).is_err());
        }
        assert!(encode(
            &Message::Resize {
                rows: 4096,
                cols: 4096
            },
            &mut out
        )
        .is_ok());
        assert!(encode(
            &Message::Resize {
                rows: 4097,
                cols: 1
            },
            &mut out
        )
        .is_err());
        for (signal, code) in [
            (Signal::Kill, 5),
            (Signal::Tstp, 6),
            (Signal::Cont, 7),
            (Signal::Winch, 8),
        ] {
            let length = encode(&Message::Signal { signal }, &mut out).unwrap();
            assert_eq!(&out[..length], &[7, 0, 1, code]);
        }
    }
}
