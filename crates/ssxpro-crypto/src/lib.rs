#![deny(unsafe_op_in_unsafe_fn)]

//! Small, purpose-specific cryptographic and key-file helpers for ssxpro.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use boring::hash::{hash, MessageDigest};
use boring::pkey::{Id, PKey, Private, Public};
use boring::sign::{Signer, Verifier};
use std::fmt;
use std::io;
use zeroize::Zeroizing;

const PRIVATE_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const PUBLIC_DER_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Debug)]
pub enum CryptoError {
    Random(io::Error),
    Boring(boring::error::ErrorStack),
    InvalidKey,
    InvalidFormat(&'static str),
    InvalidFileMetadata(String),
    Io(io::Error),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random(error) => write!(f, "getrandom failed: {error}"),
            Self::Boring(error) => write!(f, "BoringSSL operation failed: {error}"),
            Self::InvalidKey => f.write_str("invalid Ed25519 key"),
            Self::InvalidFormat(message) => f.write_str(message),
            Self::InvalidFileMetadata(message) => f.write_str(message),
            Self::Io(error) => write!(f, "I/O error: {error}"),
        }
    }
}

impl std::error::Error for CryptoError {}
impl From<boring::error::ErrorStack> for CryptoError {
    fn from(error: boring::error::ErrorStack) -> Self {
        Self::Boring(error)
    }
}
impl From<io::Error> for CryptoError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub type CryptoResult<T> = Result<T, CryptoError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519PublicKey(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Signature(pub [u8; 64]);

pub struct Ed25519Keypair {
    seed: Zeroizing<[u8; 32]>,
    public: Ed25519PublicKey,
}

impl Ed25519Keypair {
    pub fn generate() -> CryptoResult<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom(&mut *seed)?;
        Self::from_seed(*seed)
    }

    pub fn from_seed(seed: [u8; 32]) -> CryptoResult<Self> {
        let seed = Zeroizing::new(seed);
        let private = private_pkey(&seed)?;
        let mut raw = [0u8; 32];
        let public_raw = private.raw_public_key(&mut raw)?;
        if public_raw.len() != raw.len() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self {
            seed,
            public: Ed25519PublicKey(raw),
        })
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
    pub fn public_key(&self) -> Ed25519PublicKey {
        self.public
    }

    pub fn private_key_pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        let mut der = Zeroizing::new(Vec::with_capacity(
            PRIVATE_DER_PREFIX.len() + self.seed.len(),
        ));
        der.extend_from_slice(&PRIVATE_DER_PREFIX);
        der.extend_from_slice(&self.seed[..]);
        der
    }

    pub fn sign(&self, message: &[u8]) -> CryptoResult<Ed25519Signature> {
        let private = private_pkey(&self.seed)?;
        let mut signer = Signer::new_without_digest(&private)?;
        let signature = signer.sign_oneshot_to_vec(message)?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| CryptoError::InvalidKey)?;
        Ok(Ed25519Signature(signature))
    }
}

impl Ed25519PublicKey {
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> CryptoResult<bool> {
        let public = public_pkey(&self.0)?;
        let mut verifier = Verifier::new_without_digest(&public)?;
        match verifier.verify_oneshot(&signature.0, message) {
            Ok(valid) => Ok(valid),
            Err(_) => Ok(false),
        }
    }

    pub fn to_spki_der(self) -> Vec<u8> {
        let mut der = Vec::with_capacity(PUBLIC_DER_PREFIX.len() + self.0.len());
        der.extend_from_slice(&PUBLIC_DER_PREFIX);
        der.extend_from_slice(&self.0);
        der
    }
}

fn private_pkey(seed: &[u8; 32]) -> CryptoResult<PKey<Private>> {
    let mut der = Zeroizing::new([0u8; 48]);
    der[..PRIVATE_DER_PREFIX.len()].copy_from_slice(&PRIVATE_DER_PREFIX);
    der[PRIVATE_DER_PREFIX.len()..].copy_from_slice(seed);
    let pkey = PKey::private_key_from_der(&*der)?;
    if pkey.id() != Id::ED25519 {
        return Err(CryptoError::InvalidKey);
    }
    Ok(pkey)
}

fn public_pkey(public: &[u8; 32]) -> CryptoResult<PKey<Public>> {
    let mut der = [0u8; 44];
    der[..PUBLIC_DER_PREFIX.len()].copy_from_slice(&PUBLIC_DER_PREFIX);
    der[PUBLIC_DER_PREFIX.len()..].copy_from_slice(public);
    let pkey = PKey::public_key_from_der(&der)?;
    if pkey.id() != Id::ED25519 {
        return Err(CryptoError::InvalidKey);
    }
    Ok(pkey)
}

pub fn sha256(data: &[u8]) -> CryptoResult<[u8; 32]> {
    let digest = hash(MessageDigest::sha256(), data)?;
    digest
        .as_ref()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)
}

pub fn getrandom(output: &mut [u8]) -> CryptoResult<()> {
    let mut filled = 0usize;
    while filled < output.len() {
        // SAFETY: `output[filled..]` is a valid writable buffer and the syscall
        // is given its exact remaining length.
        let result = unsafe {
            libc::getrandom(
                output[filled..].as_mut_ptr().cast(),
                output.len() - filled,
                0,
            )
        };
        if result > 0 {
            filled += result as usize;
        } else if result == 0 {
            return Err(CryptoError::Random(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "getrandom returned zero bytes",
            )));
        } else {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(CryptoError::Random(error));
            }
        }
    }
    Ok(())
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && boring::memcmp::eq(left, right)
}

pub fn fingerprint_spki(spki_der: &[u8]) -> CryptoResult<String> {
    Ok(format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(sha256(spki_der)?)
    ))
}

/// Build the v1 public-key proof input. The caller must verify the server SPKI
/// hash against known_hosts before sending a signature over these bytes.
pub fn auth_signing_bytes(
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
    server_spki_hash: &[u8; 32],
    user: &[u8],
    public_key: &Ed25519PublicKey,
) -> CryptoResult<Vec<u8>> {
    if user.is_empty() || user.len() > 256 || user.contains(&0) {
        return Err(CryptoError::InvalidFormat(
            "auth username must contain 1 to 256 non-NUL bytes",
        ));
    }
    let mut input = Vec::with_capacity(14 + 96 + user.len() + 32);
    input.extend_from_slice(b"ssxpro-auth-v1");
    input.extend_from_slice(server_nonce);
    input.extend_from_slice(client_nonce);
    input.extend_from_slice(server_spki_hash);
    input.extend_from_slice(user);
    input.extend_from_slice(&public_key.0);
    Ok(input)
}

pub fn parse_authorized_keys(input: &str) -> CryptoResult<Vec<Ed25519PublicKey>> {
    if input.len() > 1024 * 1024 {
        return Err(CryptoError::InvalidFormat("authorized_keys exceeds 1 MiB"));
    }
    let mut keys = Vec::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > 4096 {
            return Err(CryptoError::InvalidFormat(
                "authorized_keys line exceeds 4096 bytes",
            ));
        }
        let mut parts = line.split_whitespace();
        if parts.next() != Some("ed25519") {
            return Err(CryptoError::InvalidFormat(
                "authorized_keys line must start with ed25519",
            ));
        }
        let encoded = parts.next().ok_or(CryptoError::InvalidFormat(
            "authorized_keys line is missing the key",
        ))?;
        let key_bytes = STANDARD
            .decode(encoded)
            .map_err(|_| CryptoError::InvalidFormat("authorized_keys key is not valid base64"))?;
        let key: [u8; 32] = key_bytes.try_into().map_err(|_| {
            CryptoError::InvalidFormat("authorized_keys key must decode to 32 bytes")
        })?;
        // This format accepts one comment token; key options and extra fields are unsupported.
        if let Some(comment) = parts.next() {
            if comment.starts_with("options=")
                || comment.starts_with("command=")
                || comment.starts_with("restrict")
                || parts.next().is_some()
            {
                return Err(CryptoError::InvalidFormat(
                    "authorized_keys options or extra tokens are not supported",
                ));
            }
        }
        keys.push(Ed25519PublicKey(key));
    }
    Ok(keys)
}

pub fn parse_known_hosts(input: &str) -> CryptoResult<Vec<(String, [u8; 32])>> {
    if input.len() > 1024 * 1024 {
        return Err(CryptoError::InvalidFormat("known_hosts exceeds 1 MiB"));
    }
    let mut entries = Vec::new();
    for line in input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if line.len() > 4096 {
            return Err(CryptoError::InvalidFormat(
                "known_hosts line exceeds 4096 bytes",
            ));
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 3 || fields[1] != "spki-sha256" {
            return Err(CryptoError::InvalidFormat(
                "known_hosts line must be `host:port spki-sha256 <base64>`",
            ));
        }
        let (host, port) = fields[0]
            .rsplit_once(':')
            .ok_or(CryptoError::InvalidFormat(
                "known_hosts host must include a port",
            ))?;
        if host.is_empty() || port.parse::<u16>().ok().filter(|port| *port != 0).is_none() {
            return Err(CryptoError::InvalidFormat(
                "known_hosts host or port is invalid",
            ));
        }
        let key_bytes = STANDARD
            .decode(fields[2])
            .map_err(|_| CryptoError::InvalidFormat("known_hosts key is not valid base64"))?;
        let fingerprint: [u8; 32] = key_bytes.try_into().map_err(|_| {
            CryptoError::InvalidFormat("known_hosts SPKI SHA-256 must decode to 32 bytes")
        })?;
        entries.push((fields[0].to_owned(), fingerprint));
    }
    Ok(entries)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyError {
    UnknownHost,
    Mismatch,
}

impl fmt::Display for HostKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownHost => f.write_str("host key is unknown"),
            Self::Mismatch => {
                f.write_str("WARNING: REMOTE HOST KEY HAS CHANGED; refusing connection")
            }
        }
    }
}
impl std::error::Error for HostKeyError {}

pub fn verify_known_host(
    entries: &[(String, [u8; 32])],
    host_port: &str,
    spki_der: &[u8],
) -> Result<(), HostKeyError> {
    let actual = sha256(spki_der).map_err(|_| HostKeyError::Mismatch)?;
    match entries.iter().find(|(host, _)| host == host_port) {
        Some((_, expected)) if constant_time_eq(expected, &actual) => Ok(()),
        Some(_) => Err(HostKeyError::Mismatch),
        None => Err(HostKeyError::UnknownHost),
    }
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const STRICT_RESOLVE: u64 = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

pub fn read_user_file(
    home: &std::path::Path,
    name: &str,
    max_bytes: usize,
) -> CryptoResult<Vec<u8>> {
    let path = home.join(".ssx").join(name);
    let (home_fd, secure_dir_fd) = open_user_dirs(home)?;
    read_user_file_from_dirs(
        home_fd,
        secure_dir_fd,
        current_euid(),
        name,
        max_bytes,
        &path,
        true,
    )
}

pub fn read_user_file_as(
    home: &std::path::Path,
    owner_uid: u32,
    name: &str,
    max_bytes: usize,
) -> CryptoResult<Vec<u8>> {
    read_user_file_as_impl(home, owner_uid, name, max_bytes, true)
}

/// Read a per-user file while skipping owner and mode checks. Intended only
/// for `ssxd` when the operator explicitly accepts the permission risks.
pub fn read_user_file_as_allow_insecure(
    home: &std::path::Path,
    owner_uid: u32,
    name: &str,
    max_bytes: usize,
) -> CryptoResult<Vec<u8>> {
    read_user_file_as_impl(home, owner_uid, name, max_bytes, false)
}

fn read_user_file_as_impl(
    home: &std::path::Path,
    owner_uid: u32,
    name: &str,
    max_bytes: usize,
    enforce_permissions: bool,
) -> CryptoResult<Vec<u8>> {
    let path = home.join(".ssx").join(name);
    let (home_fd, secure_dir_fd) =
        open_user_dirs_impl(home, false, owner_uid, enforce_permissions)?;
    read_user_file_from_dirs(
        home_fd,
        secure_dir_fd,
        owner_uid,
        name,
        max_bytes,
        &path,
        enforce_permissions,
    )
}

fn read_user_file_from_dirs(
    home_fd: std::fs::File,
    secure_dir_fd: std::fs::File,
    owner_uid: u32,
    name: &str,
    max_bytes: usize,
    path: &std::path::Path,
    enforce_permissions: bool,
) -> CryptoResult<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let file = openat2_file(
        secure_dir_fd.as_raw_fd(),
        name,
        (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
        0,
        STRICT_RESOLVE,
    )?;
    let metadata = file.metadata()?;
    if enforce_permissions {
        check_file_metadata_as(path, &metadata, 0o600, owner_uid)?;
    }
    let mut contents = Vec::with_capacity(metadata.len().min(max_bytes as u64) as usize);
    let mut limited = file.take(max_bytes as u64 + 1);
    use std::io::Read;
    limited.read_to_end(&mut contents)?;
    if contents.len() > max_bytes {
        return Err(CryptoError::InvalidFormat(
            "private file exceeds configured size limit",
        ));
    }
    drop(secure_dir_fd);
    drop(home_fd);
    Ok(contents)
}

pub fn write_user_file_new(
    home: &std::path::Path,
    name: &str,
    contents: &[u8],
) -> CryptoResult<()> {
    let (home_fd, secure_dir_fd) = open_user_dirs_create(home)?;
    use std::os::fd::AsRawFd;
    let file = openat2_file(
        secure_dir_fd.as_raw_fd(),
        name,
        (libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC) as u64,
        0o600,
        STRICT_RESOLVE,
    )?;
    let metadata = file.metadata()?;
    check_file_metadata(&home.join(".ssx").join(name), &metadata, 0o600)?;
    use std::io::Write;
    let mut file = file;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    drop(secure_dir_fd);
    drop(home_fd);
    Ok(())
}

pub fn append_user_file(
    home: &std::path::Path,
    name: &str,
    contents: &[u8],
    max_bytes: usize,
) -> CryptoResult<()> {
    let (_home_fd, secure_dir_fd) = open_user_dirs_create(home)?;
    use std::os::fd::AsRawFd;
    let mut file = openat2_file(
        secure_dir_fd.as_raw_fd(),
        name,
        (libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_CLOEXEC) as u64,
        0o600,
        STRICT_RESOLVE,
    )?;
    let metadata = file.metadata()?;
    check_file_metadata(&home.join(".ssx").join(name), &metadata, 0o600)?;
    if metadata.len().saturating_add(contents.len() as u64) > max_bytes as u64 {
        return Err(CryptoError::InvalidFormat(
            "private file exceeds configured size limit",
        ));
    }
    use std::io::Write;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

pub fn read_private_key(path: &std::path::Path, max_bytes: usize) -> CryptoResult<Vec<u8>> {
    read_strict_file(path, max_bytes, "private key exceeds size limit", true)
}

/// Read a server-owned file with strict metadata checks: regular file, owned
/// by the current euid, exact mode 0600, and no symlinks. Used for a
/// system-wide `authorized_keys` file owned by root.
pub fn read_server_file(path: &std::path::Path, max_bytes: usize) -> CryptoResult<Vec<u8>> {
    read_strict_file(path, max_bytes, "server file exceeds size limit", true)
}

/// Read a server-owned file while skipping owner and mode checks. Intended
/// only for `ssxd` when the operator explicitly accepts the permission risks.
pub fn read_server_file_allow_insecure(
    path: &std::path::Path,
    max_bytes: usize,
) -> CryptoResult<Vec<u8>> {
    read_strict_file(path, max_bytes, "server file exceeds size limit", false)
}

fn read_strict_file(
    path: &std::path::Path,
    max_bytes: usize,
    size_error: &'static str,
    enforce_permissions: bool,
) -> CryptoResult<Vec<u8>> {
    use std::os::fd::FromRawFd;
    let path_c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| CryptoError::InvalidFormat("file path contains NUL"))?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: the path is NUL terminated and `how` is a correctly laid out open_how.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path_c.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        ) as libc::c_int
    };
    if fd < 0 {
        return Err(CryptoError::Io(io::Error::last_os_error()));
    }
    // SAFETY: openat2 returned a new owned file descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(CryptoError::InvalidFormat("not a regular file"));
    }
    if enforce_permissions {
        check_file_metadata(path, &metadata, 0o600)?;
    }
    let mut data = Vec::new();
    use std::io::Read;
    file.take(max_bytes as u64 + 1).read_to_end(&mut data)?;
    if data.len() > max_bytes {
        return Err(CryptoError::InvalidFormat(size_error));
    }
    Ok(data)
}

fn open_user_dirs(home: &std::path::Path) -> CryptoResult<(std::fs::File, std::fs::File)> {
    open_user_dirs_impl(home, false, current_euid(), true)
}

fn open_user_dirs_create(home: &std::path::Path) -> CryptoResult<(std::fs::File, std::fs::File)> {
    open_user_dirs_impl(home, true, current_euid(), true)
}

fn open_user_dirs_impl(
    home: &std::path::Path,
    create: bool,
    owner_uid: u32,
    enforce_permissions: bool,
) -> CryptoResult<(std::fs::File, std::fs::File)> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let home_c = std::ffi::CString::new(home.as_os_str().as_bytes())
        .map_err(|_| CryptoError::InvalidFormat("home path contains NUL"))?;
    let home_how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: `home_c` is NUL terminated and `home_how` matches open_how.
    let home_fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            home_c.as_ptr(),
            &home_how,
            std::mem::size_of::<OpenHow>(),
        ) as libc::c_int
    };
    if home_fd < 0 {
        return Err(CryptoError::Io(io::Error::last_os_error()));
    }
    // SAFETY: openat2 returned a new owned descriptor.
    let home_file = unsafe { std::fs::File::from_raw_fd(home_fd) };
    let home_meta = home_file.metadata()?;
    if enforce_permissions {
        check_directory_metadata_as(&home_meta, false, "home directory", owner_uid)?;
    }

    let secure_name = std::ffi::CString::new(".ssx").expect("static string");
    if create {
        // SAFETY: the directory descriptor and NUL-terminated name are valid.
        let result = unsafe { libc::mkdirat(home_file.as_raw_fd(), secure_name.as_ptr(), 0o700) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(CryptoError::Io(error));
            }
        }
    }
    let secure_file = openat2_entry(
        home_file.as_raw_fd(),
        ".ssx",
        (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        0,
        STRICT_RESOLVE,
    )?;
    let secure_meta = secure_file.metadata()?;
    if enforce_permissions {
        check_directory_metadata_as(&secure_meta, true, ".ssx directory", owner_uid)?;
    }
    Ok((home_file, secure_file))
}

fn openat2_file(
    dir_fd: libc::c_int,
    name: &str,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> CryptoResult<std::fs::File> {
    let file = openat2_entry(dir_fd, name, flags, mode, resolve)?;
    if !file.metadata()?.is_file() {
        return Err(CryptoError::InvalidFormat("not a regular file"));
    }
    Ok(file)
}

fn openat2_entry(
    dir_fd: libc::c_int,
    name: &str,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> CryptoResult<std::fs::File> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name_c = std::ffi::CString::new(std::ffi::OsStr::new(name).as_bytes())
        .map_err(|_| CryptoError::InvalidFormat("file name contains NUL"))?;
    let how = OpenHow {
        flags: flags | libc::O_NONBLOCK as u64,
        mode,
        resolve,
    };
    // SAFETY: name is NUL terminated, `how` matches open_how, and both pointers remain valid.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir_fd,
            name_c.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        ) as libc::c_int
    };
    if fd < 0 {
        return Err(CryptoError::Io(io::Error::last_os_error()));
    }
    // SAFETY: openat2 returned a new owned descriptor.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

fn check_directory_metadata_as(
    metadata: &std::fs::Metadata,
    exact_private: bool,
    _description: &str,
    owner_uid: u32,
) -> CryptoResult<()> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_dir() || metadata.uid() != owner_uid {
        return Err(CryptoError::InvalidFormat(
            "directory type or owner does not satisfy strict modes",
        ));
    }
    let mode = metadata.mode() & 0o7777;
    let writable_by_others = mode & 0o022 != 0;
    if writable_by_others || (exact_private && mode & 0o077 != 0) {
        return Err(CryptoError::InvalidFormat(
            "directory permissions do not satisfy strict modes",
        ));
    }
    Ok(())
}

fn check_file_metadata(
    path: &std::path::Path,
    metadata: &std::fs::Metadata,
    required_mode: u32,
) -> CryptoResult<()> {
    check_file_metadata_as(path, metadata, required_mode, current_euid())
}

fn check_file_metadata_as(
    path: &std::path::Path,
    metadata: &std::fs::Metadata,
    required_mode: u32,
    owner_uid: u32,
) -> CryptoResult<()> {
    use std::os::unix::fs::MetadataExt;
    let mode = metadata.mode() & 0o7777;
    let issue = if !metadata.is_file() {
        Some("not a regular file")
    } else if metadata.uid() != owner_uid {
        Some("unexpected owner")
    } else if mode != required_mode {
        Some("unexpected permissions")
    } else {
        None
    };
    if let Some(issue) = issue {
        return Err(CryptoError::InvalidFileMetadata(format!(
            "{}: {issue} (expected a regular file owned by uid {owner_uid} with mode {required_mode:04o}; found uid {} with mode {mode:04o})",
            path.display(),
            metadata.uid()
        )));
    }
    Ok(())
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and returns the effective uid.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn decode_hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|pair| {
                let digit = |b: u8| (b as char).to_digit(16).unwrap() as u8;
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }
    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            sha256(b"abc").unwrap().as_slice(),
            decode_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }
    #[test]
    fn ed25519_rfc8032_vector_one() {
        let seed: [u8; 32] =
            decode_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .try_into()
                .unwrap();
        let expected_public: [u8; 32] =
            decode_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .try_into()
                .unwrap();
        let expected_signature: [u8; 64] = decode_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\n5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b".replace('\n', "").as_str()).try_into().unwrap();
        let key = Ed25519Keypair::from_seed(seed).unwrap();
        assert_eq!(key.public_key().0, expected_public);
        let signature = key.sign(b"").unwrap();
        assert_eq!(signature.0, expected_signature);
        assert!(key.public_key().verify(b"", &signature).unwrap());
        assert!(!key.public_key().verify(b"different", &signature).unwrap());
    }
    #[test]
    fn fingerprints_use_spki_hash() {
        let key = Ed25519Keypair::from_seed([0; 32]).unwrap();
        let der = key.public_key().to_spki_der();
        assert!(fingerprint_spki(&der).unwrap().starts_with("SHA256:"));
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"else"));
    }

    #[test]
    fn known_hosts_pins_spki_hash_and_mismatch_is_fatal() {
        let key = Ed25519Keypair::from_seed([5; 32]).unwrap();
        let der = key.public_key().to_spki_der();
        let hash = sha256(&der).unwrap();
        let line = format!("example.test:22 spki-sha256 {}\n", STANDARD.encode(hash));
        let entries = parse_known_hosts(&line).unwrap();
        assert_eq!(verify_known_host(&entries, "example.test:22", &der), Ok(()));
        assert_eq!(
            verify_known_host(&entries, "example.test:22", b"wrong key"),
            Err(HostKeyError::Mismatch)
        );
        assert_eq!(
            verify_known_host(&entries, "other.test:22", &der),
            Err(HostKeyError::UnknownHost)
        );
    }

    #[test]
    fn auth_binding_matches_spec_field_order() {
        let key = Ed25519Keypair::from_seed([1; 32]).unwrap();
        let bytes =
            auth_signing_bytes(&[2; 32], &[3; 32], &[4; 32], b"alice", &key.public_key()).unwrap();
        assert_eq!(&bytes[..14], b"ssxpro-auth-v1");
        assert_eq!(&bytes[14..46], &[2; 32]);
        assert_eq!(&bytes[46..78], &[3; 32]);
        assert_eq!(&bytes[78..110], &[4; 32]);
        assert_eq!(&bytes[110..115], b"alice");
        assert_eq!(&bytes[115..], &key.public_key().0);
        assert!(auth_signing_bytes(&[0; 32], &[0; 32], &[0; 32], b"", &key.public_key()).is_err());
    }
    #[test]
    fn authorized_keys_rejects_non_ed25519_and_bad_base64() {
        assert!(parse_authorized_keys("ssh-rsa abcd user\n").is_err());
        assert!(parse_authorized_keys("ed25519 !!! bad\n").is_err());
        assert!(parse_authorized_keys("ed25519 YWJj command=echo\n").is_err());
    }

    #[test]
    fn strict_user_files_require_private_modes_and_no_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let home = std::env::temp_dir().join(format!("ssxpro-crypto-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        write_user_file_new(&home, "key", b"secret").unwrap();
        assert_eq!(read_user_file(&home, "key", 16).unwrap(), b"secret");
        std::fs::set_permissions(
            home.join(".ssx/key"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let error = read_user_file(&home, "key", 16).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains(&home.join(".ssx/key").display().to_string()),
            "{message}"
        );
        assert!(message.contains("unexpected permissions"), "{message}");
        assert!(message.contains("0640"), "{message}");
        std::fs::remove_file(home.join(".ssx/key")).unwrap();
        let outside = home.join("outside");
        std::fs::write(&outside, b"secret").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&outside, home.join(".ssx/key")).unwrap();
        assert!(read_user_file(&home, "key", 16).is_err());
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn file_reads_reject_fifos_even_without_permission_checks() {
        let dir = std::env::temp_dir().join(format!("ssxpro-fifo-test-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("fifo");
        let path_c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: path_c is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);
        for enforce_permissions in [false, true] {
            assert!(matches!(
                read_strict_file(&path, 16, "too large", enforce_permissions),
                Err(CryptoError::InvalidFormat("not a regular file"))
            ));
        }
        assert!(matches!(
            openat2_file(
                libc::AT_FDCWD,
                path.to_str().unwrap(),
                libc::O_RDONLY as u64,
                0,
                RESOLVE_NO_SYMLINKS
            ),
            Err(CryptoError::InvalidFormat("not a regular file"))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn server_file_requires_private_modes_and_no_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir =
            std::env::temp_dir().join(format!("ssxpro-server-file-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("authorized_keys");
        std::fs::write(&path, b"ed25519 AAAA\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = read_server_file(&path, 1024).unwrap_err();
        let message = error.to_string();
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.contains("unexpected permissions"), "{message}");
        assert!(message.contains("0644"), "{message}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_server_file(&path, 1024).unwrap(), b"ed25519 AAAA\n");
        std::fs::remove_file(&path).unwrap();
        symlink(dir.join("missing"), &path).unwrap();
        assert!(read_server_file(&path, 1024).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
