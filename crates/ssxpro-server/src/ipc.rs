//! Bounded worker/session-broker IPC, SCM_RIGHTS transfer, and one-time
//! session-authorization tokens.

use boring::hash::hmac_sha256;
use ssxpro_crypto::{constant_time_eq, getrandom};
use ssxpro_proto::{
    decode_session_token, encode_session_token, MAX_SESSION_TOKEN, SESSION_TOKEN_MAC_LEN,
    SESSION_TOKEN_NONCE_LEN,
};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::session::LoginIdentity;

const MAX_SCM_FDS: usize = 8;
const SESSION_TOKEN_LIFETIME_SECS: u64 = 30;
const SESSION_TOKEN_CLOCK_SKEW_SECS: u64 = 5;

pub enum ChannelEvent {
    Empty,
    Closed,
    Message(ReceivedMessage),
}

pub struct ReceivedMessage {
    pub data: Vec<u8>,
    pub fds: Vec<OwnedFd>,
}

/// A `SOCK_SEQPACKET` channel. Each message is one bounded frame and may carry
/// file descriptors. Both ends are nonblocking so neither a worker nor the
/// privileged broker can stall the other.
pub struct SessionChannel {
    fd: OwnedFd,
}

impl SessionChannel {
    pub fn pair() -> io::Result<(Self, Self)> {
        let mut fds = [-1; 2];
        // SAFETY: fds points to two writable integers and the flags are valid.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                fds.as_mut_ptr(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful socketpair returned two newly owned descriptors.
        Ok((
            Self {
                fd: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            },
            Self {
                fd: unsafe { OwnedFd::from_raw_fd(fds[1]) },
            },
        ))
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn send(&self, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
        if fds.len() > MAX_SCM_FDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many descriptors in one IPC message",
            ));
        }
        let mut iov = libc::iovec {
            iov_base: data.as_ptr() as *mut _,
            iov_len: data.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        let cmsg_space = if fds.is_empty() {
            0
        } else {
            // SAFETY: CMSG_SPACE only computes storage from a scalar length.
            unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as libc::c_uint) as usize }
        };
        let words = cmsg_space.div_ceil(std::mem::size_of::<usize>());
        let mut control = vec![0usize; words];
        if !fds.is_empty() {
            message.msg_control = control.as_mut_ptr().cast();
            // `msg_controllen` is `usize` on glibc and `socklen_t` on musl.
            message.msg_controllen = cmsg_space as _;
            // SAFETY: control has at least CMSG_SPACE bytes for the declared fds.
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                if header.is_null() {
                    return Err(io::Error::other("could not construct SCM_RIGHTS message"));
                }
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len =
                    libc::CMSG_LEN(std::mem::size_of_val(fds) as libc::c_uint) as _;
                let data_ptr = libc::CMSG_DATA(header).cast::<libc::c_int>();
                for (index, fd) in fds.iter().enumerate() {
                    data_ptr.add(index).write_unaligned(*fd);
                }
            }
        }
        // SAFETY: message references iov, control, and data for the duration of the call.
        let result = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result as usize != data.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short SOCK_SEQPACKET IPC send",
            ));
        }
        Ok(())
    }

    // `msg_controllen` and `cmsg_len` are `usize` on glibc and `socklen_t` on
    // musl; the casts are required on one target and redundant on the other.
    #[allow(clippy::unnecessary_cast)]
    pub fn recv(&self, buffer: &mut [u8]) -> io::Result<ChannelEvent> {
        loop {
            let mut iov = libc::iovec {
                iov_base: buffer.as_mut_ptr().cast(),
                iov_len: buffer.len(),
            };
            let mut control = [0usize; MAX_SCM_FDS * 2];
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = std::mem::size_of_val(&control) as _;
            // SAFETY: message references writable iov and control storage.
            let result = unsafe {
                libc::recvmsg(
                    self.fd.as_raw_fd(),
                    &mut message,
                    libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                return match error.kind() {
                    io::ErrorKind::WouldBlock => Ok(ChannelEvent::Empty),
                    io::ErrorKind::Interrupted => continue,
                    _ => Err(error),
                };
            }
            if result == 0 {
                return Ok(ChannelEvent::Closed);
            }
            let mut fds = Vec::new();
            let mut ancillary_error = None;
            // SAFETY: recvmsg initialized the control buffer and its cmsghdrs.
            unsafe {
                let control_start = message.msg_control as usize;
                let control_end = control_start.saturating_add(message.msg_controllen as usize);
                let minimum = libc::CMSG_LEN(0) as usize;
                let mut header = libc::CMSG_FIRSTHDR(&message);
                while !header.is_null() {
                    let header_start = header as usize;
                    if header_start < control_start
                        || header_start
                            .checked_add(minimum)
                            .is_none_or(|end| end > control_end)
                    {
                        ancillary_error = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "malformed ancillary data on worker IPC",
                        ));
                        break;
                    }
                    let cmsg_len = (*header).cmsg_len as usize;
                    if cmsg_len < minimum
                        || header_start
                            .checked_add(cmsg_len)
                            .is_none_or(|end| end > control_end)
                    {
                        ancillary_error = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "truncated ancillary data on worker IPC",
                        ));
                        break;
                    }
                    if (*header).cmsg_level != libc::SOL_SOCKET
                        || (*header).cmsg_type != libc::SCM_RIGHTS
                    {
                        ancillary_error = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unsupported ancillary data on worker IPC",
                        ));
                    } else {
                        let data = libc::CMSG_DATA(header).cast::<libc::c_int>();
                        let payload = cmsg_len - minimum;
                        let count = payload / std::mem::size_of::<libc::c_int>();
                        if count > MAX_SCM_FDS {
                            ancillary_error = Some(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "too many descriptors on worker IPC",
                            ));
                        }
                        for index in 0..count.min(MAX_SCM_FDS) {
                            let fd = data.add(index).read_unaligned();
                            if fd < 0 {
                                ancillary_error = Some(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid descriptor on worker IPC",
                                ));
                                continue;
                            }
                            // SAFETY: SCM_RIGHTS installed a newly owned descriptor.
                            fds.push(OwnedFd::from_raw_fd(fd));
                        }
                    }
                    header = libc::CMSG_NXTHDR(&message, header);
                }
            }
            if message.msg_flags & libc::MSG_CTRUNC != 0 || message.msg_flags & libc::MSG_TRUNC != 0
            {
                // `fds` is dropped here, closing any descriptors installed
                // before the kernel reported truncation.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "worker IPC message was truncated",
                ));
            }
            if let Some(error) = ancillary_error {
                return Err(error);
            }
            return Ok(ChannelEvent::Message(ReceivedMessage {
                data: buffer[..result as usize].to_vec(),
                fds,
            }));
        }
    }
}

pub struct VerifiedSession {
    pub nonce: [u8; SESSION_TOKEN_NONCE_LEN],
    pub expires_at: u64,
    pub identity: LoginIdentity,
}

pub fn mint_session_token(
    secret: &[u8; 32],
    identity: &LoginIdentity,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let home = identity
        .home
        .to_str()
        .ok_or("home path is not valid UTF-8")?;
    let shell = identity
        .shell
        .to_str()
        .ok_or("shell path is not valid UTF-8")?;
    let now = unix_now()?;
    let expires_at = now.saturating_add(SESSION_TOKEN_LIFETIME_SECS);
    let mut nonce = [0u8; SESSION_TOKEN_NONCE_LEN];
    getrandom(&mut nonce)?;
    let mut token = vec![0u8; MAX_SESSION_TOKEN];
    let length = encode_session_token(
        &nonce,
        now,
        expires_at,
        &identity.name,
        identity.uid,
        identity.gid,
        home,
        shell,
        &identity.supplementary_groups,
        &[0u8; SESSION_TOKEN_MAC_LEN],
        &mut token,
    )?;
    let mac = hmac_sha256(secret, &token[..length - SESSION_TOKEN_MAC_LEN])?;
    token[length - SESSION_TOKEN_MAC_LEN..length].copy_from_slice(&mac);
    token.truncate(length);
    Ok(token)
}

pub fn verify_session_token(secret: &[u8; 32], token: &[u8]) -> Option<VerifiedSession> {
    let decoded = decode_session_token(token).ok()?;
    if decoded.mac.len() != SESSION_TOKEN_MAC_LEN {
        return None;
    }
    let mac = hmac_sha256(secret, &token[..token.len() - SESSION_TOKEN_MAC_LEN]).ok()?;
    if !constant_time_eq(&mac, decoded.mac) {
        return None;
    }
    let now = unix_now().ok()?;
    if decoded.issued_at > now.saturating_add(SESSION_TOKEN_CLOCK_SKEW_SECS)
        || decoded.expires_at < now
        || decoded.expires_at.saturating_sub(decoded.issued_at) > SESSION_TOKEN_LIFETIME_SECS
    {
        return None;
    }
    let (group_chunks, remainder) = decoded.groups.as_chunks::<4>();
    if !remainder.is_empty() {
        return None;
    }
    Some(VerifiedSession {
        nonce: decoded.nonce,
        expires_at: decoded.expires_at,
        identity: LoginIdentity {
            name: decoded.name.to_owned(),
            uid: decoded.uid,
            gid: decoded.gid,
            home: decoded.home.into(),
            shell: decoded.shell.into(),
            supplementary_groups: group_chunks
                .iter()
                .map(|chunk| u32::from_be_bytes(*chunk))
                .collect(),
        },
    })
}

fn unix_now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| io::Error::other("system clock is before the Unix epoch"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn test_identity() -> LoginIdentity {
        LoginIdentity {
            name: "alice".to_owned(),
            uid: 1000,
            gid: 1000,
            home: "/home/alice".into(),
            shell: "/bin/sh".into(),
            supplementary_groups: vec![10, 20],
        }
    }

    #[test]
    fn session_token_is_authenticated_and_rejects_tampering() {
        let secret = [0x42; 32];
        let identity = test_identity();
        let token = mint_session_token(&secret, &identity).unwrap();
        let second = mint_session_token(&secret, &identity).unwrap();
        assert_ne!(token[4..20], second[4..20]);
        let verified = verify_session_token(&secret, &token).unwrap();
        assert_eq!(verified.identity.name, identity.name);
        assert_eq!(verified.identity.uid, identity.uid);
        assert_eq!(verified.identity.gid, identity.gid);
        assert_eq!(verified.identity.home, identity.home);
        assert_eq!(verified.identity.shell, identity.shell);
        assert_eq!(
            verified.identity.supplementary_groups,
            identity.supplementary_groups
        );
        assert!(verify_session_token(&[0x43; 32], &token).is_none());
        let mut changed = token;
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(verify_session_token(&secret, &changed).is_none());
    }

    #[test]
    fn channel_transfers_a_descriptor() {
        let (left, right) = SessionChannel::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        left.send(b"hello", &[file.as_raw_fd()]).unwrap();
        let mut buffer = [0u8; 32];
        match right.recv(&mut buffer).unwrap() {
            ChannelEvent::Message(message) => {
                assert_eq!(message.data, b"hello");
                assert_eq!(message.fds.len(), 1);
                let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: the received descriptor is open and stat is writable.
                assert_eq!(
                    unsafe { libc::fstat(message.fds[0].as_raw_fd(), &mut stat) },
                    0
                );
            }
            _ => panic!("expected a descriptor message"),
        }
    }
}
