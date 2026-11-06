use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

#[derive(Debug, Clone)]
pub struct LoginIdentity {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub shell: PathBuf,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Debug)]
pub enum SessionError {
    Io(io::Error),
    Policy(&'static str),
    UserNotFound,
}
impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Policy(e) => f.write_str(e),
            Self::UserNotFound => f.write_str("user does not exist"),
        }
    }
}
impl std::error::Error for SessionError {}
impl From<io::Error> for SessionError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub fn lookup_login_identity(name: &str, permit_root: bool) -> Result<LoginIdentity, SessionError> {
    if name.is_empty()
        || name.len() > 256
        || name.bytes().any(|b| b == 0 || b.is_ascii_whitespace())
    {
        return Err(SessionError::Policy("invalid login name"));
    }
    let c_name = CString::new(name).map_err(|_| SessionError::Policy("invalid login name"))?;
    let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];
    // SAFETY: passwd and buffer are writable; c_name is NUL terminated.
    let status = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            passwd.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status == libc::ERANGE {
        return Err(SessionError::Policy("NSS passwd entry exceeds 16 KiB"));
    }
    if status != 0 {
        return Err(SessionError::Io(io::Error::from_raw_os_error(status)));
    }
    if result.is_null() {
        return Err(SessionError::UserNotFound);
    }
    // SAFETY: successful getpwnam_r initialized passwd and points strings into buffer.
    let passwd = unsafe { passwd.assume_init() };
    // SAFETY: successful getpwnam_r returns NUL-terminated strings valid until buffer drops.
    let canonical_name = unsafe { CStr::from_ptr(passwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: same as above.
    let home = PathBuf::from(
        unsafe { CStr::from_ptr(passwd.pw_dir) }
            .to_string_lossy()
            .as_ref(),
    );
    // SAFETY: same as above.
    let shell = PathBuf::from(
        unsafe { CStr::from_ptr(passwd.pw_shell) }
            .to_string_lossy()
            .as_ref(),
    );
    let mut group_count = 0;
    // SAFETY: a null group list asks libc to report the required capacity.
    unsafe {
        libc::getgrouplist(
            c_name.as_ptr(),
            passwd.pw_gid,
            std::ptr::null_mut(),
            &mut group_count,
        );
    }
    if !(0..=65536).contains(&group_count) {
        return Err(SessionError::Policy(
            "account has too many supplementary groups",
        ));
    }
    let mut supplementary_groups = vec![0; group_count as usize];
    // SAFETY: vector capacity is exactly the group count reported by libc.
    if unsafe {
        libc::getgrouplist(
            c_name.as_ptr(),
            passwd.pw_gid,
            supplementary_groups.as_mut_ptr(),
            &mut group_count,
        )
    } < 0
    {
        return Err(SessionError::Io(io::Error::last_os_error()));
    }
    if passwd.pw_uid == 0 && !permit_root {
        return Err(SessionError::Policy("root login is disabled"));
    }
    if home.as_os_str().is_empty() || !home.is_absolute() {
        return Err(SessionError::Policy(
            "account has no absolute home directory",
        ));
    }
    validate_login_shell(&shell)?;
    Ok(LoginIdentity {
        name: canonical_name,
        uid: passwd.pw_uid,
        gid: passwd.pw_gid,
        home,
        shell,
        supplementary_groups,
    })
}

pub fn validate_login_shell(shell: &std::path::Path) -> Result<(), SessionError> {
    let shell_text = shell
        .to_str()
        .ok_or(SessionError::Policy("shell path is not UTF-8"))?;
    if shell_text.ends_with("/nologin") || shell_text.ends_with("/false") || !shell.is_absolute() {
        return Err(SessionError::Policy(
            "account shell is not an interactive login shell",
        ));
    }
    let allowed = std::fs::read_to_string("/etc/shells")?;
    if !allowed
        .lines()
        .map(str::trim)
        .any(|line| line == shell_text)
    {
        return Err(SessionError::Policy(
            "account shell is not listed in /etc/shells",
        ));
    }
    let metadata = std::fs::metadata(shell)?;
    use std::os::unix::fs::PermissionsExt;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(SessionError::Policy(
            "account shell is not an executable file",
        ));
    }
    Ok(())
}

pub struct SpawnedSession {
    child: Child,
    master: Option<OwnedFd>,
    pidfd: OwnedFd,
    exited: bool,
}

impl SpawnedSession {
    pub fn master_fd(&self) -> Option<RawFd> {
        self.master.as_ref().map(AsRawFd::as_raw_fd)
    }
    pub fn take_master(&mut self) -> Option<OwnedFd> {
        self.master.take()
    }
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn pidfd(&self) -> RawFd {
        self.pidfd.as_raw_fd()
    }
    pub fn signal_group(&self, signal: i32) -> io::Result<()> {
        if self.exited {
            return Ok(());
        }
        self.kill_group_with(signal)
    }
    /// Signal the process group even after the session leader has been reaped.
    /// This is the backstop that prevents background descendants from keeping
    /// the PTY (and a worker reader thread) alive after the shell exits.
    pub fn kill_group(&self) -> io::Result<()> {
        self.kill_group_with(libc::SIGKILL)
    }
    fn kill_group_with(&self, signal: i32) -> io::Result<()> {
        // SAFETY: child is the session/process-group leader established by setsid.
        if unsafe { libc::kill(-(self.child.id() as i32), signal) } < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(error);
        }
        Ok(())
    }
    /// Observe child exit through the pidfd. `waitid(P_PIDFD, WEXITED | WNOHANG)`
    /// both reaps the child and reports whether it exited normally or by signal.
    pub fn try_wait_status(&mut self) -> io::Result<Option<(ssxpro_proto::ExitKind, u8)>> {
        if self.exited {
            return Ok(None);
        }
        #[repr(C)]
        struct SigInfoBase {
            si_signo: libc::c_int,
            si_errno: libc::c_int,
            si_code: libc::c_int,
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: pidfd is an open pidfd for this child and info is writable.
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.pidfd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: waitid initialized info when it reports a child.
        if unsafe { info.si_pid() } == 0 {
            return Ok(None);
        }
        // SAFETY: the first three siginfo_t fields are the common base layout.
        let code = unsafe { (*(&info as *const libc::siginfo_t as *const SigInfoBase)).si_code };
        // SAFETY: si_status is valid for SIGCHLD siginfo.
        let status = unsafe { info.si_status() };
        self.exited = true;
        let kind = if code == libc::CLD_EXITED {
            ssxpro_proto::ExitKind::Status
        } else {
            ssxpro_proto::ExitKind::Signal
        };
        Ok(Some((kind, status.clamp(0, 255) as u8)))
    }
}

impl Drop for SpawnedSession {
    fn drop(&mut self) {
        if self.exited {
            return;
        }
        let _ = self.signal_group(libc::SIGHUP);
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(150);
        while std::time::Instant::now() < deadline {
            match self.try_wait_status() {
                Ok(Some(_)) => {
                    // The leader is gone; reap any background descendants too.
                    let _ = self.kill_group();
                    return;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(5)),
                Err(_) => break,
            }
        }
        let _ = self.signal_group(libc::SIGKILL);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: pidfd is owned by this object and blocking waitid reaps the child.
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.pidfd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED,
            );
        }
    }
}

/// The worker-side view of a broker-created PTY. The master descriptor arrives
/// over SCM_RIGHTS; process lifecycle and signal delivery stay with the broker.
pub struct PtySession {
    master: OwnedFd,
    session_id: u64,
    exit: Option<(ssxpro_proto::ExitKind, u8)>,
}

impl PtySession {
    pub fn from_broker(master: OwnedFd, session_id: u64) -> Self {
        Self {
            master,
            session_id,
            exit: None,
        }
    }
    pub fn master_fd(&self) -> RawFd {
        self.master.as_raw_fd()
    }
    pub fn session_id(&self) -> u64 {
        self.session_id
    }
    pub fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: master fd is open and size points to a valid winsize structure.
        if unsafe { libc::ioctl(self.master_fd(), libc::TIOCSWINSZ as _, &size) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn set_exit(&mut self, kind: ssxpro_proto::ExitKind, value: u8) {
        self.exit = Some((kind, value));
    }
    pub fn exit_status(&self) -> Option<(ssxpro_proto::ExitKind, u8)> {
        self.exit
    }
}

pub fn spawn_login_session(
    identity: &LoginIdentity,
    term: &str,
    rows: u16,
    cols: u16,
) -> Result<SpawnedSession, SessionError> {
    let (master, slave) = open_pty(rows, cols)?;
    let master_file = File::from(master);
    let slave_file = File::from(slave);
    let stdin_slave = slave_file.try_clone()?;
    let stdout_slave = slave_file.try_clone()?;
    let mut command = Command::new(&identity.shell);
    let login_argv0 = format!(
        "-{}",
        identity
            .shell
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("sh")
    );
    let home = CString::new(identity.home.as_os_str().as_encoded_bytes())
        .map_err(|_| SessionError::Policy("home path contains NUL"))?;
    let groups = identity.supplementary_groups.clone();
    let uid = identity.uid;
    let gid = identity.gid;
    // SAFETY: geteuid/getegid have no arguments and no side effects.
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    // The broker normally runs as root and drops to the target identity here.
    // Unprivileged development mode (ssxd --skip-config-permissions) may run
    // the broker directly as the target account; privilege dropping is then
    // both impossible (no CAP_SETGID/SETUID) and unnecessary. Any other
    // unprivileged identity mismatch fails closed.
    let drop_privileges = euid == 0;
    let already_target = euid == uid && egid == gid;
    // Detect the parent-death race where the broker exits before the child
    // installs PR_SET_PDEATHSIG.
    // SAFETY: getpid has no pointer arguments or side effects.
    let expected_parent = unsafe { libc::getpid() };
    command
        .arg0(login_argv0)
        .env_clear()
        .env("HOME", &identity.home)
        .env("USER", &identity.name)
        .env("LOGNAME", &identity.name)
        .env("SHELL", &identity.shell)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("TERM", term)
        .stdin(Stdio::from(stdin_slave))
        .stdout(Stdio::from(stdout_slave))
        .stderr(Stdio::from(slave_file));
    // SAFETY: closure runs in the post-fork child and only calls async-signal-safe syscalls.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGHUP, 0, 0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != expected_parent {
                return Err(io::Error::from_raw_os_error(libc::ECANCELED));
            }
            if drop_privileges {
                if libc::setgroups(groups.len(), groups.as_ptr()) < 0
                    || libc::setresgid(gid, gid, gid) < 0
                    || libc::setresuid(uid, uid, uid) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            } else if !already_target {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            if libc::chdir(home.as_ptr()) < 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
                || libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let pidfd = match pidfd_open(child.id()) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
    };
    Ok(SpawnedSession {
        child,
        master: Some(master_file_to_owned(master_file)),
        // SAFETY: pidfd_open returned an owned descriptor.
        pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) },
        exited: false,
    })
}

pub fn signal_to_libc(signal: ssxpro_proto::Signal) -> i32 {
    match signal {
        ssxpro_proto::Signal::Hup => libc::SIGHUP,
        ssxpro_proto::Signal::Int => libc::SIGINT,
        ssxpro_proto::Signal::Quit => libc::SIGQUIT,
        ssxpro_proto::Signal::Term => libc::SIGTERM,
        ssxpro_proto::Signal::Kill => libc::SIGKILL,
        ssxpro_proto::Signal::Tstp => libc::SIGTSTP,
        ssxpro_proto::Signal::Cont => libc::SIGCONT,
        ssxpro_proto::Signal::Winch => libc::SIGWINCH,
    }
}

fn open_pty(rows: u16, cols: u16) -> io::Result<(OwnedFd, OwnedFd)> {
    // SAFETY: posix_openpt has no pointer arguments and returns an owned fd.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if master < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: master is a valid pty master fd.
    if unsafe { libc::grantpt(master) } < 0 || unsafe { libc::unlockpt(master) } < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(master);
        }
        return Err(error);
    }
    // TIOCGPTPEER opens the slave directly from the master, avoiding a pathname
    // lookup between ptsname and open. The ioctl request type is `c_ulong` on
    // glibc and `c_int` on musl, so let inference pick it.
    const TIOCGPTPEER: libc::c_ulong = 0x5441;
    // SAFETY: master is an unlocked PTY master; ioctl returns a new slave fd.
    let slave = unsafe {
        libc::ioctl(
            master,
            TIOCGPTPEER as _,
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if slave < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(master);
        }
        return Err(error);
    }
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: slave fd is open and size is a valid winsize structure.
    if unsafe { libc::ioctl(slave, libc::TIOCSWINSZ as _, &size) } < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(error);
    }
    // SAFETY: both descriptors are newly created and owned here.
    Ok((unsafe { OwnedFd::from_raw_fd(master) }, unsafe {
        OwnedFd::from_raw_fd(slave)
    }))
}

fn pidfd_open(pid: u32) -> io::Result<RawFd> {
    // pidfd_open is syscall 434 on supported Linux architectures.
    // SAFETY: syscall arguments are scalar and pid is a live child PID.
    let fd = unsafe { libc::syscall(434, pid, 0u32) as RawFd };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn master_file_to_owned(file: File) -> OwnedFd {
    use std::os::fd::IntoRawFd;
    // SAFETY: into_raw_fd transfers unique ownership.
    unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) }
}
