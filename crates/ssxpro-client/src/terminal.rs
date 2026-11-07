use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};

static RAW_FD: AtomicI32 = AtomicI32::new(-1);
static ORIGINAL_TERMIOS: AtomicPtr<libc::termios> = AtomicPtr::new(std::ptr::null_mut());
static SIGNALS_INSTALLED: AtomicBool = AtomicBool::new(false);
static RESIZE_PENDING: AtomicBool = AtomicBool::new(false);

extern "C" fn restore_terminal_and_exit(signal: libc::c_int) {
    let fd = RAW_FD.load(Ordering::Relaxed);
    let original = ORIGINAL_TERMIOS.load(Ordering::Relaxed);
    if fd >= 0 && !original.is_null() {
        // SAFETY: RawMode owns this boxed termios until it clears the atomic pointer.
        unsafe {
            libc::tcsetattr(fd, libc::TCSAFLUSH, original);
        }
    }
    // SAFETY: _exit is async-signal-safe and does not run Rust destructors.
    unsafe { libc::_exit(128 + signal) }
}

extern "C" fn record_window_resize(_: libc::c_int) {
    RESIZE_PENDING.store(true, Ordering::Relaxed);
}

pub fn take_resize_pending() -> bool {
    RESIZE_PENDING.swap(false, Ordering::AcqRel)
}

fn install_terminal_signals() -> io::Result<()> {
    if SIGNALS_INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }
    // This CLI has one foreground terminal at a time, so only one thread can
    // install the handlers.
    // SAFETY: sigaction receives a valid handler and initialized action structs.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = restore_terminal_and_exit as *const () as usize;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGHUP, &action, std::ptr::null_mut()) != 0
        {
            return Err(io::Error::last_os_error());
        }
        action.sa_sigaction = record_window_resize as *const () as usize;
        if libc::sigaction(libc::SIGWINCH, &action, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    SIGNALS_INSTALLED.store(true, Ordering::Release);
    Ok(())
}

/// Restores the exact terminal attributes that were active before entering raw mode.
pub struct RawMode {
    fd: RawFd,
    original: Option<Box<libc::termios>>,
}

impl RawMode {
    pub fn enter(fd: RawFd) -> io::Result<Self> {
        // SAFETY: termios is a plain C struct and tcgetattr initializes it on success.
        let mut original = Box::new(unsafe { std::mem::zeroed::<libc::termios>() });
        // SAFETY: fd is borrowed from the caller and original is writable.
        if unsafe { libc::tcgetattr(fd, original.as_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = *original;
        // SAFETY: cfmakeraw only mutates the supplied termios value.
        unsafe { libc::cfmakeraw(&mut raw) };
        install_terminal_signals()?;
        ORIGINAL_TERMIOS.store(original.as_mut(), Ordering::Release);
        RAW_FD.store(fd, Ordering::Release);
        // SAFETY: fd remains caller-owned, raw is a valid termios value.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } != 0 {
            RAW_FD.store(-1, Ordering::Release);
            ORIGINAL_TERMIOS.store(std::ptr::null_mut(), Ordering::Release);
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            original: Some(original),
        })
    }

    pub fn restore(&mut self) -> io::Result<()> {
        // SAFETY: fd is borrowed and original was initialized by tcgetattr.
        let original = self
            .original
            .as_ref()
            .expect("raw mode owns original termios");
        if unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &**original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = self.restore();
        let original = self
            .original
            .take()
            .expect("raw mode owns original termios");
        let pointer = Box::as_ref(&original) as *const libc::termios as *mut libc::termios;
        let _ = ORIGINAL_TERMIOS.compare_exchange(
            pointer,
            std::ptr::null_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        let _ = RAW_FD.compare_exchange(self.fd, -1, Ordering::AcqRel, Ordering::Acquire);
        // A signal handler may already have loaded this pointer. Keep its target
        // alive until process exit to avoid racing a signal with Box deallocation.
        let _ = Box::leak(original);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeAction {
    Disconnect,
    Suspend,
    Help,
}

/// Translates OpenSSH-style escapes only when `at_line_start` is true.
pub struct EscapeDecoder {
    pending_escape: bool,
    at_line_start: bool,
}

impl Default for EscapeDecoder {
    fn default() -> Self {
        Self {
            pending_escape: false,
            at_line_start: true,
        }
    }
}

impl EscapeDecoder {
    pub fn process(&mut self, input: &[u8], output: &mut [u8]) -> (usize, Option<EscapeAction>) {
        let mut written = 0;
        let mut action = None;
        for &byte in input {
            if self.pending_escape {
                self.pending_escape = false;
                match byte {
                    b'.' => action = Some(EscapeAction::Disconnect),
                    0x1a => action = Some(EscapeAction::Suspend),
                    b'?' => action = Some(EscapeAction::Help),
                    b'~' => {
                        if written < output.len() {
                            output[written] = b'~';
                            written += 1;
                        }
                        self.at_line_start = false;
                    }
                    other => {
                        if written + 2 <= output.len() {
                            output[written] = b'~';
                            output[written + 1] = other;
                            written += 2;
                        }
                        self.at_line_start = other == b'\n';
                    }
                }
            } else if self.at_line_start && byte == b'~' {
                self.pending_escape = true;
            } else {
                if written < output.len() {
                    output[written] = byte;
                    written += 1;
                }
                self.at_line_start = byte == b'\n';
            }
        }
        (written, action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_escape_expands_a_full_input_chunk() {
        let mut decoder = EscapeDecoder::default();
        let mut output = [0; 257];
        assert_eq!(decoder.process(b"~", &mut output), (0, None));
        let (n, action) = decoder.process(&[b'x'; 256], &mut output);
        assert_eq!(n, 257);
        assert_eq!(action, None);
        assert_eq!(output[0], b'~');
        assert_eq!(&output[1..], &[b'x'; 256]);
    }

    #[test]
    fn escapes_only_trigger_at_line_start() {
        let mut decoder = EscapeDecoder::default();
        let mut output = [0; 32];
        let (n, action) = decoder.process(b"hello~.\n~?", &mut output);
        assert_eq!(&output[..n], b"hello~.\n");
        assert_eq!(action, Some(EscapeAction::Help));
    }
    #[test]
    fn doubled_escape_is_literal() {
        let mut decoder = EscapeDecoder::default();
        let mut output = [0; 8];
        let (n, action) = decoder.process(b"~~", &mut output);
        assert_eq!(&output[..n], b"~");
        assert_eq!(action, None);
    }
}
