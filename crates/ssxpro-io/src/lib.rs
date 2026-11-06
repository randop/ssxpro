#![deny(unsafe_op_in_unsafe_fn)]

//! Linux io_uring capability checks shared by startup and `--check-config`.

#[cfg(not(target_os = "linux"))]
compile_error!("ssxpro requires Linux");

use std::collections::VecDeque;
use std::ffi::c_void;
use std::fmt;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// A single-issuer io_uring with the project baseline setup flags. The underlying
/// ring stays private so callers use the bounded runtime API rather than fallbacks.
pub struct RuntimeRing {
    inner: io_uring::IoUring,
    fixed_files: Vec<Option<RawFd>>,
}

const FIXED_FILE_SLOTS: usize = 32;

impl RuntimeRing {
    pub fn new(entries: u32, restricted: bool, max_iowq: [u32; 2]) -> std::io::Result<Self> {
        Self::new_with_files(entries, restricted, max_iowq, FIXED_FILE_SLOTS as u32)
    }

    /// Build a ring whose direct-descriptor table can hold `fixed_file_slots`
    /// entries. The server sizes this to its per-worker session limit so every
    /// PTY master can be installed when the session opens.
    pub fn new_with_files(
        entries: u32,
        restricted: bool,
        max_iowq: [u32; 2],
        fixed_file_slots: u32,
    ) -> std::io::Result<Self> {
        let fixed_file_slots = fixed_file_slots.max(1) as usize;
        let mut builder = io_uring::IoUring::builder();
        builder
            .setup_clamp()
            .setup_single_issuer()
            .setup_defer_taskrun()
            .setup_coop_taskrun()
            .setup_no_sqarray();
        if restricted {
            builder.setup_r_disabled();
        }
        let ring = builder.build(entries)?;
        ring.submitter()
            .register_iowq_max_workers(&mut max_iowq.clone())?;
        ring.submitter()
            .register_files_sparse(fixed_file_slots as u32)?;
        if restricted {
            use io_uring::register::Restriction;
            // IORING_REGISTER_FILES_UPDATE (stable UAPI opcode 6). Once a ring
            // is enabled with restrictions, the kernel denies every register
            // opcode that is not allowlisted here, so lazy fixed-file
            // registration (PTY masters, terminal descriptors) requires this
            // entry to be present.
            const IORING_REGISTER_FILES_UPDATE_OP: u8 = 6;
            let allowed = [9u8, 10, 11, 14, 22, 23, 40, 47, 48];
            let mut restrictions = allowed
                .into_iter()
                .map(Restriction::sqe_op)
                .collect::<Vec<_>>();
            restrictions.push(Restriction::register_op(IORING_REGISTER_FILES_UPDATE_OP));
            let sqe_flags = (io_uring::squeue::Flags::FIXED_FILE
                | io_uring::squeue::Flags::IO_LINK
                | io_uring::squeue::Flags::IO_HARDLINK
                | io_uring::squeue::Flags::IO_DRAIN
                | io_uring::squeue::Flags::ASYNC
                | io_uring::squeue::Flags::BUFFER_SELECT
                | io_uring::squeue::Flags::SKIP_SUCCESS)
                .bits();
            restrictions.push(Restriction::sqe_flags_allowed(sqe_flags));
            ring.submitter().register_restrictions(&mut restrictions)?;
            ring.submitter().register_enable_rings()?;
        }
        Ok(Self {
            inner: ring,
            fixed_files: vec![None; fixed_file_slots],
        })
    }

    /// Register a descriptor in the ring's sparse table and return its stable
    /// index. Repeated calls for the same descriptor reuse the existing slot.
    pub fn register_fd(&mut self, fd: RawFd) -> std::io::Result<io_uring::types::Fixed> {
        if let Some(index) = self
            .fixed_files
            .iter()
            .position(|registered| *registered == Some(fd))
        {
            return Ok(io_uring::types::Fixed(index as u32));
        }
        let index = self
            .fixed_files
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| std::io::Error::other("registered descriptor table is full"))?;
        let updated = self
            .inner
            .submitter()
            .register_files_update(index as u32, &[fd])?;
        if updated != 1 {
            return Err(std::io::Error::other(
                "io_uring did not register the requested descriptor",
            ));
        }
        self.fixed_files[index] = Some(fd);
        Ok(io_uring::types::Fixed(index as u32))
    }

    /// Remove a registered descriptor before the owning descriptor is closed,
    /// preventing a later fd-number reuse from referring to the old file.
    pub fn unregister_fd(&mut self, fd: RawFd) -> std::io::Result<()> {
        let Some(index) = self
            .fixed_files
            .iter()
            .position(|registered| *registered == Some(fd))
        else {
            return Ok(());
        };
        let updated = self
            .inner
            .submitter()
            .register_files_update(index as u32, &[-1])?;
        if updated != 1 {
            return Err(std::io::Error::other(
                "io_uring did not unregister the requested descriptor",
            ));
        }
        self.fixed_files[index] = None;
        Ok(())
    }

    pub fn ring(&self) -> &io_uring::IoUring {
        &self.inner
    }
    pub fn ring_mut(&mut self) -> &mut io_uring::IoUring {
        &mut self.inner
    }

    /// Submit one operation and wait for its CQE. All backing memory must remain
    /// valid until this returns; callers can therefore use stack-backed msghdrs.
    pub fn submit_wait(&mut self, entry: &io_uring::squeue::Entry) -> std::io::Result<i32> {
        {
            let mut queue = self.inner.submission();
            // SAFETY: submit_wait does not return until this SQE has a completion,
            // and the caller keeps all SQE-referenced memory alive for this call.
            unsafe {
                queue
                    .push(entry)
                    .map_err(|_| std::io::Error::other("submission queue is full"))?;
            }
        }
        self.inner.submit_and_wait(1)?;
        let mut queue = self.inner.completion();
        let cqe = queue
            .next()
            .ok_or_else(|| std::io::Error::other("io_uring returned without a CQE"))?;
        if cqe.result() < 0 {
            return Err(std::io::Error::from_raw_os_error(-cqe.result()));
        }
        Ok(cqe.result())
    }

    /// Submit one operation without waiting for a completion. Returns the CQE
    /// result if one is immediately available, or `WouldBlock` if the kernel
    /// has not yet completed the operation.
    pub fn submit_nowait(&mut self, entry: &io_uring::squeue::Entry) -> std::io::Result<i32> {
        {
            let mut queue = self.inner.submission();
            // SAFETY: submit_nowait does not wait for a completion, but the
            // caller must keep SQE-referenced memory alive until the CQE is
            // consumed.
            unsafe {
                queue
                    .push(entry)
                    .map_err(|_| std::io::Error::other("submission queue is full"))?;
            }
        }
        // Submit all pending SQEs without waiting for completions.
        self.inner.submit()?;
        let mut queue = self.inner.completion();
        let cqe = queue.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "io_uring completion not yet available",
            )
        })?;
        if cqe.result() < 0 {
            return Err(std::io::Error::from_raw_os_error(-cqe.result()));
        }
        Ok(cqe.result())
    }

    pub fn wait_timeout(&mut self, timeout: std::time::Duration) -> std::io::Result<()> {
        let timespec = io_uring::types::Timespec::new()
            .sec(timeout.as_secs())
            .nsec(timeout.subsec_nanos());
        let entry = io_uring::opcode::Timeout::new(&timespec)
            .build()
            .user_data(u64::MAX);
        match self.submit_wait(&entry) {
            Ok(_) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ETIME) => Ok(()),
            // A spurious wakeup can leave the completion queue empty even though
            // `submit_and_wait` reported success. Treat that as a timeout and
            // let the broker poll again instead of failing the whole worker.
            Err(error) if error.to_string() == "io_uring returned without a CQE" => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// One registered UDP descriptor driven exclusively through io_uring SENDMSG/RECVMSG.
pub struct UdpEndpoint {
    fd: OwnedFd,
    pending: VecDeque<(SocketAddr, Vec<u8>)>,
    direct_io: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagramInfo {
    pub peer: SocketAddr,
    pub gro_segment_size: Option<u16>,
}

/// Keeps the kernel-verified selector and its sockarray alive for a reuseport
/// group. The attached sockets also hold references while they are open.
pub struct ReusePortCidSelector {
    _map: OwnedFd,
    _program: OwnedFd,
}

impl UdpEndpoint {
    pub fn bind(address: SocketAddr, reuse_port: bool) -> std::io::Result<Self> {
        let family = match address {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };
        // SAFETY: socket arguments are valid Linux constants.
        let raw = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: socket returned a newly owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // Use a receive timeout so blocking recvmsg returns WouldBlock periodically,
        // allowing the caller to check deadlines without blocking indefinitely.
        let recv_timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        if unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&recv_timeout as *const libc::timeval).cast(),
                std::mem::size_of_val(&recv_timeout) as _,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if reuse_port {
            let enabled: libc::c_int = 1;
            // SAFETY: enabled points to an int and fd is an open socket.
            if unsafe {
                libc::setsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEPORT,
                    (&enabled as *const libc::c_int).cast(),
                    std::mem::size_of_val(&enabled) as _,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        let (storage, length) = socket_address(address);
        // SAFETY: storage contains the address matching family and length.
        if unsafe {
            libc::bind(
                raw,
                (&storage as *const libc::sockaddr_storage).cast(),
                length,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // Direct raw syscalls are the default I/O mode and work on all hosts,
        // including those where unprivileged io_uring submission is restricted.
        // Set SSXPRO_USE_IO_URING=1 to opt into the io_uring submission path.
        let use_io_uring = std::env::var("SSXPRO_USE_IO_URING")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let direct_io = !use_io_uring;
        Ok(Self {
            fd,
            pending: VecDeque::new(),
            direct_io,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&storage) as libc::socklen_t;
        // SAFETY: storage is writable and length is initialized to its capacity.
        if unsafe {
            libc::getsockname(
                self.fd.as_raw_fd(),
                (&mut storage as *mut libc::sockaddr_storage).cast(),
                &mut length,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        parse_socket_address(&storage)
    }

    pub fn enable_gro(&self) -> std::io::Result<()> {
        let enabled: libc::c_int = 1;
        // SAFETY: enabled points to an int and fd is an open UDP socket.
        if unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_UDP,
                libc::UDP_GRO,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as _,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn set_receive_timeout(&self, timeout: std::time::Duration) -> std::io::Result<()> {
        let value = libc::timeval {
            // `time_t` is i32 on musl (in the pinned libc) and i64 on glibc;
            // cap at i32::MAX and let inference pick the field type.
            tv_sec: timeout.as_secs().min(i32::MAX as u64) as _,
            tv_usec: timeout.subsec_micros().into(),
        };
        // SAFETY: value points to a valid timeval and fd is an open UDP socket.
        if unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&value as *const libc::timeval).cast(),
                std::mem::size_of_val(&value) as _,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Install a kernel-verified `sk_reuseport` eBPF selector for a complete
    /// reuseport group. Server-issued QUIC CIDs encode the worker in byte zero;
    /// unrecognized or too-short CIDs retain kernel hash selection.
    pub fn attach_reuseport_cid_selector(
        endpoints: &[&UdpEndpoint],
    ) -> std::io::Result<Option<ReusePortCidSelector>> {
        if endpoints.len() < 2 {
            return Ok(None);
        }
        if endpoints.len() > 256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "reuseport CID selector supports at most 256 workers",
            ));
        }
        const BPF_MAP_CREATE: u32 = 0;
        const BPF_MAP_UPDATE_ELEM: u32 = 2;
        const BPF_PROG_LOAD: u32 = 5;
        const BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: u32 = 20;
        const BPF_PROG_TYPE_SK_REUSEPORT: u32 = 21;
        const BPF_SK_REUSEPORT_SELECT: u32 = 39;
        const SO_ATTACH_REUSEPORT_EBPF: libc::c_int = 52;

        #[repr(C)]
        struct MapCreateAttr {
            map_type: u32,
            key_size: u32,
            value_size: u32,
            max_entries: u32,
            map_flags: u32,
            inner_map_fd: u32,
            numa_node: u32,
            map_name: [u8; 16],
            map_ifindex: u32,
            btf_fd: u32,
            btf_key_type_id: u32,
            btf_value_type_id: u32,
            btf_vmlinux_value_type_id: u32,
            map_extra: u64,
        }
        #[repr(C)]
        struct MapElemAttr {
            map_fd: u32,
            pad: u32,
            key: u64,
            value: u64,
            flags: u64,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Insn {
            code: u8,
            regs: u8,
            off: i16,
            imm: i32,
        }
        #[repr(C)]
        struct ProgLoadAttr {
            prog_type: u32,
            insn_cnt: u32,
            insns: u64,
            license: u64,
            log_level: u32,
            log_size: u32,
            log_buf: u64,
            kern_version: u32,
            prog_flags: u32,
            prog_name: [u8; 16],
            prog_ifindex: u32,
            expected_attach_type: u32,
            prog_btf_fd: u32,
            func_info_rec_size: u32,
            func_info: u64,
            func_info_cnt: u32,
            line_info_rec_size: u32,
            line_info: u64,
            line_info_cnt: u32,
            attach_btf_id: u32,
            attach_prog_fd: u32,
            core_relo_cnt: u32,
            fd_array: u64,
            core_relos: u64,
            core_relo_rec_size: u32,
            log_true_size: u32,
            prog_token_fd: i32,
            fd_array_cnt: u32,
            signature: u64,
            signature_size: u32,
            keyring_id: i32,
        }
        fn bpf(command: u32, attr: *const c_void, size: usize) -> std::io::Result<OwnedFd> {
            // SAFETY: each caller passes a correctly laid out UAPI attribute and size.
            let fd = unsafe { libc::syscall(libc::SYS_bpf, command, attr, size) as libc::c_int };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: successful BPF commands used here return a newly owned FD.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
        fn map_update(map: RawFd, key: u32, value: u32) -> std::io::Result<()> {
            let attr = MapElemAttr {
                map_fd: map as u32,
                pad: 0,
                key: (&key as *const u32) as u64,
                value: (&value as *const u32) as u64,
                flags: 0,
            };
            // SAFETY: map and key/value pointers remain valid for the syscall.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    BPF_MAP_UPDATE_ELEM,
                    (&attr as *const MapElemAttr).cast::<c_void>(),
                    size_of::<MapElemAttr>(),
                )
            };
            if result < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }

        let map_attr = MapCreateAttr {
            map_type: BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
            key_size: 4,
            value_size: 4,
            max_entries: endpoints.len() as u32,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: *b"ssxpro_sockarr\0\0",
            map_ifindex: 0,
            btf_fd: 0,
            btf_key_type_id: 0,
            btf_value_type_id: 0,
            btf_vmlinux_value_type_id: 0,
            map_extra: 0,
        };
        let map = bpf(
            BPF_MAP_CREATE,
            (&map_attr as *const MapCreateAttr).cast(),
            size_of::<MapCreateAttr>(),
        )?;
        for (index, endpoint) in endpoints.iter().enumerate() {
            map_update(
                map.as_raw_fd(),
                index as u32,
                endpoint.fd.as_raw_fd() as u32,
            )?;
        }

        let insn = |code: u8, dst: u8, src: u8, off: i16, imm: i32| Insn {
            code,
            regs: (src << 4) | dst,
            off,
            imm,
        };
        let instructions = [
            insn(0xbf, 6, 1, 0, 0),                       // r6 = ctx
            insn(0x79, 7, 6, 0, 0),                       // r7 = ctx->data
            insn(0x79, 8, 6, 8, 0),                       // r8 = ctx->data_end
            insn(0xbf, 9, 7, 0, 0),                       // r9 = UDP header
            insn(0x07, 9, 0, 0, 10),                      // r9 = UDP payload + 2
            insn(0x2d, 9, 8, 24, 0),                      // short header too small -> hash
            insn(0x71, 0, 7, 8, 0),                       // r0 = first QUIC byte
            insn(0x45, 0, 0, 6, 0x80),                    // long header -> index 6
            insn(0xbf, 9, 7, 0, 0),                       // r9 = UDP header
            insn(0x07, 9, 0, 0, 10),                      // r9 = UDP payload + 2
            insn(0x2d, 9, 8, 19, 0),                      // short header too small -> hash
            insn(0x71, 0, 7, 9, 0),                       // r0 = short-header CID byte
            insn(0x05, 0, 0, 5, 0),                       // jump to selection
            insn(0xbf, 9, 7, 0, 0),                       // r9 = UDP header
            insn(0x07, 9, 0, 0, 15),                      // r9 = UDP payload + 7
            insn(0x2d, 9, 8, 14, 0),                      // long header too small -> hash
            insn(0x71, 0, 9, -2, 0),                      // r0 = destination CID length
            insn(0x15, 0, 0, 12, 0),                      // empty destination CID -> hash
            insn(0x71, 0, 9, -1, 0),                      // r0 = first long-header CID byte
            insn(0x35, 0, 0, 10, endpoints.len() as i32), // invalid index -> hash
            insn(0x63, 10, 0, -4, 0),                     // *(u32 *)(fp - 4) = index
            insn(0xbf, 1, 6, 0, 0),                       // r1 = ctx
            insn(0x18, 2, 1, 0, map.as_raw_fd()),         // r2 = sockarray map
            insn(0x00, 0, 0, 0, 0),                       // second half of ldimm64
            insn(0xbf, 3, 10, 0, 0),                      // r3 = fp
            insn(0x07, 3, 0, 0, -4),                      // r3 = &index
            insn(0xb7, 4, 0, 0, 0),                       // r4 = flags
            insn(0x85, 0, 0, 0, 82),                      // bpf_sk_select_reuseport
            insn(0xb7, 0, 0, 0, 1),                       // SK_PASS
            insn(0x95, 0, 0, 0, 0),                       // exit
            insn(0xb7, 0, 0, 0, 1),                       // hash fallback: SK_PASS
            insn(0x95, 0, 0, 0, 0),                       // exit
        ];
        let mut log = vec![0u8; 64 * 1024];
        let mut attr = ProgLoadAttr {
            prog_type: BPF_PROG_TYPE_SK_REUSEPORT,
            insn_cnt: instructions.len() as u32,
            insns: instructions.as_ptr() as u64,
            license: c"GPL".as_ptr() as u64,
            log_level: 1,
            log_size: log.len() as u32,
            log_buf: log.as_mut_ptr() as u64,
            kern_version: 0,
            prog_flags: 0,
            prog_name: *b"ssxpro_cid\0\0\0\0\0\0",
            prog_ifindex: 0,
            expected_attach_type: BPF_SK_REUSEPORT_SELECT,
            prog_btf_fd: 0,
            func_info_rec_size: 0,
            func_info: 0,
            func_info_cnt: 0,
            line_info_rec_size: 0,
            line_info: 0,
            line_info_cnt: 0,
            attach_btf_id: 0,
            attach_prog_fd: 0,
            core_relo_cnt: 0,
            fd_array: 0,
            core_relos: 0,
            core_relo_rec_size: 0,
            log_true_size: 0,
            prog_token_fd: 0,
            fd_array_cnt: 0,
            signature: 0,
            signature_size: 0,
            keyring_id: 0,
        };
        let program = bpf(
            BPF_PROG_LOAD,
            (&mut attr as *mut ProgLoadAttr).cast(),
            size_of::<ProgLoadAttr>(),
        )
        .map_err(|error| {
            let message = String::from_utf8_lossy(&log);
            std::io::Error::new(
                error.kind(),
                format!("could not load sk_reuseport eBPF program: {error}; verifier: {message}"),
            )
        })?;
        let program_fd = program.as_raw_fd();
        // SAFETY: setsockopt copies the program FD value during the call.
        if unsafe {
            libc::setsockopt(
                endpoints[0].fd.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_ATTACH_REUSEPORT_EBPF,
                (&program_fd as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Some(ReusePortCidSelector {
            _map: map,
            _program: program,
        }))
    }

    pub fn recv_from(
        &mut self,
        ring: &mut RuntimeRing,
        buffer: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr)> {
        if let Some((peer, datagram)) = self.pending.pop_front() {
            if datagram.len() > buffer.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "UDP datagram exceeds receive buffer",
                ));
            }
            buffer[..datagram.len()].copy_from_slice(&datagram);
            return Ok((datagram.len(), peer));
        }
        let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let mut control = [0usize; 16];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&mut peer as *mut libc::sockaddr_storage).cast();
        message.msg_namelen = std::mem::size_of_val(&peer) as libc::socklen_t;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        // `msg_controllen` is `usize` on glibc and `socklen_t` on musl.
        message.msg_controllen = std::mem::size_of_val(&control) as _;
        if self.direct_io {
            // Bypass io_uring entirely when direct I/O is forced via SSXPRO_DIRECT_IO=1.
            let result = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut message, 0) };
            if result < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let length = result as usize;
            let address = parse_socket_address(&peer)?;
            return Ok((length, address));
        }
        let fd = ring.register_fd(self.fd.as_raw_fd())?;
        let entry = io_uring::opcode::RecvMsg::new(fd, &mut message)
            .build()
            .flags(io_uring::squeue::Flags::FIXED_FILE)
            .user_data(1);
        let length = ring.submit_wait(&entry)? as usize;
        if message.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "UDP ancillary data was truncated",
            ));
        }
        if message.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "UDP datagram exceeds receive buffer",
            ));
        }
        let address = parse_socket_address(&peer)?;
        Ok((length, address))
    }

    pub fn recv_gro(
        &self,
        ring: &mut RuntimeRing,
        buffer: &mut [u8],
    ) -> std::io::Result<(usize, UdpDatagramInfo)> {
        let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let mut control = [0usize; 16];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&mut peer as *mut libc::sockaddr_storage).cast();
        message.msg_namelen = std::mem::size_of_val(&peer) as libc::socklen_t;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control) as _;
        let fd = ring.register_fd(self.fd.as_raw_fd())?;
        let entry = io_uring::opcode::RecvMsg::new(fd, &mut message)
            .build()
            .flags(io_uring::squeue::Flags::FIXED_FILE)
            .user_data(3);
        let length = ring.submit_wait(&entry)? as usize;
        // SAFETY: recvmsg initialized the control buffer up to msg_controllen.
        let gro_segment_size = unsafe { find_udp_gro_size(&message) };
        Ok((
            length,
            UdpDatagramInfo {
                peer: parse_socket_address(&peer)?,
                gro_segment_size,
            },
        ))
    }

    pub fn send_to(
        &self,
        ring: &mut RuntimeRing,
        buffer: &[u8],
        peer: SocketAddr,
    ) -> std::io::Result<usize> {
        let (mut address, length) = socket_address(peer);
        let mut iov = libc::iovec {
            iov_base: buffer.as_ptr() as *mut _,
            iov_len: buffer.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&mut address as *mut libc::sockaddr_storage).cast();
        message.msg_namelen = length;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        if self.direct_io {
            // Bypass io_uring entirely when direct I/O is forced via SSXPRO_DIRECT_IO=1.
            let sent = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
            if sent < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if sent as usize != buffer.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "short UDP datagram send",
                ));
            }
            return Ok(sent as usize);
        }
        let fd = ring.register_fd(self.fd.as_raw_fd())?;
        let entry = io_uring::opcode::SendMsg::new(fd, &message)
            .build()
            .flags(io_uring::squeue::Flags::FIXED_FILE)
            .user_data(2);
        match ring.submit_wait(&entry) {
            Ok(sent) => {
                if sent as usize != buffer.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "short UDP datagram send",
                    ));
                }
                Ok(sent as usize)
            }
            Err(error) => Err(error),
        }
    }

    pub fn send_gso(
        &self,
        ring: &mut RuntimeRing,
        buffer: &[u8],
        peer: SocketAddr,
        segment_size: u16,
    ) -> std::io::Result<usize> {
        if segment_size == 0 || buffer.is_empty() || buffer.len() > u16::MAX as usize * 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid UDP GSO payload or segment size",
            ));
        }
        let (mut address, length) = socket_address(peer);
        let mut iov = libc::iovec {
            iov_base: buffer.as_ptr() as *mut _,
            iov_len: buffer.len(),
        };
        let mut control = [0usize; 8];
        let header = control.as_mut_ptr().cast::<libc::cmsghdr>();
        // SAFETY: control has aligned storage for a cmsghdr and two data bytes.
        unsafe {
            (*header).cmsg_level = libc::SOL_UDP;
            (*header).cmsg_type = libc::UDP_SEGMENT;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as _) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<u16>(), segment_size);
        }
        // SAFETY: CMSG_SPACE computes storage for the scalar payload size.
        let control_len = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as _) as usize };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&mut address as *mut libc::sockaddr_storage).cast();
        message.msg_namelen = length;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control_len as _;
        let fd = ring.register_fd(self.fd.as_raw_fd())?;
        let entry = io_uring::opcode::SendMsg::new(fd, &message)
            .build()
            .flags(io_uring::squeue::Flags::FIXED_FILE)
            .user_data(4);
        let sent = ring.submit_wait(&entry)? as usize;
        if sent != buffer.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short UDP GSO send",
            ));
        }
        Ok(sent)
    }
}

// `msg_controllen` and `cmsg_len` are `usize` on glibc and `socklen_t` on
// musl; the casts are required on one target and redundant on the other.
#[allow(clippy::unnecessary_cast)]
unsafe fn find_udp_gro_size(message: &libc::msghdr) -> Option<u16> {
    let base = message.msg_control.cast::<u8>();
    let control_len = message.msg_controllen as usize;
    let mut offset = 0usize;
    while offset + std::mem::size_of::<libc::cmsghdr>() <= control_len {
        // SAFETY: a complete cmsghdr lies within the control buffer.
        let header = unsafe { &*base.add(offset).cast::<libc::cmsghdr>() };
        // SAFETY: CMSG_LEN only computes a size from a scalar payload length.
        let minimum_cmsg_len = unsafe { libc::CMSG_LEN(2) as usize };
        let cmsg_len = header.cmsg_len as usize;
        if cmsg_len < minimum_cmsg_len || offset + cmsg_len > control_len {
            break;
        }
        if header.cmsg_level == libc::SOL_UDP && header.cmsg_type == libc::UDP_GRO {
            // SAFETY: cmsg_len validation above guarantees two data bytes.
            let data = unsafe { libc::CMSG_DATA(header) };
            return Some(u16::from_ne_bytes(unsafe { [*data, *data.add(1)] }));
        }
        let aligned =
            (cmsg_len + std::mem::size_of::<usize>() - 1) & !(std::mem::size_of::<usize>() - 1);
        if aligned == 0 {
            break;
        }
        offset += aligned;
    }
    None
}

fn socket_address(address: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let length = match address {
        SocketAddr::V4(address) => {
            let value = libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in fits within sockaddr_storage and storage is aligned.
            unsafe {
                std::ptr::write(
                    (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
                    value,
                );
            }
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(address) => {
            let value = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as _,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            // SAFETY: sockaddr_in6 fits within sockaddr_storage and storage is aligned.
            unsafe {
                std::ptr::write(
                    (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
                    value,
                );
            }
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };
    (storage, length)
}

fn parse_socket_address(storage: &libc::sockaddr_storage) -> std::io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: ss_family identifies a fully initialized sockaddr_in.
            let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(addr.sin_port),
            ))
        }
        libc::AF_INET6 => {
            // SAFETY: ss_family identifies a fully initialized sockaddr_in6.
            let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)),
                u16::from_be(addr.sin6_port),
            ))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported UDP peer address family",
        )),
    }
}

const IORING_SETUP_CLAMP: u32 = 1 << 4;
const IORING_SETUP_R_DISABLED: u32 = 1 << 6;
const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;
const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;
const IORING_SETUP_NO_SQARRAY: u32 = 1 << 16;
const IORING_REGISTER_PROBE: libc::c_uint = 8;
const IORING_REGISTER_FILES: libc::c_uint = 2;
const IORING_REGISTER_FILES_UPDATE: libc::c_uint = 6;
const IORING_REGISTER_RESTRICTIONS: libc::c_uint = 11;
const IORING_REGISTER_ENABLE_RINGS: libc::c_uint = 12;
const IORING_REGISTER_PBUF_RING: libc::c_uint = 22;
const IORING_UNREGISTER_PBUF_RING: libc::c_uint = 23;
const IORING_REGISTER_NAPI: libc::c_uint = 27;
const IORING_REGISTER_PROBE_OPS: usize = 255;
const IORING_OP_SUPPORTED: u16 = 1;
const IORING_OP_RECVMSG: u8 = 10;
const IORING_OP_SENDMSG: u8 = 9;
const IORING_OP_TIMEOUT: u8 = 11;
const IORING_OP_ASYNC_CANCEL: u8 = 14;
const IORING_OP_READ: u8 = 22;
const IORING_OP_WRITE: u8 = 23;
const IORING_OP_POLL_ADD: u8 = 6;
const IORING_OP_MSG_RING: u8 = 40;
const IORING_OP_SEND_ZC: u8 = 47;
const IORING_OP_SENDMSG_ZC: u8 = 48;
const IORING_OP_READ_MULTISHOT: u8 = 49;
#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: [u32; 10],
    cq_off: [u32; 10],
}

#[repr(C)]
#[allow(dead_code)]
struct ProbeHeader {
    last_op: u8,
    ops_len: u8,
    resv: u16,
    resv2: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProbeOp {
    op: u8,
    resv: u8,
    flags: u16,
    resv2: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Restriction {
    opcode: u16,
    arg: u8,
    resv: u8,
    resv2: [u32; 3],
}

#[repr(C)]
struct IoUringNapi {
    busy_poll_to: u32,
    prefer_busy_poll: u8,
    opcode: u8,
    pad: [u8; 2],
    op_param: u32,
    resv: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BufferRingRegistration {
    ring_addr: u64,
    ring_entries: u32,
    bgid: u16,
    flags: u16,
    min_left: u32,
    reserved: [u32; 5],
}

#[derive(Debug, Clone)]
pub struct ProbeOptions {
    pub ring_entries: u32,
    pub sqpoll_idle_ms: u32,
    pub hugepages: bool,
    pub gro: bool,
    pub gso: bool,
    pub zerocopy_send: bool,
    pub sqpoll: bool,
    pub napi_busy_poll_us: u32,
    pub txtime_pacing: bool,
    pub restrict_ring: bool,
    pub reuseport_steering: bool,
}

/// Owns a configured io_uring descriptor. No fallback backend is provided.
pub struct Ring {
    fd: RawFd,
}

impl Ring {
    /// Create a ring with the required single-issuer/taskrun setup flags.
    pub fn new(entries: u32) -> std::io::Result<Self> {
        let flags = IORING_SETUP_CLAMP
            | IORING_SETUP_COOP_TASKRUN
            | IORING_SETUP_SINGLE_ISSUER
            | IORING_SETUP_DEFER_TASKRUN
            | IORING_SETUP_NO_SQARRAY;
        Ok(Self {
            fd: setup_ring(flags, 0, entries)?,
        })
    }

    /// Create a disabled ring, install the M4 submission allowlist, then enable it.
    pub fn new_restricted(entries: u32) -> std::io::Result<Self> {
        let flags = IORING_SETUP_CLAMP
            | IORING_SETUP_R_DISABLED
            | IORING_SETUP_COOP_TASKRUN
            | IORING_SETUP_SINGLE_ISSUER
            | IORING_SETUP_DEFER_TASKRUN
            | IORING_SETUP_NO_SQARRAY;
        let fd = setup_ring(flags, 0, entries)?;
        let allowed = [
            IORING_OP_RECVMSG,
            IORING_OP_SENDMSG,
            IORING_OP_SEND_ZC,
            IORING_OP_SENDMSG_ZC,
            IORING_OP_READ,
            IORING_OP_WRITE,
            IORING_OP_TIMEOUT,
            IORING_OP_POLL_ADD,
            IORING_OP_ASYNC_CANCEL,
            IORING_OP_MSG_RING,
        ];
        let restrictions: Vec<_> = allowed
            .into_iter()
            .map(|opcode| Restriction {
                opcode: 1,
                arg: opcode,
                resv: 0,
                resv2: [0; 3],
            })
            .collect();
        let register_result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                fd,
                IORING_REGISTER_RESTRICTIONS,
                restrictions.as_ptr(),
                restrictions.len() as libc::c_uint,
            )
        };
        if register_result < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: fd is owned by this constructor and has not escaped.
            unsafe {
                libc::close(fd);
            }
            return Err(error);
        }
        // SAFETY: this registration operation takes no argument and enables this ring.
        let enable_result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                fd,
                IORING_REGISTER_ENABLE_RINGS,
                std::ptr::null::<c_void>(),
                0u32,
            )
        };
        if enable_result < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: fd is owned by this constructor and has not escaped.
            unsafe {
                libc::close(fd);
            }
            return Err(error);
        }
        Ok(Self { fd })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the ring fd.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Apply a no-filesystem Landlock ruleset and a syscall allowlist after the worker
/// has opened its ring, socket, IPC and PTY descriptors.
pub fn sandbox_worker() -> std::io::Result<()> {
    sandbox_common()?;
    match install_landlock_deny_all() {
        Ok(()) => {}
        // Landlock is part of the 6.12 baseline; a kernel that does not
        // implement it (or has CONFIG_SECURITY_LANDLOCK off) cannot provide
        // filesystem confinement. Continue with the seccomp layer and warn
        // loudly rather than silently claiming confinement.
        Err(error) if is_landlock_unsupported(&error) => {
            eprintln!(
                "ssxd: warning: Landlock is unavailable on this kernel ({error}); \
                 PTY pump continues with seccomp only"
            );
        }
        Err(error) => return Err(error),
    }
    install_worker_seccomp(false)
}

fn is_landlock_unsupported(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS)
    )
}

/// Apply process-wide prerequisites before worker threads begin handling
/// untrusted packets. The full filesystem and syscall sandbox is installed on
/// the dedicated PTY pump thread, whose much smaller syscall surface permits
/// a strict allowlist. The network worker still needs its established socket,
/// Unix monitor channel, and quiche runtime syscalls.
pub fn harden_worker_process() -> std::io::Result<()> {
    sandbox_common()
}

/// Apply filesystem denial and a signing-only syscall allowlist to the root TLS
/// monitor after its certificate and key state have been initialized.
pub fn sandbox_tls_monitor() -> std::io::Result<()> {
    sandbox_common()?;
    // The monitor must resolve NSS identities and read each user's strict-mode
    // authorized_keys file after startup. Landlock's deny-all policy would make
    // both impossible; keep the syscall allowlist and deny network creation.
    install_worker_seccomp(true)
}

fn sandbox_common() -> std::io::Result<()> {
    // SAFETY: these prctl calls have scalar arguments and no borrowed pointers.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: disables ptrace and core-dump visibility for this process.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn install_landlock_deny_all() -> std::io::Result<()> {
    const CREATE_RULESET_VERSION: u32 = 1;
    const FS_ACCESS: u64 = 0x0000_0000_0000_7fff;
    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
    }
    // Landlock syscall numbers are stable across x86_64 and aarch64 Linux ABIs.
    let abi = unsafe {
        libc::syscall(
            444,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if abi < 1 {
        return Err(std::io::Error::last_os_error());
    }
    let handled_fs = if abi >= 3 {
        FS_ACCESS
    } else if abi >= 2 {
        FS_ACCESS & !0x4000
    } else {
        FS_ACCESS & !0x6000
    };
    let attr = RulesetAttr {
        handled_access_fs: handled_fs,
        handled_access_net: 0,
    };
    let size = std::mem::size_of::<u64>();
    // SAFETY: attr is valid for the ABI-reported structure prefix and the flags are zero.
    let fd = unsafe { libc::syscall(444, &attr, size, 0u32) as libc::c_int };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: ruleset fd is valid, no rules are added, so handled rights are denied.
    let result = unsafe { libc::syscall(446, fd, 0u32) };
    let error = if result < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    // SAFETY: fd is owned locally.
    unsafe {
        libc::close(fd);
    }
    error.map_or(Ok(()), Err)
}

fn install_worker_seccomp(monitor_io: bool) -> std::io::Result<()> {
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const libc::sock_filter,
    }
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("worker seccomp supports x86_64 and aarch64 only");

    let mut allowed = vec![
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_mprotect,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        libc::SYS_clock_gettime,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_sched_yield,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    if monitor_io {
        allowed.extend([
            libc::SYS_read,
            // musl's stdio reads and writes through readv/writev and opens
            // files with the legacy open syscall; glibc resolves through
            // read/write and openat.
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_getrandom,
            libc::SYS_madvise,
            libc::SYS_open,
            libc::SYS_openat,
            libc::SYS_openat2,
            libc::SYS_newfstatat,
            // musl's stat()/lstat() use the legacy syscalls; glibc resolves
            // through newfstatat/statx.
            libc::SYS_stat,
            libc::SYS_lstat,
            libc::SYS_fstat,
            libc::SYS_statx,
            libc::SYS_lseek,
            libc::SYS_getgroups,
            libc::SYS_getuid,
            libc::SYS_geteuid,
            libc::SYS_getgid,
            libc::SYS_getegid,
            libc::SYS_access,
            libc::SYS_readlink,
        ]);
    }
    let mut filters = Vec::with_capacity(allowed.len() * 2 + 4);
    filters.push(libc::sock_filter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 4,
    });
    filters.push(libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: 1,
        jf: 0,
        k: AUDIT_ARCH,
    });
    filters.push(libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });
    filters.push(libc::sock_filter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });
    for syscall in allowed {
        filters.push(libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filters.push(libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });
    }
    if monitor_io {
        // musl's NSS code probes nscd with socket(); only EAFNOSUPPORT makes
        // it treat nscd as unavailable and fall back to the local files.
        // Returning EAFNOSUPPORT keeps the monitor unable to create sockets.
        filters.push(libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: libc::SYS_socket as u32,
        });
        filters.push(libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | libc::EAFNOSUPPORT as u32,
        });
    }
    filters.push(libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ERRNO | libc::EPERM as u32,
    });
    let program = SockFprog {
        len: filters.len() as u16,
        filter: filters.as_ptr(),
    };
    // SAFETY: filters remains alive through seccomp and program points to its exact allocation.
    let flags = u32::from(monitor_io); // TSYNC the monitor policy onto its NSS helper.
    let result = unsafe { libc::syscall(libc::SYS_seccomp, 1u32, flags, &program) };
    if result != 0 {
        return Err(if result < 0 {
            std::io::Error::last_os_error()
        } else {
            std::io::Error::other(format!(
                "seccomp TSYNC could not synchronize thread {result}"
            ))
        });
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct FeatureResult {
    pub name: &'static str,
    pub supported: bool,
    pub requested: bool,
    pub detail: String,
}

impl fmt::Display for FeatureResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.supported {
            "PASS"
        } else if self.requested {
            "FAIL"
        } else {
            "SKIP"
        };
        write!(f, "{}: {status} ({})", self.name, self.detail)
    }
}

pub fn probe_kernel(options: &ProbeOptions) -> Vec<FeatureResult> {
    let base_flags = IORING_SETUP_CLAMP
        | IORING_SETUP_COOP_TASKRUN
        | IORING_SETUP_SINGLE_ISSUER
        | IORING_SETUP_DEFER_TASKRUN
        | IORING_SETUP_NO_SQARRAY;
    let mut results = Vec::new();
    let ring = setup_ring(base_flags, 0, options.ring_entries);
    let fd = match ring {
        Ok(fd) => {
            results.push(pass(
                "io_uring setup flags",
                "required setup flags accepted",
            ));
            Some(fd)
        }
        Err(error) => {
            results.push(fail("io_uring setup flags", error.to_string()));
            None
        }
    };

    let opcodes = [
        (IORING_OP_RECVMSG, "IORING_OP_RECVMSG"),
        (IORING_OP_SENDMSG, "IORING_OP_SENDMSG"),
        (IORING_OP_TIMEOUT, "IORING_OP_TIMEOUT"),
        (IORING_OP_ASYNC_CANCEL, "IORING_OP_ASYNC_CANCEL"),
        (IORING_OP_READ, "IORING_OP_READ"),
        (IORING_OP_WRITE, "IORING_OP_WRITE"),
        (IORING_OP_POLL_ADD, "IORING_OP_POLL_ADD"),
    ];
    for (opcode, name) in opcodes {
        let supported = fd
            .and_then(|ring_fd| opcode_supported(ring_fd, opcode).ok())
            .unwrap_or(false);
        results.push(FeatureResult {
            name,
            supported,
            requested: true,
            detail: if supported {
                "kernel reports opcode supported".to_owned()
            } else {
                "opcode probe failed or opcode unsupported".to_owned()
            },
        });
    }
    for (opcode, name) in [
        (IORING_OP_SEND_ZC, "IORING_OP_SEND_ZC"),
        (IORING_OP_SENDMSG_ZC, "IORING_OP_SENDMSG_ZC"),
    ] {
        let supported = fd
            .and_then(|ring_fd| opcode_supported(ring_fd, opcode).ok())
            .unwrap_or(false);
        results.push(FeatureResult {
            name,
            supported,
            requested: options.zerocopy_send,
            detail: if supported {
                "kernel reports opcode supported".to_owned()
            } else {
                "opcode probe failed or opcode unsupported".to_owned()
            },
        });
    }
    for (opcode, name) in [
        (IORING_OP_MSG_RING, "IORING_OP_MSG_RING"),
        (IORING_OP_READ_MULTISHOT, "IORING_OP_READ_MULTISHOT"),
    ] {
        let supported = fd
            .and_then(|ring_fd| opcode_supported(ring_fd, opcode).ok())
            .unwrap_or(false);
        results.push(FeatureResult {
            name,
            supported,
            requested: false,
            detail: if supported {
                "kernel reports opcode supported".to_owned()
            } else {
                "opcode probe failed or opcode unsupported".to_owned()
            },
        });
    }
    let pbuf_result = fd.map_or_else(
        || Err(std::io::Error::other("base io_uring setup failed")),
        |_| probe_incremental_buffer_ring(),
    );
    results.push(match pbuf_result {
        Ok(()) => pass(
            "IOU_PBUF_RING_INC",
            "incremental provided-buffer ring registered and removed",
        ),
        Err(error) => fail("IOU_PBUF_RING_INC", error.to_string()),
    });

    let fixed_file_result = fd.map_or_else(
        || Err(std::io::Error::other("base io_uring setup failed")),
        |_| probe_fixed_file_table(),
    );
    results.push(match fixed_file_result {
        Ok(()) => pass(
            "registered descriptors",
            "sparse fixed-file table registered and updated",
        ),
        Err(error) => fail("registered descriptors", error.to_string()),
    });

    if options.reuseport_steering {
        results.push(match probe_reuseport_cid_selector() {
            Ok(()) => pass(
                "sk_reuseport eBPF CID selector",
                "reuseport group and CID filter attached",
            ),
            Err(error) => fail("sk_reuseport eBPF CID selector", error.to_string()),
        });
    } else {
        results.push(skip(
            "sk_reuseport eBPF CID selector",
            "single worker configured",
        ));
    }

    if options.restrict_ring {
        let result = fd.map_or_else(
            || Err(std::io::Error::other("base io_uring setup failed")),
            |_| probe_restrictions(),
        );
        results.push(match result {
            Ok(()) => pass(
                "IORING_REGISTER_RESTRICTIONS",
                "restriction allowlist registered and ring enabled",
            ),
            Err(error) => fail("IORING_REGISTER_RESTRICTIONS", error.to_string()),
        });
    } else {
        results.push(skip(
            "IORING_REGISTER_RESTRICTIONS",
            "not requested by config",
        ));
    }
    if options.hugepages {
        results.push(probe_hugepages());
    } else {
        results.push(skip("huge pages", "not requested by config"));
    }
    if options.gro {
        results.push(probe_socket_option(
            "UDP_GRO",
            libc::SOL_UDP,
            libc::UDP_GRO,
            1,
        ));
    } else {
        results.push(skip("UDP_GRO", "not requested by config"));
    }
    if options.gso {
        results.push(probe_socket_option(
            "UDP_SEGMENT",
            libc::SOL_UDP,
            libc::UDP_SEGMENT,
            1200,
        ));
    } else {
        results.push(skip("UDP_SEGMENT", "not requested by config"));
    }
    if options.zerocopy_send {
        let supported = fd
            .and_then(|ring_fd| {
                Some(
                    opcode_supported(ring_fd, IORING_OP_SEND_ZC).ok()?
                        && opcode_supported(ring_fd, IORING_OP_SENDMSG_ZC).ok()?,
                )
            })
            .unwrap_or(false);
        results.push(FeatureResult {
            name: "zero-copy send",
            supported,
            requested: options.zerocopy_send,
            detail: if supported {
                "both send opcodes are available".to_owned()
            } else {
                "SEND_ZC and SENDMSG_ZC are both required".to_owned()
            },
        });
    } else {
        results.push(skip("zero-copy send", "not requested by config"));
    }
    if options.sqpoll {
        let result = setup_ring(
            base_flags | 1 << 1,
            options.sqpoll_idle_ms,
            options.ring_entries,
        );
        match result {
            Ok(sqpoll_fd) => {
                unsafe {
                    libc::close(sqpoll_fd);
                }
                results.push(pass("SQPOLL", "ring setup accepted IORING_SETUP_SQPOLL"));
            }
            Err(error) => results.push(fail("SQPOLL", error.to_string())),
        }
    } else {
        results.push(skip("SQPOLL", "not requested by config"));
    }
    if options.napi_busy_poll_us > 0 {
        let supported =
            fd.is_some_and(|ring_fd| probe_napi(ring_fd, options.napi_busy_poll_us).is_ok());
        results.push(FeatureResult {
            name: "IORING_REGISTER_NAPI",
            supported,
            requested: true,
            detail: if supported {
                "NAPI registration succeeded".to_owned()
            } else {
                "NAPI registration unsupported or unavailable".to_owned()
            },
        });
    } else {
        results.push(skip("IORING_REGISTER_NAPI", "not requested by config"));
    }
    if options.txtime_pacing {
        results.push(probe_txtime());
    } else {
        results.push(skip("SO_TXTIME", "not requested by config"));
    }
    if let Some(ring_fd) = fd {
        unsafe {
            libc::close(ring_fd);
        }
    }
    results
}

pub fn probe_has_failures(results: &[FeatureResult], options: &ProbeOptions) -> bool {
    // Check if kernel is 5.10+ to determine IOU_PBUF_RING_INC requirement
    let require_pbuf_ring = false;
    let requested: Vec<&str> = [
        "io_uring setup flags",
        "IORING_OP_RECVMSG",
        "IORING_OP_SENDMSG",
        "IORING_OP_TIMEOUT",
        "IORING_OP_ASYNC_CANCEL",
        "IORING_OP_READ",
        "IORING_OP_WRITE",
        "IORING_OP_POLL_ADD",
    ]
    .into_iter()
    .collect();
    results.iter().any(|result| {
        if result.supported {
            return false;
        }
        // On kernels < 5.10, IOU_PBUF_RING_INC is not required
        let pbuf_required = require_pbuf_ring && result.name == "IOU_PBUF_RING_INC";
        requested.contains(&result.name)
            || (options.restrict_ring && result.name == "IORING_REGISTER_RESTRICTIONS")
            || result.name == "registered descriptors"
            || (options.hugepages && result.name == "huge pages")
            || (options.gro && result.name == "UDP_GRO")
            || (options.gso && result.name == "UDP_SEGMENT")
            || (options.zerocopy_send && result.name == "zero-copy send")
            || (options.sqpoll && result.name == "SQPOLL")
            || (options.napi_busy_poll_us > 0 && result.name == "IORING_REGISTER_NAPI")
            || (options.txtime_pacing && result.name == "SO_TXTIME")
            || pbuf_required
    })
}

fn setup_ring(flags: u32, sq_thread_idle: u32, entries: u32) -> Result<RawFd, std::io::Error> {
    let mut params: IoUringParams = unsafe { zeroed() };
    params.flags = flags;
    params.sq_thread_idle = sq_thread_idle;
    let fd =
        unsafe { libc::syscall(libc::SYS_io_uring_setup, entries, &mut params) as libc::c_int };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn opcode_supported(fd: RawFd, opcode: u8) -> Result<bool, std::io::Error> {
    let bytes = size_of::<ProbeHeader>() + IORING_REGISTER_PROBE_OPS * size_of::<ProbeOp>();
    let words = bytes.div_ceil(size_of::<u64>());
    let mut storage = vec![0u64; words];
    let result = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            fd,
            IORING_REGISTER_PROBE,
            storage.as_mut_ptr().cast::<c_void>(),
            IORING_REGISTER_PROBE_OPS as libc::c_uint,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let header = unsafe { &*storage.as_ptr().cast::<ProbeHeader>() };
    let count = usize::from(header.ops_len).min(IORING_REGISTER_PROBE_OPS);
    let ops = unsafe {
        std::slice::from_raw_parts(
            storage
                .as_ptr()
                .cast::<u8>()
                .add(size_of::<ProbeHeader>())
                .cast::<ProbeOp>(),
            count,
        )
    };
    Ok(ops
        .iter()
        .any(|entry| entry.op == opcode && entry.flags & IORING_OP_SUPPORTED != 0))
}

fn probe_restrictions() -> Result<(), std::io::Error> {
    let disabled_fd = setup_ring(IORING_SETUP_CLAMP | IORING_SETUP_R_DISABLED, 0, 8)?;
    let restrictions = [
        Restriction {
            opcode: 1,
            arg: IORING_OP_RECVMSG,
            resv: 0,
            resv2: [0; 3],
        },
        Restriction {
            opcode: 1,
            arg: IORING_OP_SENDMSG,
            resv: 0,
            resv2: [0; 3],
        },
    ];
    let result = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            disabled_fd,
            IORING_REGISTER_RESTRICTIONS,
            restrictions.as_ptr(),
            restrictions.len() as libc::c_uint,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(disabled_fd);
        }
        return Err(error);
    }
    let result = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            disabled_fd,
            IORING_REGISTER_ENABLE_RINGS,
            std::ptr::null::<c_void>(),
            0u32,
        )
    };
    unsafe {
        libc::close(disabled_fd);
    }
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn probe_fixed_file_table() -> Result<(), std::io::Error> {
    #[repr(C)]
    struct FilesUpdate {
        offset: u32,
        reserved: u32,
        fds: u64,
    }

    let ring = setup_ring(IORING_SETUP_CLAMP, 0, 8)?;
    // SAFETY: setup_ring returned a newly owned descriptor.
    let ring = unsafe { OwnedFd::from_raw_fd(ring) };
    let sparse = [-1; 4];
    // SAFETY: sparse is a live array of four descriptor entries.
    let result = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            ring.as_raw_fd(),
            IORING_REGISTER_FILES,
            sparse.as_ptr(),
            sparse.len() as libc::c_uint,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: /dev/null is opened as a new close-on-exec descriptor.
    let file = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if file < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: file is a newly owned descriptor.
    let file = unsafe { OwnedFd::from_raw_fd(file) };
    let file_fd = file.as_raw_fd();
    let update = FilesUpdate {
        offset: 0,
        reserved: 0,
        fds: (&file_fd as *const RawFd) as u64,
    };
    // SAFETY: update and its fd pointer remain valid for the duration of register.
    let result = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            ring.as_raw_fd(),
            IORING_REGISTER_FILES_UPDATE,
            &update,
            1u32,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn probe_reuseport_cid_selector() -> Result<(), std::io::Error> {
    let first = UdpEndpoint::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), true)?;
    let second = UdpEndpoint::bind(first.local_addr()?, true)?;
    let _selector = UdpEndpoint::attach_reuseport_cid_selector(&[&first, &second])?;
    drop(second);
    drop(first);
    Ok(())
}

fn probe_incremental_buffer_ring() -> Result<(), std::io::Error> {
    let ring_fd = setup_ring(IORING_SETUP_CLAMP, 0, 8)?;
    let ring_memory = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ring_memory == libc::MAP_FAILED {
        unsafe {
            libc::close(ring_fd);
        }
        return Err(std::io::Error::last_os_error());
    }
    let registration = BufferRingRegistration {
        ring_addr: ring_memory as u64,
        ring_entries: 8,
        bgid: 13,
        flags: 1 << 1,
        min_left: 0,
        reserved: [0; 5],
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            ring_fd,
            IORING_REGISTER_PBUF_RING,
            &registration,
            1u32,
        )
    };
    let register_error = (result < 0).then(std::io::Error::last_os_error);
    if register_error.is_none() {
        let unregister = BufferRingRegistration {
            ring_addr: 0,
            ring_entries: 0,
            bgid: registration.bgid,
            flags: 0,
            min_left: 0,
            reserved: [0; 5],
        };
        let unregister_result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                ring_fd,
                IORING_UNREGISTER_PBUF_RING,
                &unregister,
                1u32,
            )
        };
        unsafe {
            libc::close(ring_fd);
        }
        unsafe {
            libc::munmap(ring_memory, 4096);
        }
        if unregister_result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        return Ok(());
    }
    unsafe {
        libc::close(ring_fd);
    }
    unsafe {
        libc::munmap(ring_memory, 4096);
    }
    match register_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn probe_napi(fd: RawFd, timeout_us: u32) -> Result<(), std::io::Error> {
    let mut napi = IoUringNapi {
        busy_poll_to: timeout_us,
        prefer_busy_poll: 0,
        opcode: 0,
        pad: [0; 2],
        op_param: 0,
        resv: 0,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            fd,
            IORING_REGISTER_NAPI,
            &mut napi,
            1u32,
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn probe_socket_option(
    name: &'static str,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> FeatureResult {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return fail(name, std::io::Error::last_os_error().to_string());
    }
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const libc::c_int).cast::<c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    let error = if result < 0 {
        Some(std::io::Error::last_os_error().to_string())
    } else {
        None
    };
    unsafe {
        libc::close(fd);
    }
    match error {
        Some(error) => fail(name, error),
        None => pass(name, "socket option enabled successfully"),
    }
}

fn probe_txtime() -> FeatureResult {
    #[repr(C)]
    struct SockTxtime {
        clockid: libc::clockid_t,
        flags: u32,
    }
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return fail("SO_TXTIME", std::io::Error::last_os_error().to_string());
    }
    let value = SockTxtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TXTIME,
            (&value as *const SockTxtime).cast::<c_void>(),
            size_of::<SockTxtime>() as libc::socklen_t,
        )
    };
    let error = if result < 0 {
        Some(std::io::Error::last_os_error().to_string())
    } else {
        None
    };
    unsafe {
        libc::close(fd);
    }
    match error {
        Some(error) => fail("SO_TXTIME", error),
        None => pass(
            "SO_TXTIME",
            "socket option enabled; fq qdisc must be configured for pacing",
        ),
    }
}

fn probe_hugepages() -> FeatureResult {
    let length = 2 * 1024 * 1024;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return fail("huge pages", std::io::Error::last_os_error().to_string());
    }
    unsafe {
        libc::munmap(ptr, length);
    }
    pass("huge pages", "2 MiB MAP_HUGETLB allocation succeeded")
}

fn pass(name: &'static str, detail: impl Into<String>) -> FeatureResult {
    FeatureResult {
        name,
        supported: true,
        requested: true,
        detail: detail.into(),
    }
}
fn fail(name: &'static str, detail: impl Into<String>) -> FeatureResult {
    FeatureResult {
        name,
        supported: false,
        requested: true,
        detail: detail.into(),
    }
}

fn skip(name: &'static str, detail: impl Into<String>) -> FeatureResult {
    FeatureResult {
        name,
        supported: false,
        requested: false,
        detail: detail.into(),
    }
}

// ----- Kernel version detection -----

/// Parse the kernel release string and return (major, minor, patch).
/// Uses `uname -r` if available, otherwise falls back to parsing /proc/version.
pub fn kernel_release() -> (u16, u16, u16) {
    // Try `uname -r` first
    if let Ok(output) = std::process::Command::new("uname").args(["-r"]).output() {
        if let Ok(release) = String::from_utf8(output.stdout) {
            let release = release.trim();
            // Parse major.minor.patch
            if let Some((major_str, rest)) = release.split_once('.') {
                if let Some((minor_str, _)) = rest.split_once('.') {
                    if let (Ok(major), Ok(minor)) =
                        (major_str.parse::<u16>(), minor_str.parse::<u16>())
                    {
                        // Try to get patch version from the remaining string
                        if let Some(patch_str) = rest.split('.').next() {
                            if let Ok(patch) = patch_str.parse::<u16>() {
                                return (major, minor, patch);
                            }
                        }
                        return (major, minor, 0);
                    }
                }
            }
        }
    }

    // Fall back to /proc/version
    if let Ok(content) = std::fs::read_to_string("/proc/version") {
        let release = content.trim();
        // Parse "5.15.0-91-generic" -> (5, 15, 0)
        if let Some((_major_str, rest)) = release.split_once(' ') {
            if let Some((major_str, rest)) = rest.split_once('.') {
                if let Some((minor_str, _)) = rest.split_once('.') {
                    if let (Ok(major), Ok(minor)) =
                        (major_str.parse::<u16>(), minor_str.parse::<u16>())
                    {
                        return (major, minor, 0);
                    }
                }
            }
        }
    }

    (0, 0, 0)
}

/// Check if the kernel version is at least 5.10
pub fn is_kernel_5_10_or_later() -> bool {
    let (major, minor, _) = kernel_release();
    major > 5 || (major == 5 && minor >= 10)
}

/// Check if the kernel version is at least 5.15
pub fn is_kernel_5_15_or_later() -> bool {
    let (major, minor, _) = kernel_release();
    major > 5 || (major == 5 && minor >= 15)
}

/// Check if the kernel version is at least 6.12
pub fn is_kernel_6_12_or_later() -> bool {
    let (major, minor, _) = kernel_release();
    major > 6 || (major == 6 && minor >= 12)
}

#[cfg(test)]
mod tests {
    use super::{
        probe_has_failures, FeatureResult, ProbeHeader, ProbeOp, ProbeOptions, Restriction,
    };

    #[test]
    fn io_uring_probe_and_restriction_uapi_layouts_match_linux() {
        assert_eq!(std::mem::size_of::<ProbeHeader>(), 16);
        assert_eq!(std::mem::size_of::<ProbeOp>(), 8);
        assert_eq!(std::mem::size_of::<Restriction>(), 16);
    }

    #[test]
    fn masked_requested_feature_is_a_hard_failure() {
        let options = ProbeOptions {
            ring_entries: 4096,
            sqpoll_idle_ms: 2,
            hugepages: false,
            gro: true,
            gso: false,
            zerocopy_send: false,
            sqpoll: false,
            napi_busy_poll_us: 0,
            txtime_pacing: false,
            restrict_ring: false,
            reuseport_steering: false,
        };
        let masked = [FeatureResult {
            name: "UDP_GRO",
            supported: false,
            requested: true,
            detail: "masked by test".to_owned(),
        }];
        assert!(probe_has_failures(&masked, &options));
    }

    #[test]
    fn unsupported_unrequested_feature_does_not_fail_config() {
        let options = ProbeOptions {
            ring_entries: 4096,
            sqpoll_idle_ms: 2,
            hugepages: false,
            gro: false,
            gso: false,
            zerocopy_send: false,
            sqpoll: false,
            napi_busy_poll_us: 0,
            txtime_pacing: false,
            restrict_ring: false,
            reuseport_steering: false,
        };
        let unavailable = [FeatureResult {
            name: "UDP_GRO",
            supported: false,
            requested: false,
            detail: "not requested".to_owned(),
        }];
        assert!(!probe_has_failures(&unavailable, &options));
    }

    #[test]
    fn test_kernel_version_detection() {
        let (major, minor, patch) = super::kernel_release();
        eprintln!("Detected kernel: {}.{}.{}", major, minor, patch);
        assert!(major > 0, "Major version should be positive");
    }
}
