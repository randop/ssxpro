use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::Parser;
use ssxpro_config::{default_server_config_path, parse_server_yaml, ServerConfig};
use ssxpro_io::{probe_has_failures, probe_kernel, ProbeOptions};
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

pub mod broker;
pub mod ipc;
pub mod session;
pub mod tls;
pub mod transport;

const EXIT_USAGE: u8 = 2;
const EXIT_CONFIG: u8 = 3;
const EXIT_KERNEL: u8 = 4;
const EXIT_NOT_IMPLEMENTED: u8 = 1;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "ssxd", version, about = "ssxpro server")]
struct Args {
    /// Use this YAML configuration file.
    #[arg(short, long, value_name = "PATH", default_value_os_t = default_server_config_path())]
    config: PathBuf,
    /// Validate the configuration, protected host key, and kernel capabilities; then exit.
    #[arg(long)]
    check_config: bool,
    /// Print the server SPKI SHA-256 value as base64 for secure known_hosts provisioning.
    #[arg(long)]
    print_host_pin: bool,
    /// Skip config, host key, and authorized_keys permission checks
    #[arg(long = "yes-I-know-permission-risks-go-ahead-please")]
    skip_permission_checks: bool,
    /// Increase verbosity (repeat for more: -v, -vv, -vvv).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, default_value_t = 0)]
    verbose: u8,
}

fn main() -> ExitCode {
    let args = Args::try_parse().unwrap_or_else(|error| {
        let code = if error.use_stderr() { EXIT_USAGE } else { 0 };
        let _ = error.print();
        std::process::exit(code.into());
    });
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, message)) => {
            eprintln!("ssxd: {message}");
            ExitCode::from(code)
        }
    }
}

fn run(args: &Args) -> Result<(), (u8, String)> {
    let config_text = read_server_config(&args.config, args.skip_permission_checks)
        .map_err(|error| (EXIT_CONFIG, error))?;
    let config =
        parse_server_yaml(&config_text).map_err(|error| (EXIT_CONFIG, error.to_string()))?;
    check_server_files(&config, args.skip_permission_checks)
        .map_err(|error| (EXIT_CONFIG, error))?;
    if args.print_host_pin {
        let identity = crate::tls::identity_from_seed(
            read_host_key_seed(&config.host_key).map_err(|error| (EXIT_CONFIG, error))?,
        )
        .map_err(|error| (EXIT_CONFIG, format!("cannot derive host SPKI: {error}")))?;
        let digest = ssxpro_crypto::sha256(&identity.spki_der)
            .map_err(|error| (EXIT_CONFIG, format!("cannot hash host SPKI: {error}")))?;
        println!("{}", STANDARD.encode(digest));
        return Ok(());
    }
    let options = ProbeOptions {
        ring_entries: config.io.ring_entries,
        sqpoll_idle_ms: config.io.sqpoll_idle_ms,
        hugepages: config.io.hugepages,
        gro: config.io.gro,
        gso: config.io.gso,
        zerocopy_send: config.io.zerocopy_send,
        sqpoll: config.io.sqpoll,
        napi_busy_poll_us: config.io.napi_busy_poll_us,
        txtime_pacing: config.io.txtime_pacing,
        restrict_ring: config.io.restrict_ring,
        reuseport_steering: config
            .workers
            .min(config.quic.max_connections as usize)
            .min(config.session.max_sessions as usize)
            > 1,
    };
    let results = probe_kernel(&options);
    for result in &results {
        println!("{result}");
    }
    if probe_has_failures(&results, &options) {
        return Err((
            EXIT_KERNEL,
            "one or more required or configured kernel features are unavailable".to_owned(),
        ));
    }
    if args.check_config {
        println!("configuration and kernel capabilities are valid");
        return Ok(());
    }
    transport::serve(&config, args.verbose, args.skip_permission_checks).map_err(|error| {
        (
            EXIT_NOT_IMPLEMENTED,
            format!("server runtime failed: {error}"),
        )
    })
}

fn read_server_config(path: &Path, skip_permission_checks: bool) -> Result<String, String> {
    let file = openat2_nosymlink(path)
        .map_err(|error| format!("cannot open config {}: {error}", path.display()))?;
    if !skip_permission_checks {
        check_secure_metadata(path, &file, 0, 0o600, "config file")?;
    }
    let mut contents = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| format!("cannot read config {}: {error}", path.display()))?;
    if contents.len() as u64 > MAX_CONFIG_BYTES {
        return Err("config file exceeds 1 MiB".to_owned());
    }
    Ok(contents)
}

fn check_server_files(config: &ServerConfig, skip_permission_checks: bool) -> Result<(), String> {
    let key = openat2_nosymlink(&config.host_key).map_err(|error| {
        format!(
            "cannot open host key {}: {error}",
            config.host_key.display()
        )
    })?;
    if !skip_permission_checks {
        check_secure_metadata(&config.host_key, &key, 0, 0o600, "host key")?;
    }
    let metadata = key.metadata().map_err(|error| {
        format!(
            "cannot inspect host key {}: {error}",
            config.host_key.display()
        )
    })?;
    if metadata.len() != 32 {
        return Err("host key must contain exactly 32 raw Ed25519 seed bytes".to_owned());
    }

    if let Some(chain_path) = &config.tls.certificate_chain {
        let chain = openat2_nosymlink(chain_path).map_err(|error| {
            format!(
                "cannot open TLS certificate chain {}: {error}",
                chain_path.display()
            )
        })?;
        if !skip_permission_checks {
            // Certificates are public material, but ownership and a non-writable
            // mode prevent an unprivileged local user from replacing the server
            // identity after the initial configuration check.
            check_secure_metadata(chain_path, &chain, 0, 0o644, "TLS certificate chain")?;
        }
        let chain_metadata = chain.metadata().map_err(|error| {
            format!(
                "cannot inspect TLS certificate chain {}: {error}",
                chain_path.display()
            )
        })?;
        if chain_metadata.len() == 0 || chain_metadata.len() > 256 * 1024 {
            return Err("TLS certificate chain must be 1..=262144 bytes".to_owned());
        }
        let mut pem = Vec::with_capacity(chain_metadata.len() as usize);
        chain
            .take(256 * 1024 + 1)
            .read_to_end(&mut pem)
            .map_err(|error| format!("cannot read TLS certificate chain: {error}"))?;
        let host_identity = crate::tls::identity_from_seed(read_host_key_seed(&config.host_key)?)
            .map_err(|error| format!("cannot derive host SPKI: {error}"))?;
        crate::tls::validate_certificate_chain_pem(&pem, &host_identity.spki_der)
            .map_err(|error| format!("invalid TLS certificate chain: {error}"))?;
    }
    Ok(())
}

pub fn read_host_key_seed(path: &Path) -> Result<[u8; 32], String> {
    let mut key =
        openat2_nosymlink(path).map_err(|error| format!("cannot open host key: {error}"))?;
    let mut seed = Zeroizing::new([0u8; 32]);
    key.read_exact(&mut *seed)
        .map_err(|error| format!("host key must contain exactly 32 seed bytes: {error}"))?;
    let mut trailing = [0u8; 1];
    if key
        .read(&mut trailing)
        .map_err(|error| format!("cannot read host key: {error}"))?
        != 0
    {
        return Err("host key must contain exactly 32 seed bytes".to_owned());
    }
    Ok(*seed)
}

fn check_secure_metadata(
    path: &Path,
    file: &File,
    required_uid: u32,
    required_mode: u32,
    description: &str,
) -> Result<(), String> {
    let path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect {description} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{} {description} must be a regular file",
            path.display()
        ));
    }
    if metadata.uid() != required_uid {
        return Err(format!(
            "{} {description} must be owned by uid {required_uid}, got uid {}",
            path.display(),
            metadata.uid()
        ));
    }
    let mode = metadata.mode() & 0o7777;
    if mode != required_mode {
        return Err(format!(
            "{} {description} permissions must be {:04o}, got {:04o}",
            path.display(),
            required_mode,
            mode
        ));
    }
    Ok(())
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn openat2_nosymlink(path: &Path) -> Result<File, std::io::Error> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: 0x04,
    };
    // SAFETY: path is NUL-terminated, `how` matches struct open_how, and both
    // pointers remain valid for the duration of the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        ) as RawFd
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful openat2 returned a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::{run, Args, EXIT_CONFIG, EXIT_USAGE};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn command_line_usage_error_matches_documented_exit_code() {
        let error = Args::try_parse_from(["ssxd", "--not-a-real-option"])
            .expect_err("unknown option must be rejected");
        assert_eq!(error.exit_code(), i32::from(EXIT_USAGE));
    }

    #[test]
    fn missing_config_matches_documented_config_exit_code() {
        let args = Args {
            config: PathBuf::from("/ssxpro-test-config-does-not-exist.yaml"),
            check_config: true,
            print_host_pin: false,
            skip_permission_checks: false,
            verbose: 0,
        };
        let error = run(&args).expect_err("missing config must fail validation");
        assert_eq!(error.0, EXIT_CONFIG);
    }

    #[test]
    fn permission_override_uses_explicit_long_flag() {
        let args = Args::try_parse_from([
            "ssxd",
            "--yes-I-know-permission-risks-go-ahead-please",
            "--check-config",
        ])
        .expect("explicit permission override flag must be accepted");
        assert!(args.skip_permission_checks);
        assert!(Args::try_parse_from(["ssxd", "--skip-config-permissions"]).is_err());
    }
}
