#![forbid(unsafe_code)]

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

pub const MAX_CONTROL_FRAME_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.line, self.column) {
            (Some(line), Some(column)) => {
                write!(f, "line {line}, column {column}: {}", self.message)
            }
            (Some(line), None) => write!(f, "line {line}: {}", self.message),
            _ => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigFeatures {
    /// Enable incremental provided-buffer ring (Linux 5.10+)
    pub iopf_buf_ring: bool,
    /// Enable reuseport CID selector (requires CAP_BPF)
    pub reuseport_steering: bool,
    /// Enable hugepages support
    pub hugepages: bool,
}

fn serde_error(error: yaml_serde::Error) -> ConfigError {
    let location = error.location();
    ConfigError {
        line: location.as_ref().map(yaml_serde::Location::line),
        column: location.as_ref().map(yaml_serde::Location::column),
        message: error.to_string(),
    }
}

fn validation_error(source: &str, path: &str, message: impl Into<String>) -> ConfigError {
    let line = line_for_key_path(source, path);
    ConfigError {
        line,
        column: None,
        message: format!("{path}: {}", message.into()),
    }
}

// Locate known nested keys for semantic range errors. Parser/type errors use
// the YAML parser's exact source location instead.
fn line_for_key_path(source: &str, path: &str) -> Option<usize> {
    let keys: Vec<&str> = path.split('.').collect();
    let mut parent_indent = 0usize;
    let mut start_at = 0usize;
    for (depth, key) in keys.iter().enumerate() {
        let found = source
            .lines()
            .enumerate()
            .skip(start_at)
            .find_map(|(index, raw)| {
                let line = raw.trim_start();
                let indent = raw.len() - line.len();
                (indent >= parent_indent && line.starts_with(&format!("{key}:")))
                    .then_some((index + 1, indent))
            });
        let (line, indent) = found?;
        if depth + 1 == keys.len() {
            return Some(line);
        }
        parent_indent = indent + 1;
        start_at = line;
    }
    None
}

fn bounded<T: PartialOrd + fmt::Display>(
    source: &str,
    path: &str,
    value: T,
    min: T,
    max: T,
) -> Result<(), ConfigError> {
    if value < min || value > max {
        return Err(validation_error(
            source,
            path,
            format!("must be in {min}..={max}, got {value}"),
        ));
    }
    Ok(())
}

fn default_listen() -> String {
    "0.0.0.0:22".to_owned()
}
fn default_host_key() -> PathBuf {
    PathBuf::from("/etc/ssx/host_ed25519")
}
fn default_compression() -> CompressionMode {
    CompressionMode::Off
}
fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map_or(1, usize::from)
        .clamp(1, 256)
}
fn default_ring_entries() -> u32 {
    4096
}
fn default_recv_buffers() -> u32 {
    2048
}
fn default_buffer_size() -> u32 {
    2048
}
fn default_zc_min() -> u32 {
    16_384
}
fn default_sqpoll_idle() -> u32 {
    2
}
fn default_quic_idle() -> u32 {
    600
}
fn default_quic_keep_alive() -> u32 {
    15
}
fn default_max_connections() -> u32 {
    4096
}
fn default_max_frame() -> u32 {
    4096
}
fn default_hello_grace() -> u32 {
    5
}
fn default_auth_timeout() -> u32 {
    30
}
fn default_server_authorized_keys() -> PathBuf {
    PathBuf::from("/etc/ssx/authorized_keys")
}
fn default_login_grace() -> u32 {
    10
}
fn default_max_sessions() -> u32 {
    1024
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionMode {
    #[default]
    Off,
    /// LZ4, optimized for low CPU utilization.
    Fast,
    /// Snappy.
    Standard,
    /// Zstd level 19.
    High,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: String,
    pub host_key: PathBuf,
    /// Server-enforced PTY stream compression: off, fast (LZ4),
    /// standard (Snappy), or high (Zstd level 19).
    pub compression: CompressionMode,
    pub workers: usize,
    pub features: ConfigFeatures,
    pub io: IoConfig,
    pub quic: QuicConfig,
    pub proto: ProtoConfig,
    pub auth: AuthConfig,
    pub session: SessionConfig,
    pub log: LogConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            host_key: default_host_key(),
            compression: default_compression(),
            workers: default_workers(),
            io: IoConfig::default(),
            quic: QuicConfig::default(),
            proto: ProtoConfig::default(),
            auth: AuthConfig::default(),
            session: SessionConfig::default(),
            features: ConfigFeatures::default(),
            log: LogConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IoConfig {
    pub ring_entries: u32,
    pub recv_buffers: u32,
    pub buffer_size: u32,
    pub hugepages: bool,
    pub gro: bool,
    pub gso: bool,
    pub zerocopy_send: bool,
    pub zerocopy_min_bytes: u32,
    pub sqpoll: bool,
    pub sqpoll_idle_ms: u32,
    pub napi_busy_poll_us: u32,
    pub txtime_pacing: bool,
    pub pin_cpus: bool,
    pub restrict_ring: bool,
}

impl Default for IoConfig {
    fn default() -> Self {
        Self {
            ring_entries: default_ring_entries(),
            recv_buffers: default_recv_buffers(),
            buffer_size: default_buffer_size(),
            hugepages: true,
            gro: true,
            gso: true,
            zerocopy_send: false,
            zerocopy_min_bytes: default_zc_min(),
            sqpoll: false,
            sqpoll_idle_ms: default_sqpoll_idle(),
            napi_busy_poll_us: 0,
            txtime_pacing: false,
            pin_cpus: true,
            restrict_ring: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuicConfig {
    pub idle_timeout_secs: u32,
    /// Send a QUIC PING when no packet has been received for this many
    /// seconds. 0 disables server-side keepalives.
    pub keep_alive_interval_secs: u32,
    pub max_connections: u32,
    pub max_datagram_size: u16,
    pub retry: bool,
}
impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: default_quic_idle(),
            keep_alive_interval_secs: default_quic_keep_alive(),
            max_connections: default_max_connections(),
            max_datagram_size: 1200,
            retry: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProtoConfig {
    pub max_control_frame_bytes: u32,
    pub hello_grace_secs: u32,
    pub auth_timeout_secs: u32,
}
impl Default for ProtoConfig {
    fn default() -> Self {
        Self {
            max_control_frame_bytes: default_max_frame(),
            hello_grace_secs: default_hello_grace(),
            auth_timeout_secs: default_auth_timeout(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Absolute path to a server-wide authorized_keys file. It is checked
    /// before the per-user file; a missing file is skipped. Empty disables it.
    pub server_authorized_keys: PathBuf,
    /// Per-user key file name inside `$HOME/.ssx`, checked after the
    /// server-wide file.
    pub authorized_keys: PathBuf,
    pub max_attempts: u8,
    pub allow_root: bool,
}
impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            server_authorized_keys: default_server_authorized_keys(),
            authorized_keys: PathBuf::from("authorized_keys"),
            max_attempts: 1,
            allow_root: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionConfig {
    pub login_grace_secs: u32,
    pub max_sessions: u32,
    pub max_rows: u16,
    pub max_columns: u16,
    pub shell_path: PathBuf,
}
impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            login_grace_secs: default_login_grace(),
            max_sessions: default_max_sessions(),
            max_rows: 500,
            max_columns: 500,
            shell_path: PathBuf::from("/bin/sh"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct LogConfig {
    pub level: LogLevel,
    pub json: bool,
}
impl ServerConfig {
    pub fn validate(&self, source: &str) -> Result<(), ConfigError> {
        if self.listen.parse::<std::net::SocketAddr>().is_err() {
            return Err(validation_error(
                source,
                "listen",
                "must be a socket address such as 0.0.0.0:22",
            ));
        }
        bounded(source, "workers", self.workers, 1, 256)?;
        bounded(source, "io.ring_entries", self.io.ring_entries, 64, 32768)?;
        if !self.io.ring_entries.is_power_of_two() {
            return Err(validation_error(
                source,
                "io.ring_entries",
                "must be a power of two",
            ));
        }
        bounded(source, "io.recv_buffers", self.io.recv_buffers, 64, 65536)?;
        bounded(source, "io.buffer_size", self.io.buffer_size, 2048, 65536)?;
        bounded(
            source,
            "io.zerocopy_min_bytes",
            self.io.zerocopy_min_bytes,
            1024,
            65536,
        )?;
        bounded(source, "io.sqpoll_idle_ms", self.io.sqpoll_idle_ms, 1, 1000)?;
        bounded(
            source,
            "io.napi_busy_poll_us",
            self.io.napi_busy_poll_us,
            0,
            10000,
        )?;
        bounded(
            source,
            "quic.idle_timeout_secs",
            self.quic.idle_timeout_secs,
            10,
            86400,
        )?;
        bounded(
            source,
            "quic.keep_alive_interval_secs",
            self.quic.keep_alive_interval_secs,
            0,
            3600,
        )?;
        bounded(
            source,
            "quic.max_connections",
            self.quic.max_connections,
            1,
            1_000_000,
        )?;
        bounded(
            source,
            "quic.max_datagram_size",
            self.quic.max_datagram_size,
            1200,
            65527,
        )?;
        bounded(
            source,
            "proto.max_control_frame_bytes",
            self.proto.max_control_frame_bytes,
            1,
            MAX_CONTROL_FRAME_BYTES as u32,
        )?;
        bounded(
            source,
            "proto.hello_grace_secs",
            self.proto.hello_grace_secs,
            1,
            60,
        )?;
        bounded(
            source,
            "proto.auth_timeout_secs",
            self.proto.auth_timeout_secs,
            1,
            300,
        )?;
        bounded(source, "auth.max_attempts", self.auth.max_attempts, 1, 10)?;
        if !self.auth.server_authorized_keys.as_os_str().is_empty()
            && !self.auth.server_authorized_keys.is_absolute()
        {
            return Err(validation_error(
                source,
                "auth.server_authorized_keys",
                "must be an absolute path or empty",
            ));
        }
        bounded(
            source,
            "session.login_grace_secs",
            self.session.login_grace_secs,
            1,
            300,
        )?;
        bounded(
            source,
            "session.max_sessions",
            self.session.max_sessions,
            1,
            1_000_000,
        )?;
        bounded(
            source,
            "session.max_rows",
            self.session.max_rows,
            1,
            u16::MAX,
        )?;
        bounded(
            source,
            "session.max_columns",
            self.session.max_columns,
            1,
            u16::MAX,
        )?;
        if !self.host_key.is_absolute() {
            return Err(validation_error(
                source,
                "host_key",
                "must be an absolute path",
            ));
        }
        if !self.session.shell_path.is_absolute() {
            return Err(validation_error(
                source,
                "session.shell_path",
                "must be an absolute path",
            ));
        }
        Ok(())
    }
}

pub fn parse_server_yaml(source: &str) -> Result<ServerConfig, ConfigError> {
    let config: ServerConfig = yaml_serde::from_str(source).map_err(serde_error)?;
    config.validate(source)?;
    Ok(config)
}

fn default_identity() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|path| path.join(".ssx/id_ed25519"))
        .unwrap_or_else(|| PathBuf::from(".ssx/id_ed25519"))
}
fn default_client_port() -> u16 {
    22
}
fn default_connect_timeout() -> u32 {
    10
}
fn default_handshake_timeout() -> u32 {
    15
}
fn default_known_hosts() -> PathBuf {
    PathBuf::from("~/.ssx/known_hosts")
}
fn default_client_idle_timeout() -> u32 {
    600
}
fn default_server_alive_interval() -> u32 {
    15
}
fn default_server_alive_count_max() -> u32 {
    6
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientConfig {
    pub hosts: BTreeMap<String, HostAlias>,
    pub identity: PathBuf,
    pub port: u16,
    pub connect_timeout_secs: u32,
    pub handshake_timeout_secs: u32,
    /// QUIC idle timeout in seconds; 0 means no idle timeout.
    pub idle_timeout_secs: u32,
    /// Send a QUIC PING when no packet has been received for this many
    /// seconds (SSH `ServerAliveInterval`). 0 disables client keepalives.
    pub server_alive_interval_secs: u32,
    /// Disconnect after this many unanswered keepalives
    /// (SSH `ServerAliveCountMax`).
    pub server_alive_count_max: u32,
    pub known_hosts: PathBuf,
    pub known_hosts_policy: KnownHostsPolicy,
}
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            hosts: BTreeMap::new(),
            identity: default_identity(),
            port: default_client_port(),
            connect_timeout_secs: default_connect_timeout(),
            handshake_timeout_secs: default_handshake_timeout(),
            idle_timeout_secs: default_client_idle_timeout(),
            server_alive_interval_secs: default_server_alive_interval(),
            server_alive_count_max: default_server_alive_count_max(),
            known_hosts: default_known_hosts(),
            known_hosts_policy: KnownHostsPolicy::Ask,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostAlias {
    pub host: String,
    pub port: Option<u16>,
    pub identity: Option<PathBuf>,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KnownHostsPolicy {
    /// Reject connections to hosts that are not already pinned.
    Deny,
    /// Prompt before accepting an unknown host key.
    #[default]
    Ask,
    /// Accept and save an unknown host key without prompting.
    Approve,
}

impl ClientConfig {
    pub fn validate(&self, source: &str) -> Result<(), ConfigError> {
        bounded(source, "port", self.port, 1, u16::MAX)?;
        bounded(
            source,
            "connect_timeout_secs",
            self.connect_timeout_secs,
            1,
            600,
        )?;
        bounded(
            source,
            "handshake_timeout_secs",
            self.handshake_timeout_secs,
            1,
            600,
        )?;
        bounded(
            source,
            "idle_timeout_secs",
            self.idle_timeout_secs,
            0,
            86400,
        )?;
        bounded(
            source,
            "server_alive_interval_secs",
            self.server_alive_interval_secs,
            0,
            3600,
        )?;
        bounded(
            source,
            "server_alive_count_max",
            self.server_alive_count_max,
            1,
            100,
        )?;
        for (name, alias) in &self.hosts {
            if name.is_empty()
                || name.len() > 128
                || name.chars().any(|ch| ch == '\n' || ch == '\r')
            {
                return Err(validation_error(
                    source,
                    "hosts",
                    format!("alias name {name:?} must be 1..=128 bytes without newlines"),
                ));
            }
            if alias.host.is_empty()
                || alias.host.len() > 253
                || alias
                    .host
                    .chars()
                    .any(|ch| ch == '\n' || ch == '\r' || ch == '\0')
            {
                return Err(validation_error(
                    source,
                    &format!("hosts.{name}.host"),
                    "must be a nonempty hostname or address of at most 253 bytes",
                ));
            }
            if alias.port == Some(0) {
                return Err(validation_error(
                    source,
                    &format!("hosts.{name}.port"),
                    "must be between 1 and 65535",
                ));
            }
        }
        Ok(())
    }
}

pub fn parse_client_yaml(source: &str) -> Result<ClientConfig, ConfigError> {
    let config: ClientConfig = yaml_serde::from_str(source).map_err(serde_error)?;
    config.validate(source)?;
    Ok(config)
}

pub fn default_server_config_path() -> PathBuf {
    PathBuf::from("/etc/ssx/ssxd.yaml")
}

pub fn default_client_config_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|path| path.join(".ssx/config.yaml"))
        .unwrap_or_else(|| PathBuf::from(".ssx/config.yaml"))
}

#[cfg(test)]
mod tests {
    use super::{parse_client_yaml, parse_server_yaml, KnownHostsPolicy};

    #[test]
    fn features_default_individually_and_reject_typos() {
        let features: super::ConfigFeatures =
            yaml_serde::from_str("reuseport_steering: true").unwrap();
        assert!(features.reuseport_steering);
        assert!(!features.iopf_buf_ring);
        assert!(!features.hugepages);
        assert!(yaml_serde::from_str::<super::ConfigFeatures>("hugepage: true").is_err());
    }

    #[test]
    fn omitted_values_use_defaults() {
        let server = parse_server_yaml("").expect("empty server config uses defaults");
        assert_eq!(server.io.ring_entries, 4096);
        assert!(server.io.gro);
        let client = parse_client_yaml("").expect("empty client config uses defaults");
        assert_eq!(client.port, 22);
    }

    #[test]
    fn compression_defaults_to_off_and_accepts_all_modes() {
        let server = parse_server_yaml("").expect("empty server config uses defaults");
        assert_eq!(server.compression, super::CompressionMode::Off);

        for (name, expected) in [
            ("off", super::CompressionMode::Off),
            ("fast", super::CompressionMode::Fast),
            ("standard", super::CompressionMode::Standard),
            ("high", super::CompressionMode::High),
        ] {
            let server = parse_server_yaml(&format!("compression: {name}\n"))
                .expect("documented compression mode is accepted");
            assert_eq!(server.compression, expected);
        }
        for invalid in ["lz4", "snappy", "zstd", "FAST", "fastest"] {
            let error = parse_server_yaml(&format!("compression: {invalid}\n"))
                .expect_err("unknown compression mode is rejected");
            assert_eq!(error.line, Some(1));
        }
    }

    #[test]
    fn unknown_key_has_source_line() {
        let error = parse_server_yaml("io:\n  surprise: true\n").expect_err("unknown key rejected");
        assert_eq!(error.line, Some(2));
    }

    #[test]
    fn bad_type_has_source_line_and_column() {
        let error =
            parse_server_yaml("io:\n  ring_entries: many\n").expect_err("bad type rejected");
        assert_eq!(error.line, Some(2));
        assert!(error.column.is_some());
    }

    #[test]
    fn out_of_range_value_has_key_and_source_line() {
        let error =
            parse_server_yaml("io:\n  ring_entries: 48\n").expect_err("invalid ring size rejected");
        assert_eq!(error.line, Some(2));
        assert!(error.message.contains("io.ring_entries"));
    }

    #[test]
    fn server_authorized_keys_defaults_to_etc_and_must_be_absolute() {
        let server = parse_server_yaml("").expect("empty server config uses defaults");
        assert_eq!(
            server.auth.server_authorized_keys,
            std::path::PathBuf::from("/etc/ssx/authorized_keys")
        );
        let server = parse_server_yaml("auth:\n  server_authorized_keys: rel/keys\n")
            .expect_err("relative server key path is rejected");
        assert!(server.message.contains("auth.server_authorized_keys"));
        let server = parse_server_yaml("auth:\n  server_authorized_keys: /run/keys\n")
            .expect("absolute path accepted");
        assert_eq!(
            server.auth.server_authorized_keys,
            std::path::PathBuf::from("/run/keys")
        );
    }

    #[test]
    fn keepalive_defaults_and_overrides() {
        let client = parse_client_yaml("").expect("empty client config uses defaults");
        assert_eq!(client.idle_timeout_secs, 600);
        assert_eq!(client.server_alive_interval_secs, 15);
        assert_eq!(client.server_alive_count_max, 6);
        let server = parse_server_yaml("").expect("empty server config uses defaults");
        assert_eq!(server.quic.keep_alive_interval_secs, 15);

        let client = parse_client_yaml(
            "idle_timeout_secs: 120\nserver_alive_interval_secs: 30\nserver_alive_count_max: 4\n",
        )
        .expect("keepalive overrides are accepted");
        assert_eq!(client.idle_timeout_secs, 120);
        assert_eq!(client.server_alive_interval_secs, 30);
        assert_eq!(client.server_alive_count_max, 4);
        let server = parse_server_yaml("quic:\n  keep_alive_interval_secs: 0\n")
            .expect("server keepalive can be disabled");
        assert_eq!(server.quic.keep_alive_interval_secs, 0);
    }

    #[test]
    fn out_of_range_keepalive_values_are_rejected() {
        let error = parse_client_yaml("server_alive_count_max: 0\n")
            .expect_err("zero keepalive count is rejected");
        assert!(error.message.contains("server_alive_count_max"));
        let error = parse_server_yaml("quic:\n  keep_alive_interval_secs: 99999\n")
            .expect_err("oversize keepalive interval is rejected");
        assert!(error.message.contains("quic.keep_alive_interval_secs"));
    }

    #[test]
    fn client_known_hosts_policy_defaults_to_ask() {
        let client = parse_client_yaml("").expect("empty client config uses defaults");
        assert_eq!(client.known_hosts_policy, KnownHostsPolicy::Ask);

        let client = parse_client_yaml("known_hosts_policy: deny\n").expect("deny policy accepted");
        assert_eq!(client.known_hosts_policy, KnownHostsPolicy::Deny);
        let client = parse_client_yaml("known_hosts_policy: ask\n").expect("ask policy accepted");
        assert_eq!(client.known_hosts_policy, KnownHostsPolicy::Ask);
        let client =
            parse_client_yaml("known_hosts_policy: approve\n").expect("approve policy accepted");
        assert_eq!(client.known_hosts_policy, KnownHostsPolicy::Approve);

        assert!(parse_client_yaml("known_hosts_policy: reject\n").is_err());
        assert!(parse_client_yaml("known_hosts_policy: accept-new\n").is_err());
    }

    #[test]
    fn client_alias_unknown_key_is_rejected() {
        let error =
            parse_client_yaml("hosts:\n  home:\n    host: shell.example\n    user: alice\n")
                .expect_err("unknown alias field rejected");
        assert_eq!(error.line, Some(4));
    }
}
