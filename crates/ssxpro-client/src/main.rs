use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::{Parser, Subcommand};
use ssxpro_config::{
    default_client_config_path, parse_client_yaml, ClientConfig, KnownHostsPolicy,
};
use ssxpro_crypto::{fingerprint_spki, read_user_file, write_user_file_new, Ed25519Keypair};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub mod terminal;
pub mod transport;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "ssx", version, about = "ssxpro remote shell client")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// Connect to USER@HOST:PORT or a configured host alias.
    target: Option<String>,
    /// Use this Ed25519 identity instead of the configured identity.
    #[arg(short = 'i', long, value_name = "PATH")]
    identity: Option<PathBuf>,
    /// Override the configured (or target) QUIC port.
    #[arg(short, long, value_name = "PORT")]
    port: Option<u16>,
    /// Increase verbosity (repeat for more: -v, -vv, -vvv).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, default_value_t = 0)]
    verbose: u8,
    /// Automatically approve and save a previously unknown host key.
    #[arg(long)]
    approve_host: bool,
    /// Use this YAML configuration file instead of ~/.ssx/config.yaml.
    #[arg(short, long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Validate the YAML configuration and exit.
    #[arg(long)]
    check_config: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new Ed25519 identity in ~/.ssx.
    Keygen,
    /// Print the SPKI SHA-256 fingerprint for the local identity.
    Fingerprint,
}

struct LoadedClientConfig {
    config: ClientConfig,
    found: bool,
}

fn load_client_config(explicit: Option<&Path>) -> Result<LoadedClientConfig, String> {
    let (path, must_exist) = match explicit {
        Some(path) => (path.to_path_buf(), true),
        None => (default_client_config_path(), false),
    };
    let mut source = String::new();
    let read_result = std::fs::File::open(&path)
        .and_then(|file| file.take(MAX_CONFIG_BYTES + 1).read_to_string(&mut source));
    match read_result {
        Ok(length) if length as u64 > MAX_CONFIG_BYTES => {
            Err(format!("config file {} exceeds 1 MiB", path.display()))
        }
        Ok(_) => Ok(LoadedClientConfig {
            config: parse_client_yaml(&source).map_err(|error| error.to_string())?,
            found: true,
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !must_exist => {
            Ok(LoadedClientConfig {
                config: ClientConfig::default(),
                found: false,
            })
        }
        Err(error) => Err(format!("cannot read config {}: {error}", path.display())),
    }
}

fn main() -> ExitCode {
    let args = Args::try_parse().unwrap_or_else(|error| {
        let code = if error.use_stderr() { 2 } else { 0 };
        let _ = error.print();
        std::process::exit(code);
    });
    if let Some(command) = args.command {
        return match command {
            Command::Keygen => keygen(),
            Command::Fingerprint => fingerprint(),
        };
    }
    let mut loaded = match load_client_config(args.config.as_deref()) {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("ssx: {error}");
            return ExitCode::from(3);
        }
    };
    if args.approve_host {
        loaded.config.known_hosts_policy = KnownHostsPolicy::Approve;
    }
    if args.check_config {
        println!("configuration is valid");
        return ExitCode::SUCCESS;
    }
    let Some(raw_target) = args.target.as_deref() else {
        eprintln!(
            "ssx: no target provided. Usage: ssx USER@HOST:PORT [--identity PATH] [--port PORT] [--approve-host] [--config PATH]"
        );
        return ExitCode::from(1);
    };
    let target = match transport::parse_target(raw_target) {
        Ok(target) => target,
        Err(error) => {
            eprintln!("ssx: {error}");
            return ExitCode::from(1);
        }
    };
    if target.port.is_none() && args.port.is_none() && !loaded.found {
        eprintln!(
            "ssx: no configuration file at {}; without a config the target must be USER@HOST:PORT",
            default_client_config_path().display()
        );
        return ExitCode::from(1);
    }
    match transport::connect_and_echo(
        target,
        args.identity.as_deref(),
        args.port,
        args.verbose,
        &loaded.config,
    ) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("ssx: {error}");
            ExitCode::from(255)
        }
    }
}

fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_owned())
}

fn keygen() -> ExitCode {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let home = home_dir()?;
        let key = Ed25519Keypair::generate()?;
        let private = key.seed();
        let public = format!("ed25519 {}\n", STANDARD.encode(key.public_key().0));
        write_user_file_new(&home, "id_ed25519", private)?;
        if let Err(error) = write_user_file_new(&home, "id_ed25519.pub", public.as_bytes()) {
            eprintln!(
                "ssx: public key write failed; private key remains at ~/.ssx/id_ed25519: {error}"
            );
            return Err(Box::new(error));
        }
        println!("created ~/.ssx/id_ed25519 and ~/.ssx/id_ed25519.pub");
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ssx keygen: {error}");
            ExitCode::from(1)
        }
    }
}

fn fingerprint() -> ExitCode {
    let result = (|| -> Result<String, Box<dyn std::error::Error>> {
        let home = home_dir()?;
        let bytes = read_user_file(&home, "id_ed25519", 256)?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "private identity seed must be exactly 32 bytes")?;
        let key = Ed25519Keypair::from_seed(seed)?;
        Ok(fingerprint_spki(&key.public_key().to_spki_der())?)
    })();
    match result {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ssx fingerprint: {error}");
            ExitCode::from(1)
        }
    }
}
