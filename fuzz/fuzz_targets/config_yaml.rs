#![no_main]

use libfuzzer_sys::fuzz_target;
use ssxpro_config::{parse_client_yaml, parse_server_yaml};

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = std::str::from_utf8(data) {
        let _ = parse_server_yaml(source);
        let _ = parse_client_yaml(source);
    }
});
