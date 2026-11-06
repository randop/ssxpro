#![no_main]
use libfuzzer_sys::fuzz_target;
use ssxpro_crypto::{parse_authorized_keys, parse_known_hosts};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_authorized_keys(text);
        let _ = parse_known_hosts(text);
    }
});
