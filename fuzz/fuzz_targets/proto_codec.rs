#![no_main]
use libfuzzer_sys::fuzz_target;
use ssxpro_proto::decode;

fuzz_target!(|data: &[u8]| {
    let _ = decode(data);
});
