#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ssxpro_proto::decode_monitor_request(data);
    let _ = ssxpro_proto::decode_monitor_response(data);
    let _ = ssxpro_proto::decode_session_token(data);
    let _ = ssxpro_proto::decode_broker_request(data);
    let _ = ssxpro_proto::decode_broker_response(data);
});
