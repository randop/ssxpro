#![no_main]
use libfuzzer_sys::fuzz_target;
use ssxpro_proto::{decode, ClientState, ServerState};

fuzz_target!(|data: &[u8]| {
    if let Ok((message, _)) = decode(data) {
        let mut client = ClientState::Start;
        let _ = client.accept(&message);
        let _ = client.sent(&message);
        let mut server = ServerState::Start;
        let _ = server.accept(&message);
        let _ = server.sent(&message);
    }
});
