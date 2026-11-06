#![no_main]
use libfuzzer_sys::fuzz_target;
use ssxpro_proto::{decode, ClientState, ServerState};

fuzz_target!(|data: &[u8]| {
    let mut client = ClientState::Start;
    let mut server = ServerState::Start;
    let mut remaining = data;
    while let Ok((message, consumed)) = decode(remaining) {
        if consumed == 0 || consumed > remaining.len() { break; }
        let _ = client.accept(&message);
        let _ = client.sent(&message);
        let _ = server.accept(&message);
        let _ = server.sent(&message);
        remaining = &remaining[consumed..];
    }
});
