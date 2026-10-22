#![no_main]
use gv_edge::live::{PipeMsg, SignedSeal, StreamFrame};
use gv_edge::witness::Msg;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = PipeMsg::decode(data) {
        let _ = m.encode();
    }
    let _ = SignedSeal::decode(data);
    let _ = StreamFrame::decode(data);
    let _ = Msg::decode(data);
});
