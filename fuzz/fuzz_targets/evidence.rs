#![no_main]
use gv_edge::audit::challenge::{Challenge, Response};
use gv_edge::audit::trust::Pins;
use gv_edge::audit::Evidence;
use gv_edge::feed::SignedEvent;
use gv_edge::{CheckpointEvidence, FraudBundle, SignedCheckpoint};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(e) = Evidence::decode(data) {
        // Verification of attacker-chosen evidence must never panic.
        let _ = e.verify();
    }
    let _ = Challenge::decode(data);
    let _ = Response::decode(data);
    let _ = Pins::decode(data);
    if let Ok(e) = SignedEvent::decode(data) {
        let _ = e.verify();
    }
    let _ = CheckpointEvidence::decode(data);
    let _ = SignedCheckpoint::decode(data);
    let _ = FraudBundle::decode(data);
});
