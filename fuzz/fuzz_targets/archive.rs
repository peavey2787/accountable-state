#![no_main]
use gv_edge::export::{AuditExport, Commitment, Package};
use gv_edge::{ArenaState, CertifiedEpoch, CertifiedMatch};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Package::decode(data);
    let _ = AuditExport::decode(data);
    let _ = Commitment::decode(data);
    let _ = CertifiedMatch::decode(data);
    let _ = CertifiedEpoch::decode(data);
    let _ = ArenaState::decode(data);
});
