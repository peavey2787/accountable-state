#![no_main]
use gv_codec::{Aggregate, PackedControls, SignedPackedControls};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Canonical-or-reject: anything that decodes must re-encode to the identical bytes.
    if let Ok(r) = PackedControls::decode(data) {
        assert_eq!(r.encode().expect("decoded record re-encodes"), data);
    }
    let _ = SignedPackedControls::decode(data);
    let _ = Aggregate::decode(data);
});
