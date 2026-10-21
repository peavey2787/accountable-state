//! WASM adapter boundary; bindings and JS byte-for-byte vectors are pending.
#![forbid(unsafe_code)]
use gv_core::Digest;
pub fn bytes32(value: &[u8]) -> Option<Digest> {
    value.try_into().ok()
}
