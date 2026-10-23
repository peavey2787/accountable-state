//! Browser / Web Worker bindings for the proof queue. [`host::HostQueue`] holds the behavior (and
//! is tested natively); the wasm-bindgen class below only converts types.
#![forbid(unsafe_code)]

pub use gv_proof_queue::host;

#[cfg(target_arch = "wasm32")]
mod js;

#[cfg(target_arch = "wasm32")]
pub use js::ProofQueue;
