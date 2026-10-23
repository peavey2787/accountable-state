//! C ABI for the proof queue. [`api`] holds the behavior as safe Rust (tested natively); [`ffi`] is
//! the thin `extern "C"` layer that converts raw pointers, and the only place with `unsafe`.
//! `include/gv_proofs.h` declares every exported symbol.
pub mod api;
pub mod ffi;
