//! Byzantine single-writer head register: how an owner recovers its log head after a crash
//! without ever treating silence as authority, and without a recovered honest owner producing
//! evidence against itself.
//!
//! `n` pinned witnesses tolerate `f = (n-1)/3` faulty ones. An owner commits a head by getting a
//! quorum (`n - f`) of witnesses to store a signed [`Claim`]; recovering means reading a quorum
//! of promises under a fresh [`Ballot`], which both fences every older incarnation and returns
//! the newest committed claim (two quorums share an honest witness). Fewer than a quorum is the
//! explicit blocked state: the owner waits, it never resumes on a timeout.
pub mod acceptor;
pub mod registrar;
pub mod set;
#[cfg(test)]
mod tests;
pub mod wire;

pub use acceptor::{Acceptor, Cell, Refusal};
pub use registrar::{Event, Phase, Registrar};
pub use set::{Ballot, WitnessSet, MAX_WITNESSES};
pub use wire::{Certificate, Claim, Nack, Promise, QuorumError, QuorumMsg, Receipt, Recover};
