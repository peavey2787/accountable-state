use gv_edge::audit::{Authenticator, Response};
use gv_edge::live::PipeEvent;

/// Who sent bytes to [`crate::AccountableState::receive`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// The other participant, over the reliable signed pipeline.
    Opponent,
    /// The local witness service. It may only deliver witness challenges and heads of mine that
    /// a witness retained; anything else is refused.
    Witness,
}

/// Something [`crate::AccountableState::poll`] wants delivered.
#[derive(Clone, Debug)]
pub enum Outgoing {
    /// Reliable pipeline bytes for the opponent. Everything signed in them is already durable.
    Opponent(Vec<u8>),
    /// For the witness service.
    Witness(WitnessOut),
}

#[derive(Clone, Debug)]
pub enum WitnessOut {
    /// A signed log head (mine or the opponent's) for witnesses to retain.
    Auth(Authenticator),
    /// My answer to a witness challenge.
    Response(Response),
    /// Verified accountability evidence (`audit::Evidence` bytes).
    Evidence(Vec<u8>),
    /// A verified `GV-EVIDENCE-PACKAGE/V1` fraud witness.
    Package(Vec<u8>),
}

#[derive(Clone, Debug)]
pub enum Output {
    Send(Outgoing),
    /// Live notification for the application (remote inputs, certified epochs, violations,
    /// audit progress, faults). The durable, resumable record is [`crate::AccountableState::subscribe`].
    Event(PipeEvent),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The signing key is not one of the two roster members, or the roster repeats a key.
    NotInRoster,
    /// The resume archive does not authenticate against this match, roster and ruleset.
    Recovery(String),
    /// Durable storage could not be opened. Accountable operation never falls back to memory.
    Storage { file: String, error: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitError {
    /// The state machine classifies this action as needing external ordering or consensus.
    RequiresExternalOrdering,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveError {
    Malformed,
    NotAllowedFromWitness,
}
