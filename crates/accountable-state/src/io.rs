use gv_core::ParticipantId;
use gv_edge::audit::{Authenticator, Response};
use gv_edge::live::{Dest, PipeEvent};
use gv_edge::quorum::QuorumMsg;

/// Who sent bytes to [`crate::AccountableState::receive`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// A roster member, over the reliable signed pipeline. The transport has authenticated the
    /// link, so this id is who signed the handshake.
    Member(ParticipantId),
    /// A pinned witness service. It may only deliver witness challenges and heads of mine that a
    /// witness retained; anything else is refused.
    Witness(ParticipantId),
}

/// Something [`crate::AccountableState::poll`] wants delivered.
#[derive(Clone, Debug)]
pub enum Outgoing {
    /// Reliable pipeline bytes for one member or all of them. Everything signed in them is
    /// already durable.
    Member { to: Dest, bytes: Vec<u8> },
    /// For the witness service.
    Witness(WitnessOut),
}

#[derive(Clone, Debug)]
pub enum WitnessOut {
    /// A signed log head (mine or the opponent's) for witnesses to retain.
    Auth(Box<Authenticator>),
    /// My answer to a witness challenge.
    Response(Box<Response>),
    /// Verified accountability evidence (`audit::Evidence` bytes).
    Evidence(Vec<u8>),
    /// A verified `GV-EVIDENCE-PACKAGE/V1` fraud witness.
    Package(Vec<u8>),
    /// Head-register traffic: to one witness, or to all of them (`None`).
    Quorum {
        to: Option<ParticipantId>,
        msg: Box<QuorumMsg>,
    },
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
    /// The signing key is not a roster member that signs checkpoints, or the pipeline
    /// configuration is outside the protocol limits.
    NotInRoster,
    /// The resume archive does not authenticate against this match, roster and ruleset.
    Recovery(String),
    /// Durable storage could not be opened. Accountable operation never falls back to memory.
    Storage { file: String, error: String },
    /// The witness configuration cannot support the requested mode.
    Witnesses(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitError {
    /// The state machine classifies this action as needing external ordering or consensus.
    RequiresExternalOrdering,
    /// The action is not as wide as the configured idle input.
    WrongWidth { expected: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveError {
    Malformed,
    NotAllowedFromWitness,
}
