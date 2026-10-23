//! Accountable state: a configured roster runs the same deterministic [`StateMachine`], every action
//! is signed, replayed and co-certified, and misbehaviour leaves portable, independently
//! verifiable evidence (`GV-EVIDENCE-PACKAGE/V1`).
//!
//! Ordinary use needs six operations and one trait:
//!
//! | Operation | Purpose |
//! |---|---|
//! | [`AccountableState::open`] | identity, rules, durable storage and crash recovery |
//! | [`AccountableState::submit`] | a local action for authenticated execution and propagation |
//! | [`AccountableState::state`] | certified state and its commitment |
//! | [`AccountableState::subscribe`] | replayable, signed updates, challenges and fraud evidence |
//! | [`AccountableState::export`] | match archives, fraud proofs and audit evidence |
//! | [`Verifier::verify_package`] | verify exported evidence without running a node |
//!
//! [`AccountableState::receive`] and [`AccountableState::poll`] move protocol bytes; a transport
//! runner calls them. The application implements [`StateMachine`].
//!
//! Three streams stay separate: the lossy 60 Hz input stream ([`realtime`]), the reliable signed
//! pipeline ([`Peer::Member`]) and the witness/audit channel ([`Peer::Witness`],
//! `GV-WITNESS/V1`, [`witness`]).
//!
//! Strict defaults: durable storage is mandatory ([`DurableStorage`]), authentication is
//! ML-DSA-65 only, and an action whose outcome needs a global order
//! ([`ActionOrdering::RequiresExternalOrdering`]) is refused: the absence of a fraud proof never
//! makes such an action final.
#![forbid(unsafe_code)]
mod config;
mod evidence;
#[cfg(feature = "fault-injection")]
mod faults;
mod incarnation;
mod ingress;
mod io;
mod node;
mod own;
mod persist;
mod verifier;
pub mod view;

pub use config::{Config, DurableStorage, WitnessMode};
pub use evidence::{EvidencePackage, ExportQuery};
pub use ingress::IngressLimits;
pub use io::{OpenError, Outgoing, Output, Peer, ReceiveError, SubmitError, WitnessOut};
pub use node::{AccountableState, StateView};
pub use verifier::{Reason, VerificationResult, VerifiedProof, VerifiedRecord, Verifier};

pub use gv_core::{Digest, MatchId, ParticipantId};

/// Who takes part and how their work is certified and ordered.
pub mod session {
    pub use gv_core::{Certification, Ordering, Participant, Role, Roster, Session};
}
pub use gv_edge::export::{
    Commitment, DisclosurePolicy, ExportError, ExportEvent, FraudKind, PackageKind, TrustAnchor,
};
pub use gv_edge::feed::{read_since, SignedEvent};
pub use gv_edge::live::PipelineConfig;
pub use gv_edge::live::{
    AuditEvent, AuditStats, Dest, PeerEvent, PipeEvent as Event, SealError, SealPolicy, Suspicion,
    SuspicionKind, Violation, ViolationKind,
};
pub use gv_edge::CertifiedMatch;
pub use gv_replay::{ActionOrdering, RuleError, StateMachine, ViolationCode};

/// ML-DSA-65 identities (the only signature scheme).
pub mod identity {
    pub use gv_sig::{decode_public_key_file, encode_public_key_file, SigningKey};
}

/// Challenge states and signed log heads, as they appear in events and witness traffic.
pub mod audit {
    pub use gv_edge::audit::{Authenticator, Challenge, Evidence, Response, Status};
}

/// The lossy input stream and provisional prediction. Provisional state lives here so a 60 Hz
/// loop never waits for signatures or replay; [`AccountableState`] certifies it behind.
pub mod realtime {
    pub use gv_edge::live::{
        AdvanceError, Prediction, StreamError, StreamFrame, StreamSender, Timeline, TimelineStats,
    };
}

/// The witness service (`GV-WITNESS/V1`): pinned third parties that hold signed heads, relay
/// evidence and audit participants. They never decide gameplay.
pub mod witness {
    /// Append-only, checksummed record file: a witness process's durable item store.
    pub use gv_edge::audit::store::RecordFile;
    /// What a witness service hands its player: `PipeMsg::Challenge` or `PipeMsg::Anchor`,
    /// encoded and passed to [`crate::AccountableState::receive`] as [`crate::Peer::Witness`].
    pub use gv_edge::live::PipeMsg;
    /// The head register a witness runs and the cell store it keeps durable.
    pub use gv_edge::quorum::{CellStore, FileCellStore, QuorumMsg, RegisterWitness};
    pub use gv_edge::witness::*;
}

/// Native encrypted transport: Hydra ML-DSA-65 handshake over p2p-net.
#[cfg(feature = "p2p")]
pub mod transport {
    pub use gv_p2p::*;
}
