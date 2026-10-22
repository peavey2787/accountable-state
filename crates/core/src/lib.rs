//! Stable protocol identifiers and session types. All lengths and arithmetic are bounded.
#![forbid(unsafe_code)]

mod event;
mod session;

pub use event::{Event, EventError, MAX_EVENT_PAYLOAD};
pub use session::{
    Certification, Ordering, Participant, Role, Roster, RosterError, Session, SessionError,
    MAX_PARAMS_BYTES, MAX_PARTICIPANTS, MAX_SESSION_BYTES,
};

pub type Digest = [u8; 32];
pub type MatchId = [u8; 32];
/// Identity of anything that signs: a player, a dedicated authority or a spectator.
pub type ParticipantId = [u8; 32];

/// The untrusted claimed transition, to be checked against authenticated data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionClaim {
    pub match_id: MatchId,
    pub participant: ParticipantId,
    pub tick: u64,
    pub previous_state: Digest,
    pub claimed_next_state: Digest,
    pub input_digest: Digest,
    pub ruleset: Digest,
}

/// An opening for a hiding state commitment. Nonces must be independently unpredictable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateOpening {
    pub bytes: Vec<u8>,
    pub nonce: Digest,
}

/// Public match settings must be committed before inputs are accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchManifest {
    pub id: MatchId,
    pub ruleset: Digest,
    pub initial_state: Digest,
    pub protocol_version: u16,
    pub max_input_bytes: u32,
    pub max_state_bytes: u32,
    pub challenge_window_ticks: u64,
}
