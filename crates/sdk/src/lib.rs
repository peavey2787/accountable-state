//! Public integration boundary. Read docs/04-game-integration.md before implementing.
#![forbid(unsafe_code)]
pub use gv_core::{Digest, MatchId, MatchManifest, PlayerId, StateOpening, TransitionClaim};
pub use gv_replay::{GameRules, ReplayVerdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    OwnerOnly,
    AuthorizedTeam,
    HiddenUntilReveal,
    NeverReveal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserverRole {
    Participant,
    Opponent,
    Spectator,
    Arbiter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedView {
    pub bytes: Vec<u8>,
    pub disclosure: Visibility,
}

/// Required game integration; authenticated disclosure is controlled by the game.
/// Returning a view is not itself an access-control check at the network layer.
pub trait GameAdapter: GameRules {
    fn initial_state(&self, manifest: &MatchManifest) -> Result<StateOpening, String>;
    fn view_for(
        &self,
        canonical_state: &[u8],
        observer: &PlayerId,
        role: ObserverRole,
    ) -> Result<AuthorizedView, String>;
    fn validate_manifest(&self, manifest: &MatchManifest) -> Result<(), String>;
}

pub mod prelude {
    pub use crate::{AuthorizedView, GameAdapter, GameRules, ObserverRole, Visibility};
    pub use gv_codec::{
        Aggregate, CodecError, ControlChange, PackedControls, SignedPackedControls,
    };
    pub use gv_commitments::{commit_state, verify_membership, MerkleLog};
    pub use gv_edge::export;
    pub use gv_edge::{
        ArenaRules, ArenaState, BatchCommitment, BilateralAdmission, CertifiedEpoch,
        CertifiedMatch, Checkpoint, CheckpointEvidence, EvidenceVerdict, FraudBundle, MatchReplica,
        PublicRules, SignedBatchCommitment, SignedCheckpoint, SignedEpochLock,
    };
    pub use gv_transcript::{PlayerTranscript, SignedInput};
}
