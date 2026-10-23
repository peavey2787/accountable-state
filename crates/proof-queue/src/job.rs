//! Job model: what is verified (family + canonical inputs), how urgently, and where in its
//! lifecycle it is. A job is identified by the hash of what it verifies, so submitting the same
//! evidence twice is one job.
use gv_core::{MatchId, ParticipantId};
use sha2::{Digest as _, Sha256};

pub type JobId = [u8; 32];

/// The kind of evidence a job verifies. Open for extension: a future proof system registers a
/// family number and a verifier; nothing else changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Family(pub u16);

impl Family {
    /// Signed input batches (a list, see [`crate::verify::pack`]).
    pub const SIGNED_INPUTS: Self = Self(1);
    /// A signed batch commitment.
    pub const COMMITMENT: Self = Self(2);
    /// A witness-quorum recovery certificate.
    pub const RECOVERY_CERTIFICATE: Self = Self(3);
    /// Log-equivocation evidence (plain or witness-certified).
    pub const EQUIVOCATION: Self = Self(4);
    /// A certified epoch replayed through the deterministic state machine.
    pub const TRANSITION: Self = Self(5);
    /// First number available to proof systems outside this crate.
    pub const EXTENSION_BASE: u16 = 0x100;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Evidence that can convict or clear someone: never shed before the hard capacity.
    High = 0,
    Normal = 1,
    /// Routine certification of honest play; shed first under overload.
    Low = 2,
}

impl Priority {
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::High),
            1 => Some(Self::Normal),
            2 => Some(Self::Low),
            _ => None,
        }
    }
}

/// Everything a verifier needs, canonical and self-contained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSpec {
    pub family: Family,
    pub match_id: MatchId,
    pub payload: Vec<u8>,
    pub priority: Priority,
    /// Absolute time after which an unfinished job expires (never certifies).
    pub deadline: Option<u64>,
    /// Jobs that must be verified first (for example the epoch before this one).
    pub deps: Vec<JobId>,
}

impl JobSpec {
    /// Content identity: family, match and payload (priority, deadline and dependencies are
    /// scheduling, not part of what is verified).
    pub fn id(&self) -> JobId {
        let mut h = Sha256::new();
        h.update(b"gv/proof-job/v1");
        h.update(self.family.0.to_le_bytes());
        h.update(self.match_id);
        h.update(&self.payload);
        h.finalize().into()
    }
}

/// Lifecycle of one job. `Verified`, `Certified`, `ViolationProven`, `Uncertified`, `Expired`
/// and `Failed` are terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    Pending,
    Processing,
    /// The evidence checked out; nothing was violated.
    Verified,
    /// Verified, and it carries a certification (quorum or checkpoint policy satisfied).
    Certified,
    /// The evidence proves the accused broke the rules.
    ViolationProven,
    /// Inconclusive, cancelled, or a dependency never verified: no verdict either way.
    Uncertified,
    /// The deadline passed first. A timeout is never certification.
    Expired,
    /// The submission itself was invalid or verification kept failing.
    Failed,
}

impl JobState {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::Processing)
    }
    /// A dependency in this state lets dependents run.
    pub(crate) fn satisfies_dependency(self) -> bool {
        matches!(self, Self::Verified | Self::Certified)
    }
    pub(crate) fn code(self) -> u8 {
        self as u8
    }
    pub(crate) fn from_code(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Pending,
            1 => Self::Processing,
            2 => Self::Verified,
            3 => Self::Certified,
            4 => Self::ViolationProven,
            5 => Self::Uncertified,
            6 => Self::Expired,
            7 => Self::Failed,
            _ => return None,
        })
    }
}

/// What a verifier concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Valid,
    /// Valid and certified by the evidence itself.
    Certified,
    Violation {
        accused: ParticipantId,
        evidence: Vec<u8>,
    },
    /// The submission does not verify (forged, malformed, wrong match). Proves nothing about
    /// anyone except that the submission is unusable.
    Invalid(String),
    /// Verification could not decide either way.
    Inconclusive(String),
    /// A temporary problem (resource, dependency not loaded yet): retry later.
    Retry(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub id: JobId,
    pub spec: JobSpec,
    pub state: JobState,
    pub attempts: u32,
    pub submitted_at: u64,
    pub finished_at: u64,
    /// Earliest time the next attempt may start (exponential retry delay).
    pub not_before: u64,
    pub lease_until: u64,
    pub reason: String,
    pub accused: Option<ParticipantId>,
    /// Portable proof of the violation, when `state` is `ViolationProven`.
    pub evidence: Vec<u8>,
    pub seq: u64,
}

impl Job {
    pub(crate) fn new(spec: JobSpec, now: u64, seq: u64) -> Self {
        Self {
            id: spec.id(),
            spec,
            state: JobState::Pending,
            attempts: 0,
            submitted_at: now,
            finished_at: 0,
            not_before: 0,
            lease_until: 0,
            reason: String::new(),
            accused: None,
            evidence: Vec::new(),
            seq,
        }
    }
}

/// A state change, in the order it happened. Persisted with the queue and replayed after a
/// restart, so a subscriber resumes from its cursor without missing anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub seq: u64,
    pub at: u64,
    pub job: JobId,
    pub match_id: MatchId,
    pub family: Family,
    pub state: JobState,
}
