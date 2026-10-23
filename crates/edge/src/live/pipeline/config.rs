//! Configuration, events and error types of the live pipeline.
use crate::live::auditor::AuditEvent;
use gv_core::{Digest, ParticipantId};

/// Own input history provider: `own(from, to)` = the held input played on each tick of
/// `[from, to)`, one byte string of constant width per tick.
pub type OwnInputs<'a> = &'a dyn Fn(u64, u64) -> Option<Vec<Vec<u8>>>;

/// Optional sealed-window policy. A participant may keep its inputs secret for a fixed window
/// (commit, lock, reveal after the window). Without a policy no window can be requested and the
/// message kinds that carry one are rejected.
#[derive(Clone, Debug)]
pub struct SealPolicy {
    /// Window length in ticks (rounded up to whole epochs).
    pub ticks: u32,
    /// How far ahead of the current tick a window is scheduled.
    pub lead_ticks: u32,
    /// Minimum ticks between the end of one window and the next request; 0 disables it.
    pub cooldown_ticks: u64,
    /// After the window, the owner has this long to reveal before it is suspicious.
    pub reveal_timeout_ticks: u64,
}
impl Default for SealPolicy {
    fn default() -> Self {
        Self {
            ticks: 300,
            lead_ticks: 30,
            cooldown_ticks: 600,
            reveal_timeout_ticks: 1200,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PipelineConfig {
    /// Epoch grid. 20 ticks at 60 Hz = 333 ms of play per checkpoint.
    pub epoch_ticks: u32,
    /// Longest span certified at once (also forces a periodic idle cut).
    pub max_window: u32,
    /// The held input that means "nothing is happening". An epoch in which this participant
    /// only held it is not proposed (it still answers a peer's proposal).
    pub idle_input: Vec<u8>,
    /// After this many ticks without every submitter's batch, the rotating coordinator may close
    /// the epoch with the batches it holds. `None` waits for every submitter indefinitely.
    pub close_after_ticks: Option<u64>,
    /// How long a dropped peer may stay away before the application is told its grace period
    /// ran out. Reporting it is not a verdict.
    pub peer_grace_ticks: u64,
    pub seal: Option<SealPolicy>,
}
impl PipelineConfig {
    pub fn new(idle_input: Vec<u8>) -> Self {
        Self {
            epoch_ticks: 20,
            max_window: 3600,
            idle_input,
            close_after_ticks: None,
            peer_grace_ticks: 1800,
            seal: None,
        }
    }
}

/// Independently verifiable misbehavior: `evidence` convinces any third party offline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViolationKind {
    /// A signed checkpoint that replay proves false.
    FalseCheckpoint,
    /// A signed input the ruleset rejects (neutralized in replay).
    IllegalInput,
    /// Two different signed batches for the same epoch range.
    Equivocation,
    /// Contradictory signed log heads or checkpoints (forked history).
    LogEquivocation,
}

#[derive(Clone, Debug)]
pub struct Violation {
    pub kind: ViolationKind,
    pub accused: ParticipantId,
    pub tick: u64,
    /// Portable artifact (`GV-EVIDENCE/V1` for replay-provable kinds).
    pub evidence: Vec<u8>,
}

/// Something is wrong but no third party could verify it: it depends on timing or on what only
/// the observer saw. Never a basis for a conclusive verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuspicionKind {
    /// The window owner did not open a locked commitment in time.
    WithheldReveal,
    /// An opening that does not match its commitment (the blind is unauthenticated).
    BadReveal,
    /// A submitter did not deliver its batch before the close timeout.
    Unresponsive,
}

#[derive(Clone, Debug)]
pub struct Suspicion {
    pub kind: SuspicionKind,
    pub subject: ParticipantId,
    pub tick: u64,
}

#[derive(Clone, Debug)]
pub enum PipeEvent {
    /// Authoritative (signed) inputs from a participant: roll the timeline back.
    RemoteInputs {
        participant: ParticipantId,
        from_tick: u64,
        inputs: Vec<Vec<u8>>,
    },
    /// An epoch became the verified chain head.
    Finalized {
        start: u64,
        end: u64,
        checkpoint: Digest,
        state: Vec<u8>,
        /// Closed by fraud evidence instead of a satisfied certification policy.
        disputed: bool,
        sealed: bool,
    },
    Violation(Violation),
    Suspicion(Suspicion),
    SealScheduled {
        owner: ParticipantId,
        start: u64,
        end: u64,
    },
    /// Every sealed epoch was revealed and certified.
    SealRevealed {
        owner: ParticipantId,
    },
    /// Accountability progress (challenge state changes, rejected accusations).
    Audit(AuditEvent),
    /// Reconnection progress of a single peer.
    Peer(PeerEvent),
    /// A protocol problem that is not proof of cheating (transport, ordering).
    Fault(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerEvent {
    Down {
        peer: ParticipantId,
    },
    /// The peer proved its key and incarnation on the new link.
    Resumed {
        peer: ParticipantId,
        incarnation: u64,
    },
    /// The peer's proof lost against a newer or winning incarnation of the same identity.
    Superseded {
        peer: ParticipantId,
    },
    /// This node caught up to the certified chain at `tick`.
    CaughtUp {
        tick: u64,
    },
    /// The peer stayed away for the whole grace period (never a proof of misbehavior).
    GraceExpired {
        peer: ParticipantId,
        since: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The session configured no sealed-window policy.
    Disabled,
    /// This participant does not submit inputs.
    NotSubmitter,
    Busy,
    Cooldown {
        until: u64,
    },
}
