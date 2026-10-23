//! Asynchronous cryptographic finality for the real-time simulation.
//!
//! Gameplay never waits for this. Public play needs no commit-reveal: inputs are streamed in the
//! clear, and each submitter later signs the exact input batch it played for an epoch
//! (`collect`). Every signer replays the admitted set independently, signs the checkpoint, and
//! the session's certification policy decides when enough matching signatures exist
//! (`certify`); a disagreement yields portable fraud evidence. Commit-lock-reveal is optional
//! and only for sealed windows, where one participant really does hold secret information the
//! others must not see yet (`sealed`).
mod answers;
mod certify;
mod collect;
mod config;
mod resume;
mod sealed;

pub use config::{
    OwnInputs, PeerEvent, PipeEvent, PipelineConfig, SealError, SealPolicy, Suspicion,
    SuspicionKind, Violation, ViolationKind,
};

use super::auditor::{AuditEvent, Auditor};
use super::msg::{Outgoing, PipeMsg};
use crate::{MatchReplica, SignedCheckpoint, StateMachine};
use answers::ReplicaAnswers;
use certify::Stage;
use collect::Collect;
use gv_core::{MatchId, ParticipantId, Session};
use gv_sig::SigningKey;
use sealed::Sealed;
use std::collections::VecDeque;

/// An outbound message and what must be committed before it may leave: a witness quorum must
/// hold a head covering log position `seq` at tick `tick` (see [`Auditor::enable_witness_quorum`]).
struct Stamped {
    out: Outgoing,
    tick: u64,
    seq: u64,
}

pub struct Pipeline<R: StateMachine + Clone> {
    key: SigningKey,
    me: ParticipantId,
    session: Session,
    rules: R,
    replica: MatchReplica<R>,
    cfg: PipelineConfig,
    collect: Collect,
    stage: Stage,
    early_ckpt: Vec<SignedCheckpoint>,
    cheat_pending: bool,
    sealed: Sealed,
    outbox: VecDeque<Stamped>,
    clock: u64,
    events: VecDeque<PipeEvent>,
    reported_inputs: Vec<(u64, ParticipantId)>,
    auditor: Auditor,
    epoch_done: bool,
    last_peer_checkpoint: Option<SignedCheckpoint>,
    resume: resume::ResumeState,
    /// Ticks below this were signed by an earlier process of this identity.
    signed_floor: u64,
    /// Batches an earlier process of this identity signed, sent again as their epoch comes up.
    restorable: Vec<gv_codec::SignedEventBatch>,
}

impl<R: StateMachine + Clone> Pipeline<R> {
    /// `None` unless `key` belongs to a roster member that signs checkpoints and the
    /// configuration is within the protocol's limits.
    pub fn new(key: SigningKey, replica: MatchReplica<R>, cfg: PipelineConfig) -> Option<Self> {
        let me = key.id();
        let session = replica.session.clone();
        let signs = session.roster.find(&me).is_some_and(|p| p.role.signs());
        let limit = crate::checkpoint::MAX_EPOCH_TICKS;
        let sane = cfg.epoch_ticks > 0
            && cfg.epoch_ticks <= limit
            && cfg.max_window >= cfg.epoch_ticks
            && cfg.max_window <= limit
            && cfg.idle_input.len() <= gv_codec::MAX_HELD_WIDTH;
        if !signs || !sane {
            return None;
        }
        let rules = replica.rules.clone();
        let auditor = Auditor::new(
            key.clone(),
            &session.roster,
            session.match_id,
            rules.ruleset_hash(),
        )?;
        Some(Self {
            key,
            me,
            collect: Collect::new(session.roster.len()),
            session,
            rules,
            replica: replica.live(),
            cfg,
            stage: Stage::Collect,
            early_ckpt: Vec::new(),
            cheat_pending: false,
            sealed: Sealed::default(),
            outbox: VecDeque::new(),
            clock: 0,
            events: VecDeque::new(),
            reported_inputs: Vec::new(),
            auditor,
            epoch_done: false,
            last_peer_checkpoint: None,
            resume: resume::ResumeState::new(0),
            signed_floor: 0,
            restorable: Vec::new(),
        })
    }
    /// The durable per-storage open counter: a larger one supersedes an older process of the
    /// same identity. Set once, right after construction.
    pub fn set_incarnation(&mut self, incarnation: u64) {
        self.resume.incarnation = incarnation;
    }
    /// Never sign a batch for a window that starts below `tick`: an earlier process already
    /// released signed inputs there, and signing other inputs for the same ticks is equivocation.
    pub fn forbid_signing_below(&mut self, tick: u64) {
        self.signed_floor = self.signed_floor.max(tick);
    }
    pub fn verified_tick(&self) -> u64 {
        self.replica.next_tick()
    }
    pub fn verified_state(&self) -> &[u8] {
        self.replica.state()
    }
    pub fn replica(&self) -> &MatchReplica<R> {
        &self.replica
    }
    pub fn session(&self) -> &Session {
        &self.session
    }
    /// Keep only the newest `PipelineConfig::sync_history_epochs` accepted epochs in memory
    /// (see [`MatchReplica::prune_accepted`]); the durable record is the receipt archive.
    pub fn prune_history(&mut self) {
        self.replica.prune_accepted(self.cfg.sync_history_epochs);
    }
    /// Next message to send. Nothing leaves before the write-ahead barrier: every log entry and
    /// signed head this participant has produced is durable first (`Auditor::make_durable`).
    /// A failing store withholds messages (fail closed) and is retried; play is unaffected.
    /// In witnessed mode a signed message also waits for the quorum-committed head that covers it
    /// (the release gate); messages that sign nothing new pass it.
    pub fn poll_outbox(&mut self) -> Option<Outgoing> {
        if self.outbox.is_empty() || !self.auditor.make_durable() {
            return None;
        }
        let i = self
            .outbox
            .iter()
            .position(|s| self.auditor.release_covers(s.tick, s.seq))?;
        self.outbox.remove(i).map(|s| s.out)
    }
    /// Queue a signed message behind the release gate.
    fn enqueue(&mut self, out: Outgoing) {
        let (tick, seq) = (self.clock, self.auditor.log_len());
        self.auditor.want_cover(tick, seq);
        self.outbox.push_back(Stamped { out, tick, seq });
    }
    pub fn poll_event(&mut self) -> Option<PipeEvent> {
        self.events.pop_front()
    }
    pub fn last_peer_checkpoint(&self) -> Option<&SignedCheckpoint> {
        self.last_peer_checkpoint.as_ref()
    }
    pub fn match_id(&self) -> MatchId {
        self.session.match_id
    }
    pub fn auditor(&self) -> &Auditor {
        &self.auditor
    }
    pub fn auditor_mut(&mut self) -> &mut Auditor {
        &mut self.auditor
    }
    /// The next signed checkpoint claim will be false (test/demo of fraud proofs).
    pub fn inject_cheat(&mut self) {
        self.cheat_pending = true;
    }
    fn fault(&mut self, msg: impl Into<String>) {
        self.events.push_back(PipeEvent::Fault(msg.into()));
    }

    // ---- entry points -----------------------------------------------------------

    /// Call after every simulated tick (`now` = number of ticks simulated).
    pub fn tick(&mut self, now: u64, own: OwnInputs<'_>) {
        self.clock = self.clock.max(now);
        self.restore_due();
        self.propose_or_respond(now, own);
        self.drive_sealed(now, own);
        self.drain_future(now, own);
        self.maybe_close(now);
        self.expire_grace(now);
        if std::mem::take(&mut self.epoch_done) {
            self.auditor.on_epoch(now);
        }
        self.auditor.tick(now);
        self.pump_audit();
    }
    fn pump_audit(&mut self) {
        while let Some(m) = self.auditor.poll_msg() {
            self.outbox.push_back(Stamped {
                out: m,
                tick: 0,
                seq: 0,
            });
        }
        while let Some(e) = self.auditor.poll_event() {
            if let AuditEvent::ProvenEquivocation {
                accused, evidence, ..
            } = &e
            {
                self.events.push_back(PipeEvent::Violation(Violation {
                    kind: ViolationKind::LogEquivocation,
                    accused: *accused,
                    tick: self.replica.next_tick(),
                    evidence: evidence.clone(),
                }));
            }
            self.events.push_back(PipeEvent::Audit(e));
        }
    }
    /// A message from `from`, whose identity the transport has authenticated.
    pub fn on_message(&mut self, from: ParticipantId, msg: PipeMsg, now: u64, own: OwnInputs<'_>) {
        self.clock = self.clock.max(now);
        match msg {
            PipeMsg::Batch(b) => {
                self.note_peer_ahead(from, b.record.start_tick, now);
                self.accept_batch(b, now, own);
            }
            PipeMsg::Checkpoint(c) => {
                self.note_peer_ahead(from, c.claim.epoch_start, now);
                self.on_checkpoint(c, now);
            }
            PipeMsg::Close(c) => self.on_close(from, c, now),
            PipeMsg::Seal(s) => self.on_seal(from, s, now),
            PipeMsg::Resume(r) => self.on_resume(from, r),
            sealed @ (PipeMsg::Commit(_) | PipeMsg::Lock { .. } | PipeMsg::Reveal(_)) => {
                self.on_sealed_msg(from, sealed);
            }
            audit @ (PipeMsg::Auth(_)
            | PipeMsg::Challenge(_)
            | PipeMsg::Response(_)
            | PipeMsg::Evidence(_)
            | PipeMsg::AnchorReq
            | PipeMsg::Anchor(_)
            | PipeMsg::Quorum(_)) => {
                let src = ReplicaAnswers {
                    replica: &self.replica,
                    rules: &self.rules,
                    session: &self.session,
                    sealed: &self.sealed,
                    me: self.me,
                };
                self.auditor.on_msg(from, audit, now, &src);
            }
        }
        self.tick(now, own);
    }
}
