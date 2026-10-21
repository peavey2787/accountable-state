//! Asynchronous cryptographic finality for the 60 Hz simulation.
//!
//! Gameplay never waits for this. Public play needs no commit-reveal: inputs
//! are streamed in the clear, and each player later signs the exact input batch
//! they played for an epoch. Both replay it independently, co-sign the
//! resulting checkpoint, and a disagreement yields portable fraud evidence.
//! Commit-lock-reveal is kept only for the hidden window, where one player
//! really does hold secret information the other must not see yet.
//!
//! Epoch agreement without negotiation rounds: only a player with something to
//! certify proposes an epoch end; the other answers with the same end. If both
//! propose, the shorter end wins and the longer proposer answers with the
//! (identical-prefix) shorter batch. Nobody signs a longer end after a shorter.
use super::auditor::{Answers, AuditEvent, Auditor};
use super::msg::{Opening, PipeMsg, SignedHide};
use crate::{
    verify_checkpoint_evidence_with, BatchCommitment, BilateralAdmission, CheckpointEvidence,
    EdgeError, EvidenceVerdict, InputViolation, MatchReplica, PublicRules, SignedBatchCommitment,
    SignedCheckpoint, SignedEpochLock,
};
use gv_codec::{ControlChange, PackedControls, SignedPackedControls};
use gv_core::{Digest, MatchId, PlayerId};
use gv_sig::SigningKey;
use std::collections::VecDeque;

/// Own input history provider: `own(from, to)` = controls played for `[from, to)`.
pub type OwnInputs<'a> = &'a dyn Fn(u64, u64) -> Option<Vec<u16>>;

#[derive(Clone, Debug)]
pub struct PipelineConfig {
    /// Epoch grid. 20 ticks = 333 ms of play per checkpoint.
    pub epoch_ticks: u32,
    /// Longest span certified at once (also forces a periodic idle cut).
    pub max_window: u32,
    /// Hidden window length in ticks (rounded up to whole epochs).
    pub hide_ticks: u32,
    /// How far ahead of the current tick a hide is scheduled.
    pub hide_lead_ticks: u32,
    pub hide_cooldown_ticks: u64,
    /// After the window, the hider has this long to reveal before it is a fault.
    pub reveal_timeout_ticks: u64,
}
impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            epoch_ticks: 20,
            max_window: 3600,
            hide_ticks: 300,
            hide_lead_ticks: 30,
            hide_cooldown_ticks: 600,
            reveal_timeout_ticks: 1200,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViolationKind {
    /// A signed checkpoint that replay proves false.
    FalseCheckpoint,
    /// A signed input the ruleset rejects (neutralized in replay).
    IllegalInput,
    /// A revealed batch that does not match the signed commitment.
    BadReveal,
    /// Two different signed batches for the same epoch range.
    Equivocation,
    /// Contradictory signed log heads or checkpoints (forked history).
    LogEquivocation,
    /// The hider never opened a locked commitment.
    WithheldReveal,
}

#[derive(Clone, Debug)]
pub struct Violation {
    pub kind: ViolationKind,
    pub accused: PlayerId,
    pub tick: u64,
    /// Portable artifact (`GV-EVIDENCE/V1` for replay-provable kinds).
    pub evidence: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum PipeEvent {
    /// Authoritative (signed) controls from the opponent: roll the timeline back.
    RemoteInputs {
        from_tick: u64,
        controls: Vec<u16>,
    },
    /// An epoch became the verified chain head.
    Finalized {
        start: u64,
        end: u64,
        checkpoint: Digest,
        state: Vec<u8>,
        /// Closed by fraud evidence instead of two matching signatures.
        disputed: bool,
        hidden: bool,
    },
    Violation(Violation),
    HideScheduled {
        hider: PlayerId,
        start: u64,
        end: u64,
    },
    /// All hidden epochs were revealed and certified.
    HideRevealed {
        hider: PlayerId,
    },
    /// Accountability progress (challenge state changes, rejected accusations).
    Audit(AuditEvent),
    /// A protocol problem that is not proof of cheating (transport, ordering).
    Fault(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HideError {
    Busy,
    Cooldown { until: u64 },
}

struct Paired {
    start: u64,
    end: u64,
    hidden: bool,
    checkpoint: crate::Checkpoint,
    honest_sig: SignedCheckpoint,
    /// What we actually sent (differs only when a cheat was injected).
    sent: SignedCheckpoint,
    batches: [SignedPackedControls; 2],
    previous_state: Vec<u8>,
}

struct Cell {
    start: u64,
    end: u64,
    mine: Option<SignedPackedControls>,
    adm: Option<BilateralAdmission>,
    their_commit: Option<SignedBatchCommitment>,
    their_lock: Option<SignedEpochLock>,
    their_lock_seen: bool,
    their_reveal: Option<Opening>,
    /// Secret blinding factor of my commitment (CSPRNG; revealed only with the opening).
    blind: [u8; 32],
    my_commit_sent: bool,
    my_lock_sent: bool,
    my_reveal_sent: bool,
    reveal_ready: bool,
    done: bool,
}

struct Hide {
    hider: PlayerId,
    start: u64,
    end: u64,
    cells: Vec<Cell>,
    anchor: Option<Digest>,
    /// My latest batch digest inside the window (chain head for the next cell).
    my_head: Option<Digest>,
    reveal_deadline: u64,
    withheld_reported: bool,
    revealed_all: bool,
}

enum Stage {
    Collect,
    Paired(Box<Paired>),
}

pub struct Pipeline<R: PublicRules + Clone> {
    key: SigningKey,
    me: PlayerId,
    other: PlayerId,
    roster: [PlayerId; 2],
    match_id: MatchId,
    rules: R,
    replica: MatchReplica<R>,
    cfg: PipelineConfig,
    mine: Vec<SignedPackedControls>,
    theirs: Vec<SignedPackedControls>,
    future: Vec<SignedPackedControls>,
    owed: Option<u64>,
    stage: Stage,
    early_ckpt: Vec<SignedCheckpoint>,
    cheat_pending: bool,
    hide: Option<Hide>,
    hide_cooldown_until: u64,
    outbox: VecDeque<PipeMsg>,
    events: VecDeque<PipeEvent>,
    reported_inputs: Vec<(u64, PlayerId)>,
    auditor: Auditor,
    epoch_done: bool,
    last_peer_checkpoint: Option<SignedCheckpoint>,
}

fn controls_of(batch: &SignedPackedControls) -> Vec<u16> {
    (0..batch.record.tick_count)
        .map(|k| batch.record.state_at(k).unwrap_or(0))
        .collect()
}

fn pack(
    match_id: MatchId,
    player: PlayerId,
    head: Digest,
    start: u64,
    controls: &[u16],
    key: &SigningKey,
) -> Option<SignedPackedControls> {
    let initial_state = *controls.first()?;
    let mut changes = Vec::new();
    let mut previous = initial_state;
    for (k, c) in controls.iter().enumerate().skip(1) {
        if *c != previous {
            changes.push(ControlChange {
                offset: k as u32,
                state: *c,
            });
            previous = *c;
        }
    }
    let record = PackedControls {
        match_id,
        player,
        previous_batch_hash: head,
        start_tick: start,
        tick_count: controls.len() as u32,
        control_bytes: 1,
        initial_state,
        changes,
    };
    SignedPackedControls::sign(record, key).ok()
}

impl<R: PublicRules + Clone> Pipeline<R> {
    pub fn new(
        key: SigningKey,
        roster: [PlayerId; 2],
        match_id: MatchId,
        rules: R,
        replica: MatchReplica<R>,
        cfg: PipelineConfig,
    ) -> Option<Self> {
        let me = key.id();
        let other = roster.iter().copied().find(|p| *p != me)?;
        if !roster.contains(&me) {
            return None;
        }
        let auditor = Auditor::new(key.clone(), roster, match_id, rules.ruleset_hash())?;
        Some(Self {
            key,
            me,
            other,
            roster,
            match_id,
            rules,
            replica: replica.live(),
            cfg,
            mine: Vec::new(),
            theirs: Vec::new(),
            future: Vec::new(),
            owed: None,
            stage: Stage::Collect,
            early_ckpt: Vec::new(),
            cheat_pending: false,
            hide: None,
            hide_cooldown_until: 0,
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            reported_inputs: Vec::new(),
            auditor,
            epoch_done: false,
            last_peer_checkpoint: None,
        })
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
    /// Keep only the newest `keep` accepted epochs in memory (see
    /// [`MatchReplica::prune_accepted`]).
    pub fn prune_history(&mut self, keep: usize) {
        self.replica.prune_accepted(keep);
    }
    /// Next message to send. Nothing leaves before the write-ahead barrier: every log entry and
    /// signed head this participant has produced is durable first (`Auditor::make_durable`).
    /// A failing store withholds messages (fail closed) and is retried; play is unaffected.
    pub fn poll_outbox(&mut self) -> Option<PipeMsg> {
        if self.outbox.is_empty() || !self.auditor.make_durable() {
            return None;
        }
        self.outbox.pop_front()
    }
    pub fn poll_event(&mut self) -> Option<PipeEvent> {
        self.events.pop_front()
    }
    /// The next signed checkpoint claim will be false (test/demo of fraud proofs).
    pub fn last_peer_checkpoint(&self) -> Option<&SignedCheckpoint> {
        self.last_peer_checkpoint.as_ref()
    }
    pub fn match_id(&self) -> MatchId {
        self.match_id
    }
    pub fn auditor(&self) -> &Auditor {
        &self.auditor
    }
    pub fn auditor_mut(&mut self) -> &mut Auditor {
        &mut self.auditor
    }
    pub fn inject_cheat(&mut self) {
        self.cheat_pending = true;
    }
    pub fn hide_window(&self) -> Option<(PlayerId, u64, u64)> {
        self.hide.as_ref().map(|h| (h.hider, h.start, h.end))
    }
    pub fn hide_cooldown_until(&self) -> u64 {
        self.hide_cooldown_until
    }

    // ---- public-play epochs -------------------------------------------------

    fn ws(&self) -> u64 {
        self.replica.next_tick()
    }
    fn min_mine_end(&self) -> Option<u64> {
        self.mine
            .iter()
            .map(|b| b.record.start_tick + u64::from(b.record.tick_count))
            .min()
    }
    fn end_of(b: &SignedPackedControls) -> u64 {
        b.record.start_tick + u64::from(b.record.tick_count)
    }
    fn hide_cut(&self) -> Option<u64> {
        let ws = self.ws();
        self.hide.as_ref().filter(|h| ws < h.start).map(|h| h.start)
    }
    fn in_hidden_window(&self) -> bool {
        let ws = self.ws();
        self.hide
            .as_ref()
            .is_some_and(|h| ws >= h.start && ws < h.end)
    }
    fn sign_batch(&mut self, end: u64, own: OwnInputs<'_>) -> Option<SignedPackedControls> {
        if self.auditor.persistence_failed() {
            return None; // fail closed: sign nothing new while the write-ahead store fails
        }
        let ws = self.ws();
        let head = self.replica.next_batch_head(self.me)?;
        let controls = own(ws, end)?;
        let b = pack(self.match_id, self.me, head, ws, &controls, &self.key)?;
        self.mine.push(b.clone());
        self.auditor.record_my_batch(&b);
        Some(b)
    }
    fn propose_or_respond(&mut self, now: u64, own: OwnInputs<'_>) {
        if !matches!(self.stage, Stage::Collect) || self.in_hidden_window() {
            return;
        }
        let ws = self.ws();
        // Owed answer to an earlier opponent proposal.
        if let Some(e) = self.owed {
            if now >= e {
                self.owed = None;
                if self.mine.is_empty() || Some(e) <= self.min_mine_end() {
                    self.respond(e, own);
                    // The answer may complete a pair that is already waiting.
                    self.try_pair();
                }
            }
        }
        if !self.mine.is_empty() || !self.theirs.is_empty() {
            return;
        }
        let cut = self.hide_cut();
        let grid = u64::from(self.cfg.epoch_ticks);
        let mut end = (now / grid) * grid;
        if let Some(h0) = cut {
            if now >= h0 {
                end = h0;
            }
        }
        if end <= ws {
            return;
        }
        let forced = cut.is_some_and(|h0| end == h0) || end - ws >= u64::from(self.cfg.max_window);
        let end = end.min(ws + u64::from(self.cfg.max_window));
        let active =
            forced || self.cheat_pending || own(ws, end).is_some_and(|c| c.iter().any(|x| *x != 0));
        if !active {
            return;
        }
        if let Some(b) = self.sign_batch(end, own) {
            self.outbox.push_back(PipeMsg::Batch(b));
            self.try_pair();
        }
    }
    fn respond(&mut self, end: u64, own: OwnInputs<'_>) {
        if self.mine.iter().any(|b| Self::end_of(b) == end) {
            return;
        }
        if let Some(b) = self.sign_batch(end, own) {
            self.outbox.push_back(PipeMsg::Batch(b));
        }
    }
    fn accept_batch(&mut self, b: SignedPackedControls, now: u64, own: OwnInputs<'_>) {
        let ws = self.ws();
        if b.verify().is_err()
            || b.record.player != self.other
            || b.record.match_id != self.match_id
            || b.record.tick_count == 0
            || b.record.tick_count > self.cfg.max_window
        {
            self.events
                .push_back(PipeEvent::Fault("rejected malformed batch".into()));
            return;
        }
        self.auditor.observe_batch(&b);
        if b.record.start_tick < ws {
            return;
        }
        if b.record.start_tick > ws {
            if self.future.len() < 64 {
                self.future.push(b);
            }
            return;
        }
        if self.replica.next_batch_head(self.other) != Some(b.record.previous_batch_hash) {
            self.events
                .push_back(PipeEvent::Fault("batch does not extend their chain".into()));
            return;
        }
        if self.in_hidden_window() {
            self.events
                .push_back(PipeEvent::Fault("public batch inside hidden window".into()));
            return;
        }
        let end = Self::end_of(&b);
        if let Some(existing) = self.theirs.iter().find(|t| Self::end_of(t) == end) {
            if existing.digest().ok() != b.digest().ok() {
                let mut evidence = Vec::new();
                for x in [existing, &b] {
                    if let Ok(bytes) = x.encode() {
                        evidence.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                        evidence.extend_from_slice(&bytes);
                    }
                }
                self.events.push_back(PipeEvent::Violation(Violation {
                    kind: ViolationKind::Equivocation,
                    accused: self.other,
                    tick: ws,
                    evidence,
                }));
            }
            return;
        }
        self.events.push_back(PipeEvent::RemoteInputs {
            from_tick: ws,
            controls: controls_of(&b),
        });
        self.theirs.push(b);
        if matches!(self.stage, Stage::Collect) {
            // Never sign across the start of a hidden window: answer with the
            // identical-prefix batch that stops at it.
            let answer = self.hide_cut().map_or(end, |h0| end.min(h0));
            if self.mine.is_empty() || Some(answer) <= self.min_mine_end() {
                if now >= answer {
                    self.respond(answer, own);
                } else {
                    self.owed = Some(answer);
                }
            }
            self.try_pair();
        }
    }
    fn try_pair(&mut self) {
        if !matches!(self.stage, Stage::Collect) {
            return;
        }
        let common = self
            .mine
            .iter()
            .map(Self::end_of)
            .filter(|e| self.theirs.iter().any(|t| Self::end_of(t) == *e))
            .min();
        let Some(end) = common else { return };
        let (Some(mine), Some(theirs)) = (
            self.mine.iter().find(|b| Self::end_of(b) == end).cloned(),
            self.theirs.iter().find(|b| Self::end_of(b) == end).cloned(),
        ) else {
            return;
        };
        self.pair(mine, theirs, false);
    }
    fn pair(&mut self, mine: SignedPackedControls, theirs: SignedPackedControls, hidden: bool) {
        let start = self.ws();
        let end = Self::end_of(&mine);
        let previous_state = self.replica.state().to_vec();
        for b in [mine.clone(), theirs.clone()] {
            if let Err(e) = self.replica.admit(b) {
                self.events
                    .push_back(PipeEvent::Fault(format!("admit failed: {e:?}")));
                return;
            }
        }
        let (epoch, violations) = match self.replica.candidate_with_violations() {
            Ok(x) => x,
            Err(e) => {
                self.events
                    .push_back(PipeEvent::Fault(format!("replay failed: {e:?}")));
                return;
            }
        };
        let batches = epoch.batches.clone();
        for v in violations {
            self.report_illegal_input(&v, &epoch.checkpoint, &batches, &previous_state);
        }
        let honest_sig = SignedCheckpoint::sign(epoch.checkpoint.clone(), &self.key);
        let sent = if std::mem::take(&mut self.cheat_pending) {
            let mut lie = epoch.checkpoint.clone();
            lie.next_state = [0xa5; 32];
            SignedCheckpoint::sign(lie, &self.key)
        } else {
            honest_sig.clone()
        };
        self.auditor.record_my_checkpoint(&sent);
        self.outbox.push_back(PipeMsg::Checkpoint(sent.clone()));
        self.stage = Stage::Paired(Box::new(Paired {
            start,
            end,
            hidden,
            checkpoint: epoch.checkpoint,
            honest_sig,
            sent,
            batches,
            previous_state,
        }));
        let early = std::mem::take(&mut self.early_ckpt);
        for sig in early {
            self.on_checkpoint(sig);
        }
    }
    fn evidence(
        &self,
        accused: SignedCheckpoint,
        p_start_state: &[u8],
        batches: &[SignedPackedControls; 2],
    ) -> CheckpointEvidence {
        CheckpointEvidence {
            trusted_previous_checkpoint: self.replica.previous_checkpoint(),
            trusted_previous_state: accused.claim.previous_state,
            accused,
            previous_state: p_start_state.to_vec(),
            player_batches: batches.clone(),
            roster: self.roster,
        }
    }
    fn report_illegal_input(
        &mut self,
        v: &InputViolation,
        checkpoint: &crate::Checkpoint,
        batches: &[SignedPackedControls; 2],
        previous_state: &[u8],
    ) {
        if self.reported_inputs.contains(&(v.tick, v.player)) {
            return;
        }
        self.reported_inputs.push((v.tick, v.player));
        // Honest claim signed by us binds the exact input set; the offending
        // signed control is inside `batches`.
        let honest = SignedCheckpoint::sign(checkpoint.clone(), &self.key);
        let evidence = self
            .evidence(honest, previous_state, batches)
            .encode()
            .unwrap_or_default();
        self.events.push_back(PipeEvent::Violation(Violation {
            kind: ViolationKind::IllegalInput,
            accused: v.player,
            tick: v.tick,
            evidence,
        }));
    }
    fn on_checkpoint(&mut self, sig: SignedCheckpoint) {
        if sig.verify().is_err() || sig.player != self.other {
            self.events
                .push_back(PipeEvent::Fault("bad checkpoint signature".into()));
            return;
        }
        self.auditor.observe_checkpoint(&sig);
        self.last_peer_checkpoint = Some(sig.clone());
        let Stage::Paired(p) = &self.stage else {
            if self.early_ckpt.len() < 16 {
                self.early_ckpt.push(sig);
            }
            return;
        };
        if sig.claim.epoch_start != p.start || u64::from(sig.claim.epoch_length) != p.end - p.start
        {
            if sig.claim.epoch_start >= p.end && self.early_ckpt.len() < 16 {
                self.early_ckpt.push(sig);
            }
            return;
        }
        let Stage::Paired(p) = std::mem::replace(&mut self.stage, Stage::Collect) else {
            return;
        };
        let p = *p;
        let their_true = sig.claim == p.checkpoint;
        let mine_true = p.sent.claim == p.checkpoint;
        let (start, end, hidden) = (p.start, p.end, p.hidden);
        let disputed;
        if their_true && mine_true {
            let mut sigs = [p.honest_sig.clone(), sig];
            sigs.sort_by_key(|s| s.player);
            match self.replica.finalize(sigs) {
                Ok(_) => disputed = false,
                Err(e) => {
                    self.events
                        .push_back(PipeEvent::Fault(format!("finalize failed: {e:?}")));
                    return;
                }
            }
        } else {
            // Exactly one false claim (or both). Evidence is checked against an
            // independent replay before anyone is accused.
            let mut accused = Vec::new();
            if !their_true {
                accused.push(sig.clone());
            }
            if !mine_true {
                accused.push(p.sent.clone());
            }
            for lie in accused {
                let who = lie.player;
                let ev = self.evidence(lie, &p.previous_state, &p.batches);
                match verify_checkpoint_evidence_with(&self.rules, &ev, true) {
                    EvidenceVerdict::ProvenInvalidState => {
                        self.events.push_back(PipeEvent::Violation(Violation {
                            kind: ViolationKind::FalseCheckpoint,
                            accused: who,
                            tick: start,
                            evidence: ev.encode().unwrap_or_default(),
                        }));
                    }
                    other => self.events.push_back(PipeEvent::Fault(format!(
                        "disputed claim not proven: {other:?}"
                    ))),
                }
            }
            if let Err(e) = self.replica.finalize_disputed() {
                self.events
                    .push_back(PipeEvent::Fault(format!("dispute close failed: {e:?}")));
                return;
            }
            disputed = true;
        }
        self.mine.clear();
        self.theirs.clear();
        self.owed = None;
        self.events.push_back(PipeEvent::Finalized {
            start,
            end,
            checkpoint: self.replica.previous_checkpoint(),
            state: self.replica.state().to_vec(),
            disputed,
            hidden,
        });
        self.stage = Stage::Collect;
        self.epoch_done = true;
    }

    // ---- hidden window (commit-lock-reveal) --------------------------------

    /// Hide my location for `cfg.hide_ticks`, starting at the next epoch edge.
    pub fn request_hide(&mut self, now: u64) -> Result<(), HideError> {
        if self.hide.is_some() {
            return Err(HideError::Busy);
        }
        if now < self.hide_cooldown_until {
            return Err(HideError::Cooldown {
                until: self.hide_cooldown_until,
            });
        }
        let grid = u64::from(self.cfg.epoch_ticks);
        let start = (now + u64::from(self.cfg.hide_lead_ticks)).div_ceil(grid) * grid;
        let ticks = (self.cfg.hide_ticks).div_ceil(self.cfg.epoch_ticks) * self.cfg.epoch_ticks;
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&now.to_le_bytes());
        nonce[8..].copy_from_slice(&start.to_le_bytes());
        let msg = SignedHide::sign(self.match_id, start, ticks, nonce, &self.key);
        self.begin_hide(&msg);
        self.outbox.push_back(PipeMsg::Hide(msg));
        Ok(())
    }
    fn begin_hide(&mut self, msg: &SignedHide) {
        let grid = u64::from(self.cfg.epoch_ticks);
        let end = msg.start_tick + u64::from(msg.ticks);
        let cells = (0..u64::from(msg.ticks) / grid)
            .map(|k| Cell {
                start: msg.start_tick + k * grid,
                end: msg.start_tick + (k + 1) * grid,
                mine: None,
                adm: None,
                their_commit: None,
                their_lock: None,
                their_lock_seen: false,
                their_reveal: None,
                blind: gv_sig::random_32().unwrap_or([0; 32]),
                my_commit_sent: false,
                my_lock_sent: false,
                my_reveal_sent: false,
                reveal_ready: false,
                done: false,
            })
            .collect();
        self.hide = Some(Hide {
            hider: msg.player,
            start: msg.start_tick,
            end,
            cells,
            anchor: None,
            my_head: None,
            reveal_deadline: end + self.cfg.reveal_timeout_ticks,
            withheld_reported: false,
            revealed_all: false,
        });
        self.events.push_back(PipeEvent::HideScheduled {
            hider: msg.player,
            start: msg.start_tick,
            end,
        });
    }
    fn on_hide(&mut self, msg: SignedHide) {
        let ws = self.ws();
        let grid = u64::from(self.cfg.epoch_ticks);
        let valid = msg.verify().is_ok()
            && msg.player == self.other
            && msg.match_id == self.match_id
            && self.hide.is_none()
            && msg.start_tick >= ws
            && msg.start_tick % grid == 0
            && msg.ticks > 0
            && msg.ticks % self.cfg.epoch_ticks == 0
            && msg.ticks <= self.cfg.hide_ticks + self.cfg.epoch_ticks;
        if !valid {
            self.events
                .push_back(PipeEvent::Fault("hide announcement rejected".into()));
            return;
        }
        self.begin_hide(&msg);
    }
    fn drive_hidden(&mut self, now: u64, own: OwnInputs<'_>) {
        let Some(mut h) = self.hide.take() else {
            return;
        };
        let i_hide = h.hider == self.me;
        // The pre-hide epoch must be certified before the anchor exists.
        if h.anchor.is_none() && self.ws() == h.start {
            h.anchor = Some(self.replica.previous_checkpoint());
            h.my_head = self.replica.next_batch_head(self.me);
        }
        let ruleset = self.rules.ruleset_hash();
        if let Some(anchor) = h.anchor {
            for k in 0..h.cells.len() {
                let (start, end) = (h.cells[k].start, h.cells[k].end);
                // 1. my signed batch + commitment once the cell has been played
                if h.cells[k].mine.is_none()
                    && now >= end
                    && (k == 0 || h.cells[k - 1].mine.is_some())
                {
                    if let (Some(head), Some(controls)) = (h.my_head, own(start, end)) {
                        if let Some(b) =
                            pack(self.match_id, self.me, head, start, &controls, &self.key)
                        {
                            h.my_head = b.digest().ok();
                            h.cells[k].mine = Some(b);
                        }
                    }
                }
                let cell = &mut h.cells[k];
                let Some(mine) = cell.mine.clone() else {
                    continue;
                };
                if cell.adm.is_none() {
                    let Ok(mut adm) = BilateralAdmission::new(
                        self.match_id,
                        ruleset,
                        anchor,
                        self.roster,
                        start,
                        (end - start) as u32,
                    ) else {
                        continue;
                    };
                    let Ok(claim) = BatchCommitment::for_batch(&mine, ruleset, anchor, &cell.blind)
                    else {
                        continue;
                    };
                    let Ok(commit) = SignedBatchCommitment::sign(claim, &self.key) else {
                        continue;
                    };
                    if adm.admit_commit(commit.clone()).is_err() {
                        continue;
                    }
                    self.outbox.push_back(PipeMsg::Commit(commit));
                    cell.my_commit_sent = true;
                    cell.adm = Some(adm);
                }
                if let (Some(adm), Some(c)) = (cell.adm.as_mut(), cell.their_commit.take()) {
                    if adm.admit_commit(c.clone()).is_err() {
                        cell.their_commit = Some(c);
                    }
                }
                // 2. lock once both commitments are known
                if let Some(adm) = cell.adm.as_mut() {
                    if !cell.my_lock_sent {
                        if let Ok(lock) = adm.sign_lock(&self.key) {
                            if adm.admit_lock(lock.clone()).is_ok() {
                                self.outbox.push_back(PipeMsg::Lock(lock));
                                cell.my_lock_sent = true;
                            }
                        }
                    }
                    if let Some(l) = cell.their_lock.take() {
                        if adm.admit_lock(l.clone()).is_err() {
                            cell.their_lock = Some(l);
                        }
                    }
                    cell.reveal_ready = adm.locked();
                }
                // 3. reveal. The observer's inputs were never secret: open at
                // once. The hider opens only after the window ends and every
                // cell is locked, so nothing leaks while the window is live.
                let locked_all = h
                    .cells
                    .iter()
                    .all(|c| c.adm.as_ref().is_some_and(BilateralAdmission::locked));
                let cell = &mut h.cells[k];
                if cell.reveal_ready && !cell.my_reveal_sent {
                    let may = !i_hide || (now >= h.end && locked_all);
                    if may {
                        if let (Some(b), Some(adm)) = (cell.mine.clone(), cell.adm.as_mut()) {
                            // Our own opening counts toward the certified pair too.
                            if adm.admit_reveal(b.clone(), &cell.blind).is_ok() {
                                self.outbox.push_back(PipeMsg::Reveal(Opening {
                                    batch: b,
                                    blind: cell.blind,
                                }));
                                cell.my_reveal_sent = true;
                            }
                        }
                    }
                }
                if let (Some(adm), Some(r)) = (cell.adm.as_mut(), cell.their_reveal.take()) {
                    if cell.reveal_ready {
                        match adm.admit_reveal(r.batch.clone(), &r.blind) {
                            Ok(()) => {
                                self.events.push_back(PipeEvent::RemoteInputs {
                                    from_tick: start,
                                    controls: controls_of(&r.batch),
                                });
                            }
                            Err(_) => {
                                let mut evidence = Vec::new();
                                if let Ok(bytes) = r.batch.encode() {
                                    evidence.extend_from_slice(&bytes);
                                }
                                self.events.push_back(PipeEvent::Violation(Violation {
                                    kind: ViolationKind::BadReveal,
                                    accused: self.other,
                                    tick: start,
                                    evidence,
                                }));
                            }
                        }
                    } else {
                        cell.their_reveal = Some(r);
                    }
                }
            }
            // 4. certify revealed cells strictly in order
            if matches!(self.stage, Stage::Collect) {
                let ws = self.ws();
                if let Some(cell) = h.cells.iter_mut().find(|c| c.start == ws && !c.done) {
                    if let Some(adm) = cell.adm.as_ref() {
                        if let Ok([a, b]) = adm.ordered_reveals() {
                            cell.done = true;
                            let (mine, theirs) = if a.record.player == self.me {
                                (a, b)
                            } else {
                                (b, a)
                            };
                            self.hide = Some(h);
                            self.pair(mine, theirs, true);
                            return;
                        }
                    }
                }
            }
        }
        // 5. window complete / withheld reveal
        if !h.revealed_all
            && h.cells.iter().all(|c| c.done)
            && matches!(self.stage, Stage::Collect)
            && self.ws() >= h.end
        {
            h.revealed_all = true;
            self.hide_cooldown_until = now + self.cfg.hide_cooldown_ticks;
            self.events
                .push_back(PipeEvent::HideRevealed { hider: h.hider });
            self.hide = None;
            return;
        }
        if !h.withheld_reported && now > h.reveal_deadline && !i_hide {
            h.withheld_reported = true;
            self.events.push_back(PipeEvent::Violation(Violation {
                kind: ViolationKind::WithheldReveal,
                accused: h.hider,
                tick: h.end,
                evidence: Vec::new(),
            }));
        }
        self.hide = Some(h);
    }
    fn on_hidden_msg(&mut self, msg: PipeMsg) {
        let Some(h) = self.hide.as_mut() else {
            self.events.push_back(PipeEvent::Fault(
                "hidden-window message with no window".into(),
            ));
            return;
        };
        match msg {
            PipeMsg::Commit(c) => {
                if let Some(cell) = h.cells.iter_mut().find(|x| x.start == c.claim.start_tick) {
                    cell.their_commit = Some(c);
                }
            }
            PipeMsg::Lock(l) => {
                // A lock names no epoch. Both sides send locks in cell order
                // over an ordered channel, so the n-th lock is cell n's.
                if let Some(cell) = h.cells.iter_mut().find(|x| !x.their_lock_seen) {
                    cell.their_lock_seen = true;
                    cell.their_lock = Some(l);
                }
            }
            PipeMsg::Reveal(b) => {
                if let Some(cell) = h
                    .cells
                    .iter_mut()
                    .find(|x| x.start == b.batch.record.start_tick)
                {
                    cell.their_reveal = Some(b);
                }
            }
            _ => {}
        }
    }

    // ---- entry points -----------------------------------------------------

    /// Call after every simulated tick (`now` = number of ticks simulated).
    pub fn tick(&mut self, now: u64, own: OwnInputs<'_>) {
        self.propose_or_respond(now, own);
        self.drive_hidden(now, own);
        let ws = self.ws();
        let ready: Vec<_> = self
            .future
            .iter()
            .filter(|b| b.record.start_tick == ws)
            .cloned()
            .collect();
        if !ready.is_empty() && matches!(self.stage, Stage::Collect) {
            self.future.retain(|b| b.record.start_tick != ws);
            for b in ready {
                self.accept_batch(b, now, own);
            }
        }
        self.future.retain(|b| b.record.start_tick >= ws);
        if std::mem::take(&mut self.epoch_done) {
            self.auditor.on_epoch(now);
        }
        self.auditor.tick(now);
        self.pump_audit();
    }
    fn pump_audit(&mut self) {
        while let Some(m) = self.auditor.poll_msg() {
            self.outbox.push_back(m);
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
    pub fn on_message(&mut self, msg: PipeMsg, now: u64, own: OwnInputs<'_>) {
        match msg {
            PipeMsg::Batch(b) => self.accept_batch(b, now, own),
            PipeMsg::Checkpoint(c) => self.on_checkpoint(c),
            PipeMsg::Hide(h) => self.on_hide(h),
            other @ (PipeMsg::Commit(_) | PipeMsg::Lock(_) | PipeMsg::Reveal(_)) => {
                self.on_hidden_msg(other);
            }
            audit @ (PipeMsg::Auth(_)
            | PipeMsg::Challenge(_)
            | PipeMsg::Response(_)
            | PipeMsg::Evidence(_)
            | PipeMsg::AnchorReq
            | PipeMsg::Anchor(_)) => {
                let src = ReplicaAnswers {
                    replica: &self.replica,
                    rules: &self.rules,
                    roster: self.roster,
                    hide: self.hide.as_ref(),
                    me: self.me,
                };
                self.auditor.on_msg(audit, now, &src);
            }
        }
        self.tick(now, own);
    }
}

impl From<EdgeError> for PipeEvent {
    fn from(e: EdgeError) -> Self {
        PipeEvent::Fault(format!("{e:?}"))
    }
}

/// Answers for challenge kinds that need replica data (replay evidence, Merkle
/// witnesses, hidden reveals).
struct ReplicaAnswers<'a, R: PublicRules + Clone> {
    replica: &'a MatchReplica<R>,
    rules: &'a R,
    roster: [PlayerId; 2],
    hide: Option<&'a Hide>,
    me: PlayerId,
}

impl<R: PublicRules + Clone> ReplicaAnswers<'_, R> {
    fn epoch_at(&self, tick: u64) -> Option<&crate::Epoch> {
        self.replica.accepted().iter().find(|e| {
            e.signatures.is_some()
                && e.checkpoint.epoch_start <= tick
                && tick < e.checkpoint.epoch_start + u64::from(e.checkpoint.epoch_length)
        })
    }
}

impl<R: PublicRules + Clone> Answers for ReplicaAnswers<'_, R> {
    fn answer(&self, c: &crate::audit::Challenge) -> Option<Vec<u8>> {
        use crate::audit::ChallengeKind as K;
        match c.kind {
            K::Replay { epoch_start: t } | K::MerkleWitness { epoch_start: t } => {
                let e = self.epoch_at(t)?;
                crate::CertifiedEpoch::from_accepted(e, self.roster)
                    .ok()?
                    .encode()
                    .ok()
            }
            K::HiddenReveal { start_tick } => {
                let h = self.hide.filter(|h| h.hider == self.me)?;
                let cell = h
                    .cells
                    .iter()
                    .find(|x| x.start == start_tick && x.my_reveal_sent)?;
                PipeMsg::Reveal(Opening {
                    batch: cell.mine.clone()?,
                    blind: cell.blind,
                })
                .encode()
                .ok()
            }
            _ => None,
        }
    }
    fn check(&self, c: &crate::audit::Challenge, payload: &[u8]) -> bool {
        use crate::audit::ChallengeKind as K;
        match c.kind {
            K::Replay { epoch_start: t } | K::MerkleWitness { epoch_start: t } => {
                let (Some(mine), Ok(cert)) =
                    (self.epoch_at(t), crate::CertifiedEpoch::decode(payload))
                else {
                    return false;
                };
                cert.checkpoint_hash() == mine.checkpoint.digest()
                    && cert.verify_with(
                        self.rules,
                        mine.checkpoint.previous_checkpoint,
                        mine.checkpoint.previous_state,
                        true,
                    ) == EvidenceVerdict::ValidClaim
            }
            K::HiddenReveal { start_tick } => {
                let Some(h) = self.hide else { return false };
                let Some(cell) = h.cells.iter().find(|x| x.start == start_tick) else {
                    return false;
                };
                let (Some(commit), Ok(PipeMsg::Reveal(o))) =
                    (cell.their_commit.as_ref(), PipeMsg::decode(payload))
                else {
                    return false;
                };
                o.batch.verify().is_ok()
                    && o.batch.record.start_tick == start_tick
                    && BatchCommitment::blind_batch(&o.batch, &o.blind).ok()
                        == Some(commit.claim.blinded_batch_hash)
            }
            _ => false,
        }
    }
}
