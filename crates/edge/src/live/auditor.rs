//! Per-participant accountability engine that runs beside the real-time pipeline. It keeps the
//! tamper-evident log, exchanges authenticators once per epoch, audits every other participant's
//! chain with signed challenges, and records proven misbehavior in a deterministic ledger. It never blocks or delays play: every call is O(1)
//! amortized and all network I/O is queued messages.
use super::gate::Gate;
use super::msg::{Outgoing, PipeMsg};
use crate::audit::{
    challenge::{ChallengeBook, ChallengeGate, ChallengeKind, Response, Status, Timing},
    journal::TrustStore,
    trust::{check_log, PinError, Pins, Recovery, Refusal, Unresolved},
    AuditLog, Authenticator, Challenge, Evidence, Ledger, Outcome, Segment,
};
use crate::quorum::Ballot;
use crate::SignedCheckpoint;
use gv_codec::SignedEventBatch;
use gv_core::{Digest, MatchId, ParticipantId, Roster};
use gv_sig::SigningKey;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

mod quorum;

const KIND_BATCH: u8 = 1;
const KIND_CHECKPOINT: u8 = 2;
/// Audit a peer's chain every this many of its authenticators.
const AUDIT_EVERY: u64 = 10;
const MAX_SEEN_AUTH: usize = 256;
const MAX_BATCH_CACHE: usize = 512;
const MAX_STORED_CHECKPOINTS: usize = 256;
/// Retained log entries before safe pruning (pins protect active challenges).
const LOG_KEEP: usize = 8192;

#[derive(Clone, Debug)]
pub enum AuditEvent {
    /// Cryptographic proof of equivocation (exportable, offline-verifiable).
    ProvenEquivocation {
        accused: ParticipantId,
        id: Digest,
        evidence: Vec<u8>,
    },
    /// A challenge changed state. Only SUSPECTED/UNAVAILABLE/CLEARED/INCONCLUSIVE:
    /// a timeout is never a cheating verdict.
    Challenge {
        id: Digest,
        kind: ChallengeKind,
        status: Status,
    },
    /// Accusation material that did not verify; proves nothing.
    RejectedEvidence,
    /// Crash recovery did not (fully) trust the persisted log. Never a cheating verdict.
    RecoveryNotTrusted(Recovery),
    /// Local state was recovered from an authenticated head supplied by a peer or witness.
    Rebased { seq: u64 },
    /// The write-ahead store failed: nothing signed is released until it succeeds again.
    /// Not a verdict about anyone.
    PersistenceFailed(String),
    /// A witness quorum answered: the head committed before the restart (if any) is adopted.
    QuorumRecovered { seq: Option<u64> },
    /// A newer incarnation of this participant exists: this one stopped signing. Not a verdict.
    Fenced { newer: Ballot },
    /// Periodic telemetry (emitted by the host loop, not the auditor).
    Snapshot(AuditStats),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditStats {
    pub pending: usize,
    pub proven_equivocation: usize,
    pub suspected: usize,
    pub cleared: usize,
    pub unavailable: usize,
    pub rejected_evidence: usize,
    pub log_len: u64,
    pub log_retained: usize,
    pub authenticators_sent: u64,
    pub authenticators_seen: u64,
    pub challenges_answered: u64,
    /// Filled by the host: evidence files written and total bytes persisted.
    pub evidence_files: u32,
    pub evidence_bytes: u64,
    pub persist_ok: bool,
}

/// Application hooks for challenge kinds that need replica data.
pub trait Answers {
    fn answer(&self, c: &Challenge) -> Option<Vec<u8>>;
    fn check(&self, c: &Challenge, payload: &[u8]) -> bool;
}
/// No application data: only the built-in kinds are answerable.
pub struct NoAnswers;
impl Answers for NoAnswers {
    fn answer(&self, _: &Challenge) -> Option<Vec<u8>> {
        None
    }
    fn check(&self, _: &Challenge, _: &[u8]) -> bool {
        false
    }
}

pub struct Auditor {
    key: SigningKey,
    me: ParticipantId,
    /// Every other roster member: each is audited and challenged individually.
    peers: Vec<ParticipantId>,
    roster: Vec<ParticipantId>,
    match_id: MatchId,
    ruleset: Digest,
    log: AuditLog,
    book: ChallengeBook,
    gate: ChallengeGate,
    ledger: Ledger,
    seen: BTreeMap<(ParticipantId, u64), Authenticator>,
    /// Per peer: latest authenticator whose chain we verified (or adopted as baseline).
    checked: BTreeMap<ParticipantId, Authenticator>,
    batches: BTreeMap<u64, Vec<u8>>,
    their_batches: Vec<SignedEventBatch>,
    their_checkpoints: Vec<SignedCheckpoint>,
    outbox: VecDeque<Outgoing>,
    events: VecDeque<AuditEvent>,
    stats: AuditStats,
    auth_count: BTreeMap<ParticipantId, u64>,
    withhold_until: u64,
    equivocate_next: bool,
    kinds: BTreeMap<Digest, (ChallengeKind, ParticipantId)>,
    pins: Pins,
    pins_dirty: bool,
    recovery: Recovery,
    held_log: Option<AuditLog>,
    /// Log positions kept alive for challenges against me: id -> (from, release_tick).
    gate_pins: BTreeMap<Digest, (u64, u64)>,
    /// Pinned third-party witnesses allowed to challenge me (never gameplay authorities).
    witnesses: BTreeSet<ParticipantId>,
    witness_responses: VecDeque<Response>,
    /// Write-ahead barrier. Nothing signed leaves until a store is attached.
    store: Durability,
    store_failed: bool,
    committed_len: u64,
    committed_head: u64,
    now: u64,
    commit_retry_at: u64,
    commits: u64,
    /// Signing stays suspended until the anchor check is complete (see [`AnchorCheck`]).
    anchor_pending: bool,
    anchor: AnchorCheck,
    /// Peers that must answer an anchor check before signing resumes.
    anchor_quorum: usize,
    /// Witness-quorum head register (recovery and release gate); `None` in peers-only mode.
    register: Option<Gate>,
    fenced: bool,
}

/// Who has answered the anchor check after a (re)start. Every peer receives every head I sign,
/// so by default every peer must answer (`anchor_quorum`). When witnesses are pinned, signing
/// additionally waits for one of them to hand back a head of mine or for [`ANCHOR_WITNESS_WAIT`]
/// ticks to pass, so a newer head withheld by the peers is still recovered if any honest witness
/// holds it.
#[derive(Default)]
struct AnchorCheck {
    answers: BTreeMap<ParticipantId, AnchorAnswer>,
    witness_answered: bool,
    wait_until: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AnchorAnswer {
    Head,
    NoHeads,
}

/// Ticks to wait for a witness-held head after the peers answered an anchor check.
pub const ANCHOR_WITNESS_WAIT: u64 = 600;

/// Where signed state is made durable before it may leave the process.
enum Durability {
    /// No store attached yet: the barrier stays closed (fail closed, never a silent fallback).
    Missing,
    Journal(Box<dyn TrustStore>),
    /// Explicit in-memory mode for tests; offers no crash or rollback protection.
    #[cfg(any(test, feature = "ephemeral-store"))]
    EphemeralForTests,
}

/// Outcome of [`Auditor::restore`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreReport {
    pub recovery: Recovery,
    pub evidence_restored: usize,
}

impl Auditor {
    pub fn new(
        key: SigningKey,
        roster: &Roster,
        match_id: MatchId,
        ruleset: Digest,
    ) -> Option<Self> {
        let me = key.id();
        let roster: Vec<ParticipantId> = roster.participants().iter().map(|p| p.id).collect();
        if !roster.contains(&me) {
            return None;
        }
        let peers: Vec<ParticipantId> = roster.iter().copied().filter(|p| *p != me).collect();
        Some(Self {
            anchor_quorum: peers.len(),
            log: AuditLog::new(match_id, me),
            book: ChallengeBook::new(
                key.clone(),
                match_id,
                Timing {
                    timeout: 30,
                    grace: 120,
                },
            ),
            gate: ChallengeGate::new(me, match_id),
            ledger: Ledger::new(),
            key,
            me,
            peers,
            roster,
            match_id,
            ruleset,
            seen: BTreeMap::new(),
            checked: BTreeMap::new(),
            batches: BTreeMap::new(),
            their_batches: Vec::new(),
            their_checkpoints: Vec::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            stats: AuditStats::default(),
            auth_count: BTreeMap::new(),
            withhold_until: 0,
            equivocate_next: false,
            kinds: BTreeMap::new(),
            pins: Pins::new(),
            pins_dirty: false,
            recovery: Recovery::Fresh,
            held_log: None,
            gate_pins: BTreeMap::new(),
            witnesses: BTreeSet::new(),
            witness_responses: VecDeque::new(),
            store: Durability::Missing,
            store_failed: false,
            committed_len: 0,
            committed_head: 0,
            now: 0,
            commit_retry_at: 0,
            commits: 0,
            anchor_pending: false,
            anchor: AnchorCheck::default(),
            register: None,
            fenced: false,
        })
    }

    /// Anchored crash recovery. The persisted `log` is adopted only if it agrees with an
    /// authenticated head this participant signed earlier (`anchors`: the local pin file plus any
    /// heads handed back by peers or witnesses). Without an anchor the log is held, not adopted,
    /// signing is suspended and the state is reported as unresolved; a rollback or fork is
    /// refused. Persisted evidence is re-verified and anything invalid is dropped.
    pub fn restore(
        &mut self,
        log: Option<AuditLog>,
        anchors: &[Authenticator],
        evidence: &[Vec<u8>],
    ) -> RestoreReport {
        for a in anchors {
            self.pin(a);
        }
        let verdict = check_log(self.me, self.match_id, log.as_ref(), self.pins.items());
        match (&verdict, log) {
            (Recovery::Resumed { .. }, Some(l)) => self.log = l,
            (Recovery::Unresolved(_), Some(l)) => self.held_log = Some(l),
            _ => {}
        }
        if !verdict.may_sign() {
            self.events
                .push_back(AuditEvent::RecoveryNotTrusted(verdict.clone()));
        }
        self.recovery = verdict.clone();
        // Pinned peer heads are the baseline for auditing their resumed history.
        for peer in self.peers.clone() {
            let theirs: Vec<Authenticator> = self.pins.for_owner(peer).cloned().collect();
            for a in theirs {
                self.seen.insert((peer, a.seq), a);
            }
            if let Some(best) = self.pins.highest(peer) {
                self.checked.insert(peer, best.clone());
            }
        }
        let mut restored = 0;
        for bytes in evidence {
            if let Ok(e) = Evidence::decode(bytes) {
                if matches!(self.ledger.submit(&e, &self.roster), Outcome::Recorded(_)) {
                    restored += 1;
                }
            }
        }
        RestoreReport {
            recovery: verdict,
            evidence_restored: restored,
        }
    }
    /// Hand over an authenticated head obtained after the restart (from a peer or a witness). If it anchors a held log, recovery completes.
    pub fn supply_anchor(&mut self, a: &Authenticator) {
        self.pin(a);
        if a.owner != self.me {
            return;
        }
        // A head I signed that my current log cannot account for means the local state is
        // stale or forked: stop signing before it can contradict that head.
        if matches!(self.recovery, Recovery::Fresh | Recovery::Resumed { .. }) {
            match check_log(self.me, self.match_id, Some(&self.log), self.pins.items()) {
                v @ Recovery::Refused(_) => {
                    self.events
                        .push_back(AuditEvent::RecoveryNotTrusted(v.clone()));
                    self.recovery = v;
                }
                v @ Recovery::Resumed { .. } => self.recovery = v,
                _ => {}
            }
            return;
        }
        if let (Recovery::Unresolved(_), Some(held)) = (&self.recovery, self.held_log.take()) {
            let verdict = check_log(self.me, self.match_id, Some(&held), self.pins.items());
            match &verdict {
                Recovery::Resumed { .. } => self.log = held,
                Recovery::Unresolved(_) => self.held_log = Some(held),
                _ => {}
            }
            if verdict != self.recovery {
                if !verdict.may_sign() {
                    self.events
                        .push_back(AuditEvent::RecoveryNotTrusted(verdict.clone()));
                }
                self.recovery = verdict;
            }
        }
    }
    /// A peer or witness has confirmed that it holds no head signed by me for this match. If the
    /// only obstacle to resuming was the lack of any anchor (`NoAnchor`: the journal reached
    /// disk but the crash came before its first signed head did), the held log is adopted.
    /// Never applies to `LogLost`, `AnchorPruned`, rollback or fork.
    pub fn confirm_no_prior_heads(&mut self) -> bool {
        if !matches!(self.recovery, Recovery::Unresolved(Unresolved::NoAnchor)) {
            return false;
        }
        let Some(held) = self.held_log.take() else {
            return false;
        };
        if self.pins.for_owner(self.me).next().is_some() {
            self.held_log = Some(held);
            return false;
        }
        self.log = held;
        self.recovery = Recovery::Fresh;
        true
    }
    /// Ask every peer for the highest head of mine it holds and suspend signing until an anchor
    /// check completes ([`AnchorCheck`]). Call after every (re)start of a participant: state
    /// loss is only detectable against heads held elsewhere.
    pub fn require_anchor_check(&mut self) {
        self.anchor_pending = true;
        self.anchor = AnchorCheck::default();
        if self.register.is_none() {
            self.outbox.push_back(Outgoing::all(PipeMsg::AnchorReq));
        }
    }
    /// How many peers must answer an anchor check (default: all of them). Lowering it trades
    /// protection against a withheld newer head for liveness while peers are offline.
    pub fn set_anchor_quorum(&mut self, quorum: usize) {
        self.anchor_quorum = quorum.min(self.peers.len());
    }
    pub fn anchor_check_pending(&self) -> bool {
        self.anchor_pending
    }
    /// A peer's answer to my anchor request (wire: `PipeMsg::Anchor`).
    fn on_anchor(&mut self, from: ParticipantId, a: Option<Authenticator>) {
        let answer = match a {
            Some(a) if self.is_own_head(&a) => {
                self.supply_anchor(&a);
                AnchorAnswer::Head
            }
            Some(_) => return, // not mine / not valid: ignore, keep waiting
            None => AnchorAnswer::NoHeads,
        };
        if !self.anchor_pending
            || !self.peers.contains(&from)
            || self.anchor.answers.contains_key(&from)
        {
            return;
        }
        self.anchor.answers.insert(from, answer);
        if self.anchor.answers.len() >= self.anchor_quorum {
            self.anchor.wait_until = self.now + ANCHOR_WITNESS_WAIT;
        }
        self.finish_anchor_check();
    }
    /// A head of mine held by a pinned witness (local, from the witness service; never from a
    /// peer's wire). It is applied even outside an anchor check: a newer head proves state loss.
    pub fn on_witness_anchor(&mut self, a: &Authenticator) {
        if self.witnesses.is_empty() || !self.is_own_head(a) {
            return;
        }
        self.supply_anchor(a);
        self.anchor.witness_answered = true;
        self.finish_anchor_check();
    }
    fn is_own_head(&self, a: &Authenticator) -> bool {
        a.owner == self.me && a.match_id == self.match_id && a.verify().is_ok()
    }
    /// Resume signing once the trust boundary is met: the required peers answered, and (with
    /// witnesses pinned) a witness answered or the wait elapsed. "No heads" is only believed when no
    /// source handed back any head of mine. Residual risk, documented in doc 42: if every
    /// responding source withholds a newer head, a later head of mine can still contradict it.
    fn finish_anchor_check(&mut self) {
        if self.anchor.answers.len() < self.anchor_quorum {
            return;
        }
        let witness_done = self.witnesses.is_empty()
            || self.anchor.witness_answered
            || self.now >= self.anchor.wait_until;
        if !self.anchor_pending || !witness_done {
            return;
        }
        if self
            .anchor
            .answers
            .values()
            .all(|a| *a == AnchorAnswer::NoHeads)
        {
            self.confirm_no_prior_heads();
        }
        self.rebase_on_anchor();
        self.anchor_pending = false;
    }
    /// Recover from lost, rolled-back or forked local state using the highest head of mine that
    /// a peer or witness returned: the log restarts from that signed head (earlier entries are
    /// unavailable, so challenges about them end UNAVAILABLE, never as a verdict). Everything I
    /// signed up to that head stays consistent. Residual risk: a head signed after it and held
    /// only by a party that withheld it would then be contradicted.
    pub fn rebase_on_anchor(&mut self) -> bool {
        let recoverable = matches!(
            self.recovery,
            Recovery::Unresolved(Unresolved::LogLost | Unresolved::AnchorPruned)
                | Recovery::Refused(Refusal::Rollback { .. } | Refusal::Fork { .. })
        );
        if !recoverable {
            return false;
        }
        let Some(best) = self.pins.highest(self.me).cloned() else {
            return false;
        };
        let rebased = AuditLog::rebased(self.match_id, self.me, best.seq, best.head);
        if let Durability::Journal(store) = &mut self.store {
            let heads: Vec<Authenticator> = self.pins.for_owner(self.me).cloned().collect();
            if let Err(e) = store.reset(&rebased, &heads) {
                self.store_failed = true;
                self.commit_retry_at = self.now + 60;
                self.events
                    .push_back(AuditEvent::PersistenceFailed(e.to_string()));
                return false;
            }
            self.committed_len = rebased.len();
            self.committed_head = self.committed_head.max(best.seq);
        }
        self.log = rebased;
        self.held_log = None;
        self.recovery = Recovery::Resumed {
            len: best.seq,
            anchored_at: best.seq,
        };
        self.events.push_back(AuditEvent::Rebased { seq: best.seq });
        true
    }
    fn pin(&mut self, a: &Authenticator) {
        if a.match_id != self.match_id || !self.roster.contains(&a.owner) {
            return;
        }
        match self.pins.add(a) {
            Ok(true) => self.pins_dirty = true,
            Ok(false) | Err(PinError::Invalid) | Err(PinError::Full) => {}
            Err(PinError::Conflict(prev)) => {
                self.submit(&Evidence::ConflictingAuthenticators(*prev, a.clone()), true)
            }
        }
    }
    /// Allow a pinned witness to audit my log with signed challenges. Answers to witnesses are
    /// queued separately ([`Self::poll_witness_response`]) and never sent to a peer.
    pub fn admit_witness(&mut self, id: ParticipantId) {
        if self.witnesses.len() < 32 && !self.roster.contains(&id) {
            self.witnesses.insert(id);
        }
    }
    pub fn poll_witness_response(&mut self) -> Option<Response> {
        if self.witness_responses.is_empty() || !self.make_durable() {
            return None;
        }
        self.witness_responses.pop_front()
    }
    /// Attach the write-ahead store. `durable_len` / `durable_head` describe what it already
    /// holds (from its recovery), so only new state is committed.
    pub fn attach_store(
        &mut self,
        store: Box<dyn TrustStore>,
        durable_len: u64,
        durable_head: u64,
    ) {
        self.store = Durability::Journal(store);
        self.committed_len = durable_len;
        self.committed_head = durable_head;
    }
    /// Run without durable storage. Signed heads are lost on a crash, so a restarted participant
    /// can equivocate unknowingly: only for tests and simulations, never accountable operation.
    #[cfg(any(test, feature = "ephemeral-store"))]
    pub fn use_ephemeral_store_for_tests(&mut self) {
        self.store = Durability::EphemeralForTests;
        self.store_failed = false;
    }
    /// The durability barrier. Returns `true` when everything signed so far (log through its
    /// head, own pinned heads) is durable, so queued messages may leave the process. On a store
    /// error it returns `false` (fail closed), reports once and retries after a short delay.
    pub fn make_durable(&mut self) -> bool {
        let store = match &mut self.store {
            Durability::Journal(store) => store,
            #[cfg(any(test, feature = "ephemeral-store"))]
            Durability::EphemeralForTests => return true,
            Durability::Missing => {
                if !self.store_failed {
                    self.store_failed = true;
                    self.events.push_back(AuditEvent::PersistenceFailed(
                        "no durable trust store attached".into(),
                    ));
                }
                return false;
            }
        };
        let own_head = self.pins.highest(self.me).map_or(0, |a| a.seq);
        if !self.store_failed
            && self.committed_len == self.log.len()
            && self.committed_head >= own_head
        {
            return true;
        }
        if self.store_failed && self.now < self.commit_retry_at {
            return false;
        }
        let heads: Vec<Authenticator> = self
            .pins
            .for_owner(self.me)
            .filter(|a| a.seq > self.committed_head)
            .cloned()
            .collect();
        match store.commit(&self.log, &heads) {
            Ok(()) => {
                self.committed_len = self.log.len();
                self.committed_head = self.committed_head.max(own_head);
                self.store_failed = false;
                self.commits += 1;
                true
            }
            Err(e) => {
                if !self.store_failed {
                    self.events
                        .push_back(AuditEvent::PersistenceFailed(e.to_string()));
                }
                self.store_failed = true;
                self.commit_retry_at = self.now + 60;
                false
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn test_append(&mut self, kind: u8, payload: Vec<u8>) {
        let _ = self.log.append(kind, payload);
    }
    pub fn persistence_failed(&self) -> bool {
        self.store_failed
    }
    pub fn commits(&self) -> u64 {
        self.commits
    }
    pub fn recovery(&self) -> &Recovery {
        &self.recovery
    }
    /// Pins changed since the last call; the host must persist them durably (`Pins::save`).
    pub fn take_dirty_pins(&mut self) -> Option<&Pins> {
        if std::mem::take(&mut self.pins_dirty) {
            Some(&self.pins)
        } else {
            None
        }
    }
    pub fn pins(&self) -> &Pins {
        &self.pins
    }
    /// Challenges I issued that have no final answer yet (persist these across restarts).
    pub fn open_challenges(&self) -> Vec<Challenge> {
        self.book.open_challenges()
    }
    /// Re-issue persisted challenges after a restart with a fresh deadline: downtime never
    /// counts against the target.
    pub fn resume_challenges(&mut self, cs: &[Challenge], now: u64) -> usize {
        let mut n = 0;
        for c in cs {
            if self.book.resume(c, now) {
                self.kinds.insert(c.id(), (c.kind, c.target));
                n += 1;
            }
        }
        self.drain_challenges();
        n
    }
    fn drain_challenges(&mut self) {
        while let Some(c) = self.book.poll_outbox() {
            let to = c.target;
            self.outbox
                .push_back(Outgoing::to(to, PipeMsg::Challenge(c)));
        }
    }
    pub fn stats(&self) -> AuditStats {
        let mut s = self.stats;
        s.pending = self.book.open_count();
        s.suspected = self.book.count(Status::SuspectedNonCooperation);
        s.unavailable = self.book.count(Status::Unavailable);
        s.cleared = self.stats.cleared;
        s.proven_equivocation = self.ledger.count(Status::ProvenEquivocation);
        s.log_len = self.log.len();
        s.log_retained = self.log.retained();
        s
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    /// Crate-only: hosts receive these through `Pipeline::poll_outbox`, behind the write-ahead
    /// barrier. A public drain would let signed heads leave before they are durable.
    pub(crate) fn poll_msg(&mut self) -> Option<Outgoing> {
        self.outbox.pop_front()
    }
    pub fn poll_event(&mut self) -> Option<AuditEvent> {
        self.events.pop_front()
    }
    pub fn log(&self) -> &AuditLog {
        &self.log
    }

    // ---- demo / adversary controls ---------------------------------------------

    /// Demo: stop answering challenges until logical tick `until`.
    pub fn withhold_answers_until(&mut self, until: u64) {
        self.withhold_until = until;
    }
    /// Demo: the next authenticator is accompanied by a second, conflicting one
    /// for the same log position (a dishonest participant showing two histories).
    pub fn equivocate_next_authenticator(&mut self) {
        self.equivocate_next = true;
    }
    /// Demo: challenge `target` about a batch they delivered long ago.
    pub fn accuse_missing_batch(&mut self, target: ParticipantId, start_tick: u64, now: u64) {
        self.issue(target, ChallengeKind::MissingBatch { start_tick }, now);
    }
    fn issue(&mut self, target: ParticipantId, kind: ChallengeKind, now: u64) -> Option<Digest> {
        if !self.peers.contains(&target) {
            return None;
        }
        let c = self.book.issue(target, kind, now).ok()?;
        if self.kinds.len() >= 256 {
            self.kinds.pop_first();
        }
        self.kinds.insert(c.id(), (kind, target));
        self.outbox
            .push_back(Outgoing::to(target, PipeMsg::Challenge(c.clone())));
        Some(c.id())
    }
    /// Ask `target` for an arbitrary challenge kind (replay evidence, Merkle witness, sealed
    /// reveal, ack). Bounded by the challenge book.
    pub fn challenge(
        &mut self,
        target: ParticipantId,
        kind: ChallengeKind,
        now: u64,
    ) -> Option<Digest> {
        self.issue(target, kind, now)
    }
    /// Demo: a framing attempt. Splicing a signature is impossible (decoding
    /// verifies it), so the attacker pairs the victim's real checkpoint with a
    /// conflicting one signed by the attacker; it must verify as nothing.
    pub fn send_forged_accusation(&mut self, victim_checkpoint: &SignedCheckpoint) {
        let mut claim = victim_checkpoint.claim.clone();
        claim.next_state[0] ^= 1;
        let fake = SignedCheckpoint::sign(claim, &self.key);
        let ev = Evidence::ConflictingCheckpoints(victim_checkpoint.clone(), fake);
        self.outbox
            .push_back(Outgoing::all(PipeMsg::Evidence(Box::new(ev))));
    }

    // ---- recording -------------------------------------------------------------

    pub fn record_my_batch(&mut self, b: &SignedEventBatch) {
        if let Ok(bytes) = b.encode() {
            let _ = self
                .log
                .append(KIND_BATCH, b.digest().unwrap_or([0; 32]).to_vec());
            if self.batches.len() >= MAX_BATCH_CACHE {
                self.batches.pop_first();
            }
            self.batches.insert(b.record.start_tick, bytes);
        }
    }
    pub fn record_my_checkpoint(&mut self, c: &SignedCheckpoint) {
        let _ = self.log.append(KIND_CHECKPOINT, c.claim.digest().to_vec());
    }

    /// A peer's batch seen: any overlapping, disagreeing earlier batch is proof.
    pub fn observe_batch(&mut self, b: &SignedEventBatch) {
        // Signature checks are expensive (ML-DSA), so only batches whose tick ranges overlap
        // are paired; non-overlapping batches cannot conflict.
        let (start, end) = (
            b.record.start_tick,
            b.record.start_tick + u64::from(b.record.tick_count),
        );
        let overlapping: Vec<_> = self
            .their_batches
            .iter()
            .filter(|old| {
                let (os, oe) = (
                    old.record.start_tick,
                    old.record.start_tick + u64::from(old.record.tick_count),
                );
                old.record.participant == b.record.participant && os < end && start < oe
            })
            .cloned()
            .collect();
        for old in overlapping {
            self.submit(&Evidence::ConflictingBatches(old, b.clone()), true);
        }
        if self.their_batches.len() >= MAX_BATCH_CACHE {
            self.their_batches.remove(0);
        }
        self.their_batches.push(b.clone());
    }
    pub fn observe_checkpoint(&mut self, c: &SignedCheckpoint) {
        if !self.peers.contains(&c.signer) {
            return;
        }
        let same_slot: Vec<_> = self
            .their_checkpoints
            .iter()
            .filter(|old| {
                old.signer == c.signer
                    && old.claim.epoch_start == c.claim.epoch_start
                    && old.claim.digest() != c.claim.digest()
            })
            .cloned()
            .collect();
        for old in same_slot {
            self.submit(&Evidence::ConflictingCheckpoints(old, c.clone()), true);
        }
        if self.their_checkpoints.len() >= MAX_STORED_CHECKPOINTS {
            self.their_checkpoints.remove(0);
        }
        self.their_checkpoints.push(c.clone());
    }

    /// Once per epoch: publish my log head. Cheap: one signature per epoch.
    pub fn on_epoch(&mut self, now: u64) {
        self.now = self.now.max(now);
        if self.anchor_pending {
            return; // restart: do not sign before the anchor check answered
        }
        if (self.store_failed || matches!(self.store, Durability::Missing)) && !self.make_durable()
        {
            return; // fail closed: no new signed head while the write-ahead store is failing
        }
        if !self.recovery.may_sign() || self.fenced {
            return; // unresolved recovery: never sign a head that could contradict an earlier one
        }
        if self.register.is_some() {
            let seq = self.log.len();
            self.want_cover(now, seq);
            self.pump_register();
            return;
        }
        let a = self.log.sign_authenticator(self.ruleset, &self.key);
        self.pin(&a);
        self.stats.authenticators_sent += 1;
        self.outbox.push_back(Outgoing::all(PipeMsg::Auth(a)));
        if self.equivocate_next && !self.log.is_empty() {
            self.equivocate_next = false;
            // A forked history: same position, different head, validly signed.
            let mut fork = AuditLog::new(self.match_id, self.me);
            for i in 1..self.log.len() {
                if let Ok(seg) = self.log.segment(i - 1, i) {
                    if let Some(e) = seg.entries.first() {
                        let _ = fork.append(e.kind, e.payload.clone());
                    }
                }
            }
            let _ = fork.append(255, b"forked-history".to_vec());
            self.outbox.push_back(Outgoing::all(PipeMsg::Auth(
                fork.sign_authenticator(self.ruleset, &self.key),
            )));
        }
        // Keep storage bounded without ever dropping entries an open challenge needs.
        self.log.prune_to_keep(LOG_KEEP);
    }

    /// Advance logical time: retransmit, suspect, release pins.
    pub fn tick(&mut self, now: u64) {
        self.now = self.now.max(now);
        if self.anchor_pending && self.anchor.answers.len() < self.anchor_quorum && now % 120 == 0 {
            self.outbox.push_back(Outgoing::all(PipeMsg::AnchorReq)); // a peer may not have been connected yet
        }
        self.finish_anchor_check();
        self.pump_register();
        let expired: Vec<Digest> = self
            .gate_pins
            .iter()
            .filter(|(_, (_, rel))| *rel <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some((from, _)) = self.gate_pins.remove(&id) {
                if !self.gate_pins.values().any(|(f, _)| *f == from) {
                    self.log.unpin(from);
                }
            }
        }
        self.book.poll(now);
        self.drain_challenges();
        while let Some((id, status)) = self.book.poll_change() {
            if status == Status::Cleared {
                self.stats.cleared += 1;
            }
            self.events.push_back(AuditEvent::Challenge {
                id,
                kind: self.kind_of(&id),
                status,
            });
        }
        self.book.gc();
    }
    fn kind_of(&self, id: &Digest) -> ChallengeKind {
        self.kinds
            .get(id)
            .map_or(ChallengeKind::Ack { seq: 0 }, |(kind, _)| *kind)
    }

    // ---- inbound ---------------------------------------------------------------

    fn submit(&mut self, e: &Evidence, announce: bool) {
        if self.certify_finding(e) {
            return;
        }
        match self.ledger.submit(e, &self.roster) {
            Outcome::Recorded(_) => {
                if let (Ok(id), Ok(evidence)) = (e.id(), e.encode()) {
                    self.events.push_back(AuditEvent::ProvenEquivocation {
                        accused: e.accused(),
                        id,
                        evidence,
                    });
                    if announce {
                        // Evidence propagation: every other participant (and any witness) can
                        // verify it independently, so relaying cannot frame anyone.
                        self.outbox
                            .push_back(Outgoing::all(PipeMsg::Evidence(Box::new(e.clone()))));
                    }
                }
            }
            Outcome::Rejected(_) => {
                self.stats.rejected_evidence += 1;
                self.events.push_back(AuditEvent::RejectedEvidence);
            }
            _ => {}
        }
    }

    /// Handle one accountability message. Anything unauthenticated, malformed,
    /// replayed or over a limit is dropped without a verdict.
    pub fn on_msg(&mut self, from: ParticipantId, msg: PipeMsg, now: u64, app: &dyn Answers) {
        match msg {
            PipeMsg::Auth(a) if a.owner == from => self.on_auth(a, now),
            PipeMsg::Challenge(c) if c.challenger == from => self.on_challenge(c, now, app),
            PipeMsg::Response(r) if r.responder == from => self.on_response(r, app),
            PipeMsg::Evidence(e) => {
                // Never trust the sender: verify, then record (no re-announce: no ping-pong).
                self.submit(&e, false);
            }
            PipeMsg::AnchorReq if self.peers.contains(&from) => {
                let held = self.pins.highest(from).cloned();
                self.outbox
                    .push_back(Outgoing::to(from, PipeMsg::Anchor(held)));
            }
            PipeMsg::Anchor(a) => self.on_anchor(from, a),
            PipeMsg::Quorum(q) => self.on_quorum(from, q),
            _ => {}
        }
    }

    fn on_auth(&mut self, a: Authenticator, now: u64) {
        if !self.peers.contains(&a.owner)
            || a.match_id != self.match_id
            || a.ruleset != self.ruleset
            || a.verify().is_err()
        {
            return;
        }
        self.stats.authenticators_seen += 1;
        self.pin(&a);
        let owner = a.owner;
        if let Some(prev) = self.seen.get(&(owner, a.seq)) {
            if prev.head != a.head {
                let ev = Evidence::ConflictingAuthenticators(prev.clone(), a);
                self.submit(&ev, true);
            }
            return;
        }
        if self.seen.len() >= MAX_SEEN_AUTH {
            self.seen.pop_first();
        }
        self.seen.insert((owner, a.seq), a.clone());
        let count = self.auth_count.entry(owner).or_insert(0);
        *count += 1;
        let audit_due = *count % AUDIT_EVERY == 0;
        match self.checked.get(&owner).cloned() {
            None => {
                self.checked.insert(owner, a);
            }
            Some(base) if a.seq > base.seq && audit_due => {
                if a.seq - base.seq <= crate::audit::log::MAX_SEGMENT_ENTRIES as u64 {
                    self.issue(
                        owner,
                        ChallengeKind::LogSegment {
                            from: base.seq,
                            to: a.seq,
                        },
                        now,
                    );
                } else {
                    // Too far to audit in one segment: adopt as the new baseline.
                    self.checked.insert(owner, a);
                }
            }
            Some(_) => {}
        }
    }

    fn on_challenge(&mut self, c: Challenge, now: u64, app: &dyn Answers) {
        let from_witness = self.witnesses.contains(&c.challenger);
        if (!self.peers.contains(&c.challenger) && !from_witness) || now < self.withhold_until {
            return;
        }
        if !self.recovery.may_sign() || self.fenced || self.gate.accept(&c, now).is_err() {
            return;
        }
        if let ChallengeKind::LogSegment { from, .. } = c.kind {
            // Keep the entries this challenge needs until it can no longer be answered.
            if self.gate_pins.len() < 256 {
                self.log.pin(from);
                self.gate_pins
                    .insert(c.id(), (from, c.deadline_tick.max(now) + 240));
            }
        }
        let payload = match c.kind {
            ChallengeKind::LogSegment { from, to } => {
                self.log.segment(from, to).ok().map(|s| s.encode())
            }
            ChallengeKind::MissingBatch { start_tick } => self.batches.get(&start_tick).cloned(),
            ChallengeKind::Ack { .. } => self.current_authenticator().map(|a| a.encode()),
            _ => app.answer(&c),
        };
        if let Some(p) = payload {
            self.stats.challenges_answered += 1;
            let r = Response::sign(&c, p, &self.key);
            if from_witness {
                if self.witness_responses.len() < 64 {
                    self.witness_responses.push_back(r);
                }
            } else {
                self.outbox
                    .push_back(Outgoing::to(c.challenger, PipeMsg::Response(r)));
            }
        }
    }

    fn on_response(&mut self, r: Response, app: &dyn Answers) {
        let Some((kind, other)) = self.kinds.get(&r.challenge_id).copied() else {
            return;
        };
        let checked = self.checked.get(&other).cloned();
        let seen = self.seen.clone();
        let fork: RefCell<Option<Evidence>> = RefCell::new(None);
        let adopt: RefCell<Option<Authenticator>> = RefCell::new(None);
        let result = self.book.on_response(&r, |c, payload| match kind {
            ChallengeKind::LogSegment { from, to } => {
                let (Ok(seg), Some(base), Some(end)) = (
                    Segment::decode(payload),
                    checked.as_ref(),
                    seen.get(&(other, to)),
                ) else {
                    return false;
                };
                if seg.owner != other
                    || seg.start_seq != from
                    || seg.end_seq() != to
                    || base.seq != from
                {
                    return false;
                }
                if seg.end_head().ok() != Some(end.head) {
                    return false;
                }
                if seg.prev_head == base.head {
                    *adopt.borrow_mut() = Some(end.clone());
                } else {
                    // Their chain no longer contains the head they signed earlier.
                    *fork.borrow_mut() = Some(Evidence::Fork {
                        earlier: base.clone(),
                        later: end.clone(),
                        segment: seg,
                    });
                }
                true
            }
            ChallengeKind::MissingBatch { start_tick } => {
                SignedEventBatch::decode(payload).ok().is_some_and(|b| {
                    b.verify().is_ok()
                        && b.record.participant == other
                        && b.record.start_tick == start_tick
                })
            }
            ChallengeKind::Ack { seq } => Authenticator::decode(payload)
                .ok()
                .is_some_and(|a| a.verify().is_ok() && a.owner == other && a.seq >= seq),
            _ => app.check(c, payload),
        });
        if let Some(a) = adopt.into_inner() {
            self.checked.insert(other, a);
        }
        if let Some(ev) = fork.into_inner() {
            self.submit(&ev, true);
        }
        if let Ok(status) = result {
            if status == Status::Cleared {
                self.stats.cleared += 1;
            }
            self.events.push_back(AuditEvent::Challenge {
                id: r.challenge_id,
                kind,
                status,
            });
        }
    }
}
