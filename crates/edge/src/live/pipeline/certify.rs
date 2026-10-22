//! Checkpoint exchange: every signer replays the same admitted input set, signs the resulting
//! checkpoint and broadcasts it. The session's certification policy decides when enough matching
//! signatures exist; a claim that differs from the local replay is checked against independent
//! evidence before anyone is accused.
use super::config::{PipeEvent, Violation, ViolationKind};
use super::Pipeline;
use crate::live::msg::{Outgoing, PipeMsg};
use crate::{
    verify_checkpoint_evidence_with, Checkpoint, CheckpointEvidence, EvidenceVerdict,
    InputViolation, SignedCheckpoint, StateMachine,
};
use gv_codec::SignedEventBatch;
use gv_core::ParticipantId;

/// Checkpoints kept for epochs this participant has not reached yet, per roster member.
const EARLY_PER_MEMBER: usize = 16;

pub(super) enum Stage {
    Collect,
    Certify(Box<Certify>),
}

pub(super) struct Certify {
    start: u64,
    end: u64,
    sealed: bool,
    checkpoint: Checkpoint,
    honest: SignedCheckpoint,
    /// What was actually sent (differs from `honest` only when a cheat was injected).
    sent: SignedCheckpoint,
    inputs: Vec<Option<SignedEventBatch>>,
    previous_state: Vec<u8>,
    received: Vec<SignedCheckpoint>,
    /// Signers whose claim replay proved false.
    liars: Vec<ParticipantId>,
    /// Signers whose differing claim has already been examined.
    judged: Vec<ParticipantId>,
}

impl<R: StateMachine + Clone> Pipeline<R> {
    /// Stage the admitted inputs, replay them, then sign and broadcast the resulting checkpoint.
    pub(super) fn begin_epoch(
        &mut self,
        inputs: Vec<Option<SignedEventBatch>>,
        sealed: bool,
        now: u64,
    ) {
        let start = self.ws();
        let previous_state = self.replica.state().to_vec();
        for b in inputs.iter().flatten() {
            if let Err(e) = self.replica.admit(b.clone()) {
                self.replica.discard_pending();
                self.fault(format!("admit failed: {e:?}"));
                return;
            }
        }
        let (epoch, violations) = match self.replica.candidate_with_violations() {
            Ok(x) => x,
            Err(e) => {
                self.replica.discard_pending();
                self.fault(format!("replay failed: {e:?}"));
                return;
            }
        };
        let honest = SignedCheckpoint::sign(epoch.checkpoint.clone(), &self.key);
        for v in violations {
            self.report_illegal_input(&v, &honest, &previous_state, &inputs);
        }
        let sent = self.claim_to_send(&epoch.checkpoint, &honest);
        self.auditor.record_my_checkpoint(&sent);
        self.enqueue(Outgoing::all(PipeMsg::Checkpoint(sent.clone())));
        let end = start + u64::from(epoch.checkpoint.epoch_length);
        let mut cert = Box::new(Certify {
            start,
            end,
            sealed,
            checkpoint: epoch.checkpoint,
            honest,
            sent,
            inputs,
            previous_state,
            received: Vec::new(),
            liars: Vec::new(),
            judged: Vec::new(),
        });
        self.judge_own_claim(&mut cert);
        self.stage = Stage::Certify(cert);
        for sig in std::mem::take(&mut self.early_ckpt) {
            self.on_checkpoint(sig, now);
        }
        self.settle();
    }
    fn claim_to_send(&mut self, truth: &Checkpoint, honest: &SignedCheckpoint) -> SignedCheckpoint {
        if !std::mem::take(&mut self.cheat_pending) {
            return honest.clone();
        }
        let mut lie = truth.clone();
        lie.next_state = [0xa5; 32];
        SignedCheckpoint::sign(lie, &self.key)
    }
    fn evidence(
        &self,
        accused: SignedCheckpoint,
        previous_state: &[u8],
        inputs: &[Option<SignedEventBatch>],
    ) -> CheckpointEvidence {
        CheckpointEvidence {
            trusted_previous_checkpoint: self.replica.previous_checkpoint(),
            trusted_previous_state: accused.claim.previous_state,
            accused,
            previous_state: previous_state.to_vec(),
            session: self.session.clone(),
            inputs: inputs.to_vec(),
        }
    }
    fn report_illegal_input(
        &mut self,
        v: &InputViolation,
        honest: &SignedCheckpoint,
        previous_state: &[u8],
        inputs: &[Option<SignedEventBatch>],
    ) {
        if self.reported_inputs.contains(&(v.tick, v.participant)) {
            return;
        }
        self.reported_inputs.push((v.tick, v.participant));
        // The honest claim signed by us binds the exact input set; the offending signed event
        // is inside `inputs`.
        let evidence = self
            .evidence(honest.clone(), previous_state, inputs)
            .encode()
            .unwrap_or_default();
        self.events.push_back(PipeEvent::Violation(Violation {
            kind: ViolationKind::IllegalInput,
            accused: v.participant,
            tick: v.tick,
            evidence,
        }));
    }

    // ---- receiving checkpoints ------------------------------------------------

    pub(super) fn on_checkpoint(&mut self, sig: SignedCheckpoint, _now: u64) {
        let signs = self
            .session
            .roster
            .find(&sig.signer)
            .is_some_and(|p| p.role.signs());
        if sig.verify().is_err() || !signs || sig.signer == self.me {
            self.fault("bad checkpoint signature");
            return;
        }
        self.auditor.observe_checkpoint(&sig);
        self.last_peer_checkpoint = Some(sig.clone());
        let Stage::Certify(c) = &mut self.stage else {
            self.stash_early(sig);
            return;
        };
        let (start, end) = (c.start, c.end);
        if sig.claim.epoch_start != start || u64::from(sig.claim.epoch_length) != end - start {
            if sig.claim.epoch_start >= end {
                self.stash_early(sig);
            }
            return;
        }
        if c.received.iter().all(|r| r.signer != sig.signer) {
            c.received.push(sig);
        }
        self.settle();
    }
    fn stash_early(&mut self, sig: SignedCheckpoint) {
        if self.early_ckpt.len() < EARLY_PER_MEMBER * self.session.roster.len() {
            self.early_ckpt.push(sig);
        }
    }

    // ---- deciding ---------------------------------------------------------------

    fn judge_own_claim(&mut self, c: &mut Certify) {
        if c.sent.claim == c.checkpoint {
            return;
        }
        let sent = c.sent.clone();
        self.judge_claim(c, sent);
    }
    /// Check a differing claim against independent replay before anyone is accused.
    fn judge_claim(&mut self, c: &mut Certify, claim: SignedCheckpoint) {
        let who = claim.signer;
        if c.judged.contains(&who) {
            return;
        }
        c.judged.push(who);
        let ev = self.evidence(claim, &c.previous_state, &c.inputs);
        match verify_checkpoint_evidence_with(&self.rules, &ev, true) {
            EvidenceVerdict::ProvenInvalidState => {
                c.liars.push(who);
                self.events.push_back(PipeEvent::Violation(Violation {
                    kind: ViolationKind::FalseCheckpoint,
                    accused: who,
                    tick: c.start,
                    evidence: ev.encode().unwrap_or_default(),
                }));
            }
            other => self.fault(format!("disputed claim not proven: {other:?}")),
        }
    }
    fn truthful_slots(&self, c: &Certify) -> (Vec<usize>, Vec<SignedCheckpoint>) {
        let roster = &self.session.roster;
        let mut sigs: Vec<SignedCheckpoint> = c
            .received
            .iter()
            .filter(|s| s.claim == c.checkpoint)
            .cloned()
            .collect();
        if c.sent.claim == c.checkpoint {
            sigs.push(c.honest.clone());
        }
        let slots = sigs
            .iter()
            .filter_map(|s| roster.index_of(&s.signer))
            .collect();
        (slots, sigs)
    }
    fn dispute_is_final(&self, c: &Certify) -> bool {
        let roster = &self.session.roster;
        let possible: Vec<usize> = roster
            .signers()
            .into_iter()
            .filter(|s| roster.get(*s).is_some_and(|p| !c.liars.contains(&p.id)))
            .collect();
        !c.liars.is_empty() && !self.session.certification.satisfied(roster, &possible)
    }
    /// Finalize once the certification policy is met, or close the epoch as disputed once
    /// provable lies make it unreachable.
    pub(super) fn settle(&mut self) {
        let Stage::Certify(mut c) = std::mem::replace(&mut self.stage, Stage::Collect) else {
            return;
        };
        let differing: Vec<_> = c
            .received
            .iter()
            .filter(|s| s.claim != c.checkpoint)
            .cloned()
            .collect();
        for claim in differing {
            self.judge_claim(&mut c, claim);
        }
        let (slots, sigs) = self.truthful_slots(&c);
        let met = self
            .session
            .certification
            .satisfied(&self.session.roster, &slots);
        let outcome = if met {
            self.replica.finalize(sigs).map(|_| false)
        } else if self.dispute_is_final(&c) {
            self.replica.finalize_disputed().map(|_| true)
        } else {
            self.stage = Stage::Certify(c);
            return;
        };
        match outcome {
            Ok(disputed) => self.finish_epoch(&c, disputed),
            Err(e) => {
                self.replica.discard_pending();
                self.fault(format!("finalize failed: {e:?}"));
            }
        }
    }
    fn finish_epoch(&mut self, c: &Certify, disputed: bool) {
        self.events.push_back(PipeEvent::Finalized {
            start: c.start,
            end: c.end,
            checkpoint: self.replica.previous_checkpoint(),
            state: self.replica.state().to_vec(),
            disputed,
            sealed: c.sealed,
        });
        self.stage = Stage::Collect;
        self.epoch_done = true;
    }
}
