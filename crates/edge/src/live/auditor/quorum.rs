//! Auditor side of the witness-quorum head register: recovery without timeouts, the release
//! gate for signed output, and certification of equivocation findings.
use super::{AuditEvent, Auditor, Evidence, Outgoing, PipeMsg};
use crate::audit::Authenticator;
use crate::audit::Ledger;
use crate::live::gate::{Gate, Step};
use crate::quorum::{Claim, Phase, QuorumMsg, WitnessSet};
use gv_core::ParticipantId;

impl Auditor {
    /// Run in witnessed mode: committed heads live on a quorum of `set`, a restart recovers from
    /// a quorum read (never a timeout), signed output is released only once a quorum stored a
    /// head covering it, and log-equivocation convicts only on certified heads. Call before
    /// [`Auditor::require_anchor_check`]. Returns false for an unusable witness set.
    pub fn enable_witness_quorum(&mut self, set: WitnessSet) -> bool {
        if set.is_empty() || self.witnesses.iter().any(|w| !set.contains(w)) {
            return false;
        }
        let Some(gate) = Gate::new(self.key.clone(), self.match_id, set.clone()) else {
            return false;
        };
        self.ledger = Ledger::with_witnesses(set);
        self.register = Some(gate);
        self.anchor_pending = true;
        true
    }

    pub fn witness_quorum_enabled(&self) -> bool {
        self.register.is_some()
    }

    /// Recovery is blocked: fewer than a quorum of witnesses has answered (or the adopted head
    /// could not be reconciled). Nothing is signed and nothing times out into signing.
    pub fn recovery_blocked(&self) -> bool {
        self.register.as_ref().is_some_and(Gate::recovering)
    }

    /// Next register message for the witnesses (`None` = every witness). Behind the same
    /// write-ahead barrier as all signed output.
    pub fn poll_quorum(&mut self) -> Option<(Option<ParticipantId>, QuorumMsg)> {
        let g = self.register.as_ref()?;
        if g.phase() != Phase::Recovering && !self.make_durable() {
            return None;
        }
        self.register.as_mut()?.poll_out()
    }

    /// A register message from a pinned witness (its identity authenticated by the link).
    pub fn on_quorum(&mut self, from: ParticipantId, msg: QuorumMsg) {
        let Some(g) = self.register.as_mut() else {
            return;
        };
        if !g.witnesses().contains(&from) {
            return;
        }
        if let QuorumMsg::Held { claim, receipt } = msg {
            for e in g.gatherer.on_held(claim, receipt) {
                self.submit(&e, true);
            }
            return;
        }
        let steps = g.on_msg(msg);
        self.apply_steps(steps);
    }

    fn apply_steps(&mut self, steps: Vec<Step>) {
        for step in steps {
            match step {
                Step::Recovered(claim) => self.finish_quorum_recovery(claim),
                Step::Released(a) => self.release(*a),
                Step::Fenced(newer) => {
                    self.fenced = true;
                    self.events.push_back(AuditEvent::Fenced { newer });
                }
            }
        }
    }

    /// Reconcile the local log with the head a witness quorum holds, then start committing.
    fn finish_quorum_recovery(&mut self, claim: Option<Claim>) {
        let seq = claim.as_ref().map(|c| c.auth.seq);
        let floor = claim.as_ref().map_or(0, |c| c.through_tick);
        match &claim {
            Some(c) => {
                self.supply_anchor(&c.auth);
                self.rebase_on_anchor();
            }
            None => {
                self.confirm_no_prior_heads();
            }
        }
        self.events.push_back(AuditEvent::QuorumRecovered { seq });
        if !self.recovery.may_sign() {
            return; // stays blocked and visible: RecoveryNotTrusted was reported
        }
        if self.register.as_mut().is_some_and(|g| g.activate(floor)) {
            self.anchor_pending = false;
        }
    }

    /// A committed head leaves for the peers; it is now an anchor for crash recovery too.
    fn release(&mut self, a: Authenticator) {
        self.pin(&a);
        self.stats.authenticators_sent += 1;
        self.outbox.push_back(Outgoing::all(PipeMsg::Auth(a)));
    }

    /// Everything stamped `(tick, seq)` is covered by a committed head (always true without a
    /// register).
    pub(crate) fn release_covers(&self, tick: u64, seq: u64) -> bool {
        self.register.as_ref().is_none_or(|g| g.covers(tick, seq))
    }

    /// Something stamped `(tick, seq)` is waiting for a committed head.
    pub(crate) fn want_cover(&mut self, tick: u64, seq: u64) {
        if let Some(g) = self.register.as_mut() {
            g.want(tick, seq);
        }
    }

    /// Ticks below this were covered by a previous incarnation's claim: sign nothing there.
    pub(crate) fn sign_floor(&self) -> u64 {
        self.register.as_ref().map_or(0, Gate::floor)
    }

    pub(crate) fn log_len(&self) -> u64 {
        self.log.len()
    }

    /// Time-driven register work: retransmit, propose a head when something waits, expire
    /// uncertifiable findings.
    pub(super) fn pump_register(&mut self) {
        let now = self.now;
        let ready = !self.fenced && self.recovery.may_sign() && !self.anchor_pending;
        let Some(g) = self.register.as_mut() else {
            return;
        };
        g.retransmit(now);
        g.gatherer.expire(now);
        if ready && g.needs_claim() && self.make_durable() {
            let a = self.log.sign_authenticator(self.ruleset, &self.key);
            if let Some(g) = self.register.as_mut() {
                g.propose(a, now);
            }
        }
    }

    /// Equivocation findings need certificates before they can convict: start gathering them.
    /// Returns true if the finding was taken over by the register.
    pub(super) fn certify_finding(&mut self, e: &Evidence) -> bool {
        let plain = matches!(
            e,
            Evidence::ConflictingAuthenticators(..) | Evidence::Fork { .. }
        );
        let now = self.now;
        let Some(g) = self.register.as_mut().filter(|_| plain) else {
            return false;
        };
        if e.verify_under(None).is_ok() {
            for m in g.gatherer.start(e.clone(), now) {
                g.queue(None, m);
            }
        }
        true
    }

    /// The committed head to hand out when a peer asks for my current authenticator.
    pub(super) fn current_authenticator(&self) -> Option<Authenticator> {
        match &self.register {
            Some(g) => g.committed().map(|c| c.claim.auth.clone()),
            None => Some(self.log.sign_authenticator(self.ruleset, &self.key)),
        }
    }
}
