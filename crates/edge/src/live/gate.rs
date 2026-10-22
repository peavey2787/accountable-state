//! The release gate: nothing this participant signs leaves the process until a witness quorum
//! has stored a head that covers it (see [`crate::quorum`]).
//!
//! The gate also drives crash recovery. After a (re)start the registrar reads a quorum of
//! witness promises; fewer than a quorum leaves the participant in the explicit blocked state
//! (`recovering`), with no timeout that could resume it.
use crate::audit::Authenticator;
use crate::quorum::{
    Ballot, Certificate, Claim, Event, Gatherer, Phase, QuorumMsg, Registrar, WitnessSet,
};
use gv_core::{MatchId, ParticipantId};
use gv_sig::SigningKey;
use std::collections::VecDeque;

/// Ticks between retransmissions of an unanswered register message.
const RETRANSMIT_EVERY: u64 = 30;

/// What the auditor must do after feeding the gate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// A quorum of promises arrived: reconcile the local log with the adopted claim.
    Recovered(Option<Claim>),
    /// A head was committed; release the authenticator it carried.
    Released(Box<Authenticator>),
    /// A newer incarnation of this participant exists.
    Fenced(Ballot),
}

pub(crate) struct Gate {
    reg: Registrar,
    pub(crate) gatherer: Gatherer,
    /// Highest committed cover: `(through_tick, seq)`.
    cover: (u64, u64),
    committed: Option<Certificate>,
    in_flight: Option<Authenticator>,
    /// Newest `(tick, seq)` an outbound item is waiting on.
    wanted: (u64, u64),
    /// Ticks below this were covered by a claim of a previous incarnation: this one signs none.
    floor: u64,
    next_retransmit: u64,
    out: VecDeque<(Option<ParticipantId>, QuorumMsg)>,
}

impl Gate {
    pub(crate) fn new(key: SigningKey, match_id: MatchId, set: WitnessSet) -> Option<Self> {
        let nonce = u64::from_le_bytes(gv_sig::random_32().ok()?[..8].try_into().ok()?);
        let ballot = Ballot { counter: 1, nonce };
        let gatherer = Gatherer::new(set.clone());
        let mut g = Self {
            reg: Registrar::new(key, match_id, set, ballot),
            gatherer,
            cover: (0, 0),
            committed: None,
            in_flight: None,
            wanted: (0, 0),
            floor: 0,
            next_retransmit: 0,
            out: VecDeque::new(),
        };
        g.drain();
        Some(g)
    }

    pub(crate) fn witnesses(&self) -> &WitnessSet {
        self.reg.witnesses()
    }
    pub(crate) fn phase(&self) -> Phase {
        self.reg.phase()
    }
    /// Recovery has not yet read a quorum: signing is blocked, not timed out.
    pub(crate) fn recovering(&self) -> bool {
        matches!(self.reg.phase(), Phase::Recovering | Phase::Recovered)
    }
    pub(crate) fn floor(&self) -> u64 {
        self.floor
    }
    /// Is everything stamped `(tick, seq)` covered by a committed head?
    pub(crate) fn covers(&self, tick: u64, seq: u64) -> bool {
        self.cover.0 >= tick && self.cover.1 >= seq
    }
    pub(crate) fn committed(&self) -> Option<&Certificate> {
        self.committed.as_ref()
    }
    pub(crate) fn want(&mut self, tick: u64, seq: u64) {
        self.wanted = (self.wanted.0.max(tick), self.wanted.1.max(seq));
    }
    /// Is a new head needed (something waits that no committed or in-flight head covers)?
    pub(crate) fn needs_claim(&self) -> bool {
        self.reg.phase() == Phase::Active
            && self.in_flight.is_none()
            && !self.covers(self.wanted.0, self.wanted.1)
    }
    pub(crate) fn propose(&mut self, auth: Authenticator, through_tick: u64) {
        if self.reg.propose(auth.clone(), through_tick).is_some() {
            self.in_flight = Some(auth);
        }
        self.drain();
    }
    pub(crate) fn poll_out(&mut self) -> Option<(Option<ParticipantId>, QuorumMsg)> {
        self.out.pop_front()
    }
    pub(crate) fn queue(&mut self, to: Option<ParticipantId>, m: QuorumMsg) {
        self.out.push_back((to, m));
    }

    /// Reconciliation finished; the participant may commit heads.
    pub(crate) fn activate(&mut self, floor: u64) -> bool {
        self.floor = floor;
        self.reg.activate()
    }

    pub(crate) fn retransmit(&mut self, now: u64) {
        if now < self.next_retransmit {
            return;
        }
        self.next_retransmit = now + RETRANSMIT_EVERY;
        self.reg.retransmit();
        for m in self.gatherer.requests() {
            self.out.push_back((None, m));
        }
        self.drain();
    }

    pub(crate) fn on_msg(&mut self, m: QuorumMsg) -> Vec<Step> {
        match m {
            QuorumMsg::Promise(p) => self.reg.on_promise(p),
            QuorumMsg::Receipt(r) => self.reg.on_receipt(r),
            QuorumMsg::Nack(n) => self.reg.on_nack(n),
            _ => {}
        }
        self.drain();
        self.steps()
    }

    fn drain(&mut self) {
        while let Some(o) = self.reg.poll_out() {
            self.out.push_back(o);
        }
    }

    fn steps(&mut self) -> Vec<Step> {
        let mut steps = Vec::new();
        while let Some(e) = self.reg.poll_event() {
            match e {
                Event::Recovered(c) => steps.push(Step::Recovered(c)),
                Event::Certified(cert) => steps.extend(self.commit(*cert)),
                Event::Fenced(b) => steps.push(Step::Fenced(b)),
            }
        }
        steps
    }

    fn commit(&mut self, cert: Certificate) -> Option<Step> {
        let released = self
            .in_flight
            .take_if(|a| *a == cert.claim.auth)
            .map(Box::new)
            .map(Step::Released);
        self.cover = (
            self.cover.0.max(cert.claim.through_tick),
            self.cover.1.max(cert.claim.auth.seq),
        );
        self.committed = Some(cert);
        released
    }
}
