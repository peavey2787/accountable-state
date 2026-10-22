//! Owner side of the head register, sans-IO: feed it witness replies, drain what to send.
//!
//! Phases: `Recovering` (collecting promises, possibly blocked below a quorum), `Recovered`
//! (adopted head available, waiting for the host to reconcile its log), `Active` (committing
//! claims) and `Fenced` (a newer incarnation of this owner exists). Nothing here reads a clock;
//! `retransmit` is called by the host and only resends, it never changes a decision.
use super::set::{Ballot, WitnessSet};
use super::wire::{Certificate, Claim, Nack, Promise, QuorumMsg, Receipt, Recover};
use crate::audit::Authenticator;
use gv_core::{Digest, MatchId, ParticipantId};
use gv_sig::SigningKey;
use std::collections::{BTreeMap, VecDeque};

/// Largest ballot-counter jump when chasing a Nack, so a lying witness cannot exhaust counters.
const MAX_JUMP: u64 = 1 << 16;
/// Claims kept awaiting a quorum.
const MAX_PENDING: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Recovering,
    Recovered,
    Active,
    Fenced,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A quorum of promises: the newest committed claim (none for a fresh owner).
    Recovered(Option<Claim>),
    /// A claim reached a quorum of receipts.
    Certified(Box<Certificate>),
    /// `f + 1` witnesses report a newer incarnation: this one must stop signing.
    Fenced(Ballot),
}

struct Pending {
    claim: Claim,
    receipts: BTreeMap<ParticipantId, Receipt>,
}

pub struct Registrar {
    key: SigningKey,
    match_id: MatchId,
    set: WitnessSet,
    ballot: Ballot,
    phase: Phase,
    promises: BTreeMap<ParticipantId, Promise>,
    nacks: BTreeMap<ParticipantId, Nack>,
    pending: BTreeMap<Digest, Pending>,
    out: VecDeque<(Option<ParticipantId>, QuorumMsg)>,
    events: VecDeque<Event>,
}

impl Registrar {
    /// `ballot` must be above any ballot this owner used before; a fresh nonce keeps duplicate
    /// processes of one owner apart.
    pub fn new(key: SigningKey, match_id: MatchId, set: WitnessSet, ballot: Ballot) -> Self {
        let mut r = Self {
            key,
            match_id,
            set,
            ballot,
            phase: Phase::Recovering,
            promises: BTreeMap::new(),
            nacks: BTreeMap::new(),
            pending: BTreeMap::new(),
            out: VecDeque::new(),
            events: VecDeque::new(),
        };
        r.broadcast_recover();
        r
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn ballot(&self) -> Ballot {
        self.ballot
    }
    pub fn witnesses(&self) -> &WitnessSet {
        &self.set
    }
    pub fn poll_out(&mut self) -> Option<(Option<ParticipantId>, QuorumMsg)> {
        self.out.pop_front()
    }
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn broadcast_recover(&mut self) {
        let m = Recover::sign(self.match_id, self.ballot, &self.key);
        self.out.push_back((None, QuorumMsg::Recover(m)));
    }

    /// Resend whatever is still unanswered. Never decides anything.
    pub fn retransmit(&mut self) {
        match self.phase {
            Phase::Recovering => self.broadcast_recover(),
            Phase::Active => {
                for p in self.pending.values() {
                    self.out
                        .push_back((None, QuorumMsg::Store(p.claim.clone())));
                }
            }
            Phase::Recovered | Phase::Fenced => {}
        }
    }

    pub fn on_promise(&mut self, p: Promise) {
        let valid = self.phase == Phase::Recovering
            && p.ballot == self.ballot
            && p.match_id == self.match_id
            && p.owner == self.key.id()
            && self.set.contains(&p.witness)
            && p.verify().is_ok();
        if !valid {
            return;
        }
        self.promises.entry(p.witness).or_insert(p);
        if self.promises.len() >= self.set.quorum() {
            self.phase = Phase::Recovered;
            let adopted = self.newest_accepted();
            self.events.push_back(Event::Recovered(adopted));
        }
    }

    fn newest_accepted(&self) -> Option<Claim> {
        self.promises
            .values()
            .filter_map(|p| p.accepted.as_ref())
            .max_by_key(|c| (c.ballot, c.auth.seq, c.through_tick))
            .cloned()
    }

    /// The host has reconciled its log with the adopted head and may now commit claims.
    pub fn activate(&mut self) -> bool {
        if self.phase != Phase::Recovered {
            return false;
        }
        self.phase = Phase::Active;
        true
    }

    /// Commit `auth` (covering batches and checkpoints through `through_tick`). Returns the
    /// claim's digest, or `None` if not active or too many claims are already waiting.
    pub fn propose(&mut self, auth: Authenticator, through_tick: u64) -> Option<Digest> {
        if self.phase != Phase::Active || self.pending.len() >= MAX_PENDING {
            return None;
        }
        let claim = Claim::sign(self.ballot, auth, through_tick, &self.key);
        let digest = claim.digest();
        self.out.push_back((None, QuorumMsg::Store(claim.clone())));
        self.pending.insert(
            digest,
            Pending {
                claim,
                receipts: BTreeMap::new(),
            },
        );
        Some(digest)
    }

    pub fn on_receipt(&mut self, r: Receipt) {
        if !self.set.contains(&r.witness) || r.verify().is_err() {
            return;
        }
        let Some(p) = self.pending.get_mut(&r.claim) else {
            return;
        };
        let digest = r.claim;
        p.receipts.entry(r.witness).or_insert(r);
        if p.receipts.len() >= self.set.quorum() {
            if let Some(done) = self.pending.remove(&digest) {
                self.events
                    .push_back(Event::Certified(Box::new(Certificate {
                        claim: done.claim,
                        receipts: done.receipts.into_values().collect(),
                    })));
            }
        }
    }

    pub fn on_nack(&mut self, n: Nack) {
        let valid = n.match_id == self.match_id
            && n.owner == self.key.id()
            && n.promised > self.ballot
            && self.set.contains(&n.witness)
            && n.verify().is_ok();
        if !valid || self.phase == Phase::Fenced {
            return;
        }
        self.nacks.entry(n.witness).or_insert(n);
        if self.nacks.len() < self.set.fence_threshold() {
            return;
        }
        let newest = self
            .nacks
            .values()
            .map(|n| n.promised)
            .max()
            .unwrap_or(self.ballot);
        self.nacks.clear();
        if self.phase == Phase::Recovering {
            self.restart_above(newest);
        } else {
            self.phase = Phase::Fenced;
            self.pending.clear();
            self.events.push_back(Event::Fenced(newest));
        }
    }

    /// A recovering owner that finds a newer ballot simply retries above it.
    fn restart_above(&mut self, newest: Ballot) {
        let counter = newest
            .counter
            .saturating_add(1)
            .min(self.ballot.counter.saturating_add(MAX_JUMP));
        self.ballot = Ballot {
            counter,
            nonce: self.ballot.nonce,
        };
        self.promises.clear();
        self.broadcast_recover();
    }
}
