//! Reconnection of one participant: authenticated resume, incarnation fencing, and catch-up from
//! certified epochs. Nothing here is trusted: a proof is a fresh signature over the verifier's
//! nonce, and every epoch served is re-verified and replayed by `apply_certified`.
//! A silent peer is only ever a suspicion; the grace period just tells the application when to
//! apply its deterministic exclusion policy.
use super::config::{PeerEvent, PipeEvent};
use super::{Pipeline, Stage, Stamped};
use crate::live::msg::{Outgoing, PipeMsg};
use crate::live::resume::{ResumeMsg, SignedProof, MAX_EPOCHS_PER_MSG};
use crate::{CertifiedEpoch, StateMachine};
use gv_core::ParticipantId;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct ResumeState {
    pub(super) incarnation: u64,
    session_id: [u8; 16],
    challenged: BTreeMap<ParticipantId, [u8; 16]>,
    proven: BTreeMap<ParticipantId, SignedProof>,
    down_since: BTreeMap<ParticipantId, u64>,
    /// When each peer was last asked for epochs, to pace repeated requests.
    asked_at: BTreeMap<ParticipantId, u64>,
}

/// Ticks between sync requests to the same peer.
const RESYNC_EVERY_TICKS: u64 = 20;

fn nonce() -> [u8; 16] {
    gv_sig::random_32().map_or([0; 16], |r| r[..16].try_into().unwrap_or([0; 16]))
}

impl ResumeState {
    pub(super) fn new(incarnation: u64) -> Self {
        Self {
            incarnation,
            session_id: nonce(),
            ..Self::default()
        }
    }
}

impl<R: StateMachine + Clone> Pipeline<R> {
    /// The link to `peer` is up (first connection or reconnection): demand a fresh proof of key
    /// possession. Idempotent; a new call replaces the outstanding nonce.
    pub fn peer_up(&mut self, peer: ParticipantId) {
        if peer == self.me || self.session.roster.find(&peer).is_none() {
            return;
        }
        let n = nonce();
        self.resume.challenged.insert(peer, n);
        self.resume.down_since.remove(&peer);
        self.send(peer, ResumeMsg::Challenge { nonce: n });
    }

    /// The link to `peer` dropped at `now`. Starts the grace period and forgets the proof, so
    /// the peer must prove itself again.
    pub fn peer_down(&mut self, peer: ParticipantId, now: u64) {
        self.resume.proven.remove(&peer);
        self.resume.challenged.remove(&peer);
        self.resume.down_since.entry(peer).or_insert(now);
        self.events
            .push_back(PipeEvent::Peer(PeerEvent::Down { peer }));
    }

    pub fn is_proven(&self, peer: &ParticipantId) -> bool {
        self.resume.proven.contains_key(peer)
    }

    /// Peers whose grace period ran out are reported once; the application applies its policy
    /// (continue / exclude / forfeit). Not proof of anything.
    pub(super) fn expire_grace(&mut self, now: u64) {
        let grace = self.cfg.peer_grace_ticks;
        let expired: Vec<_> = self
            .resume
            .down_since
            .iter()
            .filter(|(_, since)| now.saturating_sub(**since) >= grace)
            .map(|(p, s)| (*p, *s))
            .collect();
        for (peer, since) in expired {
            self.resume.down_since.remove(&peer);
            self.events
                .push_back(PipeEvent::Peer(PeerEvent::GraceExpired { peer, since }));
        }
    }

    fn send(&mut self, peer: ParticipantId, msg: ResumeMsg) {
        self.outbox.push_back(Stamped {
            out: Outgoing::to(peer, PipeMsg::Resume(msg)),
            tick: 0,
            seq: 0,
        });
    }

    /// A proven peer is working on a tick beyond my verified head: fetch what I am missing
    /// (rate-limited per peer; the peer's answer is verified like any other).
    pub(super) fn note_peer_ahead(&mut self, from: ParticipantId, their_tick: u64, now: u64) {
        let tip = self.ws();
        let due = self
            .resume
            .asked_at
            .get(&from)
            .is_none_or(|t| now >= t + RESYNC_EVERY_TICKS);
        if their_tick > tip && due && self.resume.proven.contains_key(&from) {
            self.resume.asked_at.insert(from, now);
            self.send(from, ResumeMsg::Sync { tip });
        }
    }

    pub(super) fn on_resume(&mut self, from: ParticipantId, msg: ResumeMsg) {
        match msg {
            ResumeMsg::Challenge { nonce } => self.answer_challenge(from, nonce),
            ResumeMsg::Proof(p) => self.on_proof(from, p),
            ResumeMsg::Sync { tip } => self.serve_epochs(from, tip),
            ResumeMsg::Epochs { epochs, tip } => self.apply_epochs(from, &epochs, tip),
            ResumeMsg::Superseded => self
                .events
                .push_back(PipeEvent::Peer(PeerEvent::Superseded { peer: from })),
        }
    }

    fn answer_challenge(&mut self, from: ParticipantId, nonce: [u8; 16]) {
        let tip = self.ws();
        let proof = SignedProof::sign(
            self.session.match_id,
            self.resume.incarnation,
            self.resume.session_id,
            tip,
            nonce,
            &self.key,
        );
        self.send(from, ResumeMsg::Proof(proof));
        self.send(from, ResumeMsg::Sync { tip });
    }

    fn on_proof(&mut self, from: ParticipantId, p: SignedProof) {
        let fresh = self.resume.challenged.get(&from) == Some(&p.nonce);
        if !fresh || p.participant != from || p.match_id != self.session.match_id {
            return; // unsolicited, replayed or for another match: ignore
        }
        self.resume.challenged.remove(&from);
        if self
            .resume
            .proven
            .get(&from)
            .is_some_and(|old| !p.outranks(old))
        {
            self.send(from, ResumeMsg::Superseded);
            return;
        }
        let incarnation = p.incarnation;
        self.resume.proven.insert(from, p);
        self.events.push_back(PipeEvent::Peer(PeerEvent::Resumed {
            peer: from,
            incarnation,
        }));
    }

    fn serve_epochs(&mut self, from: ParticipantId, tip: u64) {
        if !self.resume.proven.contains_key(&from) {
            return; // only an authenticated, current incarnation is served
        }
        let epochs: Vec<CertifiedEpoch> = self
            .replica
            .accepted()
            .iter()
            .filter(|e| e.checkpoint.epoch_start >= tip)
            .map_while(|e| CertifiedEpoch::from_accepted(e, &self.session).ok())
            .take(MAX_EPOCHS_PER_MSG)
            .collect();
        let mine = self.ws();
        self.send(from, ResumeMsg::Epochs { epochs, tip: mine });
    }

    fn apply_epochs(&mut self, from: ParticipantId, epochs: &[CertifiedEpoch], tip: u64) {
        if !self.resume.proven.contains_key(&from) {
            return;
        }
        let before = self.ws();
        self.replica.discard_pending();
        for cert in epochs {
            if cert.evidence.accused.claim.epoch_start != self.ws() {
                continue; // already have it, or a gap this peer cannot fill
            }
            if let Err(e) = self.replica.apply_certified(cert) {
                self.fault(format!("synced epoch rejected: {e:?}"));
                break;
            }
        }
        let reached = self.ws();
        if reached == before {
            return;
        }
        self.realign(before, reached);
        if tip > reached {
            self.send(from, ResumeMsg::Sync { tip: reached });
        } else {
            self.events
                .push_back(PipeEvent::Peer(PeerEvent::CaughtUp { tick: reached }));
        }
    }

    /// The chain head moved by sync: drop the in-flight epoch (it was for the old head) and tell
    /// the application, which jumps its verified state forward.
    fn realign(&mut self, from_tick: u64, to_tick: u64) {
        self.collect.reset_epoch();
        self.early_ckpt.clear();
        self.stage = Stage::Collect;
        self.events.push_back(PipeEvent::Finalized {
            start: from_tick,
            end: to_tick,
            checkpoint: self.replica.previous_checkpoint(),
            state: self.replica.state().to_vec(),
            disputed: false,
            sealed: false,
        });
        self.epoch_done = true;
    }
}
