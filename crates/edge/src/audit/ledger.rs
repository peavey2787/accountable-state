//! Deterministic evidence ledger: canonical ids, duplicate suppression, bounded
//! processing, per-accused verdicts, counterproofs and witness assignment.
//! Replaying the same evidence set in any order yields the same verdicts.
use super::challenge::Status;
use super::evidence::{Evidence, EvidenceError, Proof};
use crate::{verify_checkpoint_evidence_with, CertifiedEpoch, CheckpointEvidence, EvidenceVerdict};
use gv_core::{Digest, MatchId, PlayerId};
use gv_replay::GameRules;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_LEDGER_ENTRIES: usize = 1024;
pub const MAX_PER_ACCUSED: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// New, verified; the accused's status may have changed.
    Recorded(Status),
    Duplicate,
    /// Did not verify: proves nothing, costs the accused nothing.
    Rejected(EvidenceError),
    /// Verified but over a bound; dropped deterministically.
    Dropped,
    /// An accusation was disproved by a counterproof.
    Exonerated,
    /// Replay evidence the verifier cannot decide from its trusted history.
    Inconclusive,
}

#[derive(Debug, Default)]
pub struct Ledger {
    entries: BTreeMap<Digest, (PlayerId, Status)>,
    per_accused: BTreeMap<PlayerId, usize>,
    /// Accusations (by id) proven false; ignored forever, never re-litigated.
    exonerated: BTreeSet<Digest>,
    /// Non-proof statuses (suspicion/cleared), by accused.
    soft: BTreeMap<PlayerId, Status>,
}

fn replay_id(e: &CheckpointEvidence) -> Digest {
    let mut s = Sha256::new();
    s.update(b"gv/audit/replay-accusation-id/v1\0");
    s.update(e.accused.claim.digest());
    s.update(e.accused.player);
    s.update(e.trusted_previous_checkpoint);
    s.update(e.trusted_previous_state);
    s.finalize().into()
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn contains(&self, id: &Digest) -> bool {
        self.entries.contains_key(id)
    }
    pub fn ids(&self) -> Vec<Digest> {
        self.entries.keys().copied().collect()
    }
    fn admit(&mut self, id: Digest, accused: PlayerId, s: Status) -> Outcome {
        if self.exonerated.contains(&id) || self.entries.contains_key(&id) {
            return Outcome::Duplicate;
        }
        let n = self.per_accused.entry(accused).or_insert(0);
        if self.entries.len() >= MAX_LEDGER_ENTRIES || *n >= MAX_PER_ACCUSED {
            return Outcome::Dropped;
        }
        *n += 1;
        self.entries.insert(id, (accused, s));
        Outcome::Recorded(s)
    }
    /// Self-proving equivocation evidence.
    pub fn submit(&mut self, e: &Evidence, roster: &[PlayerId]) -> Outcome {
        let id = match e.id() {
            Ok(id) => id,
            Err(x) => return Outcome::Rejected(x),
        };
        let Proof::Equivocation(p) = match e.verify() {
            Ok(p) => p,
            Err(x) => return Outcome::Rejected(x),
        };
        // Evidence about strangers is not about this match's participants.
        if !roster.contains(&p) {
            return Outcome::Rejected(EvidenceError::NotAViolation);
        }
        self.admit(id, p, Status::ProvenEquivocation)
    }
    /// A replay accusation: the checkpoint's signer claims a bad state transition.
    /// `rules` + trusted predecessor decide it; a wrong premise is INCONCLUSIVE and
    /// never records anything against the accused.
    pub fn submit_replay<R: GameRules>(
        &mut self,
        rules: &R,
        e: &CheckpointEvidence,
        sanitize: bool,
    ) -> Outcome {
        let id = replay_id(e);
        match verify_checkpoint_evidence_with(rules, e, sanitize) {
            EvidenceVerdict::ProvenInvalidState => {
                self.admit(id, e.accused.player, Status::ProvenFraud)
            }
            EvidenceVerdict::ProvenInvalidAction(p) => self.admit(id, p, Status::ProvenFraud),
            EvidenceVerdict::ValidClaim | EvidenceVerdict::Inconclusive(_) => Outcome::Inconclusive,
        }
    }
    /// Counterproof: a dual-signed certified epoch that verifies under the same
    /// trusted predecessor and matches the accused claim shows the allegation is
    /// false. Exonerates the accusation id; counterproofs are final (no further
    /// accusation about the same premise, so no ping-pong).
    pub fn counterproof<R: GameRules>(
        &mut self,
        rules: &R,
        accusation: &CheckpointEvidence,
        proof: &CertifiedEpoch,
        sanitize: bool,
    ) -> Outcome {
        let id = replay_id(accusation);
        let same_claim = proof.checkpoint_hash() == accusation.accused.claim.digest();
        let ok = same_claim
            && proof.verify_with(
                rules,
                accusation.trusted_previous_checkpoint,
                accusation.trusted_previous_state,
                sanitize,
            ) == EvidenceVerdict::ValidClaim;
        if !ok {
            return Outcome::Rejected(EvidenceError::NotAViolation);
        }
        if let Some((who, _)) = self.entries.remove(&id) {
            if let Some(n) = self.per_accused.get_mut(&who) {
                *n = n.saturating_sub(1);
            }
        }
        self.exonerated.insert(id);
        self.soft.insert(accusation.accused.player, Status::Cleared);
        Outcome::Exonerated
    }
    pub fn mark_soft(&mut self, who: PlayerId, s: Status) {
        if !s.is_proof() {
            self.soft.insert(who, s);
        }
    }
    /// Strongest verdict about `who`; proof outranks suspicion outranks cleared.
    pub fn status_of(&self, who: &PlayerId) -> Option<Status> {
        let proven = self
            .entries
            .values()
            .filter(|(p, _)| p == who)
            .map(|(_, s)| *s)
            .max();
        match (proven, self.soft.get(who).copied()) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }
    pub fn count(&self, s: Status) -> usize {
        self.entries.values().filter(|(_, x)| *x == s).count()
    }
    pub fn proven_total(&self) -> usize {
        self.entries.len()
    }
    pub fn exonerated_total(&self) -> usize {
        self.exonerated.len()
    }
}

/// Deterministic witness choice: rank roster members by H(match || member) and
/// take the first `k` that are not the audited pair. Witnesses are neither
/// trusted nor required; they only add redundancy for evidence and logs.
pub fn assign_witnesses(
    match_id: &MatchId,
    roster: &[PlayerId],
    exclude: &[PlayerId],
    k: usize,
) -> Vec<PlayerId> {
    let mut ranked: Vec<(Digest, PlayerId)> = roster
        .iter()
        .filter(|p| !exclude.contains(p))
        .map(|p| {
            let mut s = Sha256::new();
            s.update(b"gv/audit/witness-rank/v1\0");
            s.update(match_id);
            s.update(p);
            (s.finalize().into(), *p)
        })
        .collect();
    ranked.sort();
    ranked.dedup_by_key(|(_, p)| *p);
    ranked.into_iter().take(k).map(|(_, p)| p).collect()
}

/// Anti-entropy: ids this side lacks relative to the peer's inventory.
pub fn missing_ids(mine: &Ledger, theirs: &[Digest]) -> Vec<Digest> {
    theirs
        .iter()
        .filter(|i| !mine.contains(i))
        .copied()
        .take(64)
        .collect()
}
