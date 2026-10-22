//! Answers for challenge kinds that need replica data (replay evidence, Merkle witnesses,
//! sealed reveals).
use super::sealed::Sealed;
use crate::audit::{Challenge, ChallengeKind as K};
use crate::live::auditor::Answers;
use crate::live::msg::{Opening, PipeMsg};
use crate::{BatchCommitment, CertifiedEpoch, EvidenceVerdict, MatchReplica, StateMachine};
use gv_core::{ParticipantId, Session};

pub(super) struct ReplicaAnswers<'a, R: StateMachine + Clone> {
    pub(super) replica: &'a MatchReplica<R>,
    pub(super) rules: &'a R,
    pub(super) session: &'a Session,
    pub(super) sealed: &'a Sealed,
    pub(super) me: ParticipantId,
}

impl<R: StateMachine + Clone> ReplicaAnswers<'_, R> {
    fn epoch_at(&self, tick: u64) -> Option<&crate::Epoch> {
        self.replica.accepted().iter().find(|e| {
            e.signatures.is_some()
                && e.checkpoint.epoch_start <= tick
                && tick < e.checkpoint.epoch_start + u64::from(e.checkpoint.epoch_length)
        })
    }
    fn my_opening(&self, start_tick: u64) -> Option<Vec<u8>> {
        let w = self.sealed.window.as_ref().filter(|w| w.owner == self.me)?;
        let cell = w
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
    fn opening_matches(&self, c: &Challenge, start_tick: u64, payload: &[u8]) -> bool {
        let Some(w) = self.sealed.window.as_ref() else {
            return false;
        };
        let Some(cell) = w.cells.iter().find(|x| x.start == start_tick) else {
            return false;
        };
        let (Some(commit), Ok(PipeMsg::Reveal(o))) =
            (cell.commits.get(&c.target), PipeMsg::decode(payload))
        else {
            return false;
        };
        o.batch.verify().is_ok()
            && o.batch.record.participant == c.target
            && o.batch.record.start_tick == start_tick
            && BatchCommitment::blind_batch(&o.batch, &o.blind).ok()
                == Some(commit.claim.blinded_batch_hash)
    }
    fn certified_epoch_matches(&self, tick: u64, payload: &[u8]) -> bool {
        let (Some(mine), Ok(cert)) = (self.epoch_at(tick), CertifiedEpoch::decode(payload)) else {
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
}

impl<R: StateMachine + Clone> Answers for ReplicaAnswers<'_, R> {
    fn answer(&self, c: &Challenge) -> Option<Vec<u8>> {
        match c.kind {
            K::Replay { epoch_start: t } | K::MerkleWitness { epoch_start: t } => {
                let e = self.epoch_at(t)?;
                CertifiedEpoch::from_accepted(e, self.session)
                    .ok()?
                    .encode()
                    .ok()
            }
            K::SealedReveal { start_tick } => self.my_opening(start_tick),
            _ => None,
        }
    }
    fn check(&self, c: &Challenge, payload: &[u8]) -> bool {
        match c.kind {
            K::Replay { epoch_start: t } | K::MerkleWitness { epoch_start: t } => {
                self.certified_epoch_matches(t, payload)
            }
            K::SealedReveal { start_tick } => self.opening_matches(c, start_tick, payload),
            _ => false,
        }
    }
}
