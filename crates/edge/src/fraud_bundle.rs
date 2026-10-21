//! Standalone self-contained fraud evidence: authenticated certified history
//! PLUS the disputed next signed state claim. No quorum votes on validity.
#![forbid(unsafe_code)]
use super::{
    verify_checkpoint_evidence_with, CertifiedMatch, CheckpointError, CheckpointEvidence,
    EdgeError, EvidenceVerdict, PublicRules,
};
use gv_commitments::commit_state;
use gv_core::{MatchId, PlayerId, StateOpening};

const MAGIC: &[u8] = b"GV-FRAUD-BUNDLE/V1\0";
const MAX_BYTES: usize = 64 * 1024 * 1024;
#[derive(Clone, Debug)]
pub struct FraudBundle {
    pub history: CertifiedMatch,
    pub allegation: CheckpointEvidence,
}
impl FraudBundle {
    pub fn encode(&self) -> Result<Vec<u8>, EdgeError> {
        let history = self.history.encode()?;
        let evidence = self
            .allegation
            .encode()
            .map_err(|_| EdgeError::BadCheckpoint)?;
        let mut b = MAGIC.to_vec();
        if history
            .len()
            .checked_add(evidence.len())
            .and_then(|n| n.checked_add(b.len() + 8))
            .is_none_or(|n| n > MAX_BYTES)
        {
            return Err(EdgeError::ResourceLimit);
        }
        b.extend_from_slice(&(history.len() as u32).to_le_bytes());
        b.extend_from_slice(&history);
        b.extend_from_slice(&(evidence.len() as u32).to_le_bytes());
        b.extend_from_slice(&evidence);
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, EdgeError> {
        if b.len() > MAX_BYTES || !b.starts_with(MAGIC) {
            return Err(EdgeError::BadCheckpoint);
        }
        let mut pos = MAGIC.len();
        fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8], EdgeError> {
            let e = p.checked_add(n).ok_or(EdgeError::BadCheckpoint)?;
            let bytes = b.get(*p..e).ok_or(EdgeError::BadCheckpoint)?;
            *p = e;
            Ok(bytes)
        }
        let n = u32::from_le_bytes(
            take(b, &mut pos, 4)?
                .try_into()
                .map_err(|_| EdgeError::BadCheckpoint)?,
        ) as usize;
        if n > MAX_BYTES {
            return Err(EdgeError::ResourceLimit);
        }
        let history = CertifiedMatch::decode(take(b, &mut pos, n)?)?;
        let m = u32::from_le_bytes(
            take(b, &mut pos, 4)?
                .try_into()
                .map_err(|_| EdgeError::BadCheckpoint)?,
        ) as usize;
        if m > 512 * 1024 {
            return Err(EdgeError::ResourceLimit);
        }
        let allegation = CheckpointEvidence::decode(take(b, &mut pos, m)?)
            .map_err(|_| EdgeError::BadCheckpoint)?;
        if pos != b.len() {
            return Err(EdgeError::BadCheckpoint);
        }
        Ok(Self {
            history,
            allegation,
        })
    }
    /// The verifier receives the match ID and BOTH player public keys through
    /// an independently trusted invitation / tournament manifest.
    pub fn verify<R: PublicRules + Clone>(
        &self,
        match_id: MatchId,
        roster: [PlayerId; 2],
        rules: R,
    ) -> EvidenceVerdict {
        let fail = || EvidenceVerdict::Inconclusive(CheckpointError::InvalidHistory);
        let Ok(replica) = self.history.restore(match_id, roster, rules.clone()) else {
            return fail();
        };
        let claim = &self.allegation.accused.claim;
        if claim.match_id != match_id
            || claim.epoch_start != replica.next_tick()
            || claim.previous_checkpoint != replica.previous_checkpoint()
            || claim.previous_state
                != commit_state(&StateOpening {
                    bytes: replica.state().to_vec(),
                    nonce: [0; 32],
                })
            || self.allegation.trusted_previous_checkpoint != replica.previous_checkpoint()
            || self.allegation.trusted_previous_state != claim.previous_state
            || self.allegation.roster != replica.roster
            || self.allegation.previous_state.as_slice() != replica.state()
        {
            return fail();
        }
        verify_checkpoint_evidence_with(&rules, &self.allegation, self.history.live)
    }
}
