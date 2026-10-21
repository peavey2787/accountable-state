//! A durable, self-describing single-epoch receipt: BOTH checkpoint signatures,
//! BOTH signed packed input streams, the previous public state, and the externally
//! trusted predecessor commitment. Never infer an accepted history from this file
//! without authenticating match genesis or earlier certified checkpoints.
use super::{
    verify_checkpoint_evidence_with, CheckpointError, CheckpointEvidence, Epoch, EvidenceVerdict,
};
use gv_core::{Digest, PlayerId};
use gv_replay::GameRules;

const MAGIC: &[u8] = b"GV-CERTIFIED-EPOCH/V1\0";
#[derive(Clone, Debug)]
pub struct CertifiedEpoch {
    pub witnesses: [CheckpointEvidence; 2],
}
impl CertifiedEpoch {
    pub fn from_accepted(epoch: &Epoch, roster: [PlayerId; 2]) -> Result<Self, CheckpointError> {
        let Some(signatures) = epoch.signatures.clone() else {
            return Err(CheckpointError::InvalidEvidence);
        };
        if signatures[0].player != roster[0]
            || signatures[1].player != roster[1]
            || signatures[0].claim != signatures[1].claim
        {
            return Err(CheckpointError::InvalidEvidence);
        }
        Ok(Self {
            witnesses: [0usize, 1].map(|i| CheckpointEvidence {
                trusted_previous_checkpoint: epoch.checkpoint.previous_checkpoint,
                trusted_previous_state: epoch.checkpoint.previous_state,
                accused: signatures[i].clone(),
                previous_state: epoch.previous_state.clone(),
                player_batches: epoch.batches.clone(),
                roster,
            }),
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, CheckpointError> {
        let mut out = MAGIC.to_vec();
        for witness in &self.witnesses {
            let bytes = witness.encode()?;
            let n = u32::try_from(bytes.len()).map_err(|_| CheckpointError::InvalidEvidence)?;
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CheckpointError> {
        if bytes.len() > 4_000_000 || !bytes.starts_with(MAGIC) {
            return Err(CheckpointError::InvalidEvidence);
        };
        let mut pos = MAGIC.len();
        let mut witnesses = Vec::with_capacity(2);
        for _ in 0..2 {
            let end = pos.checked_add(4).ok_or(CheckpointError::InvalidEvidence)?;
            let len_bytes: [u8; 4] = bytes
                .get(pos..end)
                .ok_or(CheckpointError::InvalidEvidence)?
                .try_into()
                .map_err(|_| CheckpointError::InvalidEvidence)?;
            pos = end;
            let len = u32::from_le_bytes(len_bytes) as usize;
            if len > 1_000_000 {
                return Err(CheckpointError::InvalidEvidence);
            };
            let end = pos
                .checked_add(len)
                .ok_or(CheckpointError::InvalidEvidence)?;
            witnesses.push(CheckpointEvidence::decode(
                bytes
                    .get(pos..end)
                    .ok_or(CheckpointError::InvalidEvidence)?,
            )?);
            pos = end;
        }
        if pos != bytes.len() {
            return Err(CheckpointError::InvalidEvidence);
        };
        Ok(Self {
            witnesses: witnesses
                .try_into()
                .map_err(|_| CheckpointError::InvalidEvidence)?,
        })
    }
    pub fn verify<R: GameRules>(
        &self,
        rules: &R,
        known_previous_checkpoint: Digest,
        known_previous_state: Digest,
    ) -> EvidenceVerdict {
        self.verify_with(
            rules,
            known_previous_checkpoint,
            known_previous_state,
            false,
        )
    }
    pub fn verify_with<R: GameRules>(
        &self,
        rules: &R,
        known_previous_checkpoint: Digest,
        known_previous_state: Digest,
        sanitize: bool,
    ) -> EvidenceVerdict {
        let [a, b] = &self.witnesses;
        if a.roster != b.roster
            || a.roster[0] >= a.roster[1]
            || a.accused.player != a.roster[0]
            || b.accused.player != a.roster[1]
            || a.accused.claim != b.accused.claim
            || a.player_batches != b.player_batches
            || a.previous_state != b.previous_state
            || a.trusted_previous_checkpoint != known_previous_checkpoint
            || a.trusted_previous_state != known_previous_state
            || b.trusted_previous_checkpoint != known_previous_checkpoint
            || b.trusted_previous_state != known_previous_state
        {
            return EvidenceVerdict::Inconclusive(CheckpointError::InvalidHistory);
        }
        match verify_checkpoint_evidence_with(rules, a, sanitize) {
            EvidenceVerdict::ValidClaim => verify_checkpoint_evidence_with(rules, b, sanitize),
            other => other,
        }
    }
    /// Exact certified head; valid only after `verify(...)` returns ValidClaim.
    pub fn checkpoint_hash(&self) -> Digest {
        self.witnesses[0].accused.claim.digest()
    }
}
