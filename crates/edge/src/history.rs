//! A durable, self-describing single-epoch receipt: the signatures that satisfy the session's
//! certification policy, every participant's signed input stream, the previous public state and
//! the externally trusted predecessor commitment. Never infer an accepted history from this file
//! without authenticating match genesis or earlier certified checkpoints.
use super::{
    verify_checkpoint_evidence_with, CheckpointError, CheckpointEvidence, Epoch, EvidenceVerdict,
    SignedCheckpoint,
};
use gv_core::Digest;
use gv_replay::StateMachine;

const MAGIC: &[u8] = b"GV-CERTIFIED-EPOCH/V2\0";
/// Largest encoded certified epoch.
pub const MAX_CERTIFIED_EPOCH_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct CertifiedEpoch {
    /// The epoch's evidence, accusing (that is, carrying the signature of) the first signer.
    pub evidence: CheckpointEvidence,
    /// The remaining signers of the same claim, in roster order.
    pub cosigners: Vec<SignedCheckpoint>,
}
impl CertifiedEpoch {
    pub fn from_accepted(
        epoch: &Epoch,
        session: &gv_core::Session,
    ) -> Result<Self, CheckpointError> {
        let mut signatures = epoch
            .signatures
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or(CheckpointError::InvalidEvidence)?;
        let first = signatures.remove(0);
        Ok(Self {
            evidence: CheckpointEvidence {
                trusted_previous_checkpoint: epoch.checkpoint.previous_checkpoint,
                trusted_previous_state: epoch.checkpoint.previous_state,
                accused: first,
                previous_state: epoch.previous_state.clone(),
                session: session.clone(),
                inputs: epoch.inputs.clone(),
            },
            cosigners: signatures,
        })
    }
    /// Every signature, in roster order.
    pub fn signatures(&self) -> Vec<SignedCheckpoint> {
        std::iter::once(self.evidence.accused.clone())
            .chain(self.cosigners.iter().cloned())
            .collect()
    }
    pub fn encode(&self) -> Result<Vec<u8>, CheckpointError> {
        let evidence = self.evidence.encode()?;
        let n = u32::try_from(evidence.len()).map_err(|_| CheckpointError::InvalidEvidence)?;
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&evidence);
        out.extend_from_slice(&(self.cosigners.len() as u16).to_le_bytes());
        for s in &self.cosigners {
            out.extend_from_slice(&s.encode());
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CheckpointError> {
        let bad = || CheckpointError::InvalidEvidence;
        if bytes.len() > MAX_CERTIFIED_EPOCH_BYTES || !bytes.starts_with(MAGIC) {
            return Err(bad());
        }
        let body = &bytes[MAGIC.len()..];
        let len_bytes: [u8; 4] = body
            .get(..4)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        let evidence_end = 4usize.checked_add(len).ok_or_else(bad)?;
        let evidence = CheckpointEvidence::decode(body.get(4..evidence_end).ok_or_else(bad)?)?;
        let rest = body.get(evidence_end..).ok_or_else(bad)?;
        let count = rest
            .get(..2)
            .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
            .ok_or_else(bad)?;
        let sigs = &rest[2..];
        if count > gv_core::MAX_PARTICIPANTS || sigs.len() != count * SignedCheckpoint::WIRE_SIZE {
            return Err(bad());
        }
        let cosigners = sigs
            .chunks_exact(SignedCheckpoint::WIRE_SIZE)
            .map(SignedCheckpoint::decode)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            evidence,
            cosigners,
        })
    }
    pub fn verify<R: StateMachine>(
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
    /// `ValidClaim` only if the signatures satisfy the session's certification policy, all sign
    /// the identical claim, and replay of the signed inputs reproduces it.
    pub fn verify_with<R: StateMachine>(
        &self,
        rules: &R,
        known_previous_checkpoint: Digest,
        known_previous_state: Digest,
        sanitize: bool,
    ) -> EvidenceVerdict {
        let fail = |e| EvidenceVerdict::Inconclusive(e);
        let evidence = &self.evidence;
        if evidence.trusted_previous_checkpoint != known_previous_checkpoint
            || evidence.trusted_previous_state != known_previous_state
        {
            return fail(CheckpointError::InvalidHistory);
        }
        if let Err(e) = self.check_signatures() {
            return fail(e);
        }
        verify_checkpoint_evidence_with(rules, evidence, sanitize)
    }
    fn check_signatures(&self) -> Result<(), CheckpointError> {
        let session = &self.evidence.session;
        let mut slots = Vec::with_capacity(1 + self.cosigners.len());
        for s in std::iter::once(&self.evidence.accused).chain(&self.cosigners) {
            s.verify()?;
            let slot = session
                .roster
                .index_of(&s.signer)
                .filter(|slot| session.roster.get(*slot).is_some_and(|p| p.role.signs()))
                .ok_or(CheckpointError::WrongSigner)?;
            if s.claim != self.evidence.accused.claim || slots.last().is_some_and(|l| *l >= slot) {
                return Err(CheckpointError::InvalidHistory);
            }
            slots.push(slot);
        }
        if session.certification.satisfied(&session.roster, &slots) {
            Ok(())
        } else {
            Err(CheckpointError::WrongSigner)
        }
    }
    /// Exact certified head; valid only after `verify(...)` returns ValidClaim.
    pub fn checkpoint_hash(&self) -> Digest {
        self.evidence.accused.claim.digest()
    }
}
