//! Input admission: commit, mutually certify the commitment set, then reveal. A signature
//! authenticates its author's events; a lock certifies the exact set admitted for an epoch.
//! This is NOT Byzantine fault-tolerant consensus.
#![forbid(unsafe_code)]
use super::checkpoint::MAX_EPOCH_TICKS;
use gv_codec::SignedEventBatch;
use gv_core::{Digest, MatchId, ParticipantId, Session};
use gv_sig::{Signature, SigningKey, SIG_LEN};
use sha2::{Digest as _, Sha256};

const COMMIT_DOMAIN: &[u8] = b"gv/admission/commit/v1\0";
const COMMIT_LABEL: &str = "gv/admission/commit/v1";
const LOCK_LABEL: &str = "gv/admission/lock/v1";
const BLIND_DOMAIN: &[u8] = b"gv/admission/blinded-batch/v1\0";
const ROOT_DOMAIN: &[u8] = b"gv/admission/root/v1\0";
const COMMIT_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    WrongSigner,
    WrongContext,
    InvalidSignature,
    Duplicate,
    WrongPhase,
    Mismatch,
    InvalidEncoding,
    InvalidEpoch,
    Oversize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchCommitment {
    pub match_id: MatchId,
    pub ruleset: Digest,
    pub previous_checkpoint: Digest,
    pub participant: ParticipantId,
    pub start_tick: u64,
    pub tick_count: u32,
    /// `H(domain || blind || digest(signed batch))`. The 256-bit random `blind`
    /// is what makes this commitment hiding for low-entropy control words;
    /// neither the transport session nor the (randomized) signature is relied on.
    pub blinded_batch_hash: Digest,
}
impl BatchCommitment {
    pub const SIZE: usize = 1 + 32 * 5 + 8 + 4;
    /// Hiding, binding commitment to `batch` under the secret `blind`.
    pub fn blind_batch(batch: &SignedEventBatch, blind: &Digest) -> Result<Digest, AdmissionError> {
        let mut h = Sha256::new();
        h.update(BLIND_DOMAIN);
        h.update(blind);
        h.update(
            batch
                .digest()
                .map_err(|_| AdmissionError::InvalidEncoding)?,
        );
        Ok(h.finalize().into())
    }
    pub fn for_batch(
        batch: &SignedEventBatch,
        ruleset: Digest,
        previous_checkpoint: Digest,
        blind: &Digest,
    ) -> Result<Self, AdmissionError> {
        Ok(Self {
            match_id: batch.record.match_id,
            ruleset,
            previous_checkpoint,
            participant: batch.record.participant,
            start_tick: batch.record.start_tick,
            tick_count: batch.record.tick_count,
            blinded_batch_hash: Self::blind_batch(batch, blind)?,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::SIZE);
        b.push(COMMIT_VERSION);
        b.extend_from_slice(&self.match_id);
        b.extend_from_slice(&self.ruleset);
        b.extend_from_slice(&self.previous_checkpoint);
        b.extend_from_slice(&self.participant);
        b.extend_from_slice(&self.start_tick.to_le_bytes());
        b.extend_from_slice(&self.tick_count.to_le_bytes());
        b.extend_from_slice(&self.blinded_batch_hash);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, AdmissionError> {
        if b.len() != Self::SIZE || b[0] != COMMIT_VERSION {
            return Err(AdmissionError::InvalidEncoding);
        }
        let read32 = |p: usize| -> Digest {
            let mut v = [0; 32];
            v.copy_from_slice(&b[p..p + 32]);
            v
        };
        Ok(Self {
            match_id: read32(1),
            ruleset: read32(33),
            previous_checkpoint: read32(65),
            participant: read32(97),
            start_tick: u64::from_le_bytes(
                b[129..137]
                    .try_into()
                    .map_err(|_| AdmissionError::InvalidEncoding)?,
            ),
            tick_count: u32::from_le_bytes(
                b[137..141]
                    .try_into()
                    .map_err(|_| AdmissionError::InvalidEncoding)?,
            ),
            blinded_batch_hash: read32(141),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBatchCommitment {
    pub claim: BatchCommitment,
    pub signature: Signature,
}
impl SignedBatchCommitment {
    pub const SIZE: usize = BatchCommitment::SIZE + SIG_LEN;
    pub fn sign(claim: BatchCommitment, key: &SigningKey) -> Result<Self, AdmissionError> {
        if claim.participant != key.id() {
            return Err(AdmissionError::WrongSigner);
        }
        let signature = key.sign(COMMIT_LABEL, &claim.encode());
        Ok(Self { claim, signature })
    }
    pub fn verify(&self) -> Result<(), AdmissionError> {
        gv_sig::verify(
            &self.claim.participant,
            COMMIT_LABEL,
            &self.claim.encode(),
            &self.signature,
        )
        .map_err(|_| AdmissionError::InvalidSignature)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.claim.encode();
        b.extend_from_slice(self.signature.as_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, AdmissionError> {
        if b.len() != Self::SIZE {
            return Err(AdmissionError::InvalidEncoding);
        }
        let claim = BatchCommitment::decode(&b[..BatchCommitment::SIZE])?;
        let signature = Signature::from_slice(&b[BatchCommitment::SIZE..])
            .map_err(|_| AdmissionError::InvalidEncoding)?;
        let result = Self { claim, signature };
        result.verify()?;
        Ok(result)
    }
    pub fn digest(&self) -> Digest {
        let mut h = Sha256::new();
        h.update(COMMIT_DOMAIN);
        h.update(self.encode());
        h.finalize().into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedEpochLock {
    pub root: Digest,
    pub participant: ParticipantId,
    pub signature: Signature,
}
impl SignedEpochLock {
    pub const SIZE: usize = 32 + 32 + SIG_LEN;
    fn body(root: &Digest, participant: &ParticipantId) -> Vec<u8> {
        let mut msg = root.to_vec();
        msg.extend_from_slice(participant);
        msg
    }
    pub fn sign(root: Digest, key: &SigningKey) -> Self {
        let participant = key.id();
        let signature = key.sign(LOCK_LABEL, &Self::body(&root, &participant));
        Self {
            root,
            participant,
            signature,
        }
    }
    pub fn verify(&self) -> Result<(), AdmissionError> {
        gv_sig::verify(
            &self.participant,
            LOCK_LABEL,
            &Self::body(&self.root, &self.participant),
            &self.signature,
        )
        .map_err(|_| AdmissionError::InvalidSignature)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.root.to_vec();
        b.extend_from_slice(&self.participant);
        b.extend_from_slice(self.signature.as_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, AdmissionError> {
        if b.len() != Self::SIZE {
            return Err(AdmissionError::InvalidEncoding);
        }
        let mut root = [0; 32];
        root.copy_from_slice(&b[..32]);
        let mut participant = [0; 32];
        participant.copy_from_slice(&b[32..64]);
        let signature =
            Signature::from_slice(&b[64..]).map_err(|_| AdmissionError::InvalidEncoding)?;
        let value = Self {
            root,
            participant,
            signature,
        };
        value.verify()?;
        Ok(value)
    }
}

/// All admission messages can be verified offline. Signed locks prevent a peer
/// from switching to a different admitted input set after seeing the reveal.
///
/// Every submitting participant may commit; the lock certifies exactly the set of commitments
/// that exist when it is signed (a participant that never committed is absent from the epoch).
/// This is agreement on an input set among the committers, NOT Byzantine consensus.
pub struct EpochAdmission {
    pub session: Session,
    pub ruleset: Digest,
    pub previous_checkpoint: Digest,
    pub start_tick: u64,
    pub tick_count: u32,
    commits: Vec<Option<SignedBatchCommitment>>,
    locks: Vec<Option<SignedEpochLock>>,
    reveals: Vec<Option<SignedEventBatch>>,
}
impl EpochAdmission {
    pub fn new(
        session: Session,
        ruleset: Digest,
        previous_checkpoint: Digest,
        start_tick: u64,
        tick_count: u32,
    ) -> Result<Self, AdmissionError> {
        if tick_count == 0
            || tick_count > MAX_EPOCH_TICKS
            || start_tick.checked_add(u64::from(tick_count)).is_none()
        {
            return Err(AdmissionError::InvalidEpoch);
        }
        let slots = session.roster.len();
        Ok(Self {
            session,
            ruleset,
            previous_checkpoint,
            start_tick,
            tick_count,
            commits: vec![None; slots],
            locks: vec![None; slots],
            reveals: vec![None; slots],
        })
    }
    /// Slot of a participant that may commit, lock and reveal inputs.
    fn submitter(&self, participant: ParticipantId) -> Result<usize, AdmissionError> {
        self.session
            .roster
            .index_of(&participant)
            .filter(|s| {
                self.session
                    .roster
                    .get(*s)
                    .is_some_and(|p| p.role.submits())
            })
            .ok_or(AdmissionError::WrongSigner)
    }
    pub fn admit_commit(&mut self, s: SignedBatchCommitment) -> Result<(), AdmissionError> {
        if self.locks.iter().any(Option::is_some) {
            return Err(AdmissionError::WrongPhase);
        }
        s.verify()?;
        let i = self.submitter(s.claim.participant)?;
        if s.claim.match_id != self.session.match_id
            || s.claim.ruleset != self.ruleset
            || s.claim.previous_checkpoint != self.previous_checkpoint
            || s.claim.start_tick != self.start_tick
            || s.claim.tick_count != self.tick_count
        {
            return Err(AdmissionError::WrongContext);
        }
        if self.commits[i].is_some() {
            return Err(AdmissionError::Duplicate);
        }
        self.commits[i] = Some(s);
        Ok(())
    }
    /// Root over the commitments present, each bound to its roster slot.
    pub fn root(&self) -> Result<Digest, AdmissionError> {
        if self.commits.iter().all(Option::is_none) {
            return Err(AdmissionError::WrongPhase);
        }
        let mut h = Sha256::new();
        h.update(ROOT_DOMAIN);
        h.update(self.session.digest());
        for (slot, commit) in self.commits.iter().enumerate() {
            if let Some(c) = commit {
                h.update((slot as u16).to_le_bytes());
                h.update(c.digest());
            }
        }
        Ok(h.finalize().into())
    }
    pub fn sign_lock(&self, key: &SigningKey) -> Result<SignedEpochLock, AdmissionError> {
        self.submitter(key.id())?;
        Ok(SignedEpochLock::sign(self.root()?, key))
    }
    pub fn admit_lock(&mut self, lock: SignedEpochLock) -> Result<(), AdmissionError> {
        lock.verify()?;
        let i = self.submitter(lock.participant)?;
        if self.commits[i].is_none() || lock.root != self.root()? {
            return Err(AdmissionError::Mismatch);
        }
        if self.locks[i].is_some() {
            return Err(AdmissionError::Duplicate);
        }
        self.locks[i] = Some(lock);
        Ok(())
    }
    /// How many participants have committed so far.
    pub fn commit_count(&self) -> usize {
        self.commits.iter().flatten().count()
    }
    /// Every committer has locked the same commitment set.
    pub fn locked(&self) -> bool {
        self.commits.iter().any(Option::is_some)
            && self
                .commits
                .iter()
                .zip(&self.locks)
                .all(|(c, l)| c.is_none() || l.is_some())
    }
    pub fn admit_reveal(
        &mut self,
        b: SignedEventBatch,
        blind: &Digest,
    ) -> Result<(), AdmissionError> {
        if !self.locked() {
            return Err(AdmissionError::WrongPhase);
        }
        b.verify().map_err(|_| AdmissionError::InvalidSignature)?;
        let i = self.submitter(b.record.participant)?;
        if self.reveals[i].is_some() {
            return Err(AdmissionError::Duplicate);
        }
        let c = &self.commits[i]
            .as_ref()
            .ok_or(AdmissionError::WrongPhase)?
            .claim;
        if b.record.match_id != self.session.match_id
            || b.record.start_tick != self.start_tick
            || b.record.tick_count != self.tick_count
            || BatchCommitment::blind_batch(&b, blind)? != c.blinded_batch_hash
        {
            return Err(AdmissionError::Mismatch);
        }
        self.reveals[i] = Some(b);
        Ok(())
    }
    /// The revealed batches by roster slot, once every committer has revealed.
    pub fn ordered_reveals(&self) -> Result<Vec<Option<SignedEventBatch>>, AdmissionError> {
        if !self.locked()
            || self
                .commits
                .iter()
                .zip(&self.reveals)
                .any(|(c, r)| c.is_some() != r.is_some())
        {
            return Err(AdmissionError::WrongPhase);
        }
        Ok(self.reveals.clone())
    }
}

/// Two signed conflicting commitments for the same epoch and participant prove
/// cryptographic equivocation, NOT necessarily a gameplay physics violation.
pub fn verify_equivocation(a: &SignedBatchCommitment, b: &SignedBatchCommitment) -> bool {
    a.verify().is_ok()
        && b.verify().is_ok()
        && a.claim.participant == b.claim.participant
        && a.claim.match_id == b.claim.match_id
        && a.claim.ruleset == b.claim.ruleset
        && a.claim.previous_checkpoint == b.claim.previous_checkpoint
        && a.claim.start_tick == b.claim.start_tick
        && a.claim.tick_count == b.claim.tick_count
        && a.claim.blinded_batch_hash != b.claim.blinded_batch_hash
}
