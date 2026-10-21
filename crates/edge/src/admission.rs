//! Bilateral input admission: commit, mutually certify the commitment set,
//! then reveal. A player's signature authenticates an action; a mutual lock
//! certifies the exact set admitted for an epoch. This is NOT 1-Byzantine BFT.
#![forbid(unsafe_code)]
use gv_codec::SignedPackedControls;
use gv_core::{Digest, MatchId, PlayerId};
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
    InvalidRoster,
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
    pub player: PlayerId,
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
    pub fn blind_batch(
        batch: &SignedPackedControls,
        blind: &Digest,
    ) -> Result<Digest, AdmissionError> {
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
        batch: &SignedPackedControls,
        ruleset: Digest,
        previous_checkpoint: Digest,
        blind: &Digest,
    ) -> Result<Self, AdmissionError> {
        Ok(Self {
            match_id: batch.record.match_id,
            ruleset,
            previous_checkpoint,
            player: batch.record.player,
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
        b.extend_from_slice(&self.player);
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
            player: read32(97),
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
        if claim.player != key.id() {
            return Err(AdmissionError::WrongSigner);
        }
        let signature = key.sign(COMMIT_LABEL, &claim.encode());
        Ok(Self { claim, signature })
    }
    pub fn verify(&self) -> Result<(), AdmissionError> {
        gv_sig::verify(
            &self.claim.player,
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
    pub player: PlayerId,
    pub signature: Signature,
}
impl SignedEpochLock {
    pub const SIZE: usize = 32 + 32 + SIG_LEN;
    fn body(root: &Digest, player: &PlayerId) -> Vec<u8> {
        let mut msg = root.to_vec();
        msg.extend_from_slice(player);
        msg
    }
    pub fn sign(root: Digest, key: &SigningKey) -> Self {
        let player = key.id();
        let signature = key.sign(LOCK_LABEL, &Self::body(&root, &player));
        Self {
            root,
            player,
            signature,
        }
    }
    pub fn verify(&self) -> Result<(), AdmissionError> {
        gv_sig::verify(
            &self.player,
            LOCK_LABEL,
            &Self::body(&self.root, &self.player),
            &self.signature,
        )
        .map_err(|_| AdmissionError::InvalidSignature)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.root.to_vec();
        b.extend_from_slice(&self.player);
        b.extend_from_slice(self.signature.as_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, AdmissionError> {
        if b.len() != Self::SIZE {
            return Err(AdmissionError::InvalidEncoding);
        }
        let mut root = [0; 32];
        root.copy_from_slice(&b[..32]);
        let mut player = [0; 32];
        player.copy_from_slice(&b[32..64]);
        let signature =
            Signature::from_slice(&b[64..]).map_err(|_| AdmissionError::InvalidEncoding)?;
        let value = Self {
            root,
            player,
            signature,
        };
        value.verify()?;
        Ok(value)
    }
}

/// All admission messages can be verified offline. Signed locks prevent a peer
/// from switching to a different admitted input set after seeing the reveal.
pub struct BilateralAdmission {
    pub match_id: MatchId,
    pub ruleset: Digest,
    pub previous_checkpoint: Digest,
    pub roster: [PlayerId; 2],
    pub start_tick: u64,
    pub tick_count: u32,
    commits: [Option<SignedBatchCommitment>; 2],
    locks: [Option<SignedEpochLock>; 2],
    reveals: [Option<SignedPackedControls>; 2],
}
impl BilateralAdmission {
    pub fn new(
        match_id: MatchId,
        ruleset: Digest,
        previous_checkpoint: Digest,
        mut roster: [PlayerId; 2],
        start_tick: u64,
        tick_count: u32,
    ) -> Result<Self, AdmissionError> {
        roster.sort();
        if roster[0] == roster[1] {
            return Err(AdmissionError::InvalidRoster);
        }
        if tick_count == 0
            || tick_count > 4096
            || start_tick.checked_add(u64::from(tick_count)).is_none()
        {
            return Err(AdmissionError::InvalidEpoch);
        }
        Ok(Self {
            match_id,
            ruleset,
            previous_checkpoint,
            roster,
            start_tick,
            tick_count,
            commits: [None, None],
            locks: [None, None],
            reveals: [None, None],
        })
    }
    fn index(&self, player: PlayerId) -> Result<usize, AdmissionError> {
        self.roster
            .iter()
            .position(|p| *p == player)
            .ok_or(AdmissionError::WrongSigner)
    }
    pub fn admit_commit(&mut self, s: SignedBatchCommitment) -> Result<(), AdmissionError> {
        if self.locks.iter().any(Option::is_some) {
            return Err(AdmissionError::WrongPhase);
        }
        s.verify()?;
        let i = self.index(s.claim.player)?;
        if s.claim.match_id != self.match_id
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
    pub fn root(&self) -> Result<Digest, AdmissionError> {
        let a = self.commits[0].as_ref().ok_or(AdmissionError::WrongPhase)?;
        let b = self.commits[1].as_ref().ok_or(AdmissionError::WrongPhase)?;
        let mut h = Sha256::new();
        h.update(ROOT_DOMAIN);
        h.update(a.digest());
        h.update(b.digest());
        Ok(h.finalize().into())
    }
    pub fn sign_lock(&self, key: &SigningKey) -> Result<SignedEpochLock, AdmissionError> {
        self.index(key.id())?;
        Ok(SignedEpochLock::sign(self.root()?, key))
    }
    pub fn admit_lock(&mut self, lock: SignedEpochLock) -> Result<(), AdmissionError> {
        lock.verify()?;
        let i = self.index(lock.player)?;
        if lock.root != self.root()? {
            return Err(AdmissionError::Mismatch);
        }
        if self.locks[i].is_some() {
            return Err(AdmissionError::Duplicate);
        }
        self.locks[i] = Some(lock);
        Ok(())
    }
    pub fn locked(&self) -> bool {
        self.locks.iter().all(Option::is_some)
    }
    pub fn admit_reveal(
        &mut self,
        b: SignedPackedControls,
        blind: &Digest,
    ) -> Result<(), AdmissionError> {
        if !self.locked() {
            return Err(AdmissionError::WrongPhase);
        }
        b.verify().map_err(|_| AdmissionError::InvalidSignature)?;
        let i = self.index(b.record.player)?;
        if self.reveals[i].is_some() {
            return Err(AdmissionError::Duplicate);
        }
        let c = &self.commits[i]
            .as_ref()
            .ok_or(AdmissionError::WrongPhase)?
            .claim;
        if b.record.match_id != self.match_id
            || b.record.start_tick != self.start_tick
            || b.record.tick_count != self.tick_count
            || BatchCommitment::blind_batch(&b, blind)? != c.blinded_batch_hash
        {
            return Err(AdmissionError::Mismatch);
        }
        self.reveals[i] = Some(b);
        Ok(())
    }
    pub fn ordered_reveals(&self) -> Result<[SignedPackedControls; 2], AdmissionError> {
        Ok([
            self.reveals[0].clone().ok_or(AdmissionError::WrongPhase)?,
            self.reveals[1].clone().ok_or(AdmissionError::WrongPhase)?,
        ])
    }
}

/// Two signed conflicting commitments for the same epoch and player prove
/// cryptographic equivocation, NOT necessarily a gameplay physics violation.
pub fn verify_equivocation(a: &SignedBatchCommitment, b: &SignedBatchCommitment) -> bool {
    a.verify().is_ok()
        && b.verify().is_ok()
        && a.claim.player == b.claim.player
        && a.claim.match_id == b.claim.match_id
        && a.claim.ruleset == b.claim.ruleset
        && a.claim.previous_checkpoint == b.claim.previous_checkpoint
        && a.claim.start_tick == b.claim.start_tick
        && a.claim.tick_count == b.claim.tick_count
        && a.claim.blinded_batch_hash != b.claim.blinded_batch_hash
}
