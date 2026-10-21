use gv_codec::SignedPackedControls;
use gv_commitments::{commit_state, MerkleLog};
use gv_core::{Digest, MatchId, PlayerId, StateOpening};
use gv_replay::StateMachine;
use gv_sig::{Signature, SigningKey, SIG_LEN};
use sha2::{Digest as _, Sha256};

/// Maximum encoded size of one signed batch inside evidence (record + ML-DSA signature).
const MAX_BATCH_WIRE: usize = 128 * 1024;

const DOMAIN: &[u8] = b"gv/edge-checkpoint/v1\0";
const WIRE_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointError {
    WrongSigner,
    InvalidSignature,
    WrongMatch,
    WrongRules,
    WrongEpoch,
    InvalidHistory,
    InvalidState,
    InvalidEvidence,
    RuleFailure,
}

/// Canonical, signed claim binds the exact match, epoch, input set, resulting state,
/// and previous checkpoint. Player IDs are in lexicographic order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub match_id: MatchId,
    pub ruleset: Digest,
    pub epoch_start: u64,
    pub epoch_length: u32,
    pub previous_checkpoint: Digest,
    pub previous_state: Digest,
    pub input_root: Digest,
    pub next_state: Digest,
}
impl Checkpoint {
    pub const SERIALIZED_SIZE: usize = 1 + 32 * 6 + 8 + 4;
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::SERIALIZED_SIZE);
        v.push(WIRE_VERSION);
        v.extend_from_slice(&self.match_id);
        v.extend_from_slice(&self.ruleset);
        v.extend_from_slice(&self.epoch_start.to_le_bytes());
        v.extend_from_slice(&self.epoch_length.to_le_bytes());
        v.extend_from_slice(&self.previous_checkpoint);
        v.extend_from_slice(&self.previous_state);
        v.extend_from_slice(&self.input_root);
        v.extend_from_slice(&self.next_state);
        v
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CheckpointError> {
        if bytes.len() != Self::SERIALIZED_SIZE || bytes[0] != WIRE_VERSION {
            return Err(CheckpointError::InvalidEvidence);
        }
        let mut offset = 1usize;
        fn read32(bytes: &[u8], offset: &mut usize) -> Digest {
            let mut result = [0; 32];
            result.copy_from_slice(&bytes[*offset..*offset + 32]);
            *offset += 32;
            result
        }
        let match_id = read32(bytes, &mut offset);
        let ruleset = read32(bytes, &mut offset);
        let epoch_start = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CheckpointError::InvalidEvidence)?,
        );
        offset += 8;
        let epoch_length = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CheckpointError::InvalidEvidence)?,
        );
        offset += 4;
        let previous_checkpoint = read32(bytes, &mut offset);
        let previous_state = read32(bytes, &mut offset);
        let input_root = read32(bytes, &mut offset);
        let next_state = read32(bytes, &mut offset);
        Ok(Self {
            match_id,
            ruleset,
            epoch_start,
            epoch_length,
            previous_checkpoint,
            previous_state,
            input_root,
            next_state,
        })
    }
    pub fn digest(&self) -> Digest {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(self.encode());
        h.finalize().into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub claim: Checkpoint,
    pub player: PlayerId,
    pub signature: Signature,
}
impl SignedCheckpoint {
    pub const WIRE_SIZE: usize = Checkpoint::SERIALIZED_SIZE + 32 + SIG_LEN;
    const LABEL: &'static str = "gv/checkpoint-sig/v1";
    /// The signature covers the claim digest (which binds match id, ruleset,
    /// epoch bounds, predecessor checkpoint and state/input roots) and the signer.
    fn body(claim: &Checkpoint, player: &PlayerId) -> Vec<u8> {
        let mut msg = Vec::with_capacity(64);
        msg.extend_from_slice(&claim.digest());
        msg.extend_from_slice(player);
        msg
    }
    pub fn sign(claim: Checkpoint, key: &SigningKey) -> Self {
        let player = key.id();
        let signature = key.sign(Self::LABEL, &Self::body(&claim, &player));
        Self {
            claim,
            player,
            signature,
        }
    }
    pub fn verify(&self) -> Result<(), CheckpointError> {
        gv_sig::verify(
            &self.player,
            Self::LABEL,
            &Self::body(&self.claim, &self.player),
            &self.signature,
        )
        .map_err(|_| CheckpointError::InvalidSignature)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.claim.encode();
        b.extend_from_slice(&self.player);
        b.extend_from_slice(self.signature.as_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, CheckpointError> {
        if b.len() != Self::WIRE_SIZE {
            return Err(CheckpointError::InvalidEvidence);
        }
        let claim = Checkpoint::decode(&b[..Checkpoint::SERIALIZED_SIZE])?;
        let mut player = [0; 32];
        player.copy_from_slice(&b[Checkpoint::SERIALIZED_SIZE..Checkpoint::SERIALIZED_SIZE + 32]);
        let signature = Signature::from_slice(&b[Checkpoint::SERIALIZED_SIZE + 32..])
            .map_err(|_| CheckpointError::InvalidEvidence)?;
        let s = Self {
            claim,
            player,
            signature,
        };
        s.verify()?;
        Ok(s)
    }
}

/// Entirely portable evidence: public prior state, two authenticated input streams,
/// accused party's signed checkpoint. No reporter signature or quorum required.
#[derive(Clone, Debug)]
pub struct CheckpointEvidence {
    /// Trusted prior checkpoint digest and state root from the verifier's
    /// accepted history, NOT values provided solely by the accuser.
    pub trusted_previous_checkpoint: Digest,
    pub trusted_previous_state: Digest,
    pub accused: SignedCheckpoint,
    pub previous_state: Vec<u8>,
    pub player_batches: [SignedPackedControls; 2],
    pub roster: [PlayerId; 2],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceVerdict {
    ValidClaim,
    ProvenInvalidState,
    ProvenInvalidAction(PlayerId),
    Inconclusive(CheckpointError),
}

pub fn verify_checkpoint_evidence<R: StateMachine>(
    rules: &R,
    proof: &CheckpointEvidence,
) -> EvidenceVerdict {
    verify_checkpoint_evidence_with(rules, proof, false)
}

/// `sanitize` selects live replay: an illegal control word is neutralized the
/// same way the live engine did, instead of making the epoch unverifiable.
pub fn verify_checkpoint_evidence_with<R: StateMachine>(
    rules: &R,
    proof: &CheckpointEvidence,
    sanitize: bool,
) -> EvidenceVerdict {
    let fail = |e| EvidenceVerdict::Inconclusive(e);
    if proof.accused.verify().is_err() {
        return fail(CheckpointError::InvalidSignature);
    }
    let claim = &proof.accused.claim;
    if claim.previous_checkpoint != proof.trusted_previous_checkpoint
        || claim.previous_state != proof.trusted_previous_state
    {
        return fail(CheckpointError::InvalidHistory);
    }
    if claim.epoch_length == 0
        || claim.epoch_length > 4096
        || claim
            .epoch_start
            .checked_add(u64::from(claim.epoch_length))
            .is_none()
    {
        return fail(CheckpointError::WrongEpoch);
    }
    if proof.previous_state.len() > 65536 {
        return fail(CheckpointError::InvalidState);
    }
    if claim.ruleset != rules.ruleset_hash() {
        return fail(CheckpointError::WrongRules);
    }
    if proof.roster[0] >= proof.roster[1] || !proof.roster.contains(&proof.accused.player) {
        return fail(CheckpointError::WrongSigner);
    }
    let batches = &proof.player_batches;
    for (i, batch) in batches.iter().enumerate() {
        if batch.verify().is_err()
            || batch.record.player != proof.roster[i]
            || batch.record.match_id != claim.match_id
            || batch.record.start_tick != claim.epoch_start
            || batch.record.tick_count != claim.epoch_length
        {
            return fail(CheckpointError::InvalidEvidence);
        }
    }
    if commit_state(&StateOpening {
        bytes: proof.previous_state.clone(),
        nonce: [0; 32],
    }) != claim.previous_state
    {
        return fail(CheckpointError::InvalidState);
    }
    let mut log = MerkleLog::new();
    for batch in batches {
        let Ok(encoded) = batch.encode() else {
            return fail(CheckpointError::InvalidEvidence);
        };
        if log.append(&encoded).is_err() {
            return fail(CheckpointError::InvalidEvidence);
        }
    }
    if log.root() != claim.input_root {
        return fail(CheckpointError::InvalidHistory);
    }
    let mut state = proof.previous_state.clone();
    for offset in 0..claim.epoch_length {
        for batch in batches {
            let Ok(control) = batch.record.state_at(offset) else {
                return fail(CheckpointError::InvalidEvidence);
            };
            match crate::replica::apply_tick(
                rules,
                &state,
                &batch.record.player,
                claim.epoch_start + u64::from(offset),
                control,
                sanitize,
            ) {
                Ok((new, _)) if new.len() <= 65536 => state = new,
                Ok(_) | Err(_) => return fail(CheckpointError::RuleFailure),
            }
        }
    }
    let real = commit_state(&StateOpening {
        bytes: state,
        nonce: [0; 32],
    });
    if real == claim.next_state {
        EvidenceVerdict::ValidClaim
    } else {
        EvidenceVerdict::ProvenInvalidState
    }
}

impl CheckpointEvidence {
    /// Canonical portable witness container (not self-authorizing).
    /// The caller must supply the genuine trusted prior checkpoint/state roots
    /// from the independently verified match history.
    pub fn encode(&self) -> Result<Vec<u8>, CheckpointError> {
        if self.previous_state.len() > 65536 {
            return Err(CheckpointError::InvalidState);
        }
        let mut b = b"GV-EVIDENCE/V1\0".to_vec();
        b.extend_from_slice(&self.trusted_previous_checkpoint);
        b.extend_from_slice(&self.trusted_previous_state);
        b.extend_from_slice(&self.roster[0]);
        b.extend_from_slice(&self.roster[1]);
        b.extend_from_slice(&self.accused.encode());
        b.extend_from_slice(&(self.previous_state.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.previous_state);
        for batch in &self.player_batches {
            let bytes = batch
                .encode()
                .map_err(|_| CheckpointError::InvalidEvidence)?;
            if bytes.len() > MAX_BATCH_WIRE {
                return Err(CheckpointError::InvalidEvidence);
            }
            b.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            b.extend_from_slice(&bytes);
        }
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, CheckpointError> {
        if b.len() > 4 * MAX_BATCH_WIRE {
            return Err(CheckpointError::InvalidEvidence);
        }
        const MAGIC: &[u8] = b"GV-EVIDENCE/V1\0";
        if !b.starts_with(MAGIC) {
            return Err(CheckpointError::InvalidEvidence);
        }
        let mut pos = MAGIC.len();
        fn take<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], CheckpointError> {
            let end = pos.checked_add(n).ok_or(CheckpointError::InvalidEvidence)?;
            let slice = b.get(*pos..end).ok_or(CheckpointError::InvalidEvidence)?;
            *pos = end;
            Ok(slice)
        }
        fn fixed32(b: &[u8], pos: &mut usize) -> Result<Digest, CheckpointError> {
            take(b, pos, 32)?
                .try_into()
                .map_err(|_| CheckpointError::InvalidEvidence)
        }
        let trusted_previous_checkpoint = fixed32(b, &mut pos)?;
        let trusted_previous_state = fixed32(b, &mut pos)?;
        let roster = [fixed32(b, &mut pos)?, fixed32(b, &mut pos)?];
        let accused = SignedCheckpoint::decode(take(b, &mut pos, SignedCheckpoint::WIRE_SIZE)?)?;
        let state_len = u32::from_le_bytes(
            take(b, &mut pos, 4)?
                .try_into()
                .map_err(|_| CheckpointError::InvalidEvidence)?,
        ) as usize;
        if state_len > 65536 {
            return Err(CheckpointError::InvalidEvidence);
        }
        let previous_state = take(b, &mut pos, state_len)?.to_vec();
        let mut batches = Vec::with_capacity(2);
        for _ in 0..2 {
            let n = u32::from_le_bytes(
                take(b, &mut pos, 4)?
                    .try_into()
                    .map_err(|_| CheckpointError::InvalidEvidence)?,
            ) as usize;
            if n > MAX_BATCH_WIRE {
                return Err(CheckpointError::InvalidEvidence);
            }
            batches.push(
                SignedPackedControls::decode(take(b, &mut pos, n)?)
                    .map_err(|_| CheckpointError::InvalidEvidence)?,
            );
        }
        if pos != b.len() {
            return Err(CheckpointError::InvalidEvidence);
        }
        let player_batches = batches
            .try_into()
            .map_err(|_| CheckpointError::InvalidEvidence)?;
        Ok(Self {
            trusted_previous_checkpoint,
            trusted_previous_state,
            accused,
            previous_state,
            player_batches,
            roster,
        })
    }
}

/// Replay a (live) evidence epoch and list every illegal control word that was
/// neutralized in it, each authenticated by its sender's batch signature.
pub fn evidence_violations<R: StateMachine>(
    rules: &R,
    proof: &CheckpointEvidence,
) -> Result<Vec<crate::InputViolation>, CheckpointError> {
    if verify_checkpoint_evidence_with(rules, proof, true) != EvidenceVerdict::ValidClaim {
        return Err(CheckpointError::InvalidEvidence);
    }
    let claim = &proof.accused.claim;
    let mut state = proof.previous_state.clone();
    let mut found = Vec::new();
    for offset in 0..claim.epoch_length {
        for batch in &proof.player_batches {
            let control = batch
                .record
                .state_at(offset)
                .map_err(|_| CheckpointError::InvalidEvidence)?;
            let (next, violation) = crate::replica::apply_tick(
                rules,
                &state,
                &batch.record.player,
                claim.epoch_start + u64::from(offset),
                control,
                true,
            )
            .map_err(|_| CheckpointError::RuleFailure)?;
            state = next;
            found.extend(violation);
        }
    }
    Ok(found)
}
