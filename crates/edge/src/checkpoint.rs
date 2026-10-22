use gv_codec::SignedEventBatch;
use gv_commitments::{commit_state, MerkleLog};
use gv_core::{Digest, MatchId, ParticipantId, Session, StateOpening, MAX_SESSION_BYTES};
use gv_replay::{replay_epoch, InputViolation, ReplayError, StateMachine, MAX_STATE_BYTES};
use gv_sig::{Signature, SigningKey, SIG_LEN};
use sha2::{Digest as _, Sha256};

/// Maximum encoded size of one signed batch inside evidence (record + ML-DSA signature).
const MAX_BATCH_WIRE: usize = 128 * 1024;
/// Largest evidence container: every roster slot's batch, the session and the prior state.
const MAX_EVIDENCE_BYTES: usize = (gv_core::MAX_PARTICIPANTS + 8) * MAX_BATCH_WIRE;
/// Longest epoch a checkpoint may cover.
pub const MAX_EPOCH_TICKS: u32 = 4096;

const DOMAIN: &[u8] = b"gv/edge-checkpoint/v2\0";
const ABSENT_LEAF: &[u8] = b"gv/absent/v2\0";
const EVIDENCE_MAGIC: &[u8] = b"GV-EVIDENCE/V2\0";
const WIRE_VERSION: u8 = 2;

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

/// Canonical, signed claim: binds the exact session (match, roster, certification policy,
/// ordering, parameters), epoch, input set, resulting state and previous checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub match_id: MatchId,
    pub session: Digest,
    pub ruleset: Digest,
    pub epoch_start: u64,
    pub epoch_length: u32,
    pub previous_checkpoint: Digest,
    pub previous_state: Digest,
    pub input_root: Digest,
    pub next_state: Digest,
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CheckpointError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(CheckpointError::InvalidEvidence)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(CheckpointError::InvalidEvidence)?;
        self.pos = end;
        Ok(slice)
    }
    fn digest(&mut self) -> Result<Digest, CheckpointError> {
        self.take(32)?
            .try_into()
            .map_err(|_| CheckpointError::InvalidEvidence)
    }
    fn u32(&mut self) -> Result<u32, CheckpointError> {
        let b: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| CheckpointError::InvalidEvidence)?;
        Ok(u32::from_le_bytes(b))
    }
    fn u64(&mut self) -> Result<u64, CheckpointError> {
        let b: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| CheckpointError::InvalidEvidence)?;
        Ok(u64::from_le_bytes(b))
    }
    fn len_prefixed(&mut self, max: usize) -> Result<&'a [u8], CheckpointError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(CheckpointError::InvalidEvidence);
        }
        self.take(n)
    }
    fn finished(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CheckpointError> {
    let n = u32::try_from(bytes.len()).map_err(|_| CheckpointError::InvalidEvidence)?;
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

impl Checkpoint {
    pub const SERIALIZED_SIZE: usize = 1 + 32 * 7 + 8 + 4;
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::SERIALIZED_SIZE);
        v.push(WIRE_VERSION);
        v.extend_from_slice(&self.match_id);
        v.extend_from_slice(&self.session);
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
        let mut r = Reader::new(&bytes[1..]);
        Ok(Self {
            match_id: r.digest()?,
            session: r.digest()?,
            ruleset: r.digest()?,
            epoch_start: r.u64()?,
            epoch_length: r.u32()?,
            previous_checkpoint: r.digest()?,
            previous_state: r.digest()?,
            input_root: r.digest()?,
            next_state: r.digest()?,
        })
    }
    pub fn digest(&self) -> Digest {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(self.encode());
        h.finalize().into()
    }
}

pub fn state_commitment(state: &[u8]) -> Digest {
    commit_state(&StateOpening {
        bytes: state.to_vec(),
        nonce: [0; 32],
    })
}

/// Merkle root over the epoch's inputs, one leaf per roster slot: the signed batch, or an
/// explicit marker for a slot that contributed nothing (so absence is committed, not implied).
pub fn inputs_root(inputs: &[Option<&SignedEventBatch>]) -> Result<Digest, CheckpointError> {
    let mut log = MerkleLog::new();
    for (slot, input) in inputs.iter().enumerate() {
        let leaf = match input {
            Some(batch) => batch
                .encode()
                .map_err(|_| CheckpointError::InvalidEvidence)?,
            None => [ABSENT_LEAF, &(slot as u16).to_le_bytes()].concat(),
        };
        log.append(&leaf)
            .map_err(|_| CheckpointError::InvalidEvidence)?;
    }
    Ok(log.root())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub claim: Checkpoint,
    pub signer: ParticipantId,
    pub signature: Signature,
}
impl SignedCheckpoint {
    pub const WIRE_SIZE: usize = Checkpoint::SERIALIZED_SIZE + 32 + SIG_LEN;
    const LABEL: &'static str = "gv/checkpoint-sig/v2";
    /// The signature covers the claim digest (which binds session, ruleset, epoch bounds,
    /// predecessor checkpoint and state/input roots) and the signer.
    fn body(claim: &Checkpoint, signer: &ParticipantId) -> Vec<u8> {
        let mut msg = Vec::with_capacity(64);
        msg.extend_from_slice(&claim.digest());
        msg.extend_from_slice(signer);
        msg
    }
    pub fn sign(claim: Checkpoint, key: &SigningKey) -> Self {
        let signer = key.id();
        let signature = key.sign(Self::LABEL, &Self::body(&claim, &signer));
        Self {
            claim,
            signer,
            signature,
        }
    }
    pub fn verify(&self) -> Result<(), CheckpointError> {
        gv_sig::verify(
            &self.signer,
            Self::LABEL,
            &Self::body(&self.claim, &self.signer),
            &self.signature,
        )
        .map_err(|_| CheckpointError::InvalidSignature)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.claim.encode();
        b.extend_from_slice(&self.signer);
        b.extend_from_slice(self.signature.as_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, CheckpointError> {
        if b.len() != Self::WIRE_SIZE {
            return Err(CheckpointError::InvalidEvidence);
        }
        let (claim, rest) = b.split_at(Checkpoint::SERIALIZED_SIZE);
        let (signer, signature) = rest.split_at(32);
        let s = Self {
            claim: Checkpoint::decode(claim)?,
            signer: signer
                .try_into()
                .map_err(|_| CheckpointError::InvalidEvidence)?,
            signature: Signature::from_slice(signature)
                .map_err(|_| CheckpointError::InvalidEvidence)?,
        };
        s.verify()?;
        Ok(s)
    }
}

/// Entirely portable evidence: the session, the public prior state, every participant's
/// authenticated input stream for the epoch (by roster slot) and the accused signer's
/// checkpoint. No reporter signature or quorum required.
#[derive(Clone, Debug)]
pub struct CheckpointEvidence {
    /// Trusted prior checkpoint digest and state root from the verifier's
    /// accepted history, NOT values provided solely by the accuser.
    pub trusted_previous_checkpoint: Digest,
    pub trusted_previous_state: Digest,
    pub accused: SignedCheckpoint,
    pub previous_state: Vec<u8>,
    pub session: Session,
    /// One entry per roster slot; `None` is a slot that contributed nothing to this epoch.
    pub inputs: Vec<Option<SignedEventBatch>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceVerdict {
    ValidClaim,
    ProvenInvalidState,
    /// Strict replay: a participant's signed event is deterministically illegal.
    ProvenInvalidAction(ParticipantId),
    Inconclusive(CheckpointError),
}

pub fn verify_checkpoint_evidence<R: StateMachine>(
    rules: &R,
    proof: &CheckpointEvidence,
) -> EvidenceVerdict {
    verify_checkpoint_evidence_with(rules, proof, false)
}

impl CheckpointEvidence {
    fn batches(&self) -> Vec<Option<&gv_codec::EventBatch>> {
        self.inputs
            .iter()
            .map(|b| b.as_ref().map(|b| &b.record))
            .collect()
    }

    fn check_structure<R: StateMachine>(&self, rules: &R) -> Result<(), CheckpointError> {
        self.accused.verify()?;
        let claim = &self.accused.claim;
        let roster = &self.session.roster;
        if claim.previous_checkpoint != self.trusted_previous_checkpoint
            || claim.previous_state != self.trusted_previous_state
        {
            return Err(CheckpointError::InvalidHistory);
        }
        if claim.epoch_length == 0
            || claim.epoch_length > MAX_EPOCH_TICKS
            || claim
                .epoch_start
                .checked_add(u64::from(claim.epoch_length))
                .is_none()
        {
            return Err(CheckpointError::WrongEpoch);
        }
        if self.previous_state.len() > MAX_STATE_BYTES {
            return Err(CheckpointError::InvalidState);
        }
        if claim.ruleset != rules.ruleset_hash() {
            return Err(CheckpointError::WrongRules);
        }
        if claim.match_id != self.session.match_id || claim.session != self.session.digest() {
            return Err(CheckpointError::WrongMatch);
        }
        if !roster
            .find(&self.accused.signer)
            .is_some_and(|p| p.role.signs())
        {
            return Err(CheckpointError::WrongSigner);
        }
        self.check_inputs()?;
        if state_commitment(&self.previous_state) != claim.previous_state {
            return Err(CheckpointError::InvalidState);
        }
        Ok(())
    }

    fn check_inputs(&self) -> Result<(), CheckpointError> {
        let roster = &self.session.roster;
        if self.inputs.len() != roster.len() {
            return Err(CheckpointError::InvalidEvidence);
        }
        for (slot, input) in self.inputs.iter().enumerate() {
            let Some(batch) = input else { continue };
            if batch.verify().is_err()
                || roster.get(slot).map(|p| p.id) != Some(batch.record.participant)
            {
                return Err(CheckpointError::InvalidEvidence);
            }
        }
        let refs: Vec<_> = self.inputs.iter().map(Option::as_ref).collect();
        if inputs_root(&refs)? != self.accused.claim.input_root {
            return Err(CheckpointError::InvalidHistory);
        }
        Ok(())
    }
}

/// `sanitize` selects live replay: an illegal event is neutralized the same way the live
/// engine did, instead of making the epoch unverifiable.
pub fn verify_checkpoint_evidence_with<R: StateMachine>(
    rules: &R,
    proof: &CheckpointEvidence,
    sanitize: bool,
) -> EvidenceVerdict {
    if let Err(e) = proof.check_structure(rules) {
        return EvidenceVerdict::Inconclusive(e);
    }
    let claim = &proof.accused.claim;
    match replay_epoch(
        rules,
        &proof.session,
        &proof.previous_state,
        claim.epoch_start,
        claim.epoch_length,
        &proof.batches(),
        sanitize,
    ) {
        Ok(replayed) if state_commitment(&replayed.state) == claim.next_state => {
            EvidenceVerdict::ValidClaim
        }
        Ok(_) => EvidenceVerdict::ProvenInvalidState,
        Err(ReplayError::Violation(v)) => EvidenceVerdict::ProvenInvalidAction(v.participant),
        Err(ReplayError::Malformed) => {
            EvidenceVerdict::Inconclusive(CheckpointError::InvalidEvidence)
        }
        Err(ReplayError::Execution(_) | ReplayError::StateTooLarge) => {
            EvidenceVerdict::Inconclusive(CheckpointError::RuleFailure)
        }
    }
}

impl CheckpointEvidence {
    /// Canonical portable witness container (not self-authorizing).
    /// The caller must supply the genuine trusted prior checkpoint/state roots
    /// from the independently verified match history.
    pub fn encode(&self) -> Result<Vec<u8>, CheckpointError> {
        if self.previous_state.len() > MAX_STATE_BYTES
            || self.inputs.len() != self.session.roster.len()
        {
            return Err(CheckpointError::InvalidState);
        }
        let mut b = EVIDENCE_MAGIC.to_vec();
        b.extend_from_slice(&self.trusted_previous_checkpoint);
        b.extend_from_slice(&self.trusted_previous_state);
        push_len_prefixed(&mut b, &self.session.encode())?;
        b.extend_from_slice(&self.accused.encode());
        push_len_prefixed(&mut b, &self.previous_state)?;
        for input in &self.inputs {
            match input {
                None => b.push(0),
                Some(batch) => {
                    let bytes = batch
                        .encode()
                        .map_err(|_| CheckpointError::InvalidEvidence)?;
                    if bytes.len() > MAX_BATCH_WIRE {
                        return Err(CheckpointError::InvalidEvidence);
                    }
                    b.push(1);
                    push_len_prefixed(&mut b, &bytes)?;
                }
            }
        }
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, CheckpointError> {
        if b.len() > MAX_EVIDENCE_BYTES || !b.starts_with(EVIDENCE_MAGIC) {
            return Err(CheckpointError::InvalidEvidence);
        }
        let mut r = Reader::new(&b[EVIDENCE_MAGIC.len()..]);
        let trusted_previous_checkpoint = r.digest()?;
        let trusted_previous_state = r.digest()?;
        let session = Session::decode(r.len_prefixed(MAX_SESSION_BYTES)?)
            .map_err(|_| CheckpointError::InvalidEvidence)?;
        let accused = SignedCheckpoint::decode(r.take(SignedCheckpoint::WIRE_SIZE)?)?;
        let previous_state = r.len_prefixed(MAX_STATE_BYTES)?.to_vec();
        let mut inputs = Vec::with_capacity(session.roster.len());
        for _ in 0..session.roster.len() {
            inputs.push(match r.take(1)?[0] {
                0 => None,
                1 => Some(
                    SignedEventBatch::decode(r.len_prefixed(MAX_BATCH_WIRE)?)
                        .map_err(|_| CheckpointError::InvalidEvidence)?,
                ),
                _ => return Err(CheckpointError::InvalidEvidence),
            });
        }
        if !r.finished() {
            return Err(CheckpointError::InvalidEvidence);
        }
        Ok(Self {
            trusted_previous_checkpoint,
            trusted_previous_state,
            accused,
            previous_state,
            session,
            inputs,
        })
    }
}

/// Replay a (live) evidence epoch and list every illegal event that was neutralized in it,
/// each authenticated by its sender's batch signature.
pub fn evidence_violations<R: StateMachine>(
    rules: &R,
    proof: &CheckpointEvidence,
) -> Result<Vec<InputViolation>, CheckpointError> {
    if verify_checkpoint_evidence_with(rules, proof, true) != EvidenceVerdict::ValidClaim {
        return Err(CheckpointError::InvalidEvidence);
    }
    let claim = &proof.accused.claim;
    replay_epoch(
        rules,
        &proof.session,
        &proof.previous_state,
        claim.epoch_start,
        claim.epoch_length,
        &proof.batches(),
        true,
    )
    .map(|replayed| replayed.violations)
    .map_err(|_| CheckpointError::RuleFailure)
}
