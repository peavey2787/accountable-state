use super::checkpoint::{
    inputs_root, state_commitment, Checkpoint, CheckpointError, SignedCheckpoint, MAX_EPOCH_TICKS,
};
use gv_codec::SignedEventBatch;
use gv_core::{Digest, MatchId, Session};
use gv_replay::{replay_epoch, InputViolation, ReplayError, StateMachine, MAX_STATE_BYTES};
use gv_sig::SigningKey;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdgeError {
    MissingBatch,
    /// The batch's author is not a submitting member of the roster.
    WrongParticipant,
    BadSignature,
    WrongMatch,
    WrongEpoch,
    BrokenChain,
    BadCheckpoint,
    /// Strict replay found an event the rules deterministically reject.
    InvalidAction,
    /// The rules failed to execute; never evidence against a participant.
    RuleFailure,
    ResourceLimit,
    AlreadyAccepted,
    /// The signatures do not satisfy the session's certification policy.
    NotCertified,
}

/// One epoch of the chain: the checkpoint, the exact inputs it commits to (by roster slot) and,
/// once finalized, the signatures that certify it.
#[derive(Clone, Debug)]
pub struct Epoch {
    pub checkpoint: Checkpoint,
    /// One entry per roster slot; `None` is a slot that contributed nothing to the epoch.
    pub inputs: Vec<Option<SignedEventBatch>>,
    pub previous_state: Vec<u8>,
    pub next_state: Vec<u8>,
    /// Signatures satisfying the session's certification policy, present only after
    /// finalization, in roster order.
    pub signatures: Option<Vec<SignedCheckpoint>>,
}

pub struct MatchReplica<R: StateMachine> {
    pub session: Session,
    pub rules: R,
    state: Vec<u8>,
    previous_checkpoint: Digest,
    next_tick: u64,
    head: Vec<Digest>,
    proposed: Vec<Option<SignedEventBatch>>,
    accepted: Vec<Epoch>,
    sanitize: bool,
}
impl<R: StateMachine> MatchReplica<R> {
    pub fn new(session: Session, rules: R) -> Result<Self, EdgeError> {
        let state = rules.genesis(&session);
        if state.len() > MAX_STATE_BYTES {
            return Err(EdgeError::ResourceLimit);
        }
        let slots = session.roster.len();
        Ok(Self {
            session,
            rules,
            state,
            previous_checkpoint: [0; 32],
            next_tick: 0,
            head: vec![[0; 32]; slots],
            proposed: vec![None; slots],
            accepted: vec![],
            sanitize: false,
        })
    }
    pub fn match_id(&self) -> MatchId {
        self.session.match_id
    }
    /// Live play: illegal events are neutralized and reported instead of
    /// making the epoch impossible to certify.
    #[must_use]
    pub fn live(mut self) -> Self {
        self.sanitize = true;
        self
    }
    pub fn is_live(&self) -> bool {
        self.sanitize
    }
    pub fn state(&self) -> &[u8] {
        &self.state
    }
    pub fn next_tick(&self) -> u64 {
        self.next_tick
    }
    pub fn previous_checkpoint(&self) -> Digest {
        self.previous_checkpoint
    }
    pub fn accepted(&self) -> &[Epoch] {
        &self.accepted
    }
    pub fn next_batch_head(&self, participant: gv_core::ParticipantId) -> Option<Digest> {
        self.session
            .roster
            .index_of(&participant)
            .map(|i| self.head[i])
    }
    /// Stage one authenticated batch for the current epoch. All staged batches must have the
    /// same start and tick count; this does NOT decide who submitted in time.
    pub fn admit(&mut self, batch: SignedEventBatch) -> Result<(), EdgeError> {
        batch.verify().map_err(|_| EdgeError::BadSignature)?;
        if batch.record.match_id != self.session.match_id {
            return Err(EdgeError::WrongMatch);
        }
        let slot = self
            .session
            .roster
            .index_of(&batch.record.participant)
            .filter(|s| {
                self.session
                    .roster
                    .get(*s)
                    .is_some_and(|p| p.role.submits())
            })
            .ok_or(EdgeError::WrongParticipant)?;
        if self.proposed[slot].is_some() {
            return Err(EdgeError::AlreadyAccepted);
        }
        if batch.record.start_tick != self.next_tick
            || batch.record.previous_batch_hash != self.head[slot]
        {
            return Err(EdgeError::BrokenChain);
        }
        if self
            .proposed
            .iter()
            .flatten()
            .any(|other| other.record.tick_count != batch.record.tick_count)
        {
            return Err(EdgeError::WrongEpoch);
        }
        self.proposed[slot] = Some(batch);
        Ok(())
    }
    /// Drop every staged batch (an epoch that could not be completed).
    pub fn discard_pending(&mut self) {
        self.proposed = vec![None; self.session.roster.len()];
    }
    /// Every submitting participant has staged a batch.
    pub fn pending_complete(&self) -> bool {
        self.session
            .roster
            .submitters()
            .iter()
            .all(|slot| self.proposed[*slot].is_some())
    }
    /// Deterministic candidate; does not finalize until the certification policy is met.
    pub fn candidate(&self) -> Result<Epoch, EdgeError> {
        self.candidate_with_violations().map(|(epoch, _)| epoch)
    }
    /// Candidate plus every illegal event neutralized while replaying it. Slots that staged
    /// nothing are committed as absent.
    pub fn candidate_with_violations(&self) -> Result<(Epoch, Vec<InputViolation>), EdgeError> {
        let count = self
            .proposed
            .iter()
            .flatten()
            .map(|b| b.record.tick_count)
            .next()
            .ok_or(EdgeError::MissingBatch)?;
        if count == 0 || count > MAX_EPOCH_TICKS {
            return Err(EdgeError::ResourceLimit);
        }
        if self.next_tick.checked_add(u64::from(count)).is_none() {
            return Err(EdgeError::WrongEpoch);
        }
        let refs: Vec<_> = self.proposed.iter().map(Option::as_ref).collect();
        let records: Vec<_> = refs.iter().map(|b| b.map(|b| &b.record)).collect();
        let replayed = replay_epoch(
            &self.rules,
            &self.session,
            &self.state,
            self.next_tick,
            count,
            &records,
            self.sanitize,
        )
        .map_err(EdgeError::from)?;
        let checkpoint = Checkpoint {
            match_id: self.session.match_id,
            session: self.session.digest(),
            ruleset: self.rules.ruleset_hash(),
            epoch_start: self.next_tick,
            epoch_length: count,
            previous_checkpoint: self.previous_checkpoint,
            previous_state: state_commitment(&self.state),
            input_root: inputs_root(&refs).map_err(|_| EdgeError::BadSignature)?,
            next_state: state_commitment(&replayed.state),
        };
        Ok((
            Epoch {
                checkpoint,
                inputs: self.proposed.clone(),
                previous_state: self.state.clone(),
                next_state: replayed.state,
                signatures: None,
            },
            replayed.violations,
        ))
    }
    pub fn sign_candidate(&self, key: &SigningKey) -> Result<SignedCheckpoint, EdgeError> {
        if !self
            .session
            .roster
            .find(&key.id())
            .is_some_and(|p| p.role.signs())
        {
            return Err(EdgeError::WrongParticipant);
        }
        Ok(SignedCheckpoint::sign(self.candidate()?.checkpoint, key))
    }
    /// The session's certification policy decides how many matching signatures finalize an
    /// epoch. No signer can finalize a history the policy does not accept, and an epoch
    /// certified by a threshold is still only as strong as that threshold: it is not global
    /// consensus.
    pub fn finalize(&mut self, signatures: Vec<SignedCheckpoint>) -> Result<Digest, EdgeError> {
        let mut epoch = self.candidate()?;
        let roster = &self.session.roster;
        let mut slots = Vec::with_capacity(signatures.len());
        for s in &signatures {
            s.verify().map_err(|_| EdgeError::BadSignature)?;
            let slot = roster
                .index_of(&s.signer)
                .filter(|slot| roster.get(*slot).is_some_and(|p| p.role.signs()))
                .ok_or(EdgeError::WrongParticipant)?;
            if s.claim != epoch.checkpoint || slots.contains(&slot) {
                return Err(EdgeError::BadCheckpoint);
            }
            slots.push(slot);
        }
        if !self.session.certification.satisfied(roster, &slots) {
            return Err(EdgeError::NotCertified);
        }
        let mut ordered: Vec<_> = slots.into_iter().zip(signatures).collect();
        ordered.sort_by_key(|(slot, _)| *slot);
        epoch.signatures = Some(ordered.into_iter().map(|(_, s)| s).collect());
        self.advance(epoch)
    }
    fn advance(&mut self, epoch: Epoch) -> Result<Digest, EdgeError> {
        let digest = epoch.checkpoint.digest();
        for (slot, input) in epoch.inputs.iter().enumerate() {
            if let Some(batch) = input {
                self.head[slot] = batch.digest().map_err(|_| EdgeError::BadSignature)?;
            }
        }
        self.next_tick += u64::from(epoch.checkpoint.epoch_length);
        self.previous_checkpoint = digest;
        self.state = epoch.next_state.clone();
        self.accepted.push(epoch);
        self.proposed = vec![None; self.session.roster.len()];
        Ok(digest)
    }
    /// Drop all but the newest `keep` accepted epochs. A long live match
    /// certifies thousands of epochs; the durable record is the receipt archive,
    /// so the replica only needs the chain head (state, tick, checkpoint hash).
    pub fn prune_accepted(&mut self, keep: usize) {
        let excess = self.accepted.len().saturating_sub(keep);
        self.accepted.drain(..excess);
    }
    /// Advance past an epoch whose certification was refused because a signer
    /// signed a provably false claim. The caller MUST already hold independent
    /// evidence (`verify_checkpoint_evidence` => `ProvenInvalidState`); the
    /// honest, replayed candidate becomes the chain head. The epoch is kept
    /// without signatures, so it cannot be exported as a certified receipt.
    pub fn finalize_disputed(&mut self) -> Result<Digest, EdgeError> {
        let epoch = self.candidate()?;
        self.advance(epoch)
    }
}
impl From<ReplayError> for EdgeError {
    fn from(e: ReplayError) -> Self {
        match e {
            ReplayError::Violation(_) => Self::InvalidAction,
            ReplayError::Execution(_) => Self::RuleFailure,
            ReplayError::StateTooLarge => Self::ResourceLimit,
            ReplayError::Malformed => Self::WrongEpoch,
        }
    }
}
impl From<CheckpointError> for EdgeError {
    fn from(_: CheckpointError) -> Self {
        Self::BadCheckpoint
    }
}
