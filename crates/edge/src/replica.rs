use super::checkpoint::{Checkpoint, CheckpointError, SignedCheckpoint};
use gv_codec::SignedPackedControls;
use gv_commitments::{commit_state, MerkleLog};
use gv_core::{Digest, MatchId, PlayerId, StateOpening};
use gv_replay::{RuleError, StateMachine};
use gv_sig::SigningKey;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdgeError {
    InvalidRoster,
    MissingBatch,
    WrongPlayer,
    BadSignature,
    WrongMatch,
    WrongEpoch,
    BrokenChain,
    BadCheckpoint,
    InvalidAction,
    ResourceLimit,
    AlreadyAccepted,
}

/// A signed control word the ruleset rejected as illegal. In live (sanitized)
/// replay it is replaced by a neutral input so honest play cannot be stalled,
/// and this record is the portable proof of who sent what at which tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputViolation {
    pub player: PlayerId,
    pub tick: u64,
    pub control: u16,
}

/// One authenticated rules step. With `sanitize`, an illegal control word is
/// replayed as neutral (control 0) and reported; every honest replayer and every
/// independent verifier substitutes identically, so the resulting state is
/// deterministic. Without it, an illegal action is an error (strict mode).
pub fn apply_tick<R: StateMachine>(
    rules: &R,
    state: &[u8],
    player: &PlayerId,
    tick: u64,
    control: u16,
    sanitize: bool,
) -> Result<(Vec<u8>, Option<InputViolation>), EdgeError> {
    let encode = |control: u16| {
        let mut input = Vec::with_capacity(42);
        input.extend_from_slice(player);
        input.extend_from_slice(&tick.to_le_bytes());
        input.extend_from_slice(&control.to_le_bytes());
        input
    };
    match rules.apply(state, &encode(control)) {
        Ok(next) => Ok((next, None)),
        Err(RuleError::InvalidAction(_)) if sanitize => rules
            .apply(state, &encode(0))
            .map(|next| {
                (
                    next,
                    Some(InputViolation {
                        player: *player,
                        tick,
                        control,
                    }),
                )
            })
            .map_err(|_| EdgeError::InvalidAction),
        Err(_) => Err(EdgeError::InvalidAction),
    }
}

#[derive(Clone, Debug)]
pub struct Epoch {
    pub checkpoint: Checkpoint,
    pub batches: [SignedPackedControls; 2],
    pub previous_state: Vec<u8>,
    pub next_state: Vec<u8>,
    /// Both players' signed identical checkpoints, present only after finalization.
    pub signatures: Option<[SignedCheckpoint; 2]>,
}

pub struct MatchReplica<R: StateMachine> {
    pub match_id: MatchId,
    pub roster: [PlayerId; 2],
    pub rules: R,
    state: Vec<u8>,
    previous_checkpoint: Digest,
    next_tick: u64,
    head: [Digest; 2],
    proposed: [Option<SignedPackedControls>; 2],
    accepted: Vec<Epoch>,
    sanitize: bool,
}
impl<R: StateMachine> MatchReplica<R> {
    pub fn new(match_id: MatchId, mut roster: [PlayerId; 2], rules: R) -> Result<Self, EdgeError> {
        roster.sort();
        if roster[0] == roster[1] {
            return Err(EdgeError::InvalidRoster);
        }
        let state = rules.genesis(&roster);
        if state.len() > 65536 {
            return Err(EdgeError::ResourceLimit);
        }
        Ok(Self {
            match_id,
            roster,
            rules,
            state,
            previous_checkpoint: [0; 32],
            next_tick: 0,
            head: [[0; 32]; 2],
            proposed: [None, None],
            accepted: vec![],
            sanitize: false,
        })
    }
    /// Live play: illegal controls are neutralized and reported instead of
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
    pub fn next_batch_head(&self, player: PlayerId) -> Option<Digest> {
        self.roster
            .iter()
            .position(|p| *p == player)
            .map(|i| self.head[i])
    }
    /// Stage one authenticated batch for the current epoch. Both must have equal
    /// start and tick count; this does NOT decide who submitted in time.
    pub fn admit(&mut self, batch: SignedPackedControls) -> Result<(), EdgeError> {
        batch.verify().map_err(|_| EdgeError::BadSignature)?;
        if batch.record.match_id != self.match_id {
            return Err(EdgeError::WrongMatch);
        }
        let Some(i) = self.roster.iter().position(|p| *p == batch.record.player) else {
            return Err(EdgeError::WrongPlayer);
        };
        if self.proposed[i].is_some() {
            return Err(EdgeError::AlreadyAccepted);
        }
        if batch.record.start_tick != self.next_tick
            || batch.record.previous_batch_hash != self.head[i]
        {
            return Err(EdgeError::BrokenChain);
        }
        if let Some(other) = self.proposed[1 - i].as_ref() {
            if other.record.tick_count != batch.record.tick_count {
                return Err(EdgeError::WrongEpoch);
            }
        }
        self.proposed[i] = Some(batch);
        Ok(())
    }
    pub fn pending_complete(&self) -> bool {
        self.proposed.iter().all(Option::is_some)
    }
    /// Deterministic candidate; does not finalize until both signatures match.
    pub fn candidate(&self) -> Result<Epoch, EdgeError> {
        self.candidate_with_violations().map(|(epoch, _)| epoch)
    }
    /// Candidate plus every illegal input neutralized while replaying it.
    pub fn candidate_with_violations(&self) -> Result<(Epoch, Vec<InputViolation>), EdgeError> {
        let a = self.proposed[0].as_ref().ok_or(EdgeError::MissingBatch)?;
        let b = self.proposed[1].as_ref().ok_or(EdgeError::MissingBatch)?;
        let count = a.record.tick_count;
        if count == 0 || count > 4096 {
            return Err(EdgeError::ResourceLimit);
        }
        if b.record.tick_count != count || self.next_tick.checked_add(u64::from(count)).is_none() {
            return Err(EdgeError::WrongEpoch);
        }
        let mut log = MerkleLog::new();
        for b in [a, b] {
            log.append(&b.encode().map_err(|_| EdgeError::BadSignature)?)
                .map_err(|_| EdgeError::ResourceLimit)?;
        }
        let mut next = self.state.clone();
        let mut violations = Vec::new();
        for offset in 0..count {
            for batch in [a, b] {
                let control = batch
                    .record
                    .state_at(offset)
                    .map_err(|_| EdgeError::InvalidAction)?;
                let (state, violation) = apply_tick(
                    &self.rules,
                    &next,
                    &batch.record.player,
                    self.next_tick + u64::from(offset),
                    control,
                    self.sanitize,
                )?;
                next = state;
                violations.extend(violation);
                if next.len() > 65536 {
                    return Err(EdgeError::ResourceLimit);
                }
            }
        }
        let checkpoint = Checkpoint {
            match_id: self.match_id,
            ruleset: self.rules.ruleset_hash(),
            epoch_start: self.next_tick,
            epoch_length: count,
            previous_checkpoint: self.previous_checkpoint,
            previous_state: commit_state(&StateOpening {
                bytes: self.state.clone(),
                nonce: [0; 32],
            }),
            input_root: log.root(),
            next_state: commit_state(&StateOpening {
                bytes: next.clone(),
                nonce: [0; 32],
            }),
        };
        Ok((
            Epoch {
                checkpoint,
                batches: [a.clone(), b.clone()],
                previous_state: self.state.clone(),
                next_state: next,
                signatures: None,
            },
            violations,
        ))
    }
    pub fn sign_candidate(&self, key: &SigningKey) -> Result<SignedCheckpoint, EdgeError> {
        if !self.roster.contains(&key.id()) {
            return Err(EdgeError::WrongPlayer);
        }
        Ok(SignedCheckpoint::sign(self.candidate()?.checkpoint, key))
    }
    /// Exact dual-signature agreement is required: no single client can finalize
    /// a history the other did not sign. This is *not* liveness under 1 Byzantine.
    pub fn finalize(&mut self, signatures: [SignedCheckpoint; 2]) -> Result<Digest, EdgeError> {
        let mut epoch = self.candidate()?;
        let digest = epoch.checkpoint.digest();
        for (i, s) in signatures.iter().enumerate() {
            s.verify().map_err(|_| EdgeError::BadSignature)?;
            if s.player != self.roster[i] || s.claim != epoch.checkpoint {
                return Err(EdgeError::BadCheckpoint);
            }
        }
        self.head[0] = epoch.batches[0]
            .digest()
            .map_err(|_| EdgeError::BadSignature)?;
        self.head[1] = epoch.batches[1]
            .digest()
            .map_err(|_| EdgeError::BadSignature)?;
        self.next_tick += u64::from(epoch.checkpoint.epoch_length);
        self.previous_checkpoint = digest;
        self.state = epoch.next_state.clone();
        epoch.signatures = Some(signatures);
        self.accepted.push(epoch);
        self.proposed = [None, None];
        Ok(digest)
    }
}
impl<R: StateMachine> MatchReplica<R> {
    /// Drop all but the newest `keep` accepted epochs. A long live match
    /// certifies thousands of epochs; the durable record is the receipt archive,
    /// so the replica only needs the chain head (state, tick, checkpoint hash).
    pub fn prune_accepted(&mut self, keep: usize) {
        let excess = self.accepted.len().saturating_sub(keep);
        self.accepted.drain(..excess);
    }
    /// Advance past an epoch whose co-signature was refused because one party
    /// signed a provably false claim. The caller MUST already hold independent
    /// evidence (`verify_checkpoint_evidence` => `ProvenInvalidState`); the
    /// honest, replayed candidate becomes the chain head. The epoch is kept
    /// without a dual signature, so it cannot be exported as a certified receipt.
    pub fn finalize_disputed(&mut self) -> Result<Digest, EdgeError> {
        let epoch = self.candidate()?;
        let digest = epoch.checkpoint.digest();
        self.head[0] = epoch.batches[0]
            .digest()
            .map_err(|_| EdgeError::BadSignature)?;
        self.head[1] = epoch.batches[1]
            .digest()
            .map_err(|_| EdgeError::BadSignature)?;
        self.next_tick += u64::from(epoch.checkpoint.epoch_length);
        self.previous_checkpoint = digest;
        self.state = epoch.next_state.clone();
        self.accepted.push(epoch);
        self.proposed = [None, None];
        Ok(digest)
    }
}
impl From<CheckpointError> for EdgeError {
    fn from(_: CheckpointError) -> Self {
        Self::BadCheckpoint
    }
}
