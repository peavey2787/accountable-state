//! Authenticated, bounded input transcript. Signatures do not by themselves establish
//! ordering or finality; a quorum-certified checkpoint must also be verified.
#![forbid(unsafe_code)]
use gv_core::{MatchId, PlayerId};
use gv_sig::{Signature, SigningKey};

pub const MAX_INPUT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedInput {
    pub match_id: MatchId,
    pub player: PlayerId,
    pub tick: u64,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    TooLarge,
    BadSignature,
    WrongPlayer,
    WrongSession,
    WrongSequence,
}

impl SignedInput {
    pub const LABEL: &'static str = "gv/signed-input/v1";
    pub fn signing_bytes(&self) -> Result<Vec<u8>, InputError> {
        if self.payload.len() > MAX_INPUT_BYTES {
            return Err(InputError::TooLarge);
        }
        let mut b = Vec::new();
        b.extend_from_slice(&self.match_id);
        b.extend_from_slice(&self.player);
        b.extend_from_slice(&self.tick.to_le_bytes());
        b.extend_from_slice(&self.sequence.to_le_bytes());
        b.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.payload);
        Ok(b)
    }
    pub fn new(
        key: &SigningKey,
        match_id: MatchId,
        tick: u64,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<Self, InputError> {
        let mut msg = Self {
            match_id,
            player: key.id(),
            tick,
            sequence,
            payload,
            signature: Signature::zero(),
        };
        msg.signature = key.sign(Self::LABEL, &msg.signing_bytes()?);
        Ok(msg)
    }
    pub fn verify(&self) -> Result<(), InputError> {
        if self.payload.len() > MAX_INPUT_BYTES {
            return Err(InputError::TooLarge);
        }
        gv_sig::verify(
            &self.player,
            Self::LABEL,
            &self.signing_bytes()?,
            &self.signature,
        )
        .map_err(|e| match e {
            gv_sig::SigError::UnknownSigner => InputError::WrongPlayer,
            _ => InputError::BadSignature,
        })
    }
    /// Canonical Merkle leaf includes the signature itself to prevent signature substitution.
    pub fn leaf_bytes(&self) -> Result<Vec<u8>, InputError> {
        let mut b = self.signing_bytes()?;
        b.extend_from_slice(self.signature.as_bytes());
        Ok(b)
    }
}

/// A separately authenticated state-output proposal. This is essential for
/// attributing a knowingly false state claim to a player; an input signature
/// alone only proves the player submitted an input, not the state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedStateClaim {
    pub match_id: MatchId,
    pub player: PlayerId,
    pub tick: u64,
    pub previous_state: [u8; 32],
    pub proposed_next_state: [u8; 32],
    pub input_root: [u8; 32],
    pub ruleset: [u8; 32],
    pub signature: Signature,
}
impl SignedStateClaim {
    pub const LABEL: &'static str = "gv/state-claim/v1";
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.match_id);
        b.extend_from_slice(&self.player);
        b.extend_from_slice(&self.tick.to_le_bytes());
        b.extend_from_slice(&self.previous_state);
        b.extend_from_slice(&self.proposed_next_state);
        b.extend_from_slice(&self.input_root);
        b.extend_from_slice(&self.ruleset);
        b
    }
    pub fn new(
        key: &SigningKey,
        match_id: MatchId,
        tick: u64,
        previous_state: [u8; 32],
        proposed_next_state: [u8; 32],
        input_root: [u8; 32],
        ruleset: [u8; 32],
    ) -> Self {
        let mut claim = Self {
            match_id,
            player: key.id(),
            tick,
            previous_state,
            proposed_next_state,
            input_root,
            ruleset,
            signature: Signature::zero(),
        };
        claim.signature = key.sign(Self::LABEL, &claim.signing_bytes());
        claim
    }
    pub fn verify(&self) -> Result<(), InputError> {
        gv_sig::verify(
            &self.player,
            Self::LABEL,
            &self.signing_bytes(),
            &self.signature,
        )
        .map_err(|e| match e {
            gv_sig::SigError::UnknownSigner => InputError::WrongPlayer,
            _ => InputError::BadSignature,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PlayerTranscript {
    match_id: Option<MatchId>,
    player: Option<PlayerId>,
    records: Vec<SignedInput>,
}

impl PlayerTranscript {
    pub fn new(match_id: MatchId, player: PlayerId) -> Self {
        Self {
            match_id: Some(match_id),
            player: Some(player),
            records: vec![],
        }
    }
    pub fn append(&mut self, msg: SignedInput) -> Result<(), InputError> {
        msg.verify()?;
        if self.match_id != Some(msg.match_id) {
            return Err(InputError::WrongSession);
        }
        if self.player != Some(msg.player) {
            return Err(InputError::WrongPlayer);
        }
        if msg.sequence != self.records.len() as u64 {
            return Err(InputError::WrongSequence);
        }
        if self
            .records
            .last()
            .is_some_and(|prior| msg.tick < prior.tick)
        {
            return Err(InputError::WrongSequence);
        }
        self.records.push(msg);
        Ok(())
    }
    pub fn records(&self) -> &[SignedInput] {
        &self.records
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_bytes_bind_the_signature() {
        let key = SigningKey::from_seed([7; 32]);
        let a = SignedInput::new(&key, [1; 32], 0, 0, b"left".to_vec()).unwrap();
        assert_eq!(a.player, key.id());
        assert!(a.verify().is_ok());
        let leaf = a.leaf_bytes().unwrap();
        assert_eq!(
            leaf.len(),
            a.signing_bytes().unwrap().len() + gv_sig::SIG_LEN
        );
        assert_eq!(
            &leaf[leaf.len() - gv_sig::SIG_LEN..],
            a.signature.as_bytes()
        );
    }

    #[test]
    fn signature_and_sequence() {
        let key = SigningKey::from_seed([7; 32]);
        let a = SignedInput::new(&key, [1; 32], 0, 0, b"left".to_vec()).unwrap();
        assert!(a.verify().is_ok());
        let mut t = PlayerTranscript::new([1; 32], key.id());
        assert!(t.append(a.clone()).is_ok());
        assert_eq!(t.append(a), Err(InputError::WrongSequence));
        let mut forged = SignedInput::new(&key, [1; 32], 1, 1, b"right".to_vec()).unwrap();
        forged.payload[0] ^= 1;
        assert_eq!(forged.verify(), Err(InputError::BadSignature));
    }
}
