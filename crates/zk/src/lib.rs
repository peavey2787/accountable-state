//! Deliberately fail-closed extension boundary. No Groth16 proving or verification yet.
#![forbid(unsafe_code)]
use gv_core::Digest;

#[derive(Clone, Debug)]
pub struct PublicClaim {
    pub match_id: Digest,
    pub manifest_hash: Digest,
    pub ruleset_hash: Digest,
    pub program_id: Digest,
    pub accepted_checkpoint_id: Digest,
    pub prior_root: Digest,
    pub input_root: Digest,
    pub next_root: Digest,
    pub violation_code: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ZkError {
    Unsupported,
    Invalid,
}

pub trait ZkVerifier {
    fn verify(&self, statement: &PublicClaim, proof: &[u8]) -> Result<(), ZkError>;
}

pub struct DisabledZk;
impl ZkVerifier for DisabledZk {
    fn verify(&self, _: &PublicClaim, _: &[u8]) -> Result<(), ZkError> {
        Err(ZkError::Unsupported)
    }
}
