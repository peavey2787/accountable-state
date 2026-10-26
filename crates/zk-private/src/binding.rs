use crate::Program;
use gv_core::Digest;
use gv_zk::PublicClaim;
use sha2::{Digest as _, Sha256};
use zk_sdk::predicate::Commitment;

/// The public facts a step is bound to besides the two states.
#[derive(Clone, Copy, Debug)]
pub struct Context {
    pub match_id: Digest,
    pub manifest_hash: Digest,
    pub ruleset_hash: Digest,
    pub accepted_checkpoint_id: Digest,
    pub input_root: Digest,
}

impl Context {
    /// A 128-bit tag over every public field but the roots (those are bound by checking them
    /// against the commitment lists, which contain the tag).
    pub(crate) fn tag(&self, program: &Program) -> u128 {
        let mut h = Sha256::new();
        h.update(b"gv-zk-private/context/v1");
        for part in [
            &program.id(),
            &self.match_id,
            &self.manifest_hash,
            &self.ruleset_hash,
            &self.accepted_checkpoint_id,
            &self.input_root,
        ] {
            h.update(part);
        }
        h.update(program.violation_code().to_le_bytes());
        let out: Digest = h.finalize().into();
        let mut head = [0u8; 16];
        head.copy_from_slice(&out[..16]);
        u128::from_le_bytes(head)
    }

    pub(crate) fn claim(
        &self,
        program: &Program,
        old: &[Commitment],
        new: &[Commitment],
    ) -> PublicClaim {
        PublicClaim {
            match_id: self.match_id,
            manifest_hash: self.manifest_hash,
            ruleset_hash: self.ruleset_hash,
            program_id: program.id(),
            accepted_checkpoint_id: self.accepted_checkpoint_id,
            prior_root: root(old),
            input_root: self.input_root,
            next_root: root(new),
            violation_code: program.violation_code(),
        }
    }

    pub(crate) fn of(claim: &PublicClaim) -> Self {
        Self {
            match_id: claim.match_id,
            manifest_hash: claim.manifest_hash,
            ruleset_hash: claim.ruleset_hash,
            accepted_checkpoint_id: claim.accepted_checkpoint_id,
            input_root: claim.input_root,
        }
    }
}

/// Digest of an ordered commitment list.
pub(crate) fn root(list: &[Commitment]) -> Digest {
    let mut h = Sha256::new();
    h.update(b"gv-zk-private/state/v1");
    h.update((list.len() as u64).to_le_bytes());
    for c in list {
        let text = c.to_text();
        h.update((text.len() as u64).to_le_bytes());
        h.update(text.as_bytes());
    }
    h.finalize().into()
}
