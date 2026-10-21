//! Commitment/opening primitive only; confidential transport and selective disclosure
//! MUST be supplied by an audited AEAD protocol adapter.
#![forbid(unsafe_code)]
use gv_commitments::commit_secret;
use gv_core::Digest;

pub fn verify_reveal(
    label: &[u8],
    disclosed: &[u8],
    nonce: &Digest,
    locked_commitment: &Digest,
) -> bool {
    &commit_secret(label, disclosed, nonce) == locked_commitment
}
