//! Post-quantum signature layer for every portable gameplay artifact.
//!
//! * One scheme, ML-DSA-65, implemented by Hydra's `hydra-crypto` (no custom
//!   lattice code lives here).
//! * Every signature is over `SHA-512(domain-separated envelope)`; the envelope
//!   binds protocol version, algorithm id, the signer's identity and an explicit
//!   per-message-type label to the message body. Message bodies bind match id,
//!   ruleset, tick/sequence and predecessor commitments themselves.
//! * A `ParticipantId` is `SHA-256("gv/player-id/v1" || alg || verifying key)`: a
//!   fixed 32-byte name for a 1952-byte key. Keys are interned in a
//!   content-addressed table, so an entry can never disagree with its id.
//!
//! Encrypted-session authentication (Hydra transport) is deliberately not used
//! for evidence: only these signatures are verifiable by third parties.
#![forbid(unsafe_code)]

use gv_core::ParticipantId;
use hydra_core::{ML_DSA_65_SIG_SIZE, ML_DSA_65_VK_SIZE};
use hydra_crypto::{MlDsaKeyPair, MlDsaVerificationKey};
use sha2::{Digest as _, Sha256, Sha512};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use zeroize::Zeroizing;

pub const SIG_LEN: usize = ML_DSA_65_SIG_SIZE;
pub const VK_LEN: usize = ML_DSA_65_VK_SIZE;
/// Wire algorithm identifier for ML-DSA-65.
pub const ALG_ML_DSA_65: u8 = 1;
/// Signature-envelope protocol version.
pub const SIG_VERSION: u8 = 1;
/// Upper bound on interned verifying keys per process (memory DoS bound).
pub const MAX_INTERNED_KEYS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    UnknownSigner,
    BadSignature,
    BadLength,
    BadAlgorithm,
    RegistryFull,
    Entropy,
}

/// An ML-DSA-65 signature (fixed length, canonical encoding).
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(Box<[u8; SIG_LEN]>);

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}
impl Signature {
    pub fn from_slice(b: &[u8]) -> Result<Self, SigError> {
        let a: [u8; SIG_LEN] = b.try_into().map_err(|_| SigError::BadLength)?;
        Ok(Self(Box::new(a)))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
    /// A copy with one bit flipped (tamper-testing helper).
    pub fn with_bit_flipped(&self, byte: usize) -> Self {
        let mut c = self.clone();
        c.0[byte % SIG_LEN] ^= 1;
        c
    }
    /// All-zero placeholder used while a message is being assembled; never verifies.
    pub fn zero() -> Self {
        Self(Box::new([0; SIG_LEN]))
    }
}

/// The pluggable scheme boundary: everything game logic needs from a signature
/// algorithm. Game code never calls the backend directly.
pub trait SignatureScheme {
    const ALGORITHM_ID: u8;
    type Verifier: Send + Sync;
    fn decode_verifier(vk: &[u8]) -> Result<Self::Verifier, SigError>;
    fn verify(v: &Self::Verifier, digest: &[u8; 64], sig: &[u8]) -> Result<(), SigError>;
}

/// Hydra's ML-DSA-65 (FIPS 204) through `hydra-crypto`.
pub struct HydraMlDsa65;
impl SignatureScheme for HydraMlDsa65 {
    const ALGORITHM_ID: u8 = ALG_ML_DSA_65;
    type Verifier = MlDsaVerificationKey;
    fn decode_verifier(vk: &[u8]) -> Result<Self::Verifier, SigError> {
        MlDsaVerificationKey::from_bytes(vk).map_err(|_| SigError::BadLength)
    }
    fn verify(v: &Self::Verifier, digest: &[u8; 64], sig: &[u8]) -> Result<(), SigError> {
        v.verify_digest(digest, sig)
            .map_err(|_| SigError::BadSignature)
    }
}

type Scheme = HydraMlDsa65;

pub fn player_id_of(vk: &[u8]) -> ParticipantId {
    let mut h = Sha256::new();
    h.update(b"gv/player-id/v1\0");
    h.update([ALG_ML_DSA_65]);
    h.update(vk);
    h.finalize().into()
}

struct Interned {
    bytes: Box<[u8; VK_LEN]>,
    verifier: <Scheme as SignatureScheme>::Verifier,
}
static KEYS: OnceLock<RwLock<HashMap<ParticipantId, Arc<Interned>>>> = OnceLock::new();
fn table() -> &'static RwLock<HashMap<ParticipantId, Arc<Interned>>> {
    KEYS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Interns a verifying key and returns its `ParticipantId`. Idempotent.
pub fn register_key(vk: &[u8]) -> Result<ParticipantId, SigError> {
    let arr: [u8; VK_LEN] = vk.try_into().map_err(|_| SigError::BadLength)?;
    let id = player_id_of(&arr);
    if table()
        .read()
        .map_err(|_| SigError::RegistryFull)?
        .contains_key(&id)
    {
        return Ok(id);
    }
    let verifier = Scheme::decode_verifier(&arr)?;
    let mut t = table().write().map_err(|_| SigError::RegistryFull)?;
    if t.len() >= MAX_INTERNED_KEYS && !t.contains_key(&id) {
        return Err(SigError::RegistryFull);
    }
    t.entry(id).or_insert_with(|| {
        Arc::new(Interned {
            bytes: Box::new(arr),
            verifier,
        })
    });
    Ok(id)
}

/// The verifying-key bytes for an interned player, if known.
pub fn public_key_bytes(id: &ParticipantId) -> Option<Vec<u8>> {
    table().read().ok()?.get(id).map(|k| k.bytes.to_vec())
}

/// True when the key for `id` is known (verification will not fail as `UnknownSigner`).
pub fn is_known(id: &ParticipantId) -> bool {
    table().read().map(|t| t.contains_key(id)).unwrap_or(false)
}

/// 32 bytes from the operating system's CSPRNG (commitment blinding, nonces).
/// Fails closed: an entropy failure is an error, never a weak value.
pub fn random_32() -> Result<[u8; 32], SigError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| SigError::Entropy)?;
    Ok(b)
}

/// Portable public-key file: `GV-PUBKEY/V1\0 || alg || verifying key`.
pub fn encode_public_key_file(vk: &[u8; VK_LEN]) -> Vec<u8> {
    let mut b = b"GV-PUBKEY/V1\0".to_vec();
    b.push(ALG_ML_DSA_65);
    b.extend_from_slice(vk);
    b
}

/// Parses a public-key file, interns the key and returns the player's id.
pub fn decode_public_key_file(b: &[u8]) -> Result<ParticipantId, SigError> {
    const MAGIC: &[u8] = b"GV-PUBKEY/V1\0";
    let rest = b.strip_prefix(MAGIC).ok_or(SigError::BadLength)?;
    let (alg, vk) = rest.split_first().ok_or(SigError::BadLength)?;
    if *alg != ALG_ML_DSA_65 {
        return Err(SigError::BadAlgorithm);
    }
    register_key(vk)
}

/// The exact 64-byte message ML-DSA signs for `(label, signer, body)`; public so
/// independent implementations can reproduce and verify it.
pub fn envelope_digest(label: &str, signer: &ParticipantId, body: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"gv/sig-envelope\0");
    h.update([SIG_VERSION, ALG_ML_DSA_65]);
    h.update((label.len() as u16).to_le_bytes());
    h.update(label.as_bytes());
    h.update(signer);
    h.update((body.len() as u64).to_le_bytes());
    h.update(body);
    h.finalize().into()
}

/// A player's signing identity. The seed is zeroized on drop (Hydra clears the
/// expanded key); signing uses Hydra's hedged randomized ML-DSA with OS entropy.
#[derive(Clone)]
pub struct SigningKey {
    pair: Arc<MlDsaKeyPair>,
    vk: [u8; VK_LEN],
    id: ParticipantId,
}

impl SigningKey {
    pub fn generate() -> Result<Self, SigError> {
        let pair = MlDsaKeyPair::generate().map_err(|_| SigError::Entropy)?;
        Self::from_pair(pair)
    }
    /// Deterministic derivation from a 32-byte seed (identity stores, test vectors).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        let pair = MlDsaKeyPair::from_seed(*seed).expect("ML-DSA seed derivation is infallible");
        Self::from_pair(pair).expect("fresh key registers")
    }
    fn from_pair(pair: MlDsaKeyPair) -> Result<Self, SigError> {
        let vk = pair.verification_key.to_bytes();
        let id = register_key(&vk)?;
        Ok(Self {
            pair: Arc::new(pair),
            vk,
            id,
        })
    }
    pub fn id(&self) -> ParticipantId {
        self.id
    }
    pub fn public_key(&self) -> &[u8; VK_LEN] {
        &self.vk
    }
    /// Signs `body` under the message-type `label`.
    pub fn sign(&self, label: &str, body: &[u8]) -> Signature {
        let d = envelope_digest(label, &self.id, body);
        let bytes = self
            .pair
            .signing_key
            .sign_digest(&d)
            .expect("OS entropy unavailable: refusing to sign");
        Signature(Box::new(bytes))
    }
}

/// Strict verification of `sig` by `signer` over `(label, body)`.
pub fn verify(
    signer: &ParticipantId,
    label: &str,
    body: &[u8],
    sig: &Signature,
) -> Result<(), SigError> {
    let key = table()
        .read()
        .map_err(|_| SigError::UnknownSigner)?
        .get(signer)
        .cloned()
        .ok_or(SigError::UnknownSigner)?;
    Scheme::verify(
        &key.verifier,
        &envelope_digest(label, signer, body),
        sig.as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_domain_separation() {
        let k = SigningKey::from_seed([7; 32]);
        let s = k.sign("gv/test/a", b"hello");
        assert!(verify(&k.id(), "gv/test/a", b"hello", &s).is_ok());
        assert_eq!(
            verify(&k.id(), "gv/test/b", b"hello", &s),
            Err(SigError::BadSignature)
        );
        assert_eq!(
            verify(&k.id(), "gv/test/a", b"hellp", &s),
            Err(SigError::BadSignature)
        );
        let other = SigningKey::from_seed([8; 32]);
        assert_eq!(
            verify(&other.id(), "gv/test/a", b"hello", &s),
            Err(SigError::BadSignature)
        );
        let mut bad = s.as_bytes().to_vec();
        bad[10] ^= 1;
        assert!(verify(
            &k.id(),
            "gv/test/a",
            b"hello",
            &Signature::from_slice(&bad).unwrap()
        )
        .is_err());
        assert_eq!(Signature::from_slice(&bad[..100]), Err(SigError::BadLength));
    }

    #[test]
    fn public_key_files_round_trip() {
        let k = SigningKey::from_seed([5; 32]);
        let f = encode_public_key_file(k.public_key());
        assert_eq!(decode_public_key_file(&f), Ok(k.id()));
        let mut bad_alg = f.clone();
        bad_alg[b"GV-PUBKEY/V1\0".len()] = 9;
        assert_eq!(
            decode_public_key_file(&bad_alg),
            Err(SigError::BadAlgorithm)
        );
        assert!(decode_public_key_file(&f[..50]).is_err());
    }

    #[test]
    fn unknown_signer_is_rejected_and_ids_are_content_addressed() {
        let k = SigningKey::from_seed([9; 32]);
        assert_eq!(player_id_of(k.public_key()), k.id());
        assert_eq!(register_key(k.public_key()), Ok(k.id()));
        assert_eq!(register_key(&[0; 10]), Err(SigError::BadLength));
        let s = k.sign("x", b"y");
        assert_eq!(
            verify(&[1; 32], "x", b"y", &s),
            Err(SigError::UnknownSigner)
        );
    }

    #[test]
    fn fresh_keys_differ_and_signing_is_hedged() {
        let a = SigningKey::generate().unwrap();
        let b = SigningKey::generate().unwrap();
        assert_ne!(a.id(), b.id());
        let k = SigningKey::from_seed([3; 32]);
        assert_ne!(k.sign("x", b"y").as_bytes(), k.sign("x", b"y").as_bytes());
    }
}
