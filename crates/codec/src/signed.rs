//! A participant's ML-DSA signature over one canonical [`EventBatch`].
use crate::batch::{EventBatch, MAX_RECORD_BYTES};
use crate::wire::CodecError;
use gv_core::Digest;
use gv_sig::{Signature, SigningKey, SIG_LEN};
use sha2::{Digest as ShaDigest, Sha256};

const SIGN_LABEL: &str = "gv/event-batch-signed/v2";
const HASH_DOMAIN: &[u8] = b"gv/event-batch-hash/v2\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedEventBatch {
    pub record: EventBatch,
    pub signature: Signature,
}

impl SignedEventBatch {
    pub fn sign(record: EventBatch, key: &SigningKey) -> Result<Self, CodecError> {
        if record.participant != key.id() {
            return Err(CodecError::WrongSigner);
        }
        let signature = key.sign(SIGN_LABEL, &record.encode()?);
        Ok(Self { record, signature })
    }
    pub fn verify(&self) -> Result<(), CodecError> {
        let bytes = self.record.encode()?;
        gv_sig::verify(
            &self.record.participant,
            SIGN_LABEL,
            &bytes,
            &self.signature,
        )
        .map_err(|e| match e {
            gv_sig::SigError::UnknownSigner => CodecError::WrongSigner,
            _ => CodecError::InvalidSignature,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.verify()?;
        let mut out = self.record.encode()?;
        out.extend_from_slice(self.signature.as_bytes());
        Ok(out)
    }
    pub fn decode(b: &[u8]) -> Result<Self, CodecError> {
        if b.len() < SIG_LEN || b.len() > MAX_RECORD_BYTES + SIG_LEN {
            return Err(CodecError::TooLarge);
        }
        let (record_bytes, signature_bytes) = b.split_at(b.len() - SIG_LEN);
        let record = EventBatch::decode(record_bytes)?;
        let signature =
            Signature::from_slice(signature_bytes).map_err(|_| CodecError::InvalidSignature)?;
        let signed = Self { record, signature };
        signed.verify()?;
        Ok(signed)
    }
    /// Hash includes the signature. Use in Merkle logs and `previous_batch_hash`.
    pub fn digest(&self) -> Result<Digest, CodecError> {
        let mut h = Sha256::new();
        h.update(HASH_DOMAIN);
        h.update(self.encode()?);
        Ok(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::{EventBody, HeldChange};

    pub(crate) fn fixture() -> (EventBatch, SigningKey) {
        let key = SigningKey::from_seed([7; 32]);
        (
            EventBatch {
                match_id: [1; 32],
                participant: key.id(),
                previous_batch_hash: [2; 32],
                start_tick: 500,
                tick_count: 180,
                body: EventBody::Held {
                    initial: vec![1],
                    changes: vec![HeldChange {
                        offset: 179,
                        payload: vec![0],
                    }],
                },
            },
            key,
        )
    }

    /// Signatures are randomized, so two honest signings of one record differ in `digest()`.
    /// Equivocation must therefore compare the signed record, never the digest.
    #[test]
    fn re_signing_one_record_changes_the_digest_but_not_the_record() {
        let (record, key) = fixture();
        let a = SignedEventBatch::sign(record.clone(), &key).unwrap();
        let b = SignedEventBatch::sign(record, &key).unwrap();
        assert_eq!(a.record, b.record);
        assert_ne!(a.digest().unwrap(), b.digest().unwrap());
    }

    #[test]
    fn compact_layout_and_tamper_rejection() {
        let (record, key) = fixture();
        let signed = SignedEventBatch::sign(record.clone(), &key).unwrap();
        let bytes = signed.encode().unwrap();
        // magic + version + match + participant + prev + start + count + kind + width + initial
        // + change count + (2-byte delta + 1-byte payload) + signature
        assert_eq!(
            bytes.len(),
            4 + 1 + 32 + 32 + 32 + 8 + 4 + 1 + 1 + 1 + 1 + 2 + 1 + SIG_LEN
        );
        assert_eq!(SignedEventBatch::decode(&bytes).unwrap(), signed);
        // The digest commits to the signature (ML-DSA signing is hedged, so it differs per signing).
        let other = SignedEventBatch::sign(record, &key).unwrap();
        assert_ne!(signed.digest().unwrap(), other.digest().unwrap());
        let mut altered = bytes.clone();
        altered[110] ^= 1;
        assert!(SignedEventBatch::decode(&altered).is_err());
        let mut magic = bytes;
        magic[0] ^= 1;
        assert!(SignedEventBatch::decode(&magic).is_err());
    }

    #[test]
    fn only_the_participant_can_sign_for_itself() {
        let (record, _) = fixture();
        let stranger = SigningKey::from_seed([8; 32]);
        assert_eq!(
            SignedEventBatch::sign(record, &stranger),
            Err(CodecError::WrongSigner)
        );
    }
}
