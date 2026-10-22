//! Canonically ordered signed batches, optionally spanning multiple sessions.
use crate::batch::VERSION;
use crate::signed::SignedEventBatch;
use crate::wire::{push_varint, read_array, read_slice, read_varint, CodecError};
use gv_core::Digest;
use sha2::{Digest as ShaDigest, Sha256};

const AGG_MAGIC: &[u8; 4] = b"GVAG";
const AGG_DOMAIN: &[u8] = b"gv/event-aggregate-hash/v2\0";
pub const MAX_AGGREGATE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_AGGREGATE_RECORDS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aggregate {
    pub records: Vec<SignedEventBatch>,
}

impl Aggregate {
    pub fn validate(&self) -> Result<(), CodecError> {
        if self.records.is_empty() || self.records.len() > MAX_AGGREGATE_RECORDS {
            return Err(CodecError::InvalidRange);
        }
        let mut previous: Option<&SignedEventBatch> = None;
        for record in &self.records {
            record.verify()?;
            if let Some(prior) = previous {
                check_follows(prior, record)?;
            }
            previous = Some(record);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(AGG_MAGIC);
        out.push(VERSION);
        push_varint(self.records.len() as u32, &mut out);
        for record in &self.records {
            let data = record.encode()?;
            if data.len() > u32::MAX as usize
                || out.len().saturating_add(data.len()).saturating_add(5) > MAX_AGGREGATE_BYTES
            {
                return Err(CodecError::TooLarge);
            }
            push_varint(data.len() as u32, &mut out);
            out.extend_from_slice(&data);
        }
        Ok(out)
    }

    pub fn decode(b: &[u8]) -> Result<Self, CodecError> {
        if b.len() > MAX_AGGREGATE_BYTES {
            return Err(CodecError::TooLarge);
        }
        let mut pos = 0;
        if read_array::<4>(b, &mut pos)? != *AGG_MAGIC
            || read_array::<1>(b, &mut pos)?[0] != VERSION
        {
            return Err(CodecError::InvalidVersion);
        }
        let count = read_varint(b, &mut pos)? as usize;
        if count == 0 || count > MAX_AGGREGATE_RECORDS {
            return Err(CodecError::InvalidRange);
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let len = read_varint(b, &mut pos)? as usize;
            records.push(SignedEventBatch::decode(read_slice(b, &mut pos, len)?)?);
        }
        if pos != b.len() {
            return Err(CodecError::NonCanonical);
        }
        let result = Self { records };
        result.validate()?;
        Ok(result)
    }

    pub fn digest(&self) -> Result<Digest, CodecError> {
        let mut h = Sha256::new();
        h.update(AGG_DOMAIN);
        h.update(self.encode()?);
        Ok(h.finalize().into())
    }
}

/// Order is `(session, participant, start_tick)`; one participant's consecutive batches in a
/// session must chain by `previous_batch_hash` and never overlap. A gap is an epoch the
/// participant was absent from; the chain still binds what came before it.
fn check_follows(prior: &SignedEventBatch, next: &SignedEventBatch) -> Result<(), CodecError> {
    let key = |r: &SignedEventBatch| (r.record.match_id, r.record.participant, r.record.start_tick);
    if key(prior) >= key(next) {
        return Err(CodecError::NonCanonical);
    }
    let same_stream = prior.record.match_id == next.record.match_id
        && prior.record.participant == next.record.participant;
    if !same_stream {
        return Ok(());
    }
    let expected_tick = prior
        .record
        .start_tick
        .checked_add(u64::from(prior.record.tick_count))
        .ok_or(CodecError::Overflow)?;
    if next.record.start_tick < expected_tick
        || next.record.previous_batch_hash != prior.digest()?
    {
        return Err(CodecError::ChainMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::{EventBatch, EventBody};
    use gv_sig::{SigningKey, SIG_LEN};

    fn chain() -> (SignedEventBatch, SignedEventBatch) {
        let key = SigningKey::from_seed([7; 32]);
        let first = EventBatch {
            match_id: [1; 32],
            participant: key.id(),
            previous_batch_hash: [2; 32],
            start_tick: 500,
            tick_count: 180,
            body: EventBody::Held {
                initial: vec![1],
                changes: vec![],
            },
        };
        let first = SignedEventBatch::sign(first, &key).unwrap();
        let second = EventBatch {
            start_tick: 680,
            previous_batch_hash: first.digest().unwrap(),
            body: EventBody::Discrete { events: vec![] },
            ..first.record.clone()
        };
        (first, SignedEventBatch::sign(second, &key).unwrap())
    }

    #[test]
    fn single_record_layout_and_stable_digest() {
        let (first, _) = chain();
        let agg = Aggregate {
            records: vec![first.clone()],
        };
        let bytes = agg.encode().unwrap();
        assert_eq!(
            bytes.len(),
            4 + 1 + 1 + 2 + first.record.encode().unwrap().len() + SIG_LEN
        );
        assert_eq!(agg.digest().unwrap(), agg.digest().unwrap());
    }

    #[test]
    fn aggregates_require_order_chain_and_signatures() {
        let (first, second) = chain();
        let agg = Aggregate {
            records: vec![first.clone(), second.clone()],
        };
        assert_eq!(Aggregate::decode(&agg.encode().unwrap()).unwrap(), agg);
        let reversed = Aggregate {
            records: vec![second.clone(), first.clone()],
        };
        assert_eq!(reversed.validate(), Err(CodecError::NonCanonical));
        // Overlapping the previous batch is refused even when the order is right.
        let mut gap = second.record.clone();
        gap.start_tick -= 1;
        let key = SigningKey::from_seed([7; 32]);
        let gapped = Aggregate {
            records: vec![first.clone(), SignedEventBatch::sign(gap, &key).unwrap()],
        };
        assert_eq!(gapped.validate(), Err(CodecError::ChainMismatch));
        // A gap (an absent epoch) is allowed: the hash chain still binds the history.
        let mut absent = second.record.clone();
        absent.start_tick += 40;
        let absent = Aggregate {
            records: vec![first.clone(), SignedEventBatch::sign(absent, &key).unwrap()],
        };
        assert_eq!(absent.validate(), Ok(()));
        assert_eq!(
            Aggregate { records: vec![] }.validate(),
            Err(CodecError::InvalidRange)
        );
    }

    #[test]
    fn tampered_or_truncated_encodings_are_rejected() {
        let (first, second) = chain();
        let bytes = Aggregate {
            records: vec![first, second],
        }
        .encode()
        .unwrap();
        assert!(Aggregate::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Aggregate::decode(&trailing).is_err());
        let mut flipped = bytes;
        flipped[20] ^= 1;
        assert!(Aggregate::decode(&flipped).is_err());
    }
}
