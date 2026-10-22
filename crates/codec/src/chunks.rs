//! Medium-agnostic chunking of an authenticated [`Aggregate`] (`GVKC` V1).
//!
//! Splits the canonical aggregate encoding into ordered, self-describing chunks that fit any
//! size-bounded carrier (a file system record, an object store, a message queue, a settlement
//! system). The core has no opinion about the carrier; the caller supplies the size budget.
//! The aggregate digest authenticates the whole payload, but chunking provides no timestamping,
//! availability or ordering guarantee by itself.
use crate::{Aggregate, MAX_AGGREGATE_BYTES};
use gv_core::Digest;

/// Envelope bytes in front of each chunk's data: magic 4 + version 1 + digest 32 + index 4 + count 4 + len 4.
pub const CHUNK_HEADER_BYTES: usize = 49;
pub const MAX_CHUNKS: usize = 4096;
const MAGIC: &[u8; 4] = b"GVKC";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkError {
    InvalidBudget,
    TooManyChunks,
    MissingChunks,
    TamperedChunk,
    InvalidEncoding,
    Oversize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest chunk (header included) the carrier accepts.
    pub payload_ceiling: usize,
    /// Bytes inside the ceiling reserved by the caller for its own framing.
    pub application_headroom: usize,
    /// Largest number of chunks the caller is willing to emit.
    pub max_chunks: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            payload_ceiling: 24 * 1024,
            application_headroom: 256,
            max_chunks: 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkPlan {
    /// The aggregate fits within `max_chunks` chunks.
    Chunked {
        chunks: Vec<Vec<u8>>,
        aggregate_hash: Digest,
    },
    /// Too many chunks for the caller's budget: keep the bytes elsewhere and carry only the hash.
    HashOnly {
        aggregate_hash: Digest,
        bytes: usize,
        required_chunks: usize,
    },
}

/// Deterministic chunking of the canonical encoding.
pub fn plan(aggregate: &Aggregate, limits: Limits) -> Result<ChunkPlan, ChunkError> {
    let encoded = aggregate
        .encode()
        .map_err(|_| ChunkError::InvalidEncoding)?;
    let aggregate_hash = aggregate
        .digest()
        .map_err(|_| ChunkError::InvalidEncoding)?;
    if limits.payload_ceiling <= CHUNK_HEADER_BYTES + limits.application_headroom
        || limits.max_chunks == 0
    {
        return Err(ChunkError::InvalidBudget);
    }
    let data_limit = limits.payload_ceiling - CHUNK_HEADER_BYTES - limits.application_headroom;
    let needed = encoded.len().div_ceil(data_limit);
    if needed > MAX_CHUNKS {
        return Err(ChunkError::TooManyChunks);
    }
    if needed > limits.max_chunks {
        return Ok(ChunkPlan::HashOnly {
            aggregate_hash,
            bytes: encoded.len(),
            required_chunks: needed,
        });
    }
    let count = u32::try_from(needed).map_err(|_| ChunkError::TooManyChunks)?;
    let chunks = encoded
        .chunks(data_limit)
        .enumerate()
        .map(|(index, bytes)| {
            let mut chunk = Vec::with_capacity(CHUNK_HEADER_BYTES + bytes.len());
            chunk.extend_from_slice(MAGIC);
            chunk.push(1);
            chunk.extend_from_slice(&aggregate_hash);
            chunk.extend_from_slice(&(index as u32).to_le_bytes());
            chunk.extend_from_slice(&count.to_le_bytes());
            chunk.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            chunk.extend_from_slice(bytes);
            chunk
        })
        .collect();
    Ok(ChunkPlan::Chunked {
        chunks,
        aggregate_hash,
    })
}

fn le32(b: &[u8]) -> Result<u32, ChunkError> {
    Ok(u32::from_le_bytes(
        b.try_into().map_err(|_| ChunkError::TamperedChunk)?,
    ))
}

/// Reassemble only an explicitly expected hash, with exact sequential chunk indices.
pub fn reassemble(chunks: &[Vec<u8>], expected_hash: Digest) -> Result<Aggregate, ChunkError> {
    if chunks.is_empty() || chunks.len() > MAX_CHUNKS {
        return Err(ChunkError::MissingChunks);
    }
    let mut joined = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        if chunk.len() < CHUNK_HEADER_BYTES
            || &chunk[..4] != MAGIC
            || chunk[4] != 1
            || chunk[5..37] != expected_hash
        {
            return Err(ChunkError::TamperedChunk);
        }
        let (index, total, len) = (
            le32(&chunk[37..41])?,
            le32(&chunk[41..45])?,
            le32(&chunk[45..49])? as usize,
        );
        if index as usize != i
            || total as usize != chunks.len()
            || len != chunk.len() - CHUNK_HEADER_BYTES
        {
            return Err(ChunkError::MissingChunks);
        }
        joined.extend_from_slice(&chunk[CHUNK_HEADER_BYTES..]);
        if joined.len() > MAX_AGGREGATE_BYTES {
            return Err(ChunkError::Oversize);
        }
    }
    let aggregate = Aggregate::decode(&joined).map_err(|_| ChunkError::InvalidEncoding)?;
    if aggregate
        .digest()
        .map_err(|_| ChunkError::InvalidEncoding)?
        != expected_hash
    {
        return Err(ChunkError::TamperedChunk);
    }
    Ok(aggregate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventBatch, EventBody, HeldChange, SignedEventBatch};
    use gv_sig::SigningKey;

    fn sample() -> Aggregate {
        let k = SigningKey::from_seed([9; 32]);
        let changes = (1..100)
            .map(|i| HeldChange {
                offset: i,
                payload: vec![u8::from(i % 2 != 0)],
            })
            .collect();
        let rec = EventBatch {
            match_id: [1; 32],
            participant: k.id(),
            previous_batch_hash: [2; 32],
            start_tick: 0,
            tick_count: 100,
            body: EventBody::Held {
                initial: vec![0],
                changes,
            },
        };
        Aggregate {
            records: vec![SignedEventBatch::sign(rec, &k).unwrap()],
        }
    }

    #[test]
    fn split_reassemble_and_budget_fail_closed() {
        let agg = sample();
        let limits = Limits {
            payload_ceiling: 160,
            application_headroom: 0,
            max_chunks: 64,
        };
        let ChunkPlan::Chunked {
            mut chunks,
            aggregate_hash,
        } = plan(&agg, limits).unwrap()
        else {
            panic!("expected chunks")
        };
        assert!(chunks.iter().all(|c| c.len() <= 160));
        assert_eq!(reassemble(&chunks, aggregate_hash).unwrap(), agg);
        chunks[0][55] ^= 1;
        assert!(reassemble(&chunks, aggregate_hash).is_err());
        assert!(matches!(
            plan(
                &agg,
                Limits {
                    max_chunks: 1,
                    ..limits
                }
            )
            .unwrap(),
            ChunkPlan::HashOnly { .. }
        ));
        let bad = Limits {
            payload_ceiling: 49,
            application_headroom: 0,
            max_chunks: 1,
        };
        assert_eq!(plan(&agg, bad), Err(ChunkError::InvalidBudget));
    }

    #[test]
    fn missing_reordered_and_foreign_chunks_are_rejected() {
        let agg = sample();
        let limits = Limits {
            payload_ceiling: 400,
            application_headroom: 0,
            max_chunks: 64,
        };
        let ChunkPlan::Chunked {
            chunks,
            aggregate_hash,
        } = plan(&agg, limits).unwrap()
        else {
            panic!()
        };
        assert!(chunks.len() > 2);
        let mut dropped = chunks.clone();
        dropped.remove(1);
        assert!(reassemble(&dropped, aggregate_hash).is_err());
        let mut swapped = chunks.clone();
        swapped.swap(0, 1);
        assert!(reassemble(&swapped, aggregate_hash).is_err());
        assert!(reassemble(&chunks, [0; 32]).is_err());
        assert!(reassemble(&[], aggregate_hash).is_err());
    }
}
