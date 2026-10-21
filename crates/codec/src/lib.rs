//! Authenticated, event-driven digital control streams. Canonical wire format v1.
//! This codec does NOT replace input admission, BFT ordering, or physics replay.
#![forbid(unsafe_code)]
use gv_core::{Digest, MatchId, PlayerId};
use gv_sig::{Signature, SigningKey, SIG_LEN};
use sha2::{Digest as ShaDigest, Sha256};

const MAGIC: &[u8; 4] = b"GVEC";
const AGG_MAGIC: &[u8; 4] = b"GVAG";
const VERSION: u8 = 1;
const SIGN_LABEL: &str = "gv/packed-controls-signed/v1";
const HASH_DOMAIN: &[u8] = b"gv/packed-controls-hash/v1\0";
const AGG_DOMAIN: &[u8] = b"gv/packed-aggregate-hash/v1\0";
pub mod chunks;
pub const MAX_TICKS: u32 = 5_184_000; // 24 h at 60Hz; actual tick rate is game-defined.
pub const MAX_CHANGES: usize = 1_000_000;
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_AGGREGATE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_AGGREGATE_RECORDS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    InvalidVersion,
    InvalidWidth,
    InvalidRange,
    InvalidChange,
    NonCanonical,
    TooLarge,
    Truncated,
    InvalidSignature,
    WrongPlayer,
    Overflow,
    ChainMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlChange {
    /// Offset from start_tick, strictly increasing and greater than zero.
    pub offset: u32,
    pub state: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedControls {
    pub match_id: MatchId,
    pub player: PlayerId,
    /// Binds this stream to the prior authenticated batch (or match genesis).
    pub previous_batch_hash: Digest,
    pub start_tick: u64,
    pub tick_count: u32,
    /// 1 or 2 bytes. Other control schemes require another canonical codec version.
    pub control_bytes: u8,
    pub initial_state: u16,
    pub changes: Vec<ControlChange>,
}

fn push_varint(mut v: u32, out: &mut Vec<u8>) {
    while v >= 128 {
        out.push(((v as u8) & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn read_varint(b: &[u8], pos: &mut usize) -> Result<u32, CodecError> {
    let begin = *pos;
    let mut value: u64 = 0;
    for i in 0..5 {
        let byte = *b.get(*pos).ok_or(CodecError::Truncated)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            if value > u64::from(u32::MAX) {
                return Err(CodecError::Overflow);
            }
            let mut canonical = Vec::new();
            push_varint(value as u32, &mut canonical);
            if &b[begin..*pos] != canonical.as_slice() {
                return Err(CodecError::NonCanonical);
            }
            return Ok(value as u32);
        }
    }
    Err(CodecError::Overflow)
}

fn read_array<const N: usize>(b: &[u8], pos: &mut usize) -> Result<[u8; N], CodecError> {
    let end = (*pos).checked_add(N).ok_or(CodecError::Overflow)?;
    let src = b.get(*pos..end).ok_or(CodecError::Truncated)?;
    let array: [u8; N] = src.try_into().map_err(|_| CodecError::Truncated)?;
    *pos = end;
    Ok(array)
}

fn read_state(b: &[u8], pos: &mut usize, width: u8) -> Result<u16, CodecError> {
    match width {
        1 => Ok(u16::from(read_array::<1>(b, pos)?[0])),
        2 => Ok(u16::from_le_bytes(read_array::<2>(b, pos)?)),
        _ => Err(CodecError::InvalidWidth),
    }
}

fn write_state(out: &mut Vec<u8>, v: u16, width: u8) {
    if width == 1 {
        out.push(v as u8);
    } else {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

impl PackedControls {
    pub fn validate(&self) -> Result<(), CodecError> {
        if self.tick_count == 0
            || self.tick_count > MAX_TICKS
            || self
                .start_tick
                .checked_add(u64::from(self.tick_count))
                .is_none()
        {
            return Err(CodecError::InvalidRange);
        }
        if self.control_bytes != 1 && self.control_bytes != 2 {
            return Err(CodecError::InvalidWidth);
        }
        if self.control_bytes == 1 && self.initial_state > 255 {
            return Err(CodecError::InvalidRange);
        }
        if self.changes.len() > MAX_CHANGES {
            return Err(CodecError::TooLarge);
        }
        let mut previous_offset = 0;
        let mut previous_state = self.initial_state;
        for change in &self.changes {
            if change.offset <= previous_offset
                || change.offset >= self.tick_count
                || change.state == previous_state
            {
                return Err(CodecError::InvalidChange);
            }
            if self.control_bytes == 1 && change.state > 255 {
                return Err(CodecError::InvalidRange);
            }
            previous_offset = change.offset;
            previous_state = change.state;
        }
        Ok(())
    }

    /// Length-bounded, minimal-ULEB128, little-endian, strictly monotone event stream.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::with_capacity(
            116usize
                .saturating_add(self.changes.len().saturating_mul(7))
                .min(MAX_RECORD_BYTES),
        );
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(self.control_bytes);
        out.extend_from_slice(&self.match_id);
        out.extend_from_slice(&self.player);
        out.extend_from_slice(&self.previous_batch_hash);
        out.extend_from_slice(&self.start_tick.to_le_bytes());
        out.extend_from_slice(&self.tick_count.to_le_bytes());
        write_state(&mut out, self.initial_state, self.control_bytes);
        push_varint(self.changes.len() as u32, &mut out);
        let mut previous_offset = 0u32;
        for change in &self.changes {
            push_varint(change.offset - previous_offset, &mut out);
            write_state(&mut out, change.state, self.control_bytes);
            previous_offset = change.offset;
            if out.len() > MAX_RECORD_BYTES {
                return Err(CodecError::TooLarge);
            }
        }
        Ok(out)
    }

    pub fn decode(b: &[u8]) -> Result<Self, CodecError> {
        if b.len() > MAX_RECORD_BYTES {
            return Err(CodecError::TooLarge);
        }
        let mut pos = 0;
        if read_array::<4>(b, &mut pos)? != *MAGIC {
            return Err(CodecError::InvalidVersion);
        }
        if read_array::<1>(b, &mut pos)?[0] != VERSION {
            return Err(CodecError::InvalidVersion);
        }
        let control_bytes = read_array::<1>(b, &mut pos)?[0];
        if control_bytes != 1 && control_bytes != 2 {
            return Err(CodecError::InvalidWidth);
        }
        let match_id = read_array::<32>(b, &mut pos)?;
        let player = read_array::<32>(b, &mut pos)?;
        let previous_batch_hash = read_array::<32>(b, &mut pos)?;
        let start_tick = u64::from_le_bytes(read_array::<8>(b, &mut pos)?);
        let tick_count = u32::from_le_bytes(read_array::<4>(b, &mut pos)?);
        let initial_state = read_state(b, &mut pos, control_bytes)?;
        let count = read_varint(b, &mut pos)? as usize;
        if count > MAX_CHANGES || count > b.len().saturating_sub(pos) / (1 + control_bytes as usize)
        {
            return Err(CodecError::TooLarge);
        }
        let mut changes = Vec::with_capacity(count);
        let mut offset = 0u32;
        for _ in 0..count {
            let delta = read_varint(b, &mut pos)?;
            offset = offset.checked_add(delta).ok_or(CodecError::Overflow)?;
            changes.push(ControlChange {
                offset,
                state: read_state(b, &mut pos, control_bytes)?,
            });
        }
        if pos != b.len() {
            return Err(CodecError::NonCanonical);
        }
        let record = Self {
            match_id,
            player,
            previous_batch_hash,
            start_tick,
            tick_count,
            control_bytes,
            initial_state,
            changes,
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the button-state bitmask at a relative simulation tick.
    pub fn state_at(&self, offset: u32) -> Result<u16, CodecError> {
        self.validate()?;
        if offset >= self.tick_count {
            return Err(CodecError::InvalidRange);
        }
        let mut state = self.initial_state;
        for change in &self.changes {
            if change.offset > offset {
                break;
            }
            state = change.state;
        }
        Ok(state)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPackedControls {
    pub record: PackedControls,
    pub signature: Signature,
}

impl SignedPackedControls {
    pub fn sign(record: PackedControls, key: &SigningKey) -> Result<Self, CodecError> {
        if record.player != key.id() {
            return Err(CodecError::WrongPlayer);
        }
        let encoded = record.encode()?;
        let signature = key.sign(SIGN_LABEL, &encoded);
        Ok(Self { record, signature })
    }
    pub fn verify(&self) -> Result<(), CodecError> {
        let bytes = self.record.encode()?;
        gv_sig::verify(&self.record.player, SIGN_LABEL, &bytes, &self.signature).map_err(
            |e| match e {
                gv_sig::SigError::UnknownSigner => CodecError::WrongPlayer,
                _ => CodecError::InvalidSignature,
            },
        )
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
        let record = PackedControls::decode(record_bytes)?;
        let signature =
            Signature::from_slice(signature_bytes).map_err(|_| CodecError::InvalidSignature)?;
        let signed = Self { record, signature };
        signed.verify()?;
        Ok(signed)
    }
    /// Hash includes the authenticated player's signature. Use in Merkle logs and prev_batch_hash.
    pub fn digest(&self) -> Result<Digest, CodecError> {
        let mut h = Sha256::new();
        h.update(HASH_DOMAIN);
        h.update(self.encode()?);
        Ok(h.finalize().into())
    }
}

/// Canonically ordered signed player batches, optionally spanning multiple matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aggregate {
    pub records: Vec<SignedPackedControls>,
}

impl Aggregate {
    pub fn validate(&self) -> Result<(), CodecError> {
        if self.records.is_empty() || self.records.len() > MAX_AGGREGATE_RECORDS {
            return Err(CodecError::InvalidRange);
        }
        let mut previous: Option<&SignedPackedControls> = None;
        for record in &self.records {
            record.verify()?;
            if let Some(prior) = previous {
                let a = (
                    &prior.record.match_id,
                    &prior.record.player,
                    prior.record.start_tick,
                );
                let b = (
                    &record.record.match_id,
                    &record.record.player,
                    record.record.start_tick,
                );
                if a >= b {
                    return Err(CodecError::NonCanonical);
                }
                if prior.record.match_id == record.record.match_id
                    && prior.record.player == record.record.player
                {
                    let expected_tick = prior
                        .record
                        .start_tick
                        .checked_add(u64::from(prior.record.tick_count))
                        .ok_or(CodecError::Overflow)?;
                    if record.record.start_tick != expected_tick
                        || record.record.previous_batch_hash != prior.digest()?
                    {
                        return Err(CodecError::ChainMismatch);
                    }
                }
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
            let end = pos.checked_add(len).ok_or(CodecError::Overflow)?;
            let data = b.get(pos..end).ok_or(CodecError::Truncated)?;
            records.push(SignedPackedControls::decode(data)?);
            pos = end;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (PackedControls, SigningKey) {
        let key = SigningKey::from_seed([7; 32]);
        (
            PackedControls {
                match_id: [1; 32],
                player: key.id(),
                previous_batch_hash: [2; 32],
                start_tick: 500,
                tick_count: 180,
                control_bytes: 1,
                initial_state: 1,
                changes: vec![ControlChange {
                    offset: 179,
                    state: 0,
                }],
            },
            key,
        )
    }

    #[test]
    fn compact_hold_and_tamper_rejection() {
        let (record, key) = fixture();
        let signed = SignedPackedControls::sign(record.clone(), &key).unwrap();
        let bytes = signed.encode().unwrap();
        assert_eq!(
            bytes.len(),
            4 + 1 + 1 + 32 + 32 + 32 + 8 + 4 + 1 + 1 + 2 + 1 + SIG_LEN
        );
        assert_eq!(SignedPackedControls::decode(&bytes).unwrap(), signed);
        // The digest commits to the signature (ML-DSA signing is hedged, so it differs per signing).
        let other = SignedPackedControls::sign(record.clone(), &key).unwrap();
        assert_ne!(signed.digest().unwrap(), other.digest().unwrap());
        assert_eq!(record.state_at(178).unwrap(), 1);
        assert_eq!(record.state_at(179).unwrap(), 0);
        let mut altered = bytes;
        altered[110] ^= 1;
        assert!(SignedPackedControls::decode(&altered).is_err());
    }

    #[test]
    fn single_record_aggregate_layout() {
        let (record, key) = fixture();
        let signed = SignedPackedControls::sign(record, &key).unwrap();
        let agg = Aggregate {
            records: vec![signed],
        };
        assert_eq!(agg.encode().unwrap().len(), 191 - 64 + SIG_LEN);
        assert_eq!(agg.digest().unwrap(), agg.digest().unwrap());
    }

    #[test]
    fn reject_duplicate_events_bad_width_nonminimal_and_trailing() {
        let (mut record, key) = fixture();
        record.changes.push(ControlChange {
            offset: 179,
            state: 1,
        });
        assert_eq!(record.encode(), Err(CodecError::InvalidChange));
        record.changes.pop();
        record.control_bytes = 3;
        assert_eq!(record.encode(), Err(CodecError::InvalidWidth));
        record.control_bytes = 1;
        let mut encoded = record.encode().unwrap();
        encoded.push(0);
        assert_eq!(
            PackedControls::decode(&encoded),
            Err(CodecError::NonCanonical)
        );
        let mut raw = record.encode().unwrap();
        // 179 encodes minimally as b3 01. b3 81 00 is a forbidden longer form.
        raw.splice(116..118, [0xb3, 0x81, 0x00]);
        assert_eq!(PackedControls::decode(&raw), Err(CodecError::NonCanonical));
        let signed = SignedPackedControls::sign(record, &key).unwrap();
        let mut b = signed.encode().unwrap();
        b[0] ^= 1;
        assert!(SignedPackedControls::decode(&b).is_err());
    }

    #[test]
    fn aggregates_require_order_chain_and_signatures() {
        let (record, key) = fixture();
        let first = SignedPackedControls::sign(record.clone(), &key).unwrap();
        let second = SignedPackedControls::sign(
            PackedControls {
                start_tick: 680,
                previous_batch_hash: first.digest().unwrap(),
                initial_state: 0,
                changes: vec![],
                ..record
            },
            &key,
        )
        .unwrap();
        let agg = Aggregate {
            records: vec![first.clone(), second.clone()],
        };
        let encoded = agg.encode().unwrap();
        assert_eq!(Aggregate::decode(&encoded).unwrap(), agg);
        // Different aggregate fixture from the single-record Node golden vector.
        assert_eq!(
            Aggregate {
                records: vec![second, first]
            }
            .validate(),
            Err(CodecError::NonCanonical)
        );
    }

    /// One scenario: `players` each emit `events_per_second` control changes for `seconds`
    /// (alternating 1/0 so every change is a real change). `batch_ticks == 0` is one record per
    /// player for the whole span (archive form); otherwise a signed record per `batch_ticks`
    /// ticks, as the live game signs one per epoch. Records are real encodings carrying a
    /// zero-filled signature of the real ML-DSA-65 length (sizes do not depend on its value).
    struct Sizing {
        name: &'static str,
        players: usize,
        seconds: u32,
        events_per_second: u32,
        batch_ticks: u32,
    }
    fn sizing(sc: &Sizing) -> (usize, usize, usize) {
        let ticks = sc.seconds * 60;
        let gap = 60 / sc.events_per_second;
        let span = if sc.batch_ticks == 0 {
            ticks
        } else {
            sc.batch_ticks
        };
        let mut records_total = 0usize;
        let mut bytes_total = 0usize;
        let mut aggregates = 0usize;
        for player in 0..sc.players {
            let id = [player as u8 + 1; 32];
            let mut records = Vec::new();
            let mut state = 0u16;
            let mut start = 0u32;
            let mut next_event = gap; // absolute tick of the next change
            while start < ticks {
                let count = span.min(ticks - start);
                if next_event == start {
                    // a change on the batch boundary is the batch's initial state
                    state = 1 - state;
                    next_event += gap;
                }
                let initial = state;
                let mut changes = Vec::new();
                while next_event < start + count {
                    state = 1 - state;
                    changes.push(ControlChange {
                        offset: next_event - start,
                        state,
                    });
                    next_event += gap;
                }
                // A change exactly at offset 0 is the initial state; the first change is at
                // `gap` > 0 only when the batch does not start on an event boundary.
                records.push(PackedControls {
                    match_id: [9; 32],
                    player: id,
                    previous_batch_hash: [0; 32],
                    start_tick: u64::from(start),
                    tick_count: count,
                    control_bytes: 1,
                    initial_state: initial,
                    changes,
                });
                start += count;
            }
            records_total += records.len();
            for chunk in records.chunks(MAX_AGGREGATE_RECORDS) {
                let mut out = Vec::new();
                out.extend_from_slice(AGG_MAGIC);
                out.push(VERSION);
                push_varint(chunk.len() as u32, &mut out);
                for r in chunk {
                    let len = r.encode().unwrap().len() + SIG_LEN;
                    push_varint(len as u32, &mut out);
                    out.resize(out.len() + len, 0);
                }
                bytes_total += out.len();
                aggregates += 1;
            }
        }
        (records_total, aggregates, bytes_total)
    }

    /// The committed size vectors that `scripts/bench-packing.mjs` re-derives independently.
    /// Regenerate with `GV_REGEN_VECTORS=1 cargo test -p gv-codec packing_size_vectors`.
    #[test]
    fn packing_size_vectors() {
        let scenarios = [
            Sizing {
                name: "1v1, 10 min, 2 changes/s, one record per player",
                players: 2,
                seconds: 600,
                events_per_second: 2,
                batch_ticks: 0,
            },
            Sizing {
                name: "1v1, 1 h, 2 changes/s, one record per player",
                players: 2,
                seconds: 3600,
                events_per_second: 2,
                batch_ticks: 0,
            },
            Sizing {
                name: "16 players, 10 min, 2 changes/s, one record per player",
                players: 16,
                seconds: 600,
                events_per_second: 2,
                batch_ticks: 0,
            },
            Sizing {
                name: "1v1, 1 h, 60 Hz digital updates, one record per player",
                players: 2,
                seconds: 3600,
                events_per_second: 60,
                batch_ticks: 0,
            },
            Sizing {
                name: "1v1, 10 min, 2 changes/s, live epochs of 20 ticks",
                players: 2,
                seconds: 600,
                events_per_second: 2,
                batch_ticks: 20,
            },
            Sizing {
                name: "1v1, 1 h, 2 changes/s, live epochs of 20 ticks",
                players: 2,
                seconds: 3600,
                events_per_second: 2,
                batch_ticks: 20,
            },
        ];
        let mut json =
            String::from("{\n  \"format\": \"GV-PACKING-SIZES-V1\",\n  \"signature_bytes\": ");
        json.push_str(&format!(
            "{},\n  \"max_aggregate_records\": {},\n  \"scenarios\": [\n",
            SIG_LEN, MAX_AGGREGATE_RECORDS
        ));
        for (i, sc) in scenarios.iter().enumerate() {
            let (records, aggregates, bytes) = sizing(sc);
            json.push_str(&format!(
                "    {{\"name\": \"{}\", \"players\": {}, \"seconds\": {}, \"events_per_second\": {}, \"width\": 1, \"batch_ticks\": {}, \"records\": {}, \"aggregates\": {}, \"bytes\": {}}}{}\n",
                sc.name, sc.players, sc.seconds, sc.events_per_second, sc.batch_ticks, records, aggregates, bytes,
                if i + 1 < scenarios.len() { "," } else { "" }
            ));
        }
        json.push_str("  ]\n}\n");
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/interoperability/packing_sizes_v1.json"
        );
        if std::env::var("GV_REGEN_VECTORS").is_ok() {
            std::fs::write(path, &json).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            json,
            "size vectors are stale"
        );
        // One really signed record has exactly the size the zero-signature model assumes.
        let (record, key) = fixture();
        let real = SignedPackedControls::sign(record.clone(), &key)
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(real.len(), record.encode().unwrap().len() + SIG_LEN);
    }
}
