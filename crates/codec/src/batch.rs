//! One participant's authenticated event stream for a tick range. Application-defined payload
//! bytes in one of two canonical shapes; the codec never interprets a payload.
use crate::wire::{push_varint, read_array, read_slice, read_varint, CodecError};
use gv_core::{Digest, MatchId, ParticipantId, MAX_EVENT_PAYLOAD};

pub(crate) const MAGIC: &[u8; 4] = b"GVEC";
pub(crate) const VERSION: u8 = 2;
/// Longest tick range one batch may cover. Tick duration is the application's choice.
pub const MAX_TICKS: u32 = 5_184_000;
pub const MAX_CHANGES: usize = 1_000_000;
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
/// Widest held payload (a control state such as a button mask or axis block).
pub const MAX_HELD_WIDTH: usize = 32;
const KIND_HELD: u8 = 0;
const KIND_DISCRETE: u8 = 1;

/// A change of the held payload at `offset` ticks after `start_tick`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldChange {
    /// Strictly increasing and greater than zero.
    pub offset: u32,
    pub payload: Vec<u8>,
}

/// One discrete event at `offset` ticks after `start_tick`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickEvent {
    /// Non-decreasing; events at the same offset apply in the order listed.
    pub offset: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventBody {
    /// The payload holds until the next change, so every tick has exactly one event
    /// (digital controls).
    Held {
        initial: Vec<u8>,
        changes: Vec<HeldChange>,
    },
    /// Only the listed events exist (actions, commands, messages).
    Discrete { events: Vec<TickEvent> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventBatch {
    pub match_id: MatchId,
    pub participant: ParticipantId,
    /// Binds this stream to the prior authenticated batch (or session genesis).
    pub previous_batch_hash: Digest,
    pub start_tick: u64,
    pub tick_count: u32,
    pub body: EventBody,
}

impl EventBatch {
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
        match &self.body {
            EventBody::Held { initial, changes } => self.validate_held(initial, changes),
            EventBody::Discrete { events } => self.validate_discrete(events),
        }
    }

    fn validate_held(&self, initial: &[u8], changes: &[HeldChange]) -> Result<(), CodecError> {
        let width = initial.len();
        if width == 0 || width > MAX_HELD_WIDTH {
            return Err(CodecError::InvalidWidth);
        }
        if changes.len() > MAX_CHANGES {
            return Err(CodecError::TooLarge);
        }
        let mut offset = 0;
        let mut held = initial;
        for change in changes {
            if change.payload.len() != width {
                return Err(CodecError::InvalidWidth);
            }
            if change.offset <= offset || change.offset >= self.tick_count || change.payload == held
            {
                return Err(CodecError::InvalidChange);
            }
            offset = change.offset;
            held = &change.payload;
        }
        Ok(())
    }

    fn validate_discrete(&self, events: &[TickEvent]) -> Result<(), CodecError> {
        if events.len() > MAX_CHANGES {
            return Err(CodecError::TooLarge);
        }
        let mut offset = 0;
        for event in events {
            if event.payload.len() > MAX_EVENT_PAYLOAD {
                return Err(CodecError::TooLarge);
            }
            if event.offset < offset || event.offset >= self.tick_count {
                return Err(CodecError::InvalidChange);
            }
            offset = event.offset;
        }
        Ok(())
    }

    /// Length-bounded, minimal-ULEB128, little-endian, canonical event stream.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.match_id);
        out.extend_from_slice(&self.participant);
        out.extend_from_slice(&self.previous_batch_hash);
        out.extend_from_slice(&self.start_tick.to_le_bytes());
        out.extend_from_slice(&self.tick_count.to_le_bytes());
        match &self.body {
            EventBody::Held { initial, changes } => encode_held(&mut out, initial, changes)?,
            EventBody::Discrete { events } => encode_discrete(&mut out, events)?,
        }
        if out.len() > MAX_RECORD_BYTES {
            return Err(CodecError::TooLarge);
        }
        Ok(out)
    }

    pub fn decode(b: &[u8]) -> Result<Self, CodecError> {
        if b.len() > MAX_RECORD_BYTES {
            return Err(CodecError::TooLarge);
        }
        let mut pos = 0;
        if read_array::<4>(b, &mut pos)? != *MAGIC || read_array::<1>(b, &mut pos)?[0] != VERSION {
            return Err(CodecError::InvalidVersion);
        }
        let match_id = read_array::<32>(b, &mut pos)?;
        let participant = read_array::<32>(b, &mut pos)?;
        let previous_batch_hash = read_array::<32>(b, &mut pos)?;
        let start_tick = u64::from_le_bytes(read_array::<8>(b, &mut pos)?);
        let tick_count = u32::from_le_bytes(read_array::<4>(b, &mut pos)?);
        let body = match read_array::<1>(b, &mut pos)?[0] {
            KIND_HELD => decode_held(b, &mut pos)?,
            KIND_DISCRETE => decode_discrete(b, &mut pos)?,
            _ => return Err(CodecError::InvalidVersion),
        };
        if pos != b.len() {
            return Err(CodecError::NonCanonical);
        }
        let record = Self {
            match_id,
            participant,
            previous_batch_hash,
            start_tick,
            tick_count,
            body,
        };
        record.validate()?;
        Ok(record)
    }

    /// Payloads that apply at `offset` ticks after `start_tick`, in application order.
    pub fn events_at(&self, offset: u32) -> Result<Vec<&[u8]>, CodecError> {
        if offset >= self.tick_count {
            return Err(CodecError::InvalidRange);
        }
        Ok(match &self.body {
            EventBody::Held { initial, changes } => {
                let at = changes.partition_point(|c| c.offset <= offset);
                vec![at
                    .checked_sub(1)
                    .map_or(initial.as_slice(), |i| changes[i].payload.as_slice())]
            }
            EventBody::Discrete { events } => {
                let from = events.partition_point(|e| e.offset < offset);
                let to = events.partition_point(|e| e.offset <= offset);
                events[from..to]
                    .iter()
                    .map(|e| e.payload.as_slice())
                    .collect()
            }
        })
    }

    /// The held payload at a relative tick; `None` for discrete streams.
    pub fn held_at(&self, offset: u32) -> Result<Option<&[u8]>, CodecError> {
        match self.body {
            EventBody::Held { .. } => Ok(self.events_at(offset)?.into_iter().next()),
            EventBody::Discrete { .. } => Ok(None),
        }
    }
}

fn encode_held(
    out: &mut Vec<u8>,
    initial: &[u8],
    changes: &[HeldChange],
) -> Result<(), CodecError> {
    out.push(KIND_HELD);
    out.push(initial.len() as u8);
    out.extend_from_slice(initial);
    push_varint(changes.len() as u32, out);
    let mut previous = 0u32;
    for change in changes {
        push_varint(change.offset - previous, out);
        out.extend_from_slice(&change.payload);
        previous = change.offset;
        if out.len() > MAX_RECORD_BYTES {
            return Err(CodecError::TooLarge);
        }
    }
    Ok(())
}

fn encode_discrete(out: &mut Vec<u8>, events: &[TickEvent]) -> Result<(), CodecError> {
    out.push(KIND_DISCRETE);
    push_varint(events.len() as u32, out);
    let mut previous = 0u32;
    for event in events {
        push_varint(event.offset - previous, out);
        push_varint(event.payload.len() as u32, out);
        out.extend_from_slice(&event.payload);
        previous = event.offset;
        if out.len() > MAX_RECORD_BYTES {
            return Err(CodecError::TooLarge);
        }
    }
    Ok(())
}

fn decode_held(b: &[u8], pos: &mut usize) -> Result<EventBody, CodecError> {
    let width = usize::from(read_array::<1>(b, pos)?[0]);
    if width == 0 || width > MAX_HELD_WIDTH {
        return Err(CodecError::InvalidWidth);
    }
    let initial = read_slice(b, pos, width)?.to_vec();
    let count = read_varint(b, pos)? as usize;
    if count > MAX_CHANGES || count > b.len().saturating_sub(*pos) / (1 + width) {
        return Err(CodecError::TooLarge);
    }
    let mut changes = Vec::with_capacity(count);
    let mut offset = 0u32;
    for _ in 0..count {
        offset = offset
            .checked_add(read_varint(b, pos)?)
            .ok_or(CodecError::Overflow)?;
        changes.push(HeldChange {
            offset,
            payload: read_slice(b, pos, width)?.to_vec(),
        });
    }
    Ok(EventBody::Held { initial, changes })
}

fn decode_discrete(b: &[u8], pos: &mut usize) -> Result<EventBody, CodecError> {
    let count = read_varint(b, pos)? as usize;
    if count > MAX_CHANGES || count > b.len().saturating_sub(*pos) / 2 {
        return Err(CodecError::TooLarge);
    }
    let mut events = Vec::with_capacity(count);
    let mut offset = 0u32;
    for _ in 0..count {
        offset = offset
            .checked_add(read_varint(b, pos)?)
            .ok_or(CodecError::Overflow)?;
        let len = read_varint(b, pos)? as usize;
        if len > MAX_EVENT_PAYLOAD {
            return Err(CodecError::TooLarge);
        }
        events.push(TickEvent {
            offset,
            payload: read_slice(b, pos, len)?.to_vec(),
        });
    }
    Ok(EventBody::Discrete { events })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held() -> EventBatch {
        EventBatch {
            match_id: [1; 32],
            participant: [7; 32],
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
        }
    }

    fn discrete() -> EventBatch {
        EventBatch {
            body: EventBody::Discrete {
                events: vec![
                    TickEvent {
                        offset: 3,
                        payload: b"fire".to_vec(),
                    },
                    TickEvent {
                        offset: 3,
                        payload: b"reload".to_vec(),
                    },
                    TickEvent {
                        offset: 90,
                        payload: vec![],
                    },
                ],
            },
            ..held()
        }
    }

    #[test]
    fn both_shapes_round_trip() {
        for batch in [held(), discrete()] {
            assert_eq!(EventBatch::decode(&batch.encode().unwrap()).unwrap(), batch);
        }
    }

    #[test]
    fn held_state_persists_until_changed() {
        let batch = held();
        assert_eq!(batch.held_at(0).unwrap(), Some(&[1u8][..]));
        assert_eq!(batch.held_at(178).unwrap(), Some(&[1u8][..]));
        assert_eq!(batch.held_at(179).unwrap(), Some(&[0u8][..]));
        assert_eq!(batch.events_at(180), Err(CodecError::InvalidRange));
    }

    #[test]
    fn discrete_events_keep_their_order_within_a_tick() {
        let batch = discrete();
        assert_eq!(
            batch.events_at(3).unwrap(),
            vec![b"fire".as_slice(), b"reload".as_slice()]
        );
        assert!(batch.events_at(4).unwrap().is_empty());
        assert_eq!(batch.events_at(90).unwrap(), vec![&[][..]]);
        assert_eq!(batch.held_at(3).unwrap(), None);
    }

    #[test]
    fn wide_held_payloads_are_supported() {
        let mut batch = held();
        batch.body = EventBody::Held {
            initial: vec![9; MAX_HELD_WIDTH],
            changes: vec![HeldChange {
                offset: 5,
                payload: vec![8; MAX_HELD_WIDTH],
            }],
        };
        assert_eq!(EventBatch::decode(&batch.encode().unwrap()).unwrap(), batch);
        batch.body = EventBody::Held {
            initial: vec![0; MAX_HELD_WIDTH + 1],
            changes: vec![],
        };
        assert_eq!(batch.encode(), Err(CodecError::InvalidWidth));
    }

    #[test]
    fn invalid_streams_are_rejected() {
        let mut batch = held();
        // A change to the value already held is not a change.
        batch.body = EventBody::Held {
            initial: vec![1],
            changes: vec![HeldChange {
                offset: 4,
                payload: vec![1],
            }],
        };
        assert_eq!(batch.encode(), Err(CodecError::InvalidChange));
        // Mixed widths, out-of-range and non-monotone offsets.
        batch.body = EventBody::Held {
            initial: vec![1],
            changes: vec![HeldChange {
                offset: 4,
                payload: vec![0, 0],
            }],
        };
        assert_eq!(batch.encode(), Err(CodecError::InvalidWidth));
        let mut late = discrete();
        late.body = EventBody::Discrete {
            events: vec![TickEvent {
                offset: 180,
                payload: vec![1],
            }],
        };
        assert_eq!(late.encode(), Err(CodecError::InvalidChange));
        let mut backwards = discrete();
        backwards.body = EventBody::Discrete {
            events: vec![
                TickEvent {
                    offset: 9,
                    payload: vec![1],
                },
                TickEvent {
                    offset: 8,
                    payload: vec![1],
                },
            ],
        };
        assert_eq!(backwards.encode(), Err(CodecError::InvalidChange));
        let mut zero = held();
        zero.tick_count = 0;
        assert_eq!(zero.encode(), Err(CodecError::InvalidRange));
    }

    #[test]
    fn decoder_rejects_trailing_bytes_nonminimal_varints_and_oversize_counts() {
        let mut bytes = held().encode().unwrap();
        bytes.push(0);
        assert_eq!(EventBatch::decode(&bytes), Err(CodecError::NonCanonical));
        let mut raw = held().encode().unwrap();
        // The change count and the 179 delta follow the header: replace the delta's minimal
        // b3 01 with the forbidden three-byte form.
        let at = raw.len() - 3;
        raw.splice(at..at + 2, [0xb3, 0x81, 0x00]);
        assert_eq!(EventBatch::decode(&raw), Err(CodecError::NonCanonical));
        let mut bad_magic = held().encode().unwrap();
        bad_magic[0] ^= 1;
        assert_eq!(
            EventBatch::decode(&bad_magic),
            Err(CodecError::InvalidVersion)
        );
        // A count that cannot fit in the remaining bytes is refused before allocating.
        let mut huge = discrete().encode().unwrap();
        let count_at = 4 + 1 + 32 * 3 + 8 + 4 + 1;
        huge.splice(count_at..count_at + 1, [0xff, 0xff, 0xff, 0x7f]);
        assert!(EventBatch::decode(&huge).is_err());
        assert!(EventBatch::decode(&[]).is_err());
    }
}
