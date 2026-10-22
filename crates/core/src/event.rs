//! The canonical authenticated event the rules see. The envelope is generic: the payload is
//! application-defined bytes, never an interpreted control word.
use crate::ParticipantId;

/// Upper bound for one event payload, shared by every codec and verifier.
pub const MAX_EVENT_PAYLOAD: usize = 1024;
const HEADER: usize = 32 + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventError {
    Truncated,
    PayloadTooLarge,
}

/// One authenticated event: who, at which tick, with what application payload.
/// Wire form handed to `StateMachine::apply`: `participant (32) || tick (u64 LE) || payload`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event<'a> {
    pub participant: ParticipantId,
    pub tick: u64,
    pub payload: &'a [u8],
}

impl<'a> Event<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + self.payload.len());
        out.extend_from_slice(&self.participant);
        out.extend_from_slice(&self.tick.to_le_bytes());
        out.extend_from_slice(self.payload);
        out
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, EventError> {
        if bytes.len() < HEADER {
            return Err(EventError::Truncated);
        }
        let (header, payload) = bytes.split_at(HEADER);
        if payload.len() > MAX_EVENT_PAYLOAD {
            return Err(EventError::PayloadTooLarge);
        }
        let mut participant = [0u8; 32];
        participant.copy_from_slice(&header[..32]);
        let mut tick = [0u8; 8];
        tick.copy_from_slice(&header[32..]);
        Ok(Self {
            participant,
            tick: u64::from_le_bytes(tick),
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_bounds() {
        let event = Event {
            participant: [3; 32],
            tick: 99,
            payload: &[1, 2, 3],
        };
        assert_eq!(Event::decode(&event.encode()).unwrap(), event);
        assert_eq!(Event::decode(&[0; 39]), Err(EventError::Truncated));
        let big = vec![0u8; HEADER + MAX_EVENT_PAYLOAD + 1];
        assert_eq!(Event::decode(&big), Err(EventError::PayloadTooLarge));
    }
}
