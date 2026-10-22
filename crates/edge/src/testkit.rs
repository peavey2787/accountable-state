//! A minimal deterministic grid state machine for any number of participants, used by protocol
//! tests and fuzzing. It has the properties the protocol depends on (canonical state, typed
//! illegal actions) and nothing else; it is not an application.
use gv_core::{Digest, ParticipantId, Session};
use gv_replay::{RuleError, StateMachine, ViolationCode};
use sha2::{Digest as _, Sha256};

pub const LEFT: u16 = 1;
pub const RIGHT: u16 = 2;
pub const UP: u16 = 4;
pub const DOWN: u16 = 8;
/// Counted, no other effect.
pub const ACT: u16 = 16;
/// Latched while held.
pub const HOLD: u16 = 32;
const ALLOWED: u16 = LEFT | RIGHT | UP | DOWN | ACT | HOLD;
/// Positions are clamped to `-BOUND..=BOUND`.
pub const BOUND: i32 = 1000;
/// Input length: participant (32) + tick (8) + controls (2).
const INPUT_LEN: usize = 42;
const WALKER_LEN: usize = 32 + 13;

pub const INVALID_INPUT: ViolationCode = ViolationCode(1);
pub const NOT_IN_ROSTER: ViolationCode = ViolationCode(2);
pub const UNSUPPORTED_CONTROL: ViolationCode = ViolationCode(3);
pub const CONTRADICTORY_MOVEMENT: ViolationCode = ViolationCode(4);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Walker {
    pub x: i32,
    pub y: i32,
    pub acts: u32,
    pub holding: bool,
}

/// One walker per submitting participant, in roster order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GridState {
    pub walkers: Vec<(ParticipantId, Walker)>,
}

fn bad() -> RuleError {
    RuleError::ExecutionFailure("noncanonical grid state".into())
}

fn word(b: &[u8], at: usize) -> [u8; 4] {
    [b[at], b[at + 1], b[at + 2], b[at + 3]]
}

fn decode_walker(b: &[u8]) -> Result<(ParticipantId, Walker), RuleError> {
    let mut id = [0u8; 32];
    id.copy_from_slice(&b[..32]);
    let holding = match b[32 + 12] {
        0 => false,
        1 => true,
        _ => return Err(bad()),
    };
    let w = Walker {
        x: i32::from_le_bytes(word(b, 32)),
        y: i32::from_le_bytes(word(b, 36)),
        acts: u32::from_le_bytes(word(b, 40)),
        holding,
    };
    let inside = |v: i32| (-BOUND..=BOUND).contains(&v);
    if inside(w.x) && inside(w.y) {
        Ok((id, w))
    } else {
        Err(bad())
    }
}

impl GridState {
    pub fn encode(&self) -> Vec<u8> {
        let n = u16::try_from(self.walkers.len()).unwrap_or(u16::MAX);
        let mut b = Vec::with_capacity(2 + self.walkers.len() * WALKER_LEN);
        b.extend_from_slice(&n.to_le_bytes());
        for (id, w) in &self.walkers {
            b.extend_from_slice(id);
            b.extend_from_slice(&w.x.to_le_bytes());
            b.extend_from_slice(&w.y.to_le_bytes());
            b.extend_from_slice(&w.acts.to_le_bytes());
            b.push(u8::from(w.holding));
        }
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, RuleError> {
        if b.len() < 2 {
            return Err(bad());
        }
        let n = usize::from(u16::from_le_bytes([b[0], b[1]]));
        if b.len() != 2 + n * WALKER_LEN {
            return Err(bad());
        }
        let walkers = b[2..]
            .chunks_exact(WALKER_LEN)
            .map(decode_walker)
            .collect::<Result<_, _>>()?;
        Ok(Self { walkers })
    }
    pub fn walker(&self, id: &ParticipantId) -> Option<&Walker> {
        self.walkers.iter().find(|(p, _)| p == id).map(|(_, w)| w)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GridRules;

impl StateMachine for GridRules {
    fn ruleset_hash(&self) -> Digest {
        Sha256::digest(b"accountable-state/testkit/grid/v2").into()
    }
    fn genesis(&self, session: &Session) -> Vec<u8> {
        let walkers = session
            .roster
            .submitters()
            .into_iter()
            .filter_map(|slot| session.roster.get(slot))
            .enumerate()
            .map(|(i, p)| {
                let x = i32::try_from(i).unwrap_or(0) * 8 - 4;
                let w = Walker {
                    x,
                    ..Walker::default()
                };
                (p.id, w)
            })
            .collect();
        GridState { walkers }.encode()
    }
    fn apply(&self, state: &[u8], input: &[u8]) -> Result<Vec<u8>, RuleError> {
        if input.len() != INPUT_LEN {
            return Err(RuleError::InvalidAction(INVALID_INPUT));
        }
        let controls = u16::from_le_bytes([input[40], input[41]]);
        if controls & !ALLOWED != 0 {
            return Err(RuleError::InvalidAction(UNSUPPORTED_CONTROL));
        }
        let movement = controls & (LEFT | RIGHT | UP | DOWN);
        if movement.count_ones() > 1 {
            return Err(RuleError::InvalidAction(CONTRADICTORY_MOVEMENT));
        }
        let mut s = GridState::decode(state)?;
        let w = s
            .walkers
            .iter_mut()
            .find(|(p, _)| p[..] == input[..32])
            .map(|(_, w)| w)
            .ok_or(RuleError::InvalidAction(NOT_IN_ROSTER))?;
        let (dx, dy) = match movement {
            LEFT => (-1, 0),
            RIGHT => (1, 0),
            UP => (0, -1),
            DOWN => (0, 1),
            _ => (0, 0),
        };
        w.x = (w.x + dx).clamp(-BOUND, BOUND);
        w.y = (w.y + dy).clamp(-BOUND, BOUND);
        w.holding = controls & HOLD != 0;
        if controls & ACT != 0 {
            w.acts = w.acts.saturating_add(1);
        }
        Ok(s.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(player: &ParticipantId, control: u16) -> Vec<u8> {
        let mut b = player.to_vec();
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&control.to_le_bytes());
        b
    }

    #[test]
    fn illegal_inputs_are_typed_and_execution_failures_are_not_violations() {
        let rules = GridRules;
        let ids = [[1; 32], [2; 32], [3; 32]];
        let session = Session::unanimous([7; 32], &ids).unwrap();
        let g = rules.genesis(&session);
        let p = ids[0];
        assert_eq!(
            rules.apply(&g, &input(&p, LEFT | RIGHT)),
            Err(RuleError::InvalidAction(CONTRADICTORY_MOVEMENT))
        );
        assert_eq!(
            rules.apply(&g, &input(&p, 128)),
            Err(RuleError::InvalidAction(UNSUPPORTED_CONTROL))
        );
        assert_eq!(
            rules.apply(&g, &input(&[9; 32], 0)),
            Err(RuleError::InvalidAction(NOT_IN_ROSTER))
        );
        assert!(matches!(
            rules.apply(&[0; 3], &input(&p, 0)),
            Err(RuleError::ExecutionFailure(_))
        ));
        let next =
            GridState::decode(&rules.apply(&g, &input(&p, UP | ACT | HOLD)).unwrap()).unwrap();
        assert_eq!(next.walkers.len(), 3);
        assert_eq!(
            next.walker(&p),
            Some(&Walker {
                x: -4,
                y: -1,
                acts: 1,
                holding: true
            })
        );
        assert_eq!(next.walker(&ids[2]).map(|w| w.x), Some(12));
    }
}
