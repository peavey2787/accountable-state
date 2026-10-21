//! A minimal deterministic two-player state machine for protocol tests and fuzzing. It has the
//! properties the protocol depends on (canonical state, typed illegal actions, neutral no-op
//! input) and nothing else; it is not an application.
use gv_core::{Digest, PlayerId};
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GridState {
    pub walkers: [Walker; 2],
}

impl GridState {
    pub const SIZE: usize = 26;
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::SIZE);
        for w in &self.walkers {
            b.extend_from_slice(&w.x.to_le_bytes());
            b.extend_from_slice(&w.y.to_le_bytes());
            b.extend_from_slice(&w.acts.to_le_bytes());
            b.push(u8::from(w.holding));
        }
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, RuleError> {
        let bad = || RuleError::ExecutionFailure("noncanonical grid state".into());
        if b.len() != Self::SIZE {
            return Err(bad());
        }
        let word = |at: usize| -> [u8; 4] { [b[at], b[at + 1], b[at + 2], b[at + 3]] };
        let walker = |at: usize| -> Result<Walker, RuleError> {
            let w = Walker {
                x: i32::from_le_bytes(word(at)),
                y: i32::from_le_bytes(word(at + 4)),
                acts: u32::from_le_bytes(word(at + 8)),
                holding: match b[at + 12] {
                    0 => false,
                    1 => true,
                    _ => return Err(bad()),
                },
            };
            let inside = |v: i32| (-BOUND..=BOUND).contains(&v);
            if inside(w.x) && inside(w.y) {
                Ok(w)
            } else {
                Err(bad())
            }
        };
        Ok(Self {
            walkers: [walker(0)?, walker(13)?],
        })
    }
}

#[derive(Clone, Debug)]
pub struct GridRules {
    pub roster: [PlayerId; 2],
}

impl GridRules {
    pub fn new(mut roster: [PlayerId; 2]) -> Self {
        roster.sort();
        Self { roster }
    }
}

impl StateMachine for GridRules {
    fn ruleset_hash(&self) -> Digest {
        Sha256::digest(b"accountable-state/testkit/grid/v1").into()
    }
    fn genesis(&self, _: &[PlayerId; 2]) -> Vec<u8> {
        let at = |x| Walker {
            x,
            ..Walker::default()
        };
        GridState {
            walkers: [at(-4), at(4)],
        }
        .encode()
    }
    fn apply(&self, state: &[u8], input: &[u8]) -> Result<Vec<u8>, RuleError> {
        if input.len() != 42 {
            return Err(RuleError::InvalidAction(INVALID_INPUT));
        }
        let i = self
            .roster
            .iter()
            .position(|p| p[..] == input[..32])
            .ok_or(RuleError::InvalidAction(NOT_IN_ROSTER))?;
        let controls = u16::from_le_bytes([input[40], input[41]]);
        if controls & !ALLOWED != 0 {
            return Err(RuleError::InvalidAction(UNSUPPORTED_CONTROL));
        }
        let movement = controls & (LEFT | RIGHT | UP | DOWN);
        if movement.count_ones() > 1 {
            return Err(RuleError::InvalidAction(CONTRADICTORY_MOVEMENT));
        }
        let mut s = GridState::decode(state)?;
        let (dx, dy) = match movement {
            LEFT => (-1, 0),
            RIGHT => (1, 0),
            UP => (0, -1),
            DOWN => (0, 1),
            _ => (0, 0),
        };
        let w = &mut s.walkers[i];
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

    fn input(player: &PlayerId, control: u16) -> Vec<u8> {
        let mut b = player.to_vec();
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&control.to_le_bytes());
        b
    }

    #[test]
    fn illegal_inputs_are_typed_and_execution_failures_are_not_violations() {
        let rules = GridRules::new([[1; 32], [2; 32]]);
        let g = rules.genesis(&rules.roster);
        let p = rules.roster[0];
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
        assert_eq!(
            next.walkers[0],
            Walker {
                x: -4,
                y: -1,
                acts: 1,
                holding: true
            }
        );
    }
}
