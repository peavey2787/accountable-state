//! Fully deterministic, public-state, two-player tactical arena sample.
//! Fixed-grid physics, collision, cooldown, combat and terminal-state rules.
//! Intended for protocol tests, NOT a complete commercial game engine.
#![forbid(unsafe_code)]
use super::PublicRules;
use gv_core::{Digest, PlayerId};
use gv_replay::{GameRules, RuleError};
use sha2::{Digest as _, Sha256};

pub const LEFT: u16 = 1;
pub const RIGHT: u16 = 2;
pub const UP: u16 = 4;
pub const DOWN: u16 = 8;
pub const ATTACK: u16 = 16;
pub const GUARD: u16 = 32;
const ALLOWED: u16 = LEFT | RIGHT | UP | DOWN | ATTACK | GUARD;
const HP: u16 = 100;
const BOUND: i32 = 8;
/// The simulation runs at 60 Hz, one rules step per player per tick, so the
/// time-based mechanics are expressed in ticks. A held direction repeats every
/// 8 ticks (7.5 squares/s) and a tap shorter than that moves exactly once.
pub const MOVE_COOLDOWN_TICKS: u16 = 8;
/// Held attack lands at most twice a second.
pub const ATTACK_COOLDOWN_TICKS: u16 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fighter {
    pub x: i32,
    pub y: i32,
    pub hp: u16,
    pub cooldown: u16,
    pub move_cooldown: u16,
    pub guarding: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArenaState {
    pub fighters: [Fighter; 2],
}
impl ArenaState {
    pub const SIZE: usize = 30;
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::SIZE);
        for p in &self.fighters {
            b.extend_from_slice(&p.x.to_le_bytes());
            b.extend_from_slice(&p.y.to_le_bytes());
            b.extend_from_slice(&p.hp.to_le_bytes());
            b.extend_from_slice(&p.cooldown.to_le_bytes());
            b.extend_from_slice(&p.move_cooldown.to_le_bytes());
            b.push(u8::from(p.guarding));
        }
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, RuleError> {
        if b.len() != Self::SIZE {
            return Err(RuleError::EngineFailure("invalid arena state size".into()));
        }
        fn parse(b: &[u8], p: usize) -> Result<Fighter, RuleError> {
            let x = i32::from_le_bytes(
                b[p..p + 4]
                    .try_into()
                    .map_err(|_| RuleError::EngineFailure("x".into()))?,
            );
            let y = i32::from_le_bytes(
                b[p + 4..p + 8]
                    .try_into()
                    .map_err(|_| RuleError::EngineFailure("y".into()))?,
            );
            let hp = u16::from_le_bytes(
                b[p + 8..p + 10]
                    .try_into()
                    .map_err(|_| RuleError::EngineFailure("hp".into()))?,
            );
            let cooldown = u16::from_le_bytes(
                b[p + 10..p + 12]
                    .try_into()
                    .map_err(|_| RuleError::EngineFailure("cooldown".into()))?,
            );
            let move_cooldown = u16::from_le_bytes(
                b[p + 12..p + 14]
                    .try_into()
                    .map_err(|_| RuleError::EngineFailure("move cooldown".into()))?,
            );
            let guarding = match b[p + 14] {
                0 => false,
                1 => true,
                _ => return Err(RuleError::EngineFailure("guard".into())),
            };
            if !(-BOUND..=BOUND).contains(&x)
                || !(-BOUND..=BOUND).contains(&y)
                || hp > HP
                || cooldown > ATTACK_COOLDOWN_TICKS
                || move_cooldown > MOVE_COOLDOWN_TICKS
                || blocked(x, y)
            {
                return Err(RuleError::EngineFailure("state out of bounds".into()));
            }
            Ok(Fighter {
                x,
                y,
                hp,
                cooldown,
                move_cooldown,
                guarding,
            })
        }
        let a = parse(b, 0)?;
        let z = parse(b, 15)?;
        if a.x == z.x && a.y == z.y {
            return Err(RuleError::EngineFailure("overlapping fighters".into()));
        }
        Ok(Self { fighters: [a, z] })
    }
    pub fn winner(&self) -> Option<usize> {
        match (self.fighters[0].hp == 0, self.fighters[1].hp == 0) {
            (false, true) => Some(0),
            (true, false) => Some(1),
            _ => None,
        }
    }
}
fn blocked(x: i32, y: i32) -> bool {
    (x, y) == (0, 0) || (x, y) == (0, 1)
}
fn in_line_of_sight(a: Fighter, b: Fighter) -> bool {
    let dx = (a.x - b.x).abs();
    let dy = (a.y - b.y).abs();
    if dx + dy > 2 || dx + dy == 0 || (dx != 0 && dy != 0) {
        return false;
    }
    if dx > 0 {
        for x in (a.x.min(b.x) + 1)..a.x.max(b.x) {
            if blocked(x, a.y) {
                return false;
            }
        }
    }
    if dy > 0 {
        for y in (a.y.min(b.y) + 1)..a.y.max(b.y) {
            if blocked(a.x, y) {
                return false;
            }
        }
    }
    true
}
#[derive(Clone, Debug)]
pub struct ArenaRules {
    pub roster: [PlayerId; 2],
}
impl ArenaRules {
    pub fn new(mut roster: [PlayerId; 2]) -> Self {
        roster.sort();
        Self { roster }
    }
}
impl GameRules for ArenaRules {
    fn ruleset_hash(&self) -> Digest {
        // Versioned ruleset identity, NOT a reproducible binary code hash.
        Sha256::digest(b"gv/example-arena/public-deterministic/v1").into()
    }
    fn apply(&self, state: &[u8], input: &[u8]) -> Result<Vec<u8>, String> {
        self.apply_for_verification(state, input)
            .map_err(|e| format!("{e:?}"))
    }
    fn apply_for_verification(&self, state: &[u8], input: &[u8]) -> Result<Vec<u8>, RuleError> {
        if input.len() != 42 {
            return Err(RuleError::InvalidAction("input length".into()));
        }
        let player: PlayerId = input[..32]
            .try_into()
            .map_err(|_| RuleError::InvalidAction("player".into()))?;
        let i = self
            .roster
            .iter()
            .position(|p| *p == player)
            .ok_or(RuleError::InvalidAction("roster".into()))?;
        let controls = u16::from_le_bytes([input[40], input[41]]);
        if controls & !ALLOWED != 0 {
            return Err(RuleError::InvalidAction("unsupported controls".into()));
        }
        let movement = controls & (LEFT | RIGHT | UP | DOWN);
        if movement.count_ones() > 1 {
            return Err(RuleError::InvalidAction("contradictory movement".into()));
        }
        let mut s = ArenaState::decode(state)?;
        let j = 1 - i;
        // A fighter can die part-way through a multi-tick batch while its
        // player is still legitimately holding buttons. Those held inputs are
        // a deterministic no-op, not cheating; rejecting them would make an
        // honest killing blow look like fraud and abort the epoch forever.
        if s.fighters[i].hp == 0 {
            return Ok(s.encode());
        }
        if s.fighters[i].cooldown > 0 {
            s.fighters[i].cooldown -= 1;
        }
        if s.fighters[i].move_cooldown > 0 {
            s.fighters[i].move_cooldown -= 1;
        }
        let (dx, dy) = match movement {
            LEFT => (-1, 0),
            RIGHT => (1, 0),
            UP => (0, -1),
            DOWN => (0, 1),
            _ => (0, 0),
        };
        let x = s.fighters[i].x + dx;
        let y = s.fighters[i].y + dy;
        // A legal direction that hits a wall, boundary or opponent is a
        // deterministic no-op that does not spend the move cooldown. Do not
        // accuse an ordinary player of cheating merely because their held
        // movement button meets an obstacle.
        if movement != 0
            && s.fighters[i].move_cooldown == 0
            && (-BOUND..=BOUND).contains(&x)
            && (-BOUND..=BOUND).contains(&y)
            && !blocked(x, y)
            && !(x == s.fighters[j].x && y == s.fighters[j].y)
        {
            s.fighters[i].x = x;
            s.fighters[i].y = y;
            s.fighters[i].move_cooldown = MOVE_COOLDOWN_TICKS;
        }
        s.fighters[i].guarding = controls & GUARD != 0;
        if controls & ATTACK != 0 && s.fighters[i].cooldown == 0 {
            s.fighters[i].cooldown = ATTACK_COOLDOWN_TICKS;
            if in_line_of_sight(s.fighters[i], s.fighters[j]) && s.fighters[j].hp > 0 {
                let damage = if s.fighters[j].guarding { 3 } else { 12 };
                s.fighters[j].hp = s.fighters[j].hp.saturating_sub(damage);
            }
        }
        Ok(s.encode())
    }
}
impl PublicRules for ArenaRules {
    fn genesis(&self, _: &[PlayerId; 2]) -> Vec<u8> {
        ArenaState {
            fighters: [
                Fighter {
                    x: -4,
                    y: 0,
                    hp: HP,
                    cooldown: 0,
                    move_cooldown: 0,
                    guarding: false,
                },
                Fighter {
                    x: 4,
                    y: 0,
                    hp: HP,
                    cooldown: 0,
                    move_cooldown: 0,
                    guarding: false,
                },
            ],
        }
        .encode()
    }
}
