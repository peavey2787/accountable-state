//! Durable trust state for one participant: log snapshot, pinned heads and open challenges.
//! Every file is replaced atomically (`trust::write_state`) and checksummed; a missing, torn or
//! corrupted file is reported as absent and never trusted.
use super::trust::{read_state, write_state, Pins, StateRead};
use super::{AuditLog, Challenge};
use std::io;
use std::path::PathBuf;

const MAX_CHALLENGES: usize = 64;

pub struct Durable {
    base: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Loaded<T> {
    Missing,
    /// The file existed but failed its integrity check or decoding.
    Corrupt,
    Ok(T),
}

impl<T> Loaded<T> {
    pub fn ok(self) -> Option<T> {
        match self {
            Self::Ok(v) => Some(v),
            _ => None,
        }
    }
}

impl Durable {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }
    fn path(&self, ext: &str) -> PathBuf {
        let mut s = self.base.clone().into_os_string();
        s.push(".");
        s.push(ext);
        PathBuf::from(s)
    }
    pub fn log_path(&self) -> PathBuf {
        self.path("auditlog")
    }
    pub fn pins_path(&self) -> PathBuf {
        self.path("pins")
    }
    pub fn challenges_path(&self) -> PathBuf {
        self.path("challenges")
    }
    pub fn save_log(&self, log: &AuditLog) -> io::Result<()> {
        write_state(&self.log_path(), &log.encode())
    }
    pub fn load_log(&self) -> Loaded<AuditLog> {
        match read_state(&self.log_path()) {
            StateRead::Missing => Loaded::Missing,
            StateRead::Corrupt => Loaded::Corrupt,
            StateRead::Ok(b) => AuditLog::decode(&b).map_or(Loaded::Corrupt, Loaded::Ok),
        }
    }
    pub fn save_pins(&self, pins: &Pins) -> io::Result<()> {
        pins.save(&self.pins_path())
    }
    pub fn load_pins(&self) -> Loaded<Pins> {
        match read_state(&self.pins_path()) {
            StateRead::Missing => Loaded::Missing,
            StateRead::Corrupt => Loaded::Corrupt,
            StateRead::Ok(b) => Pins::decode(&b).map_or(Loaded::Corrupt, Loaded::Ok),
        }
    }
    pub fn save_challenges(&self, cs: &[Challenge]) -> io::Result<()> {
        let mut o = (cs.len().min(MAX_CHALLENGES) as u32).to_le_bytes().to_vec();
        for c in cs.iter().take(MAX_CHALLENGES) {
            let b = c.encode();
            o.extend_from_slice(&(b.len() as u32).to_le_bytes());
            o.extend_from_slice(&b);
        }
        write_state(&self.challenges_path(), &o)
    }
    pub fn load_challenges(&self) -> Loaded<Vec<Challenge>> {
        let b = match read_state(&self.challenges_path()) {
            StateRead::Missing => return Loaded::Missing,
            StateRead::Corrupt => return Loaded::Corrupt,
            StateRead::Ok(b) => b,
        };
        let parse = || -> Option<Vec<Challenge>> {
            let n = u32::from_le_bytes(b.get(..4)?.try_into().ok()?) as usize;
            if n > MAX_CHALLENGES {
                return None;
            }
            let (mut pos, mut out) = (4usize, Vec::new());
            for _ in 0..n {
                let l = u32::from_le_bytes(b.get(pos..pos + 4)?.try_into().ok()?) as usize;
                let c = Challenge::decode(b.get(pos + 4..pos + 4 + l)?).ok()?;
                if !c.verify() {
                    return None;
                }
                out.push(c);
                pos += 4 + l;
            }
            (pos == b.len()).then_some(out)
        };
        parse().map_or(Loaded::Corrupt, Loaded::Ok)
    }
}
