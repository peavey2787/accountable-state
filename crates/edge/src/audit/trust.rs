//! Trust anchors for crash recovery.
//!
//! A log that is merely self-consistent proves nothing: an attacker with write access to the
//! snapshot can supply an older (or forked) but perfectly chained log. Recovery is therefore
//! anchored to signed heads (`Authenticator`s) that were authenticated *before* the crash and are
//! held outside the snapshot: in the local pin file, and by peers and witnesses. If no anchor is
//! available the result is an explicit `Unresolved` state, never a silent adoption.
use super::fsync::replace_file;
use super::log::{AuditLog, Authenticator, LogError};
use gv_core::{Digest, MatchId, ParticipantId};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io;
use std::path::Path;

const PINS_MAGIC: &[u8] = b"GV-TRUST-PINS/V1\0";
const STATE_MAGIC: &[u8] = b"GV-STATE/V1\0";
pub const MAX_PINS: usize = 64;
pub const MAX_STATE_BYTES: usize = 64 << 20;

fn checksum(domain: &[u8], b: &[u8]) -> Digest {
    let mut s = Sha256::new();
    s.update(b"gv/state-checksum/v1\0");
    s.update(domain);
    s.update(b);
    s.finalize().into()
}

/// Durable atomic replacement: write a temp file, fsync it, rename over the target, fsync the
/// directory. A crash leaves either the complete old file or the complete new file. The
/// payload is framed with length and checksum so truncation or bit rot is detected on read.
pub fn write_state(path: &Path, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_STATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "state too large",
        ));
    }
    let mut framed = STATE_MAGIC.to_vec();
    framed.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    framed.extend_from_slice(payload);
    framed.extend_from_slice(&checksum(STATE_MAGIC, payload));
    replace_file(path, &framed)
}

#[derive(Debug, PartialEq, Eq)]
pub enum StateRead {
    Missing,
    /// Present but truncated, corrupted or oversized; the content must not be used.
    Corrupt,
    Ok(Vec<u8>),
}

pub fn read_state(path: &Path) -> StateRead {
    let Ok(meta) = fs::metadata(path) else {
        return StateRead::Missing;
    };
    if meta.len() > (MAX_STATE_BYTES + 128) as u64 {
        return StateRead::Corrupt;
    }
    let Ok(b) = fs::read(path) else {
        return StateRead::Corrupt;
    };
    let Some(r) = b.strip_prefix(STATE_MAGIC) else {
        return StateRead::Corrupt;
    };
    if r.len() < 8 + 32 {
        return StateRead::Corrupt;
    }
    let len = u64::from_le_bytes(r[..8].try_into().unwrap_or([0; 8]));
    if usize::try_from(len).ok() != r.len().checked_sub(8 + 32) {
        return StateRead::Corrupt;
    }
    let body = &r[8..r.len() - 32];
    if r[r.len() - 32..] != checksum(STATE_MAGIC, body) {
        return StateRead::Corrupt;
    }
    StateRead::Ok(body.to_vec())
}

/// Previously authenticated signed heads, bounded: at most the highest few per owner.
#[derive(Clone, Debug, Default)]
pub struct Pins {
    items: Vec<Authenticator>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PinError {
    Invalid,
    Full,
    /// Same owner and sequence, different head: the pins contradict each other (equivocation).
    Conflict(Box<Authenticator>),
}

const PER_OWNER: usize = MAX_PINS / 2;

impl Pins {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn items(&self) -> &[Authenticator] {
        &self.items
    }
    pub fn for_owner(&self, owner: ParticipantId) -> impl Iterator<Item = &Authenticator> {
        self.items.iter().filter(move |a| a.owner == owner)
    }
    pub fn highest(&self, owner: ParticipantId) -> Option<&Authenticator> {
        self.for_owner(owner).max_by_key(|a| a.seq)
    }
    /// Verify and pin. Keeps the `PER_OWNER` highest per owner so storage stays bounded.
    pub fn add(&mut self, a: &Authenticator) -> Result<bool, PinError> {
        a.verify().map_err(|_| PinError::Invalid)?;
        if let Some(prev) = self
            .items
            .iter()
            .find(|p| p.owner == a.owner && p.seq == a.seq)
        {
            return if prev.head == a.head {
                Ok(false)
            } else {
                Err(PinError::Conflict(Box::new(prev.clone())))
            };
        }
        let mine = self.for_owner(a.owner).count();
        if mine >= PER_OWNER {
            let lowest = self
                .for_owner(a.owner)
                .map(|p| p.seq)
                .min()
                .unwrap_or(u64::MAX);
            if a.seq <= lowest {
                return Err(PinError::Full);
            }
            if let Some(i) = self
                .items
                .iter()
                .position(|p| p.owner == a.owner && p.seq == lowest)
            {
                self.items.remove(i);
            }
        }
        self.items.push(a.clone());
        Ok(true)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = PINS_MAGIC.to_vec();
        o.extend_from_slice(&(self.items.len() as u32).to_le_bytes());
        for a in &self.items {
            o.extend_from_slice(&a.encode());
        }
        o
    }
    /// Strict decode; every pin must verify. A single bad pin rejects the file.
    pub fn decode(b: &[u8]) -> Result<Self, LogError> {
        let r = b.strip_prefix(PINS_MAGIC).ok_or(LogError::Malformed)?;
        if r.len() < 4 {
            return Err(LogError::Malformed);
        }
        let n = u32::from_le_bytes(r[..4].try_into().map_err(|_| LogError::Malformed)?) as usize;
        let body = &r[4..];
        if n > MAX_PINS || body.len() != n * Authenticator::WIRE_SIZE {
            return Err(LogError::Malformed);
        }
        let mut pins = Self::new();
        for c in body.chunks(Authenticator::WIRE_SIZE) {
            let a = Authenticator::decode(c)?;
            pins.add(&a).map_err(|_| LogError::BadSignature)?;
        }
        Ok(pins)
    }
    pub fn save(&self, path: &Path) -> io::Result<()> {
        write_state(path, &self.encode())
    }
    /// A missing, corrupt or invalid pin file yields no pins (and `false`): losing local pins
    /// never fabricates trust, it only forces recovery to find anchors elsewhere.
    pub fn load(path: &Path) -> (Self, bool) {
        match read_state(path) {
            StateRead::Ok(b) => match Self::decode(&b) {
                Ok(p) => (p, true),
                Err(_) => (Self::new(), false),
            },
            _ => (Self::new(), false),
        }
    }
}

/// Why a persisted log was not adopted. None of these is proof that anyone cheated: they say the
/// local copy cannot be trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    WrongOwnerOrMatch,
    /// The log is shorter than a head this participant signed earlier.
    Rollback {
        pinned_seq: u64,
        log_len: u64,
    },
    /// The log contradicts a head this participant signed earlier.
    Fork {
        seq: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unresolved {
    /// A log exists but no authenticated head exists to check it against.
    NoAnchor,
    /// The log was pruned past every available anchor; the anchor cannot be checked.
    AnchorPruned,
    /// Anchors prove a log existed, but no usable snapshot remains. Signing is suspended so a
    /// restarted chain cannot contradict previously signed heads.
    LogLost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// No prior state and no anchors: a genuinely fresh start.
    Fresh,
    Resumed {
        len: u64,
        anchored_at: u64,
    },
    Unresolved(Unresolved),
    Refused(Refusal),
}

impl Recovery {
    /// May this participant sign new log heads?
    pub fn may_sign(&self) -> bool {
        matches!(self, Self::Fresh | Self::Resumed { .. })
    }
}

/// Decide whether `log` may be adopted given `anchors` (heads signed by `me`, from the local pin
/// file or handed back by peers and witnesses). Pure; used by the auditor and by tests.
pub fn check_log(
    me: ParticipantId,
    match_id: MatchId,
    log: Option<&AuditLog>,
    anchors: &[Authenticator],
) -> Recovery {
    let mine: Vec<&Authenticator> = anchors
        .iter()
        .filter(|a| a.owner == me && a.match_id == match_id && a.verify().is_ok())
        .collect();
    let Some(log) = log else {
        return if mine.is_empty() {
            Recovery::Fresh
        } else {
            Recovery::Unresolved(Unresolved::LogLost)
        };
    };
    if log.owner() != me || log.match_id() != match_id {
        return Recovery::Refused(Refusal::WrongOwnerOrMatch);
    }
    if mine.is_empty() {
        return Recovery::Unresolved(Unresolved::NoAnchor);
    }
    let mut verified: Option<u64> = None;
    let mut pruned = false;
    for p in &mine {
        if p.seq > log.len() {
            return Recovery::Refused(Refusal::Rollback {
                pinned_seq: p.seq,
                log_len: log.len(),
            });
        }
        match log.head_at(p.seq) {
            Some(h) if h == p.head => verified = verified.max(Some(p.seq)),
            Some(_) => return Recovery::Refused(Refusal::Fork { seq: p.seq }),
            None => pruned = true,
        }
    }
    match verified {
        Some(anchored_at) => Recovery::Resumed {
            len: log.len(),
            anchored_at,
        },
        None if pruned => Recovery::Unresolved(Unresolved::AnchorPruned),
        None => Recovery::Unresolved(Unresolved::NoAnchor),
    }
}
