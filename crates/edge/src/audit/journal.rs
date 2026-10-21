//! Write-ahead trust journal.
//!
//! Rule: nothing this participant signs may leave the process until the log entries it commits
//! to, and the signed head itself, are durable (fsynced). `TrustStore::commit` is that barrier;
//! `Pipeline::poll_outbox` calls it before releasing any message and fails closed when it
//! errors. After a crash at ANY point the persisted state is therefore at least as new as
//! everything the opponent or a witness could have seen, so a restarted participant can never
//! sign a head that contradicts one it already sent (the `NoSelfEquivocation` invariant of
//! `spec/Accountability.tla`).
//!
//! Layout: `<base>.auditlog` is an atomically replaced snapshot (see `durable`); `<base>.trustwal`
//! is an append-only checksummed journal of `Header`, `Entry` (log appends) and `Head` (own
//! signed authenticators) records, group-committed with one fsync. Recovery replays the journal
//! onto the snapshot and returns the journalled heads as anchors. When the journal grows past
//! [`COMPACT_AT`] a new snapshot is written and the journal is rotated (keeping the latest heads).
use super::durable::{Durable, Loaded};
use super::failpoint;
use super::fsync::sync_parent_dir;
use super::log::{AuditLog, Authenticator};
use super::store::RecordFile;
use gv_core::{MatchId, PlayerId};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const T_HEADER: u8 = 0;
const T_ENTRY: u8 = 1;
const T_HEAD: u8 = 2;
/// Rotate the journal into a snapshot once it exceeds this many bytes.
pub const COMPACT_AT: u64 = 1 << 20;
/// Own heads kept across a rotation.
const KEEP_HEADS: usize = 8;

/// The durability barrier the auditor calls before anything it signed can leave the process.
pub trait TrustStore: Send {
    /// Make every entry of `log` and every head in `heads` durable, or fail.
    fn commit(&mut self, log: &AuditLog, heads: &[Authenticator]) -> io::Result<()>;
    /// Replace the durable state with `log` (recovery from a signed head supplied by a peer or
    /// witness): later commits continue from it. `heads` stay as anchors.
    fn reset(&mut self, _log: &AuditLog, _heads: &[Authenticator]) -> io::Result<()> {
        Ok(())
    }
}

/// What recovery found on disk.
pub struct LoadedTrust {
    pub log: Loaded<AuditLog>,
    /// Own signed heads that were durable before the crash (anchors for `check_log`).
    pub heads: Vec<Authenticator>,
}

pub struct FileTrustStore {
    snapshot: Durable,
    wal_path: PathBuf,
    wal: RecordFile,
    match_id: MatchId,
    owner: PlayerId,
    committed_len: u64,
    committed_head: u64,
    recent_heads: Vec<Authenticator>,
    has_header: bool,
    compact_at: u64,
}

fn header(match_id: &MatchId, owner: &PlayerId) -> Vec<u8> {
    let mut r = vec![T_HEADER];
    r.extend_from_slice(match_id);
    r.extend_from_slice(owner);
    r
}

fn entry(seq: u64, kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut r = vec![T_ENTRY];
    r.extend_from_slice(&seq.to_le_bytes());
    r.push(kind);
    r.extend_from_slice(payload);
    r
}

fn wal_path(base: &Path) -> PathBuf {
    let mut s = base.as_os_str().to_owned();
    s.push(".trustwal");
    PathBuf::from(s)
}

impl FileTrustStore {
    /// Open (creating if needed) and recover: snapshot plus journal replay. A torn journal tail
    /// is truncated; a gap, wrong owner/match or unreadable snapshot yields `Corrupt`/`Missing`
    /// and never a fabricated log.
    pub fn open(
        base: impl Into<PathBuf>,
        match_id: MatchId,
        owner: PlayerId,
    ) -> io::Result<(Self, LoadedTrust)> {
        let base: PathBuf = base.into();
        let snapshot = Durable::new(&base);
        let wal_path = wal_path(&base);
        let (wal, records) = RecordFile::open(&wal_path)?;
        let mut log = snapshot.load_log();
        let mut heads: Vec<Authenticator> = Vec::new();
        let mut has_header = false;
        let mut gap = false;
        let mut scratch: Option<AuditLog> = None;
        for r in &records {
            let Some((&tag, body)) = r.split_first() else {
                continue;
            };
            match tag {
                T_HEADER if body.len() == 64 => {
                    has_header = body[..32] == match_id && body[32..] == owner;
                    if has_header && matches!(log, Loaded::Missing) {
                        scratch = Some(AuditLog::new(match_id, owner));
                    }
                }
                T_ENTRY if has_header && body.len() >= 9 => {
                    let seq = u64::from_le_bytes(body[..8].try_into().unwrap_or([0; 8]));
                    let target = match (&mut log, &mut scratch) {
                        (Loaded::Ok(l), _) => Some(l),
                        (_, Some(l)) => Some(l),
                        _ => None,
                    };
                    if let Some(l) = target {
                        if seq == l.len() + 1 {
                            if l.append(body[8], body[9..].to_vec()).is_err() {
                                gap = true;
                            }
                        } else if seq > l.len() + 1 {
                            gap = true;
                        }
                    }
                }
                T_HEAD if has_header => {
                    if let Ok(a) = Authenticator::decode(body) {
                        if a.owner == owner && a.match_id == match_id && a.verify().is_ok() {
                            heads.push(a);
                        }
                    }
                }
                _ => {}
            }
        }
        if let (Loaded::Missing, Some(l)) = (&log, scratch) {
            log = Loaded::Ok(l);
        }
        if gap {
            log = Loaded::Corrupt;
        }
        let committed_len = match &log {
            Loaded::Ok(l) => l.len(),
            _ => 0,
        };
        let committed_head = heads.iter().map(|h| h.seq).max().unwrap_or(0);
        let mut recent = heads.clone();
        recent.sort_by_key(|h| h.seq);
        let keep_from = recent.len().saturating_sub(KEEP_HEADS);
        let store = Self {
            snapshot,
            wal_path,
            wal,
            match_id,
            owner,
            committed_len,
            committed_head,
            recent_heads: recent.split_off(keep_from),
            has_header,
            compact_at: COMPACT_AT,
        };
        Ok((store, LoadedTrust { log, heads }))
    }

    /// Test hook: rotate the journal at a smaller size.
    pub fn set_compact_at(&mut self, bytes: u64) {
        self.compact_at = bytes;
    }
    pub fn journal_size(&self) -> u64 {
        self.wal.size()
    }

    /// Write a snapshot of `log`, then atomically replace the journal with header + latest heads.
    fn compact(&mut self, log: &AuditLog) -> io::Result<()> {
        self.snapshot.save_log(log)?;
        failpoint::hit("compact.after_snapshot")?;
        let tmp = self.wal_path.with_extension("trustwal.new");
        let _ = fs::remove_file(&tmp);
        {
            let (mut fresh, _) = RecordFile::open(&tmp)?;
            let mut recs = vec![header(&self.match_id, &self.owner)];
            for h in &self.recent_heads {
                let mut r = vec![T_HEAD];
                r.extend_from_slice(&h.encode());
                recs.push(r);
            }
            fresh.append_group(&recs, false)?;
            fresh.sync()?;
        }
        failpoint::hit("compact.before_rename")?;
        fs::rename(&tmp, &self.wal_path)?;
        sync_parent_dir(&self.wal_path)?;
        let (wal, _) = RecordFile::open(&self.wal_path)?;
        self.wal = wal;
        self.has_header = true;
        Ok(())
    }
}

impl TrustStore for FileTrustStore {
    fn reset(&mut self, log: &AuditLog, heads: &[Authenticator]) -> io::Result<()> {
        for h in heads {
            if !self.recent_heads.iter().any(|r| r.seq == h.seq) {
                self.recent_heads.push(h.clone());
            }
        }
        self.recent_heads.sort_by_key(|h| h.seq);
        let excess = self.recent_heads.len().saturating_sub(KEEP_HEADS);
        self.recent_heads.drain(..excess);
        self.compact(log)?;
        self.committed_len = log.len();
        self.committed_head = self.recent_heads.iter().map(|h| h.seq).max().unwrap_or(0);
        Ok(())
    }
    fn commit(&mut self, log: &AuditLog, heads: &[Authenticator]) -> io::Result<()> {
        if log.owner() != self.owner || log.match_id() != self.match_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "log is not this store's",
            ));
        }
        failpoint::hit("commit.before_write")?;
        let mut recs: Vec<Vec<u8>> = Vec::new();
        if !self.has_header {
            recs.push(header(&self.match_id, &self.owner));
        }
        if log.len() < self.committed_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "log is shorter than its durable prefix",
            ));
        }
        if log.len() > self.committed_len {
            if log.base_seq() > self.committed_len {
                // Entries between the durable prefix and the retained window are gone; only a
                // snapshot can make this log durable.
                self.snapshot.save_log(log)?;
                self.committed_len = log.len();
            } else {
                let seg = log
                    .segment(self.committed_len, log.len())
                    .map_err(|_| io::Error::other("cannot read new log entries"))?;
                for (i, e) in seg.entries.iter().enumerate() {
                    recs.push(entry(self.committed_len + 1 + i as u64, e.kind, &e.payload));
                }
            }
        }
        let mut new_heads: Vec<&Authenticator> = heads
            .iter()
            .filter(|h| h.seq > self.committed_head)
            .collect();
        new_heads.sort_by_key(|h| h.seq);
        for h in &new_heads {
            let mut r = vec![T_HEAD];
            r.extend_from_slice(&h.encode());
            recs.push(r);
        }
        if recs.is_empty() {
            return Ok(());
        }
        let torn = failpoint::check("commit.torn_write");
        self.wal.append_group(&recs, torn.is_some())?;
        if let Some(action) = torn {
            // The half-written record is on disk exactly as a crash would leave it.
            let r = failpoint::fire(action, "commit.torn_write");
            self.wal.rollback();
            return r;
        }
        if let Err(e) = failpoint::hit("commit.before_sync") {
            self.wal.rollback();
            return Err(e);
        }
        if let Err(e) = self.wal.sync() {
            self.wal.rollback();
            return Err(e);
        }
        failpoint::hit("commit.after_sync")?;
        if !self.has_header {
            sync_parent_dir(&self.wal_path)?;
            self.has_header = true;
        }
        self.committed_len = log.len();
        for h in new_heads {
            self.committed_head = self.committed_head.max(h.seq);
            self.recent_heads.push(h.clone());
        }
        let excess = self.recent_heads.len().saturating_sub(KEEP_HEADS);
        self.recent_heads.drain(..excess);
        if self.wal.size() > self.compact_at {
            self.compact(log)?;
        }
        Ok(())
    }
}
