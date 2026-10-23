//! Where queue records live. [`FileJournal`] is the durable, checksummed, append-only file (a torn
//! tail from a crash is dropped at open); [`MemJournal`] is the same contract in memory, for tests
//! (crash, capacity and failure injection); [`OutboxJournal`] hands writes to a host that persists
//! them itself (a browser's IndexedDB, an engine's save system).
use gv_edge::audit::store::RecordFile;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

pub trait Journal: Send {
    /// Make `records` durable as one group: all of them or none.
    fn append(&mut self, records: &[Vec<u8>]) -> io::Result<()>;
    /// Atomically replace the whole journal (compaction).
    fn rewrite(&mut self, records: &[Vec<u8>]) -> io::Result<()>;
    fn size(&self) -> u64;
}

/// What a journal held when opened.
pub struct Opened<J> {
    pub journal: J,
    pub records: Vec<Vec<u8>>,
    /// Bytes dropped because they were torn or failed their checksum.
    pub truncated: u64,
}

pub struct FileJournal {
    path: PathBuf,
    file: Option<RecordFile>,
}

impl FileJournal {
    pub fn open(path: &Path) -> io::Result<Opened<Self>> {
        let before = std::fs::metadata(path).map_or(0, |m| m.len());
        let (file, records) = RecordFile::open(path)?;
        let truncated = before.saturating_sub(file.size());
        Ok(Opened {
            journal: Self {
                path: path.to_path_buf(),
                file: Some(file),
            },
            records,
            truncated,
        })
    }

    fn file(&mut self) -> io::Result<&mut RecordFile> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("journal closed"))
    }

    fn write_replacement(&self, records: &[Vec<u8>]) -> io::Result<PathBuf> {
        let tmp = self.path.with_extension("compact");
        let _ = std::fs::remove_file(&tmp);
        let (mut fresh, _) = RecordFile::open(&tmp)?;
        let written = fresh
            .append_group(records, false)
            .and_then(|()| fresh.sync());
        drop(fresh);
        match written {
            Ok(()) => Ok(tmp),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    }
}

impl Journal for FileJournal {
    fn append(&mut self, records: &[Vec<u8>]) -> io::Result<()> {
        let file = self.file()?;
        file.append_group(records, false)?;
        if let Err(e) = file.sync() {
            file.rollback();
            return Err(e);
        }
        Ok(())
    }

    fn rewrite(&mut self, records: &[Vec<u8>]) -> io::Result<()> {
        let tmp = self.write_replacement(records)?;
        self.file = None; // release the handle: Windows cannot replace an open file
        let renamed = std::fs::rename(&tmp, &self.path);
        let reopened = RecordFile::open(&self.path).map(|(f, _)| f);
        self.file = reopened.ok();
        renamed?;
        self.file().map(|_| ())
    }

    fn size(&self) -> u64 {
        self.file.as_ref().map_or(0, RecordFile::size)
    }
}

/// Shared in-memory state: clones are handles to the same journal, so dropping a queue and
/// reopening from another handle models a process restart.
#[derive(Clone, Default)]
pub struct MemJournal(Arc<Mutex<MemState>>);

#[derive(Default)]
struct MemState {
    records: Vec<Vec<u8>>,
    size: u64,
    capacity: Option<u64>,
    fail_appends: bool,
}

const FRAME: u64 = 12;

impl MemJournal {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, MemState> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Refuse appends that would grow the journal past `bytes` (a full disk).
    pub fn set_capacity(&self, bytes: Option<u64>) {
        self.state().capacity = bytes;
    }

    /// Fail every append until cleared (an I/O error).
    pub fn set_failing(&self, failing: bool) {
        self.state().fail_appends = failing;
    }

    pub fn records(&self) -> Vec<Vec<u8>> {
        self.state().records.clone()
    }

    /// Keep only the first `n` records, as a crash that lost the rest would.
    pub fn truncate_to(&self, n: usize) {
        let mut s = self.state();
        s.records.truncate(n);
        s.size = s.records.iter().map(|r| r.len() as u64 + FRAME).sum();
    }

    pub fn open(&self) -> Opened<Self> {
        Opened {
            journal: self.clone(),
            records: self.records(),
            truncated: 0,
        }
    }
}

impl Journal for MemJournal {
    fn append(&mut self, records: &[Vec<u8>]) -> io::Result<()> {
        let mut s = self.state();
        let add: u64 = records.iter().map(|r| r.len() as u64 + FRAME).sum();
        if s.fail_appends || s.capacity.is_some_and(|c| s.size + add > c) {
            return Err(io::Error::other("journal write refused"));
        }
        s.size += add;
        s.records.extend(records.iter().cloned());
        Ok(())
    }

    fn rewrite(&mut self, records: &[Vec<u8>]) -> io::Result<()> {
        let mut s = self.state();
        let size: u64 = records.iter().map(|r| r.len() as u64 + FRAME).sum();
        if s.fail_appends || s.capacity.is_some_and(|c| size > c) {
            return Err(io::Error::other("journal write refused"));
        }
        s.records = records.to_vec();
        s.size = size;
        Ok(())
    }

    fn size(&self) -> u64 {
        self.state().size
    }
}

/// One write a host must persist, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Write {
    /// These records, after the ones already persisted.
    Append(Vec<Vec<u8>>),
    /// These records replace everything persisted (compaction).
    Rewrite(Vec<Vec<u8>>),
}

/// A journal for hosts that cannot be written synchronously. Writes accumulate in an outbox the
/// host drains with [`OutboxJournal::take`] and stores; a result is durable only once the host has
/// stored the writes made before it, so a host acknowledges to its callers only after storing.
/// The outbox is bounded: a host that stops draining makes the queue refuse work (backpressure)
/// instead of growing without limit.
#[derive(Clone)]
pub struct OutboxJournal(Arc<Mutex<Outbox>>);

struct Outbox {
    pending: Vec<Write>,
    pending_bytes: u64,
    limit: u64,
    size: u64,
}

impl OutboxJournal {
    /// `persisted` are the records the host stored earlier; at most `limit` bytes may wait to be
    /// drained.
    pub fn open(persisted: Vec<Vec<u8>>, limit: u64) -> Opened<Self> {
        let size = persisted.iter().map(|r| r.len() as u64 + FRAME).sum();
        Opened {
            journal: Self(Arc::new(Mutex::new(Outbox {
                pending: Vec::new(),
                pending_bytes: 0,
                limit,
                size,
            }))),
            records: persisted,
            truncated: 0,
        }
    }

    fn state(&self) -> MutexGuard<'_, Outbox> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Everything the host must store, oldest first. Clears the outbox.
    pub fn take(&self) -> Vec<Write> {
        let mut s = self.state();
        s.pending_bytes = 0;
        std::mem::take(&mut s.pending)
    }

    fn push(&mut self, write: Write, bytes: u64) -> io::Result<()> {
        let mut s = self.state();
        if s.pending_bytes + bytes > s.limit {
            return Err(io::Error::other(
                "journal outbox is full: persist pending writes",
            ));
        }
        s.pending_bytes += bytes;
        s.pending.push(write);
        Ok(())
    }
}

fn framed(records: &[Vec<u8>]) -> u64 {
    records.iter().map(|r| r.len() as u64 + FRAME).sum()
}

impl Journal for OutboxJournal {
    fn append(&mut self, records: &[Vec<u8>]) -> io::Result<()> {
        let bytes = framed(records);
        self.push(Write::Append(records.to_vec()), bytes)?;
        self.state().size += bytes;
        Ok(())
    }

    fn rewrite(&mut self, records: &[Vec<u8>]) -> io::Result<()> {
        let bytes = framed(records);
        self.push(Write::Rewrite(records.to_vec()), bytes)?;
        self.state().size = bytes;
        Ok(())
    }

    fn size(&self) -> u64 {
        self.state().size
    }
}
