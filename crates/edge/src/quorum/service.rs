//! The witness side of the register: one durable [`Cell`] per owner, written before any reply.
use super::acceptor::{Acceptor, Cell};
use super::wire::QuorumMsg;
use crate::audit::fsync::replace_file;
use gv_core::{MatchId, ParticipantId};
use gv_sig::SigningKey;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;

/// Durable storage for acceptor cells. `save` returns only once the bytes survive a crash.
pub trait CellStore {
    /// `Ok(None)`: this owner has never been seen. `Err`: the record exists but is unreadable.
    fn load(&self, match_id: &MatchId, owner: &ParticipantId) -> io::Result<Option<Vec<u8>>>;
    fn save(&mut self, match_id: &MatchId, owner: &ParticipantId, bytes: &[u8]) -> io::Result<()>;
}

/// One atomically replaced file per (match, owner) under a directory. The file is named by the
/// complete match and owner ids and begins with them, so two matches never share a file and a
/// file is never read back for a match or owner it does not name.
pub struct FileCellStore {
    dir: PathBuf,
}

/// Version tag at the start of every cell file, followed by the match id and the owner id.
const CELL_MAGIC: &[u8; 8] = b"GVCELL01";
const CELL_HEADER: usize = CELL_MAGIC.len() + 64;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_owned())
}

impl FileCellStore {
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }
    fn path(&self, m: &MatchId, o: &ParticipantId) -> PathBuf {
        self.dir.join(format!("v1-{}-{}.cell", hex(m), hex(o)))
    }
    /// The pre-v1 name, which kept only id prefixes and could be shared by different matches.
    fn legacy_path(&self, m: &MatchId, o: &ParticipantId) -> PathBuf {
        self.dir
            .join(format!("{}-{}.cell", hex(&m[..8]), hex(&o[..16])))
    }
}

impl CellStore for FileCellStore {
    /// A pre-v1 file for this pair is refused rather than adopted: it records no match id, so it
    /// may hold another match's cell, and forgetting it would drop a promise. The owner is then
    /// unanswered by this witness (fail closed) until the match ends.
    fn load(&self, m: &MatchId, o: &ParticipantId) -> io::Result<Option<Vec<u8>>> {
        let bytes = match std::fs::read(self.path(m, o)) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if self.legacy_path(m, o).exists() {
                    return Err(invalid("pre-v1 cell file without match identity"));
                }
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let (header, cell) = bytes
            .split_at_checked(CELL_HEADER)
            .ok_or_else(|| invalid("truncated cell file"))?;
        if &header[..8] != CELL_MAGIC || header[8..40] != m[..] || header[40..] != o[..] {
            return Err(invalid("cell file names another match or owner"));
        }
        Ok(Some(cell.to_vec()))
    }
    fn save(&mut self, m: &MatchId, o: &ParticipantId, bytes: &[u8]) -> io::Result<()> {
        let mut file = Vec::with_capacity(CELL_HEADER + bytes.len());
        file.extend_from_slice(CELL_MAGIC);
        file.extend_from_slice(m);
        file.extend_from_slice(o);
        file.extend_from_slice(bytes);
        replace_file(&self.path(m, o), &file)
    }
}

/// The acceptor role of a witness process. Fails closed: an unreadable or unwritable cell means
/// no reply for that owner, never a reply from reconstructed or forgotten state.
pub struct RegisterWitness<S: CellStore> {
    acceptor: Acceptor,
    store: S,
    cells: BTreeMap<(MatchId, ParticipantId), Cell>,
    poisoned: BTreeSet<(MatchId, ParticipantId)>,
}

impl<S: CellStore> RegisterWitness<S> {
    pub fn new(key: SigningKey, store: S) -> Self {
        Self {
            acceptor: Acceptor::new(key),
            store,
            cells: BTreeMap::new(),
            poisoned: BTreeSet::new(),
        }
    }

    pub fn id(&self) -> ParticipantId {
        self.acceptor.id()
    }

    /// Owners whose stored cell could not be trusted.
    pub fn poisoned(&self) -> usize {
        self.poisoned.len()
    }

    /// Answer an owner's request. Empty when the request is invalid, refused, or could not be
    /// made durable.
    pub fn handle(&mut self, match_id: MatchId, msg: &QuorumMsg) -> Vec<QuorumMsg> {
        let owner = match msg {
            QuorumMsg::Recover(r) => r.owner,
            QuorumMsg::Store(c) => c.owner(),
            QuorumMsg::HeldReq { owner, .. } => *owner,
            _ => return Vec::new(),
        };
        let key = (match_id, owner);
        if !self.load(&key) {
            return Vec::new();
        }
        let Some(cell) = self.cells.get_mut(&key) else {
            return Vec::new();
        };
        if let QuorumMsg::HeldReq { seq, .. } = msg {
            return self.acceptor.held(cell, *seq);
        }
        let store = &mut self.store;
        let mut persist = |m: &MatchId, o: &ParticipantId, b: &[u8]| store.save(m, o, b).is_ok();
        self.acceptor
            .handle(cell, msg, &mut persist)
            .into_iter()
            .collect()
    }

    fn load(&mut self, key: &(MatchId, ParticipantId)) -> bool {
        if self.cells.contains_key(key) {
            return true;
        }
        if self.poisoned.contains(key) {
            return false;
        }
        let cell = match self.store.load(&key.0, &key.1) {
            Ok(None) => Some(Cell::default()),
            Ok(Some(b)) => Cell::decode(&b),
            Err(_) => None,
        };
        match cell {
            Some(c) => {
                self.cells.insert(*key, c);
                true
            }
            None => {
                self.poisoned.insert(*key);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> (PathBuf, FileCellStore) {
        let dir = std::env::temp_dir().join(format!("gv-cell-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = FileCellStore::open(&dir).unwrap();
        (dir, store)
    }

    #[test]
    fn matches_sharing_a_long_prefix_keep_separate_cells_across_reopen() {
        let (dir, mut store) = store("prefix");
        let owner = [7u8; 32];
        let (mut a, mut b) = ([9u8; 32], [9u8; 32]);
        a[31] = 1;
        b[31] = 2;
        store.save(&a, &owner, b"cell a").unwrap();
        store.save(&b, &owner, b"cell b").unwrap();
        let reopened = FileCellStore::open(&dir).unwrap();
        assert_eq!(reopened.load(&a, &owner).unwrap().unwrap(), b"cell a");
        assert_eq!(reopened.load(&b, &owner).unwrap().unwrap(), b"cell b");
        let mut other_owner = owner;
        other_owner[31] ^= 1;
        assert_eq!(reopened.load(&a, &other_owner).unwrap(), None);
    }

    #[test]
    fn a_file_naming_another_match_or_a_damaged_file_is_refused() {
        let (_dir, mut store) = store("foreign");
        let (a, b, owner) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        store.save(&b, &owner, b"cell b").unwrap();
        std::fs::copy(store.path(&b, &owner), store.path(&a, &owner)).unwrap();
        assert!(store.load(&a, &owner).is_err());
        std::fs::write(store.path(&b, &owner), b"GVCELL01").unwrap();
        assert!(store.load(&b, &owner).is_err());
    }

    #[test]
    fn a_legacy_prefix_named_cell_is_refused_not_adopted() {
        let (_dir, store) = store("legacy");
        let (m, owner) = ([4u8; 32], [5u8; 32]);
        std::fs::write(store.legacy_path(&m, &owner), [0u8]).unwrap();
        assert!(store.load(&m, &owner).is_err());
    }
}
