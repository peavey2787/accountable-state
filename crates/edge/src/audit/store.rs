//! Crash-safe append-only record file: `[u32 len][8-byte SHA-256 prefix][payload]`.
//! Recovery keeps the longest valid prefix and truncates a torn or corrupt tail, so
//! a crash mid-write never loses earlier evidence. Total size is bounded.
use sha2::{Digest as _, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const MAX_RECORD: usize = 2 << 20;
pub const MAX_FILE: u64 = 256 << 20;

pub struct RecordFile {
    path: PathBuf,
    file: File,
    size: u64,
}

fn tag(payload: &[u8]) -> [u8; 8] {
    let d = Sha256::digest(payload);
    let mut t = [0u8; 8];
    t.copy_from_slice(&d[..8]);
    t
}

/// Longest valid prefix of `data`: its length and the records in it.
fn parse(data: &[u8]) -> (usize, Vec<Vec<u8>>) {
    let (mut pos, mut out) = (0usize, Vec::new());
    while data.len() - pos >= 12 {
        let len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let end = pos + 12 + len;
        if len > MAX_RECORD
            || end > data.len()
            || data[pos + 4..pos + 12] != tag(&data[pos + 12..end])
        {
            break;
        }
        out.push(data[pos + 12..end].to_vec());
        pos = end;
    }
    (pos, out)
}

impl RecordFile {
    /// Read-only view of the intact records (never truncates), safe beside a live writer: a
    /// record still being written is simply not yet visible.
    pub fn read_all(path: &Path) -> io::Result<Vec<Vec<u8>>> {
        let mut data = Vec::new();
        File::open(path)?.take(MAX_FILE).read_to_end(&mut data)?;
        Ok(parse(&data).1)
    }
    /// Open (creating if needed) and return every intact record. Anything after
    /// the first invalid record is truncated.
    pub fn open(path: &Path) -> io::Result<(Self, Vec<Vec<u8>>)> {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let mut data = Vec::new();
        Read::by_ref(&mut f).take(MAX_FILE).read_to_end(&mut data)?;
        let (pos, out) = parse(&data);
        f.set_len(pos as u64)?;
        let mut me = Self {
            path: path.to_path_buf(),
            file: f,
            size: pos as u64,
        };
        io::Seek::seek(&mut me.file, io::SeekFrom::End(0))?;
        Ok((me, out))
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut rec = Vec::with_capacity(payload.len() + 12);
        rec.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        rec.extend_from_slice(&tag(payload));
        rec.extend_from_slice(payload);
        rec
    }
    /// Write several records with ONE sync (group commit). On any failure the file is rolled back
    /// to its previous valid size, so a later append never lands behind a partial record.
    /// `torn` writes only part of the last record, syncs, and leaves it on disk, as a crash
    /// mid-write would (fault injection; the caller then aborts or reports failure).
    pub fn append_group(&mut self, payloads: &[Vec<u8>], torn: bool) -> io::Result<()> {
        let mut buf = Vec::new();
        for p in payloads {
            if p.len() > MAX_RECORD {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "record too large",
                ));
            }
            buf.extend_from_slice(&Self::frame(p));
        }
        if self.size + buf.len() as u64 > MAX_FILE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "record store bound exceeded",
            ));
        }
        if torn {
            buf.truncate(buf.len() - payloads.last().map_or(0, |p| (p.len() + 12) / 2 + 1));
        }
        if let Err(e) = self.file.write_all(&buf) {
            self.rollback();
            return Err(e);
        }
        if torn {
            self.file.sync_data()?;
            return Ok(()); // size not advanced: the caller must abort or call `rollback`
        }
        self.size += buf.len() as u64;
        Ok(())
    }
    /// Discard anything written after the last valid record.
    pub fn rollback(&mut self) {
        let _ = self.file.set_len(self.size);
        let _ = io::Seek::seek(&mut self.file, io::SeekFrom::Start(self.size));
    }
    pub fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }
    pub fn append(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_RECORD || self.size + payload.len() as u64 + 12 > MAX_FILE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "record store bound exceeded",
            ));
        }
        let mut rec = Vec::with_capacity(payload.len() + 12);
        rec.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        rec.extend_from_slice(&tag(payload));
        rec.extend_from_slice(payload);
        self.file.write_all(&rec)?;
        self.file.sync_data()?;
        self.size += rec.len() as u64;
        Ok(())
    }
}
