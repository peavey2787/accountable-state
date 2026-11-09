//! Write policies for the node's replaceable files: when the certified archive is saved again
//! after a failure, and how standalone evidence packages are named and written.
use gv_core::Digest;
use gv_edge::audit::fsync::replace_file;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

/// Delay between archive saves while writes succeed.
const SAVE_EVERY: Duration = Duration::from_secs(1);
/// Longest wait between retries after repeated failures.
const MAX_RETRY: Duration = Duration::from_secs(30);

/// Pending-write state of the certified archive. Pending data stays pending until a write
/// succeeds; failures are retried with doubling delays and reported as unhealthy meanwhile.
pub(crate) struct ArchiveWrites {
    dirty: bool,
    healthy: bool,
    last_attempt: Option<Instant>,
    delay: Duration,
}

impl ArchiveWrites {
    pub fn new(now: Instant) -> Self {
        Self {
            dirty: false,
            healthy: true,
            last_attempt: Some(now),
            delay: SAVE_EVERY,
        }
    }
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }
    pub fn dirty(&self) -> bool {
        self.dirty
    }
    /// False from a failed write until the next successful one.
    pub fn healthy(&self) -> bool {
        self.healthy
    }
    /// Whether pending data should be written now.
    pub fn due(&self, now: Instant) -> bool {
        self.dirty
            && self
                .last_attempt
                .is_none_or(|t| now.saturating_duration_since(t) >= self.delay)
    }
    /// Record the outcome of a write attempt made at `now`.
    pub fn record(&mut self, written: bool, now: Instant) {
        self.last_attempt = Some(now);
        self.healthy = written;
        if written {
            self.dirty = false;
            self.delay = SAVE_EVERY;
        } else {
            self.delay = (self.delay * 2).min(MAX_RETRY);
        }
    }
}

/// File suffix of a standalone package: the label and the complete package digest, so two
/// different packages never share a file.
pub(crate) fn package_suffix(label: &str, id: &Digest) -> String {
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!(".{label}-{hex}.package")
}

/// Write a package unless the file already holds exactly these bytes. `Ok(true)`: written.
/// A file holding anything else (a damaged or partial copy) is replaced.
pub(crate) fn write_package(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    match std::fs::read(path) {
        Ok(existing) if existing == bytes => Ok(false),
        Ok(_) => replace_file(path, bytes).map(|()| true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => replace_file(path, bytes).map(|()| true),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gv-dw-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_failed_archive_write_stays_pending_unhealthy_and_backs_off_until_it_succeeds() {
        let t0 = Instant::now();
        let mut w = ArchiveWrites::new(t0);
        w.mark_dirty();
        let t1 = t0 + SAVE_EVERY;
        assert!(w.due(t1));
        w.record(false, t1);
        assert!(w.dirty() && !w.healthy());
        assert!(!w.due(t1 + SAVE_EVERY));
        assert!(w.due(t1 + SAVE_EVERY * 2));
        let t2 = t1 + SAVE_EVERY * 2;
        w.record(false, t2);
        assert!(!w.due(t2 + SAVE_EVERY * 3) && w.due(t2 + SAVE_EVERY * 4));
        for _ in 0..10 {
            w.record(false, t2);
        }
        assert!(w.due(t2 + MAX_RETRY));
        w.record(true, t2 + MAX_RETRY);
        assert!(!w.dirty() && w.healthy() && !w.due(t2 + MAX_RETRY * 2));
    }

    #[test]
    fn real_write_faults_keep_data_pending_and_a_later_write_recovers() {
        let base = dir("fault");
        let blocked = base.join("not-a-dir");
        std::fs::write(&blocked, b"file").unwrap();
        let target = blocked.join("archive");
        let t0 = Instant::now();
        let mut w = ArchiveWrites::new(t0);
        w.mark_dirty();
        let t1 = t0 + SAVE_EVERY;
        w.record(replace_file(&target, b"receipts").is_ok(), t1);
        assert!(w.dirty() && !w.healthy());
        std::fs::remove_file(&blocked).unwrap();
        std::fs::create_dir(&blocked).unwrap();
        let t2 = t1 + MAX_RETRY;
        assert!(w.due(t2));
        w.record(replace_file(&target, b"receipts").is_ok(), t2);
        assert!(!w.dirty() && w.healthy());
        assert_eq!(std::fs::read(&target).unwrap(), b"receipts");
    }

    #[test]
    fn packages_sharing_a_four_byte_prefix_get_separate_files() {
        let base = dir("pkg");
        let (mut a, mut b) = ([0xabu8; 32], [0xabu8; 32]);
        a[31] = 1;
        b[31] = 2;
        let (pa, pb) = (
            base.join(package_suffix("equivocation", &a)),
            base.join(package_suffix("equivocation", &b)),
        );
        assert_ne!(pa, pb);
        assert!(write_package(&pa, b"package a").unwrap());
        assert!(write_package(&pb, b"package b").unwrap());
        assert!(!write_package(&pa, b"package a").unwrap());
        assert_eq!(std::fs::read(&pa).unwrap(), b"package a");
        assert_eq!(std::fs::read(&pb).unwrap(), b"package b");
        std::fs::write(&pa, b"damaged").unwrap();
        assert!(write_package(&pa, b"package a").unwrap());
        assert_eq!(std::fs::read(&pa).unwrap(), b"package a");
    }
}
