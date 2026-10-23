//! The durable open counter behind reconnection fencing: every open of the same storage gets a
//! larger number, so a restarted process always outranks the one it replaces.
use crate::config::DurableStorage;
use crate::io::OpenError;
use gv_edge::audit::fsync::replace_file;

const SUFFIX: &str = ".incarnation";

/// Read, increment and durably store the counter. A missing file starts at 1; a corrupt one is
/// an error (guessing could let an old process outrank a new one).
pub(crate) fn next(storage: &DurableStorage) -> Result<u64, OpenError> {
    let path = storage.file(SUFFIX);
    let fail = |e: String| OpenError::Storage {
        file: path.display().to_string(),
        error: e,
    };
    let previous = match std::fs::read(&path) {
        Ok(b) => <[u8; 8]>::try_from(b.as_slice())
            .map(u64::from_le_bytes)
            .map_err(|_| fail("corrupt incarnation counter".into()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(fail(e.to_string())),
    };
    let next = previous
        .checked_add(1)
        .ok_or_else(|| fail("incarnation counter exhausted".into()))?;
    replace_file(&path, &next.to_le_bytes()).map_err(|e| fail(e.to_string()))?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_open_gets_a_larger_number_and_corruption_is_refused() {
        let dir = std::env::temp_dir().join(format!("gv-inc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = DurableStorage::at(dir.join("node"));
        assert_eq!(next(&s).unwrap(), 1);
        assert_eq!(next(&s).unwrap(), 2);
        std::fs::write(s.file(SUFFIX), b"xx").unwrap();
        assert!(next(&s).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
