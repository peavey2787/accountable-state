//! Directory durability: after creating or renaming a file, the directory entry itself must
//! reach stable storage, or a crash can lose the rename even though the file data was synced.
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// Replace `path` with `data` atomically and durably: a crash leaves the old or the new file.
pub fn replace_file(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".pending");
    let tmp = std::path::PathBuf::from(tmp);
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    sync_parent_dir(path)
}

/// Flush the directory that contains `path` (the current directory for a bare file name).
pub fn sync_parent_dir(path: &Path) -> io::Result<()> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    open_dir(dir.unwrap_or(Path::new(".")))?.sync_all()
}

/// Everywhere else (Unix, and targets without a filesystem such as browser WASM, where this
/// fails cleanly at run time) a plain open is enough.
#[cfg(not(windows))]
fn open_dir(dir: &Path) -> io::Result<File> {
    File::open(dir)
}

/// Windows opens a directory only with `FILE_FLAG_BACKUP_SEMANTICS`, and `FlushFileBuffers`
/// (`sync_all`) needs write access to the handle.
#[cfg(windows)]
fn open_dir(dir: &Path) -> io::Result<File> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
}

#[cfg(test)]
mod tests {
    use super::{replace_file, sync_parent_dir};

    #[test]
    fn parent_directory_of_a_real_file_can_be_synced() {
        let dir = std::env::temp_dir().join(format!("gv-fsync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("state");
        std::fs::write(&file, b"x").unwrap();
        sync_parent_dir(&file).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn replacing_a_file_leaves_only_the_new_content() {
        let dir = std::env::temp_dir().join(format!("gv-replace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("archive");
        replace_file(&file, b"old").unwrap();
        replace_file(&file, b"new").unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"new");
        assert!(!dir.join("archive.pending").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bare_file_name_syncs_the_current_directory() {
        sync_parent_dir(std::path::Path::new("state")).unwrap();
    }
}
