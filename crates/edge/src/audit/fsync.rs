//! Directory durability: after creating or renaming a file, the directory entry itself must
//! reach stable storage, or a crash can lose the rename even though the file data was synced.
use std::fs::File;
use std::io;
use std::path::Path;

/// Flush the directory that contains `path` (the current directory for a bare file name).
pub(crate) fn sync_parent_dir(path: &Path) -> io::Result<()> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    open_dir(dir.unwrap_or(Path::new(".")))?.sync_all()
}

#[cfg(unix)]
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
    use super::sync_parent_dir;

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
    fn bare_file_name_syncs_the_current_directory() {
        sync_parent_dir(std::path::Path::new("state")).unwrap();
    }
}
