//! Filesystem checks before portable-state reads, writes and cleanup.
//! Reject existing symlinks/reparse points before canonicalization can hide
//! them. These metadata checks do not protect against a concurrent hostile
//! writer replacing paths; drive write access remains outside the threat model.

use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy)]
enum Kind {
    Directory,
    File,
}

pub(crate) fn ensure_directory(path: impl AsRef<Path>) -> io::Result<()> {
    ensure(path.as_ref(), Kind::Directory)
}

pub(crate) fn ensure_file(path: impl AsRef<Path>) -> io::Result<()> {
    ensure(path.as_ref(), Kind::File)
}

fn unsafe_path(path: &Path, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("unsafe filesystem path `{}`: {reason}", path.display()),
    )
}

fn ensure(path: &Path, kind: Kind) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(unsafe_path(path, "an empty path is not allowed"));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    if !absolute.is_absolute()
        || absolute
            .components()
            .any(|p| matches!(p, Component::ParentDir))
    {
        return Err(unsafe_path(
            path,
            "relative drive or parent-directory components are not allowed",
        ));
    }
    let mut current = PathBuf::new();
    let mut components = absolute.components().peekable();
    while let Some(component) = components.next() {
        if matches!(component, Component::CurDir) {
            continue;
        }
        current.push(component.as_os_str());
        // A Windows drive prefix alone is drive-relative; inspect it only once
        // the following root component has made a complete absolute path.
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        if is_link(&metadata) {
            return Err(unsafe_path(
                &current,
                "symlinks and reparse points are not allowed",
            ));
        }
        if components.peek().is_some() || matches!(kind, Kind::Directory) {
            if !metadata.is_dir() {
                return Err(unsafe_path(&current, "expected an ordinary directory"));
            }
        } else if !metadata.is_file() {
            return Err(unsafe_path(&current, "expected an ordinary file"));
        }
    }
    Ok(())
}

fn is_link(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

pub(crate) fn create_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
    ensure_directory(&path)?;
    std::fs::create_dir_all(path)
}

pub(crate) fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    ensure_file(&path)?;
    std::fs::write(path, contents)
}

/// Validate the whole source tree before copying or promoting any entries.
/// Iterative traversal never follows directory links or loops through them.
pub(crate) fn ensure_tree(root: &Path) -> io::Result<()> {
    ensure_directory(root)?;
    if !root.try_exists()? {
        return Ok(());
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        ensure_directory(&directory)?;
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if is_link(&metadata) {
                return Err(unsafe_path(&path, "linked tree entries are not allowed"));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if !metadata.is_file() {
                return Err(unsafe_path(&path, "unsupported tree entry type"));
            }
        }
    }
    Ok(())
}

/// Create a new file without overwriting a prior writer's data.
/// Cleanup is restricted to the file successfully created by this call.
pub(crate) fn write_new(path: &Path, contents: &[u8]) -> io::Result<()> {
    ensure_file(path)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let result = file.write_all(contents).and_then(|()| file.sync_all());
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

/// A private sibling directory containing a replacement file and, on Windows,
/// any rollback file produced by `ReplaceFileW`. Only this call creates/cleans it.
pub(crate) struct StagedFile {
    destination: PathBuf,
    directory: PathBuf,
    retain: bool,
}

impl StagedFile {
    pub(crate) fn new(destination: &Path) -> io::Result<Self> {
        use std::hash::{BuildHasher, RandomState};
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        ensure_file(destination)?;
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        create_dir_all(parent)?;
        let token = RandomState::new()
            .hash_one((std::process::id(), SEQUENCE.fetch_add(1, Ordering::Relaxed)));
        let directory = parent.join(format!(".nomad-file-{token:016x}"));
        std::fs::create_dir(&directory)?;
        Ok(Self {
            destination: destination.to_owned(),
            directory,
            retain: false,
        })
    }

    pub(crate) fn path(&self) -> PathBuf {
        self.directory.join("replacement")
    }

    pub(crate) fn commit(&mut self) -> io::Result<()> {
        let replacement = self.path();
        ensure_file(&replacement)?;
        ensure_file(&self.destination)?;
        let metadata = match std::fs::metadata(&self.destination) {
            Ok(metadata) => Some(metadata),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        if metadata
            .as_ref()
            .is_some_and(|m| m.permissions().readonly())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing to replace a read-only settings file",
            ));
        }
        #[cfg(not(windows))]
        if let Some(metadata) = &metadata {
            std::fs::set_permissions(&replacement, metadata.permissions())?;
        }
        #[cfg(windows)]
        if metadata.is_some() {
            return self.commit_existing_with(&replacement, replace_existing_file);
        }
        std::fs::rename(&replacement, &self.destination)
    }
    #[cfg(windows)]
    fn commit_existing_with(
        &mut self,
        replacement: &Path,
        replace_fn: impl FnOnce(&Path, &Path, &Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let backup = self.directory.join("previous");
        // Preserve the private directory until the native outcome and
        // rollback state are known, including unreadable backup metadata.
        self.retain = true;
        if let Err(error) = replace_fn(&self.destination, replacement, &backup) {
            // Windows documents failures that can leave the original at
            // the backup name. Restore it rather than delete its directory.
            if backup.try_exists()? {
                if let Err(rollback) = std::fs::rename(&backup, &self.destination) {
                    self.retain = true;
                    return Err(io::Error::new(error.kind(), format!(
                        "replacement failed ({error}); rollback failed ({rollback}); original retained at {}", backup.display())));
                }
            }
            self.retain = false;
            return Err(error);
        }
        self.retain = false;
        Ok(())
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if !self.retain {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
}

/// Write and flush privately, then promote without truncating the active file.
pub(crate) fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut staged = StagedFile::new(path)?;
    write_new(&staged.path(), contents)?;
    staged.commit()
}

#[cfg(windows)]
fn replace_existing_file(destination: &Path, replacement: &Path, backup: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let absolute = parent.canonicalize()?.join(path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "replacement requires a filename",
            )
        })?);
        let mut encoded: Vec<_> = absolute.as_os_str().encode_wide().collect();
        if encoded.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NUL in replacement path",
            ));
        }
        encoded.push(0);
        Ok(encoded)
    }
    let destination = wide(destination)?;
    let replacement = wide(replacement)?;
    let backup = wide(backup)?;
    // SAFETY: all strings are checked, NUL-terminated UTF-16 and remain alive
    // for the call. Optional reserved pointers are null. Flags=0 preserves
    // destination metadata/ACLs rather than ignoring merge failures.
    let succeeded = unsafe {
        windows_sys::Win32::Storage::FileSystem::ReplaceFileW(
            destination.as_ptr(),
            replacement.as_ptr(),
            backup.as_ptr(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if succeeded == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_file_replacement_writes_complete_files_and_cleans_owned_stages() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("settings");
        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
        let staged = StagedFile::new(&path).unwrap();
        write_new(&staged.path(), b"uncommitted").unwrap();
        drop(staged);
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn partial_native_replacement_failure_restores_or_retains_the_original() {
        for fail_rollback in [false, true] {
            let fixture = tempfile::tempdir().unwrap();
            let path = fixture.path().join("settings");
            write(&path, b"original").unwrap();
            let mut staged = StagedFile::new(&path).unwrap();
            write_new(&staged.path(), b"replacement").unwrap();
            let backup = staged.directory.join("previous");
            let result = staged.commit_existing_with(&staged.path(), |destination, _, previous| {
                // Model the documented native failure that already moved the
                // original to the owned backup. No Windows API/host state used.
                std::fs::rename(destination, previous)?;
                if fail_rollback {
                    std::fs::create_dir(destination)?;
                }
                Err(io::Error::other("injected partial native failure"))
            });
            assert!(result.is_err());
            drop(staged);
            if fail_rollback {
                assert_eq!(std::fs::read(&backup).unwrap(), b"original");
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("original retained"));
            } else {
                assert_eq!(std::fs::read(&path).unwrap(), b"original");
                assert!(!backup.exists());
                assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
            }
        }
    }

    #[test]
    fn readonly_settings_are_preserved_without_leaking_a_stage() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("settings");
        write(&path, b"keep").unwrap();
        let original_permissions = std::fs::metadata(&path).unwrap().permissions();
        let mut readonly = original_permissions.clone();
        readonly.set_readonly(true);
        std::fs::set_permissions(&path, readonly).unwrap();
        let result = atomic_write(&path, b"replacement");
        std::fs::set_permissions(&path, original_permissions).unwrap();
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
    }

    #[test]
    fn guards_allow_missing_owned_paths_and_reject_wrong_types_and_parent_components() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("file");
        ensure_file(&file).unwrap();
        write(&file, b"owned").unwrap();
        assert!(ensure_directory(&file).is_err());
        assert!(ensure_file(temp.path()).is_err());
        assert!(ensure_file(temp.path().join("../other")).is_err());
        assert!(ensure_file(Path::new("")).is_err());
        let nested = temp.path().join("missing/nested");
        create_dir_all(&nested).unwrap();
        write(nested.join("file"), b"new").unwrap();
        ensure_tree(temp.path()).unwrap();
    }

    #[test]
    fn new_writes_never_overwrite_or_remove_a_preexisting_file() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("file");
        write_new(&file, b"first").unwrap();
        assert_eq!(
            write_new(&file, b"replacement").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"first");
    }

    #[test]
    fn ancestor_and_nested_tree_links_are_rejected_without_touching_targets() {
        let temp = tempfile::tempdir().unwrap();
        let foreign = temp.path().join("foreign");
        let owned = temp.path().join("owned");
        create_dir_all(&foreign).unwrap();
        create_dir_all(&owned).unwrap();
        write(foreign.join("sentinel"), b"keep").unwrap();
        let link = owned.join("linked");
        crate::tests::owned_directory_link(&temp, &link, &foreign);
        assert!(ensure_file(link.join("sentinel")).is_err());
        assert!(create_dir_all(link.join("new")).is_err());
        assert!(write(link.join("sentinel"), b"replacement").is_err());
        assert!(ensure_tree(&owned).is_err());
        assert_eq!(std::fs::read(foreign.join("sentinel")).unwrap(), b"keep");
        assert_eq!(std::fs::read_dir(&foreign).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn file_and_dangling_symlinks_are_rejected_before_write() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        write(&target, b"keep").unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write(&link, b"replacement").is_err());
        let missing = temp.path().join("missing");
        let dangling = temp.path().join("dangling");
        std::os::unix::fs::symlink(&missing, &dangling).unwrap();
        assert!(write(&dangling, b"new").is_err());
        assert!(!missing.exists());
        assert_eq!(std::fs::read(target).unwrap(), b"keep");
    }
}
