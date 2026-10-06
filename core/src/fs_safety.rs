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

#[cfg(test)]
mod tests {
    use super::*;

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
