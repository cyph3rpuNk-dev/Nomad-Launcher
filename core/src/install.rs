//! Atomic browser install: stage → swap → backup.
//!
//! Extraction goes into a `.stage` sibling of `install_dir`. Once the stage
//! is fully verified and prepared, a pair of renames moves the old install to
//! `.backup` and the stage to `install_dir`. A crash at any point before the
//! swap leaves `install_dir` intact; a crash between the two renames is
//! detected and recovered by [`recover_staging`] on the next run.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::browsers::{BrowserError, Result};

// ── Path helpers ──────────────────────────────────────────────────────────────

fn sibling(install_dir: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = install_dir
        .file_name()
        .unwrap_or(install_dir.as_os_str())
        .to_owned();
    name.push(suffix);
    install_dir.with_file_name(name)
}

/// Returns the staging directory path (`<install_dir>.stage`).
#[must_use]
pub fn stage_dir(install_dir: &Path) -> PathBuf {
    sibling(install_dir, ".stage")
}

/// Returns the backup directory path (`<install_dir>.backup`).
#[must_use]
pub fn backup_dir(install_dir: &Path) -> PathBuf {
    sibling(install_dir, ".backup")
}

// ── Instance serialization ────────────────────────────────────────────────────

/// Held for the entire recovery/update/launch attempt, including prompts and
/// fallback launch. The OS releases the lock when this handle closes, even if
/// the process crashes. Never unlink the file: competing handles must continue
/// to refer to the same file. Different configured install names in one portable
/// folder deliberately share the same lock.
pub(crate) struct InstanceLock {
    _file: std::fs::File,
    launcher_dir: PathBuf,
}

impl InstanceLock {
    pub(crate) fn acquire(install_dir: &Path) -> Result<Self> {
        let parent = install_dir
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        validate_update_paths(install_dir)?;
        crate::fs_safety::ensure_directory(parent)?;
        let launcher_dir = parent.canonicalize()?;
        let state_dir = crate::config::nomad_subdir(&launcher_dir);
        std::fs::create_dir_all(&state_dir)?;
        let mut options = std::fs::File::options();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Permit competing opens/locks but prohibit unlinking or renaming
            // this lock file while any attempt has it open.
            options.share_mode(
                windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
            );
        }
        let lock_path = state_dir.join("install.lock");
        crate::fs_safety::ensure_file(&lock_path)?;
        let file = options.open(&lock_path)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file, launcher_dir }),
            Err(std::fs::TryLockError::WouldBlock) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Another Nomad launcher is preparing this portable folder. Wait for it to finish, then retry.",
            ).into()),
            Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }

    pub(crate) fn check_install_dir(&self, install_dir: &Path) -> Result<()> {
        let parent = install_dir
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        validate_update_paths(install_dir)?;
        crate::fs_safety::ensure_directory(parent)?;
        if parent.canonicalize()? != self.launcher_dir {
            return Err(BrowserError::Ownership(
                "install transaction belongs to another portable folder".into(),
            ));
        }
        Ok(())
    }
}

fn validate_update_paths(install_dir: &Path) -> Result<()> {
    let valid_name = install_dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(crate::config::valid_install_dir_name);
    if !valid_name {
        return Err(BrowserError::Ownership(
            "installation must use one non-reserved Windows-safe folder name".into(),
        ));
    }
    for path in [
        install_dir.to_path_buf(),
        stage_dir(install_dir),
        backup_dir(install_dir),
    ] {
        crate::fs_safety::ensure_directory(&path)?;
    }
    let parent = install_dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    crate::fs_safety::ensure_directory(crate::config::nomad_subdir(parent))?;
    crate::fs_safety::ensure_directory(parent.join("Data"))?;
    Ok(())
}

// ── Startup recovery ──────────────────────────────────────────────────────────

/// Recovers from a previously interrupted install and removes leftover staging
/// directories.
///
/// Acquires the instance lock for standalone callers. Pipeline callers keep
/// one lock across recovery, staging, swap and launch. Call before the update
/// check only when updates are enabled; protocol launches skip recovery.
///
/// # Errors
/// Returns an error if locking, restoration, or stale-directory cleanup fails.
/// A failed restore preserves both stage and backup and stops dependent work.
///
/// Handles three cases:
/// - **Mid-swap crash**: `install_dir` was renamed to backup before stage was
///   moved into place. Restores backup so the browser remains launchable.
/// - **Stale stage**: a crash during extraction left `.stage` on disk. Removes
///   it so the next run starts clean.
/// - **Orphaned backup**: swap completed but backup deletion failed. Removes it.
pub fn recover_staging(install_dir: &Path) -> Result<()> {
    let lock = InstanceLock::acquire(install_dir)?;
    recover_staging_locked(install_dir, &lock)
}

pub(crate) fn recover_staging_locked(install_dir: &Path, lock: &InstanceLock) -> Result<()> {
    lock.check_install_dir(install_dir)?;
    let stage = stage_dir(install_dir);
    let backup = backup_dir(install_dir);

    if !install_dir.try_exists()? && backup.try_exists()? {
        tracing::warn!(?backup, "install directory missing; restoring from backup");
        // If restoration fails, leave both backup and stage untouched and
        // abort the attempt. Neither is safe to discard in this state.
        std::fs::rename(&backup, install_dir)?;
        tracing::info!("install directory restored from backup");
    }

    if stage.try_exists()? {
        std::fs::remove_dir_all(&stage)?;
        tracing::debug!(?stage, "removed stale stage directory");
    }

    if backup.try_exists()? && install_dir.try_exists()? {
        std::fs::remove_dir_all(&backup)?;
        tracing::debug!(?backup, "removed stale backup directory");
    }
    Ok(())
}

// ── Atomic swap ───────────────────────────────────────────────────────────────

/// Moves `stage` into place as `install_dir` via a rename-based atomic swap.
///
/// Steps:
/// 1. Refuse an unrecovered `backup`; recovery must complete before staging.
/// 2. Rename `install_dir` → `backup` (skipped on a fresh install where
///    `install_dir` does not yet exist).
/// 3. Rename `stage` → `install_dir`. On failure, attempt to restore `backup`.
/// 4. Remove `backup` (best-effort; orphaned backups are cleaned on next run
///    by [`recover_staging`]).
///
/// Both renames operate on siblings of the same parent directory and are
/// therefore guaranteed to stay on the same filesystem volume, making each
/// rename a single metadata operation on Windows.
///
/// # Errors
/// Returns [`BrowserError::Ownership`] for foreign stage/backup paths.
/// Returns [`BrowserError::Io`] if locking or the critical
/// renames fail, or an unrecovered backup exists. If step 3 fails
/// and the rollback rename also fails, the error is logged at `error` level and
/// the step-3 error is returned.
pub fn atomic_swap(install_dir: &Path, stage: &Path, backup: &Path) -> Result<()> {
    let lock = InstanceLock::acquire(install_dir)?;
    atomic_swap_locked(install_dir, stage, backup, &lock)
}

pub(crate) fn atomic_swap_locked(
    install_dir: &Path,
    stage: &Path,
    backup: &Path,
    lock: &InstanceLock,
) -> Result<()> {
    lock.check_install_dir(install_dir)?;
    if stage != stage_dir(install_dir) || backup != backup_dir(install_dir) {
        return Err(BrowserError::Ownership(
            "stage and backup must be owned install siblings".into(),
        ));
    }
    // Never erase the only surviving working installation. Even when an
    // active install exists, stale backups are recovery's responsibility.
    if backup.try_exists()? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "Unrecovered install backup exists; finish recovery before replacing the browser.",
        )
        .into());
    }

    if install_dir.try_exists()? {
        std::fs::rename(install_dir, backup)?;
    }

    if let Err(e) = std::fs::rename(stage, install_dir) {
        if backup.exists() {
            match std::fs::rename(backup, install_dir) {
                Ok(()) => tracing::warn!("install swap failed; rolled back to previous install"),
                Err(re) => tracing::error!(
                    error = %re,
                    "swap failed AND rollback failed — install directory may be missing"
                ),
            }
        }
        return Err(BrowserError::Io(e));
    }

    if backup.exists() {
        if let Err(e) = std::fs::remove_dir_all(backup) {
            tracing::warn!(
                error = %e,
                ?backup,
                "could not remove install backup; will be cleaned on next run"
            );
        }
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_roots_reject_junctions_before_mutating_other_folders() {
        for name in ["Nomad", "Browser", "Browser.stage", "Browser.backup"] {
            let temp = tempfile::tempdir().unwrap();
            let base = temp.path().join("instance");
            let foreign = temp.path().join("foreign");
            std::fs::create_dir_all(&base).unwrap();
            std::fs::create_dir_all(&foreign).unwrap();
            std::fs::write(foreign.join("sentinel"), b"keep").unwrap();
            let link = base.join(name);
            crate::tests::owned_directory_link(&temp, &link, &foreign);
            let result = recover_staging(&base.join("Browser"));
            assert!(result.is_err(), "{name} link must fail before recovery");
            assert_eq!(std::fs::read(foreign.join("sentinel")).unwrap(), b"keep");
            assert_eq!(std::fs::read_dir(&foreign).unwrap().count(), 1);
            assert!(
                link.exists(),
                "invalid links must not be automatically removed or moved"
            );
        }
    }

    #[test]
    fn linked_launcher_parent_is_rejected_before_canonicalization_and_state_creation() {
        let fixture = tempfile::tempdir().unwrap();
        let foreign = fixture.path().join("foreign");
        std::fs::create_dir_all(&foreign).unwrap();
        let base = fixture.path().join("instance");
        crate::tests::owned_directory_link(&fixture, &base, &foreign);
        assert!(InstanceLock::acquire(&base.join("Browser")).is_err());
        assert_eq!(std::fs::read_dir(&foreign).unwrap().count(), 0);
    }

    #[test]
    fn headless_install_names_cannot_replace_reserved_state_or_use_parent_components() {
        let fixture = tempfile::tempdir().unwrap();
        for name in ["Data", "Nomad", "NUL", "Browser."] {
            assert!(InstanceLock::acquire(&fixture.path().join(name)).is_err());
        }
        assert!(InstanceLock::acquire(&fixture.path().join("../Browser")).is_err());
        assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 0);
        let trailing = fixture.path().join("Browser").join("");
        assert_eq!(stage_dir(&trailing), fixture.path().join("Browser.stage"));
    }

    fn assert_busy(result: &Result<InstanceLock>) {
        assert!(matches!(result, Err(BrowserError::Io(ref e))
            if e.kind() == std::io::ErrorKind::WouldBlock));
    }

    #[test]
    fn instance_lock_serializes_install_names_and_releases_on_drop() {
        let first = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let install = first.path().join("Browser");
        let lock = InstanceLock::acquire(&install).unwrap();
        assert_busy(&InstanceLock::acquire(&install));
        assert_busy(&InstanceLock::acquire(&first.path().join("App")));
        let independent = InstanceLock::acquire(&other.path().join("Browser")).unwrap();
        drop(independent);
        drop(lock);
        assert!(first.path().join("Nomad/install.lock").is_file());
        let _next = InstanceLock::acquire(&install).unwrap();
    }

    #[test]
    fn lock_probe_child() {
        let Some(root) = std::env::var_os("NOMAD_LOCK_TEST_ROOT") else {
            return;
        };
        let root = PathBuf::from(root).canonicalize().unwrap();
        assert_eq!(
            root.parent().unwrap(),
            std::env::temp_dir().canonicalize().unwrap()
        );
        assert!(root
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("nomad-lock-test-"));
        let result = InstanceLock::acquire(&root.join("Browser"));
        if std::env::var_os("NOMAD_LOCK_TEST_EXIT").is_some() {
            let _lock = result.unwrap();
            // Deliberately bypass Rust destructors, simulating abrupt process
            // termination. This is the test harness, never a browser/installer.
            std::process::exit(0);
        }
        assert_busy(&result);
    }

    fn probe_lock(root: &Path, abrupt_exit: bool) {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "install::tests::lock_probe_child", "--nocapture"])
            .env("NOMAD_LOCK_TEST_ROOT", root);
        if abrupt_exit {
            command.env("NOMAD_LOCK_TEST_EXIT", "1");
        } else {
            command.env_remove("NOMAD_LOCK_TEST_EXIT");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "child test failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn instance_lock_blocks_another_process_and_survives_abrupt_exit() {
        let tmp = tempfile::Builder::new()
            .prefix("nomad-lock-test-")
            .tempdir()
            .unwrap();
        let install = tmp.path().join("Browser");
        let lock = InstanceLock::acquire(&install).unwrap();
        probe_lock(tmp.path(), false);
        drop(lock);
        probe_lock(tmp.path(), true);
        let _after_exit = InstanceLock::acquire(&install).unwrap();
    }

    #[test]
    fn lock_from_another_folder_cannot_recover_or_swap() {
        let first = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let lock = InstanceLock::acquire(&first.path().join("Browser")).unwrap();
        let install = other.path().join("Browser");
        let stage = stage_dir(&install);
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("partial"), b"untouched").unwrap();
        assert!(matches!(
            recover_staging_locked(&install, &lock),
            Err(BrowserError::Ownership(_))
        ));
        assert!(matches!(
            atomic_swap_locked(&install, &stage, &backup_dir(&install), &lock),
            Err(BrowserError::Ownership(_))
        ));
        assert_eq!(std::fs::read(stage.join("partial")).unwrap(), b"untouched");
    }

    #[test]
    fn standalone_recovery_and_swap_cannot_disturb_a_locked_transaction() {
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().join("Browser");
        let stage = stage_dir(&install);
        let backup = backup_dir(&install);
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&backup).unwrap();
        std::fs::write(stage.join("partial"), b"active stage").unwrap();
        std::fs::write(backup.join("browser.exe"), b"working copy").unwrap();
        let _lock = InstanceLock::acquire(&install).unwrap();
        for result in [
            recover_staging(&install),
            atomic_swap(&install, &stage, &backup),
        ] {
            assert!(matches!(result, Err(BrowserError::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock));
        }
        assert_eq!(
            std::fs::read(stage.join("partial")).unwrap(),
            b"active stage"
        );
        assert_eq!(
            std::fs::read(backup.join("browser.exe")).unwrap(),
            b"working copy"
        );
        assert!(!install.exists());
    }

    #[test]
    fn atomic_swap_rolls_back_when_the_stage_rename_fails() {
        // Step 3 (stage → install_dir) fails here because the stage was never
        // created. The previous install must be renamed back from .backup so
        // the browser stays launchable — not left stranded under the backup
        // name.
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        let stage = stage_dir(&install);
        let backup = backup_dir(&install);
        std::fs::create_dir_all(&install).unwrap();
        std::fs::write(install.join("browser.exe"), b"old install").unwrap();

        let err = atomic_swap(&install, &stage, &backup)
            .expect_err("a missing stage directory must fail the swap");
        assert!(matches!(err, BrowserError::Io(_)), "got {err:?}");

        assert_eq!(
            std::fs::read(install.join("browser.exe")).unwrap(),
            b"old install",
            "the previous install must be rolled back into place"
        );
        assert!(
            !backup.exists(),
            "the rollback rename must consume the backup directory"
        );
    }

    #[test]
    fn atomic_swap_refuses_to_delete_an_unrecovered_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().join("Browser");
        let stage = stage_dir(&install);
        let backup = backup_dir(&install);
        std::fs::create_dir_all(&backup).unwrap();
        std::fs::write(backup.join("browser.exe"), b"only working copy").unwrap();
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("browser.exe"), b"new copy").unwrap();

        assert!(atomic_swap(&install, &stage, &backup).is_err());
        assert_eq!(
            std::fs::read(backup.join("browser.exe")).unwrap(),
            b"only working copy"
        );
        assert_eq!(
            std::fs::read(stage.join("browser.exe")).unwrap(),
            b"new copy"
        );
        assert!(!install.exists());
    }

    #[cfg(windows)]
    #[test]
    fn failed_backup_restoration_preserves_stage_and_backup() {
        use std::os::windows::fs::OpenOptionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().join("Browser");
        let backup = backup_dir(&install);
        let stage = stage_dir(&install);
        std::fs::create_dir_all(&backup).unwrap();
        std::fs::write(backup.join("browser.exe"), b"working copy").unwrap();
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("partial.exe"), b"partial download").unwrap();
        // Deny rename/delete access to this fixture directory. No host paths
        // or browser executables are opened or run.
        let blocked = std::fs::File::options()
            .read(true)
            .share_mode(0)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
            .open(&backup)
            .unwrap();
        let result = recover_staging(&install);
        assert!(result.is_err(), "failed restoration must stop recovery");
        assert!(
            stage.exists(),
            "failed restoration must not delete the stage"
        );
        drop(blocked);
        assert_eq!(
            std::fs::read(backup.join("browser.exe")).unwrap(),
            b"working copy"
        );
        assert!(!install.exists());
        // Releasing the interfering handle permits a safe retry.
        recover_staging(&install).unwrap();
        assert_eq!(
            std::fs::read(install.join("browser.exe")).unwrap(),
            b"working copy"
        );
        assert!(!stage.exists());
        assert!(!backup.exists());
    }

    #[test]
    fn stage_and_backup_are_siblings_of_install_dir() {
        let install = Path::new("C:/portable/Browser");
        assert_eq!(stage_dir(install), Path::new("C:/portable/Browser.stage"));
        assert_eq!(backup_dir(install), Path::new("C:/portable/Browser.backup"));
    }

    #[test]
    fn atomic_swap_fresh_install() {
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().join("Browser");
        let stage = stage_dir(&install);
        let backup = backup_dir(&install);

        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("chrome.exe"), b"NEW").unwrap();

        atomic_swap(&install, &stage, &backup).expect("fresh install swap must succeed");

        assert_eq!(std::fs::read(install.join("chrome.exe")).unwrap(), b"NEW");
        assert!(!stage.exists(), "stage must be gone after swap");
        assert!(!backup.exists(), "no backup for a fresh install");
    }

    #[test]
    fn atomic_swap_replaces_existing_install() {
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().join("Browser");
        let stage = stage_dir(&install);
        let backup = backup_dir(&install);

        std::fs::create_dir_all(&install).unwrap();
        std::fs::write(install.join("chrome.exe"), b"OLD").unwrap();

        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("chrome.exe"), b"NEW").unwrap();

        atomic_swap(&install, &stage, &backup).expect("update swap must succeed");

        assert_eq!(std::fs::read(install.join("chrome.exe")).unwrap(), b"NEW");
        assert!(!stage.exists());
        assert!(
            !backup.exists(),
            "backup must be cleaned up after successful swap"
        );
    }

    #[test]
    fn recover_staging_removes_stale_stage() {
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().join("Browser");
        let stage = stage_dir(&install);

        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("partial.exe"), b"PARTIAL").unwrap();

        recover_staging(&install).unwrap();

        assert!(!stage.exists(), "stale stage must be removed");
        assert!(install.exists(), "install must be untouched");
    }

    #[test]
    fn recover_staging_restores_install_from_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().join("Browser");
        let backup = backup_dir(&install);

        std::fs::create_dir_all(&backup).unwrap();
        std::fs::write(backup.join("chrome.exe"), b"PREV").unwrap();

        recover_staging(&install).unwrap();

        assert!(install.exists(), "install must be restored from backup");
        assert_eq!(std::fs::read(install.join("chrome.exe")).unwrap(), b"PREV");
        assert!(!backup.exists(), "backup is now install_dir");
    }

    #[test]
    fn recover_staging_removes_orphaned_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().join("Browser");
        let backup = backup_dir(&install);

        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(&backup).unwrap();

        recover_staging(&install).unwrap();

        assert!(!backup.exists(), "orphaned backup must be removed");
        assert!(install.exists());
    }
}
