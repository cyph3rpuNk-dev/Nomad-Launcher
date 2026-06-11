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
    let mut s: OsString = install_dir.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
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

// ── Startup recovery ──────────────────────────────────────────────────────────

/// Recovers from a previously interrupted install and removes leftover staging
/// directories.
///
/// Call once per pipeline run before the update check. Handles three cases:
/// - **Mid-swap crash**: `install_dir` was renamed to backup before stage was
///   moved into place. Restores backup so the browser remains launchable.
/// - **Stale stage**: a crash during extraction left `.stage` on disk. Removes
///   it so the next run starts clean.
/// - **Orphaned backup**: swap completed but backup deletion failed. Removes it.
pub fn recover_staging(install_dir: &Path) {
    let stage = stage_dir(install_dir);
    let backup = backup_dir(install_dir);

    if !install_dir.exists() && backup.exists() {
        tracing::warn!(
            ?backup,
            "install directory missing with backup present; restoring from backup"
        );
        match std::fs::rename(&backup, install_dir) {
            Ok(()) => tracing::info!("install directory restored from backup"),
            Err(e) => tracing::error!(error = %e, "could not restore install backup"),
        }
    }

    if stage.exists() {
        match std::fs::remove_dir_all(&stage) {
            Ok(()) => tracing::debug!(?stage, "removed stale stage directory"),
            Err(e) => tracing::warn!(?stage, error = %e, "could not remove stale stage directory"),
        }
    }

    if backup.exists() && install_dir.exists() {
        match std::fs::remove_dir_all(&backup) {
            Ok(()) => tracing::debug!(?backup, "removed stale backup directory"),
            Err(e) => {
                tracing::warn!(?backup, error = %e, "could not remove stale backup directory");
            }
        }
    }
}

// ── Atomic swap ───────────────────────────────────────────────────────────────

/// Moves `stage` into place as `install_dir` via a rename-based atomic swap.
///
/// Steps:
/// 1. Remove any leftover `backup` from a previous run.
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
/// Returns [`BrowserError::Io`] if the critical renames fail. If step 3 fails
/// and the rollback rename also fails, the error is logged at `error` level and
/// the step-3 error is returned.
pub fn atomic_swap(install_dir: &Path, stage: &Path, backup: &Path) -> Result<()> {
    if backup.exists() {
        std::fs::remove_dir_all(backup)?;
    }

    if install_dir.exists() {
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

        recover_staging(&install);

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

        recover_staging(&install);

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

        recover_staging(&install);

        assert!(!backup.exists(), "orphaned backup must be removed");
        assert!(install.exists());
    }
}
