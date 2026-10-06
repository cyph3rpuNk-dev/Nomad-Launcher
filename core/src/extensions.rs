//! Chromium uBO extension staging from gorhill's release archives.
//!
//! Downloads gorhill's `uBlock0_X.X.X.chromium.zip` (GPG-authenticated via
//! the release tag's signature), extracts it under a Nomad-managed subdir of
//! the install directory, and exposes the resulting path so the launcher
//! can append it to `--load-extension=` at launch.
//!
//! gorhill's `manifest.json` carries the `key` field that deterministically
//! derives the canonical CWS extension ID `cjpalhdlnbpafiamejdnhcphjbkeiagm`,
//! so the ID is stable regardless of staging path.
//!
//! Staging approach — `--load-extension=`. The `external_extensions.json`
//! mechanism was ruled out: its documented keys (`external_crx`,
//! `external_update_url`) require a CRX whose signing key derives to the
//! pinned ID, which gorhill does not publish. The `path` field referenced
//! in earlier drafts of this work is not a valid `external_extensions.json`
//! key in current Chromium. Self-packaging a CRX with a Nomad signing key
//! was explicitly ruled out (no private key in the codebase). That leaves
//! `--load-extension=` as the only architecturally sound option.
//!
//! Banner trade-off: extensions loaded via `--load-extension=` appear in
//! `chrome://extensions` while Developer mode is on. The ungoogled-chromium
//! `chrome://extensions` page shows a single mild yellow header noting this
//! (not the older per-launch "Disable developer mode extensions" `InfoBar`,
//! which Chromium removed). This is an acceptable trade for an extension
//! that actually loads.

use std::path::{Path, PathBuf};

use crate::browsers::{BrowserError, Result};

/// Subdirectory under `<install-dir>/` that holds Nomad-managed unpacked
/// extensions passed to `--load-extension=`. Lives inside the Browser/
/// install. The browser-update preserve-state hook carries the working copy
/// into the new bundle before swapping, including when the network is offline.
const NOMAD_EXTENSIONS_SUBDIR: &str = "nomad-extensions";

/// Subdirectory of `nomad-extensions/` where uBO is staged.
const UBO_SUBDIR: &str = "uBlock0";

/// Returns the absolute path of the staged uBO directory, or `None` when
/// staging has not happened yet (e.g. offline first run, GPG verification
/// failure, or after a browser update before `fetch_extension_updates` runs).
pub(crate) fn staged_ubo_dir(install_dir: &Path) -> Option<PathBuf> {
    let dir = install_dir.join(NOMAD_EXTENSIONS_SUBDIR).join(UBO_SUBDIR);
    let backup = dir.with_file_name("uBlock0.backup");
    [dir, backup]
        .into_iter()
        .find(|path| validate_extension(path).is_ok())
}

/// Extracts gorhill's `uBlock0_X.X.X.chromium.zip` into
/// `<install-dir>/nomad-extensions/uBlock0/`. On subsequent calls the
/// existing directory is fully replaced so stale files from an older
/// version cannot remain.
///
/// `_version` is accepted for API symmetry / future logging; the version is
/// recorded by the caller in `nomad-version-cache.toml`.
///
/// # Errors
/// Returns [`BrowserError::Extract`] on ZIP failures and [`BrowserError::Io`]
/// on filesystem failures.
pub(crate) fn stage_chromium_ubo_from_gorhill_zip(
    install_dir: &Path,
    zip_bytes: &[u8],
    _version: &str,
) -> Result<()> {
    let ext_dir = install_dir.join(NOMAD_EXTENSIONS_SUBDIR).join(UBO_SUBDIR);

    let _lock = lock_extension_root(install_dir)?;
    let stage = ext_dir.with_file_name("uBlock0.stage");
    let backup = ext_dir.with_file_name("uBlock0.backup");
    recover_extension(&ext_dir, &stage, &backup)?;
    std::fs::create_dir(&stage)?;
    let result = (|| {
        extract_zip_into(zip_bytes, &stage)?;
        validate_extension(&stage)?;
        swap_extension(&ext_dir, &stage, &backup)
    })();
    if result.is_err() && stage.exists() {
        let _ = std::fs::remove_dir_all(&stage);
    }
    result
}

fn lock_extension_root(install_dir: &Path) -> Result<std::fs::File> {
    let root = install_dir.join(NOMAD_EXTENSIONS_SUBDIR);
    crate::fs_safety::create_dir_all(&root)?;
    let path = root.join(".update.lock");
    crate::fs_safety::ensure_file(&path)?;
    let mut options = std::fs::File::options();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
        );
    }
    let file = options.open(path)?;
    file.try_lock().map_err(std::io::Error::from)?;
    Ok(file)
}

fn validate_extension(root: &Path) -> Result<()> {
    crate::fs_safety::ensure_tree(root)?;
    let path = root.join("manifest.json");
    crate::fs_safety::ensure_file(&path)?;
    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)
        .map_err(|e| BrowserError::Extract(format!("invalid extension manifest: {e}")))?;
    if !manifest.is_object()
        || manifest
            .get("version")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|version| version.trim().is_empty())
    {
        return Err(BrowserError::Extract(
            "extension manifest must contain a nonempty version".into(),
        ));
    }
    Ok(())
}

fn recover_extension(current: &Path, stage: &Path, backup: &Path) -> Result<()> {
    for path in [current, stage, backup] {
        crate::fs_safety::ensure_directory(path)?;
    }
    if backup.try_exists()? {
        crate::fs_safety::ensure_tree(backup)?;
        if current.try_exists()? {
            validate_extension(current)?;
            std::fs::remove_dir_all(backup)?;
        } else {
            validate_extension(backup)?;
            std::fs::rename(backup, current)?;
        }
    }
    if stage.try_exists()? {
        crate::fs_safety::ensure_tree(stage)?;
        std::fs::remove_dir_all(stage)?;
    }
    Ok(())
}

fn swap_extension(current: &Path, stage: &Path, backup: &Path) -> Result<()> {
    if backup.try_exists()? {
        return Err(BrowserError::Extract(
            "unrecovered extension backup exists".into(),
        ));
    }
    crate::fs_safety::ensure_tree(current)?;
    if current.try_exists()? {
        std::fs::rename(current, backup)?;
    }
    if let Err(error) = std::fs::rename(stage, current) {
        if backup.exists() {
            if let Err(rollback) = std::fs::rename(backup, current) {
                tracing::error!(error = %rollback, ?backup, "extension rollback failed; backup retained");
            }
        }
        return Err(error.into());
    }
    if backup.exists() {
        if let Err(error) = std::fs::remove_dir_all(backup) {
            tracing::warn!(error = %error, "extension backup retained for next recovery");
        }
    }
    Ok(())
}

/// Preserve an existing managed extension through a browser-bundle update so
/// a later offline extension check can still launch the last working copy.
pub(crate) fn preserve_chromium_ubo(current_install: &Path, staged_install: &Path) -> Result<()> {
    let root = current_install.join(NOMAD_EXTENSIONS_SUBDIR);
    crate::fs_safety::ensure_directory(&root)?;
    if !root.try_exists()? {
        return Ok(());
    }
    let _lock = lock_extension_root(current_install)?;
    let current = current_install
        .join(NOMAD_EXTENSIONS_SUBDIR)
        .join(UBO_SUBDIR);
    let backup = current.with_file_name("uBlock0.backup");
    let stage = current.with_file_name("uBlock0.stage");
    recover_extension(&current, &stage, &backup)?;
    if !current.try_exists()? {
        return Ok(());
    }
    validate_extension(&current)?;
    let target = staged_install
        .join(NOMAD_EXTENSIONS_SUBDIR)
        .join(UBO_SUBDIR);
    crate::fs_safety::ensure_tree(&target)?;
    if target.exists() {
        std::fs::remove_dir_all(&target)?;
    }
    let mut pending = vec![(current, target)];
    while let Some((source, destination)) = pending.pop() {
        crate::fs_safety::create_dir_all(&destination)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let source = entry.path();
            let destination = destination.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                pending.push((source, destination));
            } else {
                crate::fs_safety::ensure_file(&source)?;
                crate::fs_safety::ensure_file(&destination)?;
                std::fs::copy(source, destination)?;
            }
        }
    }
    Ok(())
}

/// Cumulative decompressed-size ceiling for extension zips. gorhill's uBO
/// chromium zip expands to a few tens of MiB; anything past this is a
/// decompression bomb, not an extension.
const MAX_EXTENSION_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

fn extract_zip_into(zip_bytes: &[u8], dest: &Path) -> Result<()> {
    extract_zip_into_with_budget(zip_bytes, dest, MAX_EXTENSION_DECOMPRESSED_BYTES)
}

fn extract_zip_into_with_budget(zip_bytes: &[u8], dest: &Path, budget: u64) -> Result<()> {
    let mut remaining = budget;
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| BrowserError::Extract(e.to_string()))?;

    // gorhill's uBlock0_X.X.X.chromium.zip wraps all files inside a single
    // top-level directory (e.g. `uBlock0.chromium/`). Detect that wrapper and
    // strip it so `manifest.json` lands directly under `dest/`. Falls back to
    // a flat extraction when no consistent prefix exists (e.g. test zips that
    // place files at the archive root).
    let top_prefix = detect_top_prefix(&mut archive)?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| BrowserError::Extract(e.to_string()))?;
        let raw_name = entry.name().replace('\\', "/");
        if raw_name.contains("..") || raw_name.starts_with('/') {
            continue;
        }
        let stripped = match top_prefix.as_deref() {
            Some(prefix) => raw_name.strip_prefix(prefix).unwrap_or(&raw_name),
            None => &raw_name,
        };
        if stripped.is_empty() {
            continue;
        }
        // Defense-in-depth: reject drive-absolute / traversal entries before the
        // join (shares extract::is_safe_zip_path so the guard cannot drift from
        // the other archive extractors).
        if !crate::extract::is_safe_zip_path(stripped) {
            continue;
        }
        let out = dest.join(stripped);
        if entry.is_dir() || stripped.ends_with('/') {
            crate::fs_safety::create_dir_all(&out)?;
        } else {
            if let Some(parent) = out.parent() {
                crate::fs_safety::create_dir_all(parent)?;
            }
            crate::fs_safety::ensure_file(&out)?;
            let mut out_file = std::fs::File::create(&out)?;
            crate::extract::copy_entry_capped(&mut entry, &mut out_file, &mut remaining)?;
        }
    }
    Ok(())
}

/// Returns the shared top-level directory (with trailing `/`) used by every
/// entry in the archive, or `None` when no such prefix exists (e.g. files at
/// the archive root). Used to strip gorhill's `uBlock0.chromium/` wrapper.
fn detect_top_prefix<R: std::io::Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
) -> Result<Option<String>> {
    let mut prefix: Option<String> = None;
    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| BrowserError::Extract(e.to_string()))?;
        let name = entry.name().replace('\\', "/");
        let Some(first_slash) = name.find('/') else {
            return Ok(None);
        };
        let candidate = format!("{}/", &name[..first_slash]);
        match prefix.as_deref() {
            None => prefix = Some(candidate),
            Some(existing) if existing == candidate => {}
            _ => return Ok(None),
        }
    }
    Ok(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            for (name, content) in files {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(content).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    fn working_extension(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(path.join("manifest.json"), br#"{"version":"1.0.0"}"#).unwrap();
        std::fs::write(path.join("working.js"), b"known good").unwrap();
    }

    #[test]
    fn extension_swap_rolls_back_and_interrupted_swaps_restore_backups() {
        let fixture = tempfile::tempdir().unwrap();
        let current = fixture.path().join("nomad-extensions/uBlock0");
        let stage = current.with_file_name("uBlock0.stage");
        let backup = current.with_file_name("uBlock0.backup");
        working_extension(&current);
        assert!(swap_extension(&current, &stage, &backup).is_err());
        assert_eq!(
            std::fs::read(current.join("working.js")).unwrap(),
            b"known good"
        );
        assert!(!backup.exists());
        std::fs::rename(&current, &backup).unwrap();
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("partial"), b"incomplete").unwrap();
        assert_eq!(staged_ubo_dir(fixture.path()), Some(backup.clone()));
        recover_extension(&current, &stage, &backup).unwrap();
        assert_eq!(
            std::fs::read(current.join("working.js")).unwrap(),
            b"known good"
        );
        assert!(!stage.exists() && !backup.exists());
    }

    #[test]
    fn extension_recovery_never_discards_backup_for_an_invalid_active_copy() {
        let fixture = tempfile::tempdir().unwrap();
        let current = fixture.path().join("uBlock0");
        let stage = current.with_file_name("uBlock0.stage");
        let backup = current.with_file_name("uBlock0.backup");
        working_extension(&backup);
        std::fs::create_dir_all(&current).unwrap();
        std::fs::write(current.join("manifest.json"), b"invalid").unwrap();
        assert!(recover_extension(&current, &stage, &backup).is_err());
        assert_eq!(
            std::fs::read(backup.join("working.js")).unwrap(),
            b"known good"
        );
    }

    #[test]
    fn extension_transaction_lock_prevents_competing_staging() {
        let fixture = tempfile::tempdir().unwrap();
        let current = fixture.path().join("nomad-extensions/uBlock0");
        working_extension(&current);
        let _lock = lock_extension_root(fixture.path()).unwrap();
        let zip = make_zip(&[("manifest.json", br#"{"version":"2.0.0"}"#)]);
        let result = stage_chromium_ubo_from_gorhill_zip(fixture.path(), &zip, "2.0.0");
        assert!(
            matches!(result, Err(BrowserError::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock)
        );
        assert_eq!(
            std::fs::read(current.join("working.js")).unwrap(),
            b"known good"
        );
    }

    #[test]
    fn managed_extension_survives_browser_update_and_fresh_install_stays_staged() {
        let fixture = tempfile::tempdir().unwrap();
        let current = fixture.path().join("Browser");
        let stage = fixture.path().join("Browser.stage");
        preserve_chromium_ubo(&current, &stage).unwrap();
        assert!(!current.exists() && !stage.exists());
        let source = current.join("nomad-extensions/uBlock0");
        working_extension(&source);
        preserve_chromium_ubo(&current, &stage).unwrap();
        assert_eq!(
            std::fs::read(stage.join("nomad-extensions/uBlock0/working.js")).unwrap(),
            b"known good"
        );
        assert_eq!(
            std::fs::read(source.join("working.js")).unwrap(),
            b"known good"
        );
    }

    #[cfg(windows)]
    #[test]
    fn locked_extension_directory_preserves_old_copy_when_swap_fails() {
        use std::os::windows::fs::OpenOptionsExt;
        let fixture = tempfile::tempdir().unwrap();
        let current = fixture.path().join("nomad-extensions/uBlock0");
        working_extension(&current);
        let handle = std::fs::File::options()
            .read(true)
            .share_mode(0)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
            .open(&current)
            .unwrap();
        let zip = make_zip(&[("manifest.json", br#"{"version":"2.0.0"}"#)]);
        assert!(stage_chromium_ubo_from_gorhill_zip(fixture.path(), &zip, "2.0.0").is_err());
        drop(handle);
        assert_eq!(
            std::fs::read(current.join("working.js")).unwrap(),
            b"known good"
        );
        assert!(!current.with_file_name("uBlock0.stage").exists());
    }

    #[test]
    fn malformed_extension_updates_preserve_the_working_copy() {
        for malformed in [
            b"not a zip".to_vec(),
            make_zip(&[("background.js", b"incomplete")]),
            make_zip(&[("manifest.json", b"not JSON")]),
        ] {
            let fixture = tempfile::tempdir().unwrap();
            let current = fixture.path().join("nomad-extensions/uBlock0");
            std::fs::create_dir_all(&current).unwrap();
            let manifest = br#"{"version":"1.0.0"}"#;
            std::fs::write(current.join("manifest.json"), manifest).unwrap();
            std::fs::write(current.join("working.js"), b"known good").unwrap();
            assert!(
                stage_chromium_ubo_from_gorhill_zip(fixture.path(), &malformed, "2.0.0").is_err()
            );
            assert_eq!(
                std::fs::read(current.join("manifest.json")).unwrap(),
                manifest
            );
            assert_eq!(
                std::fs::read(current.join("working.js")).unwrap(),
                b"known good"
            );
        }
    }

    #[test]
    fn extract_zip_into_rejects_an_over_budget_extension_zip() {
        // The gorhill zip is the one runtime-fetched artifact without a hash
        // pin, so the decompressed budget is its only bomb protection.
        let dir = tempfile::tempdir().unwrap();
        let zip = make_zip(&[("payload.bin", &[0u8; 1024][..])]);
        let err = extract_zip_into_with_budget(&zip, dir.path(), 64)
            .expect_err("an over-budget extension zip must abort extraction");
        assert!(matches!(err, BrowserError::Extract(_)), "got {err:?}");
    }

    #[test]
    fn stage_gorhill_zip_extracts_under_nomad_extensions() {
        let dir = tempfile::tempdir().unwrap();
        let zip = make_zip(&[
            (
                "manifest.json",
                br#"{"version":"1.62.0","name":"uBlock Origin"}"#,
            ),
            ("background.js", b"// uBO"),
        ]);

        stage_chromium_ubo_from_gorhill_zip(dir.path(), &zip, "1.62.0").unwrap();

        let ext_dir = dir.path().join("nomad-extensions/uBlock0");
        assert!(ext_dir.join("manifest.json").is_file());
        assert!(ext_dir.join("background.js").is_file());
        assert_eq!(staged_ubo_dir(dir.path()).as_ref(), Some(&ext_dir));
    }

    #[test]
    fn stage_gorhill_zip_strips_top_level_wrapper_directory() {
        // gorhill's uBlock0_X.X.X.chromium.zip wraps all entries inside a single
        // top-level directory (`uBlock0.chromium/`). The staging code must strip
        // that wrapper so manifest.json lands directly under
        // nomad-extensions/uBlock0/, otherwise Chromium can't load the extension.
        let dir = tempfile::tempdir().unwrap();
        let zip = make_zip(&[
            ("uBlock0.chromium/manifest.json", br#"{"version":"1.71.0"}"#),
            ("uBlock0.chromium/background.js", b"// uBO"),
            ("uBlock0.chromium/css/dark.css", b"body{}"),
        ]);

        stage_chromium_ubo_from_gorhill_zip(dir.path(), &zip, "1.71.0").unwrap();

        let ext_dir = dir.path().join("nomad-extensions/uBlock0");
        assert!(
            ext_dir.join("manifest.json").is_file(),
            "manifest.json must land at nomad-extensions/uBlock0/manifest.json"
        );
        assert!(ext_dir.join("background.js").is_file());
        assert!(ext_dir.join("css/dark.css").is_file());
        assert!(
            !ext_dir.join("uBlock0.chromium").exists(),
            "the wrapper directory must not leak into the destination"
        );
    }

    #[test]
    fn staging_replaces_previous_install_completely() {
        let dir = tempfile::tempdir().unwrap();
        let ext_dir = dir.path().join("nomad-extensions/uBlock0");
        std::fs::create_dir_all(&ext_dir).unwrap();
        std::fs::write(ext_dir.join("stale.txt"), b"stale").unwrap();

        let zip = make_zip(&[("manifest.json", br#"{"version":"1.63.0"}"#)]);
        stage_chromium_ubo_from_gorhill_zip(dir.path(), &zip, "1.63.0").unwrap();

        assert!(
            !ext_dir.join("stale.txt").exists(),
            "stale files from older install must be removed"
        );
        assert!(ext_dir.join("manifest.json").is_file());
    }

    #[test]
    fn staged_ubo_dir_returns_none_when_not_staged() {
        let dir = tempfile::tempdir().unwrap();
        assert!(staged_ubo_dir(dir.path()).is_none());
    }

    #[test]
    fn stage_gorhill_zip_skips_drive_absolute_entries() {
        // A compromised-but-tag-valid gorhill zip must not be able to write
        // outside the extension dir via a drive-absolute entry name (the shared
        // extract::is_safe_zip_path guard).
        let dir = tempfile::tempdir().unwrap();
        let escape = tempfile::tempdir().unwrap();
        let escape_target = escape.path().join("escaped.txt");
        let entry = escape_target.to_string_lossy().replace('\\', "/");

        let zip = make_zip(&[
            (entry.as_str(), b"ESCAPE"),
            ("manifest.json", br#"{"version":"1.0.0"}"#),
        ]);
        stage_chromium_ubo_from_gorhill_zip(dir.path(), &zip, "1.0.0").unwrap();

        assert!(
            !escape_target.exists(),
            "drive-absolute entry must be skipped, not written outside the dest"
        );
        assert!(
            dir.path()
                .join("nomad-extensions/uBlock0/manifest.json")
                .is_file(),
            "legitimate entries must still extract"
        );
    }
}
