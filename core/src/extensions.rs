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
/// install so a browser update wipes and re-stages it cleanly on the next
/// launch (the version check then re-fetches gorhill's zip).
const NOMAD_EXTENSIONS_SUBDIR: &str = "nomad-extensions";

/// Subdirectory of `nomad-extensions/` where uBO is staged.
const UBO_SUBDIR: &str = "uBlock0";

/// Returns the absolute path of the staged uBO directory, or `None` when
/// staging has not happened yet (e.g. offline first run, GPG verification
/// failure, or after a browser update before `fetch_extension_updates` runs).
pub(crate) fn staged_ubo_dir(install_dir: &Path) -> Option<PathBuf> {
    let dir = install_dir.join(NOMAD_EXTENSIONS_SUBDIR).join(UBO_SUBDIR);
    dir.join("manifest.json").is_file().then_some(dir)
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

    if ext_dir.exists() {
        std::fs::remove_dir_all(&ext_dir)?;
    }
    std::fs::create_dir_all(&ext_dir)?;
    extract_zip_into(zip_bytes, &ext_dir)?;
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
            std::fs::create_dir_all(&out)?;
        } else {
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)?;
            }
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
