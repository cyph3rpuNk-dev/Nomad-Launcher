//! Launch-time update orchestration.
//!
//! [`update`] performs the check → download → verify → extract → prep portion
//! of the SPEC §8 flow. Launching the browser is the caller's responsibility
//! (see [`crate::run`]).

use std::path::Path;

use tokio::sync::watch;

use crate::browsers::{
    write_version_marker, BrowserError, BrowserFamily, InstalledVersion, Result, VersionInfo,
};
use crate::{downloader, gpg};

/// Options controlling the update check, taken from `[update]` in the config.
#[derive(Debug, Clone, Copy)]
pub struct UpdateOptions {
    /// Whether to check the upstream for a newer release at all.
    pub check_on_launch: bool,
    /// Whether a found update may be downloaded without prompting.
    pub auto_download: bool,
}

/// The result of an [`update`] run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// `check_on_launch` was disabled; no check was performed.
    CheckSkipped,
    /// The installed build is already the latest.
    UpToDate,
    /// A newer build exists but `auto_download` is off; nothing was changed.
    UpdateDeferred(String),
    /// A newer build was downloaded, verified, and installed.
    Updated(String),
}

/// Returns whether `latest` differs from the currently installed build.
#[must_use]
pub fn needs_update(installed: Option<&InstalledVersion>, latest: &VersionInfo) -> bool {
    match installed {
        Some(installed) => installed.browser_version != latest.browser_version,
        None => true,
    }
}

/// Verifies a downloaded package before it is extracted.
///
/// A GPG signature is checked when the browser publishes a key and a
/// signature file was fetched; the SHA-256/512 hash is checked whenever the
/// upstream publishes one. **Fail-closed:** if neither a GPG signature nor a
/// hash could actually be verified, the package is rejected rather than
/// extracted — this guards against, e.g., a separately-fetched sums file that
/// failed to download (leaving both hashes `None`).
///
/// # Errors
/// Returns [`BrowserError::Verification`] if the signature or hash does not
/// validate, or if no integrity material was available at all, and
/// [`BrowserError::Io`] if the package cannot be read.
pub fn verify_package<B: BrowserFamily + ?Sized>(
    browser: &B,
    info: &VersionInfo,
    package: &Path,
    signature: Option<&Path>,
) -> Result<()> {
    // Tracks whether at least one cryptographic check actually ran. A package
    // that reaches the end with nothing verified must never be installed.
    let mut verified = false;

    match (browser.public_key(), signature) {
        (Some(_), Some(sig)) => {
            browser.verify_signature(package, sig)?;
            tracing::debug!(browser = browser.id(), "GPG signature verified");
            verified = true;
        }
        (Some(_), None) => {
            tracing::warn!(
                browser = browser.id(),
                "GPG key is configured but no signature was published; relying on hash only"
            );
        }
        (None, _) => {
            tracing::warn!(
                browser = browser.id(),
                "no GPG signature published; relying on hash only"
            );
        }
    }

    // Check SHA-256 or SHA-512, whichever the upstream publishes.
    // At most one will be Some for any given browser.
    match (&info.sha256, &info.sha512) {
        (Some(expected), _) => {
            let bytes = std::fs::read(package)?;
            gpg::sha256::verify(&bytes, expected)
                .map_err(|e| BrowserError::Verification(e.to_string()))?;
            tracing::debug!(browser = browser.id(), "SHA-256 hash verified");
            verified = true;
        }
        (None, Some(expected)) => {
            let bytes = std::fs::read(package)?;
            gpg::sha512::verify(&bytes, expected)
                .map_err(|e| BrowserError::Verification(e.to_string()))?;
            tracing::debug!(browser = browser.id(), "SHA-512 hash verified");
            verified = true;
        }
        (None, None) => {}
    }

    if !verified {
        return Err(BrowserError::Verification(format!(
            "no integrity material (GPG signature or SHA hash) available for {}; \
             refusing to extract an unverified package",
            browser.id()
        )));
    }
    Ok(())
}

/// Runs the check → download → verify → extract → prep flow for `browser`.
///
/// # Errors
/// Propagates any [`BrowserError`] from the update check, download,
/// verification, extraction, or portability-prefs steps.
pub async fn update<B: BrowserFamily>(
    browser: &B,
    install_dir: &Path,
    options: UpdateOptions,
) -> Result<UpdateOutcome> {
    crate::install::recover_staging(install_dir);

    if !options.check_on_launch {
        tracing::info!(browser = browser.id(), "update check skipped by config");
        return Ok(UpdateOutcome::CheckSkipped);
    }

    let latest = browser.fetch_latest_version().await?;
    let installed = browser.installed_version(install_dir);
    if !needs_update(installed.as_ref(), &latest) {
        tracing::info!(
            browser = browser.id(),
            version = latest.browser_version,
            "already up to date"
        );
        return Ok(UpdateOutcome::UpToDate);
    }

    if !options.auto_download {
        tracing::info!(
            browser = browser.id(),
            version = latest.browser_version,
            "update available but auto_download is disabled"
        );
        return Ok(UpdateOutcome::UpdateDeferred(latest.browser_version));
    }

    // Headless callers carry no hardening config; payloads are written
    // unconditionally, matching the config default (`enabled = true`).
    let (progress, _receiver) = watch::channel(0.0_f32);
    download_and_install(browser, install_dir, &latest, true, progress, |_| {}).await?;
    Ok(UpdateOutcome::Updated(latest.browser_version))
}

/// A coarse step of [`download_and_install`], reported through its `on_step`
/// callback so UI callers can show per-step status text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallStep {
    /// The package download is starting.
    Downloading,
    /// The package (and optional detached signature) is being verified.
    Verifying,
    /// The package is being extracted and swapped into place.
    Installing,
}

/// The single download → verify → extract → finalize → swap sequence, shared
/// by the headless [`update`] flow and the UI pipeline in `lib.rs`.
///
/// Keep this the only implementation: the two callers previously carried
/// hand-maintained copies that drifted in both directions (the UI copy
/// dropped the preserve-state hook — wiping the Bitwarden vault on update —
/// and the headless copy dropped the Gecko policies write).
pub(crate) async fn download_and_install<B: BrowserFamily>(
    browser: &B,
    install_dir: &Path,
    latest: &VersionInfo,
    hardening_enabled: bool,
    progress: watch::Sender<f32>,
    mut on_step: impl FnMut(InstallStep),
) -> Result<()> {
    let stage_dir = crate::install::stage_dir(install_dir);
    let backup_dir = crate::install::backup_dir(install_dir);
    std::fs::create_dir_all(&stage_dir)?;
    let package = stage_dir.join(package_name(&latest.download_url));

    on_step(InstallStep::Downloading);
    browser.download(latest, &package, progress).await?;

    on_step(InstallStep::Verifying);
    let signature = match &latest.signature_url {
        Some(url) => {
            let sig_path = stage_dir.join(format!("{}.sig", package_name(&latest.download_url)));
            let (sig_progress, _rx) = watch::channel(0.0_f32);
            downloader::download(url, &sig_path, &sig_progress).await?;
            Some(sig_path)
        }
        None => None,
    };
    verify_package(browser, latest, &package, signature.as_deref())?;

    on_step(InstallStep::Installing);
    browser.extract(&package, &stage_dir)?;
    let _ = std::fs::remove_file(&package);
    if let Some(sig) = &signature {
        let _ = std::fs::remove_file(sig);
    }

    finalize_install(
        browser,
        install_dir,
        &stage_dir,
        &backup_dir,
        latest,
        hardening_enabled,
    )?;

    tracing::info!(
        browser = browser.id(),
        version = latest.browser_version,
        "update installed"
    );
    Ok(())
}

/// Writes the Gecko hardening payloads and version marker into the staged
/// install, carries over per-app state stored *inside* `install_dir` (e.g.
/// the Bitwarden vault at `Data/`), then atomically swaps the stage into
/// place.
///
/// The [`BrowserFamily::preserve_state_across_update`] call must run before
/// [`crate::install::atomic_swap`]: the swap replaces `install_dir` wholesale
/// and deletes the backup, so skipping the hook destroys any state kept
/// inside the install dir.
fn finalize_install<B: BrowserFamily>(
    browser: &B,
    install_dir: &Path,
    stage_dir: &Path,
    backup_dir: &Path,
    latest: &VersionInfo,
    hardening_enabled: bool,
) -> Result<()> {
    if hardening_enabled {
        if let crate::browsers::Hardening::GeckoProfile {
            policies,
            autoconfig,
            cfg,
            ..
        } = browser.hardening()
        {
            if let Some(p) = policies {
                crate::hardening::write_policies_json(stage_dir, p)?;
            }
            if let (Some(a), Some(c)) = (autoconfig, cfg) {
                crate::hardening::write_autoconfig(stage_dir, a, c)?;
            }
        }
    }

    write_version_marker(
        stage_dir,
        &InstalledVersion {
            browser_version: latest.browser_version.clone(),
            engine_version: latest.engine_version.clone(),
        },
    )?;

    browser.preserve_state_across_update(install_dir, stage_dir)?;
    crate::install::atomic_swap(install_dir, stage_dir, backup_dir)?;
    Ok(())
}

/// Derives a package file name from a download URL's last path segment.
pub(crate) fn package_name(url: &str) -> &str {
    url.rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("nomad-package")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browsers::ungoogled::UngoogledChromium;
    use crate::config::Arch;

    fn version_info(version: &str, sha256: Option<&str>) -> VersionInfo {
        VersionInfo {
            browser_version: version.to_owned(),
            engine_version: version.to_owned(),
            download_url: "https://example.invalid/pkg.zip".to_owned(),
            signature_url: None,
            sha256: sha256.map(str::to_owned),
            sha512: None,
        }
    }

    #[test]
    fn finalize_install_preserves_in_dir_state_across_the_swap() {
        // Regression: the shipped UI pipeline once swapped the stage into
        // place without calling preserve_state_across_update — the hook lived
        // only in updater::update, which nothing but the integration tests
        // call — so a real Bitwarden update permanently deleted the vault at
        // Data/.
        use crate::browsers::bitwarden::Bitwarden;

        let dir = tempfile::tempdir().unwrap();
        let install_dir = dir.path().join("App");
        let stage_dir = crate::install::stage_dir(&install_dir);
        let backup_dir = crate::install::backup_dir(&install_dir);

        // Live install holding a vault; freshly-staged new version without one.
        std::fs::create_dir_all(install_dir.join("Data")).unwrap();
        std::fs::write(install_dir.join("Data").join("data.json"), b"vault").unwrap();
        std::fs::create_dir_all(&stage_dir).unwrap();
        std::fs::write(stage_dir.join("Bitwarden-Portable.exe"), b"new binary").unwrap();

        let browser = Bitwarden::new(Arch::X64);
        let latest = VersionInfo {
            browser_version: "2026.6.0".to_owned(),
            engine_version: "2026.6.0".to_owned(),
            download_url: "https://example.invalid/Bitwarden-Portable-2026.6.0.exe".to_owned(),
            signature_url: None,
            sha256: None,
            sha512: None,
        };

        finalize_install(
            &browser,
            &install_dir,
            &stage_dir,
            &backup_dir,
            &latest,
            false,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(install_dir.join("Data").join("data.json")).unwrap(),
            b"vault",
            "the vault must survive the stage swap"
        );
        assert_eq!(
            std::fs::read(install_dir.join("Bitwarden-Portable.exe")).unwrap(),
            b"new binary",
            "the staged new version must be in place after the swap"
        );
        assert_eq!(
            browser
                .installed_version(&install_dir)
                .expect("version marker must be written into the stage")
                .browser_version,
            "2026.6.0"
        );
    }

    #[test]
    fn needs_update_when_nothing_installed() {
        assert!(needs_update(None, &version_info("1.0", None)));
    }

    #[test]
    fn needs_update_when_versions_differ() {
        let installed = InstalledVersion {
            browser_version: "1.0".to_owned(),
            engine_version: "1.0".to_owned(),
        };
        assert!(needs_update(Some(&installed), &version_info("2.0", None)));
    }

    #[test]
    fn no_update_when_versions_match() {
        let installed = InstalledVersion {
            browser_version: "2.0".to_owned(),
            engine_version: "2.0".to_owned(),
        };
        assert!(!needs_update(Some(&installed), &version_info("2.0", None)));
    }

    #[test]
    fn verify_package_rejects_a_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("pkg.zip");
        std::fs::write(&package, b"actual package bytes").unwrap();

        let info = version_info("1.0", Some(&"0".repeat(64)));
        let browser = UngoogledChromium::new(Arch::X64);
        let err = verify_package(&browser, &info, &package, None)
            .expect_err("a wrong SHA-256 must abort verification");
        assert!(matches!(err, BrowserError::Verification(_)));
    }

    #[test]
    fn verify_package_accepts_a_matching_hash() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("pkg.zip");
        let contents = b"actual package bytes";
        std::fs::write(&package, contents).unwrap();

        let info = version_info("1.0", Some(&gpg::sha256::hex(contents)));
        let browser = UngoogledChromium::new(Arch::X64);
        verify_package(&browser, &info, &package, None)
            .expect("a matching hash must pass verification");
    }

    #[test]
    fn verify_package_rejects_a_package_with_no_integrity_material() {
        // No GPG signature and no published hash (e.g. a sums-file fetch that
        // failed, leaving both hashes None). Verification must fail closed.
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("pkg.zip");
        std::fs::write(&package, b"unverifiable bytes").unwrap();

        let info = version_info("1.0", None);
        let browser = UngoogledChromium::new(Arch::X64);
        let err = verify_package(&browser, &info, &package, None)
            .expect_err("a package with no hash and no signature must be rejected");
        assert!(matches!(err, BrowserError::Verification(_)));
    }

    #[test]
    fn package_name_uses_the_last_url_segment() {
        assert_eq!(package_name("https://host/path/uc-x64.zip"), "uc-x64.zip");
        assert_eq!(package_name("https://host/trailing/"), "trailing");
    }
}
