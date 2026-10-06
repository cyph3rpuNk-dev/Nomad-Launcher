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
/// A detached GPG signature is required whenever the adapter exposes a package
/// signing key. A missing, unreadable or invalid signature cannot fall back to
/// a hash. The SHA-256/512 hash is also checked whenever published. Adapters
/// without a package signing key still require verifiable integrity material;
/// Firefox authenticates its checksum manifest earlier in release resolution.
///
/// # Errors
/// Returns [`BrowserError::Verification`] if the signature or hash does not
/// validate, a required signature is absent, or no integrity material was available, and
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
        (Some(_), None) => return Err(missing_package_signature(browser.id())),
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

fn missing_package_signature(browser_id: &str) -> BrowserError {
    BrowserError::Verification(format!(
        "required detached signature missing for {browser_id}; refusing hash-only verification"
    ))
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
    if !options.check_on_launch {
        tracing::info!(browser = browser.id(), "update check skipped by config");
        return Ok(UpdateOutcome::CheckSkipped);
    }

    let lock = crate::install::InstanceLock::acquire(install_dir)?;
    crate::install::recover_staging_locked(install_dir, &lock)?;
    let latest = browser.fetch_latest_version().await?;
    browser.validate_update(&latest)?;
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
    download_and_install(
        browser,
        install_dir,
        &latest,
        true,
        None,
        progress,
        |_| {},
        &lock,
    )
    .await?;
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
/// The caller must retain the same instance lock from recovery through swap.
///
/// Keep this the only implementation: the two callers previously carried
/// hand-maintained copies that drifted in both directions (the UI copy
/// dropped the preserve-state hook — wiping the Bitwarden vault on update —
/// and the headless copy dropped the Gecko policies write).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn download_and_install<B: BrowserFamily>(
    browser: &B,
    install_dir: &Path,
    latest: &VersionInfo,
    hardening_enabled: bool,
    branding: Option<&crate::Branding>,
    progress: watch::Sender<f32>,
    mut on_step: impl FnMut(InstallStep),
    lock: &crate::install::InstanceLock,
) -> Result<()> {
    lock.check_install_dir(install_dir)?;
    browser.validate_update(latest)?;
    // The shared UI/headless path must reject incomplete signature metadata
    // before downloading or creating a stage, including cached releases.
    if browser.public_key().is_some() && latest.signature_url.is_none() {
        return Err(missing_package_signature(browser.id()));
    }
    let stage_dir = crate::install::stage_dir(install_dir);
    let backup_dir = crate::install::backup_dir(install_dir);
    // Recovery must have removed any stale stage under this same lock.
    // Do not adopt an existing directory supplied by another writer.
    crate::fs_safety::ensure_directory(&stage_dir)?;
    std::fs::create_dir(&stage_dir)?;
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
        branding,
        lock,
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
#[allow(clippy::too_many_arguments)]
fn finalize_install<B: BrowserFamily>(
    browser: &B,
    install_dir: &Path,
    stage_dir: &Path,
    backup_dir: &Path,
    latest: &VersionInfo,
    hardening_enabled: bool,
    branding: Option<&crate::Branding>,
    lock: &crate::install::InstanceLock,
) -> Result<()> {
    lock.check_install_dir(install_dir)?;
    let layout = browser.staged_install_layout();
    layout.validate(stage_dir)?;
    browser.validate_staged_install(stage_dir)?;
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

    if let Some(branding) = branding {
        if !crate::branding::ensure_branding(stage_dir, branding) {
            return Err(BrowserError::Compatibility(format!(
                "required branding overlay is incompatible with {} {}; the working browser was not replaced",
                browser.display_name(), latest.browser_version
            )));
        }
    }

    browser.preserve_state_across_update(install_dir, stage_dir)?;
    // Preparation and overlays must leave the required layout intact too.
    layout.validate(stage_dir)?;
    write_version_marker(
        stage_dir,
        &InstalledVersion {
            browser_version: latest.browser_version.clone(),
            engine_version: latest.engine_version.clone(),
        },
    )?;

    crate::install::atomic_swap_locked(install_dir, stage_dir, backup_dir, lock)?;
    Ok(())
}

/// URLs select only a recognized format suffix, never a local basename.
/// Fixed names cannot escape staging or alias a staged browser executable.
pub(crate) fn package_name(url: &str) -> &'static str {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return "nomad-package.bin";
    };
    let path = parsed.path();
    let suffix = path.get(path.len().saturating_sub(4)..).unwrap_or("");
    if suffix.eq_ignore_ascii_case(".zip") {
        "nomad-package.zip"
    } else if suffix.eq_ignore_ascii_case(".exe") {
        "nomad-package.exe"
    } else {
        "nomad-package.bin"
    }
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
            None,
            &crate::install::InstanceLock::acquire(&install_dir).unwrap(),
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

    fn incomplete_stages_preserve_install<B: BrowserFamily>(
        browser: &B,
        executable: &str,
        runtime: &[&str],
    ) {
        let files: Vec<_> = std::iter::once(executable)
            .chain(runtime.iter().copied())
            .collect();
        for bad_file in &files {
            for fault in ["missing", "empty", "directory"] {
                for hardening_enabled in [false, true] {
                    let temp = tempfile::tempdir().unwrap();
                    let install = temp.path().join("Browser");
                    let stage = crate::install::stage_dir(&install);
                    let backup = crate::install::backup_dir(&install);
                    std::fs::create_dir_all(install.join("Data")).unwrap();
                    std::fs::create_dir_all(temp.path().join("Data")).unwrap();
                    std::fs::create_dir_all(&stage).unwrap();
                    std::fs::write(install.join(executable), b"working browser").unwrap();
                    std::fs::write(install.join(".nomad-version"), b"old marker").unwrap();
                    std::fs::write(install.join("Data/vault"), b"vault").unwrap();
                    std::fs::write(temp.path().join("Data/profile"), b"profile").unwrap();
                    for name in &files {
                        let path = stage.join(name);
                        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                        if name == bad_file {
                            match fault {
                                "missing" => {}
                                "empty" => std::fs::write(path, b"").unwrap(),
                                "directory" => std::fs::create_dir_all(path).unwrap(),
                                _ => unreachable!(),
                            }
                        } else {
                            std::fs::write(path, b"staged file").unwrap();
                        }
                    }
                    let lock = crate::install::InstanceLock::acquire(&install).unwrap();
                    let outcome = finalize_install(
                        browser,
                        &install,
                        &stage,
                        &backup,
                        &version_info("2.0", None),
                        hardening_enabled,
                        None,
                        &lock,
                    );
                    assert!(
                        matches!(outcome, Err(BrowserError::Compatibility(_))),
                        "{}: {fault} {bad_file}, hardening={hardening_enabled}: {outcome:?}",
                        browser.id()
                    );
                    assert_eq!(
                        std::fs::read(install.join(executable)).unwrap(),
                        b"working browser"
                    );
                    assert_eq!(
                        std::fs::read(install.join(".nomad-version")).unwrap(),
                        b"old marker"
                    );
                    assert_eq!(std::fs::read(install.join("Data/vault")).unwrap(), b"vault");
                    assert_eq!(
                        std::fs::read(temp.path().join("Data/profile")).unwrap(),
                        b"profile"
                    );
                    assert!(!backup.exists(), "invalid stage must fail before swap");
                    for generated in [
                        ".nomad-version",
                        ".branding-patched",
                        "distribution",
                        "nomad.cfg",
                        "Data",
                    ] {
                        assert!(
                            !stage.join(generated).exists(),
                            "validation must precede {generated}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn incomplete_helium_stage_preserves_install_and_profile() {
        incomplete_stages_preserve_install(
            &crate::browsers::helium::Helium::new(Arch::X64),
            "chrome.exe",
            &[
                "chrome.dll",
                "resources.pak",
                "icudtl.dat",
                "chrome_100_percent.pak",
                "chrome_200_percent.pak",
            ],
        );
    }

    #[test]
    fn incomplete_gecko_stages_preserve_install_and_profile() {
        use crate::browsers::{
            firefox::Firefox, floorp::Floorp, librewolf::Librewolf, mullvad::Mullvad,
            waterfox::Waterfox,
        };
        let runtime = &["xul.dll", "application.ini", "omni.ja", "browser/omni.ja"];
        incomplete_stages_preserve_install(&Firefox::new(Arch::X64), "firefox.exe", runtime);
        incomplete_stages_preserve_install(&Firefox::new_esr(Arch::X64), "firefox.exe", runtime);
        incomplete_stages_preserve_install(&Floorp::new(Arch::X64), "floorp.exe", runtime);
        incomplete_stages_preserve_install(&Librewolf::new(Arch::X64), "librewolf.exe", runtime);
        incomplete_stages_preserve_install(&Mullvad::new(Arch::X64), "mullvadbrowser.exe", runtime);
        incomplete_stages_preserve_install(&Waterfox::new(Arch::X64), "Waterfox.exe", runtime);
    }

    #[test]
    fn incomplete_bitwarden_stage_preserves_vault() {
        incomplete_stages_preserve_install(
            &crate::browsers::bitwarden::Bitwarden::new(Arch::X64),
            "Bitwarden-Portable.exe",
            &[],
        );
    }

    struct RemovesExecutable(std::sync::atomic::AtomicBool);

    impl BrowserFamily for RemovesExecutable {
        fn id(&self) -> &'static str {
            "fixture"
        }
        fn display_name(&self) -> &'static str {
            "Fixture"
        }
        fn engine(&self) -> crate::browsers::Engine {
            crate::browsers::Engine::Electron
        }
        fn staged_install_layout(&self) -> crate::browsers::StagedInstallLayout {
            crate::browsers::StagedInstallLayout::PortableExecutable("app.exe")
        }
        fn public_key(&self) -> Option<&'static [u8]> {
            None
        }
        fn installed_version(&self, path: &Path) -> Option<InstalledVersion> {
            crate::browsers::read_version_marker(path)
        }
        fn fetch_latest_version(
            &self,
        ) -> impl std::future::Future<Output = Result<VersionInfo>> + Send {
            std::future::ready(Err(BrowserError::Network("no network in fixture".into())))
        }
        fn download(
            &self,
            _: &VersionInfo,
            _: &Path,
            _: watch::Sender<f32>,
        ) -> impl std::future::Future<Output = Result<()>> + Send {
            std::future::ready(Err(BrowserError::Network("no downloads in fixture".into())))
        }
        fn verify_signature(&self, _: &Path, _: &Path) -> Result<()> {
            panic!("no signatures in fixture")
        }
        fn extract(&self, _: &Path, _: &Path) -> Result<()> {
            panic!("no extraction in fixture")
        }
        fn hardening(&self) -> crate::browsers::Hardening {
            crate::browsers::Hardening::LaunchFlags {
                flags: &[],
                local_state: None,
                preferences: None,
            }
        }
        fn launch_command(&self, _: &Path, _: &[String]) -> std::process::Command {
            panic!("no browser launch in fixture")
        }
        fn upstream_url(&self) -> &'static str {
            "https://example.invalid"
        }
        fn validate_staged_install(&self, stage: &Path) -> Result<()> {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            std::fs::remove_file(stage.join("app.exe"))?;
            Ok(())
        }
    }

    #[test]
    fn custom_validation_hook_cannot_bypass_layout_gate_or_remove_required_files() {
        for initially_complete in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let install = temp.path().join("Browser");
            let stage = crate::install::stage_dir(&install);
            let backup = crate::install::backup_dir(&install);
            std::fs::create_dir_all(&install).unwrap();
            std::fs::create_dir_all(&stage).unwrap();
            std::fs::write(install.join("app.exe"), b"working copy").unwrap();
            if initially_complete {
                std::fs::write(stage.join("app.exe"), b"new copy").unwrap();
            }
            let browser = RemovesExecutable(std::sync::atomic::AtomicBool::new(false));
            let lock = crate::install::InstanceLock::acquire(&install).unwrap();
            let result = finalize_install(
                &browser,
                &install,
                &stage,
                &backup,
                &version_info("2.0", None),
                false,
                None,
                &lock,
            );
            assert!(
                matches!(result, Err(BrowserError::Compatibility(_))),
                "got {result:?}"
            );
            assert_eq!(
                browser.0.load(std::sync::atomic::Ordering::Relaxed),
                initially_complete
            );
            assert_eq!(
                std::fs::read(install.join("app.exe")).unwrap(),
                b"working copy"
            );
            assert!(!backup.exists());
            assert!(!stage.join(".nomad-version").exists());
        }
    }

    #[test]
    fn complete_gecko_stage_is_prepared_and_swapped_without_launching() {
        use crate::browsers::firefox::Firefox;
        let temp = tempfile::tempdir().unwrap();
        let install = temp.path().join("Browser");
        let stage = crate::install::stage_dir(&install);
        let backup = crate::install::backup_dir(&install);
        std::fs::create_dir_all(&install).unwrap();
        std::fs::write(install.join("firefox.exe"), b"old browser").unwrap();
        for name in [
            "firefox.exe",
            "xul.dll",
            "application.ini",
            "omni.ja",
            "browser/omni.ja",
        ] {
            let path = stage.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"new file").unwrap();
        }
        let browser = Firefox::new(Arch::X64);
        let lock = crate::install::InstanceLock::acquire(&install).unwrap();
        finalize_install(
            &browser,
            &install,
            &stage,
            &backup,
            &version_info("2.0", None),
            true,
            None,
            &lock,
        )
        .unwrap();
        assert_eq!(
            browser.installed_version(&install).unwrap().browser_version,
            "2.0"
        );
        assert_eq!(
            std::fs::read(install.join("firefox.exe")).unwrap(),
            b"new file"
        );
        assert!(install.join("distribution/policies.json").is_file());
        assert!(!stage.exists() && !backup.exists());
        assert!(
            !temp.path().join("Data").exists(),
            "validation/preparation must not create a profile"
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
    fn embedded_key_requires_signature_even_with_a_matching_hash() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("pkg.exe");
        let contents = b"inert signed-browser package fixture";
        std::fs::write(&package, contents).unwrap();
        let browser = crate::browsers::mullvad::Mullvad::new(Arch::X64);
        assert!(browser.public_key().is_some());
        for sha512 in [false, true] {
            let mut info = version_info("2.0", Some(&gpg::sha256::hex(contents)));
            if sha512 {
                use sha2::Digest;
                info.sha256 = None;
                info.sha512 = Some(hex::encode(sha2::Sha512::digest(contents)));
            }
            let error = verify_package(&browser, &info, &package, None)
                .expect_err("a matching digest cannot replace a required signature");
            assert!(matches!(error, BrowserError::Verification(_)));
            assert!(error.to_string().contains("required detached signature"));
        }
        assert_eq!(std::fs::read(&package).unwrap(), contents);
    }

    #[test]
    fn invalid_or_unreadable_signature_cannot_fall_back_to_matching_hash() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("pkg.exe");
        let signature = dir.path().join("pkg.sig");
        let contents = b"inert package fixture";
        std::fs::write(&package, contents).unwrap();
        let info = version_info("2.0", Some(&gpg::sha256::hex(contents)));
        let browser = crate::browsers::mullvad::Mullvad::new(Arch::X64);
        // A supplied path must not count as a successful signature check.
        for body in [None, Some(b"not an OpenPGP signature".as_slice())] {
            if let Some(body) = body {
                std::fs::write(&signature, body).unwrap();
            }
            assert!(matches!(
                verify_package(&browser, &info, &package, Some(&signature)),
                Err(BrowserError::Verification(_))
            ));
        }
        assert_eq!(std::fs::read(&package).unwrap(), contents);
    }

    #[tokio::test]
    async fn missing_signature_url_stops_before_download_or_stage_creation() {
        use httpmock::prelude::*;
        let server = MockServer::start_async().await;
        let package_request = server
            .mock_async(|when, then| {
                when.method(GET).path("/pkg.exe");
                then.status(500); // this must not be reached
            })
            .await;
        let fixture = tempfile::tempdir().unwrap();
        let install = fixture.path().join("Browser");
        let profile = fixture.path().join("Data");
        std::fs::create_dir(&install).unwrap();
        std::fs::create_dir(&profile).unwrap();
        std::fs::write(install.join("firefox.exe"), b"working browser").unwrap();
        std::fs::write(profile.join("sentinel"), b"user data").unwrap();
        let previous = InstalledVersion {
            browser_version: "1.0".into(),
            engine_version: "1.0".into(),
        };
        write_version_marker(&install, &previous).unwrap();
        let lock = crate::install::InstanceLock::acquire(&install).unwrap();
        let browser = crate::browsers::mullvad::Mullvad::new(Arch::X64);
        let mut info = version_info("2.0", Some(&gpg::sha256::hex(b"inert fixture")));
        info.download_url = server.url("/pkg.exe");
        let (progress, _rx) = watch::channel(0.0);
        let mut steps = Vec::new();
        let result = download_and_install(
            &browser,
            &install,
            &info,
            false,
            None,
            progress,
            |step| steps.push(step),
            &lock,
        )
        .await;
        assert!(matches!(result, Err(BrowserError::Verification(_))));
        package_request.assert_calls_async(0).await;
        assert!(steps.is_empty());
        assert!(!crate::install::stage_dir(&install).exists());
        assert!(!crate::install::backup_dir(&install).exists());
        assert_eq!(
            browser.installed_version(&install).unwrap().browser_version,
            "1.0"
        );
        assert_eq!(
            std::fs::read(install.join("firefox.exe")).unwrap(),
            b"working browser"
        );
        assert_eq!(
            std::fs::read(profile.join("sentinel")).unwrap(),
            b"user data"
        );
    }

    #[tokio::test]
    async fn failed_signature_download_preserves_current_install_and_profile() {
        use httpmock::prelude::*;
        let server = MockServer::start_async().await;
        let contents = b"inert package fixture";
        let package_request = server
            .mock_async(|when, then| {
                when.method(GET).path("/pkg.exe");
                then.status(200).body(contents);
            })
            .await;
        let signature_request = server
            .mock_async(|when, then| {
                when.method(GET).path("/pkg.sig");
                then.status(404);
            })
            .await;
        let fixture = tempfile::tempdir().unwrap();
        let install = fixture.path().join("Browser");
        let profile = fixture.path().join("Data");
        std::fs::create_dir(&install).unwrap();
        std::fs::create_dir(&profile).unwrap();
        std::fs::write(install.join("firefox.exe"), b"working browser").unwrap();
        std::fs::write(profile.join("sentinel"), b"user data").unwrap();
        let previous = InstalledVersion {
            browser_version: "1.0".into(),
            engine_version: "1.0".into(),
        };
        write_version_marker(&install, &previous).unwrap();
        let lock = crate::install::InstanceLock::acquire(&install).unwrap();
        let browser = crate::browsers::mullvad::Mullvad::new(Arch::X64);
        let mut info = version_info("2.0", Some(&gpg::sha256::hex(contents)));
        info.download_url = server.url("/pkg.exe");
        info.signature_url = Some(server.url("/pkg.sig"));
        let (progress, _rx) = watch::channel(0.0);
        let mut steps = Vec::new();
        let result = download_and_install(
            &browser,
            &install,
            &info,
            false,
            None,
            progress,
            |step| steps.push(step),
            &lock,
        )
        .await;
        assert!(result.is_err());
        package_request.assert_calls_async(1).await;
        signature_request.assert_calls_async(1).await;
        assert!(!steps.contains(&InstallStep::Installing));
        assert!(!crate::install::backup_dir(&install).exists());
        assert_eq!(
            browser.installed_version(&install).unwrap().browser_version,
            "1.0"
        );
        assert_eq!(
            std::fs::read(install.join("firefox.exe")).unwrap(),
            b"working browser"
        );
        assert_eq!(
            std::fs::read(profile.join("sentinel")).unwrap(),
            b"user data"
        );
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

    #[tokio::test]
    async fn download_pipeline_does_not_adopt_a_preexisting_stage() {
        let temp = tempfile::tempdir().unwrap();
        let install = temp.path().join("Browser");
        let stage = crate::install::stage_dir(&install);
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("sentinel"), b"other writer").unwrap();
        let lock = crate::install::InstanceLock::acquire(&install).unwrap();
        let browser = RemovesExecutable(std::sync::atomic::AtomicBool::new(false));
        let (progress, _rx) = watch::channel(0.0);
        let mut started = false;
        let result = download_and_install(
            &browser,
            &install,
            &version_info("2.0", None),
            false,
            None,
            progress,
            |_| started = true,
            &lock,
        )
        .await;
        assert!(
            matches!(result, Err(BrowserError::Io(ref e)) if e.kind() == std::io::ErrorKind::AlreadyExists)
        );
        assert!(!started, "existing stages must fail before download");
        assert_eq!(
            std::fs::read(stage.join("sentinel")).unwrap(),
            b"other writer"
        );
    }

    #[test]
    fn package_names_cannot_escape_staging_or_alias_browser_files() {
        for url in [
            "https://host/path/../..",
            "https://host/C:\\outside\\escape.zip",
            "https://host/..\\..\\escape.exe",
            "https://host/chrome.exe",
            "https://host/Bitwarden-Portable.exe",
            "https://host/pkg.zip?token=secret",
            "https://host/nomad-package.zip#fragment",
        ] {
            let name = package_name(url);
            assert!(
                matches!(
                    name,
                    "nomad-package.zip" | "nomad-package.exe" | "nomad-package.bin"
                ),
                "upstream filename must never become a local path"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_drive_qualified_upstream_name_cannot_redirect_the_package_path() {
        let fixture = tempfile::tempdir().unwrap();
        let stage = fixture.path().join("Browser.stage");
        let foreign = fixture.path().join("outside.zip");
        let url = format!(
            "https://host/{}",
            foreign.to_string_lossy().replace('/', "\\")
        );
        let destination = stage.join(package_name(&url));
        assert!(destination.starts_with(&stage));
        assert_ne!(destination, foreign);
    }

    #[test]
    fn package_name_keeps_only_recognized_format_extensions() {
        assert_eq!(
            package_name("https://host/path/uc-x64.zip"),
            "nomad-package.zip"
        );
        assert_eq!(
            package_name("https://host/setup.EXE?token=private#fragment"),
            "nomad-package.exe"
        );
        assert_eq!(package_name("https://host/trailing/"), "nomad-package.bin");
        assert_eq!(package_name("not a URL"), "nomad-package.bin");
    }

    #[cfg(windows)]
    #[test]
    fn incompatible_staged_overlay_preserves_working_install() {
        let dir = tempfile::tempdir().expect("tempdir");
        let install_dir = dir.path().join("Browser");
        let stage_dir = crate::install::stage_dir(&install_dir);
        let backup_dir = crate::install::backup_dir(&install_dir);
        std::fs::create_dir_all(&install_dir).expect("working install");
        std::fs::write(install_dir.join("working.txt"), b"old").expect("working sentinel");
        std::fs::create_dir_all(&stage_dir).expect("stage");
        std::fs::write(stage_dir.join("chrome.exe"), b"new").expect("staged executable");

        let browser = UngoogledChromium::new(Arch::X64);
        let latest = version_info("152.0.7977.82-1.1", None);
        let incompatible = crate::Branding {
            targets: &["required-but-missing.exe"],
            icons: &[],
            pak_patches: &[],
        };

        let error = finalize_install(
            &browser,
            &install_dir,
            &stage_dir,
            &backup_dir,
            &latest,
            false,
            Some(&incompatible),
            &crate::install::InstanceLock::acquire(&install_dir).unwrap(),
        )
        .expect_err("missing required overlay target must abort before swap");

        assert!(matches!(error, BrowserError::Compatibility(_)));
        assert_eq!(
            std::fs::read(install_dir.join("working.txt")).expect("working install retained"),
            b"old"
        );
        assert!(!backup_dir.exists(), "the swap must not have started");
    }
}
