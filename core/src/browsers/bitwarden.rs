//! [`BrowserFamily`] implementation for Bitwarden — the official portable
//! desktop password manager, wrapped as a Nomad launcher.
//!
//! Unlike every browser, Bitwarden is not built from source and is not a
//! browser: it is the Electron desktop app distributed by Bitwarden as a
//! single self-contained portable executable. Nomad downloads that official
//! artifact, verifies it, stages it, and launches it with two environment
//! variables that make it fully portable and let Nomad own the update flow:
//!
//! - `BITWARDEN_APPDATA_DIR` redirects the vault/userData to a `Data`
//!   subdirectory *inside* `install_dir` (`<install_dir>/Data`). Because that
//!   sits inside the directory the atomic update swap replaces wholesale,
//!   [`Bitwarden::preserve_state_across_update`] copies it into the staged
//!   install before the swap. Source: `apps/desktop/src/main.ts` checks this env var
//!   first, before the portable-mode default.
//! - `ELECTRON_NO_UPDATER=1` disables the app's built-in updater; Nomad polls
//!   the `bitwarden/clients` GitHub releases instead (the standard pipeline).
//!
//! **Why the portable `.exe`, not the APPX:** the `-x64.appx` payload is inert
//! when extracted and run unpacked (it depends on its MSIX package identity —
//! it spawns an Electron process tree but creates no window and no userData).
//! The official portable `.exe` is built for standalone USB use and honours
//! both env vars. Verified empirically before this module was written.
//!
//! **Verification:** Bitwarden publishes no GPG key, so `public_key()` is
//! `None` and integrity rests on the SHA-256 the GitHub releases API records
//! for the asset (the same model as Helium — see SPEC §9). The downloaded
//! `.exe` is additionally Authenticode-signed by "Bitwarden Inc."; signer
//! pinning via `WinVerifyTrust` is layered into [`Bitwarden::extract`] in a
//! follow-up (it needs `windows-sys` WinTrust/Cryptography features).

use std::path::Path;
use std::process::Command;

use super::{
    github, read_version_marker, BrowserError, BrowserFamily, Engine, Hardening, InstalledVersion,
    ProgressSink, Result, VersionInfo,
};
use crate::config::Arch;

/// GitHub releases *list* endpoint for the Bitwarden clients repo.
///
/// `releases/latest` is deliberately NOT used: `bitwarden/clients` publishes
/// browser-extension, desktop, CLI, and web releases into one stream, so
/// `latest` may point at an unrelated product (e.g. `browser-vX.X.X`). We list
/// releases and pick the newest one tagged [`DESKTOP_TAG_PREFIX`].
const DEFAULT_RELEASES_URL: &str =
    "https://api.github.com/repos/bitwarden/clients/releases?per_page=100";

/// Tag prefix identifying a desktop-app release in the multi-product repo.
const DESKTOP_TAG_PREFIX: &str = "desktop-v";

/// Stable file name the verified portable `.exe` is staged under inside
/// `install_dir`. The download arrives version-stamped
/// (`Bitwarden-Portable-2026.5.0.exe`); staging under a fixed name lets
/// [`launch_command`](Bitwarden::launch_command) target it without knowing the
/// version, and lets the pipeline delete the version-stamped download without
/// removing the staged copy.
const EXECUTABLE: &str = "Bitwarden-Portable.exe";

/// Vault/userData directory name, nested *inside* `install_dir` (`App/Data`),
/// passed to the app via `BITWARDEN_APPDATA_DIR`. It lives inside the directory
/// the update swap replaces, so [`Bitwarden::preserve_state_across_update`]
/// carries it across each update.
const DATA_DIRNAME: &str = "Data";

/// Authenticode signer subject the downloaded portable `.exe` must carry.
/// Verified in [`Bitwarden::extract`] before the executable is staged.
const SIGNER_SUBJECT: &str = "Bitwarden Inc.";

/// Default `nomad.toml` written on first run (see [`Bitwarden::default_config`]).
/// Trimmed to only the keys that affect an Electron desktop app — the
/// browser-only privacy keys are inert for Bitwarden and intentionally omitted.
const DEFAULT_CONFIG: &str = "\
# Nomad Portable Bitwarden configuration.
# Bitwarden is the official Electron desktop app, not a browser, so the
# browser-only privacy keys (incognito, WebRTC, fingerprinting, Safe Browsing,
# Gecko user.js, etc.) do not apply and are omitted. Only the keys below have
# any effect.

[browser]
install_dir = \"App\"          # folder beside the .exe holding the Bitwarden binary; the vault lives in App\\Data

[update]
check_on_launch = true        # false = skip the update check and launch immediately
auto_download = true          # false = ask in the status window before downloading an update

[launch]
extra_args = []               # extra command-line arguments for Bitwarden (advanced; normally empty)

[hardening]
scrub_thumbnail_cache = false # true = also wipe Windows thumbnail/icon caches on exit (briefly restarts Explorer)

# PRIVACY NOTE: Windows Prefetch (C:\\Windows\\Prefetch\\) records the full path to
# every executable it launches. Those entries need administrator rights to
# remove; keep the launcher path short and non-identifying to minimise exposure.
";

/// Bitwarden portable desktop app.
pub struct Bitwarden {
    releases_url: String,
}

impl Bitwarden {
    /// Creates a launcher for Bitwarden.
    ///
    /// `arch` is accepted to match the `BrowserFamily` constructor shape the
    /// core runner expects, but is ignored: Bitwarden ships a single portable
    /// `.exe` with no per-architecture variants.
    #[must_use]
    pub fn new(_arch: Arch) -> Self {
        Self {
            releases_url: DEFAULT_RELEASES_URL.to_owned(),
        }
    }

    /// Creates a launcher pointing at a custom releases endpoint (test only).
    #[cfg(test)]
    fn for_test(releases_url: impl Into<String>) -> Self {
        Self {
            releases_url: releases_url.into(),
        }
    }
}

/// Picks the newest stable desktop release from a `releases` list. The list is
/// newest-first (GitHub's order), so the first non-prerelease whose tag starts
/// with [`DESKTOP_TAG_PREFIX`] is the latest desktop release.
///
/// # Errors
/// Returns [`BrowserError::Parse`] when the list contains no desktop release.
fn latest_desktop_release(releases: &[github::Release]) -> Result<&github::Release> {
    releases
        .iter()
        .find(|r| !r.prerelease && r.tag_name.starts_with(DESKTOP_TAG_PREFIX))
        .ok_or_else(|| {
            BrowserError::Parse(
                "no desktop-v release found in bitwarden/clients releases".to_owned(),
            )
        })
}

/// Selects the portable `.exe` asset from a release: name contains `portable`,
/// ends with `.exe`, and is not the small web-installer stub.
///
/// # Errors
/// Returns [`BrowserError::Parse`] when no matching asset is present.
fn portable_asset(release: &github::Release) -> Result<&github::ReleaseAsset> {
    release
        .assets
        .iter()
        .find(|a| {
            let name = a.name.to_ascii_lowercase();
            std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
                && name.contains("portable")
                && !name.contains("installer")
        })
        .ok_or_else(|| {
            BrowserError::Parse(format!(
                "no portable .exe asset in release {}",
                release.tag_name
            ))
        })
}

/// Stages the verified portable `.exe` into `install_dir` under the stable
/// [`EXECUTABLE`] name. Separated from [`Bitwarden::extract`] so the staging
/// behaviour is testable without a real Authenticode-signed file.
///
/// # Errors
/// Returns [`BrowserError::Extract`] / [`BrowserError::Io`] if the executable
/// cannot be staged.
fn stage_executable(package: &Path, install_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(install_dir)?;
    let dest = install_dir.join(EXECUTABLE);
    // Same directory, so rename is atomic and avoids copying ~350 MB; fall back
    // to copy if rename is unavailable for any reason.
    if std::fs::rename(package, &dest).is_err() {
        std::fs::copy(package, &dest).map_err(|e| {
            BrowserError::Extract(format!("failed to stage portable executable: {e}"))
        })?;
    }
    Ok(())
}

/// Recursively copies the directory tree at `src` into `dst`, creating `dst`
/// and any nested directories. Used to carry the vault (`Data`) across an
/// update swap.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

impl BrowserFamily for Bitwarden {
    fn id(&self) -> &'static str {
        "bitwarden"
    }

    /// Bitwarden ships a trimmed default `nomad.toml`: it runs as an Electron
    /// app, not a Chromium/Gecko browser, so the browser-only privacy keys
    /// (incognito, WebRTC, fingerprinting, Safe-Browsing, Gecko `user.js`) are
    /// inert and omitted. Only the keys that actually affect Bitwarden are
    /// written, with `install_dir = "App"` (its vault lives in `App/Data`).
    fn default_config(&self) -> &'static str {
        DEFAULT_CONFIG
    }

    fn display_name(&self) -> &'static str {
        "Bitwarden"
    }

    fn engine(&self) -> Engine {
        Engine::Electron
    }

    fn public_key(&self) -> Option<&'static [u8]> {
        // Bitwarden publishes no GPG signing key. Integrity is the GitHub
        // SHA-256 asset digest (+ Authenticode, layered into extract()).
        None
    }

    fn installed_version(&self, install_dir: &Path) -> Option<InstalledVersion> {
        read_version_marker(install_dir)
    }

    async fn fetch_latest_version(&self) -> Result<VersionInfo> {
        let client = github::build_client()?;
        let releases = github::fetch_releases(&client, &self.releases_url).await?;
        let release = latest_desktop_release(&releases)?;

        // Tag shape is `desktop-vX.X.X`; strip the prefix for the version.
        let version = release
            .tag_name
            .strip_prefix(DESKTOP_TAG_PREFIX)
            .unwrap_or(&release.tag_name)
            .to_owned();

        let asset = portable_asset(release)?;
        let sha256 = asset
            .digest
            .as_deref()
            .and_then(|d| d.strip_prefix("sha256:"))
            .map(str::to_owned);

        Ok(VersionInfo {
            browser_version: version.clone(),
            engine_version: version,
            download_url: asset.browser_download_url.clone(),
            signature_url: None,
            sha256,
            sha512: None,
        })
    }

    async fn download(
        &self,
        info: &VersionInfo,
        dest: &Path,
        progress: ProgressSink,
    ) -> Result<()> {
        crate::downloader::download(&info.download_url, dest, &progress).await
    }

    fn verify_signature(&self, _package: &Path, _sig: &Path) -> Result<()> {
        // Never called: public_key() is None, so the pipeline never fetches a
        // signature or invokes this. Bitwarden integrity is SHA-256 (+
        // Authenticode in extract()), not GPG.
        Err(BrowserError::Verification(
            "Bitwarden does not use GPG signatures".to_owned(),
        ))
    }

    fn extract(&self, package: &Path, install_dir: &Path) -> Result<()> {
        // Verify-before-stage (invariant #4): the SHA-256 digest pin already ran
        // in updater::verify_package; here we additionally require the binary be
        // Authenticode-signed by Bitwarden Inc. — a publisher pin on top of the
        // byte pin, the spirit of GPG verification for an artifact with no GPG
        // key. No-op on non-Windows builds.
        crate::authenticode::verify_signed_by(package, SIGNER_SUBJECT).map_err(|e| {
            BrowserError::Verification(format!("Authenticode verification failed: {e}"))
        })?;

        // There is no archive to unpack: the portable `.exe` *is* the runnable
        // artifact (it self-extracts to %TEMP% at launch). "Extracting" here
        // means staging the verified download under a stable name so it
        // survives the pipeline's post-extract deletion of the version-stamped
        // download. `install_dir` is the staging dir at this point.
        stage_executable(package, install_dir)
    }

    fn preserve_state_across_update(&self, current_install: &Path, stage_dir: &Path) -> Result<()> {
        // The vault (`Data`) lives inside install_dir, which the swap replaces
        // wholesale, so copy it onto the freshly-staged binary before the swap.
        // Copy (not move) so a swap failure leaves the live install's vault
        // intact. On a fresh install the
        // source does not exist yet, which is a no-op.
        let src = current_install.join(DATA_DIRNAME);
        if !src.exists() {
            return Ok(());
        }
        let dst = stage_dir.join(DATA_DIRNAME);
        if dst.exists() {
            std::fs::remove_dir_all(&dst)?;
        }
        copy_dir_recursive(&src, &dst)?;
        tracing::info!("preserved Bitwarden vault (Data) across update");
        Ok(())
    }

    fn hardening(&self) -> Hardening {
        // Bitwarden is not hardened the way a browser is — it has no curated
        // flag set, user.js, or profile prefs. An empty LaunchFlags payload
        // means the pipeline injects nothing.
        Hardening::LaunchFlags {
            flags: &[],
            local_state: None,
            preferences: None,
        }
    }

    fn launch_command(&self, install_dir: &Path, args: &[String]) -> Command {
        // The vault/userData lives at <install_dir>/Data, carried across updates
        // by preserve_state_across_update (the swap replaces install_dir).
        let appdata = install_dir.join(DATA_DIRNAME);

        let mut cmd = Command::new(install_dir.join(EXECUTABLE));
        cmd.env("BITWARDEN_APPDATA_DIR", &appdata);
        cmd.env("ELECTRON_NO_UPDATER", "1");
        cmd.args(args);
        cmd
    }

    fn upstream_url(&self) -> &'static str {
        "https://bitwarden.com"
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use httpmock::prelude::*;

    use super::super::{github, write_version_marker};
    use super::*;

    /// A releases-list fixture mirroring the real multi-product repo: a newer
    /// browser-extension release first (which `releases/latest` would wrongly
    /// return), then the desktop release with installer/portable/appx assets.
    fn fixture_releases() -> String {
        format!(
            r#"[
                {{
                    "tag_name": "browser-v2026.5.1",
                    "prerelease": false,
                    "assets": [
                        {{"name": "dist-chrome.zip",
                         "browser_download_url": "https://example.invalid/dist-chrome.zip",
                         "digest": "sha256:{ext}"}}
                    ]
                }},
                {{
                    "tag_name": "desktop-v2026.5.0",
                    "prerelease": false,
                    "assets": [
                        {{"name": "Bitwarden-Installer-2026.5.0.exe",
                         "browser_download_url": "https://example.invalid/Bitwarden-Installer-2026.5.0.exe",
                         "digest": "sha256:{installer}"}},
                        {{"name": "Bitwarden-Portable-2026.5.0.exe",
                         "browser_download_url": "https://example.invalid/Bitwarden-Portable-2026.5.0.exe",
                         "digest": "sha256:{portable}"}},
                        {{"name": "Bitwarden-2026.5.0-x64.appx",
                         "browser_download_url": "https://example.invalid/Bitwarden-2026.5.0-x64.appx",
                         "digest": "sha256:{appx}"}}
                    ]
                }}
            ]"#,
            ext = "e".repeat(64),
            installer = "a".repeat(64),
            portable = "b".repeat(64),
            appx = "c".repeat(64),
        )
    }

    #[tokio::test]
    async fn fetch_latest_skips_other_products_and_picks_desktop_portable() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(fixture_releases());
        });
        let bw = Bitwarden::for_test(server.url("/releases"));
        let info = bw.fetch_latest_version().await.unwrap();

        // Must skip the newer browser-v release and pick the desktop one.
        assert_eq!(
            info.browser_version, "2026.5.0",
            "desktop-v release selected and prefix stripped"
        );
        assert_eq!(info.engine_version, "2026.5.0");
        assert!(
            info.download_url.contains("Portable"),
            "must select the portable .exe, got {}",
            info.download_url
        );
        assert!(
            !info.download_url.contains("Installer"),
            "must not select the installer stub"
        );
        assert!(
            !info.download_url.contains(".appx"),
            "must not select the appx"
        );
        assert!(
            !info.download_url.contains("dist-chrome"),
            "must not select a browser-extension asset"
        );
        assert_eq!(info.sha256.as_deref(), Some("b".repeat(64).as_str()));
        assert!(info.signature_url.is_none(), "Bitwarden ships no GPG sig");
    }

    #[tokio::test]
    async fn fetch_latest_errors_when_no_desktop_release() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(r#"[{"tag_name": "browser-v2026.5.1", "prerelease": false, "assets": []}]"#);
        });
        let bw = Bitwarden::for_test(server.url("/releases"));
        let err = bw.fetch_latest_version().await.unwrap_err();
        assert!(matches!(err, BrowserError::Parse(_)));
    }

    #[test]
    fn latest_desktop_release_skips_prereleases() {
        let releases = vec![
            github::Release {
                tag_name: "desktop-v2026.6.0-beta".to_owned(),
                prerelease: true,
                published_at: None,
                assets: vec![],
            },
            github::Release {
                tag_name: "desktop-v2026.5.0".to_owned(),
                prerelease: false,
                published_at: None,
                assets: vec![],
            },
        ];
        let r = latest_desktop_release(&releases).unwrap();
        assert_eq!(
            r.tag_name, "desktop-v2026.5.0",
            "must skip the prerelease and pick the latest stable desktop release"
        );
    }

    #[test]
    fn fetch_latest_errors_when_desktop_release_has_no_portable() {
        let releases = vec![github::Release {
            tag_name: "desktop-v2026.5.0".to_owned(),
            prerelease: false,
            published_at: None,
            assets: vec![github::ReleaseAsset {
                name: "Bitwarden-Installer-2026.5.0.exe".to_owned(),
                browser_download_url: "https://example.invalid/i.exe".to_owned(),
                digest: Some(format!("sha256:{}", "a".repeat(64))),
                created_at: None,
                updated_at: None,
            }],
        }];
        let release = latest_desktop_release(&releases).unwrap();
        let err = portable_asset(release).unwrap_err();
        assert!(matches!(err, BrowserError::Parse(_)));
    }

    #[test]
    fn default_config_parses_and_targets_app_dir() {
        // The trimmed default must parse under the strict (deny_unknown_fields)
        // config structs and select the App install dir.
        let bw = Bitwarden::new(Arch::X64);
        let cfg = crate::config::Config::parse(bw.default_config())
            .expect("Bitwarden default config must parse");
        assert_eq!(cfg.browser.install_dir, std::path::PathBuf::from("App"));
        // The inert browser-only key *assignments* are omitted (the prose
        // comment may still mention them, so match the `key =` form).
        let text = bw.default_config();
        for key in ["disable_webrtc =", "incognito =", "reduce_system_info ="] {
            assert!(
                !text.contains(key),
                "inert browser-only key `{key}` must be omitted from the Bitwarden config"
            );
        }
    }

    #[test]
    fn metadata_is_stable() {
        let bw = Bitwarden::new(Arch::X64);
        assert_eq!(bw.id(), "bitwarden");
        assert_eq!(bw.display_name(), "Bitwarden");
        assert_eq!(bw.engine(), Engine::Electron);
        assert!(
            bw.public_key().is_none(),
            "Bitwarden publishes no GPG key (SHA-256 + Authenticode only)"
        );
    }

    #[test]
    fn launch_command_sets_portable_env_and_targets_staged_exe() {
        let bw = Bitwarden::new(Arch::X64);
        let install = Path::new("C:/nomad/App");
        let cmd = bw.launch_command(install, &[]);

        assert!(
            Path::new(cmd.get_program()).ends_with(EXECUTABLE),
            "must launch the staged portable exe"
        );

        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let appdata = envs
            .iter()
            .find(|(k, _)| k == "BITWARDEN_APPDATA_DIR")
            .expect("BITWARDEN_APPDATA_DIR must be set")
            .1
            .clone()
            .expect("BITWARDEN_APPDATA_DIR must have a value");
        assert!(
            envs.iter()
                .any(|(k, v)| k == "ELECTRON_NO_UPDATER" && v.as_deref() == Some("1")),
            "ELECTRON_NO_UPDATER=1 must be set to disable the built-in updater"
        );

        // The vault dir sits INSIDE install_dir at <install_dir>/Data; it
        // survives updates via preserve_state_across_update (see that test).
        let appdata_path = Path::new(&appdata);
        assert!(
            appdata_path.starts_with(install),
            "vault appdata ({appdata}) must be inside install_dir ({})",
            install.display()
        );
        assert_eq!(appdata_path, install.join(DATA_DIRNAME));
    }

    #[test]
    fn preserve_state_across_update_copies_vault_into_stage() {
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("App");
        let stage = dir.path().join("App.stage");
        // Live install with a vault and the new staged binary (no Data yet).
        std::fs::create_dir_all(current.join(DATA_DIRNAME)).unwrap();
        std::fs::write(current.join(DATA_DIRNAME).join("data.json"), b"vault").unwrap();
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join(EXECUTABLE), b"new binary").unwrap();

        let bw = Bitwarden::new(Arch::X64);
        bw.preserve_state_across_update(&current, &stage).unwrap();

        assert_eq!(
            std::fs::read(stage.join(DATA_DIRNAME).join("data.json")).unwrap(),
            b"vault",
            "the vault must be copied onto the staged install before the swap"
        );
        // Source must remain intact (copy, not move).
        assert!(current.join(DATA_DIRNAME).join("data.json").exists());
    }

    #[test]
    fn preserve_state_across_update_is_noop_on_fresh_install() {
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("App"); // no Data dir
        let stage = dir.path().join("App.stage");
        std::fs::create_dir_all(&stage).unwrap();
        let bw = Bitwarden::new(Arch::X64);
        // Must not error when there is no prior vault to carry over.
        bw.preserve_state_across_update(&current, &stage).unwrap();
        assert!(!stage.join(DATA_DIRNAME).exists());
    }

    #[test]
    fn stage_executable_stages_under_stable_name() {
        // Tests the staging step directly (extract() additionally gates on a
        // real Authenticode signature, which a fixture file cannot carry).
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let download = stage.join("Bitwarden-Portable-2026.5.0.exe");
        std::fs::write(&download, b"MZ portable exe bytes").unwrap();

        stage_executable(&download, &stage).unwrap();

        let staged = stage.join(EXECUTABLE);
        assert!(
            staged.exists(),
            "portable exe must be staged under {EXECUTABLE}"
        );
        assert_eq!(
            std::fs::read(&staged).unwrap(),
            b"MZ portable exe bytes",
            "staged bytes must match the download"
        );
    }

    #[cfg(windows)]
    #[test]
    fn extract_rejects_unsigned_executable() {
        // The Authenticode gate must reject a file not signed by Bitwarden Inc.
        // (here, not signed at all).
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let download = stage.join("Bitwarden-Portable-2026.5.0.exe");
        std::fs::write(&download, b"MZ not a real signed binary").unwrap();

        let bw = Bitwarden::new(Arch::X64);
        let err = bw
            .extract(&download, &stage)
            .expect_err("an unsigned executable must be rejected by extract()");
        assert!(matches!(err, BrowserError::Verification(_)));
        assert!(
            !stage.join(EXECUTABLE).exists(),
            "an unverified exe must not be staged"
        );
    }

    #[test]
    fn installed_version_reads_the_nomad_marker() {
        let dir = tempfile::tempdir().unwrap();
        let bw = Bitwarden::new(Arch::X64);
        assert!(bw.installed_version(dir.path()).is_none());
        let marker = InstalledVersion {
            browser_version: "2026.5.0".to_owned(),
            engine_version: "2026.5.0".to_owned(),
        };
        write_version_marker(dir.path(), &marker).unwrap();
        assert_eq!(bw.installed_version(dir.path()), Some(marker));
    }
}
