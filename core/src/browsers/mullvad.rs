//! [`BrowserFamily`] implementation for Mullvad Browser (Windows builds).
//!
//! Mullvad Browser is a collaboration between Mullvad VPN and the Tor Project,
//! built on top of Tor Browser with Tor networking removed. It is designed for
//! use with a trustworthy VPN and focuses on crowd-blending: all users present
//! an identical fingerprint.
//!
//! Updates are resolved from the GitHub releases API of the
//! `mullvad/mullvad-browser` repository. Each release carries a detached GPG
//! signature (`.asc`) created by the Tor Browser Developers signing key
//! (fingerprint `EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290`).
//!
//! ## Hardening philosophy — defer everything to the browser
//!
//! Mullvad ships RFP, letterboxing, standardised UA/timezone/fonts, `uBlock
//! Origin`, and `NoScript` pre-configured. Applying Nomad's standard arkenfox
//! `user.js` or `policies.json` would break Mullvad's anonymity-set model by
//! making individual users distinguishable from the crowd. Nomad therefore
//! writes **no `user.js`** and only the single policy key Mullvad does not
//! handle itself: `DisableAppUpdate` (Nomad is the sole updater).
//!
//! ## Profile layout
//!
//! Like Tor Browser, Mullvad stores its profile inside the installation tree
//! (no `%APPDATA%` writes), so the entire `Browser/` + `Data/` tree is
//! portable to a USB drive without modification.

use std::path::Path;
use std::process::Command;

use super::{
    github, read_version_marker, BrowserError, BrowserFamily, Engine, Hardening, InstalledVersion,
    ProgressSink, Result, VersionInfo,
};
use crate::config::Arch;

/// Tor Browser Developers ASCII-armored GPG public key.
///
/// Fingerprint: `EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290`
/// Mullvad Browser releases are signed by the Tor Project with this key.
static MULLVAD_KEY: &[u8] = include_bytes!("../../keys/mullvad.asc");

/// Key fingerprint verified in tests against the embedded `mullvad.asc`.
#[cfg(test)]
const MULLVAD_KEY_FINGERPRINT: &str = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290";

/// Minimal `policies.json` for Mullvad: only `DisableAppUpdate` (Nomad is the
/// updater). All other privacy/security policy is handled by Mullvad itself.
const POLICIES_JSON: &str = include_str!("../../payloads/mullvad/policies.json");

/// GitHub releases API endpoint for Mullvad Browser.
const DEFAULT_RELEASES_URL: &str =
    "https://api.github.com/repos/mullvad/mullvad-browser/releases/latest";

/// Launchable executable inside a Mullvad Browser install directory.
const EXECUTABLE: &str = "mullvadbrowser.exe";

/// Mullvad Browser family.
pub struct Mullvad {
    arch: Arch,
    releases_url: String,
}

impl Mullvad {
    /// Creates a launcher targeting the given build architecture.
    #[must_use]
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            releases_url: DEFAULT_RELEASES_URL.to_owned(),
        }
    }

    /// Creates a launcher pointing at a custom releases endpoint.
    ///
    /// Used by tests to redirect update checks at a mock server.
    #[cfg(test)]
    fn for_test(arch: Arch, releases_url: impl Into<String>) -> Self {
        Self {
            arch,
            releases_url: releases_url.into(),
        }
    }
}

/// Returns the architecture token used in Mullvad's asset names.
///
/// Mullvad only publishes x64 Windows builds; x86 and arm64 are not supported.
fn arch_asset_name(arch: Arch, version: &str) -> Result<String> {
    match arch {
        Arch::X64 => Ok(format!("mullvad-browser-windows-x86_64-{version}.exe")),
        Arch::X86 | Arch::Arm64 => Err(BrowserError::Parse(
            "Mullvad Browser only publishes x64 Windows builds; \
             configure arch = \"x64\""
                .to_owned(),
        )),
    }
}

impl BrowserFamily for Mullvad {
    fn id(&self) -> &'static str {
        "mullvad"
    }

    fn display_name(&self) -> &'static str {
        "Mullvad Browser"
    }

    fn engine(&self) -> Engine {
        Engine::Gecko
    }

    fn public_key(&self) -> Option<&'static [u8]> {
        if MULLVAD_KEY.is_empty() {
            None
        } else {
            Some(MULLVAD_KEY)
        }
    }

    fn installed_version(&self, install_dir: &Path) -> Option<InstalledVersion> {
        read_version_marker(install_dir)
    }

    async fn fetch_latest_version(&self) -> Result<VersionInfo> {
        let client = github::build_client()?;
        let release = github::fetch_release(&client, &self.releases_url).await?;

        // Mullvad tags look like "15.0.14" (no leading 'v').
        let version = release.tag_name.trim_start_matches('v').to_owned();
        let asset_name = arch_asset_name(self.arch, &version)?;

        let asset = release
            .assets
            .iter()
            .find(|a| a.name == asset_name)
            .ok_or_else(|| {
                BrowserError::Parse(format!(
                    "no asset named {asset_name} in release {}",
                    release.tag_name
                ))
            })?;

        let sig_name = format!("{asset_name}.asc");
        let signature_url = release
            .assets
            .iter()
            .find(|a| a.name == sig_name)
            .map(|a| a.browser_download_url.clone());

        let sha256 = asset
            .digest
            .as_deref()
            .and_then(|d| d.strip_prefix("sha256:"))
            .map(str::to_owned);

        Ok(VersionInfo {
            browser_version: version.clone(),
            engine_version: version,
            download_url: asset.browser_download_url.clone(),
            signature_url,
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

    fn verify_signature(&self, package: &Path, sig: &Path) -> Result<()> {
        crate::gpg::verify(package, sig, MULLVAD_KEY)
            .map_err(|e| BrowserError::Verification(e.to_string()))
    }

    fn extract(&self, package: &Path, install_dir: &Path) -> Result<()> {
        crate::extract::extract_nsis_with_7zip(package, install_dir, EXECUTABLE)?;
        // Strip Mozilla auxiliary executables that write %LOCALAPPDATA%\Mozilla\
        // before policies.json is read (AUDIT CRIT-03).
        crate::extract::strip_mozilla_runtime_extras(install_dir);
        // Mullvad also ships postupdate.exe (post-install hook) which is not
        // needed in a Nomad-managed portable install.
        let _ = std::fs::remove_file(install_dir.join("postupdate.exe"));
        Ok(())
    }

    fn hardening(&self) -> Hardening {
        // Mullvad ships its own comprehensive hardening (RFP, letterboxing,
        // standardised UA/timezone/fonts, uBO, NoScript). Nomad does not apply
        // a user.js — any prefs would break Mullvad's crowd-blending model by
        // making individual users distinguishable. The only policy key written
        // is DisableAppUpdate (Nomad is the sole updater).
        Hardening::GeckoProfile {
            user_js: "",
            policies: Some(POLICIES_JSON),
            autoconfig: None,
            cfg: None,
            ublock_xpi_releases_url: None, // Mullvad ships uBO pre-installed
        }
    }

    /// Mullvad ships full RFP, letterboxing, and a complete anti-fingerprinting
    /// framework (inherited from Tor Browser). Signal this so the core runner
    /// defers all fingerprint-related decisions to the browser.
    fn has_builtin_fingerprint_noise(&self) -> bool {
        true
    }

    fn profile_dir(&self, install_dir: &Path) -> Option<std::path::PathBuf> {
        // Profile sits inside Data/ beside the Browser/ install dir — Nomad's
        // standard portable layout. Using a fixed path ("Profile") rather than
        // Mullvad's installer-generated random prefix (e.g. texv0wrt.default-release).
        install_dir
            .parent()
            .map(|base| base.join("Data").join("Profile"))
    }

    fn launch_command(&self, install_dir: &Path, args: &[String]) -> Command {
        let profile_dir = self
            .profile_dir(install_dir)
            .unwrap_or_else(|| install_dir.join("profile"));
        let mut cmd = Command::new(install_dir.join(EXECUTABLE));
        cmd.arg("--profile").arg(&profile_dir);
        cmd.arg("--no-remote");
        // Mullvad requires MOZ_CRASHREPORTER_DISABLE to suppress the crash
        // reporter process that would write to the host system.
        cmd.env("MOZ_CRASHREPORTER_DISABLE", "1");
        cmd.args(args);
        cmd
    }

    fn upstream_url(&self) -> &'static str {
        "https://github.com/mullvad/mullvad-browser/releases"
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use httpmock::prelude::*;

    use super::super::{write_version_marker, BrowserError, InstalledVersion};
    use super::*;

    fn fixture_release(tag: &str) -> String {
        let exe = format!("mullvad-browser-windows-x86_64-{tag}.exe");
        let asc = format!("{exe}.asc");
        let digest = format!("sha256:{}", "a".repeat(64));
        format!(
            r#"{{
                "tag_name": "{tag}",
                "assets": [
                    {{
                        "name": "{exe}",
                        "browser_download_url": "https://example.invalid/{exe}",
                        "digest": "{digest}"
                    }},
                    {{
                        "name": "{asc}",
                        "browser_download_url": "https://example.invalid/{asc}",
                        "digest": null
                    }}
                ]
            }}"#
        )
    }

    fn browser_for_server(server: &MockServer) -> Mullvad {
        Mullvad::for_test(Arch::X64, server.url("/latest"))
    }

    #[tokio::test]
    async fn fetch_latest_parses_version_url_sha256_and_sig() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(fixture_release("15.0.14"));
        });
        let browser = browser_for_server(&server);
        let info = browser.fetch_latest_version().await.unwrap();
        assert_eq!(info.browser_version, "15.0.14");
        assert_eq!(info.engine_version, "15.0.14");
        assert_eq!(info.sha256.as_deref(), Some("a".repeat(64).as_str()));
        assert!(
            info.signature_url.is_some(),
            "detached .asc must be resolved as signature_url"
        );
        assert!(
            info.download_url.contains("x86_64-15.0.14.exe"),
            "download URL must reference the x64 exe asset"
        );
    }

    #[tokio::test]
    async fn fetch_latest_strips_v_prefix_when_present() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(fixture_release("v15.0.14").replace("v15.0.14", "15.0.14"));
            // tag has v, assets don't
        });
        // Simulate tag with leading 'v'
        let body = r#"{
            "tag_name": "v15.0.14",
            "assets": [
                {
                    "name": "mullvad-browser-windows-x86_64-15.0.14.exe",
                    "browser_download_url": "https://example.invalid/mullvad-browser-windows-x86_64-15.0.14.exe",
                    "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                }
            ]
        }"#;
        let server2 = MockServer::start();
        server2.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(body);
        });
        let browser = Mullvad::for_test(Arch::X64, server2.url("/latest"));
        let info = browser.fetch_latest_version().await.unwrap();
        assert_eq!(info.browser_version, "15.0.14", "v prefix must be stripped");
    }

    #[tokio::test]
    async fn fetch_fails_for_unsupported_arch() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(fixture_release("15.0.14"));
        });
        let browser = Mullvad::for_test(Arch::X86, server.url("/latest"));
        let err = browser.fetch_latest_version().await.unwrap_err();
        assert!(
            matches!(err, BrowserError::Parse(_)),
            "x86 arch must return a Parse error"
        );
    }

    #[tokio::test]
    async fn fetch_returns_offline_error_on_connection_failure() {
        let browser = Mullvad::for_test(Arch::X64, "http://127.0.0.1:1/latest");
        let err = browser.fetch_latest_version().await.unwrap_err();
        assert!(
            matches!(err, BrowserError::Offline(_)),
            "connection refused must produce BrowserError::Offline"
        );
    }

    #[test]
    fn installed_version_reads_the_nomad_marker() {
        let dir = tempfile::tempdir().unwrap();
        let browser = Mullvad::new(Arch::X64);
        assert!(browser.installed_version(dir.path()).is_none());
        let marker = InstalledVersion {
            browser_version: "15.0.14".to_owned(),
            engine_version: "15.0.14".to_owned(),
        };
        write_version_marker(dir.path(), &marker).unwrap();
        assert_eq!(browser.installed_version(dir.path()), Some(marker));
    }

    #[test]
    fn profile_dir_is_inside_data_beside_install_dir() {
        let browser = Mullvad::new(Arch::X64);
        let install = Path::new("C:/nomad/mullvad/Browser");
        let profile = browser.profile_dir(install).unwrap();
        assert_eq!(profile, Path::new("C:/nomad/mullvad/Data/Profile"));
    }

    #[test]
    fn launch_command_includes_profile_no_remote_and_env() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        std::fs::create_dir_all(&install).unwrap();
        let browser = Mullvad::new(Arch::X64);
        let cmd = browser.launch_command(&install, &["--safe-mode".to_owned()]);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|a| a == "--no-remote"));
        assert!(args.iter().any(|a| a == "--profile"));
        assert!(args.last().unwrap().contains("safe-mode"));
    }

    #[test]
    fn hardening_returns_gecko_profile_with_empty_user_js_and_minimal_policies() {
        let browser = Mullvad::new(Arch::X64);
        let Hardening::GeckoProfile {
            user_js,
            policies,
            autoconfig,
            cfg,
            ublock_xpi_releases_url,
        } = browser.hardening()
        else {
            panic!("Mullvad must return GeckoProfile hardening");
        };
        assert_eq!(
            user_js, "",
            "user_js must be empty — Mullvad manages its own prefs"
        );
        assert!(
            policies.is_some(),
            "DisableAppUpdate policy must be present"
        );
        assert!(
            autoconfig.is_none(),
            "Mullvad does not need Nomad's autoconfig"
        );
        assert!(cfg.is_none());
        assert!(
            ublock_xpi_releases_url.is_none(),
            "Mullvad ships uBO pre-installed — Nomad must not provision it"
        );
    }

    #[test]
    fn has_builtin_fingerprint_noise_returns_true() {
        let browser = Mullvad::new(Arch::X64);
        assert!(
            browser.has_builtin_fingerprint_noise(),
            "Mullvad ships RFP + letterboxing — must defer fingerprinting to the browser"
        );
    }

    #[test]
    fn metadata_is_stable() {
        let browser = Mullvad::new(Arch::X64);
        assert_eq!(browser.id(), "mullvad");
        assert_eq!(browser.display_name(), "Mullvad Browser");
        assert_eq!(browser.engine(), Engine::Gecko);
        assert!(
            browser.public_key().is_some(),
            "Tor Project signing key must be embedded"
        );
    }

    #[test]
    fn embedded_key_matches_expected_fingerprint() {
        use pgp::composed::Deserializable;
        use pgp::types::KeyDetails;
        let cursor = std::io::Cursor::new(MULLVAD_KEY);
        let (iter, _) = pgp::composed::SignedPublicKey::from_armor_many(cursor).unwrap();
        let mut found = false;
        for key in iter.flatten() {
            let fp = hex::encode_upper(key.primary_key.fingerprint().as_bytes());
            if fp.eq_ignore_ascii_case(MULLVAD_KEY_FINGERPRINT) {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "embedded mullvad.asc must contain key with fingerprint {MULLVAD_KEY_FINGERPRINT}"
        );
    }
}
