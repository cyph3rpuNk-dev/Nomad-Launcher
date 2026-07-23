//! [`BrowserFamily`] implementation for Floorp.
//!
//! Floorp is a Firefox-based browser distributed via GitHub releases.
//! Releases are verified via the GitHub-recorded SHA-256 digest on each asset.

use std::path::Path;
use std::process::Command;

use super::{
    github, read_version_marker, BrowserError, BrowserFamily, Engine, Hardening, InstalledVersion,
    ProgressSink, Result, VersionInfo,
};
use crate::config::Arch;

/// Curated safe user.js payload — shared with Firefox (both are Gecko).
const USER_JS: &str = include_str!("../../payloads/firefox/user.js");

/// Distribution-level policies.json — shared with Firefox (LibreWolf-derived, MPL-2.0).
const POLICIES_JSON: &str = include_str!("../../payloads/firefox/policies.json");

/// Autoconfig pointer — shared with Firefox.
const AUTOCONFIG_JS: &str = include_str!("../../payloads/firefox/autoconfig.js");

/// Main `lockPref()` payload — shared with Firefox.
const NOMAD_CFG: &str = include_str!("../../payloads/firefox/nomad.cfg");

const API_URL: &str = "https://api.github.com/repos/floorp-projects/floorp/releases/latest";

// Floorp no longer ships a portable .zip since v12.x; the NSIS installer
// is run silently with /S /D=<path>.  SHA-256 is sourced from hashes.txt.
const EXECUTABLE: &str = "floorp.exe";

fn installer_asset_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X64 => "floorp-windows-x86_64.installer.exe",
        Arch::X86 => "floorp-windows-x86.installer.exe",
        Arch::Arm64 => "floorp-windows-aarch64.installer.exe",
    }
}

fn hashes_txt_key(arch: Arch) -> &'static str {
    match arch {
        Arch::X64 => "win-dist/floorp-windows-x86_64.installer.exe",
        Arch::X86 => "win-dist/floorp-windows-x86.installer.exe",
        Arch::Arm64 => "win-dist/floorp-windows-aarch64.installer.exe",
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parses `SHA256: <hex> - <key>` lines from Floorp's `hashes.txt`, returning
/// the hash for `key` if present.
fn parse_hashes_txt(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        // Format: "SHA256: <hex> - <path>"
        if let Some(rest) = line.trim().strip_prefix("SHA256:") {
            if let Some((hex, path)) = rest.trim().split_once(" - ") {
                if path.trim() == key {
                    return Some(hex.trim().to_owned());
                }
            }
        }
    }
    None
}

// ── Public types ──────────────────────────────────────────────────────────────

/// Floorp browser family.
pub struct Floorp {
    arch: Arch,
    /// Overridable for unit tests; points at the GitHub releases API.
    api_url: String,
}

impl Floorp {
    /// Creates a launcher pointing at the production GitHub releases API.
    #[must_use]
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            api_url: API_URL.to_owned(),
        }
    }

    /// Creates a launcher pointing at a custom API endpoint.
    ///
    /// Used by tests to redirect all requests at a mock server.
    #[cfg(test)]
    fn for_test(arch: Arch, api_url: impl Into<String>) -> Self {
        Self {
            arch,
            api_url: api_url.into(),
        }
    }
}

// ── BrowserFamily impl ────────────────────────────────────────────────────────

impl BrowserFamily for Floorp {
    fn id(&self) -> &'static str {
        "floorp"
    }

    fn display_name(&self) -> &'static str {
        "Floorp"
    }

    fn engine(&self) -> Engine {
        Engine::Gecko
    }

    fn public_key(&self) -> Option<&'static [u8]> {
        None
    }

    fn installed_version(&self, install_dir: &Path) -> Option<InstalledVersion> {
        read_version_marker(install_dir)
    }

    async fn fetch_latest_version(&self) -> Result<VersionInfo> {
        let client = github::build_client()?;
        let release = github::fetch_release(&client, &self.api_url).await?;
        let version = release.tag_name.trim_start_matches('v').to_owned();

        // Floorp no longer ships a .zip; find the installer asset URL.
        let installer_name = installer_asset_name(self.arch);
        let installer_asset = release
            .assets
            .iter()
            .find(|a| a.name == installer_name)
            .ok_or_else(|| {
                BrowserError::Parse(format!(
                    "no Windows installer asset '{installer_name}' in release v{version}"
                ))
            })?;
        let download_url = installer_asset.browser_download_url.clone();

        // SHA-256 comes from hashes.txt published alongside the release.
        let hashes_url = release
            .assets
            .iter()
            .find(|a| a.name == "hashes.txt")
            .map(|a| a.browser_download_url.clone());
        let sha256 = match hashes_url {
            Some(url) => {
                let bytes = github::fetch_raw(&client, &url).await?;
                let text = String::from_utf8_lossy(&bytes);
                parse_hashes_txt(&text, hashes_txt_key(self.arch))
            }
            None => None,
        };

        Ok(VersionInfo {
            browser_version: version.clone(),
            engine_version: version,
            download_url,
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
        // Never called: public_key() returns None.
        Ok(())
    }

    fn extract(&self, package: &Path, install_dir: &Path) -> Result<()> {
        crate::extract::extract_nsis_with_7zip(package, install_dir, EXECUTABLE)?;
        crate::extract::strip_mozilla_runtime_extras(install_dir);
        Ok(())
    }

    fn hardening(&self) -> Hardening {
        Hardening::GeckoProfile {
            user_js: USER_JS,
            policies: Some(POLICIES_JSON),
            autoconfig: Some(AUTOCONFIG_JS),
            cfg: Some(NOMAD_CFG),
            ublock_xpi_releases_url: Some(super::UBLOCK_RELEASES_URL),
        }
    }

    fn profile_dir(&self, install_dir: &Path) -> Option<std::path::PathBuf> {
        install_dir.parent().map(|base| base.join("Data"))
    }

    fn launch_command(&self, install_dir: &Path, args: &[String]) -> Command {
        let profile_dir = self
            .profile_dir(install_dir)
            .unwrap_or_else(|| install_dir.join("profile"));
        let mut cmd = Command::new(install_dir.join(EXECUTABLE));
        cmd.arg("--profile").arg(profile_dir);
        // --no-remote deliberately absent: per-profile remoting (Firefox 67+)
        // lets a second invocation open its URL as a tab in the running
        // instance — required for the default-browser flow (SPEC §10).
        cmd.env("MOZ_CRASHREPORTER_DISABLE", "1");
        cmd.env("MOZ_LEGACY_PROFILES", "1");
        cmd.args(args);
        cmd
    }

    fn upstream_url(&self) -> &'static str {
        "https://floorp.app/en/download/"
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use httpmock::prelude::*;

    use super::super::{write_version_marker, BrowserError, InstalledVersion};
    use super::*;

    fn browser_for_server(server: &MockServer, arch: Arch) -> Floorp {
        Floorp::for_test(arch, server.url("/latest"))
    }

    fn release_json(tag: &str, installer_url: &str, hashes_url: Option<&str>) -> String {
        let hashes_asset = match hashes_url {
            Some(url) => {
                format!(r#",{{"name":"hashes.txt","browser_download_url":"{url}","digest":null}}"#)
            }
            None => String::new(),
        };
        format!(
            r#"{{"tag_name":"{tag}","assets":[{{"name":"floorp-windows-x86_64.installer.exe","browser_download_url":"{installer_url}","digest":null}}{hashes_asset}]}}"#
        )
    }

    #[tokio::test]
    async fn fetch_latest_parses_version_and_sha256() {
        let server = MockServer::start();
        let installer_url = server.url("/floorp.exe");
        let hashes_url = server.url("/hashes.txt");
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(release_json("v12.1.0", &installer_url, Some(&hashes_url)));
        });
        server.mock(|when, then| {
            when.method(GET).path("/hashes.txt");
            then.status(200).body(
                "SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
                 - win-dist/floorp-windows-x86_64.installer.exe\n",
            );
        });
        let browser = browser_for_server(&server, Arch::X64);
        let info = browser.fetch_latest_version().await.unwrap();
        assert_eq!(info.browser_version, "12.1.0", "v prefix must be stripped");
        assert_eq!(info.engine_version, "12.1.0");
        assert_eq!(info.download_url, installer_url);
        assert_eq!(
            info.sha256.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[tokio::test]
    async fn fetch_latest_no_sha256_when_no_hashes_txt() {
        let server = MockServer::start();
        let installer_url = server.url("/floorp.exe");
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(release_json("v12.1.0", &installer_url, None));
        });
        let browser = browser_for_server(&server, Arch::X64);
        let info = browser.fetch_latest_version().await.unwrap();
        assert_eq!(info.browser_version, "12.1.0");
        assert!(info.sha256.is_none());
    }

    #[tokio::test]
    async fn fetch_fails_when_no_installer_asset() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(r#"{"tag_name": "v12.1.0", "assets": []}"#);
        });
        let browser = browser_for_server(&server, Arch::X64);
        let err = browser.fetch_latest_version().await.unwrap_err();
        assert!(matches!(err, BrowserError::Parse(_)));
    }

    #[test]
    fn profile_dir_is_beside_install_dir() {
        let browser = Floorp::new(Arch::X64);
        let install = Path::new("C:/nomad/Floorp");
        let profile = browser.profile_dir(install).unwrap();
        assert_eq!(profile, Path::new("C:/nomad/Data"));
    }

    #[test]
    fn launch_command_includes_profile_and_extra_args() {
        let browser = Floorp::new(Arch::X64);
        let install = Path::new("C:/nomad/Floorp");
        let cmd = browser.launch_command(install, &["--safe-mode".to_owned()]);
        let args: Vec<_> = cmd.get_args().collect();
        assert!(
            !args.contains(&std::ffi::OsStr::new("--no-remote")),
            "--no-remote must be absent so a clicked URL opens as a tab in the running instance"
        );
        let profile_idx = args
            .iter()
            .position(|a| *a == "--profile")
            .expect("--profile must be present");
        assert!(
            profile_idx + 1 < args.len(),
            "--profile must be followed by a path"
        );
        assert!(args.last().unwrap().to_string_lossy().contains("safe-mode"));
    }

    #[test]
    fn hardening_returns_gecko_profile_with_payloads() {
        let browser = Floorp::new(Arch::X64);
        let Hardening::GeckoProfile {
            user_js,
            policies,
            autoconfig,
            cfg,
            ..
        } = browser.hardening()
        else {
            panic!("Floorp must return GeckoProfile hardening");
        };
        assert!(!user_js.is_empty(), "user_js payload must not be empty");
        assert!(policies.is_some(), "Floorp must include policies.json");
        assert!(
            autoconfig.is_some(),
            "Floorp must include the autoconfig pointer"
        );
        assert!(cfg.is_some(), "Floorp must include the nomad.cfg payload");
    }

    #[test]
    fn metadata_is_stable() {
        let browser = Floorp::new(Arch::X64);
        assert_eq!(browser.id(), "floorp");
        assert_eq!(browser.display_name(), "Floorp");
        assert_eq!(browser.engine(), Engine::Gecko);
        assert!(browser.public_key().is_none());
    }

    #[test]
    fn installed_version_reads_nomad_marker() {
        let dir = tempfile::tempdir().unwrap();
        let browser = Floorp::new(Arch::X64);
        assert!(browser.installed_version(dir.path()).is_none());
        let marker = InstalledVersion {
            browser_version: "11.5.0".to_owned(),
            engine_version: "11.5.0".to_owned(),
        };
        write_version_marker(dir.path(), &marker).unwrap();
        assert_eq!(browser.installed_version(dir.path()), Some(marker));
    }
}
