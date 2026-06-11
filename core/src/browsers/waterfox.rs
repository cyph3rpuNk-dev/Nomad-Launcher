//! [`BrowserFamily`] implementation for Waterfox.
//!
//! Waterfox is a Firefox-based browser distributed via GitHub releases.
//! Releases are verified via a SHA-512 checksum file published by the Waterfox
//! CDN beside each installer (e.g. `Waterfox Setup 6.6.13.exe.sha512`).

use std::path::Path;
use std::process::Command;

use super::{
    github, read_version_marker, BrowserFamily, Engine, Hardening, InstalledVersion, ProgressSink,
    Result, VersionInfo,
};
use crate::config::Arch;

/// Curated safe user.js payload for Waterfox (ESR 115 Gecko engine).
const USER_JS: &str = include_str!("../../payloads/waterfox/user.js");

/// Distribution-level policies.json — shared with Firefox (LibreWolf-derived, MPL-2.0).
const POLICIES_JSON: &str = include_str!("../../payloads/firefox/policies.json");

/// Autoconfig pointer — shared with Firefox.
const AUTOCONFIG_JS: &str = include_str!("../../payloads/firefox/autoconfig.js");

/// Main `lockPref()` payload — shared with Firefox.
const NOMAD_CFG: &str = include_str!("../../payloads/firefox/nomad.cfg");

// Waterfox GitHub repo (BrowserWorks org; no binary assets on GitHub —
// version tag is used to construct the CDN download URL below).
const API_URL: &str = "https://api.github.com/repos/BrowserWorks/waterfox/releases/latest";

// Waterfox distributes via their own CDN.  No portable .zip is available;
// the NSIS installer is never run — it is unpacked with the embedded 7-Zip
// (extract_nsis_with_7zip; AUDIT CRIT-02 forbids executing installers).
const CDN_BASE: &str = "https://cdn.waterfox.com/waterfox/releases";

const EXECUTABLE: &str = "Waterfox.exe";

fn arch_dir(arch: Arch) -> &'static str {
    match arch {
        Arch::X64 => "WINNT_x86_64",
        Arch::X86 => "WINNT_x86",
        Arch::Arm64 => "WINNT_aarch64",
    }
}

// ── Public types ──────────────────────────────────────────────────────────────

/// Waterfox browser family.
pub struct Waterfox {
    arch: Arch,
    /// Overridable for unit tests; points at the GitHub releases API.
    api_url: String,
    /// Overridable for unit tests; points at the Waterfox CDN base.
    cdn_base: String,
}

impl Waterfox {
    /// Creates a launcher pointing at the production GitHub releases API.
    #[must_use]
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            api_url: API_URL.to_owned(),
            cdn_base: CDN_BASE.to_owned(),
        }
    }

    /// Creates a launcher pointing at custom API and CDN endpoints.
    ///
    /// Used by tests to redirect all requests at a mock server.
    #[cfg(test)]
    fn for_test(arch: Arch, api_url: impl Into<String>, cdn_base: impl Into<String>) -> Self {
        Self {
            arch,
            api_url: api_url.into(),
            cdn_base: cdn_base.into(),
        }
    }
}

/// Fetches a `.sha512` checksum file from `url` and returns the hex digest,
/// or `None` on any network or parse failure.
///
/// The file may be a bare 128-character hex string or a standard checksum
/// line (`<hash>  <filename>`); we take the first whitespace-delimited token.
async fn fetch_sha512(client: &reqwest::Client, url: &str) -> Option<String> {
    let text = client
        .get(url)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .text()
        .await
        .ok()?;
    let hash = text.split_whitespace().next()?.to_ascii_lowercase();
    // A SHA-512 hex digest is exactly 128 characters.
    if hash.len() == 128 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hash)
    } else {
        tracing::warn!(url, len = hash.len(), "unexpected SHA-512 hash length");
        None
    }
}

// ── BrowserFamily impl ────────────────────────────────────────────────────────

impl BrowserFamily for Waterfox {
    fn id(&self) -> &'static str {
        "waterfox"
    }

    fn display_name(&self) -> &'static str {
        "Waterfox"
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
        let raw_tag = &release.tag_name;
        let version = raw_tag.trim_start_matches(['G', 'v']).to_owned();
        let dir = arch_dir(self.arch);
        let cdn = &self.cdn_base;
        let download_url = format!("{cdn}/{version}/{dir}/Waterfox%20Setup%20{version}.exe");
        // Waterfox CDN publishes a SHA-512 checksum file beside each installer.
        // The file contains the hex digest (optionally followed by whitespace and
        // the filename). Parse the first whitespace-delimited token.
        let sha512_url = format!("{download_url}.sha512");
        let sha512 = fetch_sha512(&client, &sha512_url).await;
        if sha512.is_none() {
            tracing::warn!(
                version,
                "could not fetch Waterfox SHA-512 checksum; integrity unverified"
            );
        }
        Ok(VersionInfo {
            browser_version: version.clone(),
            engine_version: version,
            download_url,
            signature_url: None,
            sha256: None,
            sha512,
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
        cmd.arg("--no-remote");
        cmd.env("MOZ_CRASHREPORTER_DISABLE", "1");
        cmd.env("MOZ_LEGACY_PROFILES", "1");
        cmd.args(args);
        cmd
    }

    fn upstream_url(&self) -> &'static str {
        "https://www.waterfox.net/releases/"
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use httpmock::prelude::*;

    use super::super::{write_version_marker, BrowserError, InstalledVersion};
    use super::*;

    fn browser_for_server(server: &MockServer, arch: Arch) -> Waterfox {
        Waterfox::for_test(arch, server.url("/latest"), server.url(""))
    }

    /// SHA-512 hex fixture — 128 lowercase hex chars.
    const FIXTURE_SHA512: &str = "73269b2404d126ee3aac21794e5438ae38e0ac2fcb2e12c0ad9f2167a6b524de\
         d0badf4021a5359b2ee266f22036941facbf1b7023f805c8b5ddbf63d453078c";

    #[tokio::test]
    async fn fetch_latest_constructs_cdn_url_and_fetches_sha512() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(r#"{"tag_name": "G6.0.20", "assets": []}"#);
        });
        // Serve the SHA-512 checksum file from the mock CDN.
        server.mock(|when, then| {
            when.method(GET)
                .path_contains("Waterfox%20Setup%206.0.20.exe.sha512");
            then.status(200)
                .header("Content-Type", "text/plain")
                .body(FIXTURE_SHA512);
        });
        let browser = browser_for_server(&server, Arch::X64);
        let info = browser.fetch_latest_version().await.unwrap();
        assert_eq!(info.browser_version, "6.0.20");
        assert_eq!(info.engine_version, "6.0.20");
        assert!(info.sha256.is_none());
        assert_eq!(info.sha512.as_deref(), Some(FIXTURE_SHA512));
        assert!(
            info.download_url.contains("/6.0.20/"),
            "version without G prefix"
        );
        assert!(info.download_url.contains("WINNT_x86_64"), "x64 arch dir");
        assert!(
            info.download_url.contains("Waterfox%20Setup"),
            "installer filename"
        );
    }

    #[tokio::test]
    async fn fetch_latest_sha512_none_when_checksum_unavailable() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(r#"{"tag_name": "G6.0.20", "assets": []}"#);
        });
        // No .sha512 mock — server returns 404 for that path.
        let browser = browser_for_server(&server, Arch::X64);
        let info = browser.fetch_latest_version().await.unwrap();
        assert!(
            info.sha512.is_none(),
            "sha512 must be None when checksum file is unavailable"
        );
    }

    #[tokio::test]
    async fn fetch_strips_v_prefix_from_tag() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(r#"{"tag_name": "v6.0.20", "assets": []}"#);
        });
        let browser = browser_for_server(&server, Arch::X64);
        let info = browser.fetch_latest_version().await.unwrap();
        assert_eq!(info.browser_version, "6.0.20", "v prefix must be stripped");
    }

    #[tokio::test]
    async fn fetch_fails_on_api_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(404);
        });
        let browser = browser_for_server(&server, Arch::X64);
        let err = browser.fetch_latest_version().await.unwrap_err();
        assert!(matches!(err, BrowserError::Network(_)));
    }

    #[test]
    fn profile_dir_is_beside_install_dir() {
        let browser = Waterfox::new(Arch::X64);
        let install = Path::new("C:/nomad/Waterfox");
        let profile = browser.profile_dir(install).unwrap();
        assert_eq!(profile, Path::new("C:/nomad/Data"));
    }

    #[test]
    fn launch_command_includes_profile_and_extra_args() {
        let browser = Waterfox::new(Arch::X64);
        let install = Path::new("C:/nomad/Waterfox");
        let cmd = browser.launch_command(install, &["--safe-mode".to_owned()]);
        let args: Vec<_> = cmd.get_args().collect();
        assert!(
            args.contains(&std::ffi::OsStr::new("--no-remote")),
            "--no-remote must be present"
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
        let browser = Waterfox::new(Arch::X64);
        let Hardening::GeckoProfile {
            user_js,
            policies,
            autoconfig,
            cfg,
            ..
        } = browser.hardening()
        else {
            panic!("Waterfox must return GeckoProfile hardening");
        };
        assert!(!user_js.is_empty(), "user_js payload must not be empty");
        assert!(policies.is_some(), "Waterfox must include policies.json");
        assert!(
            autoconfig.is_some(),
            "Waterfox must include autoconfig pointer"
        );
        assert!(cfg.is_some(), "Waterfox must include nomad.cfg payload");
    }

    #[test]
    fn metadata_is_stable() {
        let browser = Waterfox::new(Arch::X64);
        assert_eq!(browser.id(), "waterfox");
        assert_eq!(browser.display_name(), "Waterfox");
        assert_eq!(browser.engine(), Engine::Gecko);
        assert!(browser.public_key().is_none());
    }

    #[test]
    fn installed_version_reads_nomad_marker() {
        let dir = tempfile::tempdir().unwrap();
        let browser = Waterfox::new(Arch::X64);
        assert!(browser.installed_version(dir.path()).is_none());
        let marker = InstalledVersion {
            browser_version: "G6.0.20".to_owned(),
            engine_version: "G6.0.20".to_owned(),
        };
        write_version_marker(dir.path(), &marker).unwrap();
        assert_eq!(browser.installed_version(dir.path()), Some(marker));
    }
}
