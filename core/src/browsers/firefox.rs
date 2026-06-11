//! [`BrowserFamily`] implementations for Firefox stable and Firefox ESR.
//!
//! Versions are resolved from the Mozilla Product Details API. Integrity is
//! established via a two-step chain: the SHA256SUMS manifest is GPG-verified
//! against the embedded Mozilla Software Releases key (when present), and the
//! downloaded package is then SHA-256-verified against the hash parsed from
//! that manifest. No per-package detached signature is fetched.

use std::path::Path;
use std::process::Command;

use serde::Deserialize;

use super::{
    github::map_network_err, read_version_marker, BrowserError, BrowserFamily, Engine, Hardening,
    InstalledVersion, ProgressSink, Result, VersionInfo,
};
use crate::config::Arch;

/// Mozilla Software Releases ASCII-armored GPG public key.
///
/// Populated at compile time from `core/keys/firefox.asc`. The file ships as
/// an empty placeholder; replace it with the official key before release.
/// When the file is empty, GPG verification is skipped and a warning is logged
/// (see SPEC §9).
static FIREFOX_KEY: &[u8] = include_bytes!("../../keys/firefox.asc");

/// Curated safe user.js payload (arkenfox-derived, SPEC §5).
const USER_JS: &str = include_str!("../../payloads/firefox/user.js");

/// LibreWolf-derived `distribution/policies.json` (MPL-2.0).
const POLICIES_JSON: &str = include_str!("../../payloads/firefox/policies.json");

/// Autoconfig pointer written to `defaults/pref/autoconfig.js`.
const AUTOCONFIG_JS: &str = include_str!("../../payloads/firefox/autoconfig.js");

/// Main `lockPref()` payload written to `install_dir/nomad.cfg`. Derived
/// verbatim from `LibreWolf`'s `librewolf.cfg` v8.6 (MPL-2.0); see the file
/// header for attribution.
const NOMAD_CFG: &str = include_str!("../../payloads/firefox/nomad.cfg");

const PRODUCT_DETAILS_URL: &str = "https://product-details.mozilla.org/1.0/firefox_versions.json";

const RELEASES_BASE_URL: &str = "https://releases.mozilla.org/pub/firefox/releases";

const EXECUTABLE: &str = "firefox.exe";

// ── Public types ──────────────────────────────────────────────────────────────

/// Whether to track the stable or ESR release channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Firefox stable.
    Stable,
    /// Firefox Extended Support Release.
    Esr,
}

/// Firefox (stable or ESR) browser family.
pub struct Firefox {
    arch: Arch,
    channel: Channel,
    /// Overridable for unit tests; points at the product-details JSON.
    product_details_url: String,
    /// Overridable for unit tests; base URL for release tarballs and checksums.
    releases_base_url: String,
    /// Set by `for_test` to skip GPG verification (no valid signed fixture).
    skip_gpg: bool,
}

impl Firefox {
    /// Creates a launcher for the Firefox stable channel.
    #[must_use]
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            channel: Channel::Stable,
            product_details_url: PRODUCT_DETAILS_URL.to_owned(),
            releases_base_url: RELEASES_BASE_URL.to_owned(),
            skip_gpg: false,
        }
    }

    /// Creates a launcher for the Firefox ESR channel.
    #[must_use]
    pub fn new_esr(arch: Arch) -> Self {
        Self {
            arch,
            channel: Channel::Esr,
            product_details_url: PRODUCT_DETAILS_URL.to_owned(),
            releases_base_url: RELEASES_BASE_URL.to_owned(),
            skip_gpg: false,
        }
    }

    /// Creates a launcher pointing at custom endpoints.
    ///
    /// Used by tests to redirect all requests at a mock server.
    /// GPG verification is skipped because test fixtures are not GPG-signed.
    #[must_use]
    pub fn for_test(
        arch: Arch,
        channel: Channel,
        product_details_url: impl Into<String>,
        releases_base_url: impl Into<String>,
    ) -> Self {
        Self {
            arch,
            channel,
            product_details_url: product_details_url.into(),
            releases_base_url: releases_base_url.into(),
            skip_gpg: true,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns the Mozilla release-tree directory for `arch`, e.g. `"win64"`
/// for x86-64.
fn arch_dir(arch: Arch) -> &'static str {
    match arch {
        Arch::X64 => "win64",
        Arch::X86 => "win32",
        Arch::Arm64 => "win64-aarch64",
    }
}

/// Builds the expected SHA256SUMS entry path for the given version and arch.
///
/// Example: `"win64/en-US/Firefox Setup 138.0.exe"`. The NSIS `.exe` is
/// extracted as a plain archive by the bundled 7-Zip console — it is never
/// executed, so no shortcuts, registry entries, or `%PROGRAMDATA%`/
/// `%LOCALAPPDATA%` directories are created. (The MSI variant would also be
/// trace-free via `msiexec /a`, but that requires elevation on Win10/11.)
fn sums_entry(version: &str, arch: Arch) -> String {
    let dir = arch_dir(arch);
    format!("{dir}/en-US/Firefox Setup {version}.exe")
}

/// Finds and returns the SHA-256 hex string for `entry` in a SHA256SUMS file.
///
/// Each line of the file has the format `<sha256hex>  <path>` (two spaces).
///
/// # Errors
/// Returns [`BrowserError::Parse`] when the file is not valid UTF-8 or when
/// the expected entry is absent.
fn parse_sha256sums(sums: &[u8], entry: &str) -> Result<String> {
    let text = std::str::from_utf8(sums)
        .map_err(|e| BrowserError::Parse(format!("SHA256SUMS is not valid UTF-8: {e}")))?;
    for line in text.lines() {
        if let Some((hash, path)) = line.split_once("  ") {
            if path.trim() == entry {
                return Ok(hash.trim().to_owned());
            }
        }
    }
    Err(BrowserError::Parse(format!(
        "SHA256SUMS has no entry for '{entry}'"
    )))
}

/// Builds a `reqwest` client with the Nomad user-agent.
fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("nomad-portable")
        .build()
        .map_err(|e| BrowserError::Network(e.to_string()))
}

/// Fetches `url` as raw bytes using `client`.
async fn fetch_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    client
        .get(url)
        .send()
        .await
        .map_err(map_network_err)?
        .error_for_status()
        .map_err(map_network_err)?
        .bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(map_network_err)
}

/// Fetches `url` as a UTF-8 string using `client`.
async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String> {
    client
        .get(url)
        .send()
        .await
        .map_err(map_network_err)?
        .error_for_status()
        .map_err(map_network_err)?
        .text()
        .await
        .map_err(map_network_err)
}

// ── Product-details response ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct FirefoxVersions {
    #[serde(rename = "LATEST_FIREFOX_VERSION")]
    latest: String,
    #[serde(rename = "FIREFOX_ESR")]
    esr: String,
}

// ── BrowserFamily impl ────────────────────────────────────────────────────────

impl BrowserFamily for Firefox {
    fn id(&self) -> &'static str {
        match self.channel {
            Channel::Stable => "firefox",
            Channel::Esr => "firefox-esr",
        }
    }

    fn display_name(&self) -> &'static str {
        match self.channel {
            Channel::Stable => "Firefox",
            Channel::Esr => "Firefox ESR",
        }
    }

    fn engine(&self) -> Engine {
        Engine::Gecko
    }

    fn public_key(&self) -> Option<&'static [u8]> {
        // GPG verification is done inside fetch_latest_version (SHA256SUMS is
        // verified, then the per-package SHA-256 is parsed from it). The
        // standard verify_package path is SHA-256-only from here.
        None
    }

    fn installed_version(&self, install_dir: &Path) -> Option<InstalledVersion> {
        read_version_marker(install_dir)
    }

    async fn fetch_latest_version(&self) -> Result<VersionInfo> {
        let client = build_client()?;

        // 1. Resolve version from product-details API.
        let body = fetch_text(&client, &self.product_details_url).await?;
        let versions: FirefoxVersions =
            serde_json::from_str(&body).map_err(|e| BrowserError::Parse(e.to_string()))?;
        let version = match self.channel {
            Channel::Stable => versions.latest,
            Channel::Esr => versions.esr,
        };

        // 2. Derive URLs. We download the NSIS `.exe` and extract it with the
        //    bundled 7-Zip console (`extract_nsis_with_7zip`) — never run it.
        //    This avoids the elevation requirement of `msiexec /a` while still
        //    producing a fully trace-free install.
        let dir = arch_dir(self.arch);
        let base = format!("{}/{version}", self.releases_base_url);
        let entry = sums_entry(&version, self.arch);
        let download_url = format!("{base}/{dir}/en-US/Firefox%20Setup%20{version}.exe");

        // 3. Fetch SHA256SUMS.
        let sums = fetch_bytes(&client, &format!("{base}/SHA256SUMS")).await?;

        // 4. GPG-verify SHA256SUMS when the key is embedded and we're not in a test context.
        if self.skip_gpg || FIREFOX_KEY.is_empty() {
            if FIREFOX_KEY.is_empty() {
                tracing::warn!(
                    browser = self.id(),
                    "Firefox GPG key not embedded; relying on SHA-256 only (see core/keys/firefox.asc)"
                );
            }
        } else {
            let sig = fetch_bytes(&client, &format!("{base}/SHA256SUMS.asc")).await?;
            crate::gpg::verify_bytes(&sums, &sig, FIREFOX_KEY)
                .map_err(|e| BrowserError::Verification(e.to_string()))?;
            tracing::debug!(browser = self.id(), "SHA256SUMS GPG signature verified");
        }

        // 5. Parse the SHA-256 for the specific package we'll download.
        let sha256 = parse_sha256sums(&sums, &entry)?;

        // 6. engine_version strips the "esr" suffix from the version string.
        let engine_version = version.trim_end_matches("esr").to_owned();

        Ok(VersionInfo {
            browser_version: version,
            engine_version,
            download_url,
            signature_url: None,
            sha256: Some(sha256),
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
        // Profile sits beside the launcher exe, not inside the install dir,
        // so it survives browser updates without losing user data.
        install_dir.parent().map(|base| base.join("Data"))
    }

    fn launch_command(&self, install_dir: &Path, args: &[String]) -> Command {
        // Profile dir is resolved the same way as profile_dir() so the
        // --profile argument matches what do_launch writes user.js into.
        let profile_dir = self
            .profile_dir(install_dir)
            .unwrap_or_else(|| install_dir.join("profile"));
        let mut cmd = Command::new(install_dir.join(EXECUTABLE));
        cmd.arg("--profile").arg(profile_dir);
        cmd.arg("--no-remote");
        cmd.env("MOZ_CRASHREPORTER_DISABLE", "1");
        // Disable Firefox 67+ dedicated-profile-per-install; without this the
        // browser writes an install marker into %LOCALAPPDATA%\Mozilla\Firefox\.
        cmd.env("MOZ_LEGACY_PROFILES", "1");
        cmd.args(args);
        cmd
    }

    fn upstream_url(&self) -> &'static str {
        match self.channel {
            Channel::Stable => "https://www.mozilla.org/en-US/firefox/notes/",
            Channel::Esr => "https://www.mozilla.org/en-US/firefox/organizations/notes/",
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use httpmock::prelude::*;

    use super::super::{write_version_marker, InstalledVersion};
    use super::*;

    const FIXTURE_VERSIONS: &str = r#"{
        "LATEST_FIREFOX_VERSION": "138.0",
        "FIREFOX_ESR": "128.11.0esr",
        "FIREFOX_DEVEDITION": "139.0b3"
    }"#;

    /// Minimal SHA256SUMS fixture with installer entries for all three archs.
    fn fixture_sha256sums(version: &str) -> String {
        let hash = "a".repeat(64);
        format!(
            "{hash}  win64/en-US/Firefox Setup {version}.exe\n\
             {hash}  win64-aarch64/en-US/Firefox Setup {version}.exe\n\
             {hash}  win32/en-US/Firefox Setup {version}.exe\n"
        )
    }

    fn start_mock_server(version: &str) -> MockServer {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/1.0/firefox_versions.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(FIXTURE_VERSIONS);
        });
        server.mock(|when, then| {
            when.method(GET)
                .path(format!("/releases/{version}/SHA256SUMS"));
            then.status(200).body(fixture_sha256sums(version));
        });
        server
    }

    fn browser_for_server(server: &MockServer, arch: Arch, channel: Channel) -> Firefox {
        Firefox::for_test(
            arch,
            channel,
            server.url("/1.0/firefox_versions.json"),
            server.url("/releases"),
        )
    }

    #[tokio::test]
    async fn fetch_latest_stable_parses_version_and_sha256() {
        let version = "138.0";
        let server = start_mock_server(version);
        let browser = browser_for_server(&server, Arch::X64, Channel::Stable);
        let info = browser
            .fetch_latest_version()
            .await
            .expect("stable version fetch must succeed");

        assert_eq!(info.browser_version, version);
        assert_eq!(info.engine_version, version);
        assert_eq!(
            info.sha256.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert!(info.signature_url.is_none());
        assert!(
            info.download_url.contains("win64/en-US"),
            "download URL must include the win64 path"
        );
    }

    #[tokio::test]
    async fn fetch_esr_strips_esr_suffix_from_engine_version() {
        let version = "128.11.0esr";
        let server = start_mock_server(version);
        let browser = browser_for_server(&server, Arch::X64, Channel::Esr);
        let info = browser
            .fetch_latest_version()
            .await
            .expect("ESR version fetch must succeed");

        assert_eq!(info.browser_version, version);
        assert_eq!(
            info.engine_version, "128.11.0",
            "esr suffix must be stripped"
        );
    }

    #[tokio::test]
    async fn fetch_fails_when_sha256sums_has_no_matching_entry() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/1.0/firefox_versions.json");
            then.status(200).body(FIXTURE_VERSIONS);
        });
        server.mock(|when, then| {
            when.method(GET).path("/releases/138.0/SHA256SUMS");
            then.status(200)
                .body("aaaa  linux64/en-US/firefox-138.0.tar.bz2\n");
        });
        let browser = browser_for_server(&server, Arch::X64, Channel::Stable);
        let err = browser
            .fetch_latest_version()
            .await
            .expect_err("missing SHA256SUMS entry must error");
        assert!(matches!(err, BrowserError::Parse(_)));
    }

    #[test]
    fn parse_sha256sums_extracts_correct_entry() {
        // Spaces in the file name must not confuse the two-space delimiter.
        let sums = "abc123  win64/en-US/Firefox Setup 138.0.exe\n\
                    def456  win32/en-US/Firefox Setup 138.0.exe\n";
        let hash =
            parse_sha256sums(sums.as_bytes(), "win64/en-US/Firefox Setup 138.0.exe").unwrap();
        assert_eq!(hash, "abc123");
    }

    #[test]
    fn parse_sha256sums_returns_error_for_missing_entry() {
        let sums = "abc123  other-platform/file.zip\n";
        let err =
            parse_sha256sums(sums.as_bytes(), "win64/en-US/Firefox Setup 138.0.exe").unwrap_err();
        assert!(matches!(err, BrowserError::Parse(_)));
    }

    #[test]
    fn arch_dir_maps_all_three_architectures() {
        assert_eq!(arch_dir(Arch::X64), "win64");
        assert_eq!(arch_dir(Arch::X86), "win32");
        assert_eq!(arch_dir(Arch::Arm64), "win64-aarch64");
    }

    #[test]
    fn profile_dir_is_beside_install_dir() {
        let browser = Firefox::new(Arch::X64);
        let install = Path::new("C:/nomad/Firefox");
        let profile = browser.profile_dir(install).unwrap();
        assert_eq!(profile, Path::new("C:/nomad/Data"));
    }

    #[test]
    fn esr_profile_dir_matches_stable_layout() {
        // ESR intentionally shares the stable launcher's sibling-`Data`
        // profile layout — each launcher lives in its own directory, so the
        // two never collide. The assertion documents that sharing is by
        // design, not an oversight.
        let browser = Firefox::new_esr(Arch::X64);
        let install = Path::new("C:/nomad/FirefoxESR");
        let profile = browser.profile_dir(install).unwrap();
        assert_eq!(profile, Path::new("C:/nomad/Data"));
    }

    #[test]
    fn launch_command_includes_profile_and_extra_args() {
        let browser = Firefox::new(Arch::X64);
        let install = Path::new("C:/nomad/Firefox");
        let cmd = browser.launch_command(install, &["--safe-mode".to_owned()]);
        let args: Vec<_> = cmd.get_args().collect();
        let profile_idx = args
            .iter()
            .position(|a| *a == "--profile")
            .expect("--profile must be present");
        assert!(
            profile_idx + 1 < args.len(),
            "--profile must be followed by a path"
        );
        assert!(
            args.contains(&std::ffi::OsStr::new("--no-remote")),
            "--no-remote must be present"
        );
        assert!(args.last().unwrap().to_string_lossy().contains("safe-mode"));
    }

    #[test]
    fn hardening_returns_gecko_profile_with_non_empty_user_js() {
        let browser = Firefox::new(Arch::X64);
        let Hardening::GeckoProfile {
            user_js,
            policies,
            autoconfig,
            cfg,
            ..
        } = browser.hardening()
        else {
            panic!("Firefox must return GeckoProfile hardening");
        };
        assert!(
            autoconfig.is_some(),
            "Firefox must ship an autoconfig pointer"
        );
        assert!(cfg.is_some(), "Firefox must ship a nomad.cfg payload");
        assert!(!user_js.is_empty(), "user_js payload must not be empty");
        assert!(
            user_js.contains("user_pref("),
            "user_js must contain preference calls"
        );
        assert!(
            user_js.contains("privacy.trackingprotection.allow_list.baseline.enabled\", true"),
            "Strict ETP must keep the baseline WebCompat allow-list on so major sites don't break"
        );
        let cfg = cfg.unwrap();
        assert!(
            cfg.contains("privacy.resistFingerprinting\", false"),
            "Firefox/Floorp must default RFP OFF and rely on FPP — RFP is site-breaking"
        );
        // nomad.cfg is LibreWolf-derived: its UI/About-dialog URL overrides must
        // be stripped so non-LibreWolf browsers don't link to LibreWolf. Guards
        // against an upstream re-sync silently re-introducing them. (Targets the
        // removed pref names, not a bare URL — a librewolf.* uBO-assets pref
        // legitimately keeps a codeberg URL and must not trip this.)
        assert!(
            !cfg.contains("app.support.baseURL")
                && !cfg.contains("app.releaseNotesURL")
                && !cfg.contains("support.librewolf.net"),
            "nomad.cfg must not point the UI/About dialog at LibreWolf"
        );
        assert!(policies.is_some(), "Firefox must include policies.json");
    }

    #[test]
    fn metadata_is_stable() {
        let stable = Firefox::new(Arch::X64);
        assert_eq!(stable.id(), "firefox");
        assert_eq!(stable.display_name(), "Firefox");
        assert_eq!(stable.engine(), Engine::Gecko);
        assert!(stable.public_key().is_none());

        let esr = Firefox::new_esr(Arch::X64);
        assert_eq!(esr.id(), "firefox-esr");
        assert_eq!(esr.display_name(), "Firefox ESR");
    }

    #[test]
    fn installed_version_reads_the_nomad_marker() {
        let dir = tempfile::tempdir().unwrap();
        let browser = Firefox::new(Arch::X64);
        assert!(browser.installed_version(dir.path()).is_none());

        let marker = InstalledVersion {
            browser_version: "138.0".to_owned(),
            engine_version: "138.0".to_owned(),
        };
        write_version_marker(dir.path(), &marker).unwrap();
        assert_eq!(browser.installed_version(dir.path()), Some(marker));
    }
}
