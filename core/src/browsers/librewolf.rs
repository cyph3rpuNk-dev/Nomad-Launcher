//! [`BrowserFamily`] implementation for `LibreWolf`.
//!
//! `LibreWolf` is a privacy-focused fork of Firefox maintained by the `LibreWolf`
//! Community. Unlike upstream Firefox, it publishes an **official portable
//! `.zip`** alongside the installer at `dl.librewolf.net`, so extraction is
//! the same flat ZIP unpack used by ungoogled-chromium — no NSIS, no MSI.
//!
//! Version metadata comes from the `bsys6` `Codeberg` releases API (Gitea-
//! compatible JSON with the same shape as GitHub's), while the download
//! itself lives on the `LibreWolf` CDN. Integrity is verified via the
//! `sha256sums.txt` file published in each release directory.

use std::path::Path;
use std::process::Command;

use super::{
    github, read_version_marker, BrowserError, BrowserFamily, Engine, Hardening, InstalledVersion,
    ProgressSink, Result, VersionInfo,
};
use crate::config::Arch;

/// `LibreWolf`-specific minimal `user.js`. `LibreWolf` already ships
/// arkenfox-equivalent hardening (telemetry locked off, Safe Browsing off,
/// Strict ETP, RFP on, HTTPS-only, disk cache off, …), so the full Firefox
/// profile is almost entirely redundant there — many prefs are `lockPref`'d in
/// `librewolf.cfg` and cannot be overridden. This payload keeps only the
/// genuine additions `LibreWolf` does not make itself (notably `DoH`, which it
/// ships off). See the file header for the full rationale.
const USER_JS: &str = include_str!("../../payloads/librewolf/user.js");

/// Reuse Firefox's distribution-level `policies.json`. `LibreWolf` reads
/// `distribution/policies.json` the same way as upstream Firefox.
const POLICIES_JSON: &str = include_str!("../../payloads/firefox/policies.json");

/// `Codeberg` Gitea API endpoint for the `LibreWolf` build-system releases.
/// Returns the same JSON shape as GitHub's `releases/latest` endpoint.
const API_URL: &str = "https://codeberg.org/api/v1/repos/librewolf/bsys6/releases/latest";

/// CDN base where each release directory lives:
/// `<base>/<tag>/librewolf-<tag>-windows-<arch>-portable.zip`.
const CDN_BASE: &str = "https://dl.librewolf.net/librewolf";

const EXECUTABLE: &str = "librewolf.exe";

fn arch_token(arch: Arch) -> Result<&'static str> {
    match arch {
        Arch::X64 => Ok("x86_64"),
        Arch::Arm64 => Ok("arm64"),
        Arch::X86 => Err(BrowserError::Parse(
            "LibreWolf has no 32-bit Windows build; configure arch = \"x64\" or \"arm64\""
                .to_owned(),
        )),
    }
}

/// Parses a `sha256sums.txt` entry of the form `<hex>  <filename>` and returns
/// the hash for `key`, or `None` if absent.
fn parse_sha256sums(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        // Standard sha256sum format: "<64-hex>  <filename>" (two spaces).
        if let Some((hex, name)) = line.split_once("  ") {
            if name.trim() == key {
                return Some(hex.trim().to_owned());
            }
        }
    }
    None
}

/// `LibreWolf` browser family.
pub struct Librewolf {
    arch: Arch,
    /// Overridable for unit tests; points at the `Codeberg` releases API.
    api_url: String,
    /// Overridable for unit tests; CDN base URL for release directories.
    cdn_base: String,
}

impl Librewolf {
    /// Creates a launcher pointing at the production endpoints.
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

impl BrowserFamily for Librewolf {
    fn id(&self) -> &'static str {
        "librewolf"
    }

    fn display_name(&self) -> &'static str {
        "LibreWolf"
    }

    fn engine(&self) -> Engine {
        Engine::Gecko
    }

    fn public_key(&self) -> Option<&'static [u8]> {
        // LibreWolf signs releases (`.sig` files exist alongside each asset)
        // but the project does not publish a stable GPG signing key in a form
        // suitable for compile-time embedding. SHA-256 from sha256sums.txt
        // provides the integrity floor.
        None
    }

    fn installed_version(&self, install_dir: &Path) -> Option<InstalledVersion> {
        read_version_marker(install_dir)
    }

    async fn fetch_latest_version(&self) -> Result<VersionInfo> {
        let client = github::build_client()?;
        let release = github::fetch_release(&client, &self.api_url).await?;

        // LibreWolf tags are like "151.0-1" (no "v" prefix in current releases,
        // but strip one defensively in case the convention changes).
        let version = release.tag_name.trim_start_matches('v').to_owned();
        let arch = arch_token(self.arch)?;
        let asset_name = format!("librewolf-{version}-windows-{arch}-portable.zip");
        let download_url = format!("{}/{version}/{asset_name}", self.cdn_base);

        // Fetch and parse the sha256sums.txt published in the same release dir.
        let sums_url = format!("{}/{version}/sha256sums.txt", self.cdn_base);
        let sha256 = match github::fetch_raw(&client, &sums_url).await {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                parse_sha256sums(&text, &asset_name)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not fetch LibreWolf sha256sums.txt; integrity unverified"
                );
                None
            }
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
        crate::extract::extract_zip(package, install_dir)?;

        // LibreWolf's "portable" .zip is a PortableApps-style bundle: the
        // actual browser binary is nested under a `LibreWolf/` directory and
        // the archive root holds their own wrapper launcher, updater, and
        // task-scheduler scripts. Strip the wrappers, drop the empty
        // `Profiles/` root, then promote `LibreWolf/*` up so the layout
        // matches every other Gecko browser in the suite.
        for junk in [
            "LibreWolf-Portable.exe",
            "LibreWolf-WinUpdater.exe",
            "ScheduledTask-Create.ps1",
            "ScheduledTask-Remove.ps1",
        ] {
            let _ = std::fs::remove_file(install_dir.join(junk));
        }
        let _ = std::fs::remove_dir_all(install_dir.join("Profiles"));
        crate::extract::promote_subdir(install_dir, "LibreWolf")?;

        // Defensive: LibreWolf disables most Mozilla helpers at build time,
        // but they may still ship some of the auxiliary binaries. Strip the
        // ones that would otherwise spawn host-system traces.
        crate::extract::strip_mozilla_runtime_extras(install_dir);
        Ok(())
    }

    fn hardening(&self) -> Hardening {
        Hardening::GeckoProfile {
            user_js: USER_JS,
            policies: Some(POLICIES_JSON),
            // LibreWolf ships its own `defaults/pref/local-settings.js` +
            // `librewolf.cfg` autoconfig pair in the official portable .zip.
            // Skip writing ours to avoid clobbering theirs.
            autoconfig: None,
            cfg: None,
            // LibreWolf's FAQ says "we include uBlockOrigin in the browser",
            // but that applies to the .exe installer build (which fetches uBO
            // from AMO during install). The portable ZIP at dl.librewolf.net
            // ships no uBlock files, no system addons, and no first-run
            // bootstrap. Provision the AMO-signed XPI ourselves so portable
            // LibreWolf has the same out-of-the-box experience as the
            // installer build.
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
        "https://librewolf.net/"
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use httpmock::prelude::*;

    use super::super::{write_version_marker, BrowserError, InstalledVersion};
    use super::*;

    /// SHA-256 hex fixture (64 lowercase hex chars).
    const FIXTURE_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn browser_for_server(server: &MockServer, arch: Arch) -> Librewolf {
        Librewolf::for_test(arch, server.url("/api/latest"), server.url("/cdn"))
    }

    fn release_json(tag: &str) -> String {
        format!(r#"{{"tag_name":"{tag}","assets":[]}}"#)
    }

    fn sha256sums_body(version: &str, arch: &str) -> String {
        format!(
            "{FIXTURE_SHA256}  librewolf-{version}-windows-{arch}-portable.zip\n\
             {FIXTURE_SHA256}  librewolf-{version}-windows-{arch}-setup.exe\n"
        )
    }

    #[tokio::test]
    async fn fetch_latest_constructs_cdn_url_and_parses_sha256() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(release_json("151.0-1"));
        });
        server.mock(|when, then| {
            when.method(GET).path("/cdn/151.0-1/sha256sums.txt");
            then.status(200)
                .header("Content-Type", "text/plain")
                .body(sha256sums_body("151.0-1", "x86_64"));
        });

        let browser = browser_for_server(&server, Arch::X64);
        let info = browser.fetch_latest_version().await.unwrap();

        assert_eq!(info.browser_version, "151.0-1");
        assert_eq!(info.engine_version, "151.0-1");
        assert_eq!(info.sha256.as_deref(), Some(FIXTURE_SHA256));
        assert!(info.signature_url.is_none());
        assert!(
            info.download_url.contains("/151.0-1/"),
            "URL must include the version directory"
        );
        assert!(
            info.download_url.contains("windows-x86_64-portable.zip"),
            "URL must point at the x86_64 portable zip"
        );
    }

    #[tokio::test]
    async fn fetch_latest_picks_arm64_asset_when_arch_is_arm64() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/latest");
            then.status(200).body(release_json("151.0-1"));
        });
        server.mock(|when, then| {
            when.method(GET).path("/cdn/151.0-1/sha256sums.txt");
            then.status(200).body(sha256sums_body("151.0-1", "arm64"));
        });

        let browser = browser_for_server(&server, Arch::Arm64);
        let info = browser.fetch_latest_version().await.unwrap();
        assert!(info.download_url.contains("windows-arm64-portable.zip"));
        assert_eq!(info.sha256.as_deref(), Some(FIXTURE_SHA256));
    }

    #[tokio::test]
    async fn fetch_latest_rejects_x86_arch() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/latest");
            then.status(200).body(release_json("151.0-1"));
        });

        let browser = browser_for_server(&server, Arch::X86);
        let err = browser.fetch_latest_version().await.unwrap_err();
        assert!(matches!(err, BrowserError::Parse(_)));
    }

    #[tokio::test]
    async fn fetch_latest_sha256_is_none_when_sums_file_missing() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/latest");
            then.status(200).body(release_json("151.0-1"));
        });
        // No mock for sha256sums.txt — server returns 404, scrub returns None.

        let browser = browser_for_server(&server, Arch::X64);
        let info = browser.fetch_latest_version().await.unwrap();
        assert!(info.sha256.is_none());
    }

    #[tokio::test]
    async fn fetch_latest_strips_v_prefix_when_present() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/latest");
            then.status(200).body(release_json("v151.0-1"));
        });
        server.mock(|when, then| {
            when.method(GET).path("/cdn/151.0-1/sha256sums.txt");
            then.status(200).body(sha256sums_body("151.0-1", "x86_64"));
        });

        let browser = browser_for_server(&server, Arch::X64);
        let info = browser.fetch_latest_version().await.unwrap();
        assert_eq!(info.browser_version, "151.0-1", "v prefix must be stripped");
    }

    #[test]
    fn parse_sha256sums_extracts_correct_entry() {
        let body = "abc123  librewolf-151.0-1-windows-x86_64-portable.zip\n\
                    def456  librewolf-151.0-1-windows-x86_64-setup.exe\n";
        let hash = parse_sha256sums(body, "librewolf-151.0-1-windows-x86_64-portable.zip").unwrap();
        assert_eq!(hash, "abc123");
    }

    #[test]
    fn parse_sha256sums_returns_none_for_missing_entry() {
        let body = "abc  some-other-file.zip\n";
        assert!(parse_sha256sums(body, "librewolf-151.0-1-windows-x86_64-portable.zip").is_none());
    }

    #[test]
    fn profile_dir_is_beside_install_dir() {
        let browser = Librewolf::new(Arch::X64);
        let install = std::path::Path::new("C:/nomad/LibreWolf");
        let profile = browser.profile_dir(install).unwrap();
        assert_eq!(profile, std::path::Path::new("C:/nomad/Data"));
    }

    #[test]
    fn launch_command_includes_profile_no_remote_and_env_vars() {
        let browser = Librewolf::new(Arch::X64);
        let cmd = browser.launch_command(
            std::path::Path::new("C:/nomad/LibreWolf"),
            &["--safe-mode".to_owned()],
        );
        let args: Vec<_> = cmd.get_args().collect();
        assert!(
            args.iter().any(|a| *a == "--no-remote"),
            "--no-remote must be present"
        );
        assert!(
            args.iter().any(|a| *a == "--profile"),
            "--profile must be present"
        );
        assert!(
            args.last().unwrap().to_string_lossy().contains("safe-mode"),
            "extra args must be forwarded"
        );
    }

    #[test]
    fn user_js_is_the_minimal_librewolf_profile_not_the_shared_firefox_one() {
        // Guards against accidentally re-pointing USER_JS at firefox/user.js.
        // The minimal profile keeps DoH (LibreWolf's biggest gap) but must NOT
        // re-assert prefs LibreWolf already locks/defaults (telemetry, Safe
        // Browsing, fingerprintingProtection — RFP subsumes it).
        assert!(
            USER_JS.contains("network.trr.mode"),
            "minimal LibreWolf profile must still enable DoH"
        );
        assert!(
            USER_JS.contains("https://dns.quad9.net/dns-query"),
            "DoH must target Quad9's malware-blocking endpoint (Safe-Browsing substitute)"
        );
        assert!(
            !USER_JS.contains("dns10.quad9.net") && !USER_JS.contains("dns11.quad9.net"),
            "must not use a Quad9 No-Filtering endpoint"
        );
        assert!(
            !USER_JS.contains("toolkit.telemetry.enabled"),
            "telemetry prefs are lockPref'd in librewolf.cfg — must not be duplicated"
        );
        assert!(
            !USER_JS.contains("browser.safebrowsing"),
            "LibreWolf disables Safe Browsing itself — must not be duplicated"
        );
        assert!(
            !USER_JS.contains("privacy.fingerprintingProtection"),
            "LibreWolf ships RFP, which subsumes FPP — must not be set"
        );
        assert!(
            !USER_JS.contains("privacy.trackingprotection.enabled"),
            "LibreWolf ships Strict ETP — tracking-protection prefs are redundant"
        );
    }

    #[test]
    fn hardening_returns_gecko_profile_with_payloads() {
        let browser = Librewolf::new(Arch::X64);
        let Hardening::GeckoProfile {
            user_js,
            policies,
            autoconfig,
            cfg,
            ublock_xpi_releases_url,
        } = browser.hardening()
        else {
            panic!("LibreWolf must return GeckoProfile hardening");
        };
        assert!(!user_js.is_empty());
        assert!(policies.is_some());
        assert!(
            autoconfig.is_none() && cfg.is_none(),
            "LibreWolf ships its own autoconfig pair; ours must not be set"
        );
        assert!(
            ublock_xpi_releases_url.is_some(),
            "portable LibreWolf does not bundle uBlock; provisioning must be enabled"
        );
    }

    #[test]
    fn metadata_is_stable() {
        let browser = Librewolf::new(Arch::X64);
        assert_eq!(browser.id(), "librewolf");
        assert_eq!(browser.display_name(), "LibreWolf");
        assert_eq!(browser.engine(), Engine::Gecko);
        assert!(browser.public_key().is_none());
    }

    #[test]
    fn installed_version_reads_nomad_marker() {
        let dir = tempfile::tempdir().unwrap();
        let browser = Librewolf::new(Arch::X64);
        assert!(browser.installed_version(dir.path()).is_none());
        let marker = InstalledVersion {
            browser_version: "151.0-1".to_owned(),
            engine_version: "151.0-1".to_owned(),
        };
        write_version_marker(dir.path(), &marker).unwrap();
        assert_eq!(browser.installed_version(dir.path()), Some(marker));
    }
}
