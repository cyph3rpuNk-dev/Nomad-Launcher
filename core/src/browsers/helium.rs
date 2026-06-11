//! [`BrowserFamily`] implementation for Helium (Windows builds).
//!
//! Helium is a privacy-hardened, ungoogled-chromium-based browser maintained
//! by Imput. Updates are resolved from the GitHub releases API of the
//! `imputnet/helium-windows` repository. Each release carries a GitHub-recorded
//! SHA-256 digest on each asset (see SPEC §9).
//!
//! **GPG status:** Imput does not publish a project-specific PGP signing key.
//! The key formerly embedded here (`968479A1AFF927E37D1A566BB5690EEEBB952194`)
//! is GitHub's platform web-flow commit-signing key, which cannot produce
//! detached signatures for release asset files. `core/keys/helium.asc` has been
//! emptied; `HELIUM_KEY.is_empty()` is `true`, so GPG verification is skipped
//! and integrity relies solely on the GitHub-recorded SHA-256 asset digest.

use std::path::Path;
use std::process::Command;

use super::{
    github, read_version_marker, BrowserError, BrowserFamily, Engine, Hardening, InstalledVersion,
    ProgressSink, Result, VersionInfo,
};
use crate::config::Arch;

/// Helium GPG public key slot (ASCII-armored).
///
/// Currently empty: Imput publishes no project-specific signing key. When
/// empty, `public_key()` returns `None`, no `.sig` URL is requested, and
/// integrity verification uses the SHA-256 GitHub asset digest only (SPEC §9).
static HELIUM_KEY: &[u8] = include_bytes!("../../keys/helium.asc");

/// GitHub releases API endpoint for Helium Windows builds.
const DEFAULT_RELEASES_URL: &str =
    "https://api.github.com/repos/imputnet/helium-windows/releases/latest";

/// Launchable executable inside a Helium install directory.
///
/// Helium inherits the Chromium build system's binary name.
const EXECUTABLE: &str = "chrome.exe";

/// Local State JSON shared with ungoogled-chromium — Helium uses the same
/// <chrome://flags> entries and DNS-over-HTTPS resolver.
const LOCAL_STATE: &str = include_str!("../../payloads/chromium/local_state.json");

/// Profile-level prefs shared with ungoogled-chromium (HTTPS-only, Privacy
/// Sandbox m1 off, Safe Browsing off, Do Not Track on, …).
const PREFERENCES: &str = include_str!("../../payloads/chromium/preferences.json");

/// `initial_preferences` template written next to `chrome.exe`.  Consulted by
/// Chromium only on first profile creation; the documented way to set
/// MAC-protected keys like `extensions.ui.developer_mode = true` without
/// triggering tracked-preference resets on established profiles.
const INITIAL_PREFERENCES: &str = include_str!("../../payloads/chromium/initial_preferences.json");

/// Curated "safe" privacy-hardening flags for Helium (SPEC §5).
///
/// Helium is ungoogled-chromium-based and accepts the same set of
/// ungoogled-chromium launch flags. These reduce tracking and fingerprinting
/// without breaking site functionality; potentially breaking switches
/// (e.g. `--disable-webgl`) are deliberately excluded.
const HARDENING_FLAGS: &[&str] = &[
    // ─── Portability (Windows-mandatory) ───────────────────────────
    // Without these two the profile is encrypted with the host OS user
    // credentials (DPAPI) and bound to the machine ID — both make it
    // non-portable to other machines (ungoogled-chromium-specific flags).
    "--disable-machine-id",
    "--disable-encryption",
    // ─── Stock Chromium privacy / portability hygiene ──────────────
    // NOTE: `--no-first-run` is deliberately omitted here. We append it
    // conditionally in `launch_command` only after
    // `default_apps_install_state == 3` is written to the profile.
    "--disable-sync",
    "--disable-background-networking",
    "--disable-breakpad",
    "--disable-component-update",
    // JumpList: prevents recently-visited site traces in the Windows taskbar.
    // DeviceBoundSessions: Chrome 146+ cryptographically binds sessions to the
    //   host device's TPM — directly conflicts with portability to other machines.
    "--disable-features=JumpList,DeviceBoundSessions",
    "--no-default-browser-check",
    "--disable-top-sites",
    // ─── Anti-tracking / fingerprinting (no site breakage) ─────────
    "--disable-search-engine-collection",
    // NOTE: --fingerprinting-canvas-image-data-noise is intentionally omitted on
    // Helium. Helium's built-in "Helium Noise" already noises canvas pixel
    // readback (patches/helium/core/noise/canvas.patch, on by default), so the
    // ungoogled flag is redundant. measuretext and client-rects are kept below —
    // Helium Noise does NOT cover those vectors (they ride the separate Bromite
    // flags), so dropping them would leave those surfaces unprotected.
    "--fingerprinting-canvas-measuretext-noise",
    "--fingerprinting-client-rects-noise",
    "--force-punycode-hostnames",
    // ─── Network / TLS privacy ─────────────────────────────────────
    "--no-pings",
    // NOTE: --disable-grease-tls and --http-accept-header are intentionally
    // absent. Combining Tor Browser's Accept header with Chromium's UA and TLS
    // stack produces a unique mixed fingerprint no real client sends — worse
    // than either pure approach. GREASE randomises TLS ClientHello extensions,
    // which is privacy-positive; disabling it removes that entropy.
    "--webrtc-ip-handling-policy=default_public_interface_only",
    // ─── Bundled ungoogled-chromium feature flags ──────────────────
    // Chromium only honours the LAST --enable-features= switch, so all
    // features must be bundled in one entry.
    // SetIpv6ProbeFalse: forces IPv4 preference on dual-stack hosts,
    //   preventing IPv6 from leaking WAN-side topology.
    // DisableQRGenerator: removes the QR share surface.
    // MinimalReferrers: strips cross-origin referrers and minimises
    //   same-origin to origin only — the single biggest passive-tracking
    //   mitigation in the ungoogled-chromium feature set.
    // PartitionAllocWithAdvancedChecks: enables PartitionAlloc's extra
    //   heap-corruption detection across all processes — a memory-safety
    //   mitigation gained purely at launch. Orthogonal to Helium Noise.
    // ReduceAcceptLanguage: collapses the Accept-Language header to a single
    //   value, cutting a passive fingerprinting vector Helium Noise does not cover.
    "--enable-features=RemoveClientHints,SpoofWebGLInfo,MinimalReferrers,SetIpv6ProbeFalse,DisableQRGenerator,PartitionAllocWithAdvancedChecks,ReduceAcceptLanguage",
];

/// Helium browser family.
pub struct Helium {
    arch: Arch,
    releases_url: String,
}

impl Helium {
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

fn arch_token(arch: Arch) -> &'static str {
    match arch {
        Arch::X64 => "x64",
        Arch::X86 => "x86",
        Arch::Arm64 => "arm64",
    }
}

impl BrowserFamily for Helium {
    fn id(&self) -> &'static str {
        "helium"
    }

    fn display_name(&self) -> &'static str {
        "Helium"
    }

    fn engine(&self) -> Engine {
        Engine::Chromium
    }

    fn public_key(&self) -> Option<&'static [u8]> {
        if HELIUM_KEY.is_empty() {
            None
        } else {
            Some(HELIUM_KEY)
        }
    }

    fn installed_version(&self, install_dir: &Path) -> Option<InstalledVersion> {
        read_version_marker(install_dir)
    }

    async fn fetch_latest_version(&self) -> Result<VersionInfo> {
        let client = github::build_client()?;
        let release = github::fetch_release(&client, &self.releases_url).await?;
        let token = arch_token(self.arch);
        let asset = github::zip_asset(&release, token)?;

        let version = release.tag_name.trim_start_matches('v').to_owned();

        // Locate the detached sig asset (<zip-name>.sig). Skip when the key is
        // a placeholder so the pipeline never attempts a pointless download.
        let sig_name = format!("{}.sig", asset.name);
        let signature_url = if HELIUM_KEY.is_empty() {
            None
        } else {
            release
                .assets
                .iter()
                .find(|a| a.name == sig_name)
                .map(|a| a.browser_download_url.clone())
        };

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
        crate::gpg::verify(package, sig, HELIUM_KEY)
            .map_err(|e| BrowserError::Verification(e.to_string()))
    }

    fn extract(&self, package: &Path, install_dir: &Path) -> Result<()> {
        crate::extract::extract_zip(package, install_dir)
    }

    fn prepare_launch(
        &self,
        install_dir: &Path,
        _hardening_config: crate::config::HardeningConfig,
    ) -> Result<()> {
        // Drop `initial_preferences` next to chrome.exe so freshly created
        // profiles start with Developer mode = ON *and* the profile-pref
        // hardening (PREFERENCES). Chromium regenerates Default/Preferences from
        // initial_preferences on first run, so prefs must travel through here to
        // be active on the first launch rather than only the second. Chromium
        // consults this file only when `Default/Preferences` does not yet exist,
        // so existing profiles are not disturbed.
        let initial_prefs =
            match crate::hardening::build_initial_preferences(INITIAL_PREFERENCES, PREFERENCES) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        browser = self.id(),
                        error = %e,
                        "failed to merge profile prefs into initial_preferences; \
                         falling back to template (first-run profile hardening will not apply)"
                    );
                    INITIAL_PREFERENCES.to_owned()
                }
            };
        if let Err(e) =
            crate::hardening::write_chromium_initial_preferences(install_dir, &initial_prefs)
        {
            tracing::warn!(
                browser = self.id(),
                error = %e,
                "failed to write initial_preferences; new profiles will start with Developer mode off"
            );
        }
        // Helium ships its own uBlock fork built into the browser.
        Ok(())
    }

    fn hardening(&self) -> Hardening {
        // uBlock Origin is built into Helium (imputnet/uBlock fork) — no CRX
        // provisioning needed or wanted.
        Hardening::LaunchFlags {
            flags: HARDENING_FLAGS,
            local_state: Some(LOCAL_STATE),
            preferences: Some(PREFERENCES),
        }
    }

    /// Helium ships "Helium Noise", which randomises `hardwareConcurrency`
    /// itself (2..=16, believable even number). Signal this so the core runner
    /// does not force the ungoogled `ReducedSystemInfo` clamp-to-2 on top, which
    /// would override and degrade Helium's own value.
    fn has_builtin_fingerprint_noise(&self) -> bool {
        true
    }

    fn profile_dir(&self, install_dir: &Path) -> Option<std::path::PathBuf> {
        install_dir.parent().map(|base| base.join("Data"))
    }

    fn launch_command(&self, install_dir: &Path, args: &[String]) -> Command {
        let profile_dir = self
            .profile_dir(install_dir)
            .unwrap_or_else(|| install_dir.join("profile"));
        let mut cmd = Command::new(install_dir.join(EXECUTABLE));
        cmd.arg(format!("--user-data-dir={}", profile_dir.display()));
        if default_apps_already_installed(&profile_dir) {
            cmd.arg("--no-first-run");
        }
        cmd.args(args);
        cmd
    }

    fn upstream_url(&self) -> &'static str {
        "https://helium.computer"
    }
}

/// Returns `true` once Helium has finished processing the `BrowserDefaultApp`
/// extensions in `<install-dir>/default_apps/`. Gate for `--no-first-run`:
/// while `default_apps_install_state` is anything other than `3`
/// (`kInstallStateDone`), suppressing the first-run pipeline would prevent
/// CRX default apps from ever installing.
fn default_apps_already_installed(profile_dir: &Path) -> bool {
    let prefs_path = profile_dir.join("Default").join("Preferences");
    let Ok(raw) = std::fs::read_to_string(&prefs_path) else {
        return false;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    parsed
        .get("default_apps_install_state")
        .and_then(serde_json::Value::as_i64)
        == Some(3)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use httpmock::prelude::*;

    use super::super::{write_version_marker, BrowserError, InstalledVersion};
    use super::*;

    fn fixture_release(tag: &str, arch: &str, with_sig: bool) -> String {
        let zip_name = format!("helium-{tag}-windows-{arch}.zip");
        let digest = format!("sha256:{}", "b".repeat(64));
        let sig_asset = if with_sig {
            format!(
                r#", {{
                    "name": "{zip_name}.sig",
                    "browser_download_url": "https://example.invalid/helium-{arch}.zip.sig",
                    "digest": null
                }}"#
            )
        } else {
            String::new()
        };
        format!(
            r#"{{
                "tag_name": "{tag}",
                "assets": [
                    {{
                        "name": "{zip_name}",
                        "browser_download_url": "https://example.invalid/helium-{arch}.zip",
                        "digest": "{digest}"
                    }}{sig_asset}
                ]
            }}"#
        )
    }

    fn browser_for_server(server: &MockServer, arch: Arch) -> Helium {
        Helium::for_test(arch, server.url("/latest"))
    }

    #[tokio::test]
    async fn fetch_latest_parses_version_and_sha256() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(fixture_release("0.12.3.1", "x64", false));
        });
        let browser = browser_for_server(&server, Arch::X64);
        let info = browser.fetch_latest_version().await.unwrap();
        assert_eq!(info.browser_version, "0.12.3.1");
        assert_eq!(info.engine_version, "0.12.3.1");
        assert_eq!(
            info.sha256.as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        assert!(
            info.signature_url.is_none(),
            "no sig asset in fixture => None"
        );
    }

    #[tokio::test]
    async fn fetch_skips_installer_zip() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(
                    r#"{
                    "tag_name": "0.12.3.1",
                    "assets": [
                        {
                            "name": "helium-0.12.3.1-windows-x64-installer.zip",
                            "browser_download_url": "https://example.invalid/installer.zip",
                            "digest": "sha256:aaaa"
                        },
                        {
                            "name": "helium-0.12.3.1-windows-x64.zip",
                            "browser_download_url": "https://example.invalid/portable.zip",
                            "digest": "sha256:bbbb"
                        }
                    ]
                }"#,
                );
        });
        let browser = browser_for_server(&server, Arch::X64);
        let info = browser.fetch_latest_version().await.unwrap();
        assert!(!info.download_url.contains("installer"));
    }

    #[tokio::test]
    async fn fetch_fails_when_no_matching_asset() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(r#"{"tag_name": "0.12.3.1", "assets": []}"#);
        });
        let browser = browser_for_server(&server, Arch::X64);
        let err = browser.fetch_latest_version().await.unwrap_err();
        assert!(matches!(err, BrowserError::Parse(_)));
    }

    #[test]
    fn installed_version_reads_the_nomad_marker() {
        let dir = tempfile::tempdir().unwrap();
        let browser = Helium::new(Arch::X64);
        assert!(browser.installed_version(dir.path()).is_none());
        let marker = InstalledVersion {
            browser_version: "0.12.3.1".to_owned(),
            engine_version: "0.12.3.1".to_owned(),
        };
        write_version_marker(dir.path(), &marker).unwrap();
        assert_eq!(browser.installed_version(dir.path()), Some(marker));
    }

    #[test]
    fn launch_command_targets_chrome_exe() {
        let browser = Helium::new(Arch::X64);
        let cmd = browser.launch_command(Path::new("C:/nomad/helium"), &[]);
        let program = Path::new(cmd.get_program());
        assert!(program.ends_with("chrome.exe"));
        let args: Vec<_> = cmd.get_args().collect();
        assert!(
            args.iter()
                .any(|a| a.to_string_lossy().starts_with("--user-data-dir=")),
            "--user-data-dir must be present"
        );
    }

    #[test]
    fn profile_dir_is_beside_install_dir() {
        let browser = Helium::new(Arch::X64);
        let install = Path::new("C:/nomad/helium");
        let profile = browser.profile_dir(install).unwrap();
        assert_eq!(profile, Path::new("C:/nomad/Data"));
    }

    #[test]
    fn helium_defers_canvas_pixel_and_hwconcurrency_to_helium_noise() {
        let browser = Helium::new(Arch::X64);
        let Hardening::LaunchFlags { flags, .. } = browser.hardening() else {
            panic!("Helium must return LaunchFlags hardening");
        };
        // Canvas pixel readback is handled by Helium Noise — Nomad must not duplicate it.
        assert!(
            !flags.contains(&"--fingerprinting-canvas-image-data-noise"),
            "canvas image-data noise must be omitted on Helium (Helium Noise covers it)"
        );
        // measuretext + client-rects are NOT covered by Helium Noise — keep them.
        assert!(
            flags.contains(&"--fingerprinting-canvas-measuretext-noise"),
            "measuretext noise must be kept (Helium Noise does not cover it)"
        );
        assert!(
            flags.contains(&"--fingerprinting-client-rects-noise"),
            "client-rects noise must be kept (Helium Noise does not cover it)"
        );
        // Signals its built-in framework so ReducedSystemInfo is not layered on.
        assert!(
            browser.has_builtin_fingerprint_noise(),
            "Helium must report a built-in fingerprint-noise framework"
        );
    }

    #[test]
    fn hardening_returns_safe_launch_flags_with_state_seeding() {
        let browser = Helium::new(Arch::X64);
        let Hardening::LaunchFlags {
            flags,
            local_state,
            preferences,
        } = browser.hardening()
        else {
            panic!("Helium must return LaunchFlags hardening");
        };
        assert!(!flags.is_empty(), "safe flag set must not be empty");
        assert!(flags.contains(&"--no-pings"));
        assert!(
            !flags.iter().any(|f| f.contains("disable-webgl")),
            "site-breaking flags must be excluded from the safe set"
        );
        assert!(
            local_state.is_some(),
            "Helium must seed Local State for chrome://flags visibility"
        );
        assert!(
            preferences.is_some(),
            "Helium must seed profile preferences"
        );
    }

    #[test]
    fn merged_initial_preferences_carry_developer_mode_and_profile_hardening() {
        // Same first-run-clobber guard as ungoogled-chromium: Helium's
        // prepare_launch folds the profile-pref hardening into initial_preferences
        // so a fresh profile is hardened on the first launch, not the second.
        let merged =
            crate::hardening::build_initial_preferences(INITIAL_PREFERENCES, PREFERENCES).unwrap();
        let v: serde_json::Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(
            v["extensions"]["ui"]["developer_mode"], true,
            "developer_mode (the original template key) must survive the merge"
        );
        assert_eq!(
            v["https_only_mode_enabled"], true,
            "first-run profile must receive HTTPS-Only mode"
        );
        assert_eq!(
            v["profile"]["cookie_controls_mode"], 1,
            "first-run profile must block third-party cookies"
        );
    }

    #[test]
    fn metadata_is_stable() {
        let browser = Helium::new(Arch::X64);
        assert_eq!(browser.id(), "helium");
        assert_eq!(browser.display_name(), "Helium");
        assert_eq!(browser.engine(), Engine::Chromium);
        // No Imput developer signing key exists; key slot is empty.
        assert!(
            browser.public_key().is_none(),
            "Helium GPG key slot must be empty until Imput publishes an official key"
        );
    }

    #[test]
    fn hardening_flags_omit_no_first_run_so_default_apps_can_install() {
        let browser = Helium::new(Arch::X64);
        let Hardening::LaunchFlags { flags, .. } = browser.hardening() else {
            panic!("Helium must return LaunchFlags hardening");
        };
        assert!(
            !flags.contains(&"--no-first-run"),
            "--no-first-run must be conditional, not part of the baseline hardening set"
        );
    }

    #[test]
    fn default_apps_already_installed_reflects_preferences_state() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path();
        assert!(
            !default_apps_already_installed(profile),
            "missing Preferences must report not-installed"
        );
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        std::fs::write(
            profile.join("Default").join("Preferences"),
            r#"{"default_apps_install_state": 1}"#,
        )
        .unwrap();
        assert!(
            !default_apps_already_installed(profile),
            "install_state != 3 must report not-installed"
        );
        std::fs::write(
            profile.join("Default").join("Preferences"),
            r#"{"default_apps_install_state": 3}"#,
        )
        .unwrap();
        assert!(
            default_apps_already_installed(profile),
            "install_state == 3 must report installed"
        );
    }

    #[test]
    fn launch_command_omits_no_first_run_when_default_apps_not_yet_installed() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("helium");
        std::fs::create_dir_all(&install).unwrap();
        let browser = Helium::new(Arch::X64);
        let cmd = browser.launch_command(&install, &[]);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            !args.iter().any(|a| a == "--no-first-run"),
            "without Preferences, --no-first-run must NOT be appended"
        );
    }

    #[test]
    fn launch_command_includes_no_first_run_after_default_apps_installed() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("helium");
        let profile = dir.path().join("Data");
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        std::fs::write(
            profile.join("Default").join("Preferences"),
            r#"{"default_apps_install_state": 3}"#,
        )
        .unwrap();
        let browser = Helium::new(Arch::X64);
        let cmd = browser.launch_command(&install, &[]);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.iter().any(|a| a == "--no-first-run"),
            "with install_state == 3, --no-first-run must be appended"
        );
    }
}
