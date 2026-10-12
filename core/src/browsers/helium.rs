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
    // NOTE: the profile-storage switches (--disable-machine-id,
    // --disable-encryption, DeviceBoundSessions) are NOT here. They live in
    // CHROMIUM_PORTABILITY_FLAGS and are applied unconditionally by
    // launch_command — gating them on `[hardening] enabled` meant toggling
    // that setting reformatted an existing profile and wiped the user's
    // extensions and sign-ins (#38).
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
    fn package_target(&self) -> super::PackageTarget {
        self.arch.into()
    }

    fn id(&self) -> &'static str {
        "helium"
    }

    fn display_name(&self) -> &'static str {
        "Helium"
    }

    fn engine(&self) -> Engine {
        Engine::Chromium
    }

    fn staged_install_layout(&self) -> super::StagedInstallLayout {
        super::StagedInstallLayout::Chromium(EXECUTABLE)
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
        hardening_config: crate::config::HardeningConfig,
    ) -> Result<()> {
        // This is a portability invariant, independent of privacy hardening.
        // Helium's WinSparkle updater can run a per-user installer outside the
        // portable tree. Disable it in both first-run and established profiles.
        let initial_prefs = if hardening_config.enabled {
            crate::hardening::build_initial_preferences(INITIAL_PREFERENCES, PREFERENCES)?
        } else {
            INITIAL_PREFERENCES.to_owned()
        };
        let mut initial: serde_json::Value = serde_json::from_str(&initial_prefs)
            .map_err(|e| BrowserError::Parse(format!("invalid Helium initial preferences: {e}")))?;
        disable_browser_updates(&mut initial)?;
        let initial = serde_json::to_string(&initial).map_err(|e| {
            BrowserError::Parse(format!("could not serialize Helium preferences: {e}"))
        })?;
        crate::hardening::write_chromium_initial_preferences(install_dir, &initial)?;

        let profile = self
            .profile_dir(install_dir)
            .unwrap_or_else(|| install_dir.join("profile"));
        disable_existing_profile_updates(&profile)?;
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
        // Profile-storage switches belong with --user-data-dir: both decide
        // where and how the portable profile lives, and neither may be gated
        // on config (#38). Placed before `args` so a hardening
        // --disable-features= bundle (a superset) still wins, and so a user's
        // extra_args can still override.
        cmd.args(super::CHROMIUM_PORTABILITY_FLAGS);
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

/// Force only the updater preference; reject malformed containers rather than
/// replacing unrelated user data or silently leaving the updater enabled.
fn disable_browser_updates(prefs: &mut serde_json::Value) -> Result<()> {
    let mut current = prefs;
    for key in ["helium", "services"] {
        let object = current.as_object_mut().ok_or_else(|| {
            BrowserError::Parse("Helium preferences must contain JSON objects".to_owned())
        })?;
        current = object.entry(key).or_insert_with(|| serde_json::json!({}));
    }
    let services = current.as_object_mut().ok_or_else(|| {
        BrowserError::Parse("Helium services preferences must be a JSON object".to_owned())
    })?;
    services.insert("browser_updates".to_owned(), false.into());
    Ok(())
}

fn disable_existing_profile_updates(profile: &Path) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    let path = profile.join("Default").join("Preferences");
    crate::fs_safety::ensure_file(&path)?;
    let original = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        // Leave fresh profile creation to Chromium's initial_preferences path.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mut prefs: serde_json::Value = serde_json::from_slice(&original)
        .map_err(|e| BrowserError::Parse(format!("invalid Helium profile preferences: {e}")))?;
    if prefs["helium"]["services"]["browser_updates"] == false {
        return Ok(());
    }
    disable_browser_updates(&mut prefs)?;
    let bytes = serde_json::to_vec(&prefs)
        .map_err(|e| BrowserError::Parse(format!("could not serialize Helium preferences: {e}")))?;

    // A failed write must not truncate the user's existing profile preferences.
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("nomad-updates.{}.{}.tmp", std::process::id(), seq));
    crate::fs_safety::ensure_file(&tmp)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let written = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    let result = written.and_then(|()| std::fs::rename(&tmp, &path));
    if result.is_err() {
        // create_new succeeded, so this exact sibling temp file is ours.
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(BrowserError::from)
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

    #[tokio::test]
    async fn authenticated_incomplete_archive_preserves_working_install() {
        use std::io::Write;
        let server = MockServer::start_async().await;
        let mut archive = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut archive);
            zip.start_file(
                "helium/README.txt",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
            zip.write_all(b"authenticated archive with no browser")
                .unwrap();
            zip.finish().unwrap();
        }
        let bytes = archive.into_inner();
        let digest = crate::gpg::sha256::hex(&bytes);
        let package = server
            .mock_async(|when, then| {
                when.method(GET).path("/helium.zip");
                then.status(200).body(&bytes);
            })
            .await;
        let release = serde_json::json!({
            "tag_name": "2.0", "assets": [{
                "name": "helium-2.0-windows-x64.zip",
                "browser_download_url": server.url("/helium.zip"),
                "digest": format!("sha256:{digest}")
            }]
        });
        server
            .mock_async(|when, then| {
                when.method(GET).path("/latest");
                then.status(200).body(release.to_string());
            })
            .await;
        let temp = tempfile::tempdir().unwrap();
        let install = temp.path().join("Browser");
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(temp.path().join("Data")).unwrap();
        std::fs::write(install.join("chrome.exe"), b"working browser").unwrap();
        write_version_marker(
            &install,
            &InstalledVersion {
                target: Some(crate::browsers::PackageTarget::X64),
                browser_version: "1.0".into(),
                engine_version: "1.0".into(),
            },
        )
        .unwrap();
        std::fs::write(temp.path().join("Data/profile"), b"user data").unwrap();
        let browser = browser_for_server(&server, Arch::X64);
        let result = crate::updater::update(
            &browser,
            &install,
            crate::updater::UpdateOptions {
                check_on_launch: true,
                auto_download: true,
            },
        )
        .await;
        assert!(
            matches!(result, Err(BrowserError::Compatibility(_))),
            "got {result:?}"
        );
        assert_eq!(
            std::fs::read(install.join("chrome.exe")).unwrap(),
            b"working browser"
        );
        assert_eq!(
            browser.installed_version(&install).unwrap().browser_version,
            "1.0"
        );
        assert_eq!(
            std::fs::read(temp.path().join("Data/profile")).unwrap(),
            b"user data"
        );
        assert!(!crate::install::backup_dir(&install).exists());
        assert!(!crate::install::stage_dir(&install)
            .join(".nomad-version")
            .exists());
        package.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn authenticated_complete_archive_installs_without_launching() {
        use std::io::Write;
        let server = MockServer::start_async().await;
        let mut archive = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut archive);
            for name in [
                "chrome.exe",
                "chrome.dll",
                "resources.pak",
                "icudtl.dat",
                "chrome_100_percent.pak",
                "chrome_200_percent.pak",
            ] {
                zip.start_file(
                    format!("helium/{name}"),
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
                zip.write_all(b"inert fixture; never executed").unwrap();
            }
            zip.finish().unwrap();
        }
        let bytes = archive.into_inner();
        let digest = crate::gpg::sha256::hex(&bytes);
        server
            .mock_async(|when, then| {
                when.method(GET).path("/helium.zip");
                then.status(200).body(&bytes);
            })
            .await;
        let release = serde_json::json!({ "tag_name": "2.0", "assets": [{
            "name": "helium-2.0-windows-x64.zip", "browser_download_url": server.url("/helium.zip"),
            "digest": format!("sha256:{digest}")
        }]});
        server
            .mock_async(|when, then| {
                when.method(GET).path("/latest");
                then.status(200).body(release.to_string());
            })
            .await;
        let temp = tempfile::tempdir().unwrap();
        let install = temp.path().join("Browser");
        let browser = browser_for_server(&server, Arch::X64);
        let result = crate::updater::update(
            &browser,
            &install,
            crate::updater::UpdateOptions {
                check_on_launch: true,
                auto_download: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(result, crate::updater::UpdateOutcome::Updated("2.0".into()));
        assert_eq!(
            std::fs::read(install.join("chrome.exe")).unwrap(),
            b"inert fixture; never executed"
        );
        assert_eq!(
            browser.installed_version(&install).unwrap().browser_version,
            "2.0"
        );
        assert!(!temp.path().join("Data").exists());
        assert!(!crate::install::stage_dir(&install).exists());
        assert!(!crate::install::backup_dir(&install).exists());
    }

    fn prepared_preferences(enabled: bool) {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        let prefs_path = dir.path().join("Data/Default/Preferences");
        std::fs::create_dir_all(prefs_path.parent().unwrap()).unwrap();
        let original = serde_json::json!({
            "helium": {"services": {
                "browser_updates": true,
                "user_consented": true,
                "bangs": false
            }},
            "extensions": {"ui": {"developer_mode": false}},
            "homepage": "https://example.invalid/",
            "custom": [1, "preserved", {"nested": true}]
        });
        std::fs::write(&prefs_path, serde_json::to_vec(&original).unwrap()).unwrap();
        let cfg = crate::config::HardeningConfig {
            enabled,
            ..Default::default()
        };
        Helium::new(Arch::X64)
            .prepare_launch(&install, cfg)
            .unwrap();
        let actual: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&prefs_path).unwrap()).unwrap();
        assert_eq!(actual["helium"]["services"]["browser_updates"], false);
        let mut expected = original;
        expected["helium"]["services"]["browser_updates"] = false.into();
        assert_eq!(actual, expected, "unrelated user preferences must survive");
        let initial: serde_json::Value =
            serde_json::from_slice(&std::fs::read(install.join("initial_preferences")).unwrap())
                .unwrap();
        assert_eq!(initial["helium"]["services"]["browser_updates"], false);
        assert_eq!(initial["extensions"]["ui"]["developer_mode"], true);
    }

    #[test]
    fn prepare_launch_disables_browser_updates_in_existing_profile() {
        prepared_preferences(true);
    }

    #[test]
    fn prepare_launch_disables_browser_updates_without_hardening() {
        prepared_preferences(false);
    }

    #[test]
    fn prepare_launch_disables_browser_updates_for_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        Helium::new(Arch::X64)
            .prepare_launch(&install, crate::config::HardeningConfig::default())
            .unwrap();
        let initial: serde_json::Value =
            serde_json::from_slice(&std::fs::read(install.join("initial_preferences")).unwrap())
                .unwrap();
        assert_eq!(initial["helium"]["services"]["browser_updates"], false);
        assert!(
            !dir.path().join("Data").exists(),
            "keep first-run profile creation in Chromium"
        );
    }

    #[test]
    fn prepare_launch_reapplies_browser_updates_override_each_time() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        let prefs = dir.path().join("Data/Default/Preferences");
        std::fs::create_dir_all(prefs.parent().unwrap()).unwrap();
        let browser = Helium::new(Arch::X64);
        for original in [
            r#"{"homepage":"keep"}"#,
            r#"{"helium":{"services":{"browser_updates":true}},"homepage":"keep"}"#,
        ] {
            std::fs::write(&prefs, original).unwrap();
            browser
                .prepare_launch(&install, crate::config::HardeningConfig::default())
                .unwrap();
            let actual: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&prefs).unwrap()).unwrap();
            assert_eq!(actual["helium"]["services"]["browser_updates"], false);
            assert_eq!(actual["homepage"], "keep");
        }
    }

    #[test]
    fn prepare_launch_rejects_malformed_preferences_without_overwriting() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        let prefs = dir.path().join("Data/Default/Preferences");
        std::fs::create_dir_all(prefs.parent().unwrap()).unwrap();
        for original in [
            "{broken",
            "[]",
            r#"{"helium":null}"#,
            r#"{"helium":{"services":false}}"#,
        ] {
            std::fs::write(&prefs, original).unwrap();
            assert!(Helium::new(Arch::X64)
                .prepare_launch(&install, crate::config::HardeningConfig::default())
                .is_err());
            assert_eq!(std::fs::read_to_string(&prefs).unwrap(), original);
        }
    }

    #[test]
    fn prepare_launch_rejects_unreadable_preferences() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        let prefs = dir.path().join("Data/Default/Preferences");
        std::fs::create_dir_all(&prefs).unwrap();
        assert!(Helium::new(Arch::X64)
            .prepare_launch(&install, crate::config::HardeningConfig::default())
            .is_err());
        assert!(prefs.is_dir());
    }

    #[test]
    fn prepare_launch_rejects_initial_preferences_write_failure() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        std::fs::create_dir_all(install.join("initial_preferences")).unwrap();
        assert!(Helium::new(Arch::X64)
            .prepare_launch(&install, crate::config::HardeningConfig::default())
            .is_err());
    }

    #[cfg(windows)]
    #[test]
    fn prepare_launch_failed_profile_replace_keeps_original_and_cleans_temp() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        let prefs = dir.path().join("Data/Default/Preferences");
        std::fs::create_dir_all(prefs.parent().unwrap()).unwrap();
        let original = r#"{"helium":{"services":{"browser_updates":true}}}"#;
        std::fs::write(&prefs, original).unwrap();
        let permissions = std::fs::metadata(&prefs).unwrap().permissions();
        let mut readonly = permissions.clone();
        readonly.set_readonly(true);
        std::fs::set_permissions(&prefs, readonly).unwrap();
        let result = Helium::new(Arch::X64)
            .prepare_launch(&install, crate::config::HardeningConfig::default());
        std::fs::set_permissions(&prefs, permissions).unwrap();
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(&prefs).unwrap(), original);
        assert_eq!(
            std::fs::read_dir(prefs.parent().unwrap()).unwrap().count(),
            1
        );
    }

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
            target: Some(crate::browsers::PackageTarget::X64),
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
    fn prepare_launch_respects_hardening_toggle_in_initial_preferences() {
        for existing_profile in [false, true] {
            let fixture = tempfile::tempdir().unwrap();
            let install = fixture.path().join("Browser");
            let profile = fixture.path().join("Data/Default/Preferences");
            let user_prefs = br#"{"homepage":"keep","enable_do_not_track":false,"custom":[1,2]}"#;
            if existing_profile {
                std::fs::create_dir_all(profile.parent().unwrap()).unwrap();
                std::fs::write(&profile, user_prefs).unwrap();
            }
            let browser = Helium::new(Arch::X64);
            // Starts unhardened, enables hardening, then removes the stale
            // first-run privacy payload again. No real browser is launched.
            for enabled in [false, true, false] {
                let config = crate::config::HardeningConfig {
                    enabled,
                    ..Default::default()
                };
                browser.prepare_launch(&install, config).unwrap();
                let initial: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(install.join("initial_preferences")).unwrap(),
                )
                .unwrap();
                assert_eq!(initial["extensions"]["ui"]["developer_mode"], true);
                if enabled {
                    assert_eq!(initial["https_only_mode_enabled"], true);
                    assert_eq!(initial["safebrowsing"]["enabled"], false);
                    assert_eq!(initial["profile"]["cookie_controls_mode"], 1);
                } else {
                    assert_eq!(
                        initial,
                        serde_json::json!({"extensions":{"ui":{"developer_mode":true}},"helium":{"services":{"browser_updates":false}}}),
                        "disabled hardening must not seed privacy defaults"
                    );
                }
                if existing_profile {
                    let actual: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&profile).unwrap()).unwrap();
                    let mut expected: serde_json::Value =
                        serde_json::from_slice(user_prefs).unwrap();
                    expected["helium"] = serde_json::json!({"services":{"browser_updates":false}});
                    assert_eq!(
                        actual, expected,
                        "existing user settings must survive the toggle"
                    );
                } else {
                    assert!(
                        !fixture.path().join("Data").exists(),
                        "leave new profile creation to Chromium"
                    );
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn prepare_launch_rejects_failed_toggle_write_and_preserves_old_seed() {
        let fixture = tempfile::tempdir().unwrap();
        let install = fixture.path().join("Browser");
        let browser = Helium::new(Arch::X64);
        browser
            .prepare_launch(&install, crate::config::HardeningConfig::default())
            .unwrap();
        let path = install.join("initial_preferences");
        let original = std::fs::read(&path).unwrap();
        let permissions = std::fs::metadata(&path).unwrap().permissions();
        let mut readonly = permissions.clone();
        readonly.set_readonly(true);
        std::fs::set_permissions(&path, readonly).unwrap();
        let config = crate::config::HardeningConfig {
            enabled: false,
            ..Default::default()
        };
        let result = browser.prepare_launch(&install, config);
        std::fs::set_permissions(&path, permissions).unwrap();
        assert!(
            result.is_err(),
            "a stale hardened template must not silently survive disabling hardening"
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(
            std::fs::read_dir(&install).unwrap().count(),
            1,
            "private write stage must be cleaned"
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
