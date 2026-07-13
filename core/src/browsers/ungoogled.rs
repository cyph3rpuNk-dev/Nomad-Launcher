//! [`BrowserFamily`] implementation for ungoogled-chromium (Windows builds).
//!
//! Updates are resolved from the GitHub releases API of the
//! `ungoogled-software/ungoogled-chromium-windows` repository. The upstream
//! publishes no GPG signature; integrity is verified against the SHA-256
//! `digest` GitHub records for each release asset (see SPEC §9).

use std::path::Path;
use std::process::Command;

use serde::Deserialize;

use super::{
    github::map_network_err, read_version_marker, BrowserError, BrowserFamily, Engine, Hardening,
    InstalledVersion, ProgressSink, Result, VersionInfo,
};
use crate::config::Arch;
use crate::extensions::{stage_chromium_ubo_from_gorhill_zip, staged_ubo_dir};

/// GitHub releases endpoint for the Windows ungoogled-chromium builds.
const DEFAULT_RELEASES_URL: &str =
    "https://api.github.com/repos/ungoogled-software/ungoogled-chromium-windows/releases/latest";

/// GitHub API base URL for gorhill's uBlock Origin repository.
/// Endpoints are derived from this: `/releases/latest`, `/git/refs/tags/{tag}`,
/// `/git/tags/{sha}`.
const DEFAULT_UBO_API_BASE_URL: &str = "https://api.github.com/repos/gorhill/uBlock";

/// gorhill's GPG public key, embedded at compile time. Used to authenticate
/// gorhill's annotated release tag signatures before accepting any download.
/// Key ID: F5630CAE62A14316
/// Full fingerprint: 91BFC93FDEC1D00C365C061EF5630CAE62A14316
const GORHILL_KEY: &[u8] = include_bytes!("../../keys/gorhill.asc");

/// Full fingerprint of gorhill's signing key. The embedded [`GORHILL_KEY`]
/// must contain a key with this fingerprint; any mismatch is a build-time
/// bug (mis-bundled key file).
const GORHILL_KEY_FINGERPRINT: &str = "91BFC93FDEC1D00C365C061EF5630CAE62A14316";

/// Launchable executable name inside an ungoogled-chromium install.
const EXECUTABLE: &str = "chrome.exe";

/// Local State JSON seeded into `<user-data-dir>/Local State` so <chrome://flags>
/// shows our hardening as enabled and DNS-over-HTTPS uses Quad9 secure mode.
const LOCAL_STATE: &str = include_str!("../../payloads/chromium/local_state.json");

/// Profile-level prefs seeded into `<user-data-dir>/Default/Preferences` —
/// settings that are not exposed as `--flag` switches (HTTPS-only mode,
/// Privacy Sandbox m1, Safe Browsing, Do Not Track, …).
const PREFERENCES: &str = include_str!("../../payloads/chromium/preferences.json");

/// `initial_preferences` template written next to `chrome.exe`.  Chromium
/// consults it only on first profile creation and is therefore the only safe
/// place to set MAC-protected keys like `extensions.ui.developer_mode = true`
/// — writing them directly to an established `Default/Preferences` triggers
/// Chromium's tracked-preference reset.
const INITIAL_PREFERENCES: &str = include_str!("../../payloads/chromium/initial_preferences.json");

/// Curated "safe" privacy-hardening flags for ungoogled-chromium (SPEC §5).
///
/// These reduce tracking and fingerprinting without breaking site
/// functionality. Switches upstream marks as potentially breaking — notably
/// `--disable-webgl` and the `ReducedSystemInfo` feature — are deliberately
/// excluded. Sourced from ungoogled-chromium's `docs/flags.md`.
const HARDENING_FLAGS: &[&str] = &[
    // ─── Portability (Windows-mandatory) ───────────────────────────
    // Without these two the profile is encrypted with the host OS user
    // credentials (DPAPI) and bound to the machine ID — both make it
    // non-portable to other machines (ungoogled-chromium-specific flags).
    "--disable-machine-id",
    "--disable-encryption",
    // ─── Stock Chromium privacy / portability hygiene ──────────────
    // NOTE: `--no-first-run` is deliberately omitted here. It is appended
    // conditionally in `launch_command` only after `Default/Preferences` exists,
    // so that `initial_preferences` seeds `developer_mode = true` on a clean
    // first launch without being suppressed by the flag.
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
    "--fingerprinting-canvas-image-data-noise",
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
    //   mitigation gained purely at launch on an otherwise-prebuilt binary.
    // ReduceAcceptLanguage: collapses the Accept-Language header to a single
    //   value, cutting a passive fingerprinting vector.
    "--enable-features=RemoveClientHints,SpoofWebGLInfo,MinimalReferrers,SetIpv6ProbeFalse,DisableQRGenerator,PartitionAllocWithAdvancedChecks,ReduceAcceptLanguage",
];

/// The ungoogled-chromium browser family.
pub struct UngoogledChromium {
    arch: Arch,
    releases_url: String,
    /// GitHub API base URL for the gorhill/uBlock repository, used for the
    /// uBO update check. Overridable for tests.
    ubo_api_base_url: String,
}

impl UngoogledChromium {
    /// Creates a launcher targeting the given build architecture.
    #[must_use]
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            releases_url: DEFAULT_RELEASES_URL.to_owned(),
            ubo_api_base_url: DEFAULT_UBO_API_BASE_URL.to_owned(),
        }
    }

    /// Creates a launcher pointing at a custom browser releases endpoint.
    ///
    /// Used by tests to redirect update checks at a mock server.
    #[must_use]
    pub fn with_releases_url(arch: Arch, releases_url: impl Into<String>) -> Self {
        Self {
            arch,
            releases_url: releases_url.into(),
            ubo_api_base_url: DEFAULT_UBO_API_BASE_URL.to_owned(),
        }
    }
}

/// Asset-name token identifying a build's architecture.
fn arch_token(arch: Arch) -> &'static str {
    match arch {
        Arch::X64 => "x64",
        Arch::X86 => "x86",
        Arch::Arm64 => "arm64",
    }
}

/// A GitHub release, as returned by the `releases/latest` endpoint.
#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

/// One downloadable asset attached to a [`Release`].
#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    /// GitHub-recorded content digest, e.g. `"sha256:abcd…"`. Absent on
    /// releases predating GitHub's digest support.
    digest: Option<String>,
}

/// Builds a [`VersionInfo`] from a parsed release for the given architecture.
fn parse_release(release: &Release, arch: Arch) -> Result<VersionInfo> {
    let token = arch_token(arch);
    let asset = release
        .assets
        .iter()
        .find(|a| {
            let name = a.name.to_ascii_lowercase();
            let is_zip = Path::new(&name).extension().is_some_and(|e| e == "zip");
            is_zip && name.contains(token) && !name.contains("installer")
        })
        .ok_or_else(|| {
            BrowserError::Parse(format!(
                "no {token} .zip asset in release {}",
                release.tag_name
            ))
        })?;

    let browser_version = release.tag_name.trim_start_matches('v').to_owned();
    let engine_version = browser_version
        .split('-')
        .next()
        .unwrap_or(browser_version.as_str())
        .to_owned();
    let sha256 = asset
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .map(str::to_owned);

    Ok(VersionInfo {
        browser_version,
        engine_version,
        download_url: asset.browser_download_url.clone(),
        signature_url: None,
        sha256,
        sha512: None,
    })
}

impl BrowserFamily for UngoogledChromium {
    fn id(&self) -> &'static str {
        "ungoogled-chromium"
    }

    fn display_name(&self) -> &'static str {
        "Ungoogled Chromium"
    }

    fn engine(&self) -> Engine {
        Engine::Chromium
    }

    fn public_key(&self) -> Option<&'static [u8]> {
        None // ungoogled-chromium publishes no GPG signature.
    }

    fn installed_version(&self, install_dir: &Path) -> Option<InstalledVersion> {
        read_version_marker(install_dir)
    }

    async fn fetch_latest_version(&self) -> Result<VersionInfo> {
        let client = reqwest::Client::builder()
            .user_agent("nomad-portable")
            .redirect(crate::downloader::redirect_policy())
            .build()
            .map_err(|e| BrowserError::Network(e.to_string()))?;
        let body = client
            .get(&self.releases_url)
            .send()
            .await
            .map_err(map_network_err)?
            .error_for_status()
            .map_err(map_network_err)?
            .text()
            .await
            .map_err(map_network_err)?;
        let release: Release =
            serde_json::from_str(&body).map_err(|e| BrowserError::Parse(e.to_string()))?;
        parse_release(&release, self.arch)
    }

    async fn download(
        &self,
        info: &VersionInfo,
        dest: &Path,
        progress: ProgressSink,
    ) -> Result<()> {
        crate::downloader::download(&info.download_url, dest, &progress).await
    }

    fn verify_signature(&self, _package: &Path, _signature: &Path) -> Result<()> {
        // ungoogled-chromium publishes no GPG signature; never invoked.
        Ok(())
    }

    fn extract(&self, package: &Path, install_dir: &Path) -> Result<()> {
        crate::extract::extract_zip(package, install_dir)
    }

    fn hardening(&self) -> Hardening {
        Hardening::LaunchFlags {
            flags: HARDENING_FLAGS,
            local_state: Some(LOCAL_STATE),
            preferences: Some(PREFERENCES),
        }
    }

    fn prepare_launch(
        &self,
        install_dir: &Path,
        _hardening_config: crate::config::HardeningConfig,
    ) -> Result<()> {
        // Drop `initial_preferences` next to chrome.exe so freshly created
        // profiles start with Developer mode = ON (required for the toggle in
        // chrome://extensions to be visibly enabled) *and* the profile-pref
        // hardening (PREFERENCES). Chromium regenerates Default/Preferences from
        // initial_preferences on first run, so prefs must travel through here to
        // be active on the first launch rather than only the second.
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
        // uBO is staged in fetch_extension_updates (async, GPG-verified download
        // from gorhill/uBlock). Nothing synchronous to stage here.
        Ok(())
    }

    fn profile_dir(&self, install_dir: &Path) -> Option<std::path::PathBuf> {
        install_dir.parent().map(|base| base.join("Data"))
    }

    async fn fetch_extension_updates(
        &self,
        install_dir: &Path,
        _hardening_config: crate::config::HardeningConfig,
        update_opts: crate::updater::UpdateOptions,
    ) -> Result<()> {
        let launcher_dir = install_dir.parent().unwrap_or(install_dir);
        let cache_path = crate::config::nomad_subdir(launcher_dir).join("nomad-version-cache.toml");
        update_ubo_from_gorhill(
            install_dir,
            &self.ubo_api_base_url,
            update_opts.auto_download,
            &cache_path,
            GORHILL_KEY,
        )
        .await
    }

    fn launch_command(&self, install_dir: &Path, args: &[String]) -> Command {
        let profile_dir = self
            .profile_dir(install_dir)
            .unwrap_or_else(|| install_dir.join("profile"));
        let mut command = Command::new(install_dir.join(EXECUTABLE));
        command.arg(format!("--user-data-dir={}", profile_dir.display()));
        if chrome_first_run_complete(&profile_dir) {
            command.arg("--no-first-run");
        }

        // Load gorhill's uBlock Origin from its staged directory. uBO appears
        // in `chrome://extensions` with the canonical ID
        // `cjpalhdlnbpafiamejdnhcphjbkeiagm` (derived from the `key` field in
        // gorhill's `manifest.json`). When uBO has not been staged yet
        // (offline first run, GPG verification failure, etc.) the flag is
        // omitted and the browser launches without uBO until the next
        // successful update check.
        if let Some(ubo_dir) = staged_ubo_dir(install_dir) {
            // --load-extension= takes a comma-separated list; a comma in the
            // path would split the value and silently drop uBO.
            let ubo_path = ubo_dir.display().to_string();
            if ubo_path.contains(',') {
                tracing::warn!(
                    path = %ubo_path,
                    "uBO extension path contains a comma — --load-extension is \
                     not added (Chromium splits on commas). Move the launcher to \
                     a path without commas to restore uBO."
                );
            } else {
                // Warn when incognito is active: Chromium ignores --load-extension
                // in incognito windows unless the extension has been granted
                // "Allow in incognito" — tracking protection is silently absent.
                if args.iter().any(|a| a == "--incognito") {
                    tracing::warn!(
                        "uBO is staged but --incognito is active: extensions loaded \
                         via --load-extension are not active in incognito windows \
                         unless 'Allow in incognito' is enabled for the extension. \
                         Tracking protection is reduced."
                    );
                }
                command.arg(format!("--load-extension={ubo_path}"));
            }
        }

        command.args(args);
        command
    }

    fn upstream_url(&self) -> &'static str {
        "https://github.com/ungoogled-software/ungoogled-chromium-windows/releases"
    }
}

/// Returns `true` once Chromium itself has completed a first run for
/// `profile_dir`, detected via `Default/Secure Preferences`.
///
/// This gates `--no-first-run` in [`UngoogledChromium::launch_command`]:
/// Chromium only reads `initial_preferences` (where `extensions.ui.developer_mode
/// = true` is seeded) during its first-run pipeline, which `--no-first-run`
/// suppresses. So the flag must be omitted on the genuine first launch and added
/// only afterwards.
///
/// The marker must be a file **Chromium writes, not one Nomad writes**. Nomad
/// seeds `Default/Preferences` (HTTPS-only, etc.) via
/// [`crate::hardening::write_chromium_state`] *before* the browser is launched,
/// so a `Default/Preferences` check is already true on the very first launch and
/// would wrongly add `--no-first-run`, permanently suppressing the
/// `initial_preferences` seed (Developer mode never turns on). `Secure
/// Preferences` holds the MAC-protected pref store and is created by Chromium
/// during first run only — Nomad never writes it — so it correctly distinguishes
/// a fresh profile from an established one.
fn chrome_first_run_complete(profile_dir: &Path) -> bool {
    profile_dir
        .join("Default")
        .join("Secure Preferences")
        .exists()
}

// ── GitHub API types for commit/tag GPG verification ─────────────────────────

/// GitHub `git/refs/tags/{tag}` response — the ref object pointing at either
/// a commit (lightweight tag, gorhill's current practice) or an annotated
/// tag object.
#[derive(Debug, Deserialize)]
struct GitTagRef {
    object: GitTagRefObject,
}

#[derive(Debug, Deserialize)]
struct GitTagRefObject {
    sha: String,
    #[serde(rename = "type")]
    object_type: String,
}

/// GitHub `commits/{sha}` response — used when the tag is lightweight and
/// points directly to a commit. gorhill's releases follow this pattern.
#[derive(Debug, Deserialize)]
struct GitCommitResponse {
    commit: GitCommitInner,
}

#[derive(Debug, Deserialize)]
struct GitCommitInner {
    verification: Option<GitTagVerification>,
}

/// GitHub `git/tags/{sha}` response for an annotated tag, including the
/// GPG verification fields. Present for future annotated-tag support.
#[derive(Debug, Deserialize)]
struct GitTagObject {
    verification: Option<GitTagVerification>,
}

/// Shared GPG verification block returned by both commits and tag objects.
#[derive(Debug, Deserialize)]
struct GitTagVerification {
    verified: bool,
    #[serde(default)]
    reason: String,
    payload: Option<String>,
    signature: Option<String>,
}

// ── gorhill uBO update ────────────────────────────────────────────────────────

/// Checks `gorhill/uBlock` GitHub releases for a newer uBO build, verifies the
/// release tag's GPG signature against the embedded gorhill key, downloads
/// `uBlock0_X.X.X.chromium.zip`, and stages it via the gorhill path.
///
/// # Trust model
///
/// The GPG signature covers the release **tag/commit only** — it proves the
/// release event is gorhill's, but GitHub release assets are mutable
/// independently of git history, are not covered by that signature, and
/// gorhill publishes no asset checksums (`digest` is `null`). The zip's
/// bytes are therefore trusted to GitHub (TLS + API), with
/// [`super::github::asset_provenance_suspect`] as tamper evidence against a
/// post-publication asset swap. Rebuilding the zip from the signed source
/// tree is impossible in principle: it bundles filter lists pulled from the
/// latest `uBlockOrigin/uAssets` branches at gorhill's build time, which the
/// signed commit does not pin.
///
/// `gorhill_key` is the embedded ASCII-armored GPG public key bytes. Passing
/// it as a parameter enables tests to inject a test key.
///
/// GPG verification only runs if there is a newer version AND `auto_download`
/// is true — it is skipped for the "already current" and "deferred" short-circuits
/// so those code paths do not make unnecessary API round-trips.
///
/// Errors are *advisory*; offline errors are demoted to `debug`.
async fn update_ubo_from_gorhill(
    install_dir: &Path,
    api_base_url: &str,
    auto_download: bool,
    cache_path: &Path,
    gorhill_key: &[u8],
) -> Result<()> {
    let installed_version = crate::version_cache::VersionCache::load(cache_path)
        .and_then(|c| c.ubo_version)
        .unwrap_or_default(); // empty string → always treated as outdated

    let client = super::github::build_client()?;
    let releases_url = format!("{api_base_url}/releases/latest");
    let release = match super::github::fetch_release(&client, &releases_url).await {
        Ok(r) => r,
        Err(BrowserError::Offline(msg)) => {
            tracing::debug!(error = %msg, "gorhill uBO update check skipped (offline)");
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    // gorhill tags are bare versions like "1.62.0" — no leading 'v'.
    let upstream_version = release.tag_name.clone();

    if !installed_version.is_empty()
        && installed_version == upstream_version
        && staged_ubo_dir(install_dir).is_some()
    {
        tracing::debug!(version = %upstream_version, "gorhill uBO already at upstream version");
        return Ok(());
    }

    let Some(asset) = release.assets.iter().find(|a| {
        let name = a.name.to_ascii_lowercase();
        name.starts_with("ublock0_") && name.ends_with(".chromium.zip")
    }) else {
        tracing::warn!(version = %upstream_version, "no chromium.zip asset on gorhill uBO release");
        return Ok(());
    };

    tracing::info!(
        installed = %installed_version,
        available = %upstream_version,
        "gorhill uBO update available"
    );

    if !auto_download {
        tracing::info!(version = %upstream_version, "gorhill uBO update deferred (auto_download = false)");
        return Ok(());
    }

    // ── Asset provenance check ────────────────────────────────────────────────
    // The GPG signature below covers the release *tag/commit only* — GitHub
    // release assets are mutable independently of git history and gorhill
    // publishes no asset checksums, so the zip's upload timeline is the only
    // tamper evidence available against a post-publication asset swap.
    if super::github::asset_provenance_suspect(asset, &release) {
        tracing::warn!(
            version = %upstream_version,
            asset = asset.name,
            "gorhill uBO update skipped: the release asset's upload timeline \
             does not match the release publication (possible asset swap); \
             keeping the currently staged uBO"
        );
        return Ok(());
    }

    // ── Resolve tag ref and GPG-verify ────────────────────────────────────────
    let verification =
        fetch_gorhill_tag_verification(&client, api_base_url, &upstream_version).await?;
    verify_gorhill_tag_signature(
        verification.as_ref().ok_or_else(|| {
            BrowserError::Verification(format!(
                "gorhill tag {upstream_version} has no verification field"
            ))
        })?,
        gorhill_key,
        &upstream_version,
    )?;

    // ── Download and stage ────────────────────────────────────────────────────
    tracing::info!(
        version = %upstream_version,
        url = asset.browser_download_url,
        "downloading gorhill uBO zip (release tag GPG-verified, asset provenance checked)"
    );
    let zip_bytes = super::github::fetch_raw(&client, &asset.browser_download_url).await?;

    stage_chromium_ubo_from_gorhill_zip(install_dir, &zip_bytes, &upstream_version)?;
    crate::version_cache::update_ubo_version(cache_path, &upstream_version);

    tracing::info!(
        version = %upstream_version,
        "gorhill uBO staged (release tag GPG-verified, asset provenance checked)"
    );
    Ok(())
}

/// Resolves a gorhill release tag to its GPG verification block.
///
/// gorhill uses lightweight tags (pointing directly to commits). Annotated
/// tags (pointing to tag objects) are handled as a forward-compatibility case.
async fn fetch_gorhill_tag_verification(
    client: &reqwest::Client,
    api_base_url: &str,
    tag: &str,
) -> Result<Option<GitTagVerification>> {
    let tag_ref_url = format!("{api_base_url}/git/refs/tags/{tag}");
    let body = client
        .get(&tag_ref_url)
        .send()
        .await
        .map_err(super::github::map_network_err)?
        .error_for_status()
        .map_err(super::github::map_network_err)?
        .text()
        .await
        .map_err(super::github::map_network_err)?;
    let tag_ref: GitTagRef =
        serde_json::from_str(&body).map_err(|e| BrowserError::Parse(e.to_string()))?;

    match tag_ref.object.object_type.as_str() {
        "commit" => {
            let url = format!("{api_base_url}/commits/{}", tag_ref.object.sha);
            let body = client
                .get(&url)
                .send()
                .await
                .map_err(super::github::map_network_err)?
                .error_for_status()
                .map_err(super::github::map_network_err)?
                .text()
                .await
                .map_err(super::github::map_network_err)?;
            let commit: GitCommitResponse =
                serde_json::from_str(&body).map_err(|e| BrowserError::Parse(e.to_string()))?;
            Ok(commit.commit.verification)
        }
        "tag" => {
            let url = format!("{api_base_url}/git/tags/{}", tag_ref.object.sha);
            let body = client
                .get(&url)
                .send()
                .await
                .map_err(super::github::map_network_err)?
                .error_for_status()
                .map_err(super::github::map_network_err)?
                .text()
                .await
                .map_err(super::github::map_network_err)?;
            let tag_obj: GitTagObject =
                serde_json::from_str(&body).map_err(|e| BrowserError::Parse(e.to_string()))?;
            Ok(tag_obj.verification)
        }
        other => Err(BrowserError::Verification(format!(
            "gorhill tag {tag} points to unexpected object type '{other}'"
        ))),
    }
}

/// Verifies a gorhill annotated tag's GPG signature against the embedded key.
///
/// Two invariants checked:
/// 1. GitHub itself reports `verified: true` for the tag (fast pre-check).
/// 2. Our own local verification of `payload` + `signature` against the
///    embedded gorhill key succeeds (the real trust anchor).
///
/// `gorhill_key` is the ASCII-armored key bytes to verify against.
fn verify_gorhill_tag_signature(
    verification: &GitTagVerification,
    gorhill_key: &[u8],
    tag: &str,
) -> Result<()> {
    if !verification.verified {
        return Err(BrowserError::Verification(format!(
            "GitHub reports gorhill tag {tag} as unverified ({})",
            verification.reason
        )));
    }
    let payload = verification.payload.as_deref().ok_or_else(|| {
        BrowserError::Verification(format!(
            "gorhill tag {tag}: GitHub verification.payload field is empty"
        ))
    })?;
    let signature = verification.signature.as_deref().ok_or_else(|| {
        BrowserError::Verification(format!(
            "gorhill tag {tag}: GitHub verification.signature field is empty"
        ))
    })?;

    let key_armor = gorhill_key_armored(gorhill_key)?;
    crate::gpg::verify_bytes(payload.as_bytes(), signature.as_bytes(), &key_armor).map_err(
        |e| BrowserError::Verification(format!("gorhill tag {tag} GPG verification failed: {e}")),
    )?;
    Ok(())
}

/// Validates that the embedded gorhill key contains a key matching
/// [`GORHILL_KEY_FINGERPRINT`] and returns the armored bytes for use with
/// [`crate::gpg::verify_bytes`].
#[cfg(not(test))]
fn gorhill_key_armored(gorhill_key: &[u8]) -> Result<Vec<u8>> {
    use pgp::composed::Deserializable;
    use pgp::types::KeyDetails;

    let cursor = std::io::Cursor::new(gorhill_key);
    let (iter, _) = pgp::composed::SignedPublicKey::from_armor_many(cursor)
        .map_err(|e| BrowserError::Parse(format!("embedded gorhill key not armored: {e}")))?;
    for key in iter.flatten() {
        let fp = hex::encode_upper(key.primary_key.fingerprint().as_bytes());
        if fp.eq_ignore_ascii_case(GORHILL_KEY_FINGERPRINT) {
            return Ok(gorhill_key.to_vec());
        }
    }
    Err(BrowserError::Verification(format!(
        "embedded gorhill key file contains no key with fingerprint {GORHILL_KEY_FINGERPRINT}"
    )))
}

/// Test variant: skip the fingerprint check so test keys can be injected
/// without needing to match [`GORHILL_KEY_FINGERPRINT`]. The real fingerprint
/// check is covered by [`tests::gorhill_embedded_key_matches_pinned_fingerprint`].
// Must return `Result` to match the non-test signature its callers use with `?`.
#[allow(clippy::unnecessary_wraps)]
#[cfg(test)]
fn gorhill_key_armored(gorhill_key: &[u8]) -> Result<Vec<u8>> {
    Ok(gorhill_key.to_vec())
}

#[cfg(test)]
mod tests {
    use httpmock::prelude::*;

    use super::super::{write_version_marker, BrowserError, InstalledVersion};
    use super::*;

    const FIXTURE_RELEASE: &str = r#"{
        "tag_name": "148.0.7778.96-1.1",
        "assets": [
            {
                "name": "ungoogled-chromium_148.0.7778.96-1.1_installer_x64.exe",
                "browser_download_url": "https://example.invalid/installer.exe"
            },
            {
                "name": "ungoogled-chromium_148.0.7778.96-1.1_windows_x64.zip",
                "browser_download_url": "https://example.invalid/uc-x64.zip",
                "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            }
        ]
    }"#;

    #[test]
    fn parses_version_zip_url_and_digest_from_release() {
        let release: Release = serde_json::from_str(FIXTURE_RELEASE).unwrap();
        let info = parse_release(&release, Arch::X64).expect("release must parse");
        assert_eq!(info.browser_version, "148.0.7778.96-1.1");
        assert_eq!(info.engine_version, "148.0.7778.96");
        assert_eq!(info.download_url, "https://example.invalid/uc-x64.zip");
        assert!(info.signature_url.is_none());
        assert_eq!(
            info.sha256.as_deref(),
            Some("1111111111111111111111111111111111111111111111111111111111111111")
        );
    }

    #[test]
    fn parse_release_fails_when_arch_missing() {
        let release: Release = serde_json::from_str(FIXTURE_RELEASE).unwrap();
        let err =
            parse_release(&release, Arch::Arm64).expect_err("no arm64 asset exists in the fixture");
        assert!(matches!(err, BrowserError::Parse(_)));
    }

    #[test]
    fn installed_version_reads_the_nomad_marker() {
        let dir = tempfile::tempdir().unwrap();
        let browser = UngoogledChromium::new(Arch::X64);
        assert!(browser.installed_version(dir.path()).is_none());

        let marker = InstalledVersion {
            browser_version: "148.0.7778.96-1.1".to_owned(),
            engine_version: "148.0.7778.96".to_owned(),
        };
        write_version_marker(dir.path(), &marker).unwrap();
        assert_eq!(browser.installed_version(dir.path()), Some(marker));
    }

    #[test]
    fn launch_command_targets_chrome_exe() {
        let browser = UngoogledChromium::new(Arch::X64);
        let command = browser.launch_command(Path::new("C:/games/uc"), &[]);
        let program = Path::new(command.get_program());
        assert!(program.ends_with("chrome.exe"));
        let args: Vec<_> = command.get_args().collect();
        assert!(
            args.iter()
                .any(|a| a.to_string_lossy().starts_with("--user-data-dir=")),
            "--user-data-dir must be present"
        );
    }

    #[test]
    fn profile_dir_is_beside_install_dir() {
        let browser = UngoogledChromium::new(Arch::X64);
        let install = Path::new("C:/nomad/ungoogled-chromium");
        let profile = browser.profile_dir(install).unwrap();
        assert_eq!(profile, Path::new("C:/nomad/Data"));
    }

    #[test]
    fn hardening_flags_omit_no_first_run_so_initial_preferences_can_seed_developer_mode() {
        let browser = UngoogledChromium::new(Arch::X64);
        let Hardening::LaunchFlags { flags, .. } = browser.hardening() else {
            panic!("ungoogled-chromium must return LaunchFlags hardening");
        };
        assert!(
            !flags.contains(&"--no-first-run"),
            "--no-first-run must be conditional (in launch_command), not part of the baseline hardening set"
        );
    }

    #[test]
    fn launch_command_omits_no_first_run_on_clean_first_launch() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("ungoogled-chromium");
        std::fs::create_dir_all(&install).unwrap();
        let browser = UngoogledChromium::new(Arch::X64);
        let cmd = browser.launch_command(&install, &[]);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            !args.iter().any(|a| a == "--no-first-run"),
            "without an existing profile, --no-first-run must NOT be appended so initial_preferences can seed developer_mode"
        );
    }

    /// Regression: Nomad writes `Default/Preferences` (HTTPS-only, etc.) *before*
    /// launch, so gating `--no-first-run` on that file wrongly suppressed first
    /// run on the very first launch — and Developer mode never seeded. The gate
    /// must ignore Nomad-written `Default/Preferences` and only react to
    /// Chromium-written `Default/Secure Preferences`.
    #[test]
    fn launch_command_omits_no_first_run_when_only_nomad_wrote_preferences() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("ungoogled-chromium");
        let profile = dir.path().join("Data");
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        // Simulate Nomad's pre-launch write of Default/Preferences (no Secure
        // Preferences yet — Chromium has not run).
        std::fs::write(
            profile.join("Default").join("Preferences"),
            r#"{"https_only_mode_enabled":true}"#,
        )
        .unwrap();
        let browser = UngoogledChromium::new(Arch::X64);
        let cmd = browser.launch_command(&install, &[]);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            !args.iter().any(|a| a == "--no-first-run"),
            "Default/Preferences alone (Nomad-written) must NOT trigger --no-first-run; \
             first run must proceed so initial_preferences seeds developer_mode"
        );
    }

    #[test]
    fn launch_command_includes_no_first_run_after_chromium_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("ungoogled-chromium");
        let profile = dir.path().join("Data");
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        // Chromium writes Secure Preferences during first run.
        std::fs::write(
            profile.join("Default").join("Secure Preferences"),
            r#"{"extensions":{"ui":{"developer_mode":true}}}"#,
        )
        .unwrap();
        let browser = UngoogledChromium::new(Arch::X64);
        let cmd = browser.launch_command(&install, &[]);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.iter().any(|a| a == "--no-first-run"),
            "once Chromium has run (Secure Preferences exists), --no-first-run must be appended"
        );
    }

    #[test]
    fn chrome_first_run_complete_reflects_secure_preferences() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path();
        assert!(
            !chrome_first_run_complete(profile),
            "missing Default/Secure Preferences must report not-yet-run"
        );
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        // Nomad-written Default/Preferences must NOT count as a completed run.
        std::fs::write(profile.join("Default").join("Preferences"), b"{}").unwrap();
        assert!(
            !chrome_first_run_complete(profile),
            "Default/Preferences (Nomad-written) must not be mistaken for a completed first run"
        );
        std::fs::write(profile.join("Default").join("Secure Preferences"), b"{}").unwrap();
        assert!(
            chrome_first_run_complete(profile),
            "Default/Secure Preferences (Chromium-written) must report first-run complete"
        );
    }

    #[test]
    fn launch_command_omits_load_extension_when_ubo_not_staged() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("ungoogled-chromium");
        std::fs::create_dir_all(&install).unwrap();
        let browser = UngoogledChromium::new(Arch::X64);
        let cmd = browser.launch_command(&install, &[]);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            !args.iter().any(|a| a.starts_with("--load-extension=")),
            "--load-extension= must NOT be appended when uBO has not been staged"
        );
    }

    #[test]
    fn launch_command_appends_load_extension_when_ubo_is_staged() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("ungoogled-chromium");
        let ubo_dir = install.join("nomad-extensions").join("uBlock0");
        std::fs::create_dir_all(&ubo_dir).unwrap();
        std::fs::write(
            ubo_dir.join("manifest.json"),
            br#"{"version":"1.71.0","name":"uBlock Origin"}"#,
        )
        .unwrap();
        let browser = UngoogledChromium::new(Arch::X64);
        let cmd = browser.launch_command(&install, &[]);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let load_ext_arg = args
            .iter()
            .find(|a| a.starts_with("--load-extension="))
            .expect("--load-extension= must be appended when uBO is staged");
        assert!(
            load_ext_arg.contains("nomad-extensions"),
            "load-extension path must point at the staged uBO directory, got: {load_ext_arg}"
        );
        assert!(load_ext_arg.contains("uBlock0"));
    }

    #[test]
    fn hardening_returns_safe_launch_flags_with_state_seeding() {
        let browser = UngoogledChromium::new(Arch::X64);
        let Hardening::LaunchFlags {
            flags,
            local_state,
            preferences,
        } = browser.hardening()
        else {
            panic!("ungoogled-chromium must return LaunchFlags hardening");
        };
        assert!(!flags.is_empty(), "the safe flag set must not be empty");
        assert!(flags.contains(&"--no-pings"));
        // Aggressive, site-breaking switches must never appear (SPEC §13).
        assert!(
            !flags.iter().any(|f| f.contains("disable-webgl")),
            "site-breaking flags must be excluded from the safe set"
        );
        assert!(
            local_state.is_some(),
            "ungoogled-chromium must seed Local State for chrome://flags visibility"
        );
        assert!(
            preferences.is_some(),
            "ungoogled-chromium must seed profile preferences"
        );
    }

    #[test]
    fn merged_initial_preferences_carry_developer_mode_and_profile_hardening() {
        // Regression for the first-run clobber: Chromium regenerates
        // Default/Preferences from initial_preferences on first run, so the
        // profile-pref hardening must be folded into the initial_preferences
        // payload — not only seeded into Default/Preferences (which first run
        // discards). Verified end-to-end at runtime against UC.
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
        assert_eq!(
            v["net"]["network_prediction_options"], 2,
            "first-run profile must disable network prediction (nested net.* key)"
        );
    }

    #[test]
    fn metadata_is_stable() {
        let browser = UngoogledChromium::new(Arch::X64);
        assert_eq!(browser.id(), "ungoogled-chromium");
        assert_eq!(browser.display_name(), "Ungoogled Chromium");
        assert_eq!(browser.engine(), Engine::Chromium);
        assert!(browser.public_key().is_none());
    }

    #[tokio::test]
    async fn fetch_returns_offline_error_on_connection_failure() {
        // Port 1 is never open; the OS rejects the connection immediately.
        let browser =
            UngoogledChromium::with_releases_url(Arch::X64, "http://127.0.0.1:1/releases/latest");
        let err = browser.fetch_latest_version().await.unwrap_err();
        assert!(
            matches!(err, BrowserError::Offline(_)),
            "connection refused must produce BrowserError::Offline, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn fetch_returns_offline_error_on_http_403() {
        use httpmock::prelude::*;
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases/latest");
            then.status(403);
        });
        let browser =
            UngoogledChromium::with_releases_url(Arch::X64, server.url("/releases/latest"));
        let err = browser.fetch_latest_version().await.unwrap_err();
        assert!(
            matches!(err, BrowserError::Offline(_)),
            "HTTP 403 must produce BrowserError::Offline, got: {err:?}"
        );
    }

    // ── gorhill uBO update tests ──────────────────────────────────────────────
    //
    // Test fixture: RSA-2048 test key pair generated with gpg for use in tests.
    // Signs a synthetic gorhill commit verification payload. Confers no
    // real-world trust; used only to exercise the full GPG verification path.
    //
    // Test key fingerprint: 7B9D09AD50C8C4404E094175487F5FBDD2A17F93

    /// The synthetic payload that `TEST_GPG_SIG` was created over.
    const TEST_GPG_PAYLOAD: &str = r"tree abc123\nauthor gorhill <gorhill@example.invalid> 1700000000 +0000\ncommitter gorhill <gorhill@example.invalid> 1700000000 +0000\n\nRelease 1.99.0\n";

    const TEST_GPG_PUBKEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
\n\
mQENBGoYgBABCADO+Uf59RpZa4S2NWZ6PKn+f65VTDlxFcwuWohy4x6EA2/V0rSg\n\
o7kiUIY5pUdgXqIEJ2XmFfJjCyi5+H3PiN7pEHcL2Wpu8fJ+/mJkDofvN5EmXBl1\n\
vF+7eqS1yy3N3SQgHz4gmzhkkQwwhJz8ByJlfOKz+tWQJuNjMyDJGsJ4SwfGBjst\n\
hgZuWNKF18xihXZL2eM9hiqsFg7PWWBeQVu8gi8ZGIbQprsdzmddbhcTcw12WTOI\n\
iwGTc/VxH3XcE7gr28QTfW+tyn3/5RahS43Jh8Nxo9v5fuaBV7SqqbOG+ZMaGijf\n\
+yhQC0GGOcmDK4XUIIJes1GvgQP8rhlge9nvABEBAAG0IlRlc3RHb3JoaWxsIDx0\n\
ZXN0QGV4YW1wbGUuaW52YWxpZD6JAU8EEwEKADkWIQR7nQmtUMjEQE4JQXVIf1+9\n\
0qF/kwUCahiAEAMbLwQFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQSH9fvdKh\n\
f5OoMQgAiJa4G69oCkJtwMpIqy6zkvdcOujSXiRGW5oBOri33NC6zasjq7NrYNmw\n\
RS//tmDO06EQp983xnm/69zfs6vmRzDfVqxIy99aC5CuKy4pCmf6ew4o9ABpGjcM\n\
om+Q+efeNc2hkaG74IHBaw8RPpcdyCIDlLc9r4aF9XJIOLpAm0igxeTI9q3Pko4s\n\
y8hdwEA1JmaL60kc/amBnLraf9ukV15NBFUAwVUZba3iG4NMzBrlMhIpykM+Z+d1\n\
pZ3myWBUMG2znkiK5WAK8mULqVmDy8xDqQMN7+2nBCpyqHZnGgaAs+uBiwFqfuok\n\
Cj2fTehE+RqbWIHspi54nXkXFRJg97kBDQRqGIAQAQgA0is3ZLF01B5SPFVU5hDP\n\
aq8RWOqPHFOyMMH0bJXDKLx2xw6oOuwcl3vM0VKopBVQjNCMqeNORYOc0IU3oCgt\n\
jfN7vVPx1YoicgbTeblwtnQAUbscQB2Xi14xfmwD4jUfipbkE04lZDdZT6xQnsMk\n\
iurMmoI47ixInssUHKin42zrb5VC/GrfBjRpblCRGiqlAbsYog+WppeJIxDd1mzv\n\
2s43M9kxX8msfWaeWhTqhrw3st79dSsDvbCRetj6pMcf2sd9gD/Cjt1l9wLGd559\n\
nTngSr5qnhbv4Rd7uycu90u5XmcokjuYOgsNowbn1oxZ+4FjK4WiC/OsTLhnm2Dh\n\
0QARAQABiQJsBBgBCgAgFiEEe50JrVDIxEBOCUF1SH9fvdKhf5MFAmoYgBACGy4B\n\
QAkQSH9fvdKhf5PAdCAEGQEKAB0WIQQ36afiS1qrMLAVVwdxzAnyDfOHfwUCahiA\n\
EAAKCRBxzAnyDfOHf3BMCACYxbteTj/CTYpYSXH/mrfcPJrl4RnzSnNXK8MR7Z2s\n\
K9iBS2wse4r7lM5uDR4WkHbJN2YrNdbdNaQrMWNLFCvlVpDq0jUWnTlf4aDgAeTd\n\
KNxhNvZUsWmZ1+ZMDeHKm8dbHYr5meDWDtszT4yu8uRpUbQSNQSwlU4iN86eb+zN\n\
G0jcxBk8BuJC8WnB1X2fwe5KbtIejNeT/04jhL8xOzQIY59xHq7nvHs5GInVjL1u\n\
Ol106hoU2KBstwjTzvwd3AGcYe6XioyYGT17KploExr7rpzhVWNw9CSuuk8583IB\n\
ewFdUVmk6z1v1YSpLb4KWFnVaMxmkXj4TvQgjuLtiS56ShoIAL7uK6nx6rG5Mrx7\n\
IrU6dSL0ahT9p0b3uWan0ll0raAqanuPlxhUiZ5sO+JRqcWnFMcueVFpChMbb/9A\n\
6LoYMHE4dwDYUYcqsRuWQ73HWk2XRBM2zLY/2dDc8skWVmKl0qsm8n/V5eHKSyFf\n\
PAQDyBFkDyodyAAxEvX4HQAaqDIEpVk81eE49ciuJCWyShHQp4CaHHzLV8tCzp3I\n\
eAhkV7Wr2elLGF6xgYLKAHYOvvS3w9MwN+8RprwycUlZ0dHtBNBf77URY5ywt74r\n\
P94+bIoFfgOLmHh3U7Jk5rU6F2rgi9T6cd/jRTzlMyw3lgIsYX7Itjv9AyXxjJlr\n\
JmcQWz0=\n\
=Kb5e\n\
-----END PGP PUBLIC KEY BLOCK-----\n";

    const TEST_GPG_SIG: &str = "-----BEGIN PGP SIGNATURE-----\n\
\n\
iQEzBAABCgAdFiEEN+mn4ktaqzCwFVcHccwJ8g3zh38FAmoYgBAACgkQccwJ8g3z\n\
h3/ylggAlt7aceF2d+KiHEmY3V3Yi8JAimkYRZO+LJijPnFgh2QlPhwldakyM+dE\n\
N/wLEAot4HOWc7VvYtyeqE1KNIJ4FJemBkmWdyue/3Fr8T7yfl7BacGS4IAqna9B\n\
M+tfF85YnBJmDxiPTjhv8/EcGI147fNbZr5/KTqiknEgfuhgbmX2ryTQfEVvhzzK\n\
B3+UtN/g+EYPdtFk/TWASUfsY/JNotScDt8qM0xI7jKjxqHLnm0aNp/NxUjlu9dV\n\
UR9Y0oXDGvGeJG5OvKlYALST/iwstslA/gXa+6gEpyuXJkh9pDns6CRLJJ93+2WQ\n\
J+Zu3X5lo7QO2O3KqJIO5kkGah4xBA==\n\
=TCNQ\n\
-----END PGP SIGNATURE-----\n";

    // ── fixtures ──────────────────────────────────────────────────────────────

    /// Release JSON with a healthy asset timeline (uploaded just before
    /// publication, never re-uploaded) so the provenance check passes.
    fn gorhill_release_json(tag: &str, zip_url: &str) -> String {
        gorhill_release_json_with_timeline(
            tag,
            zip_url,
            "2026-01-10T12:00:00Z", // asset created_at
            "2026-01-10T12:00:01Z", // asset updated_at (benign finalization skew)
            "2026-01-10T12:05:00Z", // release published_at
        )
    }

    fn gorhill_release_json_with_timeline(
        tag: &str,
        zip_url: &str,
        created_at: &str,
        updated_at: &str,
        published_at: &str,
    ) -> String {
        format!(
            r#"{{"tag_name":"{tag}","published_at":"{published_at}","assets":[{{"name":"uBlock0_{tag}.chromium.zip","browser_download_url":"{zip_url}","digest":null,"created_at":"{created_at}","updated_at":"{updated_at}"}}]}}"#
        )
    }

    fn gorhill_commit_ref_json(sha: &str) -> String {
        format!(r#"{{"object":{{"sha":"{sha}","type":"commit"}}}}"#)
    }

    fn gorhill_commit_json(
        verified: bool,
        reason: &str,
        payload: Option<&str>,
        sig: Option<&str>,
    ) -> String {
        let p = payload.map_or_else(
            || "null".to_owned(),
            |s| {
                let escaped = s
                    .replace('\\', r"\\")
                    .replace('"', r#"\""#)
                    .replace('\n', r"\n");
                format!("\"{escaped}\"")
            },
        );
        let s = sig.map_or_else(
            || "null".to_owned(),
            |s| {
                let escaped = s
                    .replace('\\', r"\\")
                    .replace('"', r#"\""#)
                    .replace('\n', r"\n");
                format!("\"{escaped}\"")
            },
        );
        format!(
            r#"{{"commit":{{"verification":{{"verified":{verified},"reason":"{reason}","payload":{p},"signature":{s}}}}}}}"#
        )
    }

    fn make_ubo_zip() -> Vec<u8> {
        use std::io::Write;
        let mut buf = Vec::new();
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zw = zip::ZipWriter::new(cursor);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
        zw.start_file("manifest.json", opts).unwrap();
        zw.write_all(br#"{"version":"1.99.0","name":"uBlock Origin"}"#)
            .unwrap();
        zw.finish().unwrap();
        buf
    }

    /// Registers all four gorhill API mock endpoints (releases, tag ref, commit, zip).
    fn mock_gorhill_commit_flow(
        server: &httpmock::MockServer,
        tag: &str,
        commit_sha: &str,
        commit_json: &str,
        zip_bytes: &[u8],
    ) {
        let zip_path = format!("/{tag}.zip");
        let zip_url = server.url(&zip_path);
        server.mock(|when, then| {
            when.method(GET).path("/releases/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(gorhill_release_json(tag, &zip_url));
        });
        server.mock(|when, then| {
            when.method(GET).path(format!("/git/refs/tags/{tag}"));
            then.status(200)
                .header("Content-Type", "application/json")
                .body(gorhill_commit_ref_json(commit_sha));
        });
        server.mock(|when, then| {
            when.method(GET).path(format!("/commits/{commit_sha}"));
            then.status(200)
                .header("Content-Type", "application/json")
                .body(commit_json);
        });
        server.mock(|when, then| {
            when.method(GET).path(zip_path.clone());
            then.status(200)
                .header("Content-Type", "application/zip")
                .body(zip_bytes);
        });
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn gorhill_ubo_update_stages_on_valid_gpg_signature() {
        let tag = "1.99.0";
        let zip = make_ubo_zip();
        // Use the pre-computed test key + signature (gorhill_key_armored bypasses
        // the fingerprint check in test builds, so the test key is accepted).
        let commit_json =
            gorhill_commit_json(true, "valid", Some(TEST_GPG_PAYLOAD), Some(TEST_GPG_SIG));
        let server = MockServer::start();
        mock_gorhill_commit_flow(&server, tag, "abc123def456", &commit_json, &zip);

        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        std::fs::create_dir_all(&install).unwrap();
        let cache_path = dir.path().join("cache.toml");

        update_ubo_from_gorhill(
            &install,
            &server.base_url(),
            true,
            &cache_path,
            TEST_GPG_PUBKEY.as_bytes(),
        )
        .await
        .expect("valid GPG signature must result in successful staging");

        assert!(
            install
                .join("nomad-extensions/uBlock0/manifest.json")
                .is_file(),
            "uBO must be staged after valid GPG verification"
        );
        let cache = crate::version_cache::VersionCache::load(&cache_path).unwrap();
        assert_eq!(cache.ubo_version.as_deref(), Some("1.99.0"));
    }

    #[tokio::test]
    async fn gorhill_ubo_update_defers_on_suspect_asset_provenance() {
        // An asset whose bytes were replaced days after upload (updated_at
        // far past created_at) is the fingerprint of a release-asset swap —
        // the one attack the tag GPG signature cannot see. The update must
        // be skipped without error and nothing staged.
        let tag = "1.99.0";
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(gorhill_release_json_with_timeline(
                    tag,
                    &server.url(format!("/{tag}.zip")),
                    "2026-01-10T12:00:00Z", // created with the release…
                    "2026-01-14T03:00:00Z", // …bytes replaced four days later
                    "2026-01-10T12:05:00Z",
                ));
        });

        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        std::fs::create_dir_all(&install).unwrap();
        let cache_path = dir.path().join("cache.toml");

        update_ubo_from_gorhill(
            &install,
            &server.base_url(),
            true,
            &cache_path,
            TEST_GPG_PUBKEY.as_bytes(),
        )
        .await
        .expect("a suspect asset must defer the update, not fail the launch");

        assert!(
            !install.join("nomad-extensions/uBlock0").is_dir(),
            "nothing must be staged from a provenance-suspect asset"
        );
        let cache = crate::version_cache::VersionCache::load(&cache_path);
        assert!(
            cache.and_then(|c| c.ubo_version).is_none(),
            "the cache must not record a version that was never staged"
        );
    }

    #[tokio::test]
    async fn gorhill_ubo_update_rejects_unverified_commit() {
        let tag = "1.99.0";
        let zip = make_ubo_zip();
        let commit_json = gorhill_commit_json(false, "no_pubkey", Some("payload"), Some("sig"));
        let server = MockServer::start();
        mock_gorhill_commit_flow(&server, tag, "sha1", &commit_json, &zip);

        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        std::fs::create_dir_all(&install).unwrap();
        let cache_path = dir.path().join("cache.toml");

        let err =
            update_ubo_from_gorhill(&install, &server.base_url(), true, &cache_path, GORHILL_KEY)
                .await
                .expect_err("unverified commit must be rejected");
        assert!(
            matches!(err, BrowserError::Verification(_)),
            "expected Verification error, got: {err:?}"
        );
        assert!(
            !install.join("nomad-extensions/uBlock0").is_dir(),
            "nothing must be staged when signature is unverified"
        );
    }

    #[tokio::test]
    async fn gorhill_ubo_update_rejects_missing_signature_fields() {
        let tag = "1.99.0";
        let zip = make_ubo_zip();
        // verified=true but no payload or signature
        let commit_json = gorhill_commit_json(true, "valid", None, None);
        let server = MockServer::start();
        mock_gorhill_commit_flow(&server, tag, "sha1", &commit_json, &zip);

        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        std::fs::create_dir_all(&install).unwrap();
        let cache_path = dir.path().join("cache.toml");

        let err =
            update_ubo_from_gorhill(&install, &server.base_url(), true, &cache_path, GORHILL_KEY)
                .await
                .expect_err("missing fields must be rejected");
        assert!(matches!(err, BrowserError::Verification(_)));
    }

    #[tokio::test]
    async fn gorhill_ubo_update_skips_when_already_current() {
        let tag = "1.99.0";
        server_for_releases_only(tag, |server, base_url| async move {
            let dir = tempfile::tempdir().unwrap();
            let install = dir.path().join("Browser");
            std::fs::create_dir_all(&install).unwrap();
            let cache_path = dir.path().join("cache.toml");
            crate::version_cache::update_ubo_version(&cache_path, tag);
            // Staged dir must exist; without it the short-circuit does not fire
            // (the files-missing path forces re-staging even at the same version).
            let ubo_dir = install.join("nomad-extensions").join("uBlock0");
            std::fs::create_dir_all(&ubo_dir).unwrap();
            std::fs::write(ubo_dir.join("manifest.json"), br#"{"version":"1.99.0"}"#).unwrap();

            let tag_ref_mock = server.mock(|when, then| {
                when.method(GET).path(format!("/git/refs/tags/{tag}"));
                then.status(500); // must never be hit
            });

            update_ubo_from_gorhill(&install, &base_url, true, &cache_path, GORHILL_KEY)
                .await
                .expect("already-current must not error");
            assert_eq!(
                tag_ref_mock.hits(),
                0,
                "no further API calls when already current and staged"
            );
        })
        .await;
    }

    /// Regression: a browser update atomically replaces Browser/ (wiping the
    /// staged nomad-extensions/uBlock0/), while Nomad/ (and its version cache)
    /// survives.  On the next launch the cache still records the current uBO
    /// version, but the files are gone — uBO must be re-staged, not skipped.
    #[tokio::test]
    async fn gorhill_ubo_update_restages_when_files_wiped_despite_same_version() {
        let tag = "1.99.0";
        let zip = make_ubo_zip();
        let commit_json =
            gorhill_commit_json(true, "valid", Some(TEST_GPG_PAYLOAD), Some(TEST_GPG_SIG));
        let server = MockServer::start();
        mock_gorhill_commit_flow(&server, tag, "abc123def456", &commit_json, &zip);

        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        std::fs::create_dir_all(&install).unwrap();
        let cache_path = dir.path().join("cache.toml");
        // Cache says current version installed, but staged directory is absent
        // (simulates post-browser-update state where Browser/ was swapped out).
        crate::version_cache::update_ubo_version(&cache_path, tag);

        update_ubo_from_gorhill(
            &install,
            &server.base_url(),
            true,
            &cache_path,
            TEST_GPG_PUBKEY.as_bytes(),
        )
        .await
        .expect("re-staging must succeed when staged dir is missing");

        assert!(
            install
                .join("nomad-extensions/uBlock0/manifest.json")
                .is_file(),
            "uBO must be re-staged when the directory is missing, even if the cached version matches"
        );
    }

    #[tokio::test]
    async fn gorhill_ubo_update_defers_when_auto_download_false() {
        let tag = "1.99.0";
        server_for_releases_only(tag, |server, base_url| async move {
            let tag_ref_mock = server.mock(|when, then| {
                when.method(GET).path(format!("/git/refs/tags/{tag}"));
                then.status(500); // must never be hit
            });

            let dir = tempfile::tempdir().unwrap();
            let install = dir.path().join("Browser");
            std::fs::create_dir_all(&install).unwrap();
            let cache_path = dir.path().join("cache.toml");

            update_ubo_from_gorhill(&install, &base_url, false, &cache_path, GORHILL_KEY)
                .await
                .expect("deferred update must not error");
            assert_eq!(
                tag_ref_mock.hits(),
                0,
                "no GPG/download when auto_download = false"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn gorhill_ubo_update_falls_back_gracefully_when_offline() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        std::fs::create_dir_all(&install).unwrap();
        let cache_path = dir.path().join("cache.toml");

        update_ubo_from_gorhill(
            &install,
            "http://127.0.0.1:1",
            true,
            &cache_path,
            GORHILL_KEY,
        )
        .await
        .expect("offline must degrade gracefully");
    }

    /// Starts a mock server that serves only the `/releases/latest` endpoint,
    /// runs `f` with the server and its base URL, then drops the server.
    async fn server_for_releases_only<F, Fut>(tag: &str, f: F)
    where
        F: FnOnce(httpmock::MockServer, String) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases/latest");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(gorhill_release_json(tag, "http://unused"));
        });
        let base_url = server.base_url();
        f(server, base_url).await;
    }

    #[test]
    fn gorhill_embedded_key_matches_pinned_fingerprint() {
        // This test exercises the non-test variant of gorhill_key_armored.
        use pgp::composed::Deserializable;
        use pgp::types::KeyDetails;
        let cursor = std::io::Cursor::new(GORHILL_KEY);
        let (iter, _) = pgp::composed::SignedPublicKey::from_armor_many(cursor).unwrap();
        let mut found = false;
        for key in iter.flatten() {
            let fp = hex::encode_upper(key.primary_key.fingerprint().as_bytes());
            if fp.eq_ignore_ascii_case(GORHILL_KEY_FINGERPRINT) {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "embedded gorhill.asc must contain a key with fingerprint {GORHILL_KEY_FINGERPRINT}"
        );
    }
}
