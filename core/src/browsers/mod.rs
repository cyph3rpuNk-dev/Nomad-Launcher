//! The browser-family contract and its shared value types.
//!
//! Every `nomad-<browser>.exe` launcher instantiates exactly one
//! [`BrowserFamily`] implementor and hands it to the core runner (`run`,
//! added in a later task). All browser-specific behaviour — where to find
//! updates, how to verify and extract them, how to launch — lives behind
//! this trait.

use std::future::Future;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

pub mod bitwarden;
pub mod firefox;
pub mod floorp;
mod github;
pub mod helium;
pub mod librewolf;
pub mod mullvad;
pub mod ungoogled;
pub mod waterfox;

/// GitHub Releases API URL for uBlock Origin — used to provision the Firefox
/// XPI locally so `policies.json` can reference it with a `file://` URL
/// instead of the AMO endpoint at runtime.
///
/// AMO is used here instead of gorhill's GitHub releases because gorhill
/// publishes only the unsigned `.firefox.xpi` to GitHub, which Firefox stable
/// (and ESR) hardcode-reject at install time regardless of any `policies.json`
/// or `lockPref` override. AMO returns the Mozilla-signed variant of the same
/// release, which installs cleanly on every Gecko build.
pub(crate) const UBLOCK_RELEASES_URL: &str =
    "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/";

/// Fetches the latest Mozilla-signed uBlock Origin XPI from AMO into
/// `<xpi_dir>/uBlock0.xpi`, returning the on-disk path.
///
/// The call is idempotent: a `HEAD` request resolves the `/latest/` redirect
/// to a versioned CDN URL (e.g. `…/ublock_origin-1.70.0.xpi`); if that
/// version matches the cached version and the file exists, the bytes are not
/// re-downloaded.
///
/// `cache_path` is the path to `nomad-version-cache.toml`; the `ubo_version`
/// field there is updated after a successful download. `auto_download` gates
/// whether a discovered newer version is actually downloaded.
///
/// The downloaded XPI is sanity-checked for Mozilla signature files
/// (`META-INF/*.rsa`, `*.sf`) before being kept; an unsigned XPI is treated
/// as a verification failure and the temporary file is deleted.
///
/// # Errors
/// Returns a [`BrowserError`] on network, I/O, or verification failure.
pub(crate) async fn provision_gecko_ublock_xpi(
    download_url: &str,
    xpi_dir: &std::path::Path,
    cache_path: &std::path::Path,
    auto_download: bool,
) -> Result<std::path::PathBuf> {
    let client = github::build_client()?;

    let xpi_path = xpi_dir.join("uBlock0.xpi");

    // Resolve the /latest/ redirect to discover the current AMO-published
    // version without downloading the 4-5 MB XPI body each launch.
    let resolved_url = client
        .head(download_url)
        .send()
        .await
        .map_err(github::map_network_err)?
        .url()
        .to_string();
    let version =
        extract_ublock_version_from_url(&resolved_url).unwrap_or_else(|| "unknown".to_owned());

    // Check version: prefer nomad-version-cache.toml, fall back to legacy marker.
    let cached_version = crate::version_cache::VersionCache::load(cache_path)
        .and_then(|c| c.ubo_version)
        .or_else(|| {
            std::fs::read_to_string(xpi_dir.join(".ublock-version"))
                .ok()
                .map(|s| s.trim().to_owned())
        });

    if cached_version.as_deref() == Some(version.as_str()) && xpi_path.exists() {
        tracing::debug!(version = %version, "uBlock XPI already up to date; skipping download");
        return Ok(xpi_path);
    }

    if !auto_download {
        tracing::info!(
            current = cached_version.as_deref().unwrap_or("(none)"),
            available = %version,
            "newer uBlock XPI available but auto_download is disabled"
        );
        return Ok(xpi_path);
    }

    let (progress_tx, _) = tokio::sync::watch::channel(0.0f32);
    std::fs::create_dir_all(xpi_dir)?;
    crate::downloader::download(download_url, &xpi_path, &progress_tx).await?;

    // Refuse to keep an unsigned XPI: it would never install on Firefox
    // stable / ESR and may indicate a compromised CDN response.
    verify_signed_xpi(&xpi_path).inspect_err(|_| {
        let _ = std::fs::remove_file(&xpi_path);
    })?;

    crate::version_cache::update_ubo_version(cache_path, &version);
    // Also write the legacy marker so older launcher versions can read it.
    let _ = std::fs::write(xpi_dir.join(".ublock-version"), &version);

    tracing::info!(version = %version, ?xpi_path, "uBlock Origin XPI provisioned from AMO");
    Ok(xpi_path)
}

/// Extracts the uBlock version from a resolved AMO CDN URL.
///
/// AMO's `/latest/` endpoint redirects to a path like
/// `…/file/<file-id>/ublock_origin-<version>.xpi` — we read the version off
/// the final filename. Returns `None` if the URL does not follow this shape
/// (e.g. AMO changed the filename convention).
fn extract_ublock_version_from_url(url: &str) -> Option<String> {
    let last_segment = url.rsplit_once('/').map_or(url, |(_, f)| f);
    let trimmed = last_segment.split('?').next().unwrap_or(last_segment);
    let no_ext = trimmed.strip_suffix(".xpi")?;
    let after_prefix = no_ext.strip_prefix("ublock_origin-")?;
    if after_prefix.is_empty() {
        None
    } else {
        Some(after_prefix.to_owned())
    }
}

/// Verifies the XPI carries Mozilla AMO signature files in `META-INF/`.
/// Returns [`BrowserError::Verification`] when the archive is unsigned —
/// such an XPI would be rejected by Firefox stable / ESR at install time.
fn verify_signed_xpi(path: &std::path::Path) -> Result<()> {
    let bytes = std::fs::read(path)?;
    let cursor = std::io::Cursor::new(&bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| BrowserError::Parse(format!("XPI is not a valid ZIP archive: {e}")))?;
    for i in 0..archive.len() {
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        let name = entry.name();
        if name.starts_with("META-INF/") {
            let ext = std::path::Path::new(name)
                .extension()
                .and_then(|e| e.to_str());
            if ext.is_some_and(|e| e.eq_ignore_ascii_case("rsa") || e.eq_ignore_ascii_case("sf")) {
                return Ok(());
            }
        }
    }
    Err(BrowserError::Verification(
        "XPI is missing META-INF/ signature files (refusing to stage unsigned XPI)".to_owned(),
    ))
}

/// The rendering engine a browser is built on.
///
/// Selects engine-specific behaviour — e.g. the Chromium/Gecko launch-flag
/// injection in `build_launch_args` is gated on this, and `Electron` suppresses
/// it entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// Chromium-based browsers (Chromium, ungoogled-chromium, …).
    Chromium,
    /// Gecko-based, Firefox-family browsers (Firefox, Floorp, Pale Moon, …).
    Gecko,
    /// Electron-based desktop apps wrapped as portable launchers (Bitwarden).
    /// Not a rendering engine in the browser sense; the variant exists so the
    /// Chromium/Gecko-gated launch-flag injection in `build_launch_args` never
    /// applies to a non-browser app (it would feed browser switches the app's
    /// main process does not understand).
    Electron,
}

impl Engine {
    /// Engine name shown in the identity-card version subtitle,
    /// e.g. `"Firefox 150.0.2"` for [`Engine::Gecko`].
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Engine::Chromium => "Chromium",
            Engine::Gecko => "Firefox",
            Engine::Electron => "Desktop App",
        }
    }
}

/// A resolved upstream release: what to download and how to verify it.
#[derive(Debug, Clone)]
pub struct VersionInfo {
    /// The browser's own version string, e.g. `"1.19.12b"`.
    pub browser_version: String,
    /// The underlying engine version, e.g. `"150.0.2"`.
    pub engine_version: String,
    /// Direct URL to the downloadable package.
    pub download_url: String,
    /// URL of a detached GPG signature, when the upstream publishes one.
    pub signature_url: Option<String>,
    /// Expected SHA-256 hash of the package (lowercase hex), when the
    /// upstream publishes one. `None` means SHA-256 verification is skipped.
    pub sha256: Option<String>,
    /// Expected SHA-512 hash of the package (lowercase hex), when the
    /// upstream publishes one. `None` means SHA-512 verification is skipped.
    pub sha512: Option<String>,
}

/// Version metadata parsed from a local browser installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledVersion {
    /// The browser's own version string.
    pub browser_version: String,
    /// The underlying engine version.
    pub engine_version: String,
}

/// Channel sender used to report download progress in the range `0.0..=1.0`.
pub type ProgressSink = watch::Sender<f32>;

/// A browser's curated privacy-hardening payload (see SPEC §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hardening {
    /// Chromium-family: a curated "safe" set of command-line flags appended
    /// to the browser invocation at launch, plus optional JSON state seeding
    /// for `chrome://flags` visual consistency and profile-level prefs that
    /// cannot be set from the command line.
    ///
    /// File placement (both relative to the user-data-dir passed via
    /// `--user-data-dir=`):
    /// - `local_state` → `<user-data-dir>/Local State`. Drives the
    ///   `browser.enabled_labs_experiments` array that `chrome://flags`
    ///   reads, and the `dns_over_https.*` keys.
    /// - `preferences` → `<user-data-dir>/Default/Preferences`. Profile-level
    ///   prefs (HTTPS-only mode, Privacy Sandbox m1, Safe Browsing, Do Not
    ///   Track, …) that are not exposed as `--flag` switches.
    ///
    /// JSON merging is recursive and prefers existing user values; only
    /// `browser.enabled_labs_experiments` is array-merged by appending
    /// missing entries (matched on the `<basename>` before `@`).
    LaunchFlags {
        flags: &'static [&'static str],
        local_state: Option<&'static str>,
        preferences: Option<&'static str>,
    },
    /// Gecko-family: a curated `user.js` payload, an optional
    /// `distribution/policies.json`, and an optional autoconfig pair
    /// (`defaults/pref/autoconfig.js` + `nomad.cfg`).
    ///
    /// File placement:
    /// - `user_js` → `<profile_dir>/user.js` (legacy belt-and-suspenders;
    ///   profile prefs only apply after the profile loads).
    /// - `policies` → `<install_dir>/distribution/policies.json` at install time.
    /// - `autoconfig` → `<install_dir>/defaults/pref/autoconfig.js`. Tells
    ///   Gecko to load the .cfg before any profile.
    /// - `cfg` → `<install_dir>/nomad.cfg`. The actual `lockPref()` payload.
    ///
    /// Set `autoconfig` + `cfg` to `None` for forks that ship their own
    /// autoconfig bundle (e.g. `LibreWolf`), to avoid overwriting their files.
    ///
    /// `ublock_xpi_releases_url`: AMO `/latest/` download URL used to
    /// provision the Mozilla-signed uBlock XPI locally so policies.json can
    /// reference it with a `file://` URL — this avoids a per-launch phone-home
    /// to AMO while still installing an XPI Firefox stable will accept.
    /// `None` for browsers that already bundle uBlock (e.g. `LibreWolf`).
    GeckoProfile {
        user_js: &'static str,
        policies: Option<&'static str>,
        autoconfig: Option<&'static str>,
        cfg: Option<&'static str>,
        ublock_xpi_releases_url: Option<&'static str>,
    },
}

/// Errors produced by [`BrowserFamily`] operations.
#[derive(Debug, thiserror::Error)]
pub enum BrowserError {
    /// A network request failed.
    #[error("network error: {0}")]
    Network(String),
    /// A connection-level failure: no internet, DNS failure, timeout, or
    /// HTTP 403 (GitHub rate limit). The pipeline can auto-launch an existing
    /// install rather than showing an error screen.
    #[error("offline or rate-limited: {0}")]
    Offline(String),
    /// An upstream response could not be parsed.
    #[error("failed to parse upstream metadata: {0}")]
    Parse(String),
    /// A filesystem operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// Signature or hash verification failed.
    #[error("verification failed: {0}")]
    Verification(String),
    /// Archive extraction failed.
    #[error("extraction failed: {0}")]
    Extract(String),
}

/// Result alias for [`BrowserFamily`] operations.
pub type Result<T> = std::result::Result<T, BrowserError>;

/// One browser family that Nomad can update, prepare, and launch.
///
/// Implementors are constructed by their launcher crate (with any
/// arch/channel choices baked in) and are driven entirely through this trait
/// by the core runner.
pub trait BrowserFamily: Send + Sync {
    /// Stable identifier, e.g. `"ungoogled-chromium"`.
    fn id(&self) -> &'static str;

    /// Human-readable name for the identity card, e.g. `"Ungoogled Chromium"`.
    fn display_name(&self) -> &'static str;

    /// Full default `nomad.toml` written on first run. Browsers use the shared
    /// browser template; non-browser apps override this to ship a config that
    /// lists only the keys that affect them (e.g. Bitwarden, an Electron app,
    /// drops the Chromium/Gecko-only privacy keys). Only consulted when no
    /// config file exists yet; an existing `nomad.toml` always wins.
    fn default_config(&self) -> &'static str {
        crate::config::DEFAULT_NOMAD_TOML
    }

    /// The rendering engine this browser is built on.
    fn engine(&self) -> Engine;

    /// Embedded ASCII-armored GPG public key, or `None` when the upstream
    /// publishes no detached signature (verification is then SHA-256 only).
    fn public_key(&self) -> Option<&'static [u8]>;

    /// Reads the version metadata of the installation in `install_dir`,
    /// or `None` when no usable installation is present.
    fn installed_version(&self, install_dir: &Path) -> Option<InstalledVersion>;

    /// Queries the upstream for the latest available release.
    ///
    /// # Errors
    /// Returns [`BrowserError::Network`] if the request fails, or
    /// [`BrowserError::Parse`] if the response cannot be understood.
    fn fetch_latest_version(&self) -> impl Future<Output = Result<VersionInfo>> + Send;

    /// Downloads the package described by `info` to `dest`, reporting
    /// progress (`0.0..=1.0`) through `progress`.
    ///
    /// # Errors
    /// Returns [`BrowserError::Network`] on transfer failure or
    /// [`BrowserError::Io`] if the package cannot be written.
    fn download(
        &self,
        info: &VersionInfo,
        dest: &Path,
        progress: ProgressSink,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Verifies `package` against the detached signature `sig`.
    ///
    /// Only invoked when [`public_key`](Self::public_key) returns `Some`.
    ///
    /// # Errors
    /// Returns [`BrowserError::Verification`] if the signature does not
    /// validate against the embedded public key.
    fn verify_signature(&self, package: &Path, sig: &Path) -> Result<()>;

    /// Extracts the downloaded `package` into `install_dir`.
    ///
    /// # Errors
    /// Returns [`BrowserError::Extract`] or [`BrowserError::Io`] if the
    /// archive cannot be unpacked.
    fn extract(&self, package: &Path, install_dir: &Path) -> Result<()>;

    /// Carries browser state that lives *inside* `install_dir` across an update
    /// swap. Called after the fresh bundle is staged into `stage_dir` and
    /// immediately before [`crate::install::atomic_swap`] replaces the live
    /// install with it.
    ///
    /// The default is a no-op: every browser keeps its profile *outside*
    /// `install_dir`, so the wholesale swap is harmless. Bitwarden is the
    /// exception — its vault lives *inside* `install_dir` (`<install_dir>/Data`),
    /// so without this the swap would wipe the user's vault on every
    /// Nomad-driven update. Bitwarden overrides this to copy that directory
    /// from `current_install` into `stage_dir`.
    ///
    /// On a fresh install `current_install` does not yet exist; implementors
    /// must treat that as a no-op.
    ///
    /// # Errors
    /// Returns a [`BrowserError`] if state could not be carried over. The
    /// updater treats this as fatal for the swap (the existing install — with
    /// the user's profile — is left untouched), so data is never lost to a
    /// half-finished preservation.
    fn preserve_state_across_update(&self, current_install: &Path, stage_dir: &Path) -> Result<()> {
        let _ = (current_install, stage_dir);
        Ok(())
    }

    /// Returns the portable profile directory for Gecko-family browsers, or
    /// `None` for Chromium-family browsers.
    ///
    /// The pipeline writes the curated `user.js` into this directory before
    /// each launch when `[hardening] enabled = true`. Gecko browsers implement
    /// this by returning a path relative to `install_dir`'s parent (the base
    /// directory beside the launcher `.exe`).
    fn profile_dir(&self, install_dir: &Path) -> Option<std::path::PathBuf> {
        let _ = install_dir;
        None
    }

    /// Returns the browser's curated privacy-hardening payload (see SPEC §5).
    ///
    /// Chromium-family browsers return [`Hardening::LaunchFlags`]; the core
    /// runner appends those flags to the launch command when hardening is
    /// enabled in `nomad.toml`. Gecko-family browsers return
    /// [`Hardening::GeckoProfile`]; the core runner writes the profile files
    /// via [`crate::hardening`].
    fn hardening(&self) -> Hardening;

    /// Returns `true` when the browser ships its own fingerprint-noise framework
    /// that already randomises `navigator.hardwareConcurrency` (e.g. Helium's
    /// built-in "Helium Noise"). When `true`, the core runner does **not** layer
    /// the ungoogled `ReducedSystemInfo` feature on top even if
    /// `[hardening] reduce_system_info` is enabled: `ReducedSystemInfo` clamps
    /// the core count to a fixed `2`, which would override and degrade the
    /// browser's own randomised (and more believable) value. Defaults to `false`.
    fn has_builtin_fingerprint_noise(&self) -> bool {
        false
    }

    /// Accent colour for this browser's launcher window — progress-bar fill,
    /// links, focus, and the Nomad mark. Defaults to the Nomad family signature
    /// (the amber accent). Override only when a member's own brand should genuinely
    /// lead; the family is cohesion-first, so the default is preferred.
    fn accent(&self) -> eframe::egui::Color32 {
        crate::ui::theme::ACCENT
    }

    /// Performs browser-specific launch preparation after update/hardening and
    /// before the process is spawned.
    ///
    /// The default is a no-op. Implementors can use this for best-effort local
    /// staging that belongs to a specific browser build, such as Chromium
    /// default-app extension payloads. `hardening_config` is supplied so
    /// implementors can gate opt-in payloads on the user's `nomad.toml`
    /// settings.
    ///
    /// # Errors
    /// Returns a [`BrowserError`] if preparation could not complete. The core
    /// launcher logs this and continues launching the browser.
    fn prepare_launch(
        &self,
        install_dir: &Path,
        hardening_config: crate::config::HardeningConfig,
    ) -> Result<()> {
        let _ = install_dir;
        let _ = hardening_config;
        Ok(())
    }

    /// Best-effort async pre-launch hook to check and update uBlock Origin.
    ///
    /// Called from the launcher's pipeline thread after `prepare_launch` and
    /// before the browser is spawned, gated on `[update] check_on_launch`. The
    /// default implementation provisions the uBlock Origin Firefox XPI for
    /// Gecko-family browsers that set `ublock_xpi_releases_url` in their
    /// [`Hardening::GeckoProfile`] payload. Chromium-family browsers override
    /// this method to check `gorhill/uBlock` GitHub releases (GPG-verified tag).
    /// Errors are logged and never block the launch.
    ///
    /// `update_opts` carries the `auto_download` flag so that extension updates
    /// respect the same "download without prompting" setting as browser binaries.
    ///
    /// # Errors
    /// Returns a [`BrowserError`] when the update could not be completed.
    /// Treat all errors as advisory — the launcher logs and proceeds.
    fn fetch_extension_updates(
        &self,
        install_dir: &Path,
        _hardening_config: crate::config::HardeningConfig,
        update_opts: crate::updater::UpdateOptions,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let hardening = self.hardening();
        let launcher_dir = install_dir.parent().unwrap_or(install_dir);
        let nomad_dir = crate::config::nomad_subdir(launcher_dir);
        let xpi_dir = nomad_dir.join("Gecko-extensions");
        let cache_path = nomad_dir.join("nomad-version-cache.toml");
        async move {
            if let Hardening::GeckoProfile {
                ublock_xpi_releases_url: Some(url),
                ..
            } = hardening
            {
                provision_gecko_ublock_xpi(url, &xpi_dir, &cache_path, update_opts.auto_download)
                    .await?;
            }
            Ok(())
        }
    }

    /// Builds the command that launches the browser from `install_dir`,
    /// appending `args` to the browser's own command line.
    fn launch_command(&self, install_dir: &Path, args: &[String]) -> Command;

    /// URL of the upstream release page, shown in the status window's footer
    /// link ("Open upstream release page").
    fn upstream_url(&self) -> &'static str;
}

/// Filename of the Nomad-written version marker inside an install directory.
///
/// Browser builds rarely expose their version in a uniform, machine-readable
/// way, so Nomad records it itself after a successful update. The marker is
/// the single source of truth for [`BrowserFamily::installed_version`].
pub const VERSION_MARKER: &str = ".nomad-version";

/// Writes the Nomad version marker for `version` into `install_dir`.
///
/// # Errors
/// Returns [`BrowserError::Io`] if the marker file cannot be written, or
/// [`BrowserError::Parse`] if `version` cannot be serialized.
pub fn write_version_marker(install_dir: &Path, version: &InstalledVersion) -> Result<()> {
    let serialized = toml::to_string(version).map_err(|e| BrowserError::Parse(e.to_string()))?;
    std::fs::write(install_dir.join(VERSION_MARKER), serialized)?;
    Ok(())
}

/// Reads the Nomad version marker from `install_dir`.
///
/// Returns `None` when the marker is absent or unreadable — treated as
/// "no usable installation".
#[must_use]
pub fn read_version_marker(install_dir: &Path) -> Option<InstalledVersion> {
    let raw = std::fs::read_to_string(install_dir.join(VERSION_MARKER)).ok()?;
    toml::from_str(&raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    #[test]
    fn extracts_version_from_amo_cdn_url() {
        let url =
            "https://addons.mozilla.org/firefox/downloads/file/4721638/ublock_origin-1.70.0.xpi";
        assert_eq!(
            extract_ublock_version_from_url(url).as_deref(),
            Some("1.70.0")
        );
    }

    #[test]
    fn extracts_version_when_url_has_query_string() {
        let url = "https://example.invalid/ublock_origin-2.1.0.xpi?cache=bust";
        assert_eq!(
            extract_ublock_version_from_url(url).as_deref(),
            Some("2.1.0")
        );
    }

    #[test]
    fn returns_none_when_url_does_not_match_ublock_pattern() {
        for url in [
            "https://example.invalid/some-other-extension-1.0.xpi",
            "https://example.invalid/ublock_origin-.xpi", // empty version
            "https://example.invalid/ublock_origin",      // missing .xpi
            "https://example.invalid/",
        ] {
            assert!(
                extract_ublock_version_from_url(url).is_none(),
                "expected None for url: {url}"
            );
        }
    }

    // ── provision_gecko_ublock_xpi tests ──────────────────────────────────────

    /// Builds a minimal signed XPI (ZIP with META-INF/mozilla.rsa).
    fn make_signed_xpi() -> Vec<u8> {
        use std::io::Write;
        let mut buf = Vec::new();
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
        zip.start_file("META-INF/mozilla.rsa", opts).unwrap();
        zip.write_all(b"\x00\x01\x02").unwrap();
        zip.start_file("manifest.json", opts).unwrap();
        zip.write_all(b"{}").unwrap();
        zip.finish().unwrap();
        buf
    }

    #[tokio::test]
    async fn ublock_xpi_downloads_when_newer_version_available() {
        let server = MockServer::start();
        let xpi_bytes = make_signed_xpi();
        // Both HEAD and GET are served from the same URL whose path encodes the version.
        server.mock(|when, then| {
            when.method(httpmock::Method::HEAD)
                .path("/ublock_origin-1.71.0.xpi");
            then.status(200);
        });
        server.mock(|when, then| {
            when.method(GET).path("/ublock_origin-1.71.0.xpi");
            then.status(200)
                .header("Content-Type", "application/zip")
                .body(xpi_bytes.clone());
        });

        let dir = tempfile::tempdir().unwrap();
        let xpi_dir = dir.path().join("Gecko-extensions");
        let cache_path = dir.path().join("nomad-version-cache.toml");
        let url = server.url("/ublock_origin-1.71.0.xpi");

        provision_gecko_ublock_xpi(&url, &xpi_dir, &cache_path, true)
            .await
            .expect("provisioning must succeed");

        assert!(xpi_dir.join("uBlock0.xpi").exists(), "XPI must be staged");
        assert_eq!(
            std::fs::read_to_string(xpi_dir.join(".ublock-version"))
                .unwrap()
                .trim(),
            "1.71.0"
        );
        let cache = crate::version_cache::VersionCache::load(&cache_path).unwrap();
        assert_eq!(cache.ubo_version.as_deref(), Some("1.71.0"));
    }

    #[tokio::test]
    async fn ublock_xpi_skips_download_when_already_current() {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(httpmock::Method::HEAD)
                .path("/ublock_origin-1.71.0.xpi");
            then.status(200);
        });
        let download_mock = server.mock(|when, then| {
            when.method(GET).path("/ublock_origin-1.71.0.xpi");
            then.status(500); // must never be hit
        });

        let dir = tempfile::tempdir().unwrap();
        let xpi_dir = dir.path().join("Gecko-extensions");
        std::fs::create_dir_all(&xpi_dir).unwrap();
        // Pre-stage the XPI and write the version marker.
        std::fs::write(xpi_dir.join("uBlock0.xpi"), b"old xpi bytes").unwrap();
        std::fs::write(xpi_dir.join(".ublock-version"), "1.71.0").unwrap();
        let cache_path = dir.path().join("nomad-version-cache.toml");
        let url = server.url("/ublock_origin-1.71.0.xpi");

        provision_gecko_ublock_xpi(&url, &xpi_dir, &cache_path, true)
            .await
            .expect("must not fail when already current");
        assert_eq!(
            download_mock.hits(),
            0,
            "download must not be requested when XPI is current"
        );
    }

    #[tokio::test]
    async fn ublock_xpi_rejects_unsigned_xpi() {
        let server = MockServer::start();
        let unsigned_xpi = {
            use std::io::Write;
            let mut buf = Vec::new();
            let cursor = std::io::Cursor::new(&mut buf);
            let mut zip = zip::ZipWriter::new(cursor);
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip.start_file("manifest.json", opts).unwrap();
            zip.write_all(b"{}").unwrap();
            zip.finish().unwrap();
            buf
        };
        server.mock(|when, then| {
            when.method(httpmock::Method::HEAD)
                .path("/ublock_origin-1.99.0.xpi");
            then.status(200);
        });
        server.mock(|when, then| {
            when.method(GET).path("/ublock_origin-1.99.0.xpi");
            then.status(200)
                .header("Content-Type", "application/zip")
                .body(unsigned_xpi);
        });

        let dir = tempfile::tempdir().unwrap();
        let xpi_dir = dir.path().join("Gecko-extensions");
        let cache_path = dir.path().join("nomad-version-cache.toml");
        let url = server.url("/ublock_origin-1.99.0.xpi");

        let err = provision_gecko_ublock_xpi(&url, &xpi_dir, &cache_path, true)
            .await
            .expect_err("unsigned XPI must be rejected");
        assert!(
            matches!(err, BrowserError::Verification(_)),
            "expected Verification error, got: {err:?}"
        );
        assert!(
            !xpi_dir.join("uBlock0.xpi").exists(),
            "unsigned XPI must be cleaned up"
        );
    }

    #[tokio::test]
    async fn ublock_xpi_falls_back_gracefully_when_offline() {
        // Port 1 is never open; OS rejects immediately.
        let dir = tempfile::tempdir().unwrap();
        let xpi_dir = dir.path().join("Gecko-extensions");
        let cache_path = dir.path().join("nomad-version-cache.toml");

        let err =
            provision_gecko_ublock_xpi("http://127.0.0.1:1/latest/", &xpi_dir, &cache_path, true)
                .await
                .expect_err("offline must return an error");
        assert!(
            matches!(err, BrowserError::Offline(_)),
            "expected Offline error, got: {err:?}"
        );
    }

    #[test]
    fn verify_signed_xpi_accepts_archive_with_meta_inf_signature() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.xpi");
        let buf = std::fs::File::create(&path).unwrap();
        {
            let mut zip_w = zip::ZipWriter::new(buf);
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip_w.start_file("manifest.json", opts).unwrap();
            zip_w.write_all(b"{}").unwrap();
            zip_w.start_file("META-INF/mozilla.rsa", opts).unwrap();
            zip_w.write_all(b"\x00\x01\x02").unwrap();
            zip_w.finish().unwrap();
        }
        verify_signed_xpi(&path).expect("signed XPI must be accepted");
    }

    #[test]
    fn verify_signed_xpi_rejects_archive_without_signature_files() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsigned.xpi");
        let buf = std::fs::File::create(&path).unwrap();
        {
            let mut zip_w = zip::ZipWriter::new(buf);
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip_w.start_file("manifest.json", opts).unwrap();
            zip_w.write_all(b"{}").unwrap();
            zip_w.finish().unwrap();
        }
        let err = verify_signed_xpi(&path).expect_err("unsigned XPI must be rejected");
        assert!(matches!(err, BrowserError::Verification(_)));
    }
}
