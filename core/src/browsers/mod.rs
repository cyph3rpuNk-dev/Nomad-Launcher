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

pub mod floorp;
mod github;
mod staged;
pub use staged::StagedInstallLayout;
pub mod helium;
pub mod librewolf;
pub mod mullvad;
pub mod ungoogled;
pub mod waterfox;

/// Chromium-family switches that determine **how the profile is stored**, not
/// how private it is. Applied by `launch_command` on every launch, next to
/// `--user-data-dir`, and deliberately outside `[hardening] enabled`.
///
/// These are ungoogled-chromium switches (Helium inherits them):
///
/// - `--disable-machine-id` — without it Chromium mixes the host machine ID
///   into the seed for the `Secure Preferences` MACs. Those MACs protect
///   tracked preferences, `extensions.settings` among them, so changing the
///   seed invalidates every one of them: Chromium's tracked-preference
///   enforcement clears the protected values, the extension registry comes up
///   empty, and `ExtensionGarbageCollector` deletes the now-unreferenced
///   directories under `Default\Extensions`.
/// - `--disable-encryption` — without it cookies and auth tokens are sealed
///   with DPAPI, bound to the host OS user. Data written in one mode cannot be
///   decrypted in the other and Chromium drops what it cannot read.
/// - `--disable-features=DeviceBoundSessions` — Chrome 146+ binds sessions to
///   the host TPM. A browser that also passes a hardening
///   `--disable-features=` bundle overrides this one (Chromium honours only
///   the last occurrence), which is fine: that bundle is a superset.
///
/// Gating any of these on a config toggle means flipping the toggle silently
/// reformats an existing profile — the user loses their extensions and their
/// sign-ins, having changed a setting labelled "privacy hardening" (#38).
/// Keep them unconditional; the hardening list is for switches that are safe
/// to turn on and off between launches.
pub(crate) const CHROMIUM_PORTABILITY_FLAGS: &[&str] = &[
    "--disable-machine-id",
    "--disable-encryption",
    "--disable-features=DeviceBoundSessions",
];

/// AMO add-on metadata binds the current version, download URL, and digest.
/// AMO supplies the Mozilla-signed XPI that Gecko release builds require.
pub(crate) const UBLOCK_RELEASES_URL: &str =
    "https://addons.mozilla.org/api/v5/addons/addon/ublock-origin/";

#[derive(Deserialize)]
struct AmoAddon {
    guid: String,
    current_version: AmoVersion,
}

#[derive(Deserialize)]
struct AmoVersion {
    version: String,
    file: AmoFile,
}

#[derive(Deserialize)]
struct AmoFile {
    url: String,
    hash: Option<String>,
    status: String,
}

/// Resolves AMO metadata and provisions its exact XPI after SHA-256 verification.
/// Already-current files are not rehashed; `auto_download` gates new downloads.
/// Signature-file presence is an additional layout check, not cryptographic
/// Mozilla signature validation (which remains the browser's responsibility).
/// The current XPI and version cache change only after successful promotion.
///
/// # Errors
/// Returns a [`BrowserError`] on network, metadata, I/O, or verification failure.
pub(crate) async fn provision_gecko_ublock_xpi(
    metadata_url: &str,
    xpi_dir: &std::path::Path,
    cache_path: &std::path::Path,
    auto_download: bool,
) -> Result<std::path::PathBuf> {
    let client = github::build_client()?;

    let xpi_path = xpi_dir.join("uBlock0.xpi");

    let metadata = crate::network::fetch_text(&client, metadata_url).await?;
    let addon: AmoAddon = serde_json::from_str(&metadata)
        .map_err(|e| BrowserError::Parse(format!("invalid AMO add-on metadata: {e}")))?;
    let release = addon.current_version;
    let version = release.version;
    if addon.guid != "uBlock0@raymondhill.net"
        || release.file.status != "public"
        || version.trim().is_empty()
        || version != version.trim()
        || version.len() > 128
        || version.chars().any(char::is_control)
    {
        return Err(BrowserError::Verification(
            "AMO metadata must identify uBlock Origin and a public, versioned file".to_owned(),
        ));
    }
    let digest = release
        .file
        .hash
        .as_deref()
        .and_then(|hash| hash.strip_prefix("sha256:"))
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| {
            BrowserError::Verification("AMO file has no valid SHA-256 digest".to_owned())
        })?;
    validate_amo_file_url(&release.file.url)?;

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

    // Buffer within the extension archive limit and verify before writing a stage.
    let bytes = github::fetch_archive(&client, &release.file.url).await?;
    crate::gpg::sha256::verify(&bytes, digest)
        .map_err(|e| BrowserError::Verification(format!("AMO uBlock XPI: {e}")))?;
    check_xpi_signature_files(&bytes)?;
    crate::fs_safety::create_dir_all(xpi_dir)?;
    let mut staged = crate::fs_safety::StagedFile::new(&xpi_path)?;
    crate::fs_safety::write(staged.path(), &bytes)?;
    staged.commit()?;

    crate::version_cache::update_ubo_version(cache_path, &version);
    // Also write the legacy marker so older launcher versions can read it.
    let _ = crate::fs_safety::write(xpi_dir.join(".ublock-version"), &version);

    tracing::info!(version = %version, ?xpi_path, "uBlock Origin XPI provisioned (AMO SHA-256 verified)");
    Ok(xpi_path)
}

/// Require TLS for the initial request as well as subsequent redirects.
fn validate_amo_file_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| BrowserError::Verification("invalid AMO file URL".to_owned()))?;
    let secure = url.scheme() == "https" && url.host_str().is_some();
    // Local mock servers exercise the same download flow without TLS fixtures.
    #[cfg(test)]
    let secure = secure || (url.scheme() == "http" && url.host_str() == Some("127.0.0.1"));
    if !secure || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
    {
        return Err(BrowserError::Verification(
            "AMO file URL must use HTTPS without credentials or a fragment".to_owned(),
        ));
    }
    Ok(())
}

/// Checks signature-file presence only; a hash verified against AMO metadata
/// provides archive integrity. Firefox validates Mozilla signatures at install.
fn check_xpi_signature_files(bytes: &[u8]) -> Result<()> {
    let cursor = std::io::Cursor::new(bytes);
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
    /// Non-browser desktop applications.
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

/// Package selection identity. `Portable` supports legacy single-artifact records;
/// it does not claim that an executable is architecture-neutral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageTarget {
    /// 64-bit x86 package selection.
    X64,
    /// 32-bit x86 package selection.
    X86,
    /// 64-bit ARM package selection.
    Arm64,
    /// A single portable artifact with no architecture selector.
    Portable,
}

impl From<crate::config::Arch> for PackageTarget {
    fn from(arch: crate::config::Arch) -> Self {
        match arch {
            crate::config::Arch::X64 => Self::X64,
            crate::config::Arch::X86 => Self::X86,
            crate::config::Arch::Arm64 => Self::Arm64,
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
    /// Selected package target. Legacy markers omit this and remain unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PackageTarget>,
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
    /// `ublock_xpi_releases_url`: AMO add-on metadata API URL used to
    /// provision the Mozilla-signed uBlock XPI locally so policies.json can
    /// reference it with a `file://` URL — this avoids a per-launch phone-home
    /// to AMO while still installing an XPI a Gecko release build will accept.
    /// `None` for browsers that already bundle uBlock (e.g. `Mullvad`).
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
    /// A launcher does not own the portable folder it was asked to use.
    #[error("portable-folder ownership error: {0}")]
    Ownership(String),
    /// An OS protocol invocation would require installing software.
    #[error("protocol launch refused: {0}")]
    ProtocolInvocation(String),
    /// A resolved upstream build has not been certified for this launcher.
    #[error("update compatibility check failed: {0}")]
    Compatibility(String),
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

    /// Target used by the adapter's package selector, cache and install marker.
    fn package_target(&self) -> PackageTarget;

    /// Human-readable name for the identity card, e.g. `"Ungoogled Chromium"`.
    fn display_name(&self) -> &'static str;

    /// Full default `nomad.toml` written on first run. Browsers use the shared
    /// browser template; adapters can override it for their supported keys.
    /// Only consulted when no
    /// config file exists yet; an existing `nomad.toml` always wins.
    fn default_config(&self) -> &'static str {
        crate::config::DEFAULT_NOMAD_TOML
    }

    /// The rendering engine this browser is built on.
    fn engine(&self) -> Engine;

    /// Mandatory layout of the authenticated, extracted browser bundle.
    /// The shared updater validates this before preparation, and again before
    /// writing a version marker. Additional validation hooks cannot bypass it.
    fn staged_install_layout(&self) -> StagedInstallLayout;

    /// Embedded ASCII-armored package-signing key. `Some` requires a detached
    /// package signature; missing signatures must never fall back to a hash.
    /// `None` uses the adapter's hash/other verification path.
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

    /// Validates that this launcher understands the resolved release layout.
    ///
    /// Verification proves package authenticity, but not that extraction,
    /// executable discovery, policy overlays, or resource patches still match
    /// a changed upstream build. Implementors with version-sensitive behavior
    /// override this hook and fail closed until the new release is certified.
    ///
    /// # Errors
    /// Returns [`BrowserError::Compatibility`] when the release must not be
    /// installed by this launcher version.
    fn validate_update(&self, info: &VersionInfo) -> Result<()> {
        let _ = info;
        Ok(())
    }

    /// Performs additional browser-specific compatibility/overlay checks.
    /// The shared updater always checks `staged_install_layout` first, including
    /// for adapters using this default. Called before markers or swapping.
    ///
    /// # Errors
    /// Returns an error if the staged browser is incompatible with this launcher.
    fn validate_staged_install(&self, stage_dir: &Path) -> Result<()> {
        let _ = stage_dir;
        Ok(())
    }

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
    /// `install_dir`. Adapters with in-bundle state must copy it from
    /// `current_install` into `stage_dir` before replacement.
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
    /// Returns a [`BrowserError`] if required preparation could not complete.
    /// The core launcher refuses to spawn the browser, including on "Launch
    /// anyway". Optional staging should log its own failures and return `Ok`.
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
    crate::fs_safety::write(install_dir.join(VERSION_MARKER), serialized)?;
    Ok(())
}

/// Reads the Nomad version marker from `install_dir`.
///
/// Returns `None` when the marker is absent or unreadable — treated as
/// "no usable installation".
#[must_use]
pub fn read_version_marker(install_dir: &Path) -> Option<InstalledVersion> {
    crate::fs_safety::ensure_file(install_dir.join(VERSION_MARKER)).ok()?;
    let raw = std::fs::read_to_string(install_dir.join(VERSION_MARKER)).ok()?;
    toml::from_str(&raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    #[test]
    fn package_targets_follow_each_adapter_selector() {
        for arch in [
            crate::config::Arch::X64,
            crate::config::Arch::X86,
            crate::config::Arch::Arm64,
        ] {
            let expected: PackageTarget = arch.into();
            assert_eq!(floorp::Floorp::new(arch).package_target(), expected);
            assert_eq!(helium::Helium::new(arch).package_target(), expected);
            assert_eq!(librewolf::Librewolf::new(arch).package_target(), expected);
            assert_eq!(mullvad::Mullvad::new(arch).package_target(), expected);
            assert_eq!(
                ungoogled::UngoogledChromium::new(arch).package_target(),
                expected
            );
            assert_eq!(waterfox::Waterfox::new(arch).package_target(), expected);
        }
    }

    #[test]
    fn legacy_marker_keeps_unknown_target_and_user_files() {
        let temp = tempfile::tempdir().unwrap();
        let install = temp.path().join("Browser");
        std::fs::create_dir(&install).unwrap();
        let marker = install.join(".nomad-version");
        let contents = br#"browser_version = "2.0"
engine_version = "2.0"
"#;
        std::fs::write(&marker, contents).unwrap();
        let installed = read_version_marker(&install).unwrap();
        assert_eq!(installed.target, None);
        assert_eq!(installed.browser_version, "2.0");
        assert_eq!(std::fs::read(marker).unwrap(), contents);
    }

    fn amo_metadata(version: &str, url: &str, bytes: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "guid": "uBlock0@raymondhill.net",
            "current_version": {
                "version": version,
                "file": {
                    "url": url,
                    "hash": format!("sha256:{}", crate::gpg::sha256::hex(bytes)),
                    "status": "public"
                }
            }
        })
    }

    fn mock_amo_metadata(server: &MockServer, version: &str, bytes: &[u8]) {
        let metadata = amo_metadata(
            version,
            &server.url(format!("/ublock_origin-{version}.xpi")),
            bytes,
        );
        server.mock(|when, then| {
            when.method(GET).path("/addon");
            then.status(200).json_body(metadata);
        });
    }

    #[tokio::test]
    async fn ublock_xpi_uses_metadata_version_and_file_url() {
        let server = MockServer::start();
        let bytes = make_xpi_with_signature_files();
        let metadata = amo_metadata("2.0.0", &server.url("/file/123/extension.xpi"), &bytes);
        let metadata_mock = server.mock(|when, then| {
            when.method(GET).path("/addon");
            then.status(200).json_body(metadata);
        });
        let download = server.mock(|when, then| {
            when.method(GET).path("/file/123/extension.xpi");
            then.status(200).body(&bytes);
        });
        let head = server.mock(|when, then| {
            when.method(httpmock::Method::HEAD);
            then.status(200);
        });
        let dir = tempfile::tempdir().unwrap();
        let extensions = dir.path().join("Gecko-extensions");
        let cache = dir.path().join("cache.toml");
        provision_gecko_ublock_xpi(&server.url("/addon"), &extensions, &cache, true)
            .await
            .expect("metadata must bind the version, URL, and digest");
        assert_eq!(
            std::fs::read(extensions.join("uBlock0.xpi")).unwrap(),
            bytes
        );
        assert_eq!(
            crate::version_cache::VersionCache::load(&cache)
                .unwrap()
                .ubo_version
                .as_deref(),
            Some("2.0.0")
        );
        assert_eq!(
            std::fs::read_to_string(extensions.join(".ublock-version")).unwrap(),
            "2.0.0"
        );
        metadata_mock.assert_calls(1);
        download.assert_calls(1);
        head.assert_calls(0);
    }

    // ── provision_gecko_ublock_xpi tests ──────────────────────────────────────

    /// Inert XPI-shaped fixture; the signature bytes are deliberately not valid.
    fn make_xpi_with_signature_files() -> Vec<u8> {
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

    #[cfg(windows)]
    #[tokio::test]
    async fn locked_xpi_promotion_preserves_extension_and_version_cache() {
        use std::os::windows::fs::OpenOptionsExt;
        let server = MockServer::start_async().await;
        mock_amo_metadata(&server, "2.0.0", &make_xpi_with_signature_files());
        server
            .mock_async(|when, then| {
                when.method(GET).path("/ublock_origin-2.0.0.xpi");
                then.status(200).body(make_xpi_with_signature_files());
            })
            .await;
        let fixture = tempfile::tempdir().unwrap();
        let extensions = fixture.path().join("Gecko-extensions");
        std::fs::create_dir_all(&extensions).unwrap();
        let path = extensions.join("uBlock0.xpi");
        let old = make_xpi_with_signature_files();
        std::fs::write(&path, &old).unwrap();
        let cache = fixture.path().join("cache.toml");
        crate::version_cache::update_ubo_version(&cache, "1.0.0");
        let cache_bytes = std::fs::read(&cache).unwrap();
        let handle = std::fs::File::options()
            .read(true)
            .share_mode(
                windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
            )
            .open(&path)
            .unwrap();
        let result =
            provision_gecko_ublock_xpi(&server.url("/addon"), &extensions, &cache, true).await;
        assert!(matches!(result, Err(BrowserError::Io(_))), "{result:?}");
        drop(handle);
        assert_eq!(std::fs::read(&path).unwrap(), old);
        assert_eq!(std::fs::read(&cache).unwrap(), cache_bytes);
        assert_eq!(std::fs::read_dir(&extensions).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn rejected_xpi_update_preserves_existing_extension_and_cache() {
        let server = MockServer::start_async().await;
        mock_amo_metadata(&server, "2.0.0", &make_xpi_with_signature_files());
        let mut tampered = make_xpi_with_signature_files();
        tampered.push(0);
        check_xpi_signature_files(&tampered).expect("fake signature files pass the layout check");
        server
            .mock_async(|when, then| {
                when.method(GET).path("/ublock_origin-2.0.0.xpi");
                then.status(200).body(tampered);
            })
            .await;
        let fixture = tempfile::tempdir().unwrap();
        let extensions = fixture.path().join("Gecko-extensions");
        std::fs::create_dir_all(&extensions).unwrap();
        let old = make_xpi_with_signature_files();
        std::fs::write(extensions.join("uBlock0.xpi"), &old).unwrap();
        std::fs::write(extensions.join(".ublock-version"), "1.0.0").unwrap();
        let cache = fixture.path().join("cache.toml");
        crate::version_cache::update_ubo_version(&cache, "1.0.0");
        let cache_bytes = std::fs::read(&cache).unwrap();
        let result =
            provision_gecko_ublock_xpi(&server.url("/addon"), &extensions, &cache, true).await;
        assert!(
            matches!(result, Err(BrowserError::Verification(_))),
            "{result:?}"
        );
        assert_eq!(
            std::fs::read_dir(&extensions).unwrap().count(),
            2,
            "a mismatched XPI must not reach staging"
        );
        assert_eq!(std::fs::read(extensions.join("uBlock0.xpi")).unwrap(), old);
        assert_eq!(std::fs::read(&cache).unwrap(), cache_bytes);
        assert_eq!(
            std::fs::read_to_string(extensions.join(".ublock-version")).unwrap(),
            "1.0.0"
        );
    }

    #[tokio::test]
    async fn ublock_xpi_downloads_when_newer_version_available() {
        let server = MockServer::start();
        let xpi_bytes = make_xpi_with_signature_files();
        // Resolve the exact version and digest from a single metadata response.
        mock_amo_metadata(&server, "1.71.0", &xpi_bytes);
        server.mock(|when, then| {
            when.method(GET).path("/ublock_origin-1.71.0.xpi");
            then.status(200)
                .header("Content-Type", "application/zip")
                .body(xpi_bytes.clone());
        });

        let dir = tempfile::tempdir().unwrap();
        let xpi_dir = dir.path().join("Gecko-extensions");
        let cache_path = dir.path().join("nomad-version-cache.toml");
        let url = server.url("/addon");

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

        mock_amo_metadata(&server, "1.71.0", &make_xpi_with_signature_files());
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
        let url = server.url("/addon");

        provision_gecko_ublock_xpi(&url, &xpi_dir, &cache_path, true)
            .await
            .expect("must not fail when already current");
        assert_eq!(
            download_mock.calls(),
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
        mock_amo_metadata(&server, "1.99.0", &unsigned_xpi);
        server.mock(|when, then| {
            when.method(GET).path("/ublock_origin-1.99.0.xpi");
            then.status(200)
                .header("Content-Type", "application/zip")
                .body(unsigned_xpi);
        });

        let dir = tempfile::tempdir().unwrap();
        let xpi_dir = dir.path().join("Gecko-extensions");
        let cache_path = dir.path().join("nomad-version-cache.toml");
        let url = server.url("/addon");

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
    async fn ublock_xpi_rejects_invalid_metadata_before_download() {
        use serde_json::json;
        let cases = [
            ("/guid", json!("another-extension@example.invalid")),
            ("/current_version", json!(null)),
            ("/current_version/version", json!("")),
            ("/current_version/version", json!("unknown\n")),
            ("/current_version/file/status", json!("disabled")),
            ("/current_version/file/hash", json!(null)),
            ("/current_version/file/hash", json!("")),
            (
                "/current_version/file/hash",
                json!(format!("sha512:{}", "a".repeat(64))),
            ),
            (
                "/current_version/file/hash",
                json!(format!("sha256:{}", "a".repeat(63))),
            ),
            (
                "/current_version/file/hash",
                json!(format!("sha256:{}", "a".repeat(65))),
            ),
            (
                "/current_version/file/hash",
                json!(format!("sha256:{}z", "a".repeat(63))),
            ),
            (
                "/current_version/file/hash",
                json!(format!("sha256:{} ", "a".repeat(64))),
            ),
            (
                "/current_version/file/url",
                json!("http://example.invalid/file.xpi"),
            ),
            (
                "/current_version/file/url",
                json!("file:///C:/extension.xpi"),
            ),
            ("/current_version/file/url", json!("/relative.xpi")),
            (
                "/current_version/file/url",
                json!("https://user:pass@example.invalid/file.xpi"),
            ),
            (
                "/current_version/file/url",
                json!("https://example.invalid/file.xpi#fragment"),
            ),
        ];
        for (pointer, value) in cases {
            let server = MockServer::start();
            let mut metadata = amo_metadata(
                "2.0.0",
                &server.url("/file.xpi"),
                &make_xpi_with_signature_files(),
            );
            *metadata.pointer_mut(pointer).unwrap() = value;
            server.mock(|when, then| {
                when.method(GET).path("/addon");
                then.status(200).json_body(metadata);
            });
            let archive = server.mock(|when, then| {
                when.method(GET).path("/file.xpi");
                then.status(500);
            });
            let dir = tempfile::tempdir().unwrap();
            let extensions = dir.path().join("Gecko-extensions");
            let cache = dir.path().join("cache.toml");
            let err = provision_gecko_ublock_xpi(&server.url("/addon"), &extensions, &cache, true)
                .await
                .expect_err("invalid metadata must fail closed");
            assert!(
                matches!(err, BrowserError::Verification(_) | BrowserError::Parse(_)),
                "{pointer}: {err:?}"
            );
            archive.assert_calls(0);
            assert!(!extensions.exists());
            assert!(!cache.exists());
        }
    }

    #[tokio::test]
    async fn ublock_xpi_rejects_failed_metadata_http_responses() {
        for status in [403, 404, 500] {
            let server = MockServer::start();
            server.mock(|when, then| {
                when.method(GET).path("/addon");
                then.status(status).json_body(amo_metadata(
                    "2.0.0",
                    &server.url("/file.xpi"),
                    &make_xpi_with_signature_files(),
                ));
            });
            let archive = server.mock(|when, then| {
                when.method(GET).path("/file.xpi");
                then.status(200).body(make_xpi_with_signature_files());
            });
            let dir = tempfile::tempdir().unwrap();
            let extensions = dir.path().join("Gecko-extensions");
            let cache = dir.path().join("cache.toml");
            let err = provision_gecko_ublock_xpi(&server.url("/addon"), &extensions, &cache, true)
                .await
                .expect_err("HTTP failure must not be treated as release metadata");
            assert!(
                matches!(err, BrowserError::Network(_) | BrowserError::Offline(_)),
                "{err:?}"
            );
            archive.assert_calls(0);
            assert!(!extensions.exists());
            assert!(!cache.exists());
        }
    }

    #[tokio::test]
    async fn ublock_xpi_rejects_failed_downloads_without_staging() {
        for status in [404, 500] {
            let server = MockServer::start();
            mock_amo_metadata(&server, "2.0.0", &make_xpi_with_signature_files());
            let archive = server.mock(|when, then| {
                when.method(GET).path("/ublock_origin-2.0.0.xpi");
                then.status(status).body("failed transfer");
            });
            let dir = tempfile::tempdir().unwrap();
            let extensions = dir.path().join("Gecko-extensions");
            let cache = dir.path().join("cache.toml");
            let err = provision_gecko_ublock_xpi(&server.url("/addon"), &extensions, &cache, true)
                .await
                .expect_err("failed downloads must stop before staging");
            assert!(matches!(err, BrowserError::Network(_)), "{err:?}");
            archive.assert_calls(1);
            assert!(!extensions.exists());
            assert!(!cache.exists());
        }
    }

    #[tokio::test]
    async fn ublock_xpi_rejects_oversized_download_without_staging() {
        use std::io::{Read, Write};
        use std::time::{Duration, Instant};
        // Raw headers avoid allocating a 128 MiB fixture; httpmock requires
        // Content-Length to match its actual body and cannot model this case.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let file_url = format!("http://{}/file.xpi", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "archive request never arrived");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            // Windows accepted sockets inherit the listener's non-blocking mode.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            let bytes_read = stream.read(&mut request).unwrap();
            assert!(bytes_read > 0, "expected an archive request");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                crate::network::MAX_EXTENSION_ARCHIVE_BYTES + 1
            )
            .unwrap();
        });
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/addon");
            then.status(200).json_body(amo_metadata(
                "2.0.0",
                &file_url,
                &make_xpi_with_signature_files(),
            ));
        });
        let dir = tempfile::tempdir().unwrap();
        let extensions = dir.path().join("Gecko-extensions");
        let cache = dir.path().join("cache.toml");
        let result =
            provision_gecko_ublock_xpi(&server.url("/addon"), &extensions, &cache, true).await;
        worker.join().unwrap();
        let err = result.expect_err("oversized archive must be refused at the headers");
        assert!(matches!(err, BrowserError::Network(_)), "{err:?}");
        assert!(err.to_string().contains("response exceeds"), "{err:?}");
        assert!(!extensions.exists());
        assert!(!cache.exists());
    }

    #[tokio::test]
    async fn ublock_xpi_defers_when_auto_download_is_disabled() {
        let server = MockServer::start();
        mock_amo_metadata(&server, "2.0.0", &make_xpi_with_signature_files());
        let archive = server.mock(|when, then| {
            when.method(GET).path("/ublock_origin-2.0.0.xpi");
            then.status(500);
        });
        let dir = tempfile::tempdir().unwrap();
        let extensions = dir.path().join("Gecko-extensions");
        let cache = dir.path().join("cache.toml");
        provision_gecko_ublock_xpi(&server.url("/addon"), &extensions, &cache, false)
            .await
            .unwrap();
        archive.assert_calls(0);
        assert!(!extensions.exists());
        assert!(!cache.exists());
    }

    #[tokio::test]
    async fn ublock_xpi_redownloads_when_current_cache_has_no_file() {
        let server = MockServer::start();
        let bytes = make_xpi_with_signature_files();
        mock_amo_metadata(&server, "2.0.0", &bytes);
        let archive = server.mock(|when, then| {
            when.method(GET).path("/ublock_origin-2.0.0.xpi");
            then.status(200).body(&bytes);
        });
        let dir = tempfile::tempdir().unwrap();
        let extensions = dir.path().join("Gecko-extensions");
        let cache = dir.path().join("cache.toml");
        crate::version_cache::update_ubo_version(&cache, "2.0.0");
        provision_gecko_ublock_xpi(&server.url("/addon"), &extensions, &cache, true)
            .await
            .unwrap();
        archive.assert_calls(1);
        assert_eq!(
            std::fs::read(extensions.join("uBlock0.xpi")).unwrap(),
            bytes
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
    fn xpi_signature_file_check_accepts_archive_with_meta_inf_signature() {
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
        check_xpi_signature_files(&std::fs::read(&path).unwrap())
            .expect("signed XPI must be accepted");
    }

    #[test]
    fn xpi_signature_file_check_rejects_archive_without_signature_files() {
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
        let err = check_xpi_signature_files(&std::fs::read(&path).unwrap())
            .expect_err("unsigned XPI must be rejected");
        assert!(matches!(err, BrowserError::Verification(_)));
    }
}
