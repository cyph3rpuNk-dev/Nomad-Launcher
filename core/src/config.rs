//! Per-launcher configuration: loading, validation, and first-run defaults.
//!
//! Each `nomad-<browser>.exe` reads a `nomad.toml` from its `nomad/`
//! subdirectory. The file is scoped to that one browser (see SPEC §4) —
//! there is no browser array and no `channel` key. Unknown keys are
//! rejected rather than ignored.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Name of the config file, stored inside [`NOMAD_SUBDIR`].
pub const CONFIG_FILE_NAME: &str = "nomad.toml";

/// Name of the per-launcher subdirectory that houses every Nomad-managed
/// file (`nomad.toml`, `nomad.log`, `nomad-version-cache.toml`,
/// `nomad.reg-state.json`, plus the `Gecko-extensions/` XPI staging dir).
/// Lives beside the launcher executable.
pub const NOMAD_SUBDIR: &str = "Nomad";

/// Returns `<launcher_dir>/<NOMAD_SUBDIR>` — the directory holding every
/// Nomad-owned file for this launcher. Pure path arithmetic; the caller is
/// responsible for `create_dir_all` before writing.
#[must_use]
pub fn nomad_subdir(launcher_dir: &Path) -> PathBuf {
    launcher_dir.join(NOMAD_SUBDIR)
}

/// Canonical default config for browser launchers, written verbatim on first
/// run. Non-browser apps supply their own via
/// [`crate::browsers::BrowserFamily::default_config`] (e.g. Bitwarden ships a
/// trimmed config without the browser-only privacy keys).
pub(crate) const DEFAULT_NOMAD_TOML: &str = "\
[browser]
install_dir = \"Browser\"      # relative to the .exe directory
arch = \"x64\"                 # \"x64\" | \"x86\" | \"arm64\"

[update]
check_on_launch = true       # false = skip the update check, launch immediately
auto_download = true         # false = prompt in the status window before downloading

[launch]
language = \"en-US\"           # passed as --lang to browsers that accept it
extra_args = []              # additional command-line arguments
incognito = false            # true = launch Chromium browsers in --incognito mode

[hardening]
enabled = true               # false = launch with no privacy hardening applied
sanitize_on_shutdown = true  # false = disable clear-on-exit in Gecko user.js
scrub_thumbnail_cache = false  # true = enable thumbcache scrub on exit (briefly restarts Explorer)
clear_data_on_exit = false   # true = wipe Chromium cookies/sessions/history on exit (strong privacy, breaks \"stay signed in\")
scrub_prefetch = false       # true = delete Windows Prefetch entries on exit (requires UAC prompt for non-admin accounts)

# PREFETCH NOTE: Windows Prefetch (C:\\Windows\\Prefetch\\) records the full path
# to each launched executable. Enabling scrub_prefetch removes those entries on
# exit but requires administrator privileges — a UAC prompt appears on every
# browser close for standard-user accounts. Only enable on forensics-sensitive
# machines where you control the account type. To reduce exposure without the
# UAC overhead, keep launcher paths short and non-identifying.

# SECURITY NOTE: When hardening is enabled, browser Safe Browsing is disabled
# for privacy (it phones home to Google / Mozilla every ~30 minutes). This
# removes browser-level phishing and malware URL protection. Use a DNS-level
# block list or a network-layer filter as a substitute if needed.

# WEBRTC NOTE: WebRTC is disabled by default. This prevents sites from
# discovering your real IP address via STUN — including when behind a VPN,
# where WebRTC is one of the most common sources of IP leaks. For video or
# audio calls (Google Meet, Teams, Discord, Zoom in-browser), use a different
# browser. If you use a VPN, choose one that explicitly provides WebRTC and
# IP leak protection, and verify it independently at https://browserleaks.com/webrtc
# before relying on it. To re-enable WebRTC in this browser, set
# disable_webrtc = false — but understand your real IP may become visible.
disable_webrtc = true

# FINGERPRINTING NOTE: reduce_system_info adds the ungoogled ReducedSystemInfo
# feature on Ungoogled Chromium: it trims system details exposed via
# headers/JavaScript and reports navigator.hardwareConcurrency as 2 cores, which
# shrinks your fingerprint entropy (as Tor and Brave also do). Default true.
# NO EFFECT on Helium (its built-in \"Helium Noise\" already randomizes
# hardwareConcurrency, so Nomad defers to it) or on Gecko browsers. Trade-off on
# Ungoogled Chromium: apps that size thread pools from hardwareConcurrency
# (in-browser video encoders, some WASM workloads, heavy editors) may run
# slower; set false to disable.
reduce_system_info = true
";

/// Target architecture of the browser build to download.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    /// 64-bit x86 (the default).
    #[default]
    X64,
    /// 32-bit x86.
    X86,
    /// 64-bit ARM.
    Arm64,
}

impl Arch {
    /// Returns the architecture as the short lowercase string used in asset
    /// names and the runtime-details card (`"x64"`, `"x86"`, `"arm64"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::X86 => "x86",
            Self::Arm64 => "arm64",
        }
    }
}

/// The `[browser]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserConfig {
    /// Install directory, resolved relative to the launcher's directory.
    pub install_dir: PathBuf,
    /// Build architecture to download.
    #[serde(default)]
    pub arch: Arch,
}

/// The `[update]` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    /// Whether to check for updates at launch.
    #[serde(default = "default_true")]
    pub check_on_launch: bool,
    /// Whether to download a found update without prompting.
    #[serde(default = "default_true")]
    pub auto_download: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            check_on_launch: true,
            auto_download: true,
        }
    }
}

/// The `[launch]` section.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchConfig {
    /// UI language passed to browsers that accept `--lang`.
    #[serde(default)]
    pub language: Option<String>,
    /// Extra command-line arguments appended to the browser invocation.
    #[serde(default)]
    pub extra_args: Vec<String>,
    /// When `true`, Chromium browsers are launched with `--incognito`.
    /// Has no effect on Gecko-engine browsers.
    #[serde(default)]
    pub incognito: bool,
}

/// The `[hardening]` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // six distinct user-facing config toggles, not algorithm state
pub struct HardeningConfig {
    /// Whether to apply Nomad's curated privacy-hardening profile.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// When `false`, the `sanitizeOnShutdown` prefs in the Gecko `user.js` are
    /// overridden to disabled. Has no effect when `enabled = false`.
    #[serde(default = "default_true")]
    pub sanitize_on_shutdown: bool,
    /// When `true`, the cleanup watcher terminates Explorer briefly after the
    /// browser exits to delete thumbnail and icon cache files that may record
    /// file names from the portable drive. Explorer is restarted immediately.
    /// Defaults to `false` (opt-in): the scrub restarts Explorer on every
    /// exit, an acceptable trade-off only on forensics-sensitive machines.
    #[serde(default)]
    pub scrub_thumbnail_cache: bool,
    /// When `true`, Chromium-engine browsers are launched with the
    /// `ClearDataOnExit` feature enabled — cookies, history, downloads, and
    /// sessions are wiped on every exit. Defaults to `false` because it breaks
    /// session continuity (you are signed out of every site on each launch).
    /// Has no effect on Gecko-engine browsers.
    #[serde(default)]
    pub clear_data_on_exit: bool,
    /// When `true`, WebRTC is fully disabled rather than merely restricted to
    /// the public-facing interface.  Prevents real public-IP exposure via STUN
    /// even without a VPN, but breaks **all** WebRTC video/audio calls (Google
    /// Meet, Teams, Discord video, etc.).
    ///
    /// Chromium: appends `--webrtc-ip-handling-policy=disable_non_proxied_udp`.
    /// Gecko: adds `user_pref("media.peerconnection.enabled", false)` to the
    /// managed `user.js` block.
    ///
    /// Has no effect when `enabled = false`. Defaults to `true` — WebRTC is
    /// fully disabled by default because STUN exposes the real WAN IP even
    /// through a VPN. Set `false` to restore the restricted mode (public
    /// interface only; WAN IP still visible via STUN).
    #[serde(default = "default_true")]
    pub disable_webrtc: bool,
    /// When `true`, Chromium-engine browsers add the `ReducedSystemInfo` feature
    /// to the `--enable-features` bundle: system details exposed through headers
    /// and JavaScript are reduced, and `navigator.hardwareConcurrency` reports
    /// two cores. This shrinks fingerprint entropy (CPU core count is a stable
    /// identifier) — in line with how dedicated privacy browsers (Tor, Brave)
    /// clamp the same value. Defaults to `true`. The trade-off is that apps which
    /// size worker/thread pools from `hardwareConcurrency` (in-browser video
    /// encoders, some WASM workloads, heavy editors) may run slower; set `false`
    /// to disable. Has no effect on Gecko-engine browsers or when
    /// `enabled = false`.
    #[serde(default = "default_true")]
    pub reduce_system_info: bool,
    /// When `true`, the cleanup watcher attempts to delete Windows Prefetch
    /// entries (`C:\Windows\Prefetch\`) for the launcher and browser executables.
    /// Requires administrator privileges: a UAC elevation prompt will appear on
    /// browser exit for non-admin accounts. Defaults to `false` (opt-in) because
    /// the UAC prompt appears on every exit — only enable this on
    /// forensics-sensitive machines where you control the account type.
    #[serde(default)]
    pub scrub_prefetch: bool,
}

impl Default for HardeningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sanitize_on_shutdown: true,
            scrub_thumbnail_cache: false,
            clear_data_on_exit: false,
            disable_webrtc: true,
            reduce_system_info: true,
            scrub_prefetch: false,
        }
    }
}

/// A fully parsed `nomad.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The `[browser]` section (required).
    pub browser: BrowserConfig,
    /// The `[update]` section; defaults applied when absent.
    #[serde(default)]
    pub update: UpdateConfig,
    /// The `[launch]` section; defaults applied when absent.
    #[serde(default)]
    pub launch: LaunchConfig,
    /// The `[hardening]` section; defaults applied when absent.
    #[serde(default)]
    pub hardening: HardeningConfig,
}

/// Errors produced while loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file exists but could not be read.
    #[error("failed to read config file {path}")]
    Read {
        /// The path that failed to read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The default config could not be written on first run.
    #[error("failed to write default config to {path}")]
    Write {
        /// The path that failed to write.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The config file contents are not valid (bad TOML, unknown key,
    /// missing required field, …). The message is descriptive.
    #[error("invalid config: {0}")]
    Parse(#[from] toml::de::Error),
}

impl Config {
    /// Parses a `nomad.toml` from its text contents.
    ///
    /// # Errors
    /// Returns [`ConfigError::Parse`] for malformed TOML, unknown keys, or
    /// missing required fields; the wrapped error message is descriptive.
    pub fn parse(contents: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(contents)?)
    }

    /// Loads `nomad.toml` from `<launcher_dir>/nomad/`, creating the
    /// directory and writing the canonical default file on first run.
    ///
    /// `default_config` is the full `nomad.toml` text written on first run
    /// (browsers pass `DEFAULT_NOMAD_TOML`; non-browser apps pass their own
    /// trimmed config). It is ignored when a config file already exists.
    ///
    /// # Errors
    /// Returns [`ConfigError::Read`] / [`ConfigError::Write`] on I/O failure
    /// and [`ConfigError::Parse`] when the file contents are invalid.
    pub fn load_or_init(launcher_dir: &Path, default_config: &str) -> Result<Self, ConfigError> {
        let dir = nomad_subdir(launcher_dir);
        let path = dir.join(CONFIG_FILE_NAME);
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(&dir).map_err(|source| ConfigError::Write {
                    path: dir.clone(),
                    source,
                })?;
                std::fs::write(&path, default_config).map_err(|source| ConfigError::Write {
                    path: path.clone(),
                    source,
                })?;
                default_config.to_owned()
            }
            Err(source) => return Err(ConfigError::Read { path, source }),
        };
        Self::parse(&contents)
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_complete_config() {
        let cfg = Config::parse(DEFAULT_NOMAD_TOML).expect("default config must parse");
        assert_eq!(cfg.browser.install_dir, PathBuf::from("Browser"));
        assert_eq!(cfg.browser.arch, Arch::X64);
        assert!(cfg.update.check_on_launch);
        assert!(cfg.update.auto_download);
        assert_eq!(cfg.launch.language.as_deref(), Some("en-US"));
        assert!(cfg.launch.extra_args.is_empty());
        assert!(!cfg.launch.incognito);
        assert!(cfg.hardening.enabled);
        assert!(cfg.hardening.sanitize_on_shutdown);
        assert!(!cfg.hardening.scrub_thumbnail_cache);
        assert!(!cfg.hardening.clear_data_on_exit);
        assert!(cfg.hardening.reduce_system_info);
        assert!(!cfg.hardening.scrub_prefetch);
    }

    #[test]
    fn applies_defaults_when_optional_sections_absent() {
        let cfg = Config::parse("[browser]\ninstall_dir = \"browser\"\n")
            .expect("minimal config must parse");
        assert_eq!(cfg.browser.arch, Arch::X64);
        assert_eq!(cfg.update, UpdateConfig::default());
        assert_eq!(cfg.launch, LaunchConfig::default());
        assert_eq!(cfg.hardening, HardeningConfig::default());
    }

    #[test]
    fn hardening_can_be_disabled() {
        let cfg =
            Config::parse("[browser]\ninstall_dir = \"browser\"\n[hardening]\nenabled = false\n")
                .expect("config must parse");
        assert!(!cfg.hardening.enabled);
    }

    #[test]
    fn incognito_defaults_to_false_and_can_be_enabled() {
        let minimal = Config::parse("[browser]\ninstall_dir = \"browser\"\n")
            .expect("minimal config must parse");
        assert!(!minimal.launch.incognito, "incognito must default to false");

        let with_incognito =
            Config::parse("[browser]\ninstall_dir = \"browser\"\n[launch]\nincognito = true\n")
                .expect("incognito config must parse");
        assert!(with_incognito.launch.incognito);
    }

    #[test]
    fn reduce_system_info_defaults_to_true_and_can_be_disabled() {
        // Absent key (e.g. configs written before the option existed) must still
        // default to true via #[serde(default = "default_true")].
        let minimal = Config::parse("[browser]\ninstall_dir = \"browser\"\n")
            .expect("minimal config must parse");
        assert!(
            minimal.hardening.reduce_system_info,
            "reduce_system_info must default to true even when the key is absent"
        );

        let disabled = Config::parse(
            "[browser]\ninstall_dir = \"browser\"\n[hardening]\nreduce_system_info = false\n",
        )
        .expect("config must parse");
        assert!(!disabled.hardening.reduce_system_info);
    }

    #[test]
    fn scrub_prefetch_defaults_to_false_and_can_be_enabled() {
        let minimal = Config::parse("[browser]\ninstall_dir = \"browser\"\n")
            .expect("minimal config must parse");
        assert!(
            !minimal.hardening.scrub_prefetch,
            "scrub_prefetch must default to false"
        );

        let enabled = Config::parse(
            "[browser]\ninstall_dir = \"browser\"\n[hardening]\nscrub_prefetch = true\n",
        )
        .expect("config must parse");
        assert!(enabled.hardening.scrub_prefetch);

        // When [hardening] is present but the key is absent (pre-existing configs),
        // the serde default applies — must stay false, never enable silently.
        let section_present =
            Config::parse("[browser]\ninstall_dir = \"browser\"\n[hardening]\nenabled = true\n")
                .expect("config must parse");
        assert!(
            !section_present.hardening.scrub_prefetch,
            "scrub_prefetch must default to false when [hardening] is present without it"
        );
    }

    #[test]
    fn scrub_thumbnail_cache_defaults_to_false_and_can_be_enabled() {
        let minimal = Config::parse("[browser]\ninstall_dir = \"browser\"\n")
            .expect("minimal config must parse");
        assert!(
            !minimal.hardening.scrub_thumbnail_cache,
            "scrub_thumbnail_cache must default to false"
        );

        let enabled = Config::parse(
            "[browser]\ninstall_dir = \"browser\"\n[hardening]\nscrub_thumbnail_cache = true\n",
        )
        .expect("config must parse");
        assert!(enabled.hardening.scrub_thumbnail_cache);

        // Regression: with a [hardening] section present but the key omitted
        // (configs written before the key existed), the serde field default
        // applies — it was `default_true`, silently enabling the Explorer
        // restart the opt-in decision gates.
        let section_present =
            Config::parse("[browser]\ninstall_dir = \"browser\"\n[hardening]\nenabled = true\n")
                .expect("config must parse");
        assert!(
            !section_present.hardening.scrub_thumbnail_cache,
            "scrub_thumbnail_cache must default to false when [hardening] is present without it"
        );
    }

    #[test]
    fn sanitize_on_shutdown_defaults_to_true_and_can_be_disabled() {
        let minimal = Config::parse("[browser]\ninstall_dir = \"browser\"\n")
            .expect("minimal config must parse");
        assert!(
            minimal.hardening.sanitize_on_shutdown,
            "sanitize_on_shutdown must default to true"
        );

        let disabled = Config::parse(
            "[browser]\ninstall_dir = \"browser\"\n[hardening]\nsanitize_on_shutdown = false\n",
        )
        .expect("config must parse");
        assert!(!disabled.hardening.sanitize_on_shutdown);
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = Config::parse("[browser]\ninstall_dir = \"browser\"\nchannel = \"esr\"\n")
            .expect_err("unknown key must be rejected");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_missing_required_field() {
        let err = Config::parse("[browser]\narch = \"x64\"\n")
            .expect_err("missing install_dir must be rejected");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_invalid_arch() {
        let err = Config::parse("[browser]\ninstall_dir = \"browser\"\narch = \"ppc\"\n")
            .expect_err("invalid arch must be rejected");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn preserves_relative_install_dir() {
        let cfg =
            Config::parse("[browser]\ninstall_dir = \"sub/browser\"\n").expect("config must parse");
        assert!(cfg.browser.install_dir.is_relative());
        assert_eq!(cfg.browser.install_dir, PathBuf::from("sub/browser"));
    }

    #[test]
    fn load_or_init_writes_default_when_absent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let cfg =
            Config::load_or_init(dir.path(), DEFAULT_NOMAD_TOML).expect("first run must succeed");

        let written = nomad_subdir(dir.path()).join(CONFIG_FILE_NAME);
        assert!(
            written.exists(),
            "default config file must be created inside nomad/"
        );
        assert!(
            nomad_subdir(dir.path()).is_dir(),
            "nomad/ subdir must be created on first run"
        );
        assert_eq!(cfg.browser.install_dir, PathBuf::from("Browser"));

        // A second load must read the file back, not rewrite it.
        let reloaded =
            Config::load_or_init(dir.path(), DEFAULT_NOMAD_TOML).expect("second run must succeed");
        assert_eq!(cfg, reloaded);
    }

    #[test]
    fn load_or_init_writes_the_supplied_default_config() {
        let dir = tempfile::tempdir().expect("temp dir");
        let custom = "[browser]\ninstall_dir = \"App\"\n";
        let cfg = Config::load_or_init(dir.path(), custom).expect("first run must succeed");
        assert_eq!(
            cfg.browser.install_dir,
            PathBuf::from("App"),
            "the supplied default config must be written verbatim on first run"
        );
        let on_disk = std::fs::read_to_string(nomad_subdir(dir.path()).join(CONFIG_FILE_NAME))
            .expect("config written");
        assert_eq!(on_disk, custom);
    }
}
