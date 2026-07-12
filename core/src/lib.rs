#![deny(clippy::all, clippy::pedantic)]

//! Nomad Launcher — shared core library.
//!
//! Hosts the update-and-launch pipeline shared by every `nomad-<browser>.exe`
//! launcher. A launcher's `main` is a one-liner: it passes a browser
//! constructor to [`run`], which loads config, runs the update flow through a
//! live status window, and launches the browser.

pub mod authenticode;
pub mod branding;
pub mod browsers;
pub mod config;
pub mod downloader;
mod extensions;
pub mod extract;
pub mod gpg;
pub mod hardening;
pub mod install;
pub mod registry;
pub mod taskbar;
pub mod ui;
pub mod updater;
mod version_cache;

pub use branding::{Branding, BrandingGroup, BrandingIcon, PakPatch};
pub use browsers::bitwarden::Bitwarden;
pub use browsers::firefox::{Channel as FirefoxChannel, Firefox};
pub use browsers::floorp::Floorp;
pub use browsers::helium::Helium;
pub use browsers::librewolf::Librewolf;
pub use browsers::mullvad::Mullvad;
pub use browsers::ungoogled::UngoogledChromium;
pub use browsers::waterfox::Waterfox;
pub use browsers::{
    BrowserError, BrowserFamily, Engine, Hardening, InstalledVersion, ProgressSink, VersionInfo,
};
pub use config::{Arch, Config, ConfigError};

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use eframe::egui;

use crate::config::HardeningConfig;
use crate::ui::{LauncherView, ProgressState, StateHandle, StatusLines, WindowPhase};
use crate::updater::UpdateOptions;

/// Returns the crate version, sourced from `Cargo.toml` at compile time.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// A failure during a launcher run.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The launcher's own directory could not be determined.
    #[error("could not locate the launcher directory")]
    NoLauncherDir,
    /// Configuration could not be loaded.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The update or launch pipeline failed.
    #[error(transparent)]
    Browser(#[from] BrowserError),
    /// A filesystem or process operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The status window could not be opened.
    #[error("window error: {0}")]
    Ui(String),
}

/// Entry point for a `nomad-<browser>.exe` launcher.
///
/// `make` builds the [`BrowserFamily`] for the architecture read from the
/// launcher's `nomad.toml`. Loads config, opens the status window, runs the
/// update-and-launch pipeline on a background thread, and returns a process
/// exit code.
///
/// `icon` is the raw bytes of a `.ico` file embedded via `include_bytes!` in
/// the launcher crate.  Pass `&[]` to use the accent-blue placeholder instead.
///
/// `branding` optionally describes the browser's own PE icon resources to
/// rewrite after install (see [`branding`]); pass `None` to skip browser
/// branding entirely.
///
/// # `--register-default` / `--unregister-default`
///
/// When either flag is present the launcher skips the normal update/launch
/// flow and performs the requested registry operation, then exits. The UI
/// window is never opened in this path.
#[must_use]
pub fn run<B, F>(make: F, icon: &'static [u8], branding: Option<&'static Branding>) -> ExitCode
where
    B: BrowserFamily + 'static,
    F: FnOnce(Arch) -> B,
{
    // Restrict all subsequent LoadLibrary calls to System32 only.
    // This covers runtime DLL loads; /DEPENDENTLOADFLAG in .cargo/config.toml
    // covers static import-table loads that happen before this point.
    // 0x800 = LOAD_LIBRARY_SEARCH_SYSTEM32.
    #[cfg(windows)]
    {
        // SAFETY: SetDefaultDllDirectories has no preconditions beyond a valid
        // flags bitmask; the call is always safe and takes effect immediately.
        unsafe {
            windows_sys::Win32::System::LibraryLoader::SetDefaultDllDirectories(0x800);
        }
    }

    init_tracing();

    let args: Vec<String> = std::env::args().collect();
    let (own_args, forwarded_args) = split_forwarded_args(&args);
    if own_args.iter().any(|a| a == "--register-default") {
        return handle_register_flag(make);
    }
    if own_args.iter().any(|a| a == "--unregister-default") {
        return handle_unregister_flag();
    }
    if let Some(cleanup) = parse_cleanup_pid(own_args) {
        return handle_cleanup_flag(cleanup);
    }
    if own_args.iter().any(|a| a == "--nomad-scrub-prefetch") {
        return handle_prefetch_scrub_flag();
    }

    match run_with_ui(make, icon, branding, forwarded_args.to_vec()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "launcher failed");
            // Launchers are windowed processes with no console, so stderr is
            // invisible — a message box is the only channel guaranteed to
            // reach the user when the status window itself cannot open.
            let mut text = format!("Launch failed: {e}");
            if matches!(e, RunError::Ui(_)) {
                text.push_str(
                    "\n\nThe status window could not be created. This usually \
                     means OpenGL 2.0 is not available — common in virtual \
                     machines without 3D acceleration. Enable it (VirtualBox: \
                     install Guest Additions and tick \"3D Acceleration\"; \
                     VMware: tick \"Accelerate 3D graphics\") and try again.",
                );
            }
            text.push_str("\n\nDetails: Nomad\\nomad.log beside this launcher.");
            show_msgbox(&text, true);
            ExitCode::FAILURE
        }
    }
}

/// Registers the launcher as a default-browser candidate in `HKCU` and shows
/// the result in a message box (since launchers are windowed, no console).
fn handle_register_flag<B, F>(make: F) -> ExitCode
where
    B: BrowserFamily + 'static,
    F: FnOnce(Arch) -> B,
{
    // Arch doesn't affect browser metadata; X64 avoids a config-load cycle.
    let browser = make(Arch::X64);
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            show_msgbox(&format!("Registration failed: {e}"), true);
            return ExitCode::FAILURE;
        }
    };
    let sidecar = exe_path.parent().map_or_else(
        || std::path::PathBuf::from("nomad.reg-state.json"),
        |dir| config::nomad_subdir(dir).join("nomad.reg-state.json"),
    );

    match registry::register(browser.id(), browser.display_name(), &exe_path, &sidecar) {
        Ok(()) => {
            show_msgbox(
                &format!(
                    "{} (Nomad Launcher) is now registered as a browser candidate.\n\n\
                     Open Settings \u{2192} Default apps to make it your default browser.",
                    browser.display_name()
                ),
                false,
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            show_msgbox(&format!("Registration failed: {e}"), true);
            ExitCode::FAILURE
        }
    }
}

/// Removes the registration created by `--register-default` and shows the
/// result in a message box.
fn handle_unregister_flag() -> ExitCode {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            show_msgbox(&format!("Unregistration failed: {e}"), true);
            return ExitCode::FAILURE;
        }
    };
    let sidecar = exe_path.parent().map_or_else(
        || std::path::PathBuf::from("nomad.reg-state.json"),
        |dir| config::nomad_subdir(dir).join("nomad.reg-state.json"),
    );

    match registry::unregister(&sidecar) {
        Ok(()) => {
            show_msgbox("Browser registration removed successfully.", false);
            ExitCode::SUCCESS
        }
        Err(e) => {
            show_msgbox(&format!("Unregistration failed: {e}"), true);
            ExitCode::FAILURE
        }
    }
}

/// Shows a `MessageBoxW` on Windows; falls back to stderr/stdout on other
/// platforms (compile target only — launchers are Windows-only in practice).
fn show_msgbox(text: &str, error: bool) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK,
        };
        let text_w: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let caption_w: Vec<u16> = "Nomad Launcher"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let icon = if error {
            MB_ICONERROR
        } else {
            MB_ICONINFORMATION
        };
        // SAFETY: text_w and caption_w are valid null-terminated wide strings;
        // NULL hwnd centres the box on the primary monitor.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text_w.as_ptr(),
                caption_w.as_ptr(),
                MB_OK | icon,
            );
        }
    }
    #[cfg(not(windows))]
    if error {
        eprintln!("Error: {text}");
    } else {
        println!("{text}");
    }
}

/// Arguments decoded from a cleanup-watcher invocation.
#[derive(Debug, PartialEq)]
struct CleanupArgs {
    browser_pid: u32,
    browser_exe: Option<String>,
    scrub_thumbnail_cache: bool,
    scrub_prefetch: bool,
}

// ── Top-level wiring ──────────────────────────────────────────────────────────

/// Loads config, constructs the browser, opens the status window and
/// runs the pipeline on a background thread.
///
/// Blocks until the window is closed (either by the pipeline signalling
/// [`WindowPhase::Done`] or by the user clicking Close / the title-bar X).
fn run_with_ui<B, F>(
    make: F,
    icon: &'static [u8],
    branding: Option<&'static Branding>,
    forwarded_args: Vec<String>,
) -> Result<(), RunError>
where
    B: BrowserFamily + 'static,
    F: FnOnce(Arch) -> B,
{
    let exe = std::env::current_exe()?;
    let base = exe.parent().ok_or(RunError::NoLauncherDir)?;

    // `default_install_dir` (consulted only on first run) is arch-independent, so
    // determine the arch first: from an existing config if present, else the
    // default. This lets `make` be called exactly once with the real arch.
    let cfg_file = config::nomad_subdir(base).join(config::CONFIG_FILE_NAME);
    let arch = if cfg_file.exists() {
        // Config already exists, so the default-config argument is unused here.
        Config::load_or_init(base, "")?.browser.arch
    } else {
        Arch::default()
    };
    let browser = make(arch);
    let config = Config::load_or_init(base, browser.default_config())?;
    let browser = Arc::new(browser);
    // Reject absolute paths and '..' components: `base.join(abs)` silently
    // discards `base` in Rust, so an absolute or escaping install_dir would
    // redirect all extraction and atomic-swap operations outside the portable
    // tree.  Fail loudly here rather than silently writing to arbitrary paths.
    if config.browser.install_dir.is_absolute()
        || config
            .browser
            .install_dir
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(browsers::BrowserError::Parse(format!(
            "install_dir `{}` must be a relative path with no '..' — \
             absolute paths and parent-directory traversal are not allowed",
            config.browser.install_dir.display()
        ))
        .into());
    }
    let install_dir = base.join(&config.browser.install_dir);
    let opts = UpdateOptions {
        check_on_launch: config.update.check_on_launch,
        auto_download: config.update.auto_download,
    };
    let mut launch_args = build_launch_args(&*browser, &config);
    // The forwarded tail (everything after `--` on our own command line)
    // goes last, after every switch: it carries positional arguments such as
    // the URL a default-browser registration passes via `"%1"`.
    launch_args.extend(forwarded_args);
    let hardening = config.hardening;

    let view = build_initial_view(&*browser, arch, icon);

    ui::show_window_driven(view, move |state, ctx| {
        pipeline_thread(
            &browser,
            &install_dir,
            opts,
            &launch_args,
            branding,
            hardening,
            &state,
            &ctx,
        );
    })
    .map_err(|e| RunError::Ui(e.to_string()))
}

/// Builds the browser's launch arguments: the privacy-hardening flags
/// (when `[hardening] enabled` and the browser hardens via launch flags),
/// followed by the user's configured `extra_args`, followed by the incognito
/// flag (if enabled for Chromium).
///
/// Hardening flags come first so a user-supplied `extra_args` entry can
/// override a conflicting hardening flag.
fn build_launch_args<B: BrowserFamily>(browser: &B, config: &Config) -> Vec<String> {
    let mut args = Vec::new();
    if config.hardening.enabled {
        match browser.hardening() {
            Hardening::LaunchFlags { flags, .. } => {
                args.extend(flags.iter().map(|f| (*f).to_owned()));
            }
            // Gecko hardening is applied via file writes (hardening::write_user_js /
            // write_policies_json), not launch flags.
            Hardening::GeckoProfile { .. } => {}
        }
        // Chromium only honours the last --enable-features= switch, so when the
        // user opts into clear_data_on_exit we merge ClearDataOnExit into the
        // existing bundle rather than appending a second switch.
        if config.hardening.clear_data_on_exit && browser.engine() == Engine::Chromium {
            let mut merged = false;
            for arg in &mut args {
                if let Some(rest) = arg.strip_prefix("--enable-features=") {
                    *arg = format!("--enable-features={rest},ClearDataOnExit");
                    merged = true;
                    break;
                }
            }
            if !merged {
                args.push("--enable-features=ClearDataOnExit".to_owned());
            }
        }
        // ReducedSystemInfo is also a feature flag; merge it into the same
        // bundle (Chromium honours only the last --enable-features= switch).
        // Skipped for browsers with their own fingerprint-noise framework
        // (e.g. Helium) — ReducedSystemInfo's clamp-to-2 would override and
        // degrade their randomised hardwareConcurrency.
        if config.hardening.reduce_system_info
            && browser.engine() == Engine::Chromium
            && !browser.has_builtin_fingerprint_noise()
        {
            let mut merged = false;
            for arg in &mut args {
                if let Some(rest) = arg.strip_prefix("--enable-features=") {
                    *arg = format!("--enable-features={rest},ReducedSystemInfo");
                    merged = true;
                    break;
                }
            }
            if !merged {
                args.push("--enable-features=ReducedSystemInfo".to_owned());
            }
        }
    }
    if config.hardening.enabled
        && config.hardening.disable_webrtc
        && browser.engine() == Engine::Chromium
    {
        // Supersedes the default `default_public_interface_only` flag already in
        // the browser's static flag list; Chromium honours the last occurrence.
        args.push("--webrtc-ip-handling-policy=disable_non_proxied_udp".to_owned());
    }
    args.extend(config.launch.extra_args.iter().cloned());
    if config.launch.incognito && browser.engine() == Engine::Chromium {
        args.push("--incognito".to_owned());
    }
    args
}

/// Builds the initial [`LauncherView`] from browser metadata.
///
/// Version fields start as `None` and are filled in once the update check
/// resolves.
fn build_initial_view<B: BrowserFamily>(
    browser: &B,
    arch: Arch,
    icon: &'static [u8],
) -> LauncherView {
    LauncherView {
        display_name: browser.display_name().to_owned(),
        id: browser.id().to_owned(),
        arch: arch.as_str().to_owned(),
        browser_version: None,
        engine_name: browser.engine().label().to_owned(),
        engine_version: None,
        build_date: None,
        upstream_url: browser.upstream_url().to_owned(),
        status: StatusLines::new("Starting\u{2026}"),
        progress: ProgressState::Indeterminate,
        icon_bytes: if icon.is_empty() { None } else { Some(icon) },
        accent: browser.accent(),
    }
}

// ── Pipeline thread ───────────────────────────────────────────────────────────

/// Internal outcome returned by [`update_check_phase`].
enum CheckPhaseResult {
    /// The existing install is current (or the check was skipped) — launch it.
    Launch,
    /// A newer version is available and `auto_download` is on — proceed to
    /// download.
    Download(VersionInfo),
    /// A newer version is available but `auto_download` is off — ask the user.
    Prompt(VersionInfo),
}

/// Action the pipeline should take after the user dismisses the error state.
enum PostErrorAction {
    /// Restart the whole pipeline from the check step.
    Retry,
    /// Error has been handled (browser launched anyway, or window will close).
    Done,
}

/// The user's response to the error-state buttons.
enum PipelineAction {
    Retry,
    LaunchAnyway,
    Close,
}

/// Runs the full update-and-launch pipeline on the calling (background OS)
/// thread.
///
/// An outer `'retry` loop allows the pipeline to restart from scratch when the
/// user clicks *Retry* after a transient failure.
// A linear pipeline orchestrator: the `'retry` loop's match arms use
// `continue`/`break 'retry` directly, so extracting helpers would mean
// threading a control-flow enum back out — net worse for readability.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn pipeline_thread<B: BrowserFamily + 'static>(
    browser: &Arc<B>,
    install_dir: &Path,
    opts: UpdateOptions,
    extra_args: &[String],
    branding: Option<&'static Branding>,
    hardening: HardeningConfig,
    state: &StateHandle,
    ctx: &egui::Context,
) {
    // Deref coercion: &Arc<B> → &B via Arc's Deref impl.
    let b: &B = browser;

    'retry: loop {
        // Reset to the initial Running phase so the window shows status lines.
        restart_pipeline(state, ctx);

        // Build a fresh async runtime for each attempt so that a cancelled or
        // timed-out future from the previous attempt cannot pollute the new one.
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let msg = format!("Failed to initialise async runtime: {e}");
                match handle_error(
                    b,
                    install_dir,
                    extra_args,
                    branding,
                    hardening,
                    state,
                    ctx,
                    &msg,
                ) {
                    PostErrorAction::Retry => continue 'retry,
                    PostErrorAction::Done => break 'retry,
                }
            }
        };

        // ── Update-check phase ────────────────────────────────────────────
        let check = rt.block_on(update_check_phase(b, install_dir, opts, state, ctx));

        let version_info: VersionInfo = match check {
            Err(e) => match handle_error(
                b,
                install_dir,
                extra_args,
                branding,
                hardening,
                state,
                ctx,
                &e.to_string(),
            ) {
                PostErrorAction::Retry => continue 'retry,
                PostErrorAction::Done => break 'retry,
            },

            Ok(CheckPhaseResult::Launch) => {
                set_status(
                    state,
                    ctx,
                    StatusLines {
                        primary: "Launching\u{2026}".to_owned(),
                        secondary: PREFETCH_NOTICE.to_owned(),
                    },
                    ProgressState::Hidden,
                );
                if opts.check_on_launch {
                    if let Err(e) =
                        rt.block_on(b.fetch_extension_updates(install_dir, hardening, opts))
                    {
                        tracing::warn!(
                            browser = b.id(),
                            error = %e,
                            "extension update check failed; continuing with bundled fallback"
                        );
                    }
                }
                match do_launch(b, install_dir, extra_args, branding, hardening, state, ctx) {
                    Ok(()) => {}
                    Err(e) => {
                        match handle_error(
                            b,
                            install_dir,
                            extra_args,
                            branding,
                            hardening,
                            state,
                            ctx,
                            &e.to_string(),
                        ) {
                            PostErrorAction::Retry => continue 'retry,
                            PostErrorAction::Done => {}
                        }
                    }
                }
                break 'retry;
            }

            Ok(CheckPhaseResult::Download(info)) => info,

            Ok(CheckPhaseResult::Prompt(info)) => {
                // Show the update prompt and suspend until the user decides.
                signal_update_prompt(state, ctx, &info.browser_version);
                // If the user chose to download, continue to download_and_install_phase.
                if let Some(true) = wait_for_decision(state) {
                    info
                } else {
                    // User skipped the update (or closed the window).
                    if b.installed_version(install_dir).is_some() {
                        set_status(
                            state,
                            ctx,
                            StatusLines {
                                primary: "Launching\u{2026}".to_owned(),
                                secondary: PREFETCH_NOTICE.to_owned(),
                            },
                            ProgressState::Hidden,
                        );
                        if opts.check_on_launch {
                            if let Err(e) =
                                rt.block_on(b.fetch_extension_updates(install_dir, hardening, opts))
                            {
                                tracing::warn!(
                                    browser = b.id(),
                                    error = %e,
                                    "extension update check failed; continuing with bundled fallback"
                                );
                            }
                        }
                        match do_launch(b, install_dir, extra_args, branding, hardening, state, ctx)
                        {
                            Ok(()) => {}
                            Err(e) => match handle_error(
                                b,
                                install_dir,
                                extra_args,
                                branding,
                                hardening,
                                state,
                                ctx,
                                &e.to_string(),
                            ) {
                                PostErrorAction::Retry => continue 'retry,
                                PostErrorAction::Done => {}
                            },
                        }
                    } else {
                        // Nothing installed to launch; just close the window.
                        signal_done(state, ctx);
                    }
                    break 'retry;
                }
            }
        };

        // ── Download + install phase ──────────────────────────────────────
        let install = rt.block_on(download_and_install_phase(
            b,
            install_dir,
            &version_info,
            extra_args,
            branding,
            hardening,
            opts,
            state,
            ctx,
        ));

        match install {
            Ok(()) => break 'retry,
            Err(e) => match handle_error(
                b,
                install_dir,
                extra_args,
                branding,
                hardening,
                state,
                ctx,
                &e.to_string(),
            ) {
                PostErrorAction::Done => break 'retry,
                PostErrorAction::Retry => {} // loop continues to next iteration
            },
        }
    }
}

// ── Async pipeline phases ─────────────────────────────────────────────────────

/// Cleans up stale downloads, optionally checks for an update, and returns
/// the next action the pipeline should take.
///
/// Checks the on-disk version cache first; if the cache is fresh (younger
/// than `version_cache::CACHE_TTL_SECS`, currently 6 h)
/// the network call is skipped entirely. When the network call fails with
/// [`BrowserError::Offline`] (connection error or HTTP 403 rate limit) and an
/// installed version already exists, returns `CheckPhaseResult::Launch` so the
/// pipeline auto-launches without showing an error screen.
async fn update_check_phase<B: BrowserFamily>(
    browser: &B,
    install_dir: &Path,
    opts: UpdateOptions,
    state: &StateHandle,
    ctx: &egui::Context,
) -> Result<CheckPhaseResult, BrowserError> {
    install::recover_staging(install_dir);

    if !opts.check_on_launch {
        tracing::info!(browser = browser.id(), "update check skipped by config");
        return Ok(CheckPhaseResult::Launch);
    }

    // ── Version cache ────────────────────────────────────────────────────────
    let launcher_dir = install_dir.parent().unwrap_or(install_dir);
    let cache_path = config::nomad_subdir(launcher_dir).join("nomad-version-cache.toml");
    if let Some(cached) = version_cache::VersionCache::load(&cache_path) {
        if cached.is_fresh() && cached.is_url_plausible() {
            let latest = cached.into_version_info();
            tracing::debug!(
                browser = browser.id(),
                version = %latest.browser_version,
                "version cache hit; skipping network check"
            );
            return Ok(resolve_check_action(
                browser,
                install_dir,
                latest,
                opts,
                state,
                ctx,
            ));
        }
    }

    // ── Network check ────────────────────────────────────────────────────────
    set_status(
        state,
        ctx,
        StatusLines::new("Checking for updates\u{2026}"),
        ProgressState::Indeterminate,
    );

    let latest = match browser.fetch_latest_version().await {
        Ok(info) => {
            version_cache::VersionCache::from_version_info(&info)
                .with_preserved_ubo_version(&cache_path)
                .save(&cache_path);
            info
        }
        Err(BrowserError::Offline(msg)) => {
            tracing::warn!(
                browser = browser.id(),
                error = %msg,
                "offline or rate-limited; launching installed version"
            );
            return if browser.installed_version(install_dir).is_some() {
                Ok(CheckPhaseResult::Launch)
            } else {
                Err(BrowserError::Offline(msg))
            };
        }
        Err(e) => return Err(e),
    };

    Ok(resolve_check_action(
        browser,
        install_dir,
        latest,
        opts,
        state,
        ctx,
    ))
}

/// Compares `latest` against the installed version and returns the appropriate
/// [`CheckPhaseResult`]. Also updates the UI view with the resolved version
/// strings.
fn resolve_check_action<B: BrowserFamily>(
    browser: &B,
    install_dir: &Path,
    latest: VersionInfo,
    opts: UpdateOptions,
    state: &StateHandle,
    ctx: &egui::Context,
) -> CheckPhaseResult {
    {
        let (lock, _) = &**state;
        let mut guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.view.browser_version = Some(latest.browser_version.clone());
        guard.view.engine_version = Some(latest.engine_version.clone());
    }
    ctx.request_repaint();

    let installed = browser.installed_version(install_dir);
    if !updater::needs_update(installed.as_ref(), &latest) {
        tracing::info!(
            browser = browser.id(),
            version = latest.browser_version,
            "already up to date"
        );
        return CheckPhaseResult::Launch;
    }

    if opts.auto_download {
        tracing::info!(
            browser = browser.id(),
            version = latest.browser_version,
            "update available; downloading automatically"
        );
        CheckPhaseResult::Download(latest)
    } else {
        tracing::info!(
            browser = browser.id(),
            version = latest.browser_version,
            "update available; auto_download disabled — prompting"
        );
        CheckPhaseResult::Prompt(latest)
    }
}

/// Downloads, verifies, extracts, and prepares a new browser version, then
/// launches it and signals [`WindowPhase::Done`].
///
/// # Errors
/// Propagates any [`BrowserError`] from download, verification, extraction,
/// portability-prefs, or process spawn.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn download_and_install_phase<B: BrowserFamily>(
    browser: &B,
    install_dir: &Path,
    latest: &VersionInfo,
    extra_args: &[String],
    branding: Option<&Branding>,
    hardening: HardeningConfig,
    update_opts: UpdateOptions,
    state: &StateHandle,
    ctx: &egui::Context,
) -> Result<(), BrowserError> {
    let (progress_tx, mut progress_rx) = tokio::sync::watch::channel(0.0_f32);

    // Forward download progress to the UI on a separate task so the download
    // future itself is not blocked by the egui lock.
    let state_fwd = Arc::clone(state);
    let ctx_fwd = ctx.clone();
    let fwd_task = tokio::spawn(async move {
        while progress_rx.changed().await.is_ok() {
            let p = *progress_rx.borrow();
            update_progress(&state_fwd, &ctx_fwd, p);
        }
    });

    // ── Download → verify → extract → swap (shared with updater::update) ──
    updater::download_and_install(
        browser,
        install_dir,
        latest,
        hardening.enabled,
        progress_tx,
        |step| {
            let (lines, progress) = match step {
                updater::InstallStep::Downloading => (
                    StatusLines {
                        primary: "Downloading update\u{2026}".to_owned(),
                        secondary: latest.browser_version.clone(),
                    },
                    ProgressState::Determinate(0.0),
                ),
                updater::InstallStep::Verifying => (
                    StatusLines::new("Verifying\u{2026}"),
                    ProgressState::Indeterminate,
                ),
                updater::InstallStep::Installing => (
                    StatusLines::new("Installing\u{2026}"),
                    ProgressState::Indeterminate,
                ),
            };
            set_status(state, ctx, lines, progress);
        },
    )
    .await?;
    // Wait for the forwarder to drain the final progress value (the sender
    // is dropped when the download completes).
    let _ = fwd_task.await;

    // ── Launch ────────────────────────────────────────────────────────────
    set_status(
        state,
        ctx,
        StatusLines {
            primary: "Launching\u{2026}".to_owned(),
            secondary: PREFETCH_NOTICE.to_owned(),
        },
        ProgressState::Hidden,
    );
    if let Err(e) = browser
        .fetch_extension_updates(install_dir, hardening, update_opts)
        .await
    {
        tracing::warn!(
            browser = browser.id(),
            error = %e,
            "extension update check failed; continuing with bundled fallback"
        );
    }
    do_launch(
        browser,
        install_dir,
        extra_args,
        branding,
        hardening,
        state,
        ctx,
    )?;
    Ok(())
}

// ── Synchronous pipeline helpers ──────────────────────────────────────────────

/// Prefs that disable all sanitize-on-shutdown behaviour in Gecko. Written
/// into the Nomad-managed `user.js` block when `[hardening] sanitize_on_shutdown
/// = false` so users can opt out without editing payloads.
const SANITIZE_DISABLE_OVERRIDE: &str =
    "user_pref(\"privacy.sanitize.sanitizeOnShutdown\", false);";

/// Appended to the managed `user.js` block when `[hardening] disable_webrtc = true`.
///
/// Fully disables the WebRTC peer-connection stack — prevents real-IP
/// leakage via STUN at the cost of breaking all WebRTC calls.
const WEBRTC_DISABLE_OVERRIDE: &str = "user_pref(\"media.peerconnection.enabled\", false);";

/// Secondary status text shown during every browser launch.
///
/// Windows Prefetch records the full executable path on launch and requires
/// administrator privileges to delete — users on shared machines should be
/// aware that the portable drive path is logged by the OS.
const PREFETCH_NOTICE: &str =
    "Note: Windows Prefetch logs executable paths (admin access needed to clear)";

/// Applies browser branding (once), writes hardening files, spawns the browser
/// process, and signals [`WindowPhase::Done`].
#[allow(clippy::too_many_lines)]
fn do_launch<B: BrowserFamily>(
    browser: &B,
    install_dir: &Path,
    extra_args: &[String],
    branding: Option<&Branding>,
    hardening: HardeningConfig,
    state: &StateHandle,
    ctx: &egui::Context,
) -> Result<(), BrowserError> {
    apply_branding(install_dir, branding, state, ctx);
    if hardening.enabled {
        if let Hardening::LaunchFlags {
            local_state,
            preferences,
            ..
        } = browser.hardening()
        {
            if let Some(user_data_dir) = browser.profile_dir(install_dir) {
                if let Err(e) =
                    hardening::write_chromium_state(&user_data_dir, local_state, preferences)
                {
                    tracing::warn!(
                        browser = browser.id(),
                        error = %e,
                        "failed to seed Chromium Local State / Preferences; \
                         chrome://flags may not reflect hardening"
                    );
                } else if local_state.is_some() || preferences.is_some() {
                    tracing::info!(
                        browser = browser.id(),
                        "seeded Local State + Default/Preferences for chrome://flags visibility"
                    );
                }
            }
        }
        if let Hardening::GeckoProfile {
            user_js,
            policies,
            autoconfig,
            cfg,
            ..
        } = browser.hardening()
        {
            if let Some(profile_dir) = browser.profile_dir(install_dir) {
                if user_js.is_empty() {
                    // The browser opts out of Nomad's user.js (e.g. Mullvad,
                    // which manages its own prefs and crowd-blending). Write
                    // nothing — not even the WebRTC / sanitize overrides, which
                    // would make the profile fingerprint-distinguishable from
                    // the browser's own crowd. Strip any block a prior Nomad
                    // version may have left behind.
                    if let Err(e) = hardening::remove_managed_user_js(&profile_dir) {
                        tracing::warn!(
                            browser = browser.id(),
                            error = %e,
                            "failed to remove stale Nomad user.js"
                        );
                    }
                } else {
                    let mut content = if hardening.sanitize_on_shutdown {
                        user_js.to_owned()
                    } else {
                        format!("{user_js}\n{SANITIZE_DISABLE_OVERRIDE}")
                    };
                    if hardening.disable_webrtc {
                        content = format!("{content}\n{WEBRTC_DISABLE_OVERRIDE}");
                    }
                    if let Err(e) = hardening::write_user_js(&profile_dir, &content) {
                        tracing::warn!(
                            browser = browser.id(),
                            error = %e,
                            "failed to write user.js; launching without hardening update"
                        );
                    }
                }
            }
            tracing::warn!(
                browser = browser.id(),
                "Safe Browsing disabled by hardening profile (privacy trade-off); \
                 no browser-level phishing/malware protection — use a DNS block list as substitute"
            );
            if let Some(p) = policies {
                // If the uBlock XPI was provisioned by fetch_extension_updates,
                // inject a file:// URL so Firefox installs it without further
                // AMO contact.
                let launcher_dir = install_dir.parent().unwrap_or(install_dir);
                let xpi_dir = config::nomad_subdir(launcher_dir).join("Gecko-extensions");
                let ublock_xpi = xpi_dir.join("uBlock0.xpi");
                let effective_policies = if ublock_xpi.exists() {
                    hardening::inject_ublock_policy(p, &ublock_xpi)
                } else {
                    p.to_owned()
                };
                if let Err(e) = hardening::write_policies_json(install_dir, &effective_policies) {
                    tracing::warn!(
                        browser = browser.id(),
                        error = %e,
                        "failed to write policies.json; hardening may be stale"
                    );
                }
            }
            if let (Some(a), Some(c)) = (autoconfig, cfg) {
                if let Err(e) = hardening::write_autoconfig(install_dir, a, c) {
                    tracing::warn!(
                        browser = browser.id(),
                        error = %e,
                        "failed to write autoconfig pair; hardening will fall back to user.js only"
                    );
                } else {
                    tracing::info!(
                        browser = browser.id(),
                        "wrote install_dir/nomad.cfg + defaults/pref/autoconfig.js (LibreWolf-derived hardening)"
                    );
                }
            }
        }
    }
    prepare_browser_for_launch(browser, install_dir, hardening);
    // Remove host-system traces from a previous (possibly crashed) session
    // before the browser process starts. Post-exit cleanup is handled by the
    // watcher in `handle_cleanup_flag()`.
    scrub_mozilla_installs_ini();
    scrub_mozilla_runtime_dirs();
    scrub_mullvad_runtime_dir();
    scrub_chromium_runtime_dirs();
    let mut cmd = browser.launch_command(install_dir, extra_args);
    let browser_exe_name = browser_exe_file_name(&cmd);
    let child = cmd.spawn()?;
    let pid = child.id();
    tracing::info!(browser = browser.id(), pid, exe = %browser_exe_name, "browser launched");
    spawn_cleanup_watcher(
        pid,
        &browser_exe_name,
        hardening.scrub_thumbnail_cache,
        hardening.scrub_prefetch,
    );
    signal_done(state, ctx);
    Ok(())
}

/// Extracts the browser executable file name (e.g. `"firefox.exe"`,
/// `"chrome.exe"`) from a `Command` built by `BrowserFamily::launch_command()`.
fn browser_exe_file_name(cmd: &std::process::Command) -> String {
    std::path::Path::new(cmd.get_program())
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_owned()
}

/// Applies browser PE-icon branding when one is configured and not yet
/// applied, showing an "Applying branding…" status during the patch.
fn apply_branding(
    install_dir: &Path,
    branding: Option<&Branding>,
    state: &StateHandle,
    ctx: &egui::Context,
) {
    if let Some(br) = branding {
        if branding::is_pending(install_dir, br) {
            set_status(
                state,
                ctx,
                StatusLines::new("Applying branding\u{2026}"),
                ProgressState::Indeterminate,
            );
            branding::ensure_branding(install_dir, br);
        }
    }
}

/// Displays the error state, waits for the user to act, and either launches
/// the existing install (Launch anyway) or hands control back to the retry
/// loop.
#[allow(clippy::too_many_arguments)]
fn handle_error<B: BrowserFamily>(
    browser: &B,
    install_dir: &Path,
    extra_args: &[String],
    branding: Option<&Branding>,
    hardening: HardeningConfig,
    state: &StateHandle,
    ctx: &egui::Context,
    message: &str,
) -> PostErrorAction {
    let has_fallback = browser.installed_version(install_dir).is_some();
    tracing::error!(browser = browser.id(), error = message, "pipeline error");
    show_error(state, ctx, message, has_fallback);

    match wait_for_pipeline_action(state) {
        PipelineAction::Retry => PostErrorAction::Retry,
        PipelineAction::LaunchAnyway => {
            apply_branding(install_dir, branding, state, ctx);
            set_status(
                state,
                ctx,
                StatusLines::new("Launching\u{2026}"),
                ProgressState::Hidden,
            );
            prepare_browser_for_launch(browser, install_dir, hardening);
            scrub_mozilla_installs_ini();
            scrub_mozilla_runtime_dirs();
            scrub_mullvad_runtime_dir();
            scrub_chromium_runtime_dirs();
            let mut cmd = browser.launch_command(install_dir, extra_args);
            let browser_exe_name = browser_exe_file_name(&cmd);
            if let Ok(child) = cmd.spawn() {
                tracing::info!(
                    browser = browser.id(),
                    pid = child.id(),
                    exe = %browser_exe_name,
                    "browser launched (fallback)"
                );
                spawn_cleanup_watcher(
                    child.id(),
                    &browser_exe_name,
                    hardening.scrub_thumbnail_cache,
                    hardening.scrub_prefetch,
                );
            }
            signal_done(state, ctx);
            PostErrorAction::Done
        }
        PipelineAction::Close => PostErrorAction::Done,
    }
}

/// Runs browser-specific, best-effort launch preparation such as bundled
/// extension staging. Preparation failures should not prevent the browser from
/// launching; the browser itself remains the product boundary.
fn prepare_browser_for_launch<B: BrowserFamily>(
    browser: &B,
    install_dir: &Path,
    hardening: HardeningConfig,
) {
    if let Err(e) = browser.prepare_launch(install_dir, hardening) {
        tracing::warn!(
            browser = browser.id(),
            error = %e,
            "browser-specific launch preparation failed; continuing"
        );
    }
}

// ── State mutation helpers ────────────────────────────────────────────────────

/// Resets `phase` to [`WindowPhase::Running`] and clears the status lines to
/// the "Starting…" initial state. Called at the top of each retry iteration.
fn restart_pipeline(state: &StateHandle, ctx: &egui::Context) {
    let (lock, _) = &**state;
    let mut guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.phase = WindowPhase::Running;
    guard.view.status = StatusLines::new("Starting\u{2026}");
    guard.view.progress = ProgressState::Indeterminate;
    drop(guard);
    ctx.request_repaint();
}

/// Updates the view's status lines and progress bar, then requests a repaint.
fn set_status(
    state: &StateHandle,
    ctx: &egui::Context,
    status: StatusLines,
    progress: ProgressState,
) {
    let (lock, _) = &**state;
    let mut guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.view.status = status;
    guard.view.progress = progress;
    drop(guard);
    ctx.request_repaint();
}

/// Updates the progress-bar fraction, then requests a repaint.
///
/// Called from the download-progress forwarding task.
fn update_progress(state: &StateHandle, ctx: &egui::Context, fraction: f32) {
    let (lock, _) = &**state;
    let mut guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.view.progress = ProgressState::Determinate(fraction);
    drop(guard);
    ctx.request_repaint();
}

/// Sets [`WindowPhase::Done`] and wakes the condvar so any waiting side exits.
fn signal_done(state: &StateHandle, ctx: &egui::Context) {
    let (lock, cvar) = &**state;
    let mut guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.phase = WindowPhase::Done;
    cvar.notify_all();
    drop(guard);
    ctx.request_repaint();
}

/// Sets [`WindowPhase::Error`] and wakes the condvar so the window repaints.
fn show_error(state: &StateHandle, ctx: &egui::Context, message: &str, has_fallback: bool) {
    let (lock, cvar) = &**state;
    let mut guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.phase = WindowPhase::Error {
        message: message.to_owned(),
        has_fallback,
    };
    cvar.notify_all();
    drop(guard);
    ctx.request_repaint();
}

/// Sets [`WindowPhase::UpdatePrompt`] and wakes the condvar so the window
/// shows the Update / Launch-current buttons.
fn signal_update_prompt(state: &StateHandle, ctx: &egui::Context, new_version: &str) {
    let (lock, cvar) = &**state;
    let mut guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.phase = WindowPhase::UpdatePrompt {
        new_version: new_version.to_owned(),
    };
    cvar.notify_all();
    drop(guard);
    ctx.request_repaint();
}

// ── Condvar waits ─────────────────────────────────────────────────────────────

/// Blocks the calling thread until the user resolves the update prompt.
///
/// Returns `Some(true)` to download, `Some(false)` to skip, or `None` when
/// the window was closed before a decision was made.
fn wait_for_decision(state: &StateHandle) -> Option<bool> {
    let (lock, cvar) = &**state;
    let mut guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        match &guard.phase {
            WindowPhase::UpdateDecided(download) => return Some(*download),
            WindowPhase::Done => return None,
            _ => {
                guard = cvar
                    .wait(guard)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
    }
}

/// Blocks the calling thread until the user clicks Retry, Launch anyway, or
/// Close after an error.
fn wait_for_pipeline_action(state: &StateHandle) -> PipelineAction {
    let (lock, cvar) = &**state;
    let mut guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        match &guard.phase {
            WindowPhase::RetryRequested => return PipelineAction::Retry,
            WindowPhase::LaunchAnyway => return PipelineAction::LaunchAnyway,
            WindowPhase::Done => return PipelineAction::Close,
            _ => {
                guard = cvar
                    .wait(guard)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
    }
}

// ── Post-exit cleanup ─────────────────────────────────────────────────────────

/// Splits argv at the first literal `--`: Nomad's own flags come before it,
/// everything after is forwarded verbatim to the browser invocation.
///
/// This is the open-command contract registered by `--register-default`
/// (`"<exe>" -- "%1"`): the forwarded tail carries the clicked URL or
/// document as positional arguments, which must reach the browser or every
/// link click through the default-browser registration is silently dropped.
fn split_forwarded_args(args: &[String]) -> (&[String], &[String]) {
    match args.iter().position(|a| a == "--") {
        Some(i) => (&args[..i], &args[i + 1..]),
        None => (args, &[]),
    }
}

/// Parses cleanup-watcher arguments: `--nomad-cleanup-pid <pid>` (required),
/// `--nomad-cleanup-exe <name>` (optional), `--nomad-scrub-thumbcache` (flag),
/// and `--nomad-scrub-prefetch` (flag). Returns `None` when
/// `--nomad-cleanup-pid` is absent.
fn parse_cleanup_pid(args: &[String]) -> Option<CleanupArgs> {
    let pos = args.iter().position(|a| a == "--nomad-cleanup-pid")?;
    let browser_pid = args.get(pos + 1)?.parse().ok()?;
    let browser_exe = args
        .iter()
        .position(|a| a == "--nomad-cleanup-exe")
        .and_then(|i| args.get(i + 1).cloned());
    let scrub_thumbnail_cache = args.iter().any(|a| a == "--nomad-scrub-thumbcache");
    let scrub_prefetch = args.iter().any(|a| a == "--nomad-scrub-prefetch");
    Some(CleanupArgs {
        browser_pid,
        browser_exe,
        scrub_thumbnail_cache,
        scrub_prefetch,
    })
}

/// Entry point for cleanup-watcher mode.
///
/// Blocks until the browser PID (and any sibling processes spawned as
/// background tasks) have all exited, then scrubs known host-system traces.
/// Called when `run()` detects `--nomad-cleanup-pid`.
#[allow(clippy::needless_pass_by_value)] // consumed as a whole unit, not field-by-field
fn handle_cleanup_flag(args: CleanupArgs) -> ExitCode {
    tracing::info!(
        pid = args.browser_pid,
        exe = args.browser_exe.as_deref().unwrap_or("(unknown)"),
        "cleanup watcher started"
    );
    wait_for_pid(args.browser_pid);
    if let Some(ref name) = args.browser_exe {
        // Background-task children (e.g. `firefox.exe --backgroundtask defaultagent`)
        // can outlive the main UI process by minutes and hold file handles in
        // %LOCALAPPDATA%\Mozilla\. Wait up to 30 seconds for the process tree
        // to settle before scrubbing.
        wait_for_all_processes_named(name, 30);
    }
    tracing::info!(
        pid = args.browser_pid,
        "browser tree exited; scrubbing host traces"
    );
    scrub_temp();
    scrub_wer();
    scrub_mozilla_installs_ini();
    scrub_mozilla_runtime_dirs();
    scrub_mullvad_runtime_dir();
    scrub_chromium_runtime_dirs();
    scrub_shell_recent();
    scrub_automatic_destinations();
    if args.scrub_thumbnail_cache {
        scrub_thumbnail_cache();
    }
    if args.scrub_prefetch && !scrub_prefetch() {
        tracing::info!("Prefetch scrub needs elevation; requesting UAC prompt");
        elevate_for_prefetch_scrub();
    }
    ExitCode::SUCCESS
}

/// Entry point for the elevated Prefetch scrubber sub-process.
///
/// Spawned by `elevate_for_prefetch_scrub()` with the `runas` `ShellExecute` verb
/// so it runs with an elevated token. Deletes Prefetch entries for all browser
/// and launcher executables that Nomad manages, then exits.
fn handle_prefetch_scrub_flag() -> ExitCode {
    tracing::info!("elevated Prefetch scrubber started");
    scrub_prefetch();
    ExitCode::SUCCESS
}

/// Spawns this executable again as a detached cleanup watcher. The watcher
/// waits for the browser (and its background-task children) to exit, then
/// scrubs host-system traces. When `scrub_thumbnail_cache` is `true`, it also
/// clears Windows thumbnail/icon caches (briefly restarts Explorer). When
/// `scrub_prefetch` is `true`, it attempts to delete Prefetch entries,
/// elevating via UAC if needed.
fn spawn_cleanup_watcher(
    browser_pid: u32,
    browser_exe: &str,
    scrub_thumbnail_cache: bool,
    scrub_prefetch: bool,
) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut cmd_args = vec![
        "--nomad-cleanup-pid".to_owned(),
        browser_pid.to_string(),
        "--nomad-cleanup-exe".to_owned(),
        browser_exe.to_owned(),
    ];
    if scrub_thumbnail_cache {
        cmd_args.push("--nomad-scrub-thumbcache".to_owned());
    }
    if scrub_prefetch {
        cmd_args.push("--nomad-scrub-prefetch".to_owned());
    }
    match std::process::Command::new(&exe).args(&cmd_args).spawn() {
        Ok(w) => tracing::info!(
            watcher_pid = w.id(),
            browser_pid,
            exe = browser_exe,
            scrub_thumbnail_cache,
            "cleanup watcher spawned"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            browser_pid,
            "could not spawn cleanup watcher; host traces may persist"
        ),
    }
}

/// Blocks the calling thread until the process with `pid` exits.
///
/// On Windows, opens the process with `PROCESS_SYNCHRONIZE` rights and calls
/// `WaitForSingleObject` with an infinite timeout — zero CPU usage while
/// waiting. On non-Windows platforms (compile-only path) sleeps briefly.
fn wait_for_pid(pid: u32) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE,
        };
        // SAFETY: pid is a live OS process ID; handle is checked before use.
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        if handle.is_null() {
            tracing::warn!(
                pid,
                "OpenProcess failed; cleanup may race with browser exit"
            );
            std::thread::sleep(std::time::Duration::from_secs(5));
            return;
        }
        // SAFETY: handle is a valid process handle obtained above.
        unsafe {
            WaitForSingleObject(handle, INFINITE);
            CloseHandle(handle);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Polls the running process list every 500 ms and returns when **no** process
/// with the given executable file name (case-insensitive, e.g. `"firefox.exe"`)
/// is still running, or `max_wait_secs` elapses — whichever comes first.
///
/// Used by the cleanup watcher to wait out background-task children that
/// Firefox/Floorp/Waterfox spawn detached from the main UI process and which
/// hold file handles in `%LOCALAPPDATA%\Mozilla\` after the parent exits.
fn wait_for_all_processes_named(exe_name: &str, max_wait_secs: u64) {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(max_wait_secs);
    let initial = count_processes_named(exe_name);
    if initial == 0 {
        return;
    }
    tracing::info!(
        exe = exe_name,
        count = initial,
        "waiting for background-task children to exit"
    );
    while start.elapsed() < timeout {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if count_processes_named(exe_name) == 0 {
            tracing::info!(
                exe = exe_name,
                elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                "all browser processes have exited"
            );
            return;
        }
    }
    tracing::warn!(
        exe = exe_name,
        remaining = count_processes_named(exe_name),
        "timed out waiting for browser processes; proceeding with scrub anyway"
    );
}

/// Counts processes whose executable filename matches `exe_name`
/// (case-insensitive). Returns 0 on non-Windows or on any enumeration failure.
fn count_processes_named(exe_name: &str) -> u32 {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        // SAFETY: snapshot handle is closed before return; PROCESSENTRY32W is
        // zero-initialized except for dwSize per MSDN requirements.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot.is_null() || snapshot as isize == -1 {
                return 0;
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            #[allow(clippy::cast_possible_truncation)]
            // PROCESSENTRY32W is ~568 bytes, well within u32
            {
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            }
            let mut count: u32 = 0;
            let target = exe_name.to_ascii_lowercase();
            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    let len = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let name = std::ffi::OsString::from_wide(&entry.szExeFile[..len])
                        .to_string_lossy()
                        .to_ascii_lowercase();
                    if name == target {
                        count += 1;
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
            count
        }
    }
    #[cfg(not(windows))]
    {
        let _ = exe_name;
        0
    }
}

/// Returns `true` when `root` is a removable drive (e.g. a USB stick or SD
/// card).  Used to guard scrubs that would destroy system-wide Recent Items /
/// `JumpList` history when the launcher is run from a fixed drive such as `C:`.
///
/// Returns `false` for fixed, network, CD-ROM, and RAM drives, and on
/// non-Windows platforms (no scrubs run there anyway).
fn is_removable_drive(root: &std::path::Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
        // DRIVE_REMOVABLE = 2 (winbase.h); stable across all Windows versions.
        const DRIVE_REMOVABLE: u32 = 2;
        let mut wide: Vec<u16> = root.as_os_str().encode_wide().collect();
        wide.push(0);
        // SAFETY: `wide` is a valid null-terminated UTF-16 drive-root string
        // (e.g. L"C:\").  GetDriveTypeW reads it and returns immediately
        // without storing the pointer or performing any writes.
        unsafe { GetDriveTypeW(wide.as_ptr()) == DRIVE_REMOVABLE }
    }
    #[cfg(not(windows))]
    {
        let _ = root;
        false
    }
}

/// Returns the root of the drive on which this executable lives.
///
/// Used to identify the portable drive without any command-line plumbing:
/// the cleanup watcher re-executes the same launcher binary, so
/// `current_exe()` reliably points at the portable drive.
///
/// Returns `None` on non-Windows or if the path has no drive prefix.
fn portable_drive_root() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let mut root = std::path::PathBuf::new();
    for component in exe.components() {
        use std::path::Component;
        match component {
            Component::Prefix(_) => root.push(component.as_os_str()),
            Component::RootDir => {
                root.push(component.as_os_str());
                return Some(root);
            }
            _ => break,
        }
    }
    None
}

/// Parses the local file target path from a Windows Shell Link (`.lnk`) file.
///
/// Implements the subset of MS-SHLLINK needed to read `LocalBasePath` /
/// `LocalBasePathUnicode` from the optional `LinkInfo` block.  Returns `None`
/// when the file is not a valid LNK, has no `LinkInfo`, or has no local path.
fn lnk_target_path(data: &[u8]) -> Option<std::path::PathBuf> {
    if data.len() < 76 {
        return None;
    }
    // §2.1: HeaderSize must be 0x4C and first byte of CLSID is the magic 0x4C.
    if data[..4] != [0x4C, 0x00, 0x00, 0x00] {
        return None;
    }
    let link_flags = u32::from_le_bytes(data[20..24].try_into().ok()?);

    let mut pos: usize = 76;

    // §2.2: Skip optional LinkTargetIDList (flag bit 0 = HasLinkTargetIDList).
    if link_flags & 0x01 != 0 {
        if pos + 2 > data.len() {
            return None;
        }
        let id_list_size = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2 + id_list_size;
    }

    // §2.3: LinkInfo block (flag bit 1 = HasLinkInfo).
    if link_flags & 0x02 == 0 {
        return None;
    }
    if pos + 4 > data.len() {
        return None;
    }
    let li_size = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
    if li_size < 28 || pos + li_size > data.len() {
        return None;
    }
    let li = &data[pos..pos + li_size];

    // LinkInfoFlags bit 0 = VolumeIDAndLocalBasePath (local path present).
    let li_flags = u32::from_le_bytes(li[8..12].try_into().ok()?);
    if li_flags & 0x01 == 0 {
        return None;
    }

    let header_size = u32::from_le_bytes(li[4..8].try_into().ok()?) as usize;

    // §2.3.1: Extended header (>= 0x24 bytes) carries Unicode offsets.
    if header_size >= 0x24 && li.len() >= 32 {
        let uc_offset = u32::from_le_bytes(li[28..32].try_into().ok()?) as usize;
        if uc_offset > 0 && uc_offset + 2 <= li_size {
            let chars: Vec<u16> = li[uc_offset..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            if !chars.is_empty() {
                if let Ok(s) = String::from_utf16(&chars) {
                    return Some(std::path::PathBuf::from(s));
                }
            }
        }
    }

    // §2.3: Fall back to ANSI LocalBasePath.
    let ansi_offset = u32::from_le_bytes(li[16..20].try_into().ok()?) as usize;
    if ansi_offset == 0 || ansi_offset >= li_size {
        return None;
    }
    let tail = &li[ansi_offset..];
    let end = tail.iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(&tail[..end]).ok()?;
    Some(std::path::PathBuf::from(s))
}

/// Removes `.lnk` files from `%APPDATA%\Microsoft\Windows\Recent\` whose
/// resolved target path is on the portable drive.
///
/// The portable drive root is derived from the watcher's own executable path —
/// no extra command-line arguments are required.
fn scrub_shell_recent() {
    let Some(drive_root) = portable_drive_root() else {
        return;
    };
    // Skip when the launcher is on a fixed drive — the scrub would delete
    // Recent Items for the entire system drive, not just the portable medium.
    if !is_removable_drive(&drive_root) {
        return;
    }
    let Some(appdata) = std::env::var_os("APPDATA") else {
        return;
    };
    let recent = std::path::PathBuf::from(appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Recent");
    scrub_shell_recent_in(&recent, &drive_root);
}

/// Directory-level scrub, split from the env-var plumbing so it is testable
/// against a fixture directory (same pattern as `scrub_mozilla_runtime_dirs_in`).
fn scrub_shell_recent_in(recent: &Path, drive_root: &Path) {
    let Ok(entries) = std::fs::read_dir(recent) else {
        return;
    };
    let mut count: usize = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("lnk") {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        let Some(target) = lnk_target_path(&data) else {
            continue;
        };
        if target.starts_with(drive_root) && std::fs::remove_file(&path).is_ok() {
            count += 1;
        }
    }
    if count > 0 {
        tracing::info!(
            count,
            "removed shell Recent Items pointing to portable drive"
        );
    }
}

/// Removes `.automaticDestinations-ms` `JumpList` files from
/// `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` that contain
/// any reference to the portable drive root.
///
/// `AutomaticDestinations` files are OLE Compound Document archives whose
/// embedded streams each hold a Windows Shell Link record.  Rather than
/// implementing a full OLE/CFB parser, we scan the raw file bytes for the
/// drive-root string encoded as UTF-16LE — the path string appears verbatim
/// inside the OLE stream data sectors.  The scan is conservative: a file is
/// deleted only when the portable drive path is positively identified in its
/// bytes.  Files that merely list other drives, or files in subdirectories,
/// are never touched.
///
/// **Assumption / limitation — Windows drive letters only.** The needle is the
/// drive root as a colon-backslash string (e.g. `E:\`) encoded UTF-16LE, which
/// is how the Shell stores paths for a removable drive.  It will *not* detect a
/// portable location reached via a UNC / network path (`\\server\share`), a
/// mounted junction, or a drive letter held in a resolved / normalized variant.
/// Nomad only ever runs from a drive letter today, so this is sufficient;
/// revisit if non-drive-letter portable roots are ever supported.
fn scrub_automatic_destinations() {
    let Some(drive_root) = portable_drive_root() else {
        return;
    };
    // Skip when the launcher is on a fixed drive — the scrub would delete
    // JumpList files for the entire system drive, not just the portable medium.
    if !is_removable_drive(&drive_root) {
        return;
    }
    let Some(appdata) = std::env::var_os("APPDATA") else {
        return;
    };
    let dir = std::path::PathBuf::from(appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Recent")
        .join("AutomaticDestinations");
    scrub_automatic_destinations_dir(&dir, &drive_root);
}

/// Inner function — separated for unit testing.
fn scrub_automatic_destinations_dir(dir: &std::path::Path, drive_root: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    // Encode the drive root (e.g. "E:\") as UTF-16LE bytes.  Every path stored
    // inside the OLE stream will begin with this sequence.
    let needle: Vec<u8> = drive_root
        .to_string_lossy()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    if needle.is_empty() {
        return;
    }

    let mut count: usize = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("automaticDestinations-ms"))
        {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        if data.windows(needle.len()).any(|w| w == needle.as_slice()) {
            match std::fs::remove_file(&path) {
                Ok(()) => count += 1,
                Err(e) => {
                    tracing::debug!(?path, error = %e, "could not remove AutomaticDestinations file");
                }
            }
        }
    }
    if count > 0 {
        tracing::info!(
            count,
            "removed AutomaticDestinations JumpList files referencing portable drive"
        );
    }
}

/// Clears Windows thumbnail and icon caches by terminating Explorer briefly,
/// deleting `thumbcache_*.db` and `iconcache_*.db` from
/// `%LOCALAPPDATA%\Microsoft\Windows\Explorer\`, then restarting Explorer.
///
/// The taskbar and desktop icons are absent for roughly one second. Called only
/// when `[hardening] scrub_thumbnail_cache = true` in `nomad.toml`.
fn scrub_thumbnail_cache() {
    let Some(local) = std::env::var_os("LOCALAPPDATA") else {
        return;
    };
    let cache_dir = std::path::PathBuf::from(local)
        .join("Microsoft")
        .join("Windows")
        .join("Explorer");
    if !cache_dir.exists() {
        return;
    }
    tracing::info!("scrubbing thumbnail/icon cache (Explorer will restart briefly)");
    kill_all_processes_named("explorer.exe");
    // Brief pause so the OS releases file handles before we try to delete.
    std::thread::sleep(std::time::Duration::from_millis(600));
    if let Ok(entries) = std::fs::read_dir(&cache_dir) {
        let mut count: usize = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let stem = name.to_string_lossy().to_ascii_lowercase();
            if (stem.starts_with("thumbcache_") || stem.starts_with("iconcache_"))
                && path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("db"))
                && std::fs::remove_file(&path).is_ok()
            {
                count += 1;
            }
        }
        if count > 0 {
            tracing::info!(count, "removed thumbnail/icon cache files");
        }
    }
    restart_explorer();
}

/// Terminates all running instances of `exe_name` (case-insensitive) using
/// `TerminateProcess`. Used exclusively by `scrub_thumbnail_cache` to stop
/// Explorer before clearing its cache files.
fn kill_all_processes_named(exe_name: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };
        // SAFETY: handle lifetimes are tightly scoped; snapshot is closed before return.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot.is_null() || snapshot as isize == -1 {
                return;
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            #[allow(clippy::cast_possible_truncation)]
            // PROCESSENTRY32W is ~568 bytes, well within u32
            {
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            }
            let target = exe_name.to_ascii_lowercase();
            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    let len = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let name = std::ffi::OsString::from_wide(&entry.szExeFile[..len])
                        .to_string_lossy()
                        .to_ascii_lowercase();
                    if name == target {
                        let h = OpenProcess(PROCESS_TERMINATE, 0, entry.th32ProcessID);
                        if !h.is_null() {
                            TerminateProcess(h, 1);
                            CloseHandle(h);
                        }
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = exe_name;
    }
}

/// Resolves the full path to the trusted Windows Explorer binary under
/// `%SystemRoot%`, falling back to the conventional location. Using an absolute
/// path prevents `CreateProcess` from resolving a planted `explorer.exe` from
/// the launcher directory or the current working directory (CWE-426/427).
fn system_explorer_path() -> std::path::PathBuf {
    std::env::var_os("SystemRoot").map_or_else(
        || std::path::PathBuf::from(r"C:\Windows\explorer.exe"),
        |root| std::path::Path::new(&root).join("explorer.exe"),
    )
}

/// Restarts Windows Explorer as the user's shell after `kill_all_processes_named`
/// has terminated it for cache scrubbing.
fn restart_explorer() {
    match std::process::Command::new(system_explorer_path()).spawn() {
        Ok(_) => tracing::info!("Explorer restarted"),
        Err(e) => tracing::warn!(error = %e, "could not restart Explorer"),
    }
}

/// Removes browser-related temp files from `%TEMP%` that browsers may leave
/// behind after exit.
fn scrub_temp() {
    let Ok(temp) = std::env::var("TEMP") else {
        return;
    };
    scrub_temp_in(Path::new(&temp));
}

/// Directory-level scrub, split from the env-var plumbing so it is testable
/// against a fixture directory.
fn scrub_temp_in(temp: &Path) {
    let Ok(entries) = std::fs::read_dir(temp) else {
        return;
    };
    let mut count: usize = 0;
    for entry in entries.flatten() {
        if is_browser_temp_name(&entry.file_name()) {
            let removed = std::fs::remove_dir_all(entry.path())
                .or_else(|_| std::fs::remove_file(entry.path()))
                .is_ok();
            if removed {
                count += 1;
            }
        }
    }
    if count > 0 {
        tracing::info!(count, "removed browser entries from %TEMP%");
    }
}

fn is_browser_temp_name(name: &std::ffi::OsStr) -> bool {
    let n = name.to_string_lossy();
    // Chromium temp directory patterns
    n.starts_with("scoped_dir")
        || n.starts_with(".org.chromium.")
        || n.starts_with("chrome_")
        // Firefox / Gecko temp patterns
        || n.starts_with("mozilla-temp-")
        || n.starts_with(".moz_extension")
}

/// Browser process executable names Nomad scrubs WER artefacts for. Kept in
/// one place so the match sites in [`scrub_wer_crash_dumps_in`] and
/// [`scrub_wer_reports_in`] cannot drift apart, and adding a new supported
/// browser is a single-line change.
/// All entries are lowercased to match the case-folded comparison below.
const BROWSER_EXE_NAMES: &[&str] = &[
    "chrome.exe",             // Ungoogled Chromium, Helium
    "firefox.exe",            // Firefox, Firefox ESR
    "floorp.exe",             // Floorp
    "librewolf.exe",          // LibreWolf
    "mullvadbrowser.exe",     // Mullvad Browser
    "waterfox.exe",           // Waterfox
    "bitwarden.exe",          // Bitwarden desktop (self-extracted Electron app)
    "bitwarden-portable.exe", // Bitwarden staged portable binary
];

/// Removes Windows Error Reporting artefacts for browser executables:
/// - crash dumps from `%LOCALAPPDATA%\CrashDumps\`
/// - report subdirectories from `%ProgramData%\Microsoft\Windows\WER\ReportQueue\`
/// - report subdirectories from `%ProgramData%\Microsoft\Windows\WER\ReportArchive\`
///
/// WER writes these independently of each browser's own crash reporter.
fn scrub_wer() {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        scrub_wer_crash_dumps_in(&std::path::PathBuf::from(local).join("CrashDumps"));
    }
    if let Some(progdata) = std::env::var_os("ProgramData") {
        let wer_base = std::path::PathBuf::from(progdata)
            .join("Microsoft")
            .join("Windows")
            .join("WER");
        scrub_wer_reports_in(&wer_base);
    }
}

/// Removes per-user `.dmp` files for [`BROWSER_EXE_NAMES`] from a
/// `CrashDumps`-shaped directory (dump names look like
/// `firefox.exe.1234.dmp`). Split from the env-var plumbing so it is
/// testable against a fixture directory.
fn scrub_wer_crash_dumps_in(crash_dumps: &Path) {
    let Ok(entries) = std::fs::read_dir(crash_dumps) else {
        return;
    };
    let mut count: usize = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let n = name.to_string_lossy().to_ascii_lowercase();
        if BROWSER_EXE_NAMES.iter().any(|exe| n.starts_with(exe))
            && std::fs::remove_file(entry.path()).is_ok()
        {
            count += 1;
        }
    }
    if count > 0 {
        tracing::info!(
            count,
            "removed WER crash dumps from %LOCALAPPDATA%\\CrashDumps"
        );
    }
}

/// Removes system-wide report queues for [`BROWSER_EXE_NAMES`] from a
/// `WER`-shaped base directory. Report directories are named like
/// `AppCrash_firefox.exe_<hash>_cab_<guid>`; matching on the browser exe name
/// in the directory name is sufficient to identify and remove the entire
/// subdirectory (which contains WER report XML and mini-dump files that embed
/// the portable path).
fn scrub_wer_reports_in(wer_base: &Path) {
    for subdir in ["ReportQueue", "ReportArchive"] {
        let queue = wer_base.join(subdir);
        let Ok(entries) = std::fs::read_dir(&queue) else {
            continue;
        };
        let mut count: usize = 0;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let n = name.to_string_lossy().to_ascii_lowercase();
            if BROWSER_EXE_NAMES.iter().any(|exe| n.contains(exe))
                && std::fs::remove_dir_all(entry.path()).is_ok()
            {
                count += 1;
            }
        }
        if count > 0 {
            tracing::info!(count, subdir, "removed WER report directories");
        }
    }
}

/// Removes the `installs.ini` registration files that Firefox/Floorp/Waterfox
/// NSIS installers write under `%APPDATA%`. These files embed the portable
/// drive path as a host trace even after a silent `/S` install.
fn scrub_mozilla_installs_ini() {
    let Some(appdata) = std::env::var_os("APPDATA") else {
        return;
    };
    let base = std::path::PathBuf::from(appdata);
    let candidates = [
        base.join("Mozilla").join("Firefox").join("installs.ini"),
        base.join("Floorp").join("installs.ini"),
        base.join("Waterfox").join("installs.ini"),
    ];
    for path in &candidates {
        if path.exists() {
            match std::fs::remove_file(path) {
                Ok(()) => tracing::info!(path = %path.display(), "removed installs.ini"),
                Err(e) => tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "could not remove installs.ini"
                ),
            }
        }
    }
}

/// Brand-name directories that Gecko-based browsers create on the host even
/// when `--profile` points elsewhere. Mozilla's `nsXREDirProvider` (C++)
/// hardcodes `SHGetKnownFolderPath(FOLDERID_LocalAppData)` + brand and
/// `SHGetKnownFolderPath(FOLDERID_ProgramData)` + brand + install-hash; no
/// env var, pref, or CLI flag redirects them (see Mozilla bug 1528082).
///
/// Floorp uses `Floorp` in `LocalAppData` but `Noraneko` (its internal Mozilla
/// codename) for the install-hash dir in `ProgramData`. Waterfox uses `Waterfox`
/// in both. Firefox/Firefox ESR use `Mozilla` in both.
const GECKO_BRAND_DIRS: &[&str] = &[
    "Mozilla",
    "Firefox",
    "Floorp",
    "Noraneko",
    "Waterfox",
    "LibreWolf",
    "librewolf",
];

/// Removes the Gecko-runtime working directories on the host that
/// `firefox.exe` / `floorp.exe` / `waterfox.exe` create regardless of
/// `--profile`. PortableApps.com — the reference portable-Firefox launcher —
/// uses the same model: let Gecko write, scrub on exit. Each removal is
/// retried up to 3 times with a 200 ms back-off because firefox.exe may have
/// spawned detached child processes (e.g. `firefox.exe --backgroundtask`)
/// that briefly hold file handles after the parent exits.
fn scrub_mozilla_runtime_dirs() {
    let local = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from);
    let progdata = std::env::var_os("ProgramData").map(std::path::PathBuf::from);
    scrub_mozilla_runtime_dirs_in(local.as_deref(), progdata.as_deref());
}

fn scrub_mozilla_runtime_dirs_in(
    local: Option<&std::path::Path>,
    progdata: Option<&std::path::Path>,
) {
    // 1. <local>\<brand>\
    if let Some(local) = local {
        for brand in GECKO_BRAND_DIRS {
            let dir = local.join(brand);
            if dir.exists() {
                try_remove_dir_with_retry(&dir);
            }
        }
    }

    // 2. <progdata>\<brand> and <progdata>\<brand>-<HASH>\
    if let Some(progdata) = progdata {
        if let Ok(entries) = std::fs::read_dir(progdata) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let n = name.to_string_lossy();
                let matched = GECKO_BRAND_DIRS.iter().any(|brand| {
                    n.as_ref() == *brand
                        || (n.starts_with(brand) && n.as_bytes().get(brand.len()) == Some(&b'-'))
                });
                if matched {
                    try_remove_dir_with_retry(&entry.path());
                }
            }
        }
    }
}

/// Removes Mullvad Browser's host-side runtime directory
/// `%LOCALAPPDATA%\Mullvad\MullvadBrowser`. Unlike the other Gecko brands,
/// Mullvad nests its runtime dir under a `Mullvad\` parent that a co-installed
/// Mullvad VPN client may also use, so only the `MullvadBrowser` subdir is
/// removed; the parent is deleted only when nothing else remains in it.
fn scrub_mullvad_runtime_dir() {
    let local = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from);
    scrub_mullvad_runtime_dir_in(local.as_deref());
}

fn scrub_mullvad_runtime_dir_in(local: Option<&std::path::Path>) {
    let Some(local) = local else {
        return;
    };
    let parent = local.join("Mullvad");
    let browser_dir = parent.join("MullvadBrowser");
    if browser_dir.exists() {
        try_remove_dir_with_retry(&browser_dir);
    }
    // Remove the parent only when it is now empty — a co-installed Mullvad VPN
    // would leave its own entries here, and those must be preserved.
    if let Ok(mut entries) = std::fs::read_dir(&parent) {
        if entries.next().is_none() {
            let _ = std::fs::remove_dir(&parent);
        }
    }
}

/// Removes the Chromium-family host runtime directories under `%LOCALAPPDATA%`.
///
/// Unlike the Gecko brands, a *Nomad* launch of ungoogled-chromium or Helium
/// writes nothing here — `launch_command` always passes `--user-data-dir`
/// beside the exe, which redirects the whole profile. These directories only
/// appear when the browser executable is launched **outside** Nomad with no
/// such flag, so Chromium falls back to its built-in default location — most
/// commonly a link click that opened the raw `chrome.exe` because it (rather
/// than the Nomad launcher) was registered as the OS default browser. This
/// scrub clears those strays on the next Nomad-launched session so nothing
/// accumulates in `%LOCALAPPDATA%`.
///
/// - ungoogled-chromium → `%LOCALAPPDATA%\Chromium` (unbranded Chromium)
/// - Helium             → `%LOCALAPPDATA%\imput\Helium` (vendor dir `imput\`)
///
/// As with [`scrub_mullvad_runtime_dir`], Helium's vendor parent `imput\` is
/// removed only when it is left empty, so a future `imput` product's data is
/// preserved. Same accepted tradeoff as the Gecko scrub: a separate, non-Nomad
/// Chromium or Helium install would also be cleaned — the portable-first
/// posture treats these brand dirs as Nomad's to scrub.
fn scrub_chromium_runtime_dirs() {
    let local = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from);
    scrub_chromium_runtime_dirs_in(local.as_deref());
}

fn scrub_chromium_runtime_dirs_in(local: Option<&std::path::Path>) {
    let Some(local) = local else {
        return;
    };

    // ungoogled-chromium: unbranded top-level dir.
    let chromium = local.join("Chromium");
    if chromium.exists() {
        try_remove_dir_with_retry(&chromium);
    }

    // Helium: nested under the `imput` vendor dir. Remove the browser subdir,
    // then the vendor parent only if nothing else (a future imput product)
    // remains in it.
    let imput = local.join("imput");
    let helium = imput.join("Helium");
    if helium.exists() {
        try_remove_dir_with_retry(&helium);
    }
    if let Ok(mut entries) = std::fs::read_dir(&imput) {
        if entries.next().is_none() {
            let _ = std::fs::remove_dir(&imput);
        }
    }
}

/// Tolerant tree delete modeled on `LibreWolf` Portable's cleanup strategy:
/// walks `dir` post-order, deletes each **file** individually (a single
/// locked file doesn't abort the rest), then removes each **directory** only
/// if it became empty. Survives "file in use" errors from detached
/// background-task processes still holding handles. Final removal of `dir`
/// itself is attempted last; if any file or subdir is still locked, the
/// remaining structure is left in place rather than partially destroyed.
fn try_remove_dir_with_retry(dir: &std::path::Path) {
    let started_with = dir.exists();
    let mut locked: u32 = 0;
    let mut deleted_files: u32 = 0;
    delete_tree_tolerant(dir, &mut deleted_files, &mut locked);
    if !started_with {
        return;
    }
    if dir.exists() {
        // Top-level dir still present — log enough detail to diagnose.
        tracing::warn!(
            path = %dir.display(),
            deleted_files,
            locked,
            "browser runtime dir partially scrubbed (some entries still locked)"
        );
    } else {
        tracing::info!(
            path = %dir.display(),
            deleted_files,
            "removed browser runtime dir"
        );
    }
}

/// Recursive tolerant delete helper. Returns silently — accumulates counts in
/// the out-params so the caller can log a summary.
fn delete_tree_tolerant(path: &std::path::Path, deleted_files: &mut u32, locked: &mut u32) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() && !meta.file_type().is_symlink() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                delete_tree_tolerant(&entry.path(), deleted_files, locked);
            }
        }
        // After all children processed, try to remove the (hopefully empty) dir.
        if let Err(e) = std::fs::remove_dir(path) {
            // ErrorKind::DirectoryNotEmpty stable since 1.83; fall back to
            // string match for older toolchains we might still support.
            if e.raw_os_error() != Some(145) {
                tracing::debug!(
                    path = %path.display(),
                    error = %e,
                    "could not remove directory"
                );
            }
            *locked += 1;
        }
    } else {
        // Regular file, junction, or symlink — delete as a file.
        match std::fs::remove_file(path) {
            Ok(()) => *deleted_files += 1,
            Err(e) => {
                tracing::debug!(
                    path = %path.display(),
                    error = %e,
                    "could not remove file (locked or in use)"
                );
                *locked += 1;
            }
        }
    }
}

/// Executable name prefixes that identify Nomad-managed browser processes in
/// `C:\Windows\Prefetch\`. Each `.pf` filename has the form `<EXE>-<HASH>.pf`
/// (uppercase); matching on the `<EXE>-` prefix avoids false positives.
const PREFETCH_TOKENS: &[&str] = &[
    "CHROME.EXE-",
    "FIREFOX.EXE-",
    "FLOORP.EXE-",
    "LIBREWOLF.EXE-",
    "MULLVADBROWSER.EXE-",
    "WATERFOX.EXE-",
    "BITWARDEN.EXE-",
    "BITWARDEN-PORTABLE.EXE-",
    "NOMAD-BITWARDEN.EXE-",
    "NOMAD-FIREFOX.EXE-",
    "NOMAD-FIREFOX-ESR.EXE-",
    "NOMAD-FLOORP.EXE-",
    "NOMAD-HELIUM.EXE-",
    "NOMAD-LIBREWOLF.EXE-",
    "NOMAD-MULLVAD.EXE-",
    "NOMAD-UNGOOGLED-CHROMIUM.EXE-",
    "NOMAD-WATERFOX.EXE-",
];

/// Attempts to remove Prefetch entries for all Nomad-managed browser and
/// launcher executables from `C:\Windows\Prefetch\`.
///
/// Returns `true` if the scrub completed without any access-denied errors (or
/// there was nothing to scrub), `false` if at least one deletion was blocked by
/// insufficient privileges — the caller should then invoke
/// `elevate_for_prefetch_scrub()` to retry under an elevated token.
fn scrub_prefetch() -> bool {
    scrub_prefetch_dir(std::path::Path::new(r"C:\Windows\Prefetch"))
}

fn scrub_prefetch_dir(dir: &std::path::Path) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return false,
        Err(_) => return true,
    };
    let mut need_elevation = false;
    let mut count: usize = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let n = name.to_string_lossy().to_ascii_uppercase();
        if PREFETCH_TOKENS.iter().any(|&t| n.starts_with(t)) {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => count += 1,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    need_elevation = true;
                }
                Err(e) => tracing::warn!(
                    path = %entry.path().display(),
                    error = %e,
                    "Prefetch scrub: could not remove entry"
                ),
            }
        }
    }
    if count > 0 {
        tracing::info!(count, "removed Prefetch entries");
    }
    !need_elevation
}

/// Re-spawns this executable with `--nomad-scrub-prefetch` under an elevated
/// token using `ShellExecuteW` with the `"runas"` verb. The UAC consent dialog
/// appears once; on approval the elevated process deletes the Prefetch entries
/// and exits silently.
fn elevate_for_prefetch_scrub() {
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

        fn wide(s: &OsStr) -> Vec<u16> {
            s.encode_wide().chain(std::iter::once(0)).collect()
        }

        let Ok(exe) = std::env::current_exe() else {
            tracing::warn!("elevate_for_prefetch_scrub: could not resolve current exe");
            return;
        };

        let verb = wide(OsStr::new("runas"));
        let file = wide(exe.as_os_str());
        let params = wide(OsStr::new("--nomad-scrub-prefetch"));

        // SAFETY: all three wide string vecs are valid null-terminated UTF-16.
        // ShellExecuteW is a synchronous shell launch with no lifetime concerns.
        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                SW_HIDE,
            );
        }
    }
}

/// Rotates `path` to `path.1` when it reaches 512 KB, keeping one backup.
fn rotate_log(path: &std::path::Path) {
    const MAX_BYTES: u64 = 512 * 1024;
    if std::fs::metadata(path).map_or(0, |m| m.len()) >= MAX_BYTES {
        let backup = {
            let mut p = path.to_owned();
            let mut name = path.file_name().unwrap_or_default().to_owned();
            name.push(".1");
            p.set_file_name(name);
            p
        };
        let _ = std::fs::remove_file(&backup);
        let _ = std::fs::rename(path, backup);
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("NOMAD_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));

    // The launcher is a windowed (no-console) process, so diagnostics are
    // appended to `nomad/nomad.log` beside the executable rather than written
    // to stdout.  If the log file cannot be opened, fall back to stdout.
    let log_file = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(config::nomad_subdir))
        .and_then(|nomad_dir| {
            // init_tracing runs before Config::load_or_init, so the nomad/
            // directory may not exist yet on first run — create it here.
            std::fs::create_dir_all(&nomad_dir).ok()?;
            Some(nomad_dir.join("nomad.log"))
        })
        .and_then(|path| {
            rotate_log(&path);
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
        });

    if let Some(file) = log_file {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_explorer_path_is_absolute_not_a_bare_name() {
        // Must be an absolute path so CreateProcess cannot resolve a planted
        // explorer.exe from the launcher dir or CWD (F-03 / CWE-426).
        let p = system_explorer_path();
        assert!(
            p.is_absolute(),
            "explorer path must be absolute, got {}",
            p.display()
        );
        assert!(
            p.file_name()
                .is_some_and(|n| n.eq_ignore_ascii_case("explorer.exe")),
            "must resolve to explorer.exe, got {}",
            p.display()
        );
    }

    #[test]
    fn build_launch_args_appends_reduced_system_info_when_enabled_on_chromium() {
        use crate::browsers::ungoogled::UngoogledChromium;
        use crate::config::{Arch, Config};

        let browser = UngoogledChromium::new(Arch::X64);
        let mut config = Config::parse("[browser]\ninstall_dir = \"Browser\"\n").unwrap();

        // Disabled: the feature bundle exists but carries no ReducedSystemInfo.
        config.hardening.reduce_system_info = false;
        let args = build_launch_args(&browser, &config);
        let bundles: Vec<_> = args
            .iter()
            .filter(|a| a.starts_with("--enable-features="))
            .collect();
        assert_eq!(bundles.len(), 1, "exactly one --enable-features bundle");
        assert!(
            !bundles[0].contains("ReducedSystemInfo"),
            "ReducedSystemInfo must be off by default"
        );
        assert!(
            bundles[0].contains("RemoveClientHints"),
            "baseline features must be present"
        );

        // Opt-in: ReducedSystemInfo is merged into the SAME single bundle,
        // never a second --enable-features (which Chromium would let win alone).
        config.hardening.reduce_system_info = true;
        let args = build_launch_args(&browser, &config);
        let bundles: Vec<_> = args
            .iter()
            .filter(|a| a.starts_with("--enable-features="))
            .collect();
        assert_eq!(
            bundles.len(),
            1,
            "must remain a single --enable-features bundle"
        );
        assert!(
            bundles[0].contains("ReducedSystemInfo"),
            "ReducedSystemInfo must be appended when opted in"
        );
        assert!(
            bundles[0].contains("RemoveClientHints"),
            "existing features must be preserved when merging"
        );
    }

    #[test]
    fn build_launch_args_skips_reduced_system_info_for_browsers_with_builtin_noise() {
        use crate::browsers::helium::Helium;
        use crate::config::{Arch, Config};

        let helium = Helium::new(Arch::X64);
        let mut config = Config::parse("[browser]\ninstall_dir = \"Browser\"\n").unwrap();
        // Even with the feature explicitly opted in, Helium must NOT receive it —
        // its own Helium Noise randomises hardwareConcurrency.
        config.hardening.reduce_system_info = true;
        let args = build_launch_args(&helium, &config);
        let bundle = args
            .iter()
            .find(|a| a.starts_with("--enable-features="))
            .expect("bundle present");
        assert!(
            !bundle.contains("ReducedSystemInfo"),
            "ReducedSystemInfo must not be layered onto a browser with built-in fingerprint noise"
        );
    }

    /// Constructs a minimal LNK binary whose `LocalBasePath` is `target`.
    ///
    /// Layout:
    ///   - 76-byte `ShellLinkHeader` (`LinkFlags` = `HasLinkInfo` only)
    ///   - `LinkInfo` with compact header (0x1C), minimal `VolumeIDInfo`, ANSI path
    fn make_lnk(target: &str) -> Vec<u8> {
        let path_bytes: Vec<u8> = target.bytes().chain(std::iter::once(0u8)).collect();
        // VolumeIDInfo: size(4) + DriveType(4) + Serial(4) + LabelOffset(4) + NullLabel(1)
        let vol_id_size: u32 = 17;
        // LinkInfo header (28 bytes) + VolumeIDInfo (17 bytes) + path + suffix null
        let suffix_offset = 28u32 + vol_id_size + u32::try_from(path_bytes.len()).unwrap();
        let li_size = suffix_offset + 1; // +1 for the CommonPathSuffix null byte

        let mut buf = Vec::with_capacity(76 + li_size as usize);

        // ── ShellLinkHeader (76 bytes) ────────────────────────────────────────
        buf.extend_from_slice(&[0x4C, 0x00, 0x00, 0x00]); // magic
                                                          // CLSID
        buf.extend_from_slice(&[
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ]);
        buf.extend_from_slice(&0x02u32.to_le_bytes()); // LinkFlags = HasLinkInfo
        buf.extend_from_slice(&[0u8; 52]); // remainder of 76-byte header

        // ── LinkInfo ──────────────────────────────────────────────────────────
        let local_base_path_offset: u32 = 28 + vol_id_size; // after header + VolumeIDInfo
        buf.extend_from_slice(&li_size.to_le_bytes()); // LinkInfoSize
        buf.extend_from_slice(&0x1Cu32.to_le_bytes()); // LinkInfoHeaderSize = 28
        buf.extend_from_slice(&0x01u32.to_le_bytes()); // LinkInfoFlags = VolumeIDAndLocalBasePath
        buf.extend_from_slice(&0x1Cu32.to_le_bytes()); // VolumeIDOffset = 28
        buf.extend_from_slice(&local_base_path_offset.to_le_bytes()); // LocalBasePathOffset
        buf.extend_from_slice(&0x00u32.to_le_bytes()); // CommonNetworkRelativeLinkOffset = 0
        buf.extend_from_slice(&suffix_offset.to_le_bytes()); // CommonPathSuffixOffset

        // VolumeIDInfo (17 bytes)
        buf.extend_from_slice(&vol_id_size.to_le_bytes()); // VolumeIDSize = 17
        buf.extend_from_slice(&0x03u32.to_le_bytes()); // DriveType = DRIVE_FIXED
        buf.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // DriveSerialNumber
        buf.extend_from_slice(&0x10u32.to_le_bytes()); // VolumeLabelOffset = 16
        buf.push(0x00); // empty label

        // LocalBasePath (null-terminated ANSI)
        buf.extend_from_slice(&path_bytes);

        // CommonPathSuffix (empty)
        buf.push(0x00);

        buf
    }

    #[test]
    fn lnk_target_path_parses_ansi_local_base_path() {
        let data = make_lnk("E:\\downloads\\file.zip");
        let target = lnk_target_path(&data).expect("must parse");
        assert_eq!(target, std::path::PathBuf::from("E:\\downloads\\file.zip"));
    }

    #[test]
    fn lnk_target_path_rejects_wrong_magic() {
        let mut data = make_lnk("E:\\file.zip");
        data[0] = 0xFF; // corrupt magic
        assert!(lnk_target_path(&data).is_none());
    }

    #[test]
    fn lnk_target_path_rejects_too_short() {
        assert!(lnk_target_path(&[0u8; 10]).is_none());
    }

    #[test]
    fn lnk_target_path_returns_none_when_no_link_info_flag() {
        let mut data = make_lnk("E:\\file.zip");
        // Clear bit 1 (HasLinkInfo) in LinkFlags at offset 20.
        let flags = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let new_flags = flags & !0x02u32;
        data[20..24].copy_from_slice(&new_flags.to_le_bytes());
        assert!(lnk_target_path(&data).is_none());
    }

    #[test]
    fn lnk_skips_id_list_when_present() {
        // Build a LNK with HasLinkTargetIDList + HasLinkInfo.
        let inner = make_lnk("E:\\with_idlist.exe");
        // The inner already has a correct LinkInfo.  Prepend a 4-byte IDList.
        let idlist_payload = [0xAB, 0xCD]; // 2 bytes of fake IDList data
        let mut data = Vec::new();
        // Copy header with updated flags.
        data.extend_from_slice(&inner[..76]);
        let flags = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let new_flags = flags | 0x01u32; // set HasLinkTargetIDList
        data[20..24].copy_from_slice(&new_flags.to_le_bytes());
        // Insert 2-byte size prefix + 2 payload bytes before the LinkInfo.
        data.extend_from_slice(&u16::try_from(idlist_payload.len()).unwrap().to_le_bytes());
        data.extend_from_slice(&idlist_payload);
        // Append the LinkInfo from the original binary.
        data.extend_from_slice(&inner[76..]);

        let target = lnk_target_path(&data).expect("must parse despite IDList");
        assert_eq!(target, std::path::PathBuf::from("E:\\with_idlist.exe"));
    }

    #[test]
    fn scrub_prefetch_dir_removes_matching_pf_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("FIREFOX.EXE-12345678.pf"), b"pf").unwrap();
        std::fs::write(dir.path().join("CHROME.EXE-ABCDEF01.pf"), b"pf").unwrap();
        std::fs::write(dir.path().join("NOMAD-WATERFOX.EXE-11223344.pf"), b"pf").unwrap();
        std::fs::write(dir.path().join("NOTEPAD.EXE-99999999.pf"), b"pf").unwrap();

        let ok = scrub_prefetch_dir(dir.path());
        assert!(
            ok,
            "scrub must not report needing elevation on writable dir"
        );
        assert!(!dir.path().join("FIREFOX.EXE-12345678.pf").exists());
        assert!(!dir.path().join("CHROME.EXE-ABCDEF01.pf").exists());
        assert!(!dir.path().join("NOMAD-WATERFOX.EXE-11223344.pf").exists());
        assert!(
            dir.path().join("NOTEPAD.EXE-99999999.pf").exists(),
            "non-browser .pf must be preserved"
        );
    }

    #[test]
    fn scrub_prefetch_dir_returns_true_for_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let ok = scrub_prefetch_dir(&dir.path().join("nonexistent"));
        assert!(ok, "missing directory is not a permission error");
    }

    #[test]
    fn is_browser_temp_name_matches_known_patterns_only() {
        for name in [
            "scoped_dir12345",
            ".org.chromium.Chromium.aBcDeF",
            "chrome_BITS_1234",
            "mozilla-temp-987",
            ".moz_extension-cache",
        ] {
            assert!(
                is_browser_temp_name(std::ffi::OsStr::new(name)),
                "{name} must match"
            );
        }
        for name in [
            "report.docx",
            "scoped",
            "my_chrome_notes",
            "Mozilla Firefox",
        ] {
            assert!(
                !is_browser_temp_name(std::ffi::OsStr::new(name)),
                "{name} must NOT match"
            );
        }
    }

    #[test]
    fn scrub_temp_in_removes_browser_entries_and_spares_bystanders() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("scoped_dir9999")).unwrap();
        std::fs::write(dir.path().join("scoped_dir9999").join("f"), b"x").unwrap();
        std::fs::write(dir.path().join("mozilla-temp-7"), b"x").unwrap();
        std::fs::write(dir.path().join("unrelated.tmp"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("SomeAppDir")).unwrap();

        scrub_temp_in(dir.path());

        assert!(!dir.path().join("scoped_dir9999").exists());
        assert!(!dir.path().join("mozilla-temp-7").exists());
        assert!(dir.path().join("unrelated.tmp").exists());
        assert!(dir.path().join("SomeAppDir").exists());

        // A missing directory must be a quiet no-op, not a panic.
        scrub_temp_in(Path::new("definitely/not/here"));
    }

    #[test]
    fn scrub_wer_crash_dumps_in_removes_browser_dumps_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("firefox.exe.1234.dmp"), b"d").unwrap();
        // Case-folded match for the Bitwarden portable binary added with the
        // nomad-bitwarden launcher.
        std::fs::write(dir.path().join("Bitwarden-Portable.exe.77.dmp"), b"d").unwrap();
        std::fs::write(dir.path().join("notepad.exe.1.dmp"), b"d").unwrap();

        scrub_wer_crash_dumps_in(dir.path());

        assert!(!dir.path().join("firefox.exe.1234.dmp").exists());
        assert!(!dir.path().join("Bitwarden-Portable.exe.77.dmp").exists());
        assert!(
            dir.path().join("notepad.exe.1.dmp").exists(),
            "non-browser dumps must survive"
        );
        scrub_wer_crash_dumps_in(Path::new("definitely/not/here"));
    }

    #[test]
    fn scrub_wer_reports_in_removes_browser_report_dirs_only() {
        let dir = tempfile::tempdir().unwrap();
        for sub in ["ReportQueue", "ReportArchive"] {
            let queue = dir.path().join(sub);
            std::fs::create_dir_all(queue.join("AppCrash_bitwarden.exe_ab12_cab_cd34")).unwrap();
            std::fs::create_dir_all(queue.join("AppCrash_waterfox.exe_ef56_cab_gh78")).unwrap();
            std::fs::create_dir_all(queue.join("AppCrash_calc.exe_zz99")).unwrap();
        }

        scrub_wer_reports_in(dir.path());

        for sub in ["ReportQueue", "ReportArchive"] {
            let queue = dir.path().join(sub);
            assert!(!queue.join("AppCrash_bitwarden.exe_ab12_cab_cd34").exists());
            assert!(!queue.join("AppCrash_waterfox.exe_ef56_cab_gh78").exists());
            assert!(
                queue.join("AppCrash_calc.exe_zz99").exists(),
                "non-browser reports must survive in {sub}"
            );
        }
        scrub_wer_reports_in(Path::new("definitely/not/here"));
    }

    #[test]
    fn scrub_shell_recent_in_removes_links_targeting_the_portable_drive() {
        let dir = tempfile::tempdir().unwrap();
        let recent = dir.path();
        std::fs::write(recent.join("portable.lnk"), make_lnk(r"E:\Nomad\doc.pdf")).unwrap();
        std::fs::write(recent.join("local.lnk"), make_lnk(r"C:\Users\x\doc.pdf")).unwrap();
        std::fs::write(recent.join("not-a-link.txt"), b"plain").unwrap();
        std::fs::write(recent.join("garbage.lnk"), b"not a shell link").unwrap();

        scrub_shell_recent_in(recent, Path::new(r"E:\"));

        assert!(
            !recent.join("portable.lnk").exists(),
            "links to the portable drive must be removed"
        );
        assert!(
            recent.join("local.lnk").exists(),
            "links to other drives must survive"
        );
        assert!(recent.join("not-a-link.txt").exists());
        assert!(
            recent.join("garbage.lnk").exists(),
            "unparseable .lnk files are conservatively left alone"
        );
        scrub_shell_recent_in(Path::new("definitely/not/here"), Path::new(r"E:\"));
    }

    #[test]
    fn scrub_prefetch_dir_matches_all_nomad_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let cases = [
            "CHROME.EXE-00000001.pf",
            "FIREFOX.EXE-00000002.pf",
            "FLOORP.EXE-00000003.pf",
            "WATERFOX.EXE-00000004.pf",
            "MULLVADBROWSER.EXE-0000000B.pf",
            "NOMAD-FIREFOX.EXE-00000005.pf",
            "NOMAD-FIREFOX-ESR.EXE-00000006.pf",
            "NOMAD-FLOORP.EXE-00000007.pf",
            "NOMAD-WATERFOX.EXE-00000008.pf",
            "NOMAD-HELIUM.EXE-00000009.pf",
            "NOMAD-UNGOOGLED-CHROMIUM.EXE-0000000A.pf",
            "NOMAD-MULLVAD.EXE-0000000C.pf",
            "NOMAD-BITWARDEN.EXE-0000000D.pf",
            "BITWARDEN-PORTABLE.EXE-0000000E.pf",
            "BITWARDEN.EXE-0000000F.pf",
        ];
        for name in &cases {
            std::fs::write(dir.path().join(name), b"pf").unwrap();
        }
        scrub_prefetch_dir(dir.path());
        for name in &cases {
            assert!(
                !dir.path().join(name).exists(),
                "{name} must have been deleted"
            );
        }
    }

    #[test]
    fn scrub_mozilla_runtime_dirs_handles_all_brand_variants() {
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path().join("local");
        let progdata = temp.path().join("progdata");

        // LOCALAPPDATA brand dirs — each Gecko fork uses its own brand name.
        let local_brands = ["Mozilla", "Floorp", "Waterfox"];
        for brand in &local_brands {
            std::fs::create_dir_all(local.join(brand).join("subdir")).unwrap();
            std::fs::write(local.join(brand).join("subdir").join("f"), b"x").unwrap();
        }
        // A bystander dir in LOCALAPPDATA that must NOT be touched.
        std::fs::create_dir_all(local.join("Microsoft")).unwrap();

        // PROGRAMDATA dirs — brand alone, brand-<GUID>, and Floorp's Noraneko
        // codename for the install-hash dir.
        let pd_cases = [
            "Mozilla",
            "Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38",
            "Waterfox-1de4eec8-1241-4177-a864-e594e8d1fb38",
            "Noraneko-1de4eec8-1241-4177-a864-e594e8d1fb38",
        ];
        for name in &pd_cases {
            std::fs::create_dir_all(progdata.join(name)).unwrap();
            std::fs::write(progdata.join(name).join("f"), b"x").unwrap();
        }
        // A bystander dir in PROGRAMDATA that must NOT be touched.
        std::fs::create_dir_all(progdata.join("Microsoft")).unwrap();
        // A name that starts with a brand string but has no '-' separator
        // (e.g. "MozillaSomething") must NOT be removed.
        std::fs::create_dir_all(progdata.join("MozillaSomething")).unwrap();

        scrub_mozilla_runtime_dirs_in(Some(&local), Some(&progdata));

        for brand in &local_brands {
            assert!(
                !local.join(brand).exists(),
                "LOCALAPPDATA\\{brand} must be removed"
            );
        }
        assert!(
            local.join("Microsoft").exists(),
            "bystander LOCALAPPDATA dir must be preserved"
        );

        for name in &pd_cases {
            assert!(
                !progdata.join(name).exists(),
                "PROGRAMDATA\\{name} must be removed"
            );
        }
        assert!(
            progdata.join("Microsoft").exists(),
            "bystander PROGRAMDATA dir must be preserved"
        );
        assert!(
            progdata.join("MozillaSomething").exists(),
            "name without '-' separator must NOT be matched"
        );
    }

    #[test]
    fn scrub_mullvad_runtime_dir_removes_browser_subdir_but_preserves_vpn_data() {
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path();
        let browser = local.join("Mullvad").join("MullvadBrowser");
        std::fs::create_dir_all(browser.join("crashes")).unwrap();
        std::fs::write(browser.join("crashes").join("x"), b"trace").unwrap();
        // Simulate a co-installed Mullvad VPN leaving its own data under Mullvad\.
        let vpn = local.join("Mullvad").join("MullvadVPN");
        std::fs::create_dir_all(&vpn).unwrap();
        std::fs::write(vpn.join("settings.json"), b"{}").unwrap();

        scrub_mullvad_runtime_dir_in(Some(local));

        assert!(
            !browser.exists(),
            "MullvadBrowser runtime dir must be removed"
        );
        assert!(
            vpn.join("settings.json").exists(),
            "co-installed Mullvad VPN data must be preserved"
        );
        assert!(
            local.join("Mullvad").exists(),
            "parent must be kept while other Mullvad data remains"
        );
    }

    #[test]
    fn scrub_mullvad_runtime_dir_removes_now_empty_parent() {
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path();
        std::fs::create_dir_all(local.join("Mullvad").join("MullvadBrowser")).unwrap();

        scrub_mullvad_runtime_dir_in(Some(local));

        assert!(
            !local.join("Mullvad").exists(),
            "empty Mullvad parent must be removed when only the browser dir existed"
        );
    }

    #[test]
    fn scrub_mullvad_runtime_dir_handles_missing_base_dir() {
        scrub_mullvad_runtime_dir_in(None);
        let temp = tempfile::tempdir().unwrap();
        // No Mullvad dir present — must not panic or create anything.
        scrub_mullvad_runtime_dir_in(Some(temp.path()));
        assert!(!temp.path().join("Mullvad").exists());
    }

    #[test]
    fn scrub_mozilla_runtime_dirs_handles_missing_base_dirs() {
        scrub_mozilla_runtime_dirs_in(None, None);

        let temp = tempfile::tempdir().unwrap();
        let nonexistent = temp.path().join("does-not-exist");
        scrub_mozilla_runtime_dirs_in(Some(&nonexistent), Some(&nonexistent));
    }

    #[test]
    fn scrub_chromium_runtime_dirs_removes_chromium_and_helium() {
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path();

        // ungoogled-chromium's unbranded default profile.
        let chromium = local.join("Chromium").join("User Data").join("Default");
        std::fs::create_dir_all(&chromium).unwrap();
        std::fs::write(chromium.join("Preferences"), b"{}").unwrap();

        // Helium's profile under the imput vendor dir.
        let helium = local.join("imput").join("Helium").join("User Data");
        std::fs::create_dir_all(&helium).unwrap();
        std::fs::write(helium.join("Local State"), b"{}").unwrap();

        // A future imput product sharing the vendor parent — must be preserved.
        let other = local.join("imput").join("SomethingElse");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("data"), b"keep").unwrap();

        // A bystander dir that must NOT be touched.
        std::fs::create_dir_all(local.join("Microsoft")).unwrap();

        scrub_chromium_runtime_dirs_in(Some(local));

        assert!(
            !local.join("Chromium").exists(),
            "LOCALAPPDATA\\Chromium must be removed"
        );
        assert!(
            !local.join("imput").join("Helium").exists(),
            "LOCALAPPDATA\\imput\\Helium must be removed"
        );
        assert!(
            other.join("data").exists(),
            "other imput product data must be preserved"
        );
        assert!(
            local.join("imput").exists(),
            "imput vendor parent must be kept while other product data remains"
        );
        assert!(
            local.join("Microsoft").exists(),
            "bystander LOCALAPPDATA dir must be preserved"
        );
    }

    #[test]
    fn scrub_chromium_runtime_dirs_removes_now_empty_imput_parent() {
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path();
        std::fs::create_dir_all(local.join("imput").join("Helium").join("User Data")).unwrap();

        scrub_chromium_runtime_dirs_in(Some(local));

        assert!(
            !local.join("imput").exists(),
            "empty imput parent must be removed when only Helium existed"
        );
    }

    #[test]
    fn scrub_chromium_runtime_dirs_handles_missing_base_dir() {
        // None base dir — must not panic.
        scrub_chromium_runtime_dirs_in(None);
        // Present base dir with no Chromium/imput entries — must not panic or create anything.
        let temp = tempfile::tempdir().unwrap();
        scrub_chromium_runtime_dirs_in(Some(temp.path()));
        assert!(!temp.path().join("Chromium").exists());
        assert!(!temp.path().join("imput").exists());
    }

    #[test]
    fn scrub_automatic_destinations_dir_removes_matching_files() {
        let dir = tempfile::tempdir().unwrap();
        let drive = std::path::Path::new("E:\\");

        // Encode "E:\" as UTF-16LE — the sequence that appears inside OLE streams.
        let needle: Vec<u8> = "E:\\".encode_utf16().flat_map(u16::to_le_bytes).collect();

        // File whose content references the portable drive — must be deleted.
        let matching = dir.path().join("abc123.automaticDestinations-ms");
        let mut data = b"\xD0\xCF\x11\xE0".to_vec(); // OLE magic header
        data.extend_from_slice(&vec![0u8; 508]); // padding
        data.extend_from_slice(&needle);
        std::fs::write(&matching, &data).unwrap();

        // File that does not reference the drive — must survive.
        let no_match = dir.path().join("def456.automaticDestinations-ms");
        std::fs::write(&no_match, b"unrelated content without needle").unwrap();

        // Wrong extension — must not be touched even if content matches.
        let wrong_ext = dir.path().join("abc.txt");
        std::fs::write(&wrong_ext, &data).unwrap();

        scrub_automatic_destinations_dir(dir.path(), drive);

        assert!(!matching.exists(), "matching file must be deleted");
        assert!(no_match.exists(), "non-matching file must survive");
        assert!(
            wrong_ext.exists(),
            "wrong-extension file must not be touched"
        );
    }

    #[test]
    fn scrub_automatic_destinations_dir_ignores_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        // Must not panic when the directory does not exist.
        scrub_automatic_destinations_dir(
            &dir.path().join("nonexistent"),
            std::path::Path::new("E:\\"),
        );
    }

    #[test]
    fn delete_tree_tolerant_removes_full_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Mozilla-deadbeef");
        let nested = root.join("Firefox").join("updates").join("hash");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("UpdateLock-1"), b"x").unwrap();
        std::fs::write(root.join("Firefox").join("profile_count.json"), b"{}").unwrap();
        std::fs::write(root.join("readme.txt"), b"r").unwrap();

        let mut deleted = 0;
        let mut locked = 0;
        delete_tree_tolerant(&root, &mut deleted, &mut locked);

        assert!(!root.exists(), "tolerant delete must fully remove the tree");
        assert_eq!(locked, 0, "no entries should be locked in a tempdir");
        assert_eq!(deleted, 3, "three files were created and must be counted");
    }

    #[test]
    fn delete_tree_tolerant_no_panic_on_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut deleted = 0;
        let mut locked = 0;
        delete_tree_tolerant(
            &dir.path().join("does-not-exist"),
            &mut deleted,
            &mut locked,
        );
        assert_eq!(deleted, 0);
        assert_eq!(locked, 0);
    }

    #[test]
    fn split_forwarded_args_separates_the_registered_url_tail() {
        // Regression: the open command registered by --register-default is
        // `"<exe>" -- "%1"`, but the launcher used to ignore everything after
        // the `--`, so clicked links opened the browser without navigating.
        let args = vec![
            "nomad-firefox.exe".to_owned(),
            "--".to_owned(),
            "https://example.com/page".to_owned(),
        ];
        let (own, forwarded) = split_forwarded_args(&args);
        assert_eq!(own, &args[..1]);
        assert_eq!(forwarded, &["https://example.com/page".to_owned()][..]);

        // No separator: everything is Nomad's own, nothing is forwarded.
        let plain = vec![
            "nomad-firefox.exe".to_owned(),
            "--register-default".to_owned(),
        ];
        let (own, forwarded) = split_forwarded_args(&plain);
        assert_eq!(own, &plain[..]);
        assert!(forwarded.is_empty());

        // Nomad flags are only honoured before the separator; after it they
        // are browser arguments, not ours.
        let tricky = vec![
            "nomad-firefox.exe".to_owned(),
            "--".to_owned(),
            "--register-default".to_owned(),
        ];
        let (own, forwarded) = split_forwarded_args(&tricky);
        assert!(!own.iter().any(|a| a == "--register-default"));
        assert_eq!(forwarded, &["--register-default".to_owned()][..]);
    }

    #[test]
    fn parse_cleanup_pid_extracts_pid_and_optional_exe() {
        let with_exe = vec![
            "nomad-firefox.exe".to_owned(),
            "--nomad-cleanup-pid".to_owned(),
            "1234".to_owned(),
            "--nomad-cleanup-exe".to_owned(),
            "firefox.exe".to_owned(),
        ];
        assert_eq!(
            parse_cleanup_pid(&with_exe),
            Some(CleanupArgs {
                browser_pid: 1234,
                browser_exe: Some("firefox.exe".to_owned()),
                scrub_thumbnail_cache: false,
                scrub_prefetch: false,
            })
        );

        let pid_only = vec![
            "nomad-firefox.exe".to_owned(),
            "--nomad-cleanup-pid".to_owned(),
            "9999".to_owned(),
        ];
        assert_eq!(
            parse_cleanup_pid(&pid_only),
            Some(CleanupArgs {
                browser_pid: 9999,
                browser_exe: None,
                scrub_thumbnail_cache: false,
                scrub_prefetch: false,
            })
        );

        let unrelated = vec!["nomad-firefox.exe".to_owned()];
        assert_eq!(parse_cleanup_pid(&unrelated), None);

        let bad_pid = vec![
            "nomad-firefox.exe".to_owned(),
            "--nomad-cleanup-pid".to_owned(),
            "notanumber".to_owned(),
        ];
        assert_eq!(parse_cleanup_pid(&bad_pid), None);
    }

    #[test]
    fn parse_cleanup_pid_sets_scrub_thumbnail_cache_flag() {
        let args = vec![
            "nomad-firefox.exe".to_owned(),
            "--nomad-cleanup-pid".to_owned(),
            "42".to_owned(),
            "--nomad-cleanup-exe".to_owned(),
            "firefox.exe".to_owned(),
            "--nomad-scrub-thumbcache".to_owned(),
        ];
        let result = parse_cleanup_pid(&args).expect("must parse");
        assert!(result.scrub_thumbnail_cache);
        assert!(!result.scrub_prefetch);
        assert_eq!(result.browser_pid, 42);
        assert_eq!(result.browser_exe.as_deref(), Some("firefox.exe"));
    }

    #[test]
    fn parse_cleanup_pid_sets_scrub_prefetch_flag() {
        let args = vec![
            "nomad-firefox.exe".to_owned(),
            "--nomad-cleanup-pid".to_owned(),
            "55".to_owned(),
            "--nomad-cleanup-exe".to_owned(),
            "firefox.exe".to_owned(),
            "--nomad-scrub-prefetch".to_owned(),
        ];
        let result = parse_cleanup_pid(&args).expect("must parse");
        assert!(result.scrub_prefetch);
        assert!(!result.scrub_thumbnail_cache);
        assert_eq!(result.browser_pid, 55);
    }

    #[test]
    fn count_processes_named_self_is_at_least_one() {
        // Best-effort cross-platform test: the current process is named
        // something predictable on Windows test runners but varies elsewhere.
        // Pass a sentinel that definitely shouldn't be running, and verify 0.
        let count = count_processes_named("nomad-zzzz-not-a-real-process.exe");
        assert_eq!(count, 0, "non-existent process must report 0");
    }
}
