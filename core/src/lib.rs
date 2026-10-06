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
mod cleanup;
pub mod config;
pub mod downloader;
mod extensions;
pub mod extract;
pub mod gpg;
pub mod hardening;
pub mod install;
mod instance;
pub mod registry;
mod selfreg_watch;
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

    let args: Vec<String> = std::env::args().collect();
    // Reject malformed protocol arguments before logging creates state or
    // internal registration/cleanup handlers can run.
    let (own_args, forwarded_args) = match split_forwarded_args(&args) {
        Ok(parts) => parts,
        Err(error) => {
            show_msgbox(&format!("Launch failed: {error}"), true);
            return ExitCode::FAILURE;
        }
    };
    init_tracing();
    if own_args.iter().any(|a| a == "--register-default") {
        return handle_register_flag(make);
    }
    if own_args.iter().any(|a| a == "--unregister-default") {
        return handle_unregister_flag(make);
    }
    if let Some(cleanup) = parse_cleanup_pid(own_args) {
        return handle_cleanup_flag(make, cleanup);
    }
    if own_args.iter().any(|a| a == "--nomad-scrub-prefetch") {
        return handle_prefetch_scrub_flag();
    }

    // Panics bypass the Result-based error arm below and would otherwise die
    // on the invisible stderr (e.g. deep inside the GL window stack when a VM
    // exposes no usable pixel format). Log and surface them like any other
    // launch failure. Installed after the flag dispatch above so the detached
    // cleanup watcher never pops a dialog on the user's desktop.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "launcher panicked");
        show_msgbox(
            &format!("Nomad Launcher crashed:\n\n{info}\n\nDetails: Nomad\\nomad.log beside this launcher."),
            true,
        );
        default_hook(info);
    }));

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
    let Some(base) = exe_path.parent() else {
        show_msgbox(
            "Registration failed: could not locate the launcher directory",
            true,
        );
        return ExitCode::FAILURE;
    };
    if let Err(error) = instance::ensure(base, browser.id(), true) {
        show_msgbox(&format!("Registration failed: {error}"), true);
        return ExitCode::FAILURE;
    }
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
fn handle_unregister_flag<B, F>(make: F) -> ExitCode
where
    B: BrowserFamily + 'static,
    F: FnOnce(Arch) -> B,
{
    let browser = make(Arch::X64);
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            show_msgbox(&format!("Unregistration failed: {e}"), true);
            return ExitCode::FAILURE;
        }
    };
    let Some(base) = exe_path.parent() else {
        show_msgbox(
            "Unregistration failed: could not locate the launcher directory",
            true,
        );
        return ExitCode::FAILURE;
    };
    if let Err(error) = instance::ensure(base, browser.id(), false) {
        show_msgbox(&format!("Unregistration failed: {error}"), true);
        return ExitCode::FAILURE;
    }
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
    /// Full path of the launched browser executable, used to match the
    /// portable browser's processes by image path. A bare file name is
    /// accepted and falls back to name-only matching (bounded wait).
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
    // Defense in depth for callers of the launch pipeline: validate before
    // resolving config, recording ownership, or constructing the browser.
    if !forwarded_args.is_empty() {
        validate_forwarded_args(&forwarded_args)?;
    }
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
    let protocol_invocation = !forwarded_args.is_empty();
    let browser = make(arch);
    instance::ensure(base, browser.id(), !protocol_invocation)?;
    let config = Config::load_or_init(base, browser.default_config())?;
    let browser = Arc::new(browser);
    // Config deserialization requires one safe, non-reserved folder name.
    // It cannot escape base, replace Data/Nomad, or move sibling state into a
    // nested directory that the browser-family layout does not support.
    let install_dir = base.join(&config.browser.install_dir);
    if protocol_invocation && browser.installed_version(&install_dir).is_none() {
        return Err(BrowserError::ProtocolInvocation(format!(
            "{} is not installed in this portable folder; run the launcher directly once before opening links through it",
            browser.display_name()
        ))
        .into());
    }
    if protocol_invocation {
        tracing::info!(
            browser = browser.id(),
            "protocol invocation: launching existing install without update or provisioning"
        );
    }
    let opts = effective_update_options(
        config.update.check_on_launch,
        config.update.auto_download,
        protocol_invocation,
    );
    let mut launch_args = build_launch_args(&*browser, &config);
    // The validated single URL/file target goes last as a positional
    // argument, unchanged from the registered "%1" invocation.
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

/// Derives update permissions for a launch origin. The OS protocol handler is
/// deliberately launch-only: a clicked link must never become an implicit
/// software installation or update trigger.
fn effective_update_options(
    check_on_launch: bool,
    auto_download: bool,
    protocol_invocation: bool,
) -> UpdateOptions {
    UpdateOptions {
        check_on_launch: check_on_launch && !protocol_invocation,
        auto_download: auto_download && !protocol_invocation,
    }
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

        // Serialize the whole attempt, including prompts, fallback writes,
        // launch preparation and spawn. A lock failure cannot offer fallback:
        // that would let the losing process mutate an active transaction.
        let instance_lock = match install::InstanceLock::acquire(install_dir) {
            Ok(lock) => lock,
            Err(e) => {
                tracing::error!(error = %e, "portable folder is unavailable for launch");
                show_error(state, ctx, &e.to_string(), false);
                match wait_for_pipeline_action(state) {
                    PipelineAction::Retry => continue 'retry,
                    PipelineAction::Close | PipelineAction::LaunchAnyway => break 'retry,
                }
            }
        };

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
        let check = rt.block_on(update_check_phase(
            b,
            install_dir,
            opts,
            state,
            ctx,
            &instance_lock,
        ));

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
            &instance_lock,
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
    instance_lock: &install::InstanceLock,
) -> Result<CheckPhaseResult, BrowserError> {
    if !opts.check_on_launch {
        tracing::info!(browser = browser.id(), "update check skipped by config");
        return Ok(CheckPhaseResult::Launch);
    }

    install::recover_staging_locked(install_dir, instance_lock)?;

    // ── Version cache ────────────────────────────────────────────────────────
    let launcher_dir = install_dir.parent().unwrap_or(install_dir);
    let cache_path = config::nomad_subdir(launcher_dir).join("nomad-version-cache.toml");
    if let Some(cached) = version_cache::VersionCache::load(&cache_path) {
        // Never reuse a cache entry that was created when an upstream hash
        // endpoint was temporarily missing or used an unrecognised format.
        // Such an entry would otherwise suppress the corrected parser until
        // the six-hour TTL expires and make a verified update appear
        // permanently unverifiable after a launcher upgrade.
        if cached.is_fresh() && cached.is_url_plausible() && cached.has_integrity_material() {
            let latest = cached.into_version_info();
            browser.validate_update(&latest)?;
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
            browser.validate_update(&info)?;
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
    instance_lock: &install::InstanceLock,
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
        branding,
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
        instance_lock,
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
    } else {
        remove_gecko_hardening(browser, install_dir);
    }
    prepare_browser_for_launch(browser, install_dir, hardening)?;
    // Shared host profiles and registration maps are never pre-launch cleanup
    // targets. Attributed post-exit cleanup runs in handle_cleanup_flag().
    let mut cmd = browser.launch_command(install_dir, extra_args);
    let browser_exe = browser_exe_path(&cmd);
    let child = cmd.spawn()?;
    let pid = child.id();
    tracing::info!(browser = browser.id(), pid, exe = %browser_exe, "browser launched");
    spawn_cleanup_watcher(
        pid,
        &browser_exe,
        hardening.scrub_thumbnail_cache,
        hardening.scrub_prefetch,
    );
    signal_done(state, ctx);
    Ok(())
}

/// Withdraws the Gecko hardening Nomad previously wrote, so `[hardening]
/// enabled = false` disables hardening on an already-hardened profile instead
/// of merely not refreshing it.
///
/// Gecko hardening lives in files that persist between launches, unlike the
/// Chromium-family launch flags which simply stop being passed. Skipping the
/// write left the previous `user.js` fence and the locked `nomad.cfg` in place,
/// so a user who turned the setting off to unbreak a site saw no change at all
/// — and `lockPref` values cannot even be overridden from `about:config`.
///
/// Two surfaces are withdrawn:
/// - the Nomad-managed `user.js` fence (content the user added outside the
///   markers is preserved; see `hardening::remove_managed_user_js`);
/// - the autoconfig pair, but only for browsers that declare one. `LibreWolf`
///   and Mullvad ship their own and Nomad never writes theirs.
///
/// `distribution/policies.json` is deliberately **kept**. Nothing in the
/// curated payload breaks a site — it covers telemetry, updates, Pocket, and
/// first-run pages — so removing it does not serve the reason people turn
/// hardening off, and it carries the injected uBO `ExtensionSettings` entry,
/// so deleting it would uninstall the user's ad blocker. Nomad also overwrites
/// the vendor's own file on browsers that ship one, so the original could not
/// be restored.
///
/// The Chromium family has no equivalent: its profile seeds are merged into
/// the browser's own `Preferences` with user-wins semantics and cannot be
/// cleanly un-merged. Turning hardening off stops the locked scalars being
/// re-enforced, which is the most that can be withdrawn there.
fn remove_gecko_hardening<B: BrowserFamily>(browser: &B, install_dir: &Path) {
    let Hardening::GeckoProfile {
        autoconfig, cfg, ..
    } = browser.hardening()
    else {
        return;
    };
    if let Some(profile_dir) = browser.profile_dir(install_dir) {
        match hardening::remove_managed_user_js(&profile_dir) {
            Ok(()) => tracing::info!(
                browser = browser.id(),
                "hardening disabled — removed the Nomad-managed user.js block"
            ),
            Err(e) => tracing::warn!(
                browser = browser.id(),
                error = %e,
                "hardening disabled but the Nomad user.js block could not be removed; \
                 the profile stays hardened"
            ),
        }
    }
    if autoconfig.is_some() && cfg.is_some() {
        match hardening::remove_autoconfig(install_dir) {
            Ok(()) => tracing::info!(
                browser = browser.id(),
                "hardening disabled — removed nomad.cfg + defaults/pref/autoconfig.js"
            ),
            Err(e) => tracing::warn!(
                browser = browser.id(),
                error = %e,
                "hardening disabled but the autoconfig pair could not be removed; \
                 locked prefs stay in force"
            ),
        }
    }
}

/// Returns the full path of the browser executable a `Command` built by
/// `BrowserFamily::launch_command()` will spawn. The cleanup watcher matches
/// browser processes by this image path rather than by bare file name: a name
/// like `chrome.exe` also matches unrelated installs of the same browser, so
/// on a host that runs a desktop Chrome alongside Nomad the watcher's
/// exit-wait could never reach zero and scrubbed early on its timeout.
fn browser_exe_path(cmd: &std::process::Command) -> String {
    cmd.get_program().to_string_lossy().into_owned()
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
            let _ = branding::ensure_branding(install_dir, br);
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
            if let Err(e) = prepare_browser_for_launch(browser, install_dir, hardening) {
                tracing::error!(browser = browser.id(), error = %e, "launch preparation refused fallback");
                show_error(state, ctx, &e.to_string(), false);
                return match wait_for_pipeline_action(state) {
                    PipelineAction::Retry => PostErrorAction::Retry,
                    PipelineAction::Close | PipelineAction::LaunchAnyway => PostErrorAction::Done,
                };
            }
            let mut cmd = browser.launch_command(install_dir, extra_args);
            let browser_exe = browser_exe_path(&cmd);
            if let Ok(child) = cmd.spawn() {
                tracing::info!(
                    browser = browser.id(),
                    pid = child.id(),
                    exe = %browser_exe,
                    "browser launched (fallback)"
                );
                spawn_cleanup_watcher(
                    child.id(),
                    &browser_exe,
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

/// Enforces browser-specific launch preparation before best-effort
/// self-registration repair. Required portability preparation must succeed
/// before either normal or fallback launch can spawn the browser.
fn prepare_browser_for_launch<B: BrowserFamily>(
    browser: &B,
    install_dir: &Path,
    hardening: HardeningConfig,
) -> Result<(), BrowserError> {
    browser.prepare_launch(install_dir, hardening)?;
    // If the browser registered *itself* as a URL/HTML handler (its own
    // "Make default" button), that registration launches the browser exe
    // directly — host profile, no hardening, no portable Data dir — and a
    // clicked link then opens a second, empty-profile instance whose data the
    // older cleanup could delete on exit. Reroute exactly those commands through
    // this launcher; registrations pointing outside our install tree are
    // never touched (see SPEC §10).
    match std::env::current_exe() {
        Ok(launcher_exe) => {
            let repaired = registry::repair_self_registration(install_dir, &launcher_exe);
            if repaired > 0 {
                tracing::info!(
                    browser = browser.id(),
                    repaired,
                    "rerouted browser self-registration(s) through the launcher"
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not resolve launcher path; skipping registration repair");
        }
    }
    Ok(())
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

/// Splits argv at the first literal `--` and validates the untrusted target.
///
/// The registered command (`"<exe>" -- "%1"`) carries exactly one non-empty
/// URL/file argument. A missing target, extra arguments, or a browser switch
/// must fail before either internal flags or the launch pipeline are reached.
fn split_forwarded_args(args: &[String]) -> Result<(&[String], &[String]), BrowserError> {
    match args.iter().position(|a| a == "--") {
        Some(i) => {
            let forwarded = &args[i + 1..];
            validate_forwarded_args(forwarded)?;
            Ok((&args[..i], forwarded))
        }
        None => Ok((args, &[])),
    }
}

/// Keep the protocol target as one positional argument, never as a switch.
fn validate_forwarded_args(forwarded: &[String]) -> Result<(), BrowserError> {
    if let [target] = forwarded {
        // Windows Gecko command-line parsing treats '/' as a switch prefix,
        // too. Drive-qualified Windows paths and file:// URLs remain valid.
        // Chromium trims Unicode whitespace before recognizing switches.
        // Inspect the trimmed view, but forward the original target unchanged.
        let checked = target.trim();
        if !checked.is_empty() && !checked.starts_with('-') && !checked.starts_with('/') {
            return Ok(());
        }
    }
    // Targets can contain authentication data; do not echo their contents.
    Err(BrowserError::ProtocolInvocation(
        "arguments after -- must contain exactly one non-empty URL or file path; \
         targets beginning with '-' or '/' after whitespace and additional arguments are not allowed"
            .to_owned(),
    ))
}

/// Parses cleanup-watcher arguments: `--nomad-cleanup-pid <pid>` (required),
/// `--nomad-cleanup-exe <path>` (optional; full browser-executable path, a
/// bare name is tolerated), `--nomad-scrub-thumbcache` (flag), and
/// `--nomad-scrub-prefetch` (flag). Returns `None` when
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
fn handle_cleanup_flag<B, F>(make: F, args: CleanupArgs) -> ExitCode
where
    B: BrowserFamily,
    F: FnOnce(Arch) -> B,
{
    tracing::info!(
        pid = args.browser_pid,
        exe = args.browser_exe.as_deref().unwrap_or("(unknown)"),
        "cleanup watcher started"
    );
    // Reroute a "Make default" clicked inside the browser as soon as it
    // happens, rather than only after exit: until then every clicked link
    // would start a second browser on the host profile instead of opening a
    // tab in the portable instance.
    let live_repair =
        install_dir_from_browser_exe(args.browser_exe.as_deref()).and_then(|install_dir| {
            let launcher_exe = std::env::current_exe().ok()?;
            selfreg_watch::start(install_dir, launcher_exe)
        });
    wait_for_pid(args.browser_pid);
    if let Some(ref exe) = args.browser_exe {
        // The anchor PID alone is not enough: Chromium hands its initial
        // process off to a new one, and Gecko background-task children (e.g.
        // `firefox.exe --backgroundtask defaultagent`) outlive the main UI
        // process and hold file handles in %LOCALAPPDATA%\Mozilla\. Wait for
        // the whole browser tree — matched by image path — to exit before
        // scrubbing.
        wait_for_browser_tree_exit(exe, 30);
    }
    if let Some(live) = live_repair {
        live.stop();
    }
    tracing::info!(
        pid = args.browser_pid,
        "browser tree exited; scrubbing host traces"
    );
    repair_registration_after_exit(args.browser_exe.as_deref());
    if let (Ok(launcher), Some(browser_exe)) =
        (std::env::current_exe(), args.browser_exe.as_deref())
    {
        if let Some(base) = launcher.parent() {
            let browser = make(Arch::X64);
            cleanup::scrub_host_traces(base, Path::new(browser_exe), browser.id());
        }
    }
    if args.scrub_thumbnail_cache {
        scrub_thumbnail_cache();
    }
    if args.scrub_prefetch && !scrub_prefetch() {
        tracing::info!("Prefetch scrub needs elevation; requesting UAC prompt");
        elevate_for_prefetch_scrub();
    }
    ExitCode::SUCCESS
}

/// Re-applies the self-registration repair once the browser tree is down.
///
/// The launch-time repair in `prepare_browser_for_launch` only sees the state
/// at launch. A user who clicks "Make default" *inside* the browser rewrites
/// the handler commands mid-session, with no launcher running to notice — so
/// every clicked link goes to the browser exe directly (host profile, no
/// portable Data dir, no handoff to the running instance) until the next
/// launch. The watcher is already a detached post-exit process, so re-running
/// the repair here closes that window at no extra cost.
///
/// `install_dir` is derived from the launched browser's own path: for every
/// family the executable sits directly in the install dir. A relative or bare
/// `browser_exe` yields no usable install dir and is skipped rather than
/// guessed at — `repair_self_registration` would refuse an empty root anyway,
/// but the intent is clearer stated here.
fn repair_registration_after_exit(browser_exe: Option<&str>) {
    let Some(install_dir) = install_dir_from_browser_exe(browser_exe) else {
        return;
    };
    let Ok(launcher_exe) = std::env::current_exe() else {
        tracing::warn!("could not resolve launcher path; skipping post-exit registration repair");
        return;
    };
    let repaired = registry::repair_self_registration(&install_dir, &launcher_exe);
    if repaired > 0 {
        tracing::warn!(
            repaired,
            "browser re-registered itself as default during the session; \
             rerouted through the launcher so clicked links reach the portable profile"
        );
    }
}

/// Derives the install dir from the launched browser's executable path: for
/// every family the executable sits directly in the install dir. A missing,
/// relative, or bare path yields `None` rather than a guess, because the
/// registry repair treats this directory as the containment boundary.
fn install_dir_from_browser_exe(browser_exe: Option<&str>) -> Option<std::path::PathBuf> {
    let exe = std::path::Path::new(browser_exe?);
    if !exe.is_absolute() {
        return None;
    }
    exe.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
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

/// Blocks until every process belonging to the launched browser has exited.
///
/// When `exe` is a full path (the normal case — `spawn_cleanup_watcher`
/// passes the launch command's program path), matching is by process image
/// path, so an unrelated install of the same browser (every Chromium ships
/// as `chrome.exe`) is never latched onto. Because a path match is exact,
/// the wait is unbounded: it parks on real process handles (zero CPU) until
/// the portable browser tree is genuinely gone — scrubbing must not race a
/// browser the user still has open, and Chromium routinely retires the
/// anchor PID while the tree lives on.
///
/// A bare file name (legacy invocations only) cannot make that distinction,
/// so it keeps the historical bounded behaviour: poll every 500 ms and give
/// up after `bare_name_max_wait_secs`, scrubbing anyway.
fn wait_for_browser_tree_exit(exe: &str, bare_name_max_wait_secs: u64) {
    let by_path = exe.contains(['\\', '/']);
    let start = std::time::Instant::now();
    let initial = processes_matching(exe).len();
    if initial == 0 {
        return;
    }
    tracing::info!(
        exe,
        count = initial,
        by_path,
        "waiting for remaining browser processes to exit"
    );

    if by_path {
        // wait_for_pid falls back to a 5 s sleep when the process cannot be
        // opened, so this loop always makes progress.
        while let Some(&pid) = processes_matching(exe).first() {
            wait_for_pid(pid);
        }
        tracing::info!(
            exe,
            elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            "all browser processes have exited"
        );
        return;
    }

    let timeout = std::time::Duration::from_secs(bare_name_max_wait_secs);
    while start.elapsed() < timeout {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if processes_matching(exe).is_empty() {
            tracing::info!(
                exe,
                elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                "all browser processes have exited"
            );
            return;
        }
    }
    tracing::warn!(
        exe,
        remaining = processes_matching(exe).len(),
        "timed out waiting for browser processes; proceeding with scrub anyway"
    );
}

/// Returns the PIDs of running processes that match `exe` (case-insensitive).
///
/// When `exe` contains a path separator it is a full executable path:
/// candidates are pre-filtered by file name, then confirmed by querying each
/// candidate's image path. A bare file name matches on the name alone.
/// Returns an empty list on non-Windows or on enumeration failure.
fn processes_matching(exe: &str) -> Vec<u32> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let target_path = exe.replace('/', "\\");
        let by_path = target_path.contains('\\');
        let target_name = std::path::Path::new(&target_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if target_name.is_empty() {
            return Vec::new();
        }
        let mut pids = Vec::new();
        // SAFETY: snapshot handle is closed before return; PROCESSENTRY32W is
        // zero-initialized except for dwSize per MSDN requirements.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot.is_null() || snapshot as isize == -1 {
                return Vec::new();
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            #[allow(clippy::cast_possible_truncation)]
            // PROCESSENTRY32W is ~568 bytes, well within u32
            {
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            }
            if Process32FirstW(snapshot, &raw mut entry) != 0 {
                loop {
                    let len = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let name = std::ffi::OsString::from_wide(&entry.szExeFile[..len])
                        .to_string_lossy()
                        .to_ascii_lowercase();
                    if name == target_name
                        && (!by_path || image_path_matches(entry.th32ProcessID, &target_path))
                    {
                        pids.push(entry.th32ProcessID);
                    }
                    if Process32NextW(snapshot, &raw mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }
        pids
    }
    #[cfg(not(windows))]
    {
        let _ = exe;
        Vec::new()
    }
}

/// Returns `true` when process `pid`'s full image path equals `target_path`
/// (case-insensitive, `\\?\` prefixes ignored on both sides).
///
/// Processes whose path cannot be queried do **not** match: the portable
/// browser runs unelevated as the current user and is always queryable, so
/// an unqueryable process cannot be one Nomad launched — and counting it
/// would stall the scrub on somebody else's process.
#[cfg(windows)]
fn image_path_matches(pid: u32, target_path: &str) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: the handle is checked before use and closed on every path; the
    // buffer length is passed in/out per the QueryFullProcessImageNameW
    // contract.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut buf = vec![0u16; 32768];
        #[allow(clippy::cast_possible_truncation)] // 32768 fits in u32
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &raw mut len);
        CloseHandle(handle);
        if ok == 0 {
            return false;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        strip_verbatim(&path).eq_ignore_ascii_case(strip_verbatim(target_path))
    }
}

/// Drops a leading `\\?\` verbatim prefix so image-path comparisons are
/// stable regardless of which form the OS returns.
#[cfg(windows)]
fn strip_verbatim(path: &str) -> &str {
    path.strip_prefix(r"\\?\").unwrap_or(path)
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
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| u16::from_le_bytes(*chunk))
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
            if Process32FirstW(snapshot, &raw mut entry) != 0 {
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
                    if Process32NextW(snapshot, &raw mut entry) == 0 {
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

    fn helium_failure_fixture() -> (tempfile::TempDir, browsers::helium::Helium, StateHandle) {
        let dir = tempfile::tempdir().unwrap();
        let browser = browsers::helium::Helium::new(config::Arch::X64);
        let prefs = dir.path().join("Data/Default/Preferences");
        std::fs::create_dir_all(prefs.parent().unwrap()).unwrap();
        std::fs::write(&prefs, "{broken").unwrap();
        let state = std::sync::Arc::new((
            std::sync::Mutex::new(ui::NomadState {
                view: build_initial_view(&browser, config::Arch::X64, &[]),
                phase: WindowPhase::Running,
            }),
            std::sync::Condvar::new(),
        ));
        (dir, browser, state)
    }

    #[tokio::test]
    async fn launch_only_check_phase_preserves_stage_and_backup() {
        let (dir, browser, state) = helium_failure_fixture();
        let install = dir.path().join("Browser");
        let staging_dir = install::stage_dir(&install);
        let backup = install::backup_dir(&install);
        std::fs::create_dir_all(&staging_dir).unwrap();
        std::fs::create_dir_all(&backup).unwrap();
        std::fs::write(staging_dir.join("partial"), b"partial").unwrap();
        std::fs::write(backup.join("chrome.exe"), b"working copy").unwrap();
        let lock = install::InstanceLock::acquire(&install).unwrap();
        let outcome = update_check_phase(
            &browser,
            &install,
            UpdateOptions {
                check_on_launch: false,
                auto_download: false,
            },
            &state,
            &egui::Context::default(),
            &lock,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, CheckPhaseResult::Launch));
        assert!(!install.exists());
        assert_eq!(
            std::fs::read(staging_dir.join("partial")).unwrap(),
            b"partial"
        );
        assert_eq!(
            std::fs::read(backup.join("chrome.exe")).unwrap(),
            b"working copy"
        );
    }

    #[test]
    fn locked_gui_pipeline_offers_no_fallback_and_preserves_stage() {
        // Malformed portable Preferences make even a regressed launch fail
        // before registry repair or process spawn. All paths belong to TempDir.
        let (dir, browser, state) = helium_failure_fixture();
        let install_dir = dir.path().join("Browser");
        let staging_dir = install::stage_dir(&install_dir);
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::create_dir_all(&staging_dir).unwrap();
        std::fs::write(staging_dir.join("partial"), b"active download").unwrap();
        browsers::write_version_marker(
            &install_dir,
            &browsers::InstalledVersion {
                browser_version: "1.0".into(),
                engine_version: "1.0".into(),
            },
        )
        .unwrap();
        let _lock = install::InstanceLock::acquire(&install_dir).unwrap();
        let controller = Arc::clone(&state);
        let user = std::thread::spawn(move || {
            let (mutex, cvar) = &*controller;
            let (mut state, timeout) = cvar
                .wait_timeout_while(
                    mutex.lock().unwrap(),
                    std::time::Duration::from_secs(10),
                    |s| !matches!(s.phase, WindowPhase::Error { .. }),
                )
                .unwrap();
            let blocked = !timeout.timed_out()
                && matches!(&state.phase,
                WindowPhase::Error { message, has_fallback: false } if message.contains("Another Nomad launcher"));
            state.phase = WindowPhase::Done;
            cvar.notify_all();
            blocked
        });
        pipeline_thread(
            &Arc::new(browser),
            &install_dir,
            UpdateOptions {
                check_on_launch: false,
                auto_download: false,
            },
            &[],
            None,
            HardeningConfig {
                enabled: false,
                ..Default::default()
            },
            &state,
            &egui::Context::default(),
        );
        assert!(
            user.join().unwrap(),
            "lock contention must offer Retry/Close without fallback"
        );
        assert_eq!(
            std::fs::read(staging_dir.join("partial")).unwrap(),
            b"active download"
        );
    }

    #[test]
    fn helium_preparation_failure_stops_normal_launch() {
        let (dir, browser, state) = helium_failure_fixture();
        let config = HardeningConfig {
            enabled: false,
            ..Default::default()
        };
        let result = do_launch(
            &browser,
            &dir.path().join("Browser"),
            &[],
            None,
            config,
            &state,
            &egui::Context::default(),
        );
        assert!(matches!(result, Err(BrowserError::Parse(_))));
        assert!(!matches!(state.0.lock().unwrap().phase, WindowPhase::Done));
    }

    #[test]
    fn helium_preparation_failure_cannot_be_bypassed_by_launch_anyway() {
        let (dir, browser, state) = helium_failure_fixture();
        let install = dir.path().join("Browser");
        std::fs::create_dir_all(&install).unwrap();
        browsers::write_version_marker(
            &install,
            &browsers::InstalledVersion {
                browser_version: "0.18.3.1".to_owned(),
                engine_version: "0.18.3.1".to_owned(),
            },
        )
        .unwrap();
        let controller = std::sync::Arc::clone(&state);
        let user = std::thread::spawn(move || {
            let (lock, cvar) = &*controller;
            let guard = lock.lock().unwrap();
            let (mut guard, timeout) = cvar
                .wait_timeout_while(guard, std::time::Duration::from_secs(10), |s| {
                    !matches!(s.phase, WindowPhase::Error { .. })
                })
                .unwrap();
            assert!(!timeout.timed_out());
            assert!(matches!(
                guard.phase,
                WindowPhase::Error {
                    has_fallback: true,
                    ..
                }
            ));
            guard.phase = WindowPhase::LaunchAnyway;
            cvar.notify_all();
            let (mut guard, timeout) = cvar
                .wait_timeout_while(guard, std::time::Duration::from_secs(10), |s| {
                    !matches!(
                        s.phase,
                        WindowPhase::Error {
                            has_fallback: false,
                            ..
                        } | WindowPhase::Done
                    )
                })
                .unwrap();
            let blocked = !timeout.timed_out()
                && matches!(
                    guard.phase,
                    WindowPhase::Error {
                        has_fallback: false,
                        ..
                    }
                );
            guard.phase = WindowPhase::Done;
            cvar.notify_all();
            blocked
        });
        let action = handle_error(
            &browser,
            &install,
            &[],
            None,
            HardeningConfig {
                enabled: false,
                ..Default::default()
            },
            &state,
            &egui::Context::default(),
            "mock update failure",
        );
        assert!(matches!(action, PostErrorAction::Done));
        assert!(
            user.join().unwrap(),
            "fallback must show the preparation error without offering another bypass"
        );
    }

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

    /// `[hardening] enabled = false` must actually disable Gecko hardening.
    ///
    /// The hardening block writes files that persist between launches, so
    /// skipping the write left the previous `user.js` fence and the locked
    /// `nomad.cfg` in force: a user who turned the setting off to unbreak a
    /// site saw no change, and `lockPref` cannot be overridden from
    /// `about:config`.
    #[test]
    fn disabling_hardening_withdraws_the_gecko_payloads() {
        use crate::browsers::firefox::Firefox;
        use crate::config::Arch;

        let temp = tempfile::tempdir().unwrap();
        let install_dir = temp.path().join("Browser");
        std::fs::create_dir_all(&install_dir).unwrap();
        let browser = Firefox::new(Arch::X64);
        let profile_dir = browser.profile_dir(&install_dir).unwrap();

        // A previously hardened install, plus a pref the user wrote themselves
        // and a file the browser ships beside ours.
        std::fs::create_dir_all(&profile_dir).unwrap();
        std::fs::write(profile_dir.join("user.js"), "user_pref(\"mine\", true);\n").unwrap();
        hardening::write_user_js(&profile_dir, "user_pref(\"privacy.rfp\", true);").unwrap();
        hardening::write_autoconfig(&install_dir, "pointer\n", "lockPref(\"a\", 1);\n").unwrap();
        let vendor = install_dir
            .join("defaults")
            .join("pref")
            .join("channel-prefs.js");
        std::fs::write(&vendor, "vendor").unwrap();

        remove_gecko_hardening(&browser, &install_dir);

        let user_js = std::fs::read_to_string(profile_dir.join("user.js")).unwrap();
        assert!(
            user_js.contains("user_pref(\"mine\", true);"),
            "the user's own prefs must survive"
        );
        assert!(
            !user_js.contains("privacy.rfp"),
            "the Nomad-managed block must be gone"
        );
        assert!(
            !install_dir.join("nomad.cfg").exists(),
            "locked prefs must stop being applied"
        );
        assert!(!install_dir.join("defaults/pref/autoconfig.js").exists());
        assert!(
            vendor.exists(),
            "the browser's own files are not ours to delete"
        );
    }

    /// `LibreWolf` and Mullvad declare `autoconfig: None` — they ship their own
    /// pair and Nomad never writes one, so disabling hardening must not delete
    /// theirs.
    #[test]
    fn disabling_hardening_spares_a_vendor_owned_autoconfig_pair() {
        use crate::browsers::librewolf::Librewolf;
        use crate::config::Arch;

        let temp = tempfile::tempdir().unwrap();
        let install_dir = temp.path().join("Browser");
        std::fs::create_dir_all(&install_dir).unwrap();
        // Stand in for LibreWolf's own local-settings.js + librewolf.cfg by
        // writing files at the paths our remover targets.
        hardening::write_autoconfig(&install_dir, "vendor pointer\n", "vendor cfg\n").unwrap();

        remove_gecko_hardening(&Librewolf::new(Arch::X64), &install_dir);

        assert!(
            install_dir.join("nomad.cfg").exists()
                && install_dir.join("defaults/pref/autoconfig.js").exists(),
            "a browser that ships its own autoconfig must keep it"
        );
    }

    /// Regression (#38): `--disable-machine-id` and `--disable-encryption`
    /// used to live in `HARDENING_FLAGS`, so `[hardening] enabled = false`
    /// dropped them. They decide the profile's storage format, not its
    /// privacy level:
    ///
    /// - the machine ID seeds the `Secure Preferences` MACs that protect
    ///   `extensions.settings`, so changing it makes Chromium clear the
    ///   extension registry and garbage-collect `Default\Extensions`;
    /// - the encryption switch decides whether cookies and auth tokens are
    ///   DPAPI-sealed, and Chromium drops what it cannot decrypt.
    ///
    /// Toggling the setting therefore wiped the user's extensions and
    /// sign-ins. They must reach the browser whatever the config says.
    #[test]
    fn profile_storage_flags_survive_hardening_disabled() {
        use crate::browsers::helium::Helium;
        use crate::browsers::ungoogled::UngoogledChromium;
        use crate::config::{Arch, Config};

        let install_dir = std::path::Path::new(r"C:\Portables\Test\Browser");
        let mut config = Config::parse("[browser]\ninstall_dir = \"Browser\"\n").unwrap();
        config.hardening.enabled = false;

        for (label, argv) in [
            ("ungoogled-chromium", {
                let b = UngoogledChromium::new(Arch::X64);
                let args = build_launch_args(&b, &config);
                assert!(
                    !args.iter().any(|a| a.starts_with("--disable-")),
                    "hardening flags must still be gated off when disabled"
                );
                argv_of(&b.launch_command(install_dir, &args))
            }),
            ("helium", {
                let b = Helium::new(Arch::X64);
                let args = build_launch_args(&b, &config);
                argv_of(&b.launch_command(install_dir, &args))
            }),
        ] {
            for flag in ["--disable-machine-id", "--disable-encryption"] {
                assert!(
                    argv.iter().any(|a| a == flag),
                    "{label}: {flag} must be passed even with hardening disabled"
                );
            }
            assert!(
                argv.iter().any(|a| a.starts_with("--user-data-dir=")),
                "{label}: the portable profile must still be selected"
            );
        }
    }

    /// With hardening on, the hardening `--disable-features=` bundle must be
    /// the last such switch: Chromium honours only the final occurrence, and
    /// the hardening bundle is a superset of the portability one.
    #[test]
    fn hardening_disable_features_bundle_wins_over_the_portability_one() {
        use crate::browsers::ungoogled::UngoogledChromium;
        use crate::config::{Arch, Config};

        let browser = UngoogledChromium::new(Arch::X64);
        let config = Config::parse("[browser]\ninstall_dir = \"Browser\"\n").unwrap();
        assert!(config.hardening.enabled, "default config hardens");

        let hardening_args = build_launch_args(&browser, &config);
        let full_argv = argv_of(&browser.launch_command(
            std::path::Path::new(r"C:\Portables\Test\Browser"),
            &hardening_args,
        ));
        let last = full_argv
            .iter()
            .rfind(|a| a.starts_with("--disable-features="))
            .expect("a --disable-features bundle must be present");
        assert!(
            last.contains("DeviceBoundSessions"),
            "the winning bundle must keep the portability feature: {last}"
        );
        assert!(
            last.contains("JumpList"),
            "the winning bundle must be the hardening superset: {last}"
        );
    }

    /// Renders a built `Command` as its argument list for assertions.
    fn argv_of(cmd: &std::process::Command) -> Vec<String> {
        cmd.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
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
    pub(super) fn make_lnk(target: &str) -> Vec<u8> {
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
    fn split_forwarded_args_separates_the_registered_url_tail() {
        // Regression: the open command registered by --register-default is
        // `"<exe>" -- "%1"`, but the launcher used to ignore everything after
        // the `--`, so clicked links opened the browser without navigating.
        let args = vec![
            "nomad-firefox.exe".to_owned(),
            "--".to_owned(),
            "https://example.com/page".to_owned(),
        ];
        let (own, forwarded) = split_forwarded_args(&args).unwrap();
        assert_eq!(own, &args[..1]);
        assert_eq!(forwarded, &["https://example.com/page".to_owned()][..]);

        // No separator: everything is Nomad's own, nothing is forwarded.
        let plain = vec![
            "nomad-firefox.exe".to_owned(),
            "--register-default".to_owned(),
        ];
        let (own, forwarded) = split_forwarded_args(&plain).unwrap();
        assert_eq!(own, &plain[..]);
        assert!(forwarded.is_empty());

        // A Nomad flag in the untrusted target position must be rejected,
        // rather than dispatched internally or forwarded as a browser switch.
        let tricky = vec![
            "nomad-firefox.exe".to_owned(),
            "--".to_owned(),
            "--register-default".to_owned(),
        ];
        assert!(matches!(
            split_forwarded_args(&tricky),
            Err(BrowserError::ProtocolInvocation(_))
        ));
    }

    fn protocol_args(tail: &[&str]) -> Vec<String> {
        ["nomad-firefox.exe", "--"]
            .into_iter()
            .chain(tail.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    fn assert_invalid_forwarded_args(args: &[String]) {
        let result = split_forwarded_args(args);
        assert!(
            matches!(result, Err(BrowserError::ProtocolInvocation(_))),
            "malformed protocol arguments must fail at argument parsing"
        );
    }

    #[test]
    fn forwarded_args_reject_missing_target() {
        assert_invalid_forwarded_args(&protocol_args(&[]));
    }

    #[test]
    fn forwarded_args_reject_empty_or_blank_target() {
        for target in ["", " ", "\t\n"] {
            assert_invalid_forwarded_args(&protocol_args(&[target]));
        }
    }

    #[test]
    fn forwarded_args_reject_browser_switches_without_echoing_target() {
        for target in [
            "-",
            "--",
            "--register-default",
            "--nomad-scrub-prefetch",
            "--user-data-dir=private-test-value",
            "-profile",
            "/profile",
            "/prefetch:1",
        ] {
            let args = protocol_args(&[target]);
            assert_invalid_forwarded_args(&args);
            let error = split_forwarded_args(&args).unwrap_err().to_string();
            assert!(
                !error.contains("private-test-value"),
                "errors must not echo the untrusted target"
            );
        }
    }

    #[test]
    fn forwarded_args_reject_whitespace_prefixed_switches() {
        for target in [
            "  --user-data-dir=other",
            "\t--no-sandbox",
            "\r\n/profile",
            "\u{a0}--no-sandbox",
            "\u{2003}/profile",
            "\u{3000}--no-sandbox",
        ] {
            assert_invalid_forwarded_args(&protocol_args(&[target]));
        }
    }

    #[test]
    fn forwarded_args_reject_additional_arguments() {
        for tail in [
            vec!["https://example.invalid/", "--user-data-dir=other"],
            vec!["https://example.invalid/", "https://example.invalid/second"],
            vec!["https://example.invalid/", "--", "--no-sandbox"],
            vec!["https://example.invalid/", ""],
        ] {
            assert_invalid_forwarded_args(&protocol_args(&tail));
        }
    }

    #[test]
    fn forwarded_args_reject_malformed_tail_before_internal_flags() {
        for own_flag in [
            "--register-default",
            "--unregister-default",
            "--nomad-cleanup-pid",
            "--nomad-scrub-prefetch",
        ] {
            let args = ["nomad-firefox.exe", own_flag, "--", "--no-sandbox"].map(str::to_owned);
            assert_invalid_forwarded_args(&args);
        }
    }

    #[test]
    fn forwarded_args_preserve_single_url_or_windows_file_target() {
        for target in [
            "https://example.invalid/page?flag=--no-sandbox#section",
            r#"https://example.invalid/?text=\"quoted\"&name=with spaces"#,
            "file:///C:/My%20Files/page.html",
            r"C:\My Files\page.html",
            r"\\server\share\My Files\page.html",
            "relative page.html",
            "  https://example.invalid/page  ",
            "about:blank",
        ] {
            let args = protocol_args(&[target]);
            let (own, forwarded) = split_forwarded_args(&args).unwrap();
            assert_eq!(own, &args[..1]);
            assert_eq!(forwarded, &args[2..]);
            assert_eq!(forwarded, &[target.to_owned()]);
        }
    }

    #[test]
    fn forwarded_args_fail_before_browser_construction_or_configuration() {
        let called = std::cell::Cell::new(false);
        for tail in [
            vec!["--user-data-dir=other"],
            vec!["/profile"],
            vec!["https://example.invalid/", "--no-sandbox"],
            vec![""],
        ] {
            let result = run_with_ui(
                |arch| {
                    called.set(true);
                    browsers::helium::Helium::new(arch)
                },
                &[],
                None,
                tail.into_iter().map(str::to_owned).collect(),
            );
            assert!(matches!(
                result,
                Err(RunError::Browser(BrowserError::ProtocolInvocation(_)))
            ));
            assert!(
                !called.get(),
                "invalid arguments must not reach browser construction"
            );
        }
    }

    #[test]
    fn protocol_invocations_cannot_check_or_download_updates() {
        let direct = effective_update_options(true, true, false);
        assert!(direct.check_on_launch);
        assert!(direct.auto_download);

        let protocol = effective_update_options(true, true, true);
        assert!(!protocol.check_on_launch);
        assert!(!protocol.auto_download);
    }

    #[test]
    fn protocol_invocation_cannot_reenable_download_independently() {
        let protocol = effective_update_options(false, true, true);
        assert!(!protocol.check_on_launch);
        assert!(!protocol.auto_download);
    }

    /// The live and post-exit repairs both use this directory as the only
    /// boundary for rewriting handlers, so anything that is not a full path
    /// must yield nothing rather than a guess.
    #[test]
    fn install_dir_from_browser_exe_requires_a_full_path() {
        assert_eq!(
            install_dir_from_browser_exe(Some(r"C:\Portables\Helium\Browser\chrome.exe")),
            Some(std::path::PathBuf::from(r"C:\Portables\Helium\Browser"))
        );
        assert_eq!(install_dir_from_browser_exe(Some("chrome.exe")), None);
        assert_eq!(
            install_dir_from_browser_exe(Some(r"Browser\chrome.exe")),
            None
        );
        assert_eq!(install_dir_from_browser_exe(None), None);
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
    fn processes_matching_reports_nothing_for_absent_targets() {
        // A name that definitely isn't running, and a path that doesn't exist.
        assert!(processes_matching("nomad-zzzz-not-a-real-process.exe").is_empty());
        assert!(processes_matching(r"C:\definitely\not\here\nomad-zzzz.exe").is_empty());
        // Degenerate input (no file name at all) must be an empty result,
        // never a match-everything.
        assert!(processes_matching("").is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn processes_matching_finds_the_current_process_by_full_path() {
        // The test process itself is a live process whose image path we know
        // exactly — a real end-to-end check of the Toolhelp + image-path pipe.
        let exe = std::env::current_exe().expect("current exe");
        let by_path = processes_matching(&exe.to_string_lossy());
        assert!(
            by_path.contains(&std::process::id()),
            "the current process must be found by its own image path"
        );

        // A *different* path with the same file name must NOT match this
        // process — the exact scenario of a desktop Chrome vs. the portable
        // one (both `chrome.exe`, different directories).
        let same_name_elsewhere = format!(
            r"C:\definitely\not\here\{}",
            exe.file_name().unwrap().to_string_lossy()
        );
        assert!(
            !processes_matching(&same_name_elsewhere).contains(&std::process::id()),
            "a same-named executable at a different path must not match"
        );

        // Bare-name matching (legacy) is a superset of path matching.
        let name = exe.file_name().unwrap().to_string_lossy();
        assert!(
            processes_matching(&name).contains(&std::process::id()),
            "the current process must be found by bare name"
        );
    }

    #[cfg(windows)]
    #[test]
    fn strip_verbatim_removes_only_the_verbatim_prefix() {
        assert_eq!(
            strip_verbatim(r"\\?\C:\Portables\Browser\chrome.exe"),
            r"C:\Portables\Browser\chrome.exe"
        );
        assert_eq!(
            strip_verbatim(r"C:\Portables\Browser\chrome.exe"),
            r"C:\Portables\Browser\chrome.exe"
        );
        // UNC paths are not verbatim paths and must be left intact.
        assert_eq!(
            strip_verbatim(r"\\server\share\x.exe"),
            r"\\server\share\x.exe"
        );
    }
}
