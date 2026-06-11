//! Nomad Launcher — transient status window.
//!
//! Opens a single egui/eframe window that lives for the duration of the
//! update-and-launch sequence, then closes itself once the browser spawns.
//!
//! # Architecture (pipeline ↔ window)
//!
//! The window runs on the main thread (required by eframe). The pipeline runs
//! on a dedicated background OS thread. They share a
//! `Arc<(Mutex<`[`NomadState`]`>, Condvar)>` ([`StateHandle`]):
//!
//! - The pipeline writes [`NomadState`] and calls [`egui::Context::request_repaint`].
//! - The window reads the state each frame and renders accordingly.
//! - User decisions (update prompt, retry, launch-anyway) are returned to the
//!   pipeline via [`WindowPhase`] and the [`Condvar`].
//!
//! # Module layout
//! - [`theme`] — Nomad design tokens (palette, type/spacing/radius scales).
//! - [`identity`] — identity card widget (logo, name, status, progress bar).
//! - [`LauncherView`] / [`NomadState`] / [`WindowPhase`] — view model types.
//! - [`show_window`] — static preview (no pipeline).
//! - [`show_window_driven`] — full pipeline-driven window.

pub mod identity;
pub mod theme;

use std::sync::{Arc, Condvar, Mutex};

use eframe::egui;

/// Nomad brand emblem (the shield-rocket from `nomad.png`, wordmark cropped),
/// packed as a multi-res PNG-framed `.ico` so it decodes via [`decode_ico_rgba`]
/// with no separate image-decoder dependency. Shown in the footer lockup.
const NOMAD_EMBLEM_ICO: &[u8] = include_bytes!("../../payloads/nomad/nomad-emblem.ico");

/// Atkinson Hyperlegible (SIL OFL) — the launcher UI typeface, embedded so eframe
/// can be built without `default_fonts` (dropping egui's bundled Ubuntu / emoji /
/// mono, which the launcher never renders). Chosen for legibility at the UI's
/// 9–15 px sizes. License: `core/payloads/fonts/OFL.txt`.
const UI_FONT: &[u8] = include_bytes!("../../payloads/fonts/AtkinsonHyperlegible-Regular.ttf");

// ── View model types ──────────────────────────────────────────────────────────

/// Progress-bar state for the identity card.
#[derive(Debug, Clone, PartialEq)]
pub enum ProgressState {
    /// Animated sweep — used during check / verify / extract.
    Indeterminate,
    /// Determinate fraction (0.0 – 1.0) — used during download.
    Determinate(f32),
    /// No bar drawn.
    Hidden,
}

/// Status text shown in the identity card's status block.
#[derive(Debug, Clone)]
pub struct StatusLines {
    /// Primary status (14 px) — e.g. `"Checking for updates…"`.
    pub primary: String,
    /// Secondary detail (11 px) — finer sub-step; may be empty.
    pub secondary: String,
}

impl StatusLines {
    /// Creates a status with the given `primary` text and an empty secondary.
    #[must_use]
    pub fn new(primary: impl Into<String>) -> Self {
        Self {
            primary: primary.into(),
            secondary: String::new(),
        }
    }
}

/// Complete view model for the Nomad status window.
///
/// All fields are plain data; the window renders whatever is in this struct at
/// the time of each repaint. Updated from the pipeline thread via
/// [`NomadState`] / [`StateHandle`].
#[derive(Debug, Clone)]
pub struct LauncherView {
    /// Browser display name, e.g. `"Ungoogled Chromium"`.
    pub display_name: String,
    /// Runtime id used in the *Name* detail row, e.g. `"ungoogled-chromium"`.
    pub id: String,
    /// Architecture string, e.g. `"x64"`.
    pub arch: String,
    /// Browser (release) version — `None` until the update check resolves.
    pub browser_version: Option<String>,
    /// Engine display name, e.g. `"Chromium"` or `"Firefox"`.
    pub engine_name: String,
    /// Engine version — `None` until the update check resolves.
    pub engine_version: Option<String>,
    /// Build date shown in the runtime details card; `None` when unknown.
    pub build_date: Option<String>,
    /// URL for the *Open upstream release page* footer link.
    pub upstream_url: String,
    /// Status lines shown in the identity card's status block.
    pub status: StatusLines,
    /// Progress bar state.
    pub progress: ProgressState,
    /// Raw `.ico` bytes embedded at compile time via `include_bytes!`.
    ///
    /// When `Some`, [`show_window_driven`] decodes the best-fit 32×32 RGBA
    /// frame and uses it as both the title-bar and taskbar icon.  When `None`
    /// the accent placeholder is used instead.
    pub icon_bytes: Option<&'static [u8]>,
    /// Family signature accent (amber by default), or a per-browser
    /// override from [`crate::browsers::BrowserFamily::accent`]. Drives the
    /// progress bar, links, the logo fallback tile, and the Nomad mark.
    pub accent: egui::Color32,
}

impl LauncherView {
    /// Formats the version subtitle for the identity card header per SPEC §7.
    ///
    /// Format: `{browser_version} — {engine} {engine_version} (Portable)`.
    /// The ` — {engine} {engine_version}` segment is omitted when the browser
    /// version and engine version strings are equal.
    #[must_use]
    pub fn version_subtitle(&self) -> String {
        match (&self.browser_version, &self.engine_version) {
            (Some(bv), Some(ev)) if bv != ev => {
                format!("{bv} \u{2014} {} {ev} (Portable)", self.engine_name)
            }
            (Some(bv), _) => format!("{bv} (Portable)"),
            (None, _) => "(Portable)".to_owned(),
        }
    }
}

// ── Shared state (pipeline ↔ window) ─────────────────────────────────────────

/// Control-flow phase: what the pipeline is doing / what the window should show.
#[derive(Debug, Clone)]
pub enum WindowPhase {
    /// Pipeline running normally — render status lines and progress bar.
    Running,
    /// Update detected; waiting for the user to decide (`auto_download = false`).
    UpdatePrompt {
        /// Version string of the available update.
        new_version: String,
    },
    /// Set by the window after the user decides: `true` = download, `false` = skip.
    UpdateDecided(bool),
    /// Browser spawned — window should close itself.
    Done,
    /// Pipeline failed — show error UI with action buttons.
    Error {
        /// Human-readable error description.
        message: String,
        /// Whether a usable install exists that the user could launch anyway.
        has_fallback: bool,
    },
    /// Set by the window when the user clicks *Retry*.
    RetryRequested,
    /// Set by the window when the user clicks *Launch anyway*.
    LaunchAnyway,
}

/// Shared state between the eframe window and the pipeline thread.
#[derive(Debug, Clone)]
pub struct NomadState {
    /// The current view model rendered each frame.
    pub view: LauncherView,
    /// The current control-flow phase.
    pub phase: WindowPhase,
}

/// Thread-safe handle shared between the pipeline thread and the eframe window.
///
/// Contains a `(Mutex<`[`NomadState`]`>, Condvar)` pair:
/// - The [`Condvar`] is notified whenever the pipeline or the window changes
///   the phase so the other side can wake up immediately.
pub type StateHandle = Arc<(Mutex<NomadState>, Condvar)>;

// ── eframe App ────────────────────────────────────────────────────────────────

/// The eframe application for the Nomad status window.
struct NomadWindow {
    state: StateHandle,
    /// Browser-logo texture for the identity card, lazily decoded once from
    /// [`LauncherView::icon_bytes`] on the first frame.
    logo: Option<egui::TextureHandle>,
    /// Nomad brand-emblem texture for the footer lockup, lazily decoded once
    /// from the embedded [`NOMAD_EMBLEM_ICO`] on the first frame.
    nomad_logo: Option<egui::TextureHandle>,
    /// `ITaskbarList3` wrapper; drives taskbar-button progress on Windows.
    taskbar: crate::taskbar::TaskbarProgress,
    /// Window handle of the launcher window; populated on the first frame.
    hwnd: Option<crate::taskbar::Hwnd>,
}

impl eframe::App for NomadWindow {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // Snapshot state without holding the lock during rendering.
        let (phase, view) = {
            let (lock, _) = &*self.state;
            let guard = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (guard.phase.clone(), guard.view.clone())
        };

        // Lazily capture the HWND on the first frame, then drive taskbar progress.
        if self.hwnd.is_none() {
            self.hwnd = crate::taskbar::acquire_hwnd();
        }
        if let Some(hwnd) = self.hwnd {
            let is_error = matches!(phase, WindowPhase::Error { .. });
            self.taskbar.apply(hwnd, &view.progress, is_error);
        }

        // Auto-close when the pipeline signals done.
        if matches!(phase, WindowPhase::Done) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        let _ = frame; // frame is unused on non-Windows builds

        // Lazily decode the embedded browser icon into a GPU texture (once).
        if self.logo.is_none() {
            if let Some(bytes) = view.icon_bytes {
                if let Some((rgba, w, h)) = decode_ico_rgba(bytes, 64) {
                    let image =
                        egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
                    self.logo = Some(ctx.load_texture(
                        "nomad-browser-logo",
                        image,
                        egui::TextureOptions::LINEAR,
                    ));
                }
            }
        }

        // Lazily decode the Nomad brand emblem for the footer lockup (once).
        if self.nomad_logo.is_none() {
            if let Some((rgba, w, h)) = decode_ico_rgba(NOMAD_EMBLEM_ICO, 64) {
                let image =
                    egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
                self.nomad_logo =
                    Some(ctx.load_texture("nomad-emblem", image, egui::TextureOptions::LINEAR));
            }
        }

        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::same(8)),
            )
            .show(ctx, |ui| {
                ui.set_min_width(340.0);

                identity::identity_card(ui, &view, self.logo.as_ref());
                ui.add_space(theme::space::MD);
                runtime_details_card(ui, &view);
                ui.add_space(theme::space::MD);

                match &phase {
                    WindowPhase::UpdatePrompt { new_version } => {
                        self.render_update_prompt(ui, new_version);
                    }
                    WindowPhase::Error {
                        message,
                        has_fallback,
                    } => {
                        self.render_error(ui, ctx, message, *has_fallback);
                    }
                    _ => {
                        footer(
                            ui,
                            &view.upstream_url,
                            view.accent,
                            self.nomad_logo.as_ref(),
                        );
                    }
                }
            });
    }
}

impl NomadWindow {
    /// Renders the *Update available* prompt with Update / Launch-current buttons.
    fn render_update_prompt(&self, ui: &mut egui::Ui, new_version: &str) {
        ui.add_space(theme::space::SM);
        ui.label(
            egui::RichText::new(format!("Version {new_version} is available."))
                .size(theme::text::BODY)
                .color(theme::TEXT_PRIMARY),
        );
        ui.add_space(theme::space::MD);
        ui.horizontal(|ui| {
            if ui.button("Update").clicked() {
                self.set_decided(true);
            }
            if ui.button("Launch current").clicked() {
                self.set_decided(false);
            }
        });
    }

    /// Renders the error state with the error message and Retry / Launch-anyway / Close buttons.
    fn render_error(
        &self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        message: &str,
        has_fallback: bool,
    ) {
        ui.add_space(theme::space::SM);
        ui.label(
            egui::RichText::new(message)
                .size(theme::text::BODY)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            if ui.button("Retry").clicked() {
                self.signal_phase(WindowPhase::RetryRequested);
            }
            if has_fallback && ui.button("Launch anyway").clicked() {
                self.signal_phase(WindowPhase::LaunchAnyway);
            }
            if ui.button("Close").clicked() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
    }

    /// Signals an `UpdateDecided` phase and wakes the pipeline.
    fn set_decided(&self, update: bool) {
        self.signal_phase(WindowPhase::UpdateDecided(update));
    }

    /// Locks the state, sets the phase, and notifies the pipeline condvar.
    fn signal_phase(&self, phase: WindowPhase) {
        let (lock, cvar) = &*self.state;
        let mut guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.phase = phase;
        cvar.notify_all();
    }
}

// ── Helper widgets ────────────────────────────────────────────────────────────

/// Renders the runtime details card (`RUNTIME DETAILS` eyebrow + four rows).
fn runtime_details_card(ui: &mut egui::Ui, view: &LauncherView) {
    let frame = egui::Frame::NONE
        .fill(theme::CARD)
        .corner_radius(egui::CornerRadius::same(theme::RADIUS_CARD))
        .inner_margin(egui::Margin::same(12));

    frame.show(ui, |ui| {
        ui.label(
            egui::RichText::new("RUNTIME DETAILS")
                .size(theme::text::EYEBROW)
                .color(theme::EYEBROW),
        );

        ui.add_space(theme::space::MD);

        let name_val = format!("{} {}", view.id, view.arch);
        let version_key = format!("{} version", view.display_name);
        let version_val = view.browser_version.as_deref().unwrap_or("\u{2014}");
        let date_val = view.build_date.as_deref().unwrap_or("\u{2014}");

        detail_row(ui, "Name", &name_val);
        detail_row(ui, "Bundle mode", "Self-updating portable");
        detail_row(ui, &version_key, version_val);
        detail_row(ui, "Build date", date_val);
    });
}

/// Renders a single `key  ···  value` row in the runtime details card.
fn detail_row(ui: &mut egui::Ui, key: &str, val: &str) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(key)
                .size(theme::text::BODY)
                .color(theme::TEXT_SECONDARY),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                egui::RichText::new(val)
                    .size(theme::text::BODY)
                    .color(theme::TEXT_PRIMARY),
            );
        });
    });
    ui.add_space(theme::space::SM);
}

/// Renders the footer: the upstream-release hyperlink (left) and the Nomad
/// brand lockup (right) — the Nomad emblem stacked *above* the `NOMAD` wordmark.
/// The wordmark is in `accent`; the emblem is the fixed-colour brand mark
/// (`emblem`, decoded from [`NOMAD_EMBLEM_ICO`]), falling back to the painter
/// [`nomad_mark`] when the texture is unavailable. The lockup is the family's
/// shared signature.
fn footer(
    ui: &mut egui::Ui,
    url: &str,
    accent: egui::Color32,
    emblem: Option<&egui::TextureHandle>,
) {
    ui.add_space(theme::space::XS);
    ui.horizontal(|ui| {
        ui.hyperlink_to(
            egui::RichText::new("Open upstream release page")
                .size(theme::text::BODY)
                .color(accent),
            url,
        );
        // Right-align a vertical lockup: emblem centered on top, wordmark below.
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(64.0, 48.0),
                egui::Layout::top_down(egui::Align::Center),
                |ui| {
                    let mark = egui::vec2(28.0, 28.0);
                    if let Some(texture) = emblem {
                        ui.add(
                            egui::Image::from_texture(egui::load::SizedTexture::from_handle(
                                texture,
                            ))
                            .fit_to_exact_size(mark),
                        );
                    } else {
                        let (rect, _) = ui.allocate_exact_size(mark, egui::Sense::hover());
                        nomad_mark(ui.painter(), rect, accent);
                    }
                    ui.add_space(theme::space::XS);
                    ui.label(
                        egui::RichText::new("NOMAD")
                            .size(theme::text::BODY)
                            .color(accent)
                            .strong(),
                    );
                },
            );
        });
    });
    ui.add_space(theme::space::XS);
}

/// Draws the Nomad "N-Route" mark into `rect`, tinted `color`: an `N` monogram
/// whose diagonal reads as a route, with two waypoint nodes at the diagonal's
/// ends. This is the procedural *fallback* used only when the embedded emblem
/// texture is unavailable — cheap painter primitives, no asset decode, and it
/// tints to any accent for free.
fn nomad_mark(painter: &egui::Painter, rect: egui::Rect, color: egui::Color32) {
    let s = rect.size().min_elem();
    let sw = s * 0.14;
    let stroke = egui::Stroke::new(sw, color);
    let x0 = rect.left() + s * 0.16;
    let x1 = rect.right() - s * 0.16;
    let yt = rect.top() + s * 0.14;
    let yb = rect.bottom() - s * 0.14;
    painter.line_segment([egui::pos2(x0, yb), egui::pos2(x0, yt)], stroke); // left vertical
    painter.line_segment([egui::pos2(x0, yt), egui::pos2(x1, yb)], stroke); // diagonal route
    painter.line_segment([egui::pos2(x1, yb), egui::pos2(x1, yt)], stroke); // right vertical
    let r = sw * 0.95;
    painter.circle_filled(egui::pos2(x0, yt), r, color); // waypoint node (start)
    painter.circle_filled(egui::pos2(x1, yb), r, color); // waypoint node (end)
}

// ── Icon helpers ─────────────────────────────────────────────────────────────

/// Decodes the `.ico` frame whose width is closest to `target_px` into
/// `(rgba, width, height)` straight-alpha RGBA8 pixels.
///
/// Uses the [`ico`] crate, which transparently handles both BMP/DIB frames
/// *and* PNG-compressed frames — the latter being what the generated
/// grayscale branding ICOs use for every size.
fn decode_ico_rgba(bytes: &[u8], target_px: u32) -> Option<(Vec<u8>, u32, u32)> {
    let dir = ico::IconDir::read(std::io::Cursor::new(bytes)).ok()?;
    let entry = dir
        .entries()
        .iter()
        .min_by_key(|e| u64::from(e.width()).abs_diff(u64::from(target_px)))?;
    let image = entry.decode().ok()?;
    Some((image.rgba_data().to_vec(), image.width(), image.height()))
}

/// Decodes a `.ico` file into [`egui::viewport::IconData`] for the window /
/// taskbar icon, picking the frame closest to 64 px — large enough for a
/// crisp icon while keeping the resulting `HICON` lightweight; Windows
/// rescales it as needed.
fn parse_ico_icon(bytes: &[u8]) -> Option<egui::viewport::IconData> {
    let (rgba, width, height) = decode_ico_rgba(bytes, 64)?;
    Some(egui::viewport::IconData {
        rgba,
        width,
        height,
    })
}

/// Generates a 32×32 solid `accent`-filled icon used as the window / taskbar
/// icon when no browser icon bytes are provided.
fn make_placeholder_icon(accent: egui::Color32) -> egui::viewport::IconData {
    const SIZE: u32 = 32;
    let (r, g, b) = (accent.r(), accent.g(), accent.b());
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for _ in 0..(SIZE * SIZE) {
        rgba.extend_from_slice(&[r, g, b, 0xFF]);
    }
    egui::viewport::IconData {
        rgba,
        width: SIZE,
        height: SIZE,
    }
}

// ── Fonts ───────────────────────────────────────────────────────────────────

/// Installs [`UI_FONT`] (Atkinson Hyperlegible) as the only proportional and
/// monospace family. Required because eframe is built without `default_fonts`,
/// so egui otherwise ships no fonts at all. `.strong()` text stays single-weight
/// (egui renders it brighter, not bolder).
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::empty();
    fonts.font_data.insert(
        "atkinson".to_owned(),
        Arc::new(egui::FontData::from_static(UI_FONT)),
    );
    let family = vec!["atkinson".to_owned()];
    fonts
        .families
        .insert(egui::FontFamily::Proportional, family.clone());
    fonts.families.insert(egui::FontFamily::Monospace, family);
    ctx.set_fonts(fonts);
}

// ── Visuals ───────────────────────────────────────────────────────────────────

/// Applies the Nomad dark visuals to the egui context, deriving widget styling
/// (buttons, hover, selection) from the palette + `accent` so default egui
/// widgets match the bespoke cards instead of rendering as stock gray.
fn setup_visuals(ctx: &egui::Context, accent: egui::Color32) {
    let mut vis = egui::Visuals::dark();
    vis.panel_fill = theme::BG;
    vis.window_fill = theme::BG;
    vis.override_text_color = Some(theme::TEXT_PRIMARY);
    vis.hyperlink_color = accent;

    let radius = egui::CornerRadius::same(theme::RADIUS_CARD);
    let w = &mut vis.widgets;
    // Resting button: card surface with a hairline border.
    w.inactive.bg_fill = theme::CARD;
    w.inactive.weak_bg_fill = theme::CARD;
    w.inactive.bg_stroke = egui::Stroke::new(1.0, theme::BORDER);
    w.inactive.fg_stroke = egui::Stroke::new(1.0, theme::TEXT_PRIMARY);
    w.inactive.corner_radius = radius;
    // Hover: lift to the border tone, accent outline.
    w.hovered.bg_fill = theme::BORDER;
    w.hovered.weak_bg_fill = theme::BORDER;
    w.hovered.bg_stroke = egui::Stroke::new(1.0, accent);
    w.hovered.fg_stroke = egui::Stroke::new(1.0, theme::TEXT_PRIMARY);
    w.hovered.corner_radius = radius;
    // Pressed/active: accent fill with on-accent ink.
    w.active.bg_fill = accent;
    w.active.weak_bg_fill = accent;
    w.active.bg_stroke = egui::Stroke::new(1.0, accent);
    w.active.fg_stroke = egui::Stroke::new(1.0, theme::ON_ACCENT);
    w.active.corner_radius = radius;

    vis.selection.bg_fill = accent.gamma_multiply(0.4);
    vis.selection.stroke = egui::Stroke::new(1.0, accent);
    ctx.set_visuals(vis);
}

// ── Entry points ──────────────────────────────────────────────────────────────

/// Opens the Nomad status window with a static [`LauncherView`] and blocks
/// until the user closes it.
///
/// This is a thin wrapper around [`show_window_driven`] with a no-op pipeline,
/// used by the `ui_preview` example and for manual visual checks.
///
/// # Errors
/// Returns an [`eframe::Error`] if the windowing backend cannot be
/// initialised (e.g. no GPU / display available).
pub fn show_window(view: LauncherView) -> Result<(), eframe::Error> {
    show_window_driven(view, |_state, _ctx| {
        // Static preview: no pipeline. The window stays open until the user
        // closes it with the window controls.
    })
}

/// Opens the Nomad status window, immediately starts the pipeline on a
/// background thread, and blocks until the window is closed.
///
/// `start_pipeline` receives the [`StateHandle`] and a cloned
/// [`egui::Context`]; it should update the state and call
/// [`egui::Context::request_repaint`] after each change. The function is
/// called exactly once at window creation.
///
/// The pipeline drives the window by setting [`NomadState::phase`]:
/// - [`WindowPhase::Done`] → window closes itself.
/// - [`WindowPhase::Error`] → window shows error buttons.
/// - [`WindowPhase::UpdatePrompt`] → window shows Update / Launch-current.
///
/// # Errors
/// Returns an [`eframe::Error`] if the windowing backend cannot be
/// initialised.
pub fn show_window_driven<F>(view: LauncherView, start_pipeline: F) -> Result<(), eframe::Error>
where
    F: Fn(StateHandle, egui::Context) + Send + Sync + 'static,
{
    let title = format!("{} \u{2014} Nomad Launcher", view.display_name);
    let accent = view.accent;
    let icon = view
        .icon_bytes
        .and_then(parse_ico_icon)
        .unwrap_or_else(|| make_placeholder_icon(accent));

    let state: StateHandle = Arc::new((
        Mutex::new(NomadState {
            view,
            phase: WindowPhase::Running,
        }),
        Condvar::new(),
    ));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size([460.0, 380.0])
            .with_resizable(false)
            .with_maximize_button(false)
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "Nomad Launcher",
        options,
        Box::new(move |cc| {
            install_fonts(&cc.egui_ctx);
            setup_visuals(&cc.egui_ctx, accent);

            // Start the pipeline on a dedicated background thread.
            let state_bg = Arc::clone(&state);
            let ctx_bg = cc.egui_ctx.clone();
            std::thread::spawn(move || start_pipeline(state_bg, ctx_bg));

            Ok(Box::new(NomadWindow {
                state,
                logo: None,
                nomad_logo: None,
                taskbar: crate::taskbar::TaskbarProgress::new(),
                hwnd: None,
            }))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_nomad_emblem_decodes() {
        // The footer emblem is a hand-built multi-res PNG-framed ICO; verify it
        // decodes through the same path the window uses, so a malformed asset
        // fails the build rather than silently falling back to the painter mark.
        let (rgba, w, h) = decode_ico_rgba(NOMAD_EMBLEM_ICO, 64).expect("emblem ICO must decode");
        assert!(w > 0 && h > 0, "decoded emblem must be non-empty");
        assert_eq!(rgba.len(), (w * h * 4) as usize, "RGBA8 buffer size");
        // The emblem is square (wordmark cropped, padded to a square canvas).
        assert_eq!(w, h, "emblem frame must be square");
    }
}
