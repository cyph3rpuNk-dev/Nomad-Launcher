//! Identity card widget — the top card in the Nomad status window.
//!
//! Renders the browser logo, display name, version subtitle, eyebrow label,
//! live status lines, and progress bar. All sizing/spacing comes from the
//! [`theme`] tokens; the accent is [`LauncherView::accent`] (the Nomad family
//! signature by default, or a per-browser override).

use eframe::egui::{self, Color32};

use super::{theme, LauncherView, ProgressState};

/// Renders the identity card into `ui`.
///
/// The card contains:
/// 1. Header row (logo + name + version subtitle).
/// 2. Hairline divider.
/// 3. `PORTABLE LAUNCHER` eyebrow, primary status, secondary detail.
/// 4. 3 px progress bar (`BORDER` track / accent fill).
pub fn identity_card(ui: &mut egui::Ui, view: &LauncherView, logo: Option<&egui::TextureHandle>) {
    let frame = egui::Frame::NONE
        .fill(theme::CARD)
        .corner_radius(egui::CornerRadius::same(theme::RADIUS_CARD))
        .inner_margin(egui::Margin::same(12));

    frame.show(ui, |ui| {
        // ── Header: browser logo + name + version subtitle ───────────────────
        ui.horizontal(|ui| {
            browser_logo(ui, &view.display_name, logo, view.accent);
            ui.add_space(theme::space::XL);
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new(&view.display_name)
                        .size(theme::text::DISPLAY)
                        .color(theme::TEXT_PRIMARY)
                        .strong(),
                );
                ui.add_space(theme::space::XS);
                ui.label(
                    egui::RichText::new(view.version_subtitle())
                        .size(theme::text::BODY)
                        .color(theme::TEXT_SECONDARY),
                );
            });
        });

        ui.add_space(theme::space::LG);

        // Hairline divider (rgba(255,255,255,0.08))
        let sep_w = ui.available_width();
        let (sep_rect, _) = ui.allocate_exact_size(egui::vec2(sep_w, 1.0), egui::Sense::hover());
        ui.painter()
            .rect_filled(sep_rect, egui::CornerRadius::default(), theme::divider());

        ui.add_space(theme::space::LG);

        // ── Status block ─────────────────────────────────────────────────────
        ui.label(
            egui::RichText::new("PORTABLE LAUNCHER")
                .size(theme::text::EYEBROW)
                .color(theme::EYEBROW),
        );

        ui.add_space(theme::space::SM);

        ui.label(
            egui::RichText::new(&view.status.primary)
                .size(theme::text::STRONG)
                .color(theme::TEXT_PRIMARY)
                .strong(),
        );

        if !view.status.secondary.is_empty() {
            ui.add_space(theme::space::XS);
            ui.label(
                egui::RichText::new(&view.status.secondary)
                    .size(theme::text::BODY)
                    .color(theme::TEXT_SECONDARY),
            );
        }

        ui.add_space(theme::space::MD);

        // 3 px progress bar
        progress_bar(ui, &view.progress, view.accent);
    });
}

/// 34×34 browser logo.
///
/// When `logo` is `Some`, the decoded browser icon texture is drawn. When it
/// is `None` (icon missing or undecodable), a fallback tile is drawn: the
/// first Unicode character of `display_name`, uppercased, on an `accent` tile.
fn browser_logo(
    ui: &mut egui::Ui,
    display_name: &str,
    logo: Option<&egui::TextureHandle>,
    accent: Color32,
) {
    let size = egui::vec2(34.0, 34.0);

    if let Some(texture) = logo {
        ui.add(
            egui::Image::from_texture(egui::load::SizedTexture::from_handle(texture))
                .fit_to_exact_size(size),
        );
        return;
    }

    // Fallback: accent tile with the browser's first letter in on-accent ink.
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(theme::RADIUS_CARD), accent);
    if let Some(first) = display_name.chars().next() {
        let letter: String = first.to_uppercase().collect();
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            letter,
            egui::FontId::proportional(18.0),
            theme::ON_ACCENT,
        );
    }
}

/// Renders the 3 px progress bar with the `accent` palette.
///
/// * [`ProgressState::Hidden`] — only the track is drawn (acts as an empty
///   placeholder so the card height stays stable).
/// * [`ProgressState::Determinate`] — solid fill from left to right.
/// * [`ProgressState::Indeterminate`] — animated triangle-wave sweep.
fn progress_bar(ui: &mut egui::Ui, state: &ProgressState, accent: Color32) {
    let bar_w = ui.available_width();
    let (track, response) = ui.allocate_exact_size(egui::vec2(bar_w, 3.0), egui::Sense::hover());

    // Track
    ui.painter()
        .rect_filled(track, egui::CornerRadius::same(1), theme::BORDER);

    match state {
        ProgressState::Hidden => {}

        ProgressState::Determinate(f) => {
            let f = f.clamp(0.0, 1.0);
            // Accessibility: expose the download percentage to screen readers as
            // a progress-indicator node (AccessKit, enabled by default in eframe).
            response.widget_info(|| {
                egui::WidgetInfo::labeled(
                    egui::WidgetType::ProgressIndicator,
                    true,
                    format!("Download progress {:.0}%", f * 100.0),
                )
            });
            let fill_w = track.width() * f;
            if fill_w > 0.0 {
                let fill = egui::Rect::from_min_size(track.min, egui::vec2(fill_w, track.height()));
                ui.painter()
                    .rect_filled(fill, egui::CornerRadius::same(1), accent);
            }
        }

        ProgressState::Indeterminate => {
            // Accessibility: an indeterminate progress-indicator node (no value).
            response.widget_info(|| {
                egui::WidgetInfo::labeled(egui::WidgetType::ProgressIndicator, true, "Working")
            });
            // Triangle-wave sweep: 0 → 1 → 0 over one `SWEEP_PERIOD_SECS`.
            #[allow(clippy::cast_possible_truncation)]
            let t = ui.input(|i| i.time) as f32;
            let rate = 2.0 / theme::SWEEP_PERIOD_SECS;
            let p = (t * rate).rem_euclid(2.0); // 0 .. 2
            let phase = if p < 1.0 { p } else { 2.0 - p }; // 0 .. 1 .. 0
            let pill_w = track.width() * 0.35;
            let start_x = track.min.x + (track.width() - pill_w) * phase;
            let fill = egui::Rect::from_min_size(
                egui::pos2(start_x, track.min.y),
                egui::vec2(pill_w, track.height()),
            );
            ui.painter()
                .rect_filled(fill, egui::CornerRadius::same(1), accent);
            // Keep repainting while the animation is running.
            ui.ctx().request_repaint();
        }
    }
}
