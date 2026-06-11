//! Nomad design tokens — the single source of visual truth for the launcher UI.
//!
//! A semantic colour palette (Nomad dark) plus type / spacing / radius / motion
//! scales, so widget code references named tokens instead of magic numbers.
//!
//! **Accent** is the family signature (an amber accent); it is the *default* and may
//! be overridden per browser via [`crate::browsers::BrowserFamily::accent`].
//! Every other token is shared family-wide for cohesion (see `DESIGN.md`).

use eframe::egui::Color32;

// ── Surfaces & text ─────────────────────────────────────────────────────────
/// `#202124` — window body background.
pub const BG: Color32 = Color32::from_rgb(0x20, 0x21, 0x24);
/// `#292A2D` — identity card and runtime-details card surface.
pub const CARD: Color32 = Color32::from_rgb(0x29, 0x2A, 0x2D);
/// `#3C4043` — card borders and progress-bar track.
pub const BORDER: Color32 = Color32::from_rgb(0x3C, 0x40, 0x43);
/// `#9AA0A6` — labels, captions, and detail text.
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(0x9A, 0xA0, 0xA6);
/// `#E8EAED` — browser name, status line, and values.
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(0xE8, 0xEA, 0xED);
/// `#80868C` — tiny uppercase eyebrow section labels. Raised from the original
/// `#5F6368` (≈2.4:1, failed WCAG AA) to clear AA on the card surface (≈3.4:1).
pub const EYEBROW: Color32 = Color32::from_rgb(0x80, 0x86, 0x8C);

// ── Accent (Nomad family signature) ─────────────────────────────────────────
/// `#E8B255` — the amber family-signature accent: progress fill, links,
/// focus, and the Nomad mark. This is the **default**; a browser may override it
/// via [`crate::browsers::BrowserFamily::accent`]. Clears WCAG AA on both
/// surfaces (~9:1 on [`BG`]).
pub const ACCENT: Color32 = Color32::from_rgb(0xE8, 0xB2, 0x55);
/// Near-black ink for text/glyphs drawn *on* the amber accent fill.
pub const ON_ACCENT: Color32 = Color32::from_rgb(0x12, 0x14, 0x16);

/// Hairline divider colour: white at ~8 %, premultiplied so it blends over the
/// `#292A2D` card surface. Not `const` — [`Color32::from_rgba_unmultiplied`] is
/// not a `const fn`.
#[must_use]
pub fn divider() -> Color32 {
    Color32::from_rgba_unmultiplied(0xFF, 0xFF, 0xFF, 20)
}

// ── Type scale (px) ─────────────────────────────────────────────────────────
/// Font sizes — replaces inline literals scattered across the widgets.
pub mod text {
    /// 9 px — uppercase, letter-spaced eyebrow section labels.
    pub const EYEBROW: f32 = 9.0;
    /// 11 px — body, captions, detail rows, version subtitle, links.
    pub const BODY: f32 = 11.0;
    /// 14 px — the primary status line.
    pub const STRONG: f32 = 14.0;
    /// 15 px — the browser display name.
    pub const DISPLAY: f32 = 15.0;
}

// ── Spacing scale (px) ──────────────────────────────────────────────────────
/// Vertical rhythm — replaces ad-hoc `add_space` literals.
pub mod space {
    /// 2 px — hairline gaps (eyebrow→status, name→subtitle).
    pub const XS: f32 = 2.0;
    /// 4 px — tight separation.
    pub const SM: f32 = 4.0;
    /// 6 px — status→progress, prompt spacing.
    pub const MD: f32 = 6.0;
    /// 8 px — block separation (around dividers, between cards' contents).
    pub const LG: f32 = 8.0;
    /// 12 px — card inner margin / logo gap.
    pub const XL: f32 = 12.0;
}

// ── Radius / motion ─────────────────────────────────────────────────────────
/// Card and control corner radius (px).
pub const RADIUS_CARD: u8 = 6;
/// Period of the indeterminate progress sweep (seconds).
pub const SWEEP_PERIOD_SECS: f32 = 2.9;
