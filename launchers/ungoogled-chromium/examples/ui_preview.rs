//! Visual preview of the Nomad status window with a static `LauncherView`.
//!
//! Run with:
//!   cargo run -p nomad-ungoogled-chromium --example ui_preview

static ICON: &[u8] = include_bytes!("../assets/icon.ico");

fn main() {
    let view = nomad_core::ui::LauncherView {
        display_name: "Ungoogled Chromium".to_owned(),
        id: "ungoogled-chromium".to_owned(),
        arch: "x64".to_owned(),
        browser_version: Some("148.0.7778.96-1.1".to_owned()),
        engine_name: "Chromium".to_owned(),
        engine_version: Some("148.0.7778.96".to_owned()),
        build_date: None,
        upstream_url: "https://github.com/ungoogled-software/ungoogled-chromium/releases"
            .to_owned(),
        status: nomad_core::ui::StatusLines {
            primary: "Checking for updates\u{2026}".to_owned(),
            secondary: "Fetching GitHub release metadata".to_owned(),
        },
        progress: nomad_core::ui::ProgressState::Indeterminate,
        icon_bytes: Some(ICON),
        accent: nomad_core::ui::theme::ACCENT,
    };

    if let Err(e) = nomad_core::ui::show_window(view) {
        eprintln!("window error: {e}");
        std::process::exit(1);
    }
}
