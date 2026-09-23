#![deny(clippy::all, clippy::pedantic)]
// Build as a Windows GUI (windowed) application so launching the .exe does
// not spawn a console window.  Diagnostics go to `nomad.log` beside the .exe.
#![windows_subsystem = "windows"]

//! Nomad Launcher binary for ungoogled-chromium.
//!
//! The entire launcher is one call: `nomad_core::run` loads `nomad.toml`,
//! constructs the browser for the configured architecture, updates the
//! install, and launches it.

use std::process::ExitCode;

use nomad_core::branding::CHROMIUM;

/// Ungoogled-Chromium icon, embedded at compile time from the launcher's
/// `assets/` directory and used for the status-window title bar and taskbar.
static ICON: &[u8] = include_bytes!("../assets/icon.ico");

fn main() -> ExitCode {
    nomad_core::run(nomad_core::UngoogledChromium::new, ICON, Some(&CHROMIUM))
}
