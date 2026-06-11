#![deny(clippy::all, clippy::pedantic)]
// Build as a Windows GUI (windowed) application so launching the .exe does
// not spawn a console window.
#![windows_subsystem = "windows"]

//! Nomad Launcher binary for Helium.

use std::process::ExitCode;

/// Helium icon embedded at compile time (placeholder — replace before release).
static ICON: &[u8] = include_bytes!("../assets/icon.ico");

fn main() -> ExitCode {
    nomad_core::run(nomad_core::Helium::new, ICON, None)
}
