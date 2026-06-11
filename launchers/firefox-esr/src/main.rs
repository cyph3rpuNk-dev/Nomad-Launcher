#![deny(clippy::all, clippy::pedantic)]
#![windows_subsystem = "windows"]

//! Nomad Launcher binary for Firefox ESR.

use std::process::ExitCode;

/// Firefox ESR icon embedded at compile time (placeholder — replace before release).
static ICON: &[u8] = include_bytes!("../assets/icon.ico");

fn main() -> ExitCode {
    nomad_core::run(nomad_core::Firefox::new_esr, ICON, None)
}
