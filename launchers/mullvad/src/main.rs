#![deny(clippy::all, clippy::pedantic)]
#![windows_subsystem = "windows"]

//! Nomad Launcher binary for Mullvad Browser.

use std::process::ExitCode;

/// Mullvad Browser icon embedded at compile time.
static ICON: &[u8] = include_bytes!("../assets/icon.ico");

fn main() -> ExitCode {
    nomad_core::run(nomad_core::Mullvad::new, ICON, None)
}
