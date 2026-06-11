#![deny(clippy::all, clippy::pedantic)]
#![windows_subsystem = "windows"]

//! Nomad Launcher binary for Helium.

use std::process::ExitCode;

/// Helium icon embedded at compile time.
static ICON: &[u8] = include_bytes!("../assets/icon.ico");

fn main() -> ExitCode {
    nomad_core::run(nomad_core::Helium::new, ICON, None)
}
