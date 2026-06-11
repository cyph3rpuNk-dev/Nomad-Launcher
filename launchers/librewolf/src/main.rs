#![deny(clippy::all, clippy::pedantic)]
#![windows_subsystem = "windows"]

//! Nomad Launcher binary for `LibreWolf`.

use std::process::ExitCode;

/// `LibreWolf` icon embedded at compile time.
static ICON: &[u8] = include_bytes!("../assets/icon.ico");

fn main() -> ExitCode {
    nomad_core::run(nomad_core::Librewolf::new, ICON, None)
}
