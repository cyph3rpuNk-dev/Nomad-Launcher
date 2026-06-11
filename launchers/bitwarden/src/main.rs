#![deny(clippy::all, clippy::pedantic)]
#![windows_subsystem = "windows"]

//! Nomad Launcher binary for Bitwarden (portable desktop app).

use std::process::ExitCode;

/// Bitwarden icon embedded at compile time.
static ICON: &[u8] = include_bytes!("../assets/icon.ico");

fn main() -> ExitCode {
    // No PE-icon branding payload: Bitwarden ships its own portable .exe with
    // its own icon, which Nomad does not rewrite.
    nomad_core::run(nomad_core::Bitwarden::new, ICON, None)
}
