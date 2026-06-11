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

use nomad_core::{Branding, BrandingGroup, BrandingIcon, PakPatch};

/// Ungoogled-Chromium icon, embedded at compile time from the launcher's
/// `assets/` directory and used for the status-window title bar and taskbar.
static ICON: &[u8] = include_bytes!("../assets/icon.ico");

/// Browser branding: the grayscale icons written into `chrome.exe` /
/// `chrome.dll` after install so the browser's taskbar button, Alt-Tab entry
/// and window icon match the launcher.
///
/// The five icon groups and their resource names mirror the set Chromium
/// builds embed (numeric `100` plus the four `IDR_*` named groups).
static BRANDING: Branding = Branding {
    targets: &["chrome.exe", "chrome.dll"],
    icons: &[
        BrandingIcon {
            group: BrandingGroup::Id(100),
            ico: include_bytes!("../assets/branding/icon_100.ico"),
        },
        // chrome.dll stores `IDR_MAINFRAME` as numeric 101 (per
        // `chrome_dll_resource.h`), and `chrome/browser/win/app_icon.cc` loads
        // it by integer ID — this is the resource that drives the window icon
        // (Snap Layouts, Alt-Tab, title bar, taskbar button). The string-named
        // entry below covers chrome.exe, which stores it as a named resource.
        BrandingIcon {
            group: BrandingGroup::Id(101),
            ico: include_bytes!("../assets/branding/icon_mainframe.ico"),
        },
        BrandingIcon {
            group: BrandingGroup::Named("IDR_MAINFRAME"),
            ico: include_bytes!("../assets/branding/icon_mainframe.ico"),
        },
        BrandingIcon {
            group: BrandingGroup::Named("IDR_X001_APP_LIST"),
            ico: include_bytes!("../assets/branding/icon_app_list.ico"),
        },
        BrandingIcon {
            group: BrandingGroup::Named("IDR_X006_HTML_DOC"),
            ico: include_bytes!("../assets/branding/icon_html_doc.ico"),
        },
        BrandingIcon {
            group: BrandingGroup::Named("IDR_X007_PDF_DOC"),
            ico: include_bytes!("../assets/branding/icon_pdf_doc.ico"),
        },
    ],
    // Replace the blue Chromium product-logo resources with the grayscale
    // launcher icon.  IDs are identified by extracting every PNG from
    // chrome_{100,200}_percent.pak and visually confirming the Chromium ball.
    //
    // When a Chromium update breaks the logo patch (branding.rs warns
    // "PAK resource is not the expected logo image"), re-derive the IDs:
    //
    //   $pak = [IO.File]::ReadAllBytes('Browser\chrome_100_percent.pak')
    //   # parse PAK v5 entries, check each for PNG sig + IHDR dims
    //   # grep for 32x32 (100%) and 64x64 (200%) near the current IDs
    //
    // Last verified for ungoogled-chromium 149.0.7827.x (2026-06-08).
    pak_patches: &[
        // Main product logo — chrome://settings/help (current-channel-logo).
        // 32px logical: 32×32 in 100% pak, 64×64 in 200% pak.
        // (Was id=16324 in ≤148.x; shifted to 16325 in 149.x.)
        PakPatch {
            pak_file: "chrome_100_percent.pak",
            resource_id: 16325,
            png_bytes: include_bytes!("../assets/branding/product_logo_32.png"),
        },
        PakPatch {
            pak_file: "chrome_200_percent.pak",
            resource_id: 16325,
            png_bytes: include_bytes!("../assets/branding/product_logo_64.png"),
        },
        // Small logo variant — 16px logical: 16×16 in 100% pak, 32×32 in 200% pak.
        // (Was id=16323/16326 in ≤148.x; consolidated at 16327 in 149.x.)
        PakPatch {
            pak_file: "chrome_100_percent.pak",
            resource_id: 16327,
            png_bytes: include_bytes!("../assets/branding/product_logo_16.png"),
        },
        PakPatch {
            pak_file: "chrome_200_percent.pak",
            resource_id: 16327,
            png_bytes: include_bytes!("../assets/branding/product_logo_32.png"),
        },
    ],
};

fn main() -> ExitCode {
    nomad_core::run(nomad_core::UngoogledChromium::new, ICON, Some(&BRANDING))
}
