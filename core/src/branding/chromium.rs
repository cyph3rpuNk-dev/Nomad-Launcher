//! Required Chromium overlays shared by GUI, headless updates, and live checks.

use super::{Branding, BrandingGroup, BrandingIcon, PakPatch};

/// Browser branding: the grayscale icons written into `chrome.exe` /
/// `chrome.dll` after install so the browser's taskbar button, Alt-Tab entry
/// and window icon match the launcher.
///
/// The five icon groups and their resource names mirror the set Chromium
/// builds embed (numeric `100` plus the four `IDR_*` named groups).
pub static CHROMIUM: Branding = Branding {
    targets: &["chrome.exe", "chrome.dll"],
    icons: &[
        BrandingIcon {
            group: BrandingGroup::Id(100),
            ico: include_bytes!("../../payloads/chromium/branding/icon_100.ico"),
        },
        // chrome.dll stores `IDR_MAINFRAME` as numeric 101 (per
        // `chrome_dll_resource.h`), and `chrome/browser/win/app_icon.cc` loads
        // it by integer ID — this is the resource that drives the window icon
        // (Snap Layouts, Alt-Tab, title bar, taskbar button). The string-named
        // entry below covers chrome.exe, which stores it as a named resource.
        BrandingIcon {
            group: BrandingGroup::Id(101),
            ico: include_bytes!("../../payloads/chromium/branding/icon_mainframe.ico"),
        },
        BrandingIcon {
            group: BrandingGroup::Named("IDR_MAINFRAME"),
            ico: include_bytes!("../../payloads/chromium/branding/icon_mainframe.ico"),
        },
        BrandingIcon {
            group: BrandingGroup::Named("IDR_X001_APP_LIST"),
            ico: include_bytes!("../../payloads/chromium/branding/icon_app_list.ico"),
        },
        BrandingIcon {
            group: BrandingGroup::Named("IDR_X006_HTML_DOC"),
            ico: include_bytes!("../../payloads/chromium/branding/icon_html_doc.ico"),
        },
        BrandingIcon {
            group: BrandingGroup::Named("IDR_X007_PDF_DOC"),
            ico: include_bytes!("../../payloads/chromium/branding/icon_pdf_doc.ico"),
        },
    ],
    // Match the reviewed upstream PNG pixels, independent of grit IDs.
    // See payloads/chromium/logos/README.md for source and licensing.
    pak_patches: &[
        // Main product logo — chrome://settings/help (current-channel-logo).
        // 32px logical: 32×32 in 100% pak, 64×64 in 200% pak.
        // (Was id=16324 in <=148.x, 16325 in 149.x, 15315 in 150.x,
        // 15317 in 151.x; shifted to 14321 in 152.x.)
        PakPatch {
            pak_file: "chrome_100_percent.pak",
            resource_id: 14321,
            expected_png_bytes: include_bytes!(
                "../../payloads/chromium/logos/product_logo_32_100.png"
            ),
            png_bytes: include_bytes!("../../payloads/chromium/branding/product_logo_32.png"),
        },
        PakPatch {
            pak_file: "chrome_200_percent.pak",
            resource_id: 14321,
            expected_png_bytes: include_bytes!(
                "../../payloads/chromium/logos/product_logo_32_200.png"
            ),
            png_bytes: include_bytes!("../../payloads/chromium/branding/product_logo_64.png"),
        },
        // Small logo variant — 16px logical: 16×16 in 100% pak, 32×32 in 200% pak.
        // (Was id=16323/16326 in <=148.x, 16327 in 149.x, 15317 in 150.x,
        // 15319 in 151.x; shifted to 14323 in 152.x.)
        PakPatch {
            pak_file: "chrome_100_percent.pak",
            resource_id: 14323,
            expected_png_bytes: include_bytes!(
                "../../payloads/chromium/logos/product_logo_16_100.png"
            ),
            png_bytes: include_bytes!("../../payloads/chromium/branding/product_logo_16.png"),
        },
        PakPatch {
            pak_file: "chrome_200_percent.pak",
            resource_id: 14323,
            expected_png_bytes: include_bytes!(
                "../../payloads/chromium/logos/product_logo_16_200.png"
            ),
            png_bytes: include_bytes!("../../payloads/chromium/branding/product_logo_32.png"),
        },
    ],
};
