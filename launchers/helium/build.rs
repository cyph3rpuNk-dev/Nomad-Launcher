// Helium brand icon — manually sourced and committed to assets/icon.ico.
// Update assets/icon.ico with a fresh copy from the Helium project when the
// branding changes; the build will automatically pick it up.
//
// Placeholder size (grey ungoogled-chromium fallback): 54 140 bytes.
// If icon.ico is missing or reverted to that size the build aborts with a
// clear error so the problem is never silently ignored.

const PLACEHOLDER_SIZE: u64 = 54140;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icon.ico");

    check_icon();

    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        let ver = format!("{}.0", env!("CARGO_PKG_VERSION"));
        res.set("FileDescription", "Nomad Launcher \u{2014} Helium");
        res.set("ProductName", "Nomad Launcher");
        res.set("FileVersion", &ver);
        res.set("ProductVersion", &ver);
        res.set("InternalName", "Nomad-Helium");
        res.set("OriginalFilename", "Nomad-Helium.exe");
        res.set("LegalCopyright", "\u{00a9} 2026 Cyph3rpuNk-dev");
        res.compile().expect("failed to compile Windows resources");
    }
}

fn check_icon() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let icon_path = std::path::Path::new(&manifest).join("assets/icon.ico");

    match std::fs::metadata(&icon_path) {
        Ok(m) if m.len() == PLACEHOLDER_SIZE => {
            panic!(
                "launchers/helium/assets/icon.ico is still the grey placeholder — \
                 replace it with the real Helium brand icon before building"
            );
        }
        Err(_) => {
            panic!(
                "launchers/helium/assets/icon.ico is missing — \
                 add the Helium brand icon before building"
            );
        }
        Ok(_) => {}
    }
}
