// Icon: Mullvad Browser VisualElements_150.png, sourced from the installed
// browser's browser/VisualElements/ directory. winresource accepts PNG directly.
// Update assets/icon.ico from a newer Mullvad install when branding changes.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icon.ico");

    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        let ver = format!("{}.0", env!("CARGO_PKG_VERSION"));
        res.set("FileDescription", "Nomad Launcher \u{2014} Mullvad Browser");
        res.set("ProductName", "Nomad Launcher");
        res.set("FileVersion", &ver);
        res.set("ProductVersion", &ver);
        res.set("InternalName", "Nomad-Mullvad");
        res.set("OriginalFilename", "Nomad-Mullvad.exe");
        res.set("LegalCopyright", "\u{00a9} 2026 Cyph3rpuNk-dev");
        res.compile().expect("failed to compile Windows resources");
    }
}
