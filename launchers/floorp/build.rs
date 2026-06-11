// Official Floorp brand icon (Floorp installer assets), vendored at
// assets/icon.ico — no build-time network fetch (CLAUDE.md invariant #6):
// https://raw.githubusercontent.com/Floorp-Projects/Floorp/main/static/installers/stub-win64-installer/src-tauri/icons/icon.ico

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icon.ico");

    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        let ver = format!("{}.0", env!("CARGO_PKG_VERSION"));
        res.set("FileDescription", "Nomad Launcher \u{2014} Floorp");
        res.set("ProductName", "Nomad Launcher");
        res.set("FileVersion", &ver);
        res.set("ProductVersion", &ver);
        res.set("InternalName", "Nomad-Floorp");
        res.set("OriginalFilename", "Nomad-Floorp.exe");
        res.set("LegalCopyright", "\u{00a9} 2026 Cyph3rpuNk-dev");
        res.compile().expect("failed to compile Windows resources");
    }
}
