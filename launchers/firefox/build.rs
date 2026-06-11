// Official Firefox brand icon (Mozilla Software Releases), vendored at
// assets/icon.ico — no build-time network fetch (CLAUDE.md invariant #6):
// https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main/browser/branding/official/firefox.ico

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icon.ico");

    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        let ver = format!("{}.0", env!("CARGO_PKG_VERSION"));
        res.set("FileDescription", "Nomad Launcher \u{2014} Firefox");
        res.set("ProductName", "Nomad Launcher");
        res.set("FileVersion", &ver);
        res.set("ProductVersion", &ver);
        res.set("InternalName", "Nomad-Firefox");
        res.set("OriginalFilename", "Nomad-Firefox.exe");
        res.set("LegalCopyright", "\u{00a9} 2026 Cyph3rpuNk-dev");
        res.compile().expect("failed to compile Windows resources");
    }
}
