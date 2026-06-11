fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icon.ico");

    // Embed the ungoogled-chromium icon and version metadata into the .exe on
    // Windows.  On other platforms (CI cross-compile, etc.) this is a no-op.
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        let ver = format!("{}.0", env!("CARGO_PKG_VERSION"));
        res.set(
            "FileDescription",
            "Nomad Launcher \u{2014} Ungoogled Chromium",
        );
        res.set("ProductName", "Nomad Launcher");
        res.set("FileVersion", &ver);
        res.set("ProductVersion", &ver);
        res.set("InternalName", "Nomad-Chromium");
        res.set("OriginalFilename", "Nomad-Chromium.exe");
        res.set("LegalCopyright", "\u{00a9} 2026 Cyph3rpuNk-dev");
        res.compile().expect("failed to compile Windows resources");
    }
}
