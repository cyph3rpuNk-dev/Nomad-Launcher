//! Live checks that every launcher can still verify a download.
//!
//! Nomad pins assumptions about how each upstream publishes its integrity
//! material: the name and format of a checksum file, the key an entry is filed
//! under, the presence of a GitHub asset digest. Upstreams change those without
//! notice, and when one does, the affected launcher stops being able to install
//! or update at all. `verify_package` fails closed, which is correct, but the
//! failure is invisible until somebody runs the launcher.
//!
//! Two releases in a row shipped a launcher broken exactly this way. v1.0.5
//! shipped a Firefox that could not install, because Mozilla added a signing
//! subkey after the embedded key snapshot was taken. v1.0.6 shipped a Floorp
//! that could not install, because Floorp moved `hashes.txt` to standard
//! `sha256sum` lines and dropped the `win-dist/` prefix from its filenames.
//! Neither was detectable from inside the repository.
//!
//! These tests call the real `fetch_latest_version` against the real endpoints,
//! so they exercise the same parsers the launcher uses and cannot drift from
//! them the way a reimplementation in CI script would. The assertion uses the
//! production metadata preflight: a required signature URL cannot fall back to
//! a checksum. This checks metadata availability, not package authenticity.
//!
//! Ignored by default because they hit the network and depend on upstream
//! availability. The weekly upstream-drift workflow runs them with `--ignored`.
//!
//! Run locally with:
//!   cargo test -p nomad-core --test upstream_live --locked --target x86_64-pc-windows-msvc -- --ignored --nocapture

use nomad_core::{
    Arch, BrowserFamily, Floorp, Helium, Librewolf, Mullvad, UngoogledChromium, VersionInfo,
    Waterfox,
};

/// Resolves the current upstream release and checks its verification metadata.
/// Package downloads and cryptographic verification are separate checks.
///
/// A failure here means one of two things, both of which leave the launcher
/// unable to install anything: the release metadata no longer parses, or it
/// parses but yields nothing to check the download against.
async fn assert_verifiable<B: BrowserFamily>(browser: &B) {
    let id = browser.id();
    let info = match browser.fetch_latest_version().await {
        Ok(info) => info,
        Err(e) => panic!(
            "{id}: could not resolve a release from upstream: {e}\n\
             The launcher cannot install or update in this state. Upstream has \
             probably changed its release metadata, asset naming, or signing key."
        ),
    };

    assert!(
        !info.browser_version.is_empty(),
        "{id}: upstream resolved an empty version string"
    );
    assert!(
        !info.download_url.is_empty(),
        "{id}: upstream resolved no download URL"
    );

    assert_verification_metadata(browser, &info);
    let gpg = browser.public_key().is_some() && info.signature_url.is_some();

    browser.validate_update(&info).unwrap_or_else(|error| {
        panic!(
            "{id}: release {} is incompatible with this launcher: {error}",
            info.browser_version
        )
    });

    println!(
        "ok  {id}: {} (gpg={gpg}, sha256={}, sha512={})",
        info.browser_version,
        info.sha256.is_some(),
        info.sha512.is_some()
    );
}

#[tokio::test]
#[ignore = "hits the network; run via the weekly upstream-drift job"]
async fn floorp_release_is_verifiable() {
    assert_verifiable(&Floorp::new(Arch::X64)).await;
}

#[tokio::test]
#[ignore = "hits the network; run via the weekly upstream-drift job"]
async fn waterfox_release_is_verifiable() {
    assert_verifiable(&Waterfox::new(Arch::X64)).await;
}

#[tokio::test]
#[ignore = "hits the network; run via the weekly upstream-drift job"]
async fn librewolf_release_is_verifiable() {
    assert_verifiable(&Librewolf::new(Arch::X64)).await;
}

#[tokio::test]
#[ignore = "hits the network; run via the weekly upstream-drift job"]
async fn mullvad_release_is_verifiable() {
    assert_verifiable(&Mullvad::new(Arch::X64)).await;
}

#[tokio::test]
#[ignore = "hits the network; run via the weekly upstream-drift job"]
async fn ungoogled_chromium_release_is_verifiable() {
    assert_verifiable(&UngoogledChromium::new(Arch::X64)).await;
}

#[tokio::test]
#[ignore = "hits the network; run via the weekly upstream-drift job"]
async fn helium_release_is_verifiable() {
    assert_verifiable(&Helium::new(Arch::X64)).await;
}

fn assert_verification_metadata<B: BrowserFamily>(browser: &B, info: &VersionInfo) {
    let id = browser.id();
    nomad_core::updater::validate_verification_metadata(browser, info).unwrap_or_else(|error| {
        panic!(
            "{id}: release {} lacks required verification metadata: {error}",
            info.browser_version
        )
    });
}

#[test]
fn missing_required_signature_cannot_pass_live_preflight_with_a_hash() {
    let browser = Mullvad::new(Arch::X64);
    for sha512 in [false, true] {
        let info = VersionInfo {
            browser_version: "2.0".into(),
            engine_version: "2.0".into(),
            download_url: "https://example.invalid/package.exe".into(),
            signature_url: None,
            sha256: (!sha512).then(|| "0".repeat(64)),
            sha512: sha512.then(|| "0".repeat(128)),
        };
        assert!(
            std::panic::catch_unwind(|| assert_verification_metadata(&browser, &info)).is_err()
        );
    }
}

#[test]
fn live_preflight_covers_signature_and_digest_availability() {
    let signed = Mullvad::new(Arch::X64);
    let unsigned = UngoogledChromium::new(Arch::X64);
    for signature in [false, true] {
        for digest in [0, 256, 512] {
            let info = VersionInfo {
                browser_version: "2.0".into(),
                engine_version: "2.0".into(),
                download_url: "https://example.invalid/package.exe".into(),
                signature_url: signature.then(|| "https://example.invalid/package.sig".into()),
                sha256: (digest == 256).then(|| "0".repeat(64)),
                sha512: (digest == 512).then(|| "0".repeat(128)),
            };
            assert_eq!(
                std::panic::catch_unwind(|| assert_verification_metadata(&signed, &info)).is_ok(),
                signature,
                "signed adapter: signature={signature}, digest={digest}"
            );
            assert_eq!(
                std::panic::catch_unwind(|| assert_verification_metadata(&unsigned, &info)).is_ok(),
                digest != 0,
                "hash-only adapter: signature={signature}, digest={digest}"
            );
        }
    }
}
