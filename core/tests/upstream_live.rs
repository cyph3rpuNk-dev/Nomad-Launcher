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
//! them the way a reimplementation in CI script would. The assertion mirrors
//! what `verify_package` requires: a usable GPG signature, or a checksum.
//!
//! Ignored by default because they hit the network and depend on upstream
//! availability. The weekly upstream-drift workflow runs them with `--ignored`.
//!
//! Run locally with:
//!   cargo test -p nomad-core --test upstream_live -- --ignored --nocapture

use nomad_core::{
    Arch, Bitwarden, BrowserFamily, Firefox, Floorp, Helium, Librewolf, Mullvad, UngoogledChromium,
    Waterfox,
};

/// Resolves the current upstream release and asserts it could actually be
/// verified if it were downloaded.
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

    // Mirrors verify_package: a GPG check needs both an embedded key and a
    // published signature; otherwise a hash is the only thing standing between
    // the download and the disk.
    let gpg = browser.public_key().is_some() && info.signature_url.is_some();
    let hash = info.sha256.is_some() || info.sha512.is_some();

    assert!(
        gpg || hash,
        "{id}: release {} resolved with no usable signature and no checksum, so \
         verify_package will refuse to install it. Upstream has probably changed \
         the name, location, or format of its checksum file, or stopped \
         publishing one.",
        info.browser_version
    );

    println!(
        "ok  {id}: {} (gpg={gpg}, sha256={}, sha512={})",
        info.browser_version,
        info.sha256.is_some(),
        info.sha512.is_some()
    );
}

#[tokio::test]
#[ignore = "hits the network; run via the weekly upstream-drift job"]
async fn firefox_release_is_verifiable() {
    assert_verifiable(&Firefox::new(Arch::X64)).await;
}

#[tokio::test]
#[ignore = "hits the network; run via the weekly upstream-drift job"]
async fn firefox_esr_release_is_verifiable() {
    assert_verifiable(&Firefox::new_esr(Arch::X64)).await;
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

#[tokio::test]
#[ignore = "hits the network; run via the weekly upstream-drift job"]
async fn bitwarden_release_is_verifiable() {
    assert_verifiable(&Bitwarden::new(Arch::X64)).await;
}
