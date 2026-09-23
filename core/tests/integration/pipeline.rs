//! Integration test: the full headless update pipeline — update check,
//! download, SHA-256 verification, extract, version marker — against a mock
//! server.

use std::io::Write;

use httpmock::prelude::*;
use nomad_core::browsers::ungoogled::UngoogledChromium;
use nomad_core::browsers::BrowserFamily;
use nomad_core::config::Arch;
use nomad_core::gpg::sha256;
use nomad_core::updater::{self, UpdateOptions, UpdateOutcome};

/// Builds an in-memory zip mimicking an ungoogled-chromium release archive.
fn fixture_zip(valid_logos: bool) -> Vec<u8> {
    let executable = pe_fixture();
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
        writer.start_file("uc-148/chrome.exe", opts).unwrap();
        // An inert PE fixture, never executed. Windows resource updates require
        // a real PE, so reuse the repository's bundled extractor in the sandbox.
        writer.write_all(&executable).unwrap();
        writer.start_file("uc-148/chrome.dll", opts).unwrap();
        writer.write_all(&executable).unwrap();
        for name in ["resources.pak", "icudtl.dat"] {
            writer.start_file(format!("uc-148/{name}"), opts).unwrap();
            writer.write_all(b"fixture").unwrap();
        }
        for name in ["chrome_100_percent.pak", "chrome_200_percent.pak"] {
            writer.start_file(format!("uc-148/{name}"), opts).unwrap();
            if valid_logos {
                writer.write_all(&logo_pak(name)).unwrap();
            } else {
                writer.write_all(b"incompatible PAK").unwrap();
            }
        }
        writer.start_file("uc-148/resources/app.pak", opts).unwrap();
        writer.write_all(b"PAK").unwrap();
        writer.finish().unwrap();
    }
    cursor.into_inner()
}

fn pe_fixture() -> Vec<u8> {
    let bytes = include_bytes!("../../payloads/7zip/7z.exe");
    #[cfg(windows)]
    {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fixture.exe");
        std::fs::write(&path, bytes).unwrap();
        let branding = nomad_core::Branding {
            targets: &["fixture.exe"],
            icons: nomad_core::branding::CHROMIUM.icons,
            pak_patches: &[],
        };
        assert!(nomad_core::branding::ensure_branding(
            temp.path(),
            &branding
        ));
        std::fs::read(path).unwrap()
    }
    #[cfg(not(windows))]
    bytes.to_vec()
}

fn logo_pak(name: &str) -> Vec<u8> {
    let patches: Vec<_> = nomad_core::branding::CHROMIUM
        .pak_patches
        .iter()
        .filter(|p| p.pak_file == name)
        .collect();
    let mut data = Vec::new();
    data.extend_from_slice(&5u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&u16::try_from(patches.len()).unwrap().to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    let mut offset = u32::try_from(18 + patches.len() * 6).unwrap();
    for (index, patch) in patches.iter().enumerate() {
        // Deliberately unrelated to the historical grit resource IDs.
        data.extend_from_slice(&u16::try_from(index + 1).unwrap().to_le_bytes());
        data.extend_from_slice(&offset.to_le_bytes());
        offset += u32::try_from(patch.expected_png_bytes.len()).unwrap();
    }
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&offset.to_le_bytes());
    for patch in patches {
        data.extend_from_slice(patch.expected_png_bytes);
    }
    data
}

/// Builds release JSON whose single asset points at `/uc.zip` with `digest`.
fn release_json(zip_url: &str, digest: &str) -> String {
    format!(
        r#"{{"tag_name":"200.0.0.0-1.1","assets":[{{"name":"ungoogled-chromium_148_windows_x64.zip","browser_download_url":"{zip_url}","digest":"sha256:{digest}"}}]}}"#
    )
}

#[tokio::test]
async fn full_pipeline_downloads_verifies_and_installs_then_skips_when_current() {
    let server = MockServer::start_async().await;
    let zip_bytes = fixture_zip(true);
    let digest = sha256::hex(&zip_bytes);

    let download_mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/uc.zip");
            then.status(200).body(&zip_bytes);
        })
        .await;
    let release_mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/releases/latest");
            then.status(200)
                .body(release_json(&server.url("/uc.zip"), &digest));
        })
        .await;

    let dir = tempfile::tempdir().unwrap();
    let install_dir = dir.path().join("browser");
    let browser = UngoogledChromium::with_releases_url(Arch::X64, server.url("/releases/latest"));
    let options = UpdateOptions {
        check_on_launch: true,
        auto_download: true,
    };

    // First run: a full, SHA-256-verified update.
    let outcome = updater::update(&browser, &install_dir, options)
        .await
        .expect("first update must succeed");
    assert_eq!(outcome, UpdateOutcome::Updated("200.0.0.0-1.1".to_owned()));
    assert!(std::fs::read(install_dir.join("chrome.exe"))
        .unwrap()
        .starts_with(b"MZ"));
    assert!(install_dir.join("resources/app.pak").exists());
    assert!(
        browser.installed_version(&install_dir).is_some(),
        "a version marker must be written"
    );
    #[cfg(windows)]
    assert!(install_dir.join(".branding-patched").is_file());
    download_mock.assert_async().await;
    release_mock.assert_async().await;

    // Second run: the installed build is current, so nothing is downloaded.
    let outcome = updater::update(&browser, &install_dir, options)
        .await
        .expect("second update must succeed");
    assert_eq!(outcome, UpdateOutcome::UpToDate);
    download_mock.assert_hits_async(1).await;
}

#[tokio::test]
async fn pipeline_aborts_on_a_sha256_mismatch() {
    let server = MockServer::start_async().await;
    let zip_bytes = fixture_zip(true);

    server
        .mock_async(|when, then| {
            when.method(GET).path("/uc.zip");
            then.status(200).body(&zip_bytes);
        })
        .await;
    server
        .mock_async(|when, then| {
            when.method(GET).path("/releases/latest");
            then.status(200)
                .body(release_json(&server.url("/uc.zip"), &"0".repeat(64)));
        })
        .await;

    let dir = tempfile::tempdir().unwrap();
    let install_dir = dir.path().join("browser");
    let browser = UngoogledChromium::with_releases_url(Arch::X64, server.url("/releases/latest"));
    let options = UpdateOptions {
        check_on_launch: true,
        auto_download: true,
    };

    let result = updater::update(&browser, &install_dir, options).await;
    assert!(result.is_err(), "a digest mismatch must abort the update");
    assert!(
        !install_dir.join("chrome.exe").exists(),
        "nothing must be extracted when verification fails"
    );
}

#[tokio::test]
async fn pipeline_defers_when_auto_download_is_disabled() {
    let server = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(GET).path("/releases/latest");
            then.status(200).body(release_json(
                "https://downloads.invalid/x.zip",
                &"0".repeat(64),
            ));
        })
        .await;

    let dir = tempfile::tempdir().unwrap();
    let browser = UngoogledChromium::with_releases_url(Arch::X64, server.url("/releases/latest"));
    let options = UpdateOptions {
        check_on_launch: true,
        auto_download: false,
    };

    let outcome = updater::update(&browser, &dir.path().join("browser"), options)
        .await
        .expect("deferred update must not error");
    assert_eq!(
        outcome,
        UpdateOutcome::UpdateDeferred("200.0.0.0-1.1".to_owned())
    );
}

#[tokio::test]
async fn authenticated_future_release_with_incompatible_logos_preserves_install_and_profile() {
    let server = MockServer::start_async().await;
    let zip_bytes = fixture_zip(false);
    let digest = sha256::hex(&zip_bytes);
    server
        .mock_async(|when, then| {
            when.method(GET).path("/uc.zip");
            then.status(200).body(&zip_bytes);
        })
        .await;
    server
        .mock_async(|when, then| {
            when.method(GET).path("/releases/latest");
            then.status(200)
                .body(release_json(&server.url("/uc.zip"), &digest));
        })
        .await;
    let temp = tempfile::tempdir().unwrap();
    let install = temp.path().join("Browser");
    let profile = temp.path().join("Data");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::write(install.join("chrome.exe"), b"working browser").unwrap();
    let old_version =
        "browser_version = \"152.0.7977.82-1.1\"\nengine_version = \"152.0.7977.82\"\n";
    std::fs::write(install.join(".nomad-version"), old_version).unwrap();
    std::fs::write(profile.join("Preferences"), b"user preferences").unwrap();
    let browser = UngoogledChromium::with_releases_url(Arch::X64, server.url("/releases/latest"));
    let result = updater::update(
        &browser,
        &install,
        UpdateOptions {
            check_on_launch: true,
            auto_download: true,
        },
    )
    .await;
    assert!(matches!(
        result,
        Err(nomad_core::browsers::BrowserError::Compatibility(_))
    ));
    assert_eq!(
        std::fs::read(install.join("chrome.exe")).unwrap(),
        b"working browser"
    );
    assert_eq!(
        std::fs::read(profile.join("Preferences")).unwrap(),
        b"user preferences"
    );
    assert_eq!(
        std::fs::read_to_string(install.join(".nomad-version")).unwrap(),
        old_version
    );
    assert!(!install.join(".branding-patched").exists());
    let stage = nomad_core::install::stage_dir(&install);
    assert!(!stage.join(".nomad-version").exists());
    assert!(!stage.join(".branding-patched").exists());
}
