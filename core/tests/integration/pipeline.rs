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
fn fixture_zip() -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
        writer.start_file("uc-148/chrome.exe", opts).unwrap();
        writer.write_all(b"FAKE-CHROME-BINARY").unwrap();
        writer.start_file("uc-148/resources/app.pak", opts).unwrap();
        writer.write_all(b"PAK").unwrap();
        writer.finish().unwrap();
    }
    cursor.into_inner()
}

/// Builds release JSON whose single asset points at `/uc.zip` with `digest`.
fn release_json(zip_url: &str, digest: &str) -> String {
    format!(
        r#"{{"tag_name":"148.0.7778.96-1.1","assets":[{{"name":"ungoogled-chromium_148_windows_x64.zip","browser_download_url":"{zip_url}","digest":"sha256:{digest}"}}]}}"#
    )
}

#[tokio::test]
async fn full_pipeline_downloads_verifies_and_installs_then_skips_when_current() {
    let server = MockServer::start_async().await;
    let zip_bytes = fixture_zip();
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
    assert_eq!(
        outcome,
        UpdateOutcome::Updated("148.0.7778.96-1.1".to_owned())
    );
    assert_eq!(
        std::fs::read(install_dir.join("chrome.exe")).unwrap(),
        b"FAKE-CHROME-BINARY"
    );
    assert!(install_dir.join("resources/app.pak").exists());
    assert!(
        browser.installed_version(&install_dir).is_some(),
        "a version marker must be written"
    );
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
    let zip_bytes = fixture_zip();

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
        UpdateOutcome::UpdateDeferred("148.0.7778.96-1.1".to_owned())
    );
}
