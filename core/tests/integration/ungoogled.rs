//! Integration test: ungoogled-chromium update resolution against a mock
//! GitHub releases endpoint.

use httpmock::prelude::*;
use nomad_core::browsers::ungoogled::UngoogledChromium;
use nomad_core::browsers::BrowserFamily;
use nomad_core::config::Arch;

const RELEASE_JSON: &str = r#"{
    "tag_name": "148.0.7778.96-1.1",
    "assets": [
        {
            "name": "ungoogled-chromium_148.0.7778.96-1.1_windows_x64.zip",
            "browser_download_url": "https://downloads.invalid/uc-x64.zip",
            "digest": "sha256:2f5886be06b7bf24c8ad7b9dba3e5e95509adaed4e3dee4002e5ed39deb79511"
        }
    ]
}"#;

#[tokio::test]
async fn fetch_latest_version_parses_the_github_release() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/releases/latest");
            then.status(200)
                .header("content-type", "application/json")
                .body(RELEASE_JSON);
        })
        .await;

    let browser = UngoogledChromium::with_releases_url(Arch::X64, server.url("/releases/latest"));
    let info = browser
        .fetch_latest_version()
        .await
        .expect("update check must succeed");

    mock.assert_async().await;
    assert_eq!(info.browser_version, "148.0.7778.96-1.1");
    assert_eq!(info.engine_version, "148.0.7778.96");
    assert_eq!(info.download_url, "https://downloads.invalid/uc-x64.zip");
    assert_eq!(
        info.sha256.as_deref(),
        Some("2f5886be06b7bf24c8ad7b9dba3e5e95509adaed4e3dee4002e5ed39deb79511")
    );
}

#[tokio::test]
async fn fetch_latest_version_surfaces_server_errors() {
    let server = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(GET).path("/releases/latest");
            then.status(500);
        })
        .await;

    let browser = UngoogledChromium::with_releases_url(Arch::X64, server.url("/releases/latest"));
    assert!(
        browser.fetch_latest_version().await.is_err(),
        "a 500 response must surface as an error"
    );
}
