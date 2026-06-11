//! Integration tests for the streaming HTTP downloader.

use httpmock::prelude::*;
use nomad_core::downloader;
use tokio::sync::watch;

#[tokio::test]
async fn downloads_file_and_reports_completion() {
    let server = MockServer::start_async().await;
    let body = vec![7u8; 256 * 1024];
    let mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/pkg.bin");
            then.status(200).body(&body);
        })
        .await;

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("pkg.bin");
    let (tx, rx) = watch::channel(0.0f32);

    downloader::download(&server.url("/pkg.bin"), &dest, &tx)
        .await
        .expect("download must succeed");

    mock.assert_async().await;
    assert!(dest.exists(), "destination file must exist");
    assert_eq!(std::fs::read(&dest).unwrap(), body, "contents must match");
    assert_eq!(*rx.borrow(), 1.0, "progress must reach 1.0");
    assert!(
        !dir.path().join("pkg.bin.tmp").exists(),
        "temporary file must be cleaned up after success"
    );
}

#[tokio::test]
async fn missing_resource_fails_without_leaving_files() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/missing.bin");
            then.status(404);
        })
        .await;

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("missing.bin");
    let (tx, _rx) = watch::channel(0.0f32);

    let result = downloader::download(&server.url("/missing.bin"), &dest, &tx).await;

    mock.assert_async().await;
    assert!(result.is_err(), "a 404 must surface as an error");
    assert!(!dest.exists(), "no destination file on failure");
    assert!(
        !dir.path().join("missing.bin.tmp").exists(),
        "temporary file must be removed on failure"
    );
}
