//! Streaming HTTP downloads with progress reporting.
//!
//! A download is written to a sibling `<dest>.tmp` file and renamed onto
//! `dest` only after a fully successful transfer, so `dest` is never left
//! partially written. A failed transfer removes its own `.tmp`; one orphaned
//! by a hard crash dies with the staging directory, which
//! `install::recover_staging` deletes wholesale on the next run.

use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;

use crate::browsers::{BrowserError, ProgressSink, Result};

/// Hard ceiling on a single download. Generous headroom over the largest
/// browser package (a full Chromium build is ~200 MB) while bounding a
/// malicious or misbehaving endpoint that streams without end (CWE-400).
const MAX_DOWNLOAD_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB

/// Maximum redirect hops, matching reqwest's default policy.
const MAX_REDIRECTS: usize = 10;

/// Returns `true` when following `next` would step down from https to a
/// non-https scheme anywhere in the redirect chain. Package integrity is
/// hash/GPG-pinned regardless, but a downgraded hop would expose the full
/// download URL (not just the hostname) to on-path observers.
fn is_scheme_downgrade(next: &reqwest::Url, previous: &[reqwest::Url]) -> bool {
    next.scheme() != "https" && previous.iter().any(|u| u.scheme() == "https")
}

/// Redirect policy shared by every Nomad HTTP client: follows up to
/// [`MAX_REDIRECTS`] hops but refuses a redirect that downgrades from https
/// to http. Plain-http chains (test mock servers) are unaffected because the
/// guard only fires once the chain has been on https.
pub(crate) fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > MAX_REDIRECTS {
            attempt.error("too many redirects")
        } else if is_scheme_downgrade(attempt.url(), attempt.previous()) {
            attempt.error("refusing redirect downgrade from https to http")
        } else {
            attempt.follow()
        }
    })
}

/// Streams the resource at `url` to `dest`, reporting fractional progress
/// (`0.0..=1.0`) through `progress`.
///
/// On success `dest` holds the complete file. On failure the temporary file
/// is removed and `dest` is left untouched.
///
/// # Errors
/// Returns [`BrowserError::Network`] if the request fails or returns a
/// non-success status, and [`BrowserError::Io`] if the file cannot be
/// written or renamed.
pub async fn download(url: &str, dest: &Path, progress: &ProgressSink) -> Result<()> {
    let client = crate::network::build_client(crate::network::DOWNLOAD_TIMEOUT)?;
    download_with_client(&client, url, dest, progress).await
}

async fn download_with_client(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    progress: &ProgressSink,
) -> Result<()> {
    let tmp = tmp_path(dest);
    crate::fs_safety::ensure_file(dest)?;
    crate::fs_safety::ensure_file(&tmp)?;
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            crate::fs_safety::create_dir_all(parent)?;
        }
    }

    let mut owns_tmp = false;
    let result = match download_to_tmp(
        client,
        url,
        &tmp,
        progress,
        MAX_DOWNLOAD_BYTES,
        &mut owns_tmp,
    )
    .await
    {
        Ok(()) => match crate::fs_safety::ensure_file(dest) {
            Ok(()) => tokio::fs::rename(&tmp, dest)
                .await
                .map_err(BrowserError::from),
            Err(error) => Err(error.into()),
        },
        Err(e) => Err(e),
    };
    if result.is_err() && owns_tmp {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    result
}

/// Downloads `url` into the temporary file `tmp`, streaming chunk by chunk.
/// Aborts with [`BrowserError::Network`] if the transfer exceeds `max_bytes`.
async fn download_to_tmp(
    client: &reqwest::Client,
    url: &str,
    tmp: &Path,
    progress: &ProgressSink,
    max_bytes: u64,
    owns_tmp: &mut bool,
) -> Result<()> {
    tracing::debug!(url, "GET");
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(crate::network::map_network_err)?;

    let status = response.status();
    if !status.is_success() {
        return Err(BrowserError::Network(format!("HTTP {status} for {url}")));
    }

    let total = response.content_length();
    // Reject an over-cap transfer up front when the server declares its size.
    if let Some(len) = total {
        if len > max_bytes {
            return Err(BrowserError::Network(format!(
                "{url}: declared size {len} B exceeds the {max_bytes} B limit"
            )));
        }
    }
    crate::fs_safety::ensure_file(tmp)?;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
        .await?;
    *owns_tmp = true;
    let mut downloaded: u64 = 0;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(crate::network::map_network_err)?
    {
        downloaded += chunk.len() as u64;
        // Enforce the cap for chunked / undeclared-length responses too.
        if downloaded > max_bytes {
            return Err(BrowserError::Network(format!(
                "{url}: download exceeded the {max_bytes} B limit"
            )));
        }
        file.write_all(&chunk).await?;
        if let Some(total) = total.filter(|t| *t > 0) {
            // Progress is a display fraction; precision loss on huge files
            // is irrelevant.
            #[allow(clippy::cast_precision_loss)]
            let fraction = (downloaded as f32 / total as f32).min(1.0);
            let _ = progress.send(fraction);
        }
    }

    file.flush().await?;
    let _ = progress.send(1.0);
    tracing::debug!(url, bytes = downloaded, %status, "download complete");
    Ok(())
}

/// Returns the `<dest>.tmp` sibling path used for in-progress downloads.
fn tmp_path(dest: &Path) -> PathBuf {
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    dest.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timeout_preserves_destination_and_removes_owned_partial_download() {
        let (url, server) = crate::network::tests::socket_fixture(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\npart",
            b"done",
            std::time::Duration::from_millis(250),
        );
        let fixture = tempfile::tempdir().unwrap();
        let dest = fixture.path().join("pkg.zip");
        std::fs::write(&dest, b"working package").unwrap();
        let client = crate::network::build_client(std::time::Duration::from_millis(80)).unwrap();
        let (progress, _) = tokio::sync::watch::channel(0.0);
        let result = download_with_client(&client, &url, &dest, &progress).await;
        assert!(matches!(result, Err(BrowserError::Offline(_))));
        assert_eq!(std::fs::read(&dest).unwrap(), b"working package");
        assert!(!tmp_path(&dest).exists());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn failed_download_preserves_a_preexisting_temporary_file() {
        use httpmock::prelude::*;
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/missing");
                then.status(404);
            })
            .await;
        let fixture = tempfile::tempdir().unwrap();
        let dest = fixture.path().join("pkg.zip");
        let tmp = tmp_path(&dest);
        std::fs::write(&tmp, b"someone else's temporary data").unwrap();
        let (progress, _rx) = tokio::sync::watch::channel(0.0);
        assert!(download(&server.url("/missing"), &dest, &progress)
            .await
            .is_err());
        assert_eq!(
            std::fs::read(tmp).unwrap(),
            b"someone else's temporary data"
        );
    }

    #[tokio::test]
    async fn download_rejects_a_linked_destination_before_network_or_writes() {
        use httpmock::prelude::*;
        let server = MockServer::start_async().await;
        let request = server
            .mock_async(|when, then| {
                when.method(GET).path("/pkg");
                then.status(200).body("replacement");
            })
            .await;
        let fixture = tempfile::tempdir().unwrap();
        let base = fixture.path().join("instance");
        let foreign = fixture.path().join("foreign");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("pkg.zip"), b"foreign data").unwrap();
        crate::tests::owned_directory_link(&fixture, &base.join("stage"), &foreign);
        let (progress, _rx) = tokio::sync::watch::channel(0.0);
        assert!(
            download(&server.url("/pkg"), &base.join("stage/pkg.zip"), &progress)
                .await
                .is_err()
        );
        request.assert_calls_async(0).await;
        assert_eq!(
            std::fs::read(foreign.join("pkg.zip")).unwrap(),
            b"foreign data"
        );
    }

    #[tokio::test]
    async fn successful_response_cannot_overwrite_a_preexisting_temp_file() {
        use httpmock::prelude::*;
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/pkg");
                then.status(200).body("replacement");
            })
            .await;
        let fixture = tempfile::tempdir().unwrap();
        let dest = fixture.path().join("pkg.zip");
        let tmp = tmp_path(&dest);
        std::fs::write(&dest, b"current").unwrap();
        std::fs::write(&tmp, b"other writer").unwrap();
        let (progress, _rx) = tokio::sync::watch::channel(0.0);
        assert!(download(&server.url("/pkg"), &dest, &progress)
            .await
            .is_err());
        assert_eq!(std::fs::read(&dest).unwrap(), b"current");
        assert_eq!(std::fs::read(&tmp).unwrap(), b"other writer");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn failed_download_promotion_removes_only_its_owned_temporary_file() {
        use httpmock::prelude::*;
        use std::os::windows::fs::OpenOptionsExt;
        let server = MockServer::start_async().await;
        let request = server
            .mock_async(|when, then| {
                when.method(GET).path("/pkg");
                then.status(200).body("replacement");
            })
            .await;
        let fixture = tempfile::tempdir().unwrap();
        let dest = fixture.path().join("pkg.zip");
        std::fs::write(&dest, b"current").unwrap();
        // Allow ordinary reads/stat but deny replacement of this fixture file.
        let handle = std::fs::File::options()
            .read(true)
            .share_mode(
                windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
            )
            .open(&dest)
            .unwrap();
        let (progress, _rx) = tokio::sync::watch::channel(0.0);
        assert!(download(&server.url("/pkg"), &dest, &progress)
            .await
            .is_err());
        request.assert_calls_async(1).await;
        drop(handle);
        assert_eq!(std::fs::read(&dest).unwrap(), b"current");
        assert!(!tmp_path(&dest).exists());
    }

    #[test]
    fn tmp_path_appends_tmp_suffix() {
        let tmp = tmp_path(Path::new("dir/pkg.zip"));
        assert_eq!(tmp, PathBuf::from("dir/pkg.zip.tmp"));
    }

    #[test]
    fn scheme_downgrade_is_detected_only_after_an_https_hop() {
        let secure: reqwest::Url = "https://releases.mozilla.org/pkg".parse().unwrap();
        let plain: reqwest::Url = "http://mirror.example/pkg".parse().unwrap();
        let other: reqwest::Url = "http://mirror2.example/pkg".parse().unwrap();

        // https chain redirected to http: downgrade, must be refused.
        assert!(is_scheme_downgrade(&plain, std::slice::from_ref(&secure)));
        // https to https: fine.
        assert!(!is_scheme_downgrade(&secure, std::slice::from_ref(&secure)));
        // Pure http chain (test mock servers): the guard must not fire.
        assert!(!is_scheme_downgrade(&other, std::slice::from_ref(&plain)));
        // Once the chain has been on https, a later hop may not drop back.
        assert!(!is_scheme_downgrade(&secure, std::slice::from_ref(&plain)));
        assert!(is_scheme_downgrade(&other, &[plain, secure]));
    }

    #[tokio::test]
    async fn download_follows_same_scheme_redirects() {
        use httpmock::prelude::*;
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/old");
                then.status(302).header("Location", server.url("/new"));
            })
            .await;
        let target = server
            .mock_async(|when, then| {
                when.method(GET).path("/new");
                then.status(200).body(b"payload");
            })
            .await;

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("pkg.bin");
        let (tx, _rx) = tokio::sync::watch::channel(0.0_f32);

        download(&server.url("/old"), &dest, &tx)
            .await
            .expect("a same-scheme redirect must be followed");
        target.assert_async().await;
        assert_eq!(std::fs::read(&dest).unwrap(), b"payload");
    }

    #[tokio::test]
    async fn download_to_tmp_aborts_when_body_exceeds_cap() {
        use httpmock::prelude::*;
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path("/big");
                then.status(200).body(vec![0u8; 100]);
            })
            .await;

        let client = reqwest::Client::builder().build().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("pkg.tmp");
        let (tx, _rx) = tokio::sync::watch::channel(0.0_f32);

        // Cap of 10 bytes against a 100-byte body: the transfer must be refused.
        let err = download_to_tmp(&client, &server.url("/big"), &tmp, &tx, 10, &mut false)
            .await
            .expect_err("a body larger than the cap must error");
        mock.assert_async().await;
        assert!(matches!(err, BrowserError::Network(_)));
    }
}
