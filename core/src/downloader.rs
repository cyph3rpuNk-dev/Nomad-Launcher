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
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }

    let client = reqwest::Client::builder()
        .user_agent("nomad-portable")
        .build()
        .map_err(|e| BrowserError::Network(e.to_string()))?;

    let tmp = tmp_path(dest);
    match download_to_tmp(&client, url, &tmp, progress, MAX_DOWNLOAD_BYTES).await {
        Ok(()) => {
            tokio::fs::rename(&tmp, dest).await?;
            tracing::debug!(url, ?dest, "download installed");
            Ok(())
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            tracing::debug!(url, error = %e, "download failed; temporary file removed");
            Err(e)
        }
    }
}

/// Downloads `url` into the temporary file `tmp`, streaming chunk by chunk.
/// Aborts with [`BrowserError::Network`] if the transfer exceeds `max_bytes`.
async fn download_to_tmp(
    client: &reqwest::Client,
    url: &str,
    tmp: &Path,
    progress: &ProgressSink,
    max_bytes: u64,
) -> Result<()> {
    tracing::debug!(url, "GET");
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| BrowserError::Network(e.to_string()))?;

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
    let mut file = tokio::fs::File::create(tmp).await?;
    let mut downloaded: u64 = 0;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| BrowserError::Network(e.to_string()))?
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

    #[test]
    fn tmp_path_appends_tmp_suffix() {
        let tmp = tmp_path(Path::new("dir/pkg.zip"));
        assert_eq!(tmp, PathBuf::from("dir/pkg.zip.tmp"));
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
        let err = download_to_tmp(&client, &server.url("/big"), &tmp, &tx, 10)
            .await
            .expect_err("a body larger than the cap must error");
        mock.assert_async().await;
        assert!(matches!(err, BrowserError::Network(_)));
    }
}
