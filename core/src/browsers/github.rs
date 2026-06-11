//! Shared GitHub releases API types and helpers.
//!
//! Browsers distributed via GitHub releases (Floorp, Waterfox, …) all follow
//! the same fetch → filter → SHA-256 pattern. This module centralises the
//! common pieces so each browser impl only describes what is unique to it.

use serde::Deserialize;

use super::{BrowserError, Result};

/// Maps a `reqwest::Error` to the appropriate [`BrowserError`] variant.
///
/// Connection-level failures (`is_connect`, `is_timeout`) and HTTP 403
/// (GitHub rate limit) become [`BrowserError::Offline`] so the pipeline can
/// auto-launch an existing install. All other errors become
/// [`BrowserError::Network`].
#[allow(clippy::needless_pass_by_value)] // designed for .map_err() which requires FnOnce(E)
pub(super) fn map_network_err(e: reqwest::Error) -> BrowserError {
    if e.is_connect() || e.is_timeout() {
        BrowserError::Offline(e.to_string())
    } else if e.status() == Some(reqwest::StatusCode::FORBIDDEN) {
        BrowserError::Offline(format!("GitHub API rate limit exceeded: {e}"))
    } else {
        BrowserError::Network(e.to_string())
    }
}

// ── API types ─────────────────────────────────────────────────────────────────

/// A GitHub release, as returned by the `releases/latest` and `releases`
/// endpoints.
#[derive(Debug, Deserialize)]
pub(super) struct Release {
    pub tag_name: String,
    /// Whether this is a prerelease. Used when filtering a `releases` list for
    /// the latest *stable* release; ignored by `releases/latest` consumers.
    /// Defaults to `false` when absent.
    #[serde(default)]
    pub prerelease: bool,
    /// When the release was published (`YYYY-MM-DDTHH:MM:SSZ`). Consumed by
    /// [`asset_provenance_suspect`]; `None` only for draft releases.
    pub published_at: Option<String>,
    pub assets: Vec<ReleaseAsset>,
}

/// One downloadable asset attached to a [`Release`].
#[derive(Debug, Deserialize)]
pub(super) struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    /// GitHub-recorded content digest, e.g. `"sha256:abcd…"`. Absent on
    /// releases predating GitHub's digest support.
    pub digest: Option<String>,
    /// When the asset was first uploaded. Consumed by
    /// [`asset_provenance_suspect`].
    pub created_at: Option<String>,
    /// When the asset's bytes were last replaced. Consumed by
    /// [`asset_provenance_suspect`].
    pub updated_at: Option<String>,
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Builds a `reqwest` client with the Nomad user-agent.
pub(super) fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("nomad-portable")
        .build()
        .map_err(|e| BrowserError::Network(e.to_string()))
}

/// Fetches raw bytes from `url`.
pub(super) async fn fetch_raw(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    client
        .get(url)
        .send()
        .await
        .map_err(map_network_err)?
        .error_for_status()
        .map_err(map_network_err)?
        .bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(map_network_err)
}

/// Fetches and deserialises a GitHub release from `url`.
pub(super) async fn fetch_release(client: &reqwest::Client, url: &str) -> Result<Release> {
    let body = client
        .get(url)
        .send()
        .await
        .map_err(map_network_err)?
        .error_for_status()
        .map_err(map_network_err)?
        .text()
        .await
        .map_err(map_network_err)?;
    serde_json::from_str(&body).map_err(|e| BrowserError::Parse(e.to_string()))
}

/// Fetches and deserialises a list of GitHub releases from `url` (the
/// `releases` endpoint). Returned newest-first, as GitHub orders them.
///
/// Used by repos that publish multiple products into one release stream
/// (e.g. `bitwarden/clients`), where `releases/latest` may point at an
/// unrelated product and the caller must filter by tag.
pub(super) async fn fetch_releases(client: &reqwest::Client, url: &str) -> Result<Vec<Release>> {
    let body = client
        .get(url)
        .send()
        .await
        .map_err(map_network_err)?
        .error_for_status()
        .map_err(map_network_err)?
        .text()
        .await
        .map_err(map_network_err)?;
    serde_json::from_str(&body).map_err(|e| BrowserError::Parse(e.to_string()))
}

// ── Asset provenance ──────────────────────────────────────────────────────────

/// Tolerance for an asset's `updated_at` exceeding its `created_at`. GitHub
/// finalises upload metadata slightly after creation (a 1-second skew was
/// observed on real gorhill release assets); anything well beyond that means
/// the asset's bytes were replaced in place after upload.
const ASSET_REUPLOAD_TOLERANCE_SECS: i64 = 5 * 60;

/// Tolerance for an asset's `created_at` falling after the release's
/// `published_at`. The normal flow uploads assets before publishing; deleting
/// and re-uploading an asset — the swap technique that resets `created_at` —
/// lands far outside this window.
const ASSET_LATE_UPLOAD_TOLERANCE_SECS: i64 = 48 * 60 * 60;

/// Returns `true` when `asset`'s upload timeline does not match the release's
/// original publication — tamper evidence for a release-asset swap, which
/// GitHub permits without touching the (possibly GPG-signed) tag.
///
/// Two swap techniques, two fingerprints:
/// - replacing the asset in place advances `updated_at` past `created_at`;
/// - deleting and re-uploading resets `created_at` to long after
///   `published_at`.
///
/// Missing or unparseable timestamps count as suspect (fail-safe: callers
/// are expected to skip an *optional* update, never to abort a launch).
/// Only apply this to assets uploaded with the release itself — artifacts
/// that legitimately arrive later (e.g. AMO-signed XPIs) would false-flag.
pub(super) fn asset_provenance_suspect(asset: &ReleaseAsset, release: &Release) -> bool {
    let (Some(created), Some(updated), Some(published)) = (
        asset.created_at.as_deref().and_then(timestamp_epoch),
        asset.updated_at.as_deref().and_then(timestamp_epoch),
        release.published_at.as_deref().and_then(timestamp_epoch),
    ) else {
        return true;
    };
    updated - created > ASSET_REUPLOAD_TOLERANCE_SECS
        || created - published > ASSET_LATE_UPLOAD_TOLERANCE_SECS
}

/// Parses a GitHub API timestamp (`YYYY-MM-DDTHH:MM:SSZ`) into Unix epoch
/// seconds. Returns `None` for any other shape — the GitHub REST API emits
/// second-precision UTC `Z` timestamps exclusively, so sub-second and
/// offset forms are rejected rather than guessed at.
fn timestamp_epoch(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<i64> {
        let s = ts.get(range)?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, min, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil` algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ── Asset selection ───────────────────────────────────────────────────────────

/// Finds the first `.zip` asset whose lowercased name contains `arch_token`
/// and does not contain `"installer"`.
///
/// # Errors
/// Returns [`BrowserError::Parse`] when no matching asset is found.
pub(super) fn zip_asset<'r>(release: &'r Release, arch_token: &str) -> Result<&'r ReleaseAsset> {
    release
        .assets
        .iter()
        .find(|a| {
            let name = a.name.to_ascii_lowercase();
            std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
                && name.contains(arch_token)
                && !name.contains("installer")
        })
        .ok_or_else(|| {
            BrowserError::Parse(format!(
                "no {arch_token} .zip asset in release {}",
                release.tag_name
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(published_at: Option<&str>) -> Release {
        Release {
            tag_name: "1.99.0".to_owned(),
            prerelease: false,
            published_at: published_at.map(str::to_owned),
            assets: Vec::new(),
        }
    }

    fn asset(created_at: Option<&str>, updated_at: Option<&str>) -> ReleaseAsset {
        ReleaseAsset {
            name: "uBlock0_1.99.0.chromium.zip".to_owned(),
            browser_download_url: "https://example.invalid/x.zip".to_owned(),
            digest: None,
            created_at: created_at.map(str::to_owned),
            updated_at: updated_at.map(str::to_owned),
        }
    }

    #[test]
    fn timestamp_epoch_matches_chrono() {
        // Cross-check the hand-rolled parser against chrono for epoch,
        // leap-year, century and real GitHub-emitted timestamps.
        for ts in [
            "1970-01-01T00:00:00Z",
            "2000-02-29T23:59:59Z",
            "2024-02-29T12:00:00Z",
            "2026-05-11T16:40:22Z", // real gorhill 1.71.0 chromium.zip created_at
            "2026-05-11T16:41:12Z", // real gorhill 1.71.0 published_at
            "2099-12-31T00:00:01Z",
        ] {
            let expected = chrono::DateTime::parse_from_rfc3339(ts)
                .expect("fixture must be valid RFC 3339")
                .timestamp();
            assert_eq!(timestamp_epoch(ts), Some(expected), "mismatch for {ts}");
        }
    }

    #[test]
    fn timestamp_epoch_rejects_non_github_shapes() {
        for ts in [
            "",
            "2026-05-11",
            "2026-05-11T16:40:22",       // missing Z
            "2026-05-11T16:40:22.123Z",  // sub-second precision
            "2026-05-11T16:40:22+02:00", // offset form
            "2026-13-11T16:40:22Z",      // bad month
            "2026-05-32T16:40:22Z",      // bad day
            "2026-05-11T24:40:22Z",      // bad hour
            "yyyy-mm-ddThh:mm:ssZ",
        ] {
            assert_eq!(timestamp_epoch(ts), None, "must reject {ts:?}");
        }
    }

    #[test]
    fn asset_provenance_accepts_a_clean_release() {
        // Real-world profile: asset uploaded a minute before publication,
        // metadata finalised a second after creation.
        let rel = release(Some("2026-05-11T16:41:12Z"));
        let a = asset(Some("2026-05-11T16:40:22Z"), Some("2026-05-11T16:40:23Z"));
        assert!(!asset_provenance_suspect(&a, &rel));
    }

    #[test]
    fn asset_provenance_flags_an_in_place_swap() {
        // Replacing an asset's bytes advances updated_at past created_at.
        let rel = release(Some("2026-05-11T16:41:12Z"));
        let a = asset(Some("2026-05-11T16:40:22Z"), Some("2026-05-14T09:00:00Z"));
        assert!(asset_provenance_suspect(&a, &rel));
    }

    #[test]
    fn asset_provenance_flags_a_delete_and_reupload() {
        // Deleting and re-uploading resets created_at to the swap time,
        // long after the release was published.
        let rel = release(Some("2026-05-11T16:41:12Z"));
        let a = asset(Some("2026-05-21T08:00:00Z"), Some("2026-05-21T08:00:00Z"));
        assert!(asset_provenance_suspect(&a, &rel));
    }

    #[test]
    fn asset_provenance_flags_missing_timestamps() {
        // Fail-safe: no timeline means no tamper evidence either way, and
        // the caller should skip the optional update.
        let rel = release(Some("2026-05-11T16:41:12Z"));
        assert!(asset_provenance_suspect(&asset(None, None), &rel));
        let a = asset(Some("2026-05-11T16:40:22Z"), Some("2026-05-11T16:40:22Z"));
        assert!(asset_provenance_suspect(&a, &release(None)));
    }
}
