//! On-disk cache for the last successful version check result.
//!
//! Writing a `VersionCache` after every successful API call means subsequent
//! launches within the TTL window skip the network entirely — this avoids
//! GitHub's 60-req/hour shared rate limit and makes offline launches seamless
//! when a browser is already installed.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::browsers::VersionInfo;

/// Cache TTL: 6 hours. Sized to keep four checks/day across all browsers
/// comfortably under GitHub's 60-req/hour unauthenticated cap.
const CACHE_TTL_SECS: u64 = 6 * 60 * 60;

/// Serialisable snapshot of a `VersionInfo` plus the Unix timestamp at which
/// the API was last queried.
#[derive(Debug, Serialize, Deserialize)]
pub struct VersionCache {
    /// Unix timestamp (seconds) when the cache was written.
    pub fetched_at: u64,
    pub browser_version: String,
    pub engine_version: String,
    pub download_url: String,
    pub signature_url: Option<String>,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    /// Installed uBlock Origin version, e.g. `"1.70.2"`.
    /// `None` means the bundled version is in use or the check has not run yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ubo_version: Option<String>,
}

impl VersionCache {
    /// Creates a cache entry from a freshly fetched [`VersionInfo`].
    pub fn from_version_info(info: &VersionInfo) -> Self {
        Self {
            fetched_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            browser_version: info.browser_version.clone(),
            engine_version: info.engine_version.clone(),
            download_url: info.download_url.clone(),
            signature_url: info.signature_url.clone(),
            sha256: info.sha256.clone(),
            sha512: info.sha512.clone(),
            ubo_version: None,
        }
    }

    /// Copies the `ubo_version` from the existing cache at `path` into `self`,
    /// so that a browser-version refresh does not erase a previously recorded
    /// uBO version.
    #[must_use]
    pub fn with_preserved_ubo_version(mut self, path: &Path) -> Self {
        if let Some(existing) = Self::load(path) {
            self.ubo_version = existing.ubo_version;
        }
        self
    }

    /// Converts the cache entry back into a [`VersionInfo`].
    pub fn into_version_info(self) -> VersionInfo {
        VersionInfo {
            browser_version: self.browser_version,
            engine_version: self.engine_version,
            download_url: self.download_url,
            signature_url: self.signature_url,
            sha256: self.sha256,
            sha512: self.sha512,
        }
    }

    /// Returns `false` when `download_url` points outside the known distribution
    /// hosts, preventing a poisoned cache file from redirecting downloads to
    /// attacker infrastructure.  An implausible URL causes the cache entry to be
    /// treated as a miss, triggering a fresh API check.
    pub fn is_url_plausible(&self) -> bool {
        let url = self.download_url.as_str();
        url.starts_with("https://github.com/")
            || url.starts_with("https://releases.mozilla.org/")
            || url.starts_with("https://download.mozilla.org/")
            || url.starts_with("https://addons.mozilla.org/")
            || url.starts_with("https://dl.librewolf.net/")
            || url.starts_with("https://cdn.waterfox.com/")
    }

    /// Returns `true` when the cache was written less than [`CACHE_TTL_SECS`] ago.
    pub fn is_fresh(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.fetched_at) < CACHE_TTL_SECS
    }

    /// Reads and deserialises a cache from `path`.  Returns `None` on any
    /// error (missing file, malformed TOML, etc.).
    pub fn load(path: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(path).ok()?;
        toml::from_str(&text).ok()
    }

    /// Serialises the cache to `path` via a temp file + atomic rename, so a
    /// concurrent reader — or a second launcher writing the same file — never
    /// observes a half-written cache. Failures are silently ignored: a missing
    /// or stale cache just costs a network round-trip on the next launch.
    pub fn save(&self, path: &Path) {
        use std::sync::atomic::{AtomicU64, Ordering};
        // Process-wide sequence so concurrent writers each get a distinct temp
        // path: threads within one process via the counter, separate launcher
        // processes via the pid. Without it two writers could clobber the same
        // temp file before either rename completes.
        static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

        let Ok(text) = toml::to_string(self) else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Write to a unique sibling temp file, then atomically replace the
        // target. `std::fs::rename` is MoveFileExW(MOVEFILE_REPLACE_EXISTING)
        // on Windows: the swap is atomic, so a reader sees either the old or
        // the new complete file — never a torn mix of two writers' bytes.
        let pid = std::process::id();
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("tmp.{pid}.{seq}"));
        if std::fs::write(&tmp, text).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return;
        }
        if std::fs::rename(&tmp, path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

/// Records `version` as the installed uBlock Origin version in the cache at
/// `path`. Creates a stub cache entry if the file does not yet exist so the
/// uBO version is always persisted; the stub has `fetched_at = 0` (immediately
/// stale) so the browser-version check still runs on the next launch.
pub fn update_ubo_version(path: &Path, version: &str) {
    let mut cache = VersionCache::load(path).unwrap_or_else(|| VersionCache {
        fetched_at: 0,
        browser_version: String::new(),
        engine_version: String::new(),
        download_url: String::new(),
        signature_url: None,
        sha256: None,
        sha512: None,
        ubo_version: None,
    });
    cache.ubo_version = Some(version.to_owned());
    cache.save(path);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_info(version: &str) -> VersionInfo {
        VersionInfo {
            browser_version: version.to_owned(),
            engine_version: version.to_owned(),
            download_url: format!("https://example.invalid/{version}.zip"),
            signature_url: None,
            sha256: Some("a".repeat(64)),
            sha512: None,
        }
    }

    fn fixture_cache(version: &str) -> VersionCache {
        VersionCache::from_version_info(&fixture_info(version))
    }

    #[test]
    fn round_trips_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nomad-version-cache.toml");

        let info = fixture_info("1.2.3");
        VersionCache::from_version_info(&info).save(&path);

        let loaded = VersionCache::load(&path).expect("cache must be readable");
        assert_eq!(loaded.browser_version, "1.2.3");
        assert_eq!(loaded.sha256.as_deref(), Some(&"a".repeat(64) as &str));
    }

    #[test]
    fn into_version_info_preserves_all_fields() {
        let info = fixture_info("2.0.0");
        let cached = VersionCache::from_version_info(&info);
        let roundtripped = cached.into_version_info();
        assert_eq!(roundtripped.browser_version, info.browser_version);
        assert_eq!(roundtripped.download_url, info.download_url);
        assert_eq!(roundtripped.sha256, info.sha256);
    }

    #[test]
    fn fresh_cache_is_fresh() {
        let cache = VersionCache {
            fetched_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            browser_version: "1.0".to_owned(),
            engine_version: "1.0".to_owned(),
            download_url: String::new(),
            signature_url: None,
            sha256: None,
            sha512: None,
            ubo_version: None,
        };
        assert!(cache.is_fresh());
    }

    #[test]
    fn expired_cache_is_stale() {
        let cache = VersionCache {
            fetched_at: 0, // Unix epoch — always expired
            browser_version: "1.0".to_owned(),
            engine_version: "1.0".to_owned(),
            download_url: String::new(),
            signature_url: None,
            sha256: None,
            sha512: None,
            ubo_version: None,
        };
        assert!(!cache.is_fresh());
    }

    #[test]
    fn plausible_url_passes_host_check() {
        let mut cache = VersionCache {
            fetched_at: 0,
            browser_version: "1.0".to_owned(),
            engine_version: "1.0".to_owned(),
            download_url: String::new(),
            signature_url: None,
            sha256: None,
            sha512: None,
            ubo_version: None,
        };
        for url in [
            "https://github.com/ungoogled-software/ungoogled-chromium-windows/releases/download/1/foo.zip",
            "https://releases.mozilla.org/pub/firefox/releases/128.0/win64/en-US/Firefox%20Setup%20128.0.exe",
            "https://download.mozilla.org/?product=firefox-128.0&os=win64&lang=en-US",
            // Regression: dl.librewolf.net and cdn.waterfox.com were missing
            // from the allow-list, so every LibreWolf/Waterfox cache hit was
            // rejected as implausible and the launcher hit the network on
            // every run.
            "https://dl.librewolf.net/139.0-1/librewolf-139.0-1-windows-x86_64-portable.zip",
            "https://cdn.waterfox.com/waterfox/releases/6.5.6/WINNT_x86_64/Waterfox%206.5.6%20Setup.exe",
        ] {
            cache.download_url = url.to_owned();
            assert!(cache.is_url_plausible(), "expected plausible: {url}");
        }
        for url in [
            "https://evil.example.com/malware.zip",
            "http://github.com/foo/bar/releases/download/1/foo.zip",
            "ftp://github.com/foo",
            "",
        ] {
            cache.download_url = url.to_owned();
            assert!(!cache.is_url_plausible(), "expected implausible: {url}");
        }
    }

    #[test]
    fn load_returns_none_for_missing_file() {
        let result = VersionCache::load(std::path::Path::new("nonexistent-cache.toml"));
        assert!(result.is_none());
    }

    #[test]
    fn load_returns_none_for_malformed_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, b"not valid toml {{{{").unwrap();
        assert!(VersionCache::load(&path).is_none());
    }

    #[test]
    fn ubo_version_round_trips_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.toml");
        let mut cache = fixture_cache("1.0");
        cache.ubo_version = Some("1.70.2".to_owned());
        cache.save(&path);
        let loaded = VersionCache::load(&path).unwrap();
        assert_eq!(loaded.ubo_version.as_deref(), Some("1.70.2"));
    }

    #[test]
    fn ubo_version_absent_from_old_cache_deserializes_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.toml");
        // Simulate a cache file written before the ubo_version field existed.
        std::fs::write(
            &path,
            "fetched_at = 0\nbrowser_version = \"1.0\"\nengine_version = \"1.0\"\ndownload_url = \"https://github.com/foo\"\n",
        )
        .unwrap();
        let loaded = VersionCache::load(&path).unwrap();
        assert!(loaded.ubo_version.is_none());
    }

    #[test]
    fn with_preserved_ubo_version_copies_existing_ubo_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.toml");
        let mut old = fixture_cache("1.0");
        old.ubo_version = Some("1.70.0".to_owned());
        old.save(&path);

        let new_cache = fixture_cache("2.0").with_preserved_ubo_version(&path);
        assert_eq!(new_cache.browser_version, "2.0");
        assert_eq!(new_cache.ubo_version.as_deref(), Some("1.70.0"));
    }

    #[test]
    fn update_ubo_version_writes_to_existing_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.toml");
        fixture_cache("1.0").save(&path);

        update_ubo_version(&path, "1.70.2");

        let loaded = VersionCache::load(&path).unwrap();
        assert_eq!(loaded.ubo_version.as_deref(), Some("1.70.2"));
        assert_eq!(
            loaded.browser_version, "1.0",
            "browser version must be preserved"
        );
    }

    #[test]
    fn update_ubo_version_creates_stub_when_cache_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.toml");
        update_ubo_version(&path, "1.70.2");
        // A stub cache must be created so the uBO version is persisted.
        let loaded = VersionCache::load(&path).expect("stub cache must be created");
        assert_eq!(loaded.ubo_version.as_deref(), Some("1.70.2"));
        // The stub is immediately stale so the browser check still runs next launch.
        assert!(!loaded.is_fresh());
    }

    #[test]
    fn amo_url_passes_plausibility_check() {
        let mut cache = fixture_cache("1.0");
        cache.download_url =
            "https://addons.mozilla.org/firefox/downloads/file/123/ublock_origin-1.70.0.xpi"
                .to_owned();
        assert!(cache.is_url_plausible());
    }

    #[test]
    fn concurrent_saves_never_yield_a_torn_file_or_leak_temps() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("nomad-version-cache.toml"));

        // Many threads hammer the same path; the atomic rename must keep every
        // observable state a complete, parseable file.
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let p = Arc::clone(&path);
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        fixture_cache(&format!("{i}.0.0")).save(&p);
                        // A racing reader must always see a complete file (or
                        // none yet) — never a half-written one.
                        if let Some(c) = VersionCache::load(&p) {
                            assert!(!c.browser_version.is_empty());
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        // Final state is a valid cache, and no temp files were left behind.
        assert!(VersionCache::load(&path).is_some());
        let temps: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .map(|e| e.file_name())
            .collect();
        assert!(temps.is_empty(), "temp files leaked: {temps:?}");
    }
}
