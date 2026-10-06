//! Conservative ordering for the stable release formats used by the adapters.

use std::cmp::Ordering;

use crate::browsers::{BrowserError, InstalledVersion, Result, VersionInfo};

struct StableVersion {
    release: Vec<u64>,
    revision: Vec<u64>,
}

impl StableVersion {
    fn parse(text: &str) -> Option<Self> {
        // Bound allocations and reject arbitrary labels/prerelease syntax.
        if text.len() > 128 {
            return None;
        }
        let text = text
            .strip_prefix('v')
            .or_else(|| text.strip_prefix('G'))
            .unwrap_or(text);
        let text = text.strip_suffix("esr").unwrap_or(text);
        let (release, revision) = text
            .split_once('-')
            .map_or((text, None), |(release, revision)| {
                (release, Some(revision))
            });
        Some(Self {
            release: components(release)?,
            revision: match revision {
                Some(revision) => components(revision)?,
                None => Vec::new(),
            },
        })
    }

    fn compare(&self, other: &Self) -> Ordering {
        compare_components(&self.release, &other.release)
            .then_with(|| compare_components(&self.revision, &other.revision))
    }
}

fn components(text: &str) -> Option<Vec<u64>> {
    if text.split('.').count() > 16 {
        return None;
    }
    text.split('.')
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        })
        .collect()
}

fn compare_components(left: &[u64], right: &[u64]) -> Ordering {
    for index in 0..left.len().max(right.len()) {
        let ordering = left
            .get(index)
            .copied()
            .unwrap_or(0)
            .cmp(&right.get(index).copied().unwrap_or(0));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

/// Reject unknown release syntax and every decrease, regardless of target.
/// Called again before staging so metadata-check callers cannot bypass it.
pub(crate) fn ensure_not_older(
    installed: Option<&InstalledVersion>,
    latest: &VersionInfo,
) -> Result<()> {
    let offered = StableVersion::parse(&latest.browser_version).ok_or_else(|| {
        BrowserError::Compatibility(
            "cannot safely order the offered browser version; unsupported stable release format"
                .into(),
        )
    })?;
    if let Some(installed) = installed {
        let current = StableVersion::parse(&installed.browser_version).ok_or_else(||
            BrowserError::Compatibility("cannot safely order the installed browser version; unsupported stable release format".into()))?;
        if offered.compare(&current) == Ordering::Less {
            return Err(BrowserError::Compatibility(format!(
                "refusing browser downgrade from {} to {}; the installed build is newer",
                installed.browser_version, latest.browser_version
            )));
        }
    }
    Ok(())
}
