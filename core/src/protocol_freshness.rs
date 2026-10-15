//! Local advisory checks for launch-only URL/file handlers; no network or update.
use crate::browsers::{BrowserFamily, Hardening, PackageTarget};
use crate::version_cache::VersionCache;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub(crate) const REMINDER_FILE: &str = "protocol-update-reminder.json";
const WEEK: u64 = 7 * 24 * 60 * 60;
const DAY: u64 = 24 * 60 * 60;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledgment {
    schema: u8,
    browser: String,
    target: PackageTarget,
    acknowledged_at: u64,
}

fn recent(checked: u64, now: u64, limit: u64) -> bool {
    checked != 0 && now.checked_sub(checked).is_some_and(|age| age < limit)
}

/// Advisory only: cache timestamps do not prove current security or installation.
pub(crate) fn message<B: BrowserFamily>(browser: &B, install: &Path, now: u64) -> Option<String> {
    let base = install.parent()?;
    let state = crate::config::nomad_subdir(base);
    let cache = VersionCache::load(&state.join("nomad-version-cache.toml"));
    let installed = browser.installed_version(install);
    let checked_browser = cache.as_ref().filter(|c| {
        c.target == Some(browser.package_target())
            && c.fetched_at != 0
            && c.fetched_at <= now
            && c.is_url_plausible()
            && c.has_integrity_material()
    });
    let browser_change = checked_browser.and_then(|c| {
        let latest = crate::browsers::VersionInfo {
            browser_version: c.browser_version.clone(),
            engine_version: c.engine_version.clone(),
            download_url: c.download_url.clone(),
            signature_url: c.signature_url.clone(),
            sha256: c.sha256.clone(),
            sha512: c.sha512.clone(),
        };
        crate::updater::needs_update(installed.as_ref(), &latest, browser.package_target()).ok()
    });
    let browser_pending = browser_change == Some(true);
    let browser_recent = browser_change.is_some()
        && checked_browser.is_some_and(|c| recent(c.fetched_at, now, WEEK));
    let managed_extension = browser.id() == "ungoogled-chromium"
        || matches!(
            browser.hardening(),
            Hardening::GeckoProfile {
                ublock_xpi_releases_url: Some(_),
                ..
            }
        );
    let extension = crate::version_cache::extension_check(&state.join("nomad-version-cache.toml"));
    let extension_recent = !managed_extension
        || extension
            .as_ref()
            .is_some_and(|c| recent(c.checked_at, now, WEEK));
    let extension_pending = managed_extension
        && extension.as_ref().is_some_and(|c| {
            c.checked_at != 0
                && c.checked_at <= now
                && cache.as_ref().and_then(|v| v.ubo_version.as_ref()) != Some(&c.version)
        });
    if browser_recent && extension_recent && !browser_pending && !extension_pending {
        return None;
    }
    let acknowledged = crate::version_cache::read_bounded(&state.join(REMINDER_FILE), 4096)
        .and_then(|bytes| serde_json::from_slice::<Acknowledgment>(&bytes).ok());
    if acknowledged.is_some_and(|a| {
        a.schema == 1
            && a.browser == browser.id()
            && a.target == browser.package_target()
            && recent(a.acknowledged_at, now, DAY)
    }) {
        return None;
    }
    let subject = if managed_extension {
        "browser or managed uBlock"
    } else {
        "browser"
    };
    let action = if managed_extension {
        "browser and managed uBlock updates"
    } else {
        "browser updates"
    };
    let summary = if browser_pending || extension_pending {
        format!("A previous check found a {subject} version that is not recorded as installed.")
    } else {
        format!("A recent {subject} update check is missing or at least 7 days old.")
    };
    Some(format!("{summary}\n\nClose the browser and run Nomad directly with update checks enabled to check {action}. Opening a link does not check or download updates.\n\nContinue opens this link with the installed browser. No update runs here."))
}

/// Rate-limit only acknowledged reminders, never mark an update as checked.
pub(crate) fn acknowledge<B: BrowserFamily>(
    browser: &B,
    install: &Path,
    now: u64,
) -> std::io::Result<()> {
    let base = install
        .parent()
        .ok_or_else(|| std::io::Error::other("missing launcher directory"))?;
    let state = crate::config::nomad_subdir(base);
    crate::fs_safety::create_dir_all(&state)?;
    let bytes = serde_json::to_vec(&Acknowledgment {
        schema: 1,
        browser: browser.id().to_owned(),
        target: browser.package_target(),
        acknowledged_at: now,
    })?;
    crate::fs_safety::atomic_write(&state.join(REMINDER_FILE), &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browsers::{floorp::Floorp, helium::Helium, InstalledVersion, VersionInfo};
    const NOW: u64 = 2_000_000;
    fn install(root: &Path) -> std::path::PathBuf {
        let path = root.join("Browser");
        std::fs::create_dir_all(&path).unwrap();
        crate::browsers::write_version_marker(
            &path,
            &InstalledVersion {
                target: Some(PackageTarget::X64),
                browser_version: "1.0".into(),
                engine_version: "1.0".into(),
            },
        )
        .unwrap();
        path
    }
    fn cached(root: &Path, fetched_at: u64, latest: &str) {
        let mut cache = VersionCache::from_version_info(
            &VersionInfo {
                browser_version: latest.into(),
                engine_version: latest.into(),
                download_url: "https://github.com/example/release.zip".into(),
                signature_url: None,
                sha256: Some("a".repeat(64)),
                sha512: None,
            },
            PackageTarget::X64,
        );
        cache.fetched_at = fetched_at;
        cache.ubo_version = Some("1.0".into());
        cache.save(&root.join("Nomad/nomad-version-cache.toml"));
    }
    fn extension(root: &Path, at: u64, version: &str) {
        let path = root.join("Nomad/managed-extension-check.json");
        crate::fs_safety::create_dir_all(path.parent().unwrap()).unwrap();
        let check = crate::version_cache::ExtensionCheck {
            schema: 1,
            checked_at: at,
            version: version.into(),
        };
        std::fs::write(path, serde_json::to_vec(&check).unwrap()).unwrap();
    }
    #[test]
    fn protocol_freshness_requires_independent_recent_checks_and_no_known_pending_update() {
        let browser = Floorp::new(crate::Arch::X64);
        let temp = tempfile::tempdir().unwrap();
        let path = install(temp.path());
        assert!(message(&browser, &path, NOW).unwrap().contains("missing"));
        cached(temp.path(), NOW, "1.0");
        assert!(
            message(&browser, &path, NOW).is_some(),
            "browser lookup cannot refresh extension evidence"
        );
        extension(temp.path(), NOW, "1.0");
        assert!(message(&browser, &path, NOW).is_none());
        for (at, latest, extension_at, extension_latest, pending) in [
            (NOW - WEEK, "1.0", NOW, "1.0", false),
            (NOW, "1.0", NOW - WEEK, "1.0", false),
            (NOW + 1, "1.0", NOW, "1.0", false),
            (NOW, "1.0", NOW + 1, "1.0", false),
            (0, "1.0", NOW, "1.0", false),
            (NOW, "2.0", NOW, "1.0", true),
            (NOW, "1.0", NOW, "2.0", true),
            (NOW, "0.9", NOW, "1.0", false),
            (NOW, "unorderable", NOW, "1.0", false),
        ] {
            cached(temp.path(), at, latest);
            extension(temp.path(), extension_at, extension_latest);
            let text = message(&browser, &path, NOW).expect("cannot silently establish freshness");
            assert_eq!(text.contains("previous check"), pending);
        }
    }
    #[test]
    fn protocol_freshness_does_not_claim_to_manage_builtin_extensions() {
        let temp = tempfile::tempdir().unwrap();
        let path = install(temp.path());
        let browser = Helium::new(crate::Arch::X64);
        assert!(!message(&browser, &path, NOW).unwrap().contains("uBlock"));
        cached(temp.path(), NOW, "1.0");
        assert!(message(&browser, &path, NOW).is_none());
    }
    #[test]
    fn protocol_freshness_acknowledgment_is_scoped_expires_and_does_not_refresh_checks() {
        let temp = tempfile::tempdir().unwrap();
        let path = install(temp.path());
        let browser = Floorp::new(crate::Arch::X64);
        acknowledge(&browser, &path, NOW).unwrap();
        assert!(message(&browser, &path, NOW + DAY - 1).is_none());
        assert!(message(&browser, &path, NOW + DAY).is_some());
        assert!(
            message(&browser, &path, NOW - 1).is_some(),
            "future acknowledgment is not trusted"
        );
        assert!(message(&Floorp::new(crate::Arch::X86), &path, NOW).is_some());
        assert!(message(&Helium::new(crate::Arch::X64), &path, NOW).is_some());
        assert!(!temp.path().join("Nomad/nomad-version-cache.toml").exists());
        assert!(!temp
            .path()
            .join("Nomad/managed-extension-check.json")
            .exists());
        let bytes = std::fs::read(temp.path().join("Nomad").join(REMINDER_FILE)).unwrap();
        let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(record.as_object().unwrap().len(), 4);
    }
    #[test]
    fn protocol_freshness_invalid_oversized_linked_records_do_not_hide_reminders_or_mutate_targets()
    {
        let temp = tempfile::tempdir().unwrap();
        let path = install(temp.path());
        let browser = Floorp::new(crate::Arch::X64);
        let state = temp.path().join("Nomad");
        std::fs::create_dir_all(&state).unwrap();
        for (file, bytes) in [
            (REMINDER_FILE, vec![b'x'; 4097]),
            ("nomad-version-cache.toml", vec![b'x'; 65537]),
            ("managed-extension-check.json", vec![b'x'; 4097]),
        ] {
            std::fs::write(state.join(file), &bytes).unwrap();
            assert!(message(&browser, &path, NOW).is_some());
            assert_eq!(std::fs::read(state.join(file)).unwrap(), bytes);
        }
        let other = tempfile::tempdir().unwrap();
        let foreign = other.path().join("foreign");
        std::fs::create_dir_all(&foreign).unwrap();
        let linked_root = other.path().join("owned");
        std::fs::create_dir_all(&linked_root).unwrap();
        let linked_install = install(&linked_root);
        crate::tests::owned_directory_link(&other, &linked_root.join("Nomad"), &foreign);
        std::fs::write(foreign.join(REMINDER_FILE), b"preserve sentinel").unwrap();
        assert!(message(&browser, &linked_install, NOW).is_some());
        assert!(acknowledge(&browser, &linked_install, NOW).is_err());
        assert_eq!(
            std::fs::read(foreign.join(REMINDER_FILE)).unwrap(),
            b"preserve sentinel"
        );
        assert_eq!(std::fs::read_dir(&foreign).unwrap().count(), 1);
    }
}
