//! Automatic host cleanup with explicit portable-instance attribution.
//!
//! Shared browser profiles, registration maps, temporary files, raw dumps,
//! and compound Jump Lists cannot be attributed by brand/filename alone.
//! Leave them intact; remove only individually corroborated shortcuts/reports.

use std::path::{Path, PathBuf};

struct HostPaths {
    appdata: Option<PathBuf>,
    programdata: Option<PathBuf>,
}

pub(crate) fn scrub_host_traces(launcher: &Path, browser_exe: &Path, browser_id: &str) {
    let paths = HostPaths {
        appdata: std::env::var_os("APPDATA").map(PathBuf::from),
        programdata: std::env::var_os("ProgramData").map(PathBuf::from),
    };
    scrub_host_traces_in(launcher, browser_exe, browser_id, &paths);
}

const MAX_METADATA_BYTES: u64 = 65_536;

struct Scope {
    launcher: PathBuf,
    browser_exe: PathBuf,
}

impl Scope {
    fn new(launcher: &Path, browser_exe: &Path, browser_id: &str) -> Option<Self> {
        if !launcher.is_absolute() || !browser_exe.is_absolute() || launcher.parent().is_none() {
            return None;
        }
        if !plain_path_under(launcher, &launcher.join("Nomad/instance.toml"))
            || !plain_path_under(launcher, browser_exe)
            || crate::instance::ensure(launcher, browser_id, false).is_err()
        {
            return None;
        }
        let launcher = std::fs::canonicalize(launcher).ok()?;
        let browser_exe = std::fs::canonicalize(browser_exe).ok()?;
        if !browser_exe.is_file() || !browser_exe.starts_with(&launcher) {
            return None;
        }
        Some(Self {
            launcher,
            browser_exe,
        })
    }
}

/// All automatic deletion is gated by a claimed instance and its actual image
/// path. There is intentionally no shared profile/temp/dump/JumpList scrub.
fn scrub_host_traces_in(launcher: &Path, browser_exe: &Path, browser_id: &str, paths: &HostPaths) {
    let Some(scope) = Scope::new(launcher, browser_exe, browser_id) else {
        tracing::warn!("cannot prove cleanup instance ownership; preserving host traces");
        return;
    };
    if let Some(appdata) = &paths.appdata {
        cleanup_recent(appdata, &scope);
    }
    if let Some(programdata) = &paths.programdata {
        cleanup_reports(programdata, &scope);
    }
}

/// Reject symlinks/reparse points and missing or escaping components. The
/// base itself must be an ordinary directory, including on Windows junctions.
fn plain_path_under(base: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(base) else {
        return false;
    };
    let Ok(base_meta) = std::fs::symlink_metadata(base) else {
        return false;
    };
    if !base_meta.is_dir() || is_reparse(&base_meta) {
        return false;
    }
    let mut current = base.to_owned();
    for part in relative.components() {
        if !matches!(part, std::path::Component::Normal(_)) {
            return false;
        }
        current.push(part);
        let Ok(meta) = std::fs::symlink_metadata(&current) else {
            return false;
        };
        if is_reparse(&meta) {
            return false;
        }
    }
    true
}

fn is_reparse(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

fn read_metadata_file(base: &Path, path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    if !plain_path_under(base, path) {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_METADATA_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= usize::try_from(MAX_METADATA_BYTES).ok()?).then_some(bytes)
}

/// Accept only the local-path subset that the parser can corroborate: no
/// competing IDList/network/relative/environment targets or opaque extra data.
fn unambiguous_link_target(bytes: &[u8]) -> Option<PathBuf> {
    const SHELL_LINK_CLSID: &[u8] = &[
        0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46,
    ];
    if bytes.get(4..20) != Some(SHELL_LINK_CLSID) {
        return None;
    }
    let flags = u32::from_le_bytes(bytes.get(20..24)?.try_into().ok()?);
    if flags != 0x02 {
        return None;
    } // HasLinkInfo only
    let info = bytes.get(76..)?;
    let size = usize::try_from(u32::from_le_bytes(info.get(..4)?.try_into().ok()?)).ok()?;
    let suffix = usize::try_from(u32::from_le_bytes(info.get(24..28)?.try_into().ok()?)).ok()?;
    let info_flags = u32::from_le_bytes(info.get(8..12)?.try_into().ok()?);
    let header_size = u32::from_le_bytes(info.get(4..8)?.try_into().ok()?);
    if !matches!(header_size, 28 | 36) {
        return None;
    }
    // An empty suffix means LocalBasePath is already the complete target.
    if info_flags != 1 || size > info.len() || suffix < 28 || suffix >= size || info[suffix] != 0 {
        return None;
    }
    if info.len() != size && info.get(size..) != Some(&[0, 0, 0, 0]) {
        return None;
    }
    crate::lnk_target_path(bytes)
}

fn cleanup_recent(appdata: &Path, scope: &Scope) {
    let recent = appdata.join("Microsoft/Windows/Recent");
    if !plain_path_under(appdata, &recent) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(&recent) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
        {
            continue;
        }
        let Some(bytes) = read_metadata_file(appdata, &path) else {
            continue;
        };
        let Some(target) = unambiguous_link_target(&bytes).filter(|target| target.is_absolute())
        else {
            continue;
        };
        let Ok(target) = std::fs::canonicalize(target) else {
            continue;
        };
        if target.starts_with(&scope.launcher)
            && target != scope.launcher
            && plain_path_under(appdata, &path)
            && std::fs::remove_file(&path).is_ok()
        {
            tracing::info!(path = %path.display(), "removed Recent shortcut attributed to this instance");
        }
    }
}

fn report_application_path(bytes: &[u8]) -> Option<PathBuf> {
    let text = if let Some(payload) = bytes.strip_prefix(&[0xff, 0xfe]) {
        if payload.len() % 2 != 0 {
            return None;
        }
        let chars: Vec<u16> = payload
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&chars).ok()?
    } else {
        String::from_utf8(
            bytes
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(bytes)
                .to_owned(),
        )
        .ok()?
    };
    let mut found = None;
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key.trim().eq_ignore_ascii_case("AppPath") {
                if found.is_some() {
                    return None;
                } // ambiguous even when duplicated values agree
                let path = PathBuf::from(value.trim());
                if !path.is_absolute() {
                    return None;
                }
                found = Some(path);
            }
        }
    }
    found
}

fn cleanup_reports(programdata: &Path, scope: &Scope) {
    for subdir in ["ReportQueue", "ReportArchive"] {
        let queue = programdata.join("Microsoft/Windows/WER").join(subdir);
        if !plain_path_under(programdata, &queue) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&queue) else {
            continue;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !plain_path_under(programdata, &dir) || !dir.is_dir() {
                continue;
            }
            let Some(bytes) = read_metadata_file(programdata, &dir.join("Report.wer")) else {
                continue;
            };
            let Some(image) = report_application_path(&bytes) else {
                continue;
            };
            let Ok(image) = std::fs::canonicalize(image) else {
                continue;
            };
            if image == scope.browser_exe
                && plain_path_under(programdata, &dir)
                && std::fs::remove_dir_all(&dir).is_ok()
            {
                tracing::info!(path = %dir.display(), "removed WER report attributed to this browser image");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        temp: tempfile::TempDir,
        launcher: PathBuf,
        exe: PathBuf,
        paths: HostPaths,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let launcher = temp.path().join("portable/Helium");
            let exe = launcher.join("Browser/chrome.exe");
            std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
            std::fs::write(&exe, b"MZ fixture").unwrap();
            crate::instance::ensure(&launcher, "helium", true).unwrap();
            let paths = HostPaths {
                appdata: Some(temp.path().join("host/AppData")),
                programdata: Some(temp.path().join("host/ProgramData")),
            };
            Self {
                temp,
                launcher,
                exe,
                paths,
            }
        }

        fn host(&self, relative: &str) -> PathBuf {
            self.temp.path().join("host").join(relative)
        }

        fn put(&self, relative: &str, content: &[u8]) -> PathBuf {
            let path = self.host(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
            path
        }

        fn recent(&self, name: &str, target: &Path) -> PathBuf {
            self.put(
                &format!("AppData/Microsoft/Windows/Recent/{name}.lnk"),
                &crate::tests::make_lnk(&target.to_string_lossy()),
            )
        }

        fn report(&self, name: &str, content: &[u8]) -> PathBuf {
            self.put(
                &format!("ProgramData/Microsoft/Windows/WER/ReportQueue/{name}/Report.wer"),
                content,
            )
            .parent()
            .unwrap()
            .to_owned()
        }

        fn run(&self) {
            scrub_host_traces_in(&self.launcher, &self.exe, "helium", &self.paths);
        }
    }

    #[test]
    fn cleanup_preserves_shared_profiles_registration_maps_and_temporary_files() {
        let f = Fixture::new();
        let names = [
            "Local/Chromium/User Data/Local State", // system-wide executable lives elsewhere
            "Local/Chromium/User Data/Default/Cookies",
            "Local/imput/Helium/User Data/Local State",
            "Local/Mozilla/Firefox/Profiles/real/cache",
            "Local/Firefox/Profiles/real/prefs.js",
            "Local/Floorp/Profiles/real/prefs.js",
            "Local/Waterfox/Profiles/real/prefs.js",
            "Local/LibreWolf/Profiles/real/prefs.js",
            "Local/Mullvad/MullvadBrowser/Profiles/real/prefs.js",
            "Local/Mullvad/MullvadVPN/settings.json",
            "ProgramData/Mozilla-deadbeef/update-state",
            "ProgramData/Noraneko-deadbeef/update-state",
            "AppData/Mozilla/Firefox/installs.ini",
            "AppData/Floorp/installs.ini",
            "AppData/Waterfox/installs.ini",
            "Temp/scoped_dir_other_browser/data",
            "Temp/mozilla-temp-other",
            "Temp/chrome_BITS_foreign",
        ];
        for name in names {
            f.put(name, b"user data");
        }
        f.run();
        for name in names {
            assert_eq!(
                std::fs::read(f.host(name)).unwrap(),
                b"user data",
                "preserve {name}"
            );
        }
    }

    #[test]
    fn cleanup_preserves_raw_dumps_and_mixed_jump_lists() {
        let f = Fixture::new();
        let dump = f.put(
            "Local/CrashDumps/chrome.exe.1234.dmp",
            b"foreign or unattributed dump",
        );
        let mut mixed = f
            .launcher
            .to_string_lossy()
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        mixed.extend_from_slice(b"foreign document history");
        let jump = f.put(
            "AppData/Microsoft/Windows/Recent/AutomaticDestinations/mixed.automaticDestinations-ms",
            &mixed,
        );
        f.run();
        assert_eq!(
            std::fs::read(dump).unwrap(),
            b"foreign or unattributed dump"
        );
        assert_eq!(std::fs::read(jump).unwrap(), mixed);
    }

    #[test]
    fn cleanup_removes_only_shortcuts_resolved_inside_this_instance() {
        let f = Fixture::new();
        let own = f.recent("own", &f.exe);
        let foreign_exe = f.put("installed/chrome.exe", b"MZ foreign");
        let foreign = f.recent("foreign_same_drive", &foreign_exe);
        let sibling_exe = f
            .temp
            .path()
            .join("portable/Helium-other/Browser/chrome.exe");
        std::fs::create_dir_all(sibling_exe.parent().unwrap()).unwrap();
        std::fs::write(&sibling_exe, b"MZ sibling").unwrap();
        let sibling = f.recent("sibling_instance", &sibling_exe);
        let unknown = f.put(
            "AppData/Microsoft/Windows/Recent/unknown.lnk",
            b"not a shortcut",
        );
        f.run();
        assert!(!own.exists());
        assert!(foreign.exists() && sibling.exists() && unknown.exists());
    }

    #[test]
    fn cleanup_requires_exact_report_application_path() {
        let f = Fixture::new();
        let own_text = format!("Version=1\r\nAppPath={}\r\n", f.exe.display());
        let own = f.report("AppCrash_chrome.exe_own", own_text.as_bytes());
        let foreign_exe = f.put("installed/chrome.exe", b"MZ foreign");
        let foreign = f.report(
            "AppCrash_chrome.exe_foreign",
            format!("AppPath={}\n", foreign_exe.display()).as_bytes(),
        );
        let unknown = f.report("AppCrash_chrome.exe_missing_path", b"AppName=chrome.exe\n");
        let duplicate = f.report(
            "AppCrash_chrome.exe_ambiguous",
            format!("{own_text}AppPath={}\n", foreign_exe.display()).as_bytes(),
        );
        let archive = f.put(
            "ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_chrome.exe_own/Report.wer",
            own_text.as_bytes(),
        );
        f.run();
        assert!(!own.exists() && !archive.parent().unwrap().exists());
        assert!(foreign.exists() && unknown.exists() && duplicate.exists());
    }

    #[test]
    fn cleanup_requires_claimed_instance_and_contained_browser_executable() {
        let f = Fixture::new();
        let own = f.recent("own", &f.exe);
        let report = f.report(
            "AppCrash_chrome.exe_own",
            format!("AppPath={}\n", f.exe.display()).as_bytes(),
        );
        for id in ["firefox", ""] {
            scrub_host_traces_in(&f.launcher, &f.exe, id, &f.paths);
            assert!(own.exists() && report.exists());
        }
        let foreign = f.put("installed/chrome.exe", b"MZ foreign");
        for exe in [
            foreign.as_path(),
            Path::new("chrome.exe"),
            Path::new("missing.exe"),
        ] {
            scrub_host_traces_in(&f.launcher, exe, "helium", &f.paths);
            assert!(own.exists() && report.exists());
        }
        std::fs::remove_file(f.launcher.join("Nomad/instance.toml")).unwrap();
        f.run();
        assert!(own.exists() && report.exists());
    }

    #[test]
    fn cleanup_preserves_malformed_oversized_or_unreadable_report_metadata() {
        let f = Fixture::new();
        let malformed = f.report("AppCrash_chrome.exe_bad", &[0xff, 0xfe, 0x41]);
        // Even valid attribution must not bypass the metadata size budget.
        let mut large_metadata = format!("AppPath={}\n", f.exe.display()).into_bytes();
        large_metadata.resize(65_537, b'x');
        let oversized = f.report("AppCrash_chrome.exe_large", &large_metadata);
        let unreadable = f.report("AppCrash_chrome.exe_unreadable", b"temp");
        std::fs::remove_file(unreadable.join("Report.wer")).unwrap();
        std::fs::create_dir(unreadable.join("Report.wer")).unwrap();
        f.run();
        assert!(malformed.exists() && oversized.exists() && unreadable.exists());
    }

    #[test]
    fn cleanup_handles_utf16_reports_and_missing_host_roots() {
        let f = Fixture::new();
        let mut text = vec![0xff, 0xfe];
        text.extend(
            format!("Version=1\r\nAppPath={}\r\n", f.exe.display())
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        let report = f.report("AppCrash_chrome.exe_utf16", &text);
        f.run();
        assert!(!report.exists());
        scrub_host_traces_in(
            &f.launcher,
            &f.exe,
            "helium",
            &HostPaths {
                appdata: None,
                programdata: None,
            },
        );
    }

    #[test]
    fn cleanup_preserves_shortcuts_with_ambiguous_target_records() {
        let f = Fixture::new();
        let base = crate::tests::make_lnk(&f.exe.to_string_lossy());
        for flag in [0x01, 0x08, 0x100, 0x200] {
            let mut bytes = base.clone();
            bytes[20..24].copy_from_slice(&(0x02u32 | flag).to_le_bytes());
            let path = f.put(
                &format!("AppData/Microsoft/Windows/Recent/ambiguous-{flag}.lnk"),
                &bytes,
            );
            f.run();
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
        let mut suffix = base.clone();
        *suffix.last_mut().unwrap() = b'x';
        let path = f.put("AppData/Microsoft/Windows/Recent/suffix.lnk", &suffix);
        f.run();
        assert!(path.exists());
    }

    #[test]
    fn cleanup_preserves_report_and_shortcut_directory_links() {
        let f = Fixture::new();
        let source = f.host("external-report");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("Report.wer"),
            format!("AppPath={}\n", f.exe.display()),
        )
        .unwrap();
        let report_link =
            f.host("ProgramData/Microsoft/Windows/WER/ReportQueue/AppCrash_chrome.exe_link");
        std::fs::create_dir_all(report_link.parent().unwrap()).unwrap();
        make_directory_link(&f.temp, &report_link, &source);
        let recent_link = f.host("AppData/Microsoft/Windows/Recent");
        std::fs::create_dir_all(recent_link.parent().unwrap()).unwrap();
        let external_recent = f.host("external-recent");
        std::fs::create_dir_all(&external_recent).unwrap();
        std::fs::write(
            external_recent.join("own.lnk"),
            crate::tests::make_lnk(&f.exe.to_string_lossy()),
        )
        .unwrap();
        make_directory_link(&f.temp, &recent_link, &external_recent);
        f.run();
        assert!(report_link.exists() && source.join("Report.wer").exists());
        assert!(recent_link.exists() && external_recent.join("own.lnk").exists());
    }

    fn make_directory_link(temp: &tempfile::TempDir, link: &Path, target: &Path) {
        let root = std::fs::canonicalize(temp.path()).unwrap();
        assert!(std::fs::canonicalize(link.parent().unwrap())
            .unwrap()
            .starts_with(&root));
        assert!(std::fs::canonicalize(target).unwrap().starts_with(&root));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // mklink /J is unprivileged. Every path is an owned fixture; reject
            // shell metacharacters before passing data to this Windows builtin.
            for path in [link, target] {
                assert!(path
                    .to_str()
                    .unwrap()
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || r"\/:. _-".contains(c)));
            }
            let cmd = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join("System32")
                .join("cmd.exe");
            // Rust's normal argument escaping follows CommandLineToArgvW,
            // whereas cmd builtins use cmd's quoting rules. Paths were checked
            // above to contain no shell metacharacters and stay in this fixture.
            let command = format!(
                r#"/d /s /c "mklink /J "{}" "{}"""#,
                link.to_string_lossy().replace('/', "\\"),
                target.to_string_lossy().replace('/', "\\")
            );
            let result = std::process::Command::new(cmd)
                .raw_arg(&command)
                .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "owned fixture junction creation failed ({command}): {} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
    }
}
