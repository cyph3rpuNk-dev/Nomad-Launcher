//! Automatic host cleanup with explicit portable-instance attribution.
//!
//! Shared browser profiles, registration maps, temporary files, raw dumps,
//! and compound Jump Lists cannot be attributed by brand/filename alone.
//! Leave them intact; remove only individually corroborated shortcuts/reports.

use std::path::{Path, PathBuf};

struct HostPaths {
    appdata: Option<PathBuf>,
    localappdata: Option<PathBuf>,
    programdata: Option<PathBuf>,
}

pub(crate) fn scrub_host_traces(launcher: &Path, browser_exe: &Path, browser_id: &str) -> bool {
    let paths = HostPaths {
        appdata: std::env::var_os("APPDATA").map(PathBuf::from),
        localappdata: std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
        programdata: std::env::var_os("ProgramData").map(PathBuf::from),
    };
    scrub_host_traces_in(launcher, browser_exe, browser_id, &paths)
}

/// Inert fixture adapter: callers supply every root; never reads host environment.
#[cfg(test)]
pub(crate) fn scrub_fixture(root: &Path, image: &Path, id: &str, host: &Path) -> bool {
    scrub_host_traces_in(
        root,
        image,
        id,
        &HostPaths {
            appdata: Some(host.join("AppData")),
            localappdata: Some(host.join("Local")),
            programdata: Some(host.join("ProgramData")),
        },
    )
}

const MAX_METADATA_BYTES: u64 = 65_536;

pub(crate) struct Scope {
    pub(crate) launcher: PathBuf,
    pub(crate) browser_exe: PathBuf,
}

impl Scope {
    /// The outer bundle folder determines the shared install lock, even if
    /// the browser image lives in a versioned or nested child directory.
    pub(crate) fn install_dir(&self) -> Option<PathBuf> {
        let mut relative = self
            .browser_exe
            .strip_prefix(&self.launcher)
            .ok()?
            .components();
        let std::path::Component::Normal(folder) = relative.next()? else {
            return None;
        };
        relative.next()?;
        Some(self.launcher.join(folder))
    }

    pub(crate) fn new(launcher: &Path, browser_exe: &Path, browser_id: &str) -> Option<Self> {
        if !launcher.is_absolute() || !browser_exe.is_absolute() || launcher.parent().is_none() {
            return None;
        }
        if crate::fs_safety::ensure_directory(launcher).is_err()
            || crate::fs_safety::ensure_file(browser_exe).is_err()
            || !plain_path_under(launcher, &launcher.join("Nomad/instance.toml"))
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

/// One cleanup coordinator per owned portable folder. Keep the file handle
/// alive until all exit actions finish; never unlink the shared lock file.
/// The OS releases the lock if the worker dies, allowing a later launch to
/// coordinate a new session. Recovery journals are managed separately.
pub(crate) struct CleanupSession {
    _file: std::fs::File,
}

impl CleanupSession {
    pub(crate) fn acquire(
        launcher: &Path,
        browser_exe: &Path,
        browser_id: &str,
    ) -> std::io::Result<Option<Self>> {
        let scope = Scope::new(launcher, browser_exe, browser_id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "cannot prove cleanup instance ownership",
            )
        })?;
        let path = scope.launcher.join("Nomad/cleanup.lock");
        crate::fs_safety::ensure_file(&path)?;
        let mut options = std::fs::File::options();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(
                windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
            );
        }
        let file = options.open(path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(error)) => Err(error),
        }
    }
}

/// Best-effort opt-in cache clearing. Never stop Explorer or any other process
/// to obtain access: locked files, links and unreadable paths are preserved.
pub(crate) fn scrub_unlocked_thumbnail_cache(cache_dir: &Path) -> std::io::Result<usize> {
    crate::fs_safety::ensure_directory(cache_dir)?;
    let mut removed = 0;
    for entry in std::fs::read_dir(cache_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if (name.starts_with("thumbcache_") || name.starts_with("iconcache_"))
            && path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("db"))
            && crate::fs_safety::ensure_file(&path).is_ok()
            && remove_unlocked_cache_file(&path).is_ok()
        {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Hold a Windows handle that denies concurrent read/write access while
/// allowing our own deletion. Existing readers/writers make open fail even
/// when their handles allow deletion; do not unlink an actively used database.
fn remove_unlocked_cache_file(path: &Path) -> std::io::Result<()> {
    let mut options = std::fs::File::options();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE);
    }
    let _guard = options.open(path)?;
    std::fs::remove_file(path)
}

/// All automatic deletion is gated by a claimed instance and its actual image
/// path. There is intentionally no shared profile/temp/dump/JumpList scrub.
fn scrub_host_traces_in(
    launcher: &Path,
    browser_exe: &Path,
    browser_id: &str,
    paths: &HostPaths,
) -> bool {
    let Some(scope) = Scope::new(launcher, browser_exe, browser_id) else {
        tracing::warn!("cannot prove cleanup instance ownership; preserving host traces");
        return false;
    };
    let mut completed =
        paths.appdata.is_some() && paths.localappdata.is_some() && paths.programdata.is_some();
    if let Some(appdata) = &paths.appdata {
        completed &= cleanup_recent(appdata, &scope);
    }
    for root in [&paths.localappdata, &paths.programdata]
        .into_iter()
        .flatten()
    {
        completed &= cleanup_reports(root, &scope);
    }
    completed
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

fn cleanup_recent(appdata: &Path, scope: &Scope) -> bool {
    let recent = appdata.join("Microsoft/Windows/Recent");
    if crate::fs_safety::ensure_directory(&recent).is_err() {
        return false;
    }
    let entries = match std::fs::read_dir(&recent) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    if !plain_path_under(appdata, &recent) {
        return false;
    }
    let mut completed = true;
    for entry in entries {
        let Ok(entry) = entry else {
            completed = false;
            continue;
        };
        let path = entry.path();
        if !path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
        {
            continue;
        }
        let Some(bytes) = read_metadata_file(appdata, &path) else {
            completed = false;
            continue;
        };
        let Some(target) = crate::shell_link::owned_target(&bytes, &path, &scope.launcher) else {
            continue;
        };
        if target.starts_with(&scope.launcher) && target != scope.launcher {
            if plain_path_under(appdata, &path) && std::fs::remove_file(&path).is_ok() {
                tracing::info!(path = %path.display(), "removed Recent shortcut attributed to this instance");
            } else {
                completed = false;
            }
        }
    }
    completed
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
    if text.contains('\0') {
        return None;
    }
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

/// Accept ordinary absolute local paths; never look up a network/device path
/// or collapse a parent component before proving the ownership boundary.
fn ordinary_report_path(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, std::path::Component::ParentDir))
    {
        return None;
    }
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let ordinary = PathBuf::from(crate::strip_verbatim(path.to_str()?));
        let mut parts = ordinary.components();
        if !matches!(parts.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
            || !matches!(parts.next(), Some(Component::RootDir))
        {
            return None;
        }
        Some(ordinary)
    }
    #[cfg(not(windows))]
    Some(path.to_owned())
}

fn report_matches_image(image: &Path, scope: &Scope) -> bool {
    let Some(image) = ordinary_report_path(image) else {
        return false;
    };
    let Some(root) = ordinary_report_path(&scope.launcher) else {
        return false;
    };
    let image_parts: Vec<_> = image.components().collect();
    let root_parts: Vec<_> = root.components().collect();
    if image_parts.len() <= root_parts.len()
        || !image_parts.iter().zip(&root_parts).all(|(a, b)| {
            #[cfg(windows)]
            {
                a.as_os_str()
                    .to_str()
                    .zip(b.as_os_str().to_str())
                    .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
            }
            #[cfg(not(windows))]
            {
                a == b
            }
        })
    {
        return false;
    }
    // Reject existing aliases before canonicalize can follow them. A missing
    // image, alternate browser executable or sibling instance is not ownership.
    crate::fs_safety::ensure_file(&image).is_ok()
        && std::fs::canonicalize(image).is_ok_and(|path| path == scope.browser_exe)
}

const MAX_REPORT_FILES: usize = 256;

/// Flat report directories only. Preflight every attachment before mutation,
/// holding Windows handles that deny active readers/writers but allow deletion.
/// Unsupported entries, nested directories and linked paths preserve the report.
fn idle_report_files(root: &Path, dir: &Path) -> std::io::Result<Vec<(PathBuf, std::fs::File)>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if files.len() == MAX_REPORT_FILES || !plain_path_under(root, &path) {
            return Err(std::io::Error::other(
                "unsupported or oversized WER report directory",
            ));
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() || is_reparse(&metadata) {
            return Err(std::io::Error::other("nonordinary WER report attachment"));
        }
        let mut options = std::fs::File::options();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE);
        }
        let file = options.open(&path)?;
        files.push((path, file));
    }
    Ok(files)
}

/// Leave attribution metadata until all attachments have been removed, so a
/// normal partial deletion failure can be retried on a later completed session.
/// New entries are not recursively deleted; `remove_dir` must find an empty folder.
fn remove_attributed_report(root: &Path, dir: &Path, scope: &Scope) -> std::io::Result<()> {
    use std::io::Read;
    let mut files = idle_report_files(root, dir)?;
    let is_metadata = |path: &Path| {
        path.file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("Report.wer"))
    };
    if files.iter().filter(|(path, _)| is_metadata(path)).count() != 1 {
        return Err(std::io::Error::other(
            "ambiguous WER report metadata filename",
        ));
    }
    files.sort_by(|(a, _), (b, _)| is_metadata(a).cmp(&is_metadata(b)).then_with(|| a.cmp(b)));
    let (metadata_path, metadata_file) = files
        .pop()
        .ok_or_else(|| std::io::Error::other("empty WER report"))?;
    let mut bytes = Vec::new();
    if metadata_file.metadata()?.len() > MAX_METADATA_BYTES {
        return Err(std::io::Error::other("oversized WER report metadata"));
    }
    (&metadata_file)
        .take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > usize::try_from(MAX_METADATA_BYTES).unwrap_or(0)
        || !report_application_path(&bytes).is_some_and(|image| report_matches_image(&image, scope))
    {
        return Err(std::io::Error::other(
            "WER attribution changed or is unreadable",
        ));
    }
    for (path, guard) in files {
        if !plain_path_under(root, &path) {
            return Err(std::io::Error::other("WER attachment path changed"));
        }
        std::fs::remove_file(path)?;
        drop(guard);
    }
    if !plain_path_under(root, &metadata_path) {
        return Err(std::io::Error::other("WER metadata path changed"));
    }
    std::fs::remove_file(metadata_path)?;
    drop(metadata_file);
    if !plain_path_under(root, dir) {
        return Err(std::io::Error::other("WER report directory path changed"));
    }
    std::fs::remove_dir(dir)
}

fn cleanup_reports(root: &Path, scope: &Scope) -> bool {
    if ordinary_report_path(root).is_none() || crate::fs_safety::ensure_directory(root).is_err() {
        return false;
    }
    let mut completed = true;
    for subdir in ["ReportQueue", "ReportArchive"] {
        let queue = root.join("Microsoft/Windows/WER").join(subdir);
        if crate::fs_safety::ensure_directory(&queue).is_err() {
            completed = false;
            continue;
        }
        let entries = match std::fs::read_dir(&queue) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                completed = false;
                continue;
            }
        };
        if !plain_path_under(root, &queue) {
            completed = false;
            continue;
        }
        for entry in entries {
            let Ok(entry) = entry else {
                completed = false;
                continue;
            };
            let dir = entry.path();
            if !plain_path_under(root, &dir) {
                completed = false;
                continue;
            }
            if !dir.is_dir() {
                continue;
            }
            let Some(bytes) = read_metadata_file(root, &dir.join("Report.wer")) else {
                completed = false;
                continue;
            };
            let Some(image) = report_application_path(&bytes) else {
                continue;
            };
            if !report_matches_image(&image, scope) {
                continue;
            }
            if remove_attributed_report(root, &dir, scope).is_ok() {
                tracing::info!(path = %dir.display(), "removed WER report attributed to this browser image");
            } else {
                completed = false;
                tracing::debug!(path = %dir.display(), "WER report not fully removed; inaccessible, active or unsupported entries may remain");
            }
        }
    }
    completed
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
            Self::from_temp(crate::tests::owned_temp_fixture())
        }

        fn from_temp(temp: tempfile::TempDir) -> Self {
            let launcher = temp.path().join("portable/Helium");
            let exe = launcher.join("Browser/chrome.exe");
            std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
            std::fs::write(&exe, b"MZ fixture").unwrap();
            crate::instance::ensure(&launcher, "helium", true).unwrap();
            let paths = HostPaths {
                appdata: Some(temp.path().join("host/AppData")),
                localappdata: Some(temp.path().join("host/Local")),
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
    fn nested_browser_image_uses_the_outer_instance_install_lock() {
        let f = Fixture::new();
        let image = f.launcher.join("Browser/version/chrome.exe");
        std::fs::create_dir_all(image.parent().unwrap()).unwrap();
        std::fs::write(&image, b"inert").unwrap();
        let scope = Scope::new(&f.launcher, &image, "helium").unwrap();
        assert_eq!(scope.install_dir(), Some(scope.launcher.join("Browser")));
        let _lock = crate::install::InstanceLock::acquire(&f.launcher.join("Browser")).unwrap();
        assert!(crate::install::InstanceLock::acquire(&scope.install_dir().unwrap()).is_err());
    }

    #[test]
    fn cleanup_session_coalesces_workers_and_releases_for_the_next_session() {
        let f = Fixture::new();
        let first = CleanupSession::acquire(&f.launcher, &f.exe, "helium")
            .unwrap()
            .unwrap();
        assert!(CleanupSession::acquire(&f.launcher, &f.exe, "helium")
            .unwrap()
            .is_none());
        let other = Fixture::new();
        assert!(
            CleanupSession::acquire(&other.launcher, &other.exe, "helium")
                .unwrap()
                .is_some()
        );
        drop(first);
        assert!(CleanupSession::acquire(&f.launcher, &f.exe, "helium")
            .unwrap()
            .is_some());
    }

    #[test]
    fn cleanup_session_rejects_foreign_identity_and_linked_lock_without_writes() {
        let f = Fixture::new();
        assert!(CleanupSession::acquire(&f.launcher, &f.exe, "floorp").is_err());
        let lock = f.launcher.join("Nomad/cleanup.lock");
        assert!(!lock.exists());
        let foreign = f.host("foreign");
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("sentinel"), b"keep").unwrap();
        crate::tests::owned_directory_link(&f.temp, &lock, &foreign);
        assert!(CleanupSession::acquire(&f.launcher, &f.exe, "helium").is_err());
        assert_eq!(std::fs::read(foreign.join("sentinel")).unwrap(), b"keep");
    }

    #[test]
    fn thumbnail_cleanup_preserves_other_files_and_linked_cache_sources() {
        let f = Fixture::new();
        let dir = f.host("Explorer");
        std::fs::create_dir_all(&dir).unwrap();
        for name in [
            "thumbcache_32.db",
            "iconcache_48.db",
            "notes.db",
            "thumbcache_32.txt",
        ] {
            std::fs::write(dir.join(name), b"fixture").unwrap();
        }
        assert_eq!(scrub_unlocked_thumbnail_cache(&dir).unwrap(), 2);
        for name in ["notes.db", "thumbcache_32.txt"] {
            assert_eq!(std::fs::read(dir.join(name)).unwrap(), b"fixture");
        }
        let link = f.host("linked");
        crate::tests::owned_directory_link(&f.temp, &link, &dir);
        assert!(scrub_unlocked_thumbnail_cache(&link).is_err());
        assert_eq!(std::fs::read(dir.join("notes.db")).unwrap(), b"fixture");
    }

    #[cfg(windows)]
    #[test]
    fn thumbnail_cleanup_preserves_active_readers_even_with_delete_sharing() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        let temp = tempfile::tempdir().unwrap();
        let locked = temp.path().join("thumbcache_locked.db");
        std::fs::write(&locked, b"keep").unwrap();
        for sharing in [0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE] {
            let handle = std::fs::File::options()
                .read(true)
                .share_mode(sharing)
                .open(&locked)
                .unwrap();
            assert_eq!(scrub_unlocked_thumbnail_cache(temp.path()).unwrap(), 0);
            drop(handle);
            assert_eq!(std::fs::read(&locked).unwrap(), b"keep");
        }
        assert_eq!(scrub_unlocked_thumbnail_cache(temp.path()).unwrap(), 1);
        assert!(!locked.exists());
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

    fn wer_metadata(image: &Path) -> String {
        // Authored synthetic report-shaped metadata, not a captured Windows crash.
        format!("Version=1\r\nEventType=APPCRASH\r\nReportType=2\r\nAppName=chrome.exe\r\nSig[0].Name=Application Name\r\nSig[0].Value=chrome.exe\r\nAppPath={}\r\n", image.display())
    }

    #[test]
    fn wer_cleanup_covers_user_and_machine_queues_and_archives_without_name_attribution() {
        let f = Fixture::new();
        let foreign_image = f.put("installed/chrome.exe", b"foreign fixture");
        let mut owned = Vec::new();
        let mut foreign = Vec::new();
        for root in ["Local", "ProgramData"] {
            for queue in ["ReportQueue", "ReportArchive"] {
                let base = format!("{root}/Microsoft/Windows/WER/{queue}");
                let text = wer_metadata(&f.exe);
                let bytes = if queue == "ReportQueue" {
                    let mut bytes = vec![0xef, 0xbb, 0xbf];
                    bytes.extend_from_slice(text.as_bytes());
                    bytes
                } else {
                    let mut bytes = vec![0xff, 0xfe];
                    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
                    bytes
                };
                let report = f
                    .put(&format!("{base}/arbitrary-owned-name/Report.wer"), &bytes)
                    .parent()
                    .unwrap()
                    .to_owned();
                std::fs::write(report.join("memory.dmp"), b"inert dump attachment").unwrap();
                std::fs::write(report.join("details.xml"), b"inert diagnostic attachment").unwrap();
                owned.push(report);
                let other = f
                    .put(
                        &format!("{base}/AppCrash_chrome.exe_misleading/Report.wer"),
                        wer_metadata(&foreign_image).as_bytes(),
                    )
                    .parent()
                    .unwrap()
                    .to_owned();
                std::fs::write(other.join("memory.dmp"), b"foreign attachment").unwrap();
                foreign.push(other);
            }
        }
        let standalone = f.put(
            "Local/CrashDumps/chrome.exe.1234.dmp",
            b"unattributed memory",
        );
        let temporary = f.put(
            "Local/Microsoft/Windows/WER/Temp/browser.dmp",
            b"shared temp diagnostic",
        );
        f.run();
        assert!(owned.iter().all(|report| !report.exists()));
        for report in foreign {
            assert_eq!(
                std::fs::read(report.join("memory.dmp")).unwrap(),
                b"foreign attachment"
            );
        }
        assert_eq!(std::fs::read(standalone).unwrap(), b"unattributed memory");
        assert_eq!(std::fs::read(temporary).unwrap(), b"shared temp diagnostic");
    }

    #[test]
    fn wer_cleanup_preserves_ambiguous_invalid_missing_and_other_owned_images() {
        let f = Fixture::new();
        let other = f.launcher.join("Browser/other.exe");
        std::fs::write(&other, b"owned but different image").unwrap();
        let missing = f.launcher.join("Browser/missing.exe");
        let text = wer_metadata(&f.exe);
        let cases = [
            format!("{text}AppPath={}\n", f.exe.display()).into_bytes(),
            format!("{text}aPpPaTh={}\n", other.display()).into_bytes(),
            format!("{text}\0ignored trailing content").into_bytes(),
            wer_metadata(&other).into_bytes(),
            wer_metadata(&missing).into_bytes(),
            b"Version=1\nAppPath=Browser/chrome.exe\n".to_vec(),
            b"Version=1\nAppName=chrome.exe\n".to_vec(),
            vec![0xff, 0xfe, 0x00, 0xd8],
        ];
        let reports: Vec<_> = cases
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                let report = f
                    .put(
                        &format!("Local/Microsoft/Windows/WER/ReportQueue/invalid-{i}/Report.wer"),
                        bytes,
                    )
                    .parent()
                    .unwrap()
                    .to_owned();
                std::fs::write(report.join("memory.dmp"), b"keep attachment").unwrap();
                report
            })
            .collect();
        f.run();
        for (report, bytes) in reports.iter().zip(&cases) {
            assert_eq!(&std::fs::read(report.join("Report.wer")).unwrap(), bytes);
            assert_eq!(
                std::fs::read(report.join("memory.dmp")).unwrap(),
                b"keep attachment"
            );
        }
    }

    #[test]
    fn wer_cleanup_refuses_app_path_aliases_and_parent_components() {
        let f = Fixture::new();
        let alias = f.launcher.join("alias");
        make_directory_link(&f.temp, &alias, f.exe.parent().unwrap());
        let foreign_alias = f.host("installed-alias");
        std::fs::create_dir_all(foreign_alias.parent().unwrap()).unwrap();
        make_directory_link(&f.temp, &foreign_alias, f.exe.parent().unwrap());
        let candidates = [
            alias.join("chrome.exe"),
            foreign_alias.join("chrome.exe"),
            f.launcher.join("Browser/../Browser/chrome.exe"),
        ];
        let reports: Vec<_> = candidates
            .iter()
            .enumerate()
            .map(|(i, image)| {
                f.put(
                    &format!("Local/Microsoft/Windows/WER/ReportQueue/alias-{i}/Report.wer"),
                    wer_metadata(image).as_bytes(),
                )
            })
            .collect();
        f.run();
        for report in reports {
            assert!(report.exists());
        }
        assert_eq!(std::fs::read(&f.exe).unwrap(), b"MZ fixture");
    }

    #[test]
    fn wer_cleanup_preserves_linked_nested_and_over_budget_report_attachments() {
        let f = Fixture::new();
        let text = wer_metadata(&f.exe);
        let linked = f.report("linked-attachment", text.as_bytes());
        let outside = f.host("external-diagnostics");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep"), b"unrelated data").unwrap();
        make_directory_link(&f.temp, &linked.join("attachment"), &outside);
        let nested = f.report("nested-attachment", text.as_bytes());
        std::fs::create_dir(nested.join("child")).unwrap();
        std::fs::write(nested.join("child/keep"), b"unsupported nested content").unwrap();
        let large = f.report("over-budget", text.as_bytes());
        for i in 0..MAX_REPORT_FILES {
            std::fs::write(large.join(format!("attachment-{i}")), b"fixture").unwrap();
        }
        f.run();
        for report in [&linked, &nested, &large] {
            assert_eq!(
                std::fs::read(report.join("Report.wer")).unwrap(),
                text.as_bytes()
            );
        }
        assert_eq!(
            std::fs::read(outside.join("keep")).unwrap(),
            b"unrelated data"
        );
        assert_eq!(
            std::fs::read(nested.join("child/keep")).unwrap(),
            b"unsupported nested content"
        );
        assert_eq!(
            std::fs::read(large.join("attachment-0")).unwrap(),
            b"fixture"
        );
        // Exactly the file budget, including Report.wer, remains supported.
        std::fs::remove_file(large.join("attachment-0")).unwrap();
        f.run();
        assert!(!large.exists());
    }

    #[test]
    fn wer_cleanup_preserves_linked_user_root_and_still_cleans_the_machine_root() {
        let mut f = Fixture::new();
        let report = f.report("machine-own", wer_metadata(&f.exe).as_bytes());
        let outside = f.host("outside-local");
        let keep = f.put(
            "outside-local/Microsoft/Windows/WER/ReportQueue/own/Report.wer",
            wer_metadata(&f.exe).as_bytes(),
        );
        let alias = f.host("linked-local");
        make_directory_link(&f.temp, &alias, &outside);
        f.paths.localappdata = Some(alias);
        f.run();
        assert!(!report.exists() && keep.exists());
    }

    #[cfg(windows)]
    #[test]
    fn wer_cleanup_preserves_active_readers_then_retries_after_handles_close() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        let f = Fixture::new();
        let metadata = f.put(
            "Local/Microsoft/Windows/WER/ReportQueue/busy/Report.wer",
            wer_metadata(&f.exe).as_bytes(),
        );
        let report = metadata.parent().unwrap();
        let attachment = report.join("memory.dmp");
        std::fs::write(&attachment, b"busy fixture").unwrap();
        let guard = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&attachment)
            .unwrap();
        f.run();
        assert!(metadata.exists());
        assert_eq!(std::fs::read(&attachment).unwrap(), b"busy fixture");
        drop(guard);
        f.run();
        assert!(!report.exists());
    }

    #[cfg(windows)]
    #[test]
    fn wer_cleanup_partial_delete_failure_keeps_attribution_for_retry() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
        let f = Fixture::new();
        let report = f.report("deletion-blocked", wer_metadata(&f.exe).as_bytes());
        let free = report.join("a-free.txt");
        let blocked = report.join("z-blocked.dmp");
        std::fs::write(&free, b"free attachment").unwrap();
        std::fs::write(&blocked, b"blocked attachment").unwrap();
        // DELETE-only access, with no delete sharing: this is not an active
        // reader/writer, so preflight succeeds, but DeleteFile must fail.
        let guard = std::fs::OpenOptions::new()
            .read(true)
            .access_mode(0x0001_0000)
            .share_mode(FILE_SHARE_READ)
            .open(&blocked)
            .unwrap();
        let root = f.paths.programdata.as_ref().unwrap();
        assert!(idle_report_files(root, &report).is_ok());
        f.run();
        assert!(
            !free.exists(),
            "exercise a real partial deletion before the failure"
        );
        assert!(report.join("Report.wer").exists());
        assert_eq!(std::fs::read(&blocked).unwrap(), b"blocked attachment");
        drop(guard);
        f.run();
        assert!(!report.exists());
    }

    #[cfg(windows)]
    #[test]
    fn wer_report_image_matching_accepts_case_and_verbatim_drive_paths_but_not_devices() {
        let f = Fixture::new();
        let scope = Scope::new(&f.launcher, &f.exe, "helium").unwrap();
        assert!(report_matches_image(
            &PathBuf::from(f.exe.to_str().unwrap().to_ascii_uppercase()),
            &scope
        ));
        assert!(report_matches_image(
            &std::fs::canonicalize(&f.exe).unwrap(),
            &scope
        ));
        for image in [
            r"\\nomad-invalid-host\share\chrome.exe",
            r"\\.\C:\chrome.exe",
            r"C:chrome.exe",
        ] {
            assert!(!report_matches_image(Path::new(image), &scope));
        }
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
                localappdata: None,
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

    #[cfg(windows)]
    fn windows_link(f: &Fixture, name: &str, target: &Path) -> PathBuf {
        let root = f.temp.path();
        let marker = root.join(".nomad-shortcut-fixture");
        std::fs::write(marker, "Nomad inert shortcut fixture").unwrap();
        let script = root.join("create-shell-link.ps1");
        std::fs::write(
            &script,
            include_str!("../tests/fixtures/create-shell-link.ps1"),
        )
        .unwrap();
        let link = f.host(&format!("AppData/Microsoft/Windows/Recent/{name}.lnk"));
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(script)
            .arg("-Root")
            .arg(root)
            .arg("-Target")
            .arg(target.components().collect::<PathBuf>())
            .arg("-Link")
            .arg(&link)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = std::fs::read(&link).unwrap();
        let flags = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        assert!(
            flags & 1 != 0 && flags & 128 != 0,
            "must exercise real IDList/Unicode metadata: {flags:#x}"
        );
        link
    }

    #[cfg(windows)]
    #[test]
    fn windows_created_linkinfo_unicode_and_idlist_only_targets_are_removed_when_paths_agree() {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target");
        std::fs::create_dir_all(&parent).unwrap();
        crate::fs_safety::ensure_directory(&parent).unwrap();
        let f = Fixture::from_temp(
            tempfile::Builder::new()
                .prefix("nomad-native-shortcut-")
                .tempdir_in(&parent)
                .unwrap(),
        );
        let document = f.launcher.join("document.txt");
        std::fs::write(&document, b"owned non-ASCII fixture").unwrap();
        let own = windows_link(&f, "native-unicode-linkinfo", &document);
        let bytes = std::fs::read(&own).unwrap();
        let flags = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        assert!(
            flags & 2 != 0,
            "must test Windows-created LinkInfo as well: {flags:#x}"
        );
        f.run();
        assert!(!own.exists());
        let unicode_document = f.launcher.join("café.txt");
        std::fs::write(&unicode_document, b"owned non-ASCII fixture").unwrap();
        let unicode_link = windows_link(&f, "native-unicode-target", &unicode_document);
        // Derive the format variant that Windows can also emit: retain its
        // real PIDL/StringData/ExtraData but remove the optional LinkInfo.
        let mut id_only = std::fs::read(&unicode_link).unwrap();
        let flags = u32::from_le_bytes(id_only[20..24].try_into().unwrap());
        assert!(flags & 2 != 0);
        let info_pos = windows_link_info_offset(&id_only);
        let size = u32::from_le_bytes(id_only[info_pos..info_pos + 4].try_into().unwrap()) as usize;
        id_only.drain(info_pos..info_pos + size);
        id_only[20..24].copy_from_slice(&(flags & !2).to_le_bytes());
        let id_only_link = f.put("AppData/Microsoft/Windows/Recent/idlist-only.lnk", &id_only);
        f.run();
        assert!(!unicode_link.exists() && !id_only_link.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_created_links_preserve_unknown_folder_translation() {
        // The checkout may be on D: outside any known user folder on CI.
        // TEMP is under LocalAppData/Profile on the supported Windows runners;
        // keep this format-specific case there and still require the record.
        let f = Fixture::from_temp(crate::tests::owned_temp_fixture());
        let source = windows_link(&f, "folder-source", &f.exe);
        let bytes = std::fs::read(&source).unwrap();
        let flags = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let mut cursor = windows_link_info_offset(&bytes);
        if flags & 2 != 0 {
            cursor += u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        }
        for bit in [4, 8, 16, 32, 64] {
            if flags & bit != 0 {
                let count = usize::from(u16::from_le_bytes(
                    bytes[cursor..cursor + 2].try_into().unwrap(),
                ));
                cursor += 2 + count * (if flags & 128 != 0 { 2 } else { 1 });
            }
        }
        let mut known_pos = None;
        let mut special_pos = None;
        while u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) != 0 {
            let size = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
            let sig = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
            match sig {
                0xa000_000b => known_pos = Some(cursor),
                0xa000_0005 => special_pos = Some(cursor),
                _ => {}
            }
            cursor += size;
        }
        let known = known_pos.expect("must exercise a Windows-created folder translation record");
        let mut unknown = bytes.clone();
        unknown[known + 8..known + 24].fill(0x55);
        let mut wrong_folder = bytes.clone();
        // A supported but conflicting folder ID must fail native corroboration,
        // not merely the allowlist check. Keep the paired legacy ID consistent.
        let profile = [
            0x8f, 0x85, 0x6c, 0x5e, 0x22, 0x0e, 0x60, 0x47, 0x9a, 0xfe, 0xea, 0x33, 0x17, 0xb6,
            0x71, 0x73,
        ];
        let local = [
            0x85, 0x27, 0xb3, 0xf1, 0xba, 0x6f, 0xcf, 0x4f, 0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15,
            0x70, 0x91,
        ];
        let (guid, legacy) = if bytes[known + 8..known + 24] == local {
            (profile, 40u32)
        } else {
            (local, 28u32)
        };
        wrong_folder[known + 8..known + 24].copy_from_slice(&guid);
        if let Some(special) = special_pos {
            wrong_folder[special + 8..special + 12].copy_from_slice(&legacy.to_le_bytes());
        }
        let mut invalid_offset = bytes.clone();
        invalid_offset[known + 24..known + 28].copy_from_slice(&1u32.to_le_bytes());
        let mut wrong_offset = bytes.clone();
        let terminal = u32::from(u16::from_le_bytes(bytes[76..78].try_into().unwrap())) - 2;
        wrong_offset[known + 24..known + 28].copy_from_slice(&terminal.to_le_bytes());
        if let Some(special) = special_pos {
            wrong_offset[special + 12..special + 16].copy_from_slice(&terminal.to_le_bytes());
        }
        let cases = [unknown, wrong_folder, invalid_offset, wrong_offset];
        let links: Vec<_> = cases
            .iter()
            .enumerate()
            .map(|(i, content)| {
                f.put(
                    &format!("AppData/Microsoft/Windows/Recent/folder-conflict-{i}.lnk"),
                    content,
                )
            })
            .collect();
        f.run();
        for (i, (link, expected)) in links.iter().zip(&cases).enumerate() {
            assert_eq!(
                &std::fs::read(link).unwrap_or_else(|e| panic!("folder case {i}: {e}")),
                expected
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_created_links_preserve_missing_targets_without_resolution() {
        let f = Fixture::new();
        let document = f.launcher.join("removed-document.txt");
        std::fs::write(&document, b"inert fixture").unwrap();
        let own = windows_link(&f, "native-missing", &document);
        let original = std::fs::read(&own).unwrap();
        std::fs::remove_file(&document).unwrap();
        f.run();
        assert_eq!(std::fs::read(&own).unwrap(), original);
    }

    #[cfg(windows)]
    fn windows_link_info_offset(bytes: &[u8]) -> usize {
        78 + usize::from(u16::from_le_bytes(bytes[76..78].try_into().unwrap()))
    }

    #[cfg(windows)]
    #[test]
    fn windows_created_links_cleanup_only_owns_matching_current_targets() {
        let f = Fixture::new();
        let document = f.launcher.join("document.txt");
        std::fs::write(&document, b"owned text fixture").unwrap();
        let own = windows_link(&f, "native-owned", &document);
        let foreign_target = f.put("installed/document.txt", b"foreign fixture");
        let foreign = windows_link(&f, "native-foreign", &foreign_target);
        let sibling_target = f.temp.path().join("portable/Helium-other/document.txt");
        std::fs::create_dir_all(sibling_target.parent().unwrap()).unwrap();
        std::fs::write(&sibling_target, b"sibling fixture").unwrap();
        let sibling = windows_link(&f, "native-sibling", &sibling_target);
        let expected = std::fs::canonicalize(&document).unwrap();
        let scope = Scope::new(&f.launcher, &f.exe, "helium").unwrap();
        assert_eq!(
            crate::shell_link::owned_target(&std::fs::read(&own).unwrap(), &own, &scope.launcher),
            Some(expected)
        );
        f.run();
        assert!(
            !own.exists(),
            "real Windows-created owned link must be removed"
        );
        assert!(foreign.exists() && sibling.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_created_links_preserve_conflicting_idlist_and_relative_targets() {
        let f = Fixture::new();
        let own = windows_link(&f, "native-own-source", &f.exe);
        let foreign_target = f.put("installed/chrome.exe", b"foreign fixture");
        let foreign = windows_link(&f, "native-foreign-source", &foreign_target);
        let mut owned_bytes = std::fs::read(&own).unwrap();
        let original_flags = u32::from_le_bytes(owned_bytes[20..24].try_into().unwrap());
        if original_flags & 2 == 0 {
            // Windows can omit LinkInfo for known-folder links. Add the separate
            // stored representation specifically to exercise disagreement.
            let synthetic = crate::tests::make_lnk(&f.exe.to_string_lossy());
            let info_pos = windows_link_info_offset(&owned_bytes);
            owned_bytes.splice(info_pos..info_pos, synthetic[76..].iter().copied());
            owned_bytes[20..24].copy_from_slice(&(original_flags | 2).to_le_bytes());
        }
        let foreign_bytes = std::fs::read(&foreign).unwrap();
        let mut conflicting = owned_bytes[..76].to_vec();
        conflicting.extend_from_slice(&foreign_bytes[76..windows_link_info_offset(&foreign_bytes)]);
        conflicting.extend_from_slice(&owned_bytes[windows_link_info_offset(&owned_bytes)..]);
        let idlist_conflict = f.put(
            "AppData/Microsoft/Windows/Recent/idlist-conflict.lnk",
            &conflicting,
        );
        let info = windows_link_info_offset(&owned_bytes);
        let info_size =
            u32::from_le_bytes(owned_bytes[info..info + 4].try_into().unwrap()) as usize;
        let string_pos = info + info_size;
        let flags = u32::from_le_bytes(owned_bytes[20..24].try_into().unwrap());
        assert!(flags & 4 == 0 && flags & 8 != 0);
        let old_count = usize::from(u16::from_le_bytes(
            owned_bytes[string_pos..string_pos + 2].try_into().unwrap(),
        ));
        let replacement: Vec<u16> = foreign_target.to_str().unwrap().encode_utf16().collect();
        let mut relative_bytes = owned_bytes[..string_pos].to_vec();
        relative_bytes.extend_from_slice(&u16::try_from(replacement.len()).unwrap().to_le_bytes());
        for ch in replacement {
            relative_bytes.extend_from_slice(&ch.to_le_bytes());
        }
        relative_bytes.extend_from_slice(&owned_bytes[string_pos + 2 + old_count * 2..]);
        let relative_conflict = f.put(
            "AppData/Microsoft/Windows/Recent/relative-conflict.lnk",
            &relative_bytes,
        );
        f.run();
        assert_eq!(std::fs::read(idlist_conflict).unwrap(), conflicting);
        assert_eq!(std::fs::read(relative_conflict).unwrap(), relative_bytes);
        assert!(foreign.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_created_links_preserve_malformed_override_and_unknown_records() {
        let f = Fixture::new();
        let source = windows_link(&f, "native-source", &f.exe);
        let original = std::fs::read(&source).unwrap();
        let mut cases = Vec::new();
        let mut invalid_item = original.clone();
        invalid_item[78..80].copy_from_slice(&u16::MAX.to_le_bytes());
        cases.push(invalid_item);
        let mut unknown_root = original.clone();
        unknown_root[82..98].fill(0);
        cases.push(unknown_root);
        let mut no_terminator = original.clone();
        no_terminator.truncate(no_terminator.len() - 4);
        cases.push(no_terminator);
        let mut unknown_block = original[..original.len() - 4].to_vec();
        unknown_block.extend_from_slice(&8u32.to_le_bytes());
        unknown_block.extend_from_slice(&0xa000_0001u32.to_le_bytes());
        unknown_block.extend_from_slice(&0u32.to_le_bytes());
        cases.push(unknown_block);
        for flag in [0x100u32, 0x200, 0x1000, 0x0200_0000] {
            let mut bytes = original.clone();
            let flags = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
            bytes[20..24].copy_from_slice(&(flags | flag).to_le_bytes());
            cases.push(bytes);
        }
        let paths: Vec<_> = cases
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                f.put(
                    &format!("AppData/Microsoft/Windows/Recent/malformed-{i}.lnk"),
                    bytes,
                )
            })
            .collect();
        f.run();
        for (path, expected) in paths.iter().zip(&cases) {
            assert_eq!(&std::fs::read(path).unwrap(), expected);
        }
    }
    fn make_directory_link(temp: &tempfile::TempDir, link: &Path, target: &Path) {
        crate::tests::owned_directory_link(temp, link, target);
    }
}
