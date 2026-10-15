//! Bounded, host/user-bound recovery of attributed cleanup only.
use crate::{
    cleanup::{CleanupSession, Scope},
    cleanup_process::Presence,
};
use serde::{Deserialize, Serialize};
use std::{
    hash::{BuildHasher, RandomState},
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
pub(crate) const DIRECTORY: &str = "cleanup-pending";
const MAX_RECORDS: usize = 32;
const MAX_ENTRIES: usize = 64;
const MAX_BYTES: u64 = 65_536;
const MAGIC: &[u8] = b"NOMAD-CLEANUP-1\0";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u8,
    browser: String,
    root: PathBuf,
    image: PathBuf,
}
trait Binding {
    fn seal(&self, bytes: &[u8]) -> io::Result<Vec<u8>>;
    fn open(&self, bytes: &[u8]) -> io::Result<Vec<u8>>;
}
struct NativeBinding;
impl Binding for NativeBinding {
    fn seal(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        #[cfg(windows)]
        {
            let user = dpapi(bytes, true, false)?;
            dpapi(&user, true, true)
        }
        #[cfg(not(windows))]
        {
            let _ = bytes;
            Err(io::Error::other("Windows binding unavailable"))
        }
    }
    fn open(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        #[cfg(windows)]
        {
            let machine = dpapi(bytes, false, false)?;
            dpapi(&machine, false, false)
        }
        #[cfg(not(windows))]
        {
            let _ = bytes;
            Err(io::Error::other("Windows binding unavailable"))
        }
    }
}
#[cfg(windows)]
fn dpapi(bytes: &[u8], protect: bool, machine: bool) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE,
            CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };
    if bytes.len() > usize::try_from(MAX_BYTES).unwrap_or(0) {
        return Err(io::Error::other("cleanup binding input too large"));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(io::Error::other)?,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let flags = CRYPTPROTECT_UI_FORBIDDEN
        | if protect && machine {
            CRYPTPROTECT_LOCAL_MACHINE
        } else {
            0
        };
    // SAFETY: initialized bounded blobs; all optional pointers are null, UI is forbidden,
    // and returned Windows allocation is always released with LocalFree below.
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &raw const input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                flags,
                &raw mut output,
            )
        } else {
            CryptUnprotectData(
                &raw const input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                flags,
                &raw mut output,
            )
        }
    };
    let result = if ok == 0 {
        Err(io::Error::last_os_error())
    } else if output.pbData.is_null() || output.cbData == 0 || u64::from(output.cbData) > MAX_BYTES
    {
        Err(io::Error::other("invalid cleanup binding output"))
    } else {
        // SAFETY: successful DPAPI result describes this Windows-owned initialized buffer.
        Ok(unsafe {
            std::slice::from_raw_parts(output.pbData, usize::try_from(output.cbData).unwrap_or(0))
        }
        .to_vec())
    };
    if !output.pbData.is_null() {
        // SAFETY: DPAPI returned this allocation and no Rust slice is retained.
        unsafe {
            LocalFree(output.pbData.cast());
        }
    }
    result
}
fn directory(root: &Path) -> PathBuf {
    crate::config::nomad_subdir(root).join(DIRECTORY)
}
fn records(root: &Path) -> io::Result<Vec<PathBuf>> {
    record_listing(root).map(|(paths, _)| paths)
}
fn record_listing(root: &Path) -> io::Result<(Vec<PathBuf>, usize)> {
    let dir = directory(root);
    crate::fs_safety::ensure_directory(&dir)?;
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(e),
    };
    let mut paths = Vec::new();
    let mut count = 0;
    for (index, entry) in entries.enumerate() {
        if index == MAX_ENTRIES {
            return Err(io::Error::other("cleanup journal entry budget exceeded"));
        }
        let path = entry?.path();
        count += 1;
        let valid = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("pending-"))
            .and_then(|n| n.strip_suffix(".bin"))
            .is_some_and(|n| n.len() == 16 && n.bytes().all(|b| b.is_ascii_hexdigit()));
        if valid {
            paths.push(path);
            if paths.len() > MAX_RECORDS {
                return Err(io::Error::other("cleanup journal record budget exceeded"));
            }
        }
    }
    paths.sort();
    Ok((paths, count))
}
fn decode<B: Binding>(binding: &B, bytes: &[u8], root: &Path, id: &str) -> Option<Scope> {
    let encrypted = bytes.strip_prefix(MAGIC)?;
    let plaintext = binding.open(encrypted).ok()?;
    if plaintext.len() > usize::try_from(MAX_BYTES).ok()? {
        return None;
    }
    let record: Record = serde_json::from_slice(&plaintext).ok()?;
    if record.schema != 1 || record.browser != id || record.root != root {
        return None;
    }
    let scope = Scope::new(root, &record.image, id)?;
    (scope.launcher == record.root && scope.browser_exe == record.image).then_some(scope)
}
fn arm_with<B: Binding>(root: &Path, image: &Path, id: &str, binding: &B) -> io::Result<()> {
    let scope =
        Scope::new(root, image, id).ok_or_else(|| io::Error::other("cleanup scope unavailable"))?;
    let (entries, count) = record_listing(&scope.launcher)?;
    for path in &entries {
        if let Some(bytes) = crate::version_cache::read_bounded(path, MAX_BYTES) {
            if decode(binding, &bytes, &scope.launcher, id)
                .is_some_and(|old| old.browser_exe == scope.browser_exe)
            {
                return Ok(());
            }
        }
    }
    if entries.len() == MAX_RECORDS || count == MAX_ENTRIES {
        return Err(io::Error::other(
            "cleanup journal is full; existing records preserved",
        ));
    }
    let payload = serde_json::to_vec(&Record {
        schema: 1,
        browser: id.into(),
        root: scope.launcher.clone(),
        image: scope.browser_exe,
    })?;
    let encrypted = binding.seal(&payload)?;
    let mut bytes = MAGIC.to_vec();
    bytes.extend(encrypted);
    if u64::try_from(bytes.len()).map_err(io::Error::other)? > MAX_BYTES {
        return Err(io::Error::other("cleanup record too large"));
    }
    let dir = directory(&scope.launcher);
    crate::fs_safety::create_dir_all(&dir)?;
    for _ in 0..16 {
        let token = RandomState::new()
            .hash_one((std::process::id(), SEQUENCE.fetch_add(1, Ordering::Relaxed)));
        let path = dir.join(format!("pending-{token:016x}.bin"));
        match crate::fs_safety::write_new(&path, &bytes) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("cannot allocate cleanup journal record"))
}
fn retire(path: &Path, expected: &[u8]) -> io::Result<()> {
    crate::fs_safety::ensure_file(path)?;
    if crate::version_cache::read_bounded(path, MAX_BYTES).as_deref() != Some(expected) {
        return Err(io::Error::other("cleanup journal changed; preserving it"));
    }
    std::fs::remove_file(path)
}
fn replay_with<B: Binding>(
    root: &Path,
    id: &str,
    binding: &B,
    mut probe: impl FnMut(&Scope) -> Presence,
    mut clean: impl FnMut(&Scope) -> bool,
) -> io::Result<usize> {
    let root = root.canonicalize()?;
    let mut retired = 0;
    for path in records(&root)? {
        let Some(bytes) = crate::version_cache::read_bounded(&path, MAX_BYTES) else {
            continue;
        };
        let Some(scope) = decode(binding, &bytes, &root, id) else {
            continue;
        };
        let Some(_coordinator) = CleanupSession::acquire(&root, &scope.browser_exe, id)? else {
            continue;
        };
        if probe(&scope) == Presence::Idle && clean(&scope) {
            retire(&path, &bytes)?;
            retired += 1;
        }
    }
    Ok(retired)
}
/// Caller must hold the per-folder install lock; no process, update or registry action here.
pub(crate) fn recover(root: &Path, id: &str) {
    let result = replay_with(
        root,
        id,
        &NativeBinding,
        |s| crate::cleanup_process::probe(&s.launcher, &s.browser_exe),
        |s| crate::cleanup::scrub_host_traces(&s.launcher, &s.browser_exe, id),
    );
    match result {
        Ok(count) if count != 0 => {
            tracing::info!(count, "retired completed owned cleanup recovery records");
        }
        Err(error) => {
            tracing::warn!(%error, "cleanup recovery incomplete; pending records preserved");
        }
        _ => {}
    }
}
/// Best effort, before process creation and under the install lock. Never plaintext fallback.
pub(crate) fn arm(root: &Path, image: &Path, id: &str) {
    if let Err(error) = arm_with(root, image, id, &NativeBinding) {
        tracing::warn!(%error, "cleanup recovery could not be armed; launch may leave host traces");
    }
}
/// Normal coordinator already holds cleanup and install locks and has proved quiescence.
pub(crate) fn complete(root: &Path, image: &Path, id: &str) {
    let result = (|| -> io::Result<()> {
        let scope = Scope::new(root, image, id)
            .ok_or_else(|| io::Error::other("cleanup scope unavailable"))?;
        for path in records(&scope.launcher)? {
            let Some(bytes) = crate::version_cache::read_bounded(&path, MAX_BYTES) else {
                continue;
            };
            if decode(&NativeBinding, &bytes, &scope.launcher, id)
                .is_some_and(|old| old.browser_exe == scope.browser_exe)
            {
                retire(&path, &bytes)?;
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        tracing::warn!(%error, "completed cleanup journal could not be retired");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Model context binding only. This is deliberately NOT a DPAPI/encryption test.
    struct FakeBinding(&'static [u8]);
    impl Binding for FakeBinding {
        fn seal(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
            Ok([self.0, bytes].concat())
        }
        fn open(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
            bytes
                .strip_prefix(self.0)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| io::Error::other("different simulated context"))
        }
    }
    const HERE: FakeBinding = FakeBinding(b"machine-a/user-a:");
    struct Fixture {
        temp: tempfile::TempDir,
        root: PathBuf,
        image: PathBuf,
        _lock: crate::install::InstanceLock,
    }
    impl Fixture {
        fn new() -> Self {
            let temp = crate::tests::owned_temp_fixture();
            let root = temp.path().join("portable");
            let image = root.join("Browser/chrome.exe");
            std::fs::create_dir_all(image.parent().unwrap()).unwrap();
            std::fs::write(&image, b"inert image").unwrap();
            crate::instance::ensure(&root, "helium", true).unwrap();
            let lock = crate::install::InstanceLock::acquire(image.parent().unwrap()).unwrap();
            Self {
                temp,
                root,
                image,
                _lock: lock,
            }
        }
        fn arm(&self) {
            arm_with(&self.root, &self.image, "helium", &HERE).unwrap();
        }
        fn paths(&self) -> Vec<PathBuf> {
            records(&self.root).unwrap()
        }
        fn replay(&self, presence: Presence, completed: bool) -> usize {
            replay_with(
                &self.root,
                "helium",
                &HERE,
                |_| presence,
                |_| {
                    assert_eq!(presence, Presence::Idle);
                    completed
                },
            )
            .unwrap()
        }
        fn replace_record(&self, mutate: impl FnOnce(&mut Record)) {
            let path = self.paths().pop().unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let mut record: Record =
                serde_json::from_slice(&HERE.open(bytes.strip_prefix(MAGIC).unwrap()).unwrap())
                    .unwrap();
            mutate(&mut record);
            let mut bytes = MAGIC.to_vec();
            bytes.extend(HERE.seal(&serde_json::to_vec(&record).unwrap()).unwrap());
            std::fs::write(path, bytes).unwrap();
        }
    }
    #[test]
    fn interrupted_session_deduplicates_then_retries_until_completed() {
        let f = Fixture::new();
        f.arm();
        f.arm();
        assert_eq!(f.paths().len(), 1);
        let before = std::fs::read(&f.paths()[0]).unwrap();
        for presence in [Presence::Running, Presence::Unknown] {
            assert_eq!(
                replay_with(
                    &f.root,
                    "helium",
                    &HERE,
                    |_| presence,
                    |_| panic!("uncertain browser must not clean")
                )
                .unwrap(),
                0
            );
        }
        assert_eq!(f.replay(Presence::Idle, false), 0);
        assert_eq!(std::fs::read(&f.paths()[0]).unwrap(), before);
        assert_eq!(f.replay(Presence::Idle, true), 1);
        assert_eq!(f.paths(), [] as [PathBuf; 0]);
    }
    #[test]
    fn other_machine_or_user_cannot_authorize_replay_or_evict_pending_records() {
        for context in [
            b"machine-b/user-a:".as_slice(),
            b"machine-a/user-b:".as_slice(),
        ] {
            let f = Fixture::new();
            arm_with(&f.root, &f.image, "helium", &FakeBinding(context)).unwrap();
            let old = f.paths()[0].clone();
            let before = std::fs::read(&old).unwrap();
            assert_eq!(
                replay_with(
                    &f.root,
                    "helium",
                    &HERE,
                    |_| panic!("foreign record"),
                    |_| panic!("foreign record")
                )
                .unwrap(),
                0
            );
            f.arm();
            assert_eq!(f.paths().len(), 2);
            assert_eq!(f.replay(Presence::Idle, true), 1);
            assert_eq!(std::fs::read(old).unwrap(), before);
        }
    }
    #[test]
    fn coordinator_contention_preserves_records_and_skips_process_and_cleanup() {
        let f = Fixture::new();
        f.arm();
        let coordinator = CleanupSession::acquire(&f.root, &f.image, "helium")
            .unwrap()
            .unwrap();
        assert_eq!(
            replay_with(
                &f.root,
                "helium",
                &HERE,
                |_| panic!("coordinator busy"),
                |_| panic!("coordinator busy")
            )
            .unwrap(),
            0
        );
        drop(coordinator);
        assert_eq!(f.replay(Presence::Idle, true), 1);
    }
    #[test]
    fn schema_browser_root_and_image_mismatches_never_authorize_cleanup() {
        for case in 0..5 {
            let f = Fixture::new();
            f.arm();
            let foreign = f.temp.path().join("foreign/chrome.exe");
            std::fs::create_dir_all(foreign.parent().unwrap()).unwrap();
            std::fs::write(&foreign, b"preserve foreign").unwrap();
            f.replace_record(|r| match case {
                0 => r.schema = 2,
                1 => r.browser = "floorp".into(),
                2 => r.root = f.temp.path().join("moved"),
                3 => r.image = foreign.clone(),
                _ => r.image = f.root.join("Browser/missing.exe"),
            });
            assert_eq!(
                replay_with(
                    &f.root,
                    "helium",
                    &HERE,
                    |_| panic!("invalid scope"),
                    |_| panic!("invalid scope")
                )
                .unwrap(),
                0
            );
            assert_eq!(f.paths().len(), 1);
            assert_eq!(std::fs::read(foreign).unwrap(), b"preserve foreign");
        }
    }
    #[test]
    fn lost_image_or_marker_preserves_record_for_later_return() {
        for missing in ["Browser/chrome.exe", "Nomad/instance.toml"] {
            let f = Fixture::new();
            f.arm();
            let path = f.root.join(missing);
            let bytes = std::fs::read(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            assert_eq!(
                replay_with(
                    &f.root,
                    "helium",
                    &HERE,
                    |_| panic!("missing ownership"),
                    |_| panic!("missing ownership")
                )
                .unwrap(),
                0
            );
            std::fs::write(path, bytes).unwrap();
            assert_eq!(f.replay(Presence::Idle, true), 1);
        }
    }
    #[test]
    fn moved_folder_cannot_replay_the_original_absolute_scope() {
        let f = Fixture::new();
        f.arm();
        let moved = f.temp.path().join("moved");
        std::fs::create_dir_all(moved.join("Browser")).unwrap();
        std::fs::write(moved.join("Browser/chrome.exe"), b"inert").unwrap();
        crate::instance::ensure(&moved, "helium", true).unwrap();
        std::fs::create_dir_all(directory(&moved)).unwrap();
        let copied = directory(&moved).join(f.paths()[0].file_name().unwrap());
        std::fs::copy(&f.paths()[0], &copied).unwrap();
        let _lock = crate::install::InstanceLock::acquire(&moved.join("Browser")).unwrap();
        assert_eq!(
            replay_with(
                &moved,
                "helium",
                &HERE,
                |_| panic!("moved folder"),
                |_| panic!("moved folder")
            )
            .unwrap(),
            0
        );
        assert!(copied.exists());
    }
    #[test]
    fn malformed_and_oversized_records_are_preserved() {
        let f = Fixture::new();
        f.arm();
        let path = f.paths()[0].clone();
        for bytes in [
            b"truncated ciphertext".to_vec(),
            vec![0; usize::try_from(MAX_BYTES).unwrap() + 1],
            [MAGIC, b"machine-a/user-a:{\"schema\":1,\"unknown\":true}"].concat(),
        ] {
            std::fs::write(&path, &bytes).unwrap();
            assert_eq!(
                replay_with(
                    &f.root,
                    "helium",
                    &HERE,
                    |_| panic!("invalid record"),
                    |_| panic!("invalid record")
                )
                .unwrap(),
                0
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }
    #[test]
    fn full_journal_never_evicts_foreign_records() {
        let f = Fixture::new();
        std::fs::create_dir_all(directory(&f.root)).unwrap();
        for index in 0..MAX_RECORDS {
            std::fs::write(
                directory(&f.root).join(format!("pending-{index:016x}.bin")),
                b"foreign",
            )
            .unwrap();
        }
        assert!(arm_with(&f.root, &f.image, "helium", &HERE).is_err());
        assert_eq!(f.paths().len(), MAX_RECORDS);
        for path in f.paths() {
            assert_eq!(std::fs::read(path).unwrap(), b"foreign");
        }
    }
    #[test]
    fn directory_budget_is_checked_before_any_replay_mutation() {
        let f = Fixture::new();
        f.arm();
        for index in 0..MAX_ENTRIES {
            std::fs::write(
                directory(&f.root).join(format!("unrecognized-{index}")),
                b"preserve",
            )
            .unwrap();
        }
        assert!(replay_with(
            &f.root,
            "helium",
            &HERE,
            |_| panic!("over budget"),
            |_| panic!("over budget")
        )
        .is_err());
        assert_eq!(
            std::fs::read_dir(directory(&f.root)).unwrap().count(),
            MAX_ENTRIES + 1
        );
    }
    #[test]
    fn linked_journal_directory_is_rejected_without_touching_target() {
        let f = Fixture::new();
        let outside = f.temp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"preserve").unwrap();
        crate::tests::owned_directory_link(&f.temp, &directory(&f.root), &outside);
        assert!(arm_with(&f.root, &f.image, "helium", &HERE).is_err());
        assert!(replay_with(
            &f.root,
            "helium",
            &HERE,
            |_| panic!("linked directory"),
            |_| panic!("linked directory")
        )
        .is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"preserve"
        );
    }
    #[test]
    fn sealing_failure_has_no_plaintext_fallback() {
        struct Failed;
        impl Binding for Failed {
            fn seal(&self, _: &[u8]) -> io::Result<Vec<u8>> {
                Err(io::Error::other("unavailable"))
            }
            fn open(&self, _: &[u8]) -> io::Result<Vec<u8>> {
                Err(io::Error::other("unavailable"))
            }
        }
        let f = Fixture::new();
        assert!(arm_with(&f.root, &f.image, "helium", &Failed).is_err());
        assert!(!directory(&f.root).exists());
    }
    #[test]
    fn changed_record_is_not_retired_after_cleanup() {
        let f = Fixture::new();
        f.arm();
        let path = f.paths()[0].clone();
        assert!(replay_with(
            &f.root,
            "helium",
            &HERE,
            |_| Presence::Idle,
            |_| {
                std::fs::write(&path, b"replacement").unwrap();
                true
            }
        )
        .is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"replacement");
    }
    #[cfg(windows)]
    #[test]
    fn locked_record_remains_pending_after_successful_cleanup() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        let f = Fixture::new();
        f.arm();
        let path = f.paths()[0].clone();
        let guard = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path)
            .unwrap();
        assert!(replay_with(&f.root, "helium", &HERE, |_| Presence::Idle, |_| true).is_err());
        assert!(path.exists());
        drop(guard);
        assert_eq!(f.replay(Presence::Idle, true), 1);
    }
    #[cfg(windows)]
    #[test]
    fn busy_attributed_report_is_recovered_only_after_handle_release() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        let f = Fixture::new();
        f.arm();
        let host = f.temp.path().join("host");
        for root in ["AppData", "Local", "ProgramData"] {
            std::fs::create_dir_all(host.join(root)).unwrap();
        }
        let report = host.join("Local/Microsoft/Windows/WER/ReportQueue/owned");
        std::fs::create_dir_all(&report).unwrap();
        std::fs::write(
            report.join("Report.wer"),
            format!("AppPath={}\r\n", f.image.display()),
        )
        .unwrap();
        let dump = report.join("memory.dmp");
        std::fs::write(&dump, b"owned inert report attachment").unwrap();
        let shared = host.join("Local/CrashDumps/chrome.exe.123.dmp");
        std::fs::create_dir_all(shared.parent().unwrap()).unwrap();
        std::fs::write(&shared, b"unattributed preserve").unwrap();
        let guard = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&dump)
            .unwrap();
        let run = || {
            replay_with(
                &f.root,
                "helium",
                &HERE,
                |_| Presence::Idle,
                |s| crate::cleanup::scrub_fixture(&s.launcher, &s.browser_exe, "helium", &host),
            )
            .unwrap()
        };
        assert_eq!(run(), 0);
        assert!(report.join("Report.wer").exists() && f.paths().len() == 1);
        drop(guard);
        assert_eq!(run(), 1);
        assert!(!report.exists() && f.paths().is_empty());
        assert_eq!(std::fs::read(shared).unwrap(), b"unattributed preserve");
    }
    #[test]
    fn linked_record_is_not_read_and_linked_image_is_not_attributed() {
        let f = Fixture::new();
        f.arm();
        let outside = f.temp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"preserve").unwrap();
        let record = directory(&f.root).join("pending-0000000000000000.bin");
        crate::tests::owned_directory_link(&f.temp, &record, &outside);
        assert_eq!(f.replay(Presence::Idle, true), 1);
        assert!(record.exists());
        let image_alias = f.root.join("Browser-alias");
        crate::tests::owned_directory_link(&f.temp, &image_alias, f.image.parent().unwrap());
        assert!(arm_with(&f.root, &image_alias.join("chrome.exe"), "helium", &HERE).is_err());
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"preserve"
        );
    }
    #[test]
    fn full_directory_cannot_add_a_record_that_would_disable_replay() {
        let f = Fixture::new();
        std::fs::create_dir_all(directory(&f.root)).unwrap();
        for index in 0..MAX_ENTRIES {
            std::fs::write(
                directory(&f.root).join(format!("foreign-{index}")),
                b"preserve",
            )
            .unwrap();
        }
        assert!(arm_with(&f.root, &f.image, "helium", &HERE).is_err());
        assert_eq!(
            std::fs::read_dir(directory(&f.root)).unwrap().count(),
            MAX_ENTRIES
        );
        assert_eq!(f.paths(), [] as [PathBuf; 0]);
    }
    #[test]
    fn existing_current_intent_is_reused_at_directory_capacity() {
        let f = Fixture::new();
        f.arm();
        let path = f.paths()[0].clone();
        let bytes = std::fs::read(&path).unwrap();
        for index in 1..MAX_ENTRIES {
            std::fs::write(
                directory(&f.root).join(format!("foreign-{index}")),
                b"preserve",
            )
            .unwrap();
        }
        f.arm();
        assert_eq!(f.paths().len(), 1);
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        assert_eq!(f.replay(Presence::Idle, true), 1);
        assert_eq!(
            std::fs::read_dir(directory(&f.root)).unwrap().count(),
            MAX_ENTRIES - 1
        );
    }
}

// Explicit disposable qualification only; never selected by the normal gate.
#[cfg(all(test, windows))]
#[path = "cleanup_recovery/sandbox_tests.rs"]
mod sandbox_tests;
