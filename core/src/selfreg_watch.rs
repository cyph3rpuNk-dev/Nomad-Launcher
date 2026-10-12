//! Live self-registration repair while the browser is running.
//!
//! A browser's own "Make default" button registers the browser executable
//! itself as the URL handler, bypassing the launcher. Every link clicked
//! after that starts a second browser on its built-in host profile instead of
//! opening a tab in the portable instance. The launch-time and post-exit
//! repairs (`prepare_browser_for_launch`, `repair_registration_after_exit`)
//! leave the whole session in between misrouted, because the button is
//! normally used *while* the browser is open.
//!
//! The detached cleanup watcher already lives exactly as long as the browser,
//! so it also watches `HKCU\Software\Classes` (where every self-registration
//! writes its `ProgId`) and re-runs [`crate::registry::repair_self_registration`]
//! once a burst of changes settles. The repair itself is unchanged: it only
//! rewrites commands whose executable lives inside this launcher's install
//! dir.

use std::time::Duration;

/// How long [`run_repair_loop`] waits for a change before re-checking its stop
/// condition. Bounds how long the watcher outlives the browser.
const POLL: Duration = Duration::from_millis(500);

/// How long a burst of registry changes must stay quiet before the repair
/// runs. A browser writes a dozen keys when it makes itself the default, and
/// unrelated programs write under `Software\Classes` too; settling first
/// turns a burst into one repair instead of a dozen.
pub(crate) const SETTLE: Duration = Duration::from_millis(400);

/// Outcome of waiting on a [`ChangeSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wait {
    /// The watched registry subtree changed.
    Changed,
    /// Nothing changed within the timeout.
    TimedOut,
    /// The source can no longer report changes; the loop must end.
    Failed,
}

/// Something that reports changes to the watched registry subtree.
pub(crate) trait ChangeSource {
    /// Blocks for at most `timeout` waiting for a change.
    fn wait(&mut self, timeout: Duration) -> Wait;
}

/// Runs `repair` after every settled burst of changes from `source` until
/// `should_stop` returns `true` or the source fails. Returns the total number
/// of commands `repair` reported as rewritten.
pub(crate) fn run_repair_loop(
    source: &mut impl ChangeSource,
    should_stop: impl Fn() -> bool,
    mut repair: impl FnMut() -> usize,
    settle: Duration,
) -> usize {
    let mut total = 0;
    while !should_stop() {
        match source.wait(POLL) {
            Wait::TimedOut => {}
            Wait::Failed => return total,
            Wait::Changed => {
                // Drain the rest of the burst. A failure mid-burst still gets
                // one repair for the changes already seen.
                let mut failed = false;
                loop {
                    match source.wait(settle) {
                        Wait::Changed if !should_stop() => {}
                        Wait::Failed => {
                            failed = true;
                            break;
                        }
                        _ => break,
                    }
                }
                total += repair();
                if failed {
                    return total;
                }
            }
        }
    }
    total
}

/// Name of the per-install mutex that lets only one watcher run the live
/// repair. Every clicked link spawns its own cleanup watcher for the whole
/// session; without this, each would sweep the registry on every change.
/// Derived from the lowercased install dir so it is stable for one portable
/// folder and distinct between folders, and contains no backslash after the
/// `Local\` namespace prefix (a kernel-object name requirement).
pub(crate) fn watch_mutex_name(install_dir: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let key = install_dir.to_string_lossy().to_lowercase();
    let digest = hex::encode(Sha256::digest(key.as_bytes()));
    format!("Local\\NomadSelfRegWatch-{}", &digest[..32])
}

#[cfg(windows)]
mod win {
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_NOTIFY,
        REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, CreateMutexW, ReleaseMutex, WaitForSingleObject,
    };

    use super::{ChangeSource, Wait};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Change notifications for the `HKCU\Software\Classes` subtree.
    pub(crate) struct RegistryChangeSource {
        key: HKEY,
        event: HANDLE,
    }

    impl RegistryChangeSource {
        /// Opens the subtree and arms the first notification. Returns `None`
        /// when either step fails; the caller then relies on the post-exit
        /// repair alone, as before.
        pub(crate) fn open() -> Option<Self> {
            let subkey = wide("Software\\Classes");
            let mut key: HKEY = std::ptr::null_mut();
            // SAFETY: `subkey` is NUL-terminated and outlives the call; `key`
            // is a valid out-pointer. The handle is closed in Drop.
            let opened = unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    subkey.as_ptr(),
                    0,
                    KEY_NOTIFY,
                    &raw mut key,
                )
            };
            if opened != ERROR_SUCCESS {
                return None;
            }
            // SAFETY: an unnamed auto-reset event with default security.
            let event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
            if event.is_null() {
                // SAFETY: `key` was opened above and is not used afterwards.
                unsafe { RegCloseKey(key) };
                return None;
            }
            let source = Self { key, event };
            source.arm().then_some(source)
        }

        /// Requests one asynchronous notification. Windows signals `event`
        /// once and must be re-armed after every signal.
        fn arm(&self) -> bool {
            // SAFETY: `key` and `event` are valid handles owned by `self`.
            let status = unsafe {
                RegNotifyChangeKeyValue(
                    self.key,
                    1,
                    REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                    self.event,
                    1,
                )
            };
            status == ERROR_SUCCESS
        }
    }

    impl ChangeSource for RegistryChangeSource {
        fn wait(&mut self, timeout: Duration) -> Wait {
            let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
            // SAFETY: `event` is a valid handle owned by `self`.
            match unsafe { WaitForSingleObject(self.event, ms) } {
                WAIT_OBJECT_0 if self.arm() => Wait::Changed,
                WAIT_TIMEOUT => Wait::TimedOut,
                _ => Wait::Failed,
            }
        }
    }

    impl Drop for RegistryChangeSource {
        fn drop(&mut self) {
            // SAFETY: both handles were created in `open` and are released
            // exactly once here; closing the key cancels the notification.
            unsafe {
                RegCloseKey(self.key);
                CloseHandle(self.event);
            }
        }
    }

    /// Ownership of the per-install watcher mutex, released on drop.
    pub(crate) struct WatchGuard(HANDLE);

    /// Claims the named mutex. Returns `None` when another watcher for the
    /// same install already holds it, or the mutex cannot be created.
    pub(crate) fn claim(name: &str) -> Option<WatchGuard> {
        let name = wide(name);
        // SAFETY: `name` is NUL-terminated and outlives the call.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 1, name.as_ptr()) };
        if handle.is_null() {
            return None;
        }
        // SAFETY: reads the calling thread's last-error value set by
        // CreateMutexW above.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: `handle` is valid and not used afterwards.
            unsafe { CloseHandle(handle) };
            return None;
        }
        Some(WatchGuard(handle))
    }

    impl Drop for WatchGuard {
        fn drop(&mut self) {
            // SAFETY: this thread owns the mutex it created with initial
            // ownership; release, then close the handle exactly once.
            unsafe {
                ReleaseMutex(self.0);
                CloseHandle(self.0);
            }
        }
    }
}

/// A running live-repair thread, stopped by [`LiveRepair::stop`].
pub(crate) struct LiveRepair {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl LiveRepair {
    /// Signals the thread and waits for it, at most about one [`POLL`].
    pub(crate) fn stop(self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = self.thread.join();
    }
}

/// Starts watching for self-registrations that point into `install_dir` and
/// reroutes them through `launcher_exe` while the browser runs. Returns
/// `None` when another watcher already covers this install or the platform
/// has no registry; the post-exit repair still runs in either case.
#[allow(clippy::unnecessary_wraps)] // `None` on non-Windows targets
pub(crate) fn start(
    install_dir: std::path::PathBuf,
    launcher_exe: std::path::PathBuf,
) -> Option<LiveRepair> {
    #[cfg(windows)]
    {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let name = watch_mutex_name(&install_dir);
        let thread = std::thread::spawn(move || {
            // The mutex is claimed on the watching thread: a Win32 mutex is
            // owned by the thread that created it, and must be released by it.
            let Some(_guard) = win::claim(&name) else {
                tracing::debug!("another watcher handles live self-registration repair");
                return;
            };
            let Some(mut source) = win::RegistryChangeSource::open() else {
                tracing::warn!(
                    "could not watch HKCU\\Software\\Classes; self-registrations are \
                     repaired after the browser exits instead"
                );
                return;
            };
            let repaired = run_repair_loop(
                &mut source,
                || stop_thread.load(Ordering::Relaxed),
                || {
                    let n = crate::registry::repair_self_registration(&install_dir, &launcher_exe);
                    if n > 0 {
                        tracing::warn!(
                            repaired = n,
                            "browser registered itself as default during the session; \
                             rerouted through the launcher so clicked links open as tabs \
                             in the portable profile"
                        );
                    }
                    n
                },
                SETTLE,
            );
            tracing::debug!(repaired, "live self-registration watch ended");
        });
        Some(LiveRepair { stop, thread })
    }
    #[cfg(not(windows))]
    {
        let _ = (install_dir, launcher_exe);
        None
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::path::Path;
    use std::rc::Rc;

    use super::*;

    /// Replays a fixed script of wait results, then reports `TimedOut`. The
    /// wait count is shared so a stop closure can read it while the loop
    /// holds the source mutably.
    struct Scripted {
        script: VecDeque<Wait>,
        waits: Rc<Cell<usize>>,
    }

    impl Scripted {
        fn new(script: &[Wait]) -> Self {
            Self {
                script: script.iter().copied().collect(),
                waits: Rc::new(Cell::new(0)),
            }
        }
    }

    impl ChangeSource for Scripted {
        fn wait(&mut self, _timeout: Duration) -> Wait {
            self.waits.set(self.waits.get() + 1);
            self.script.pop_front().unwrap_or(Wait::TimedOut)
        }
    }

    /// Runs the loop over `script`, stopping once the source has been
    /// consulted `limit` times so a test cannot spin forever. Returns the
    /// number of repair calls and the total the loop reported.
    fn run(script: &[Wait], limit: usize) -> (usize, usize) {
        let mut source = Scripted::new(script);
        let waits = Rc::clone(&source.waits);
        let calls = Cell::new(0);
        let total = run_repair_loop(
            &mut source,
            || waits.get() >= limit,
            || {
                calls.set(calls.get() + 1);
                2
            },
            Duration::ZERO,
        );
        (calls.get(), total)
    }

    /// The bug: a browser's own "Make default" during a session was only
    /// repaired after exit. A registry change must now trigger a repair while
    /// the loop is still running.
    #[test]
    fn a_change_during_the_session_triggers_a_repair() {
        let (calls, total) = run(&[Wait::Changed, Wait::TimedOut], 5);
        assert_eq!(calls, 1, "one settled change must cause one repair");
        assert_eq!(total, 2, "the repaired count is reported");
    }

    #[test]
    fn a_burst_of_changes_is_repaired_once() {
        let (calls, _) = run(
            &[Wait::Changed, Wait::Changed, Wait::Changed, Wait::TimedOut],
            8,
        );
        assert_eq!(calls, 1, "a burst must settle into a single repair");
    }

    #[test]
    fn separate_bursts_are_repaired_separately() {
        let (calls, total) = run(
            &[
                Wait::Changed,
                Wait::TimedOut,
                Wait::TimedOut,
                Wait::Changed,
                Wait::TimedOut,
            ],
            8,
        );
        assert_eq!(calls, 2);
        assert_eq!(total, 4);
    }

    #[test]
    fn no_change_means_no_repair() {
        let (calls, total) = run(&[Wait::TimedOut, Wait::TimedOut], 4);
        assert_eq!((calls, total), (0, 0));
    }

    #[test]
    fn a_failed_source_ends_the_loop_without_repairing() {
        let mut source = Scripted::new(&[Wait::Failed]);
        let calls = Cell::new(0);
        let total = run_repair_loop(
            &mut source,
            || false,
            || {
                calls.set(calls.get() + 1);
                1
            },
            Duration::ZERO,
        );
        assert_eq!((calls.get(), total), (0, 0));
        assert_eq!(
            source.waits.get(),
            1,
            "the loop must not keep waiting on a dead source"
        );
    }

    #[test]
    fn a_failure_mid_burst_still_repairs_what_was_seen() {
        let mut source = Scripted::new(&[Wait::Changed, Wait::Failed]);
        let calls = Cell::new(0);
        let total = run_repair_loop(
            &mut source,
            || false,
            || {
                calls.set(calls.get() + 1);
                1
            },
            Duration::ZERO,
        );
        assert_eq!((calls.get(), total), (1, 1));
    }

    #[test]
    fn a_stop_request_ends_the_loop_before_waiting() {
        let mut source = Scripted::new(&[Wait::Changed]);
        let total = run_repair_loop(&mut source, || true, || 1, Duration::ZERO);
        assert_eq!(total, 0);
        assert_eq!(source.waits.get(), 0);
    }

    #[test]
    fn watch_mutex_name_is_stable_per_folder_and_valid() {
        let a = watch_mutex_name(Path::new(r"C:\Portables\Helium\Browser"));
        let same = watch_mutex_name(Path::new(r"c:\portables\helium\browser"));
        let other = watch_mutex_name(Path::new(r"C:\Portables\Floorp\Browser"));
        assert_eq!(a, same, "path case must not split one folder's watchers");
        assert_ne!(a, other, "different folders need different watchers");
        let suffix = a.strip_prefix("Local\\NomadSelfRegWatch-").unwrap();
        assert!(
            !suffix.contains('\\') && suffix.len() == 32,
            "kernel object names allow no backslash after the namespace: {a}"
        );
    }

    /// End-to-end against the real registry: a synthetic `ProgId` whose command
    /// points into a fake install dir must be rerouted while the watcher runs.
    #[cfg(windows)]
    #[test]
    #[ignore = "writes HKCU; run manually only in an isolated test account"]
    fn live_repair_reroutes_a_self_registration_written_mid_session() {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let token: u64 = rand::random();
        let install_dir = std::env::temp_dir()
            .join(format!("nomad-live-{token:x}"))
            .join("Browser");
        let launcher = install_dir.parent().unwrap().join("Nomad-Test.exe");
        let prog_id = format!("Software\\Classes\\NomadLiveTest{token:x}");
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        let live = start(install_dir.clone(), launcher.clone()).expect("watcher starts");
        std::thread::sleep(Duration::from_millis(300));
        let (cmd, _) = hkcu
            .create_subkey(format!("{prog_id}\\shell\\open\\command"))
            .unwrap();
        let browser = install_dir.join("browser.exe");
        cmd.set_value("", &format!("\"{}\" -osint -url \"%1\"", browser.display()))
            .unwrap();

        let expected = format!("\"{}\" -- \"%1\"", launcher.display());
        let mut rerouted = false;
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(100));
            if cmd.get_value::<String, _>("").unwrap() == expected {
                rerouted = true;
                break;
            }
        }
        live.stop();
        let _ = hkcu.delete_subkey_all(&prog_id);
        assert!(
            rerouted,
            "the self-registration was not rerouted while the watcher ran"
        );
    }
}
