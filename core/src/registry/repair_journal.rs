//! Write-ahead records for automatic HKCU command repairs. The file lock only
//! serializes Nomad processes; the registry compare/write is not an OS transaction.
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fs_safety;

const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or mismatched registry repair journal",
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Command {
    pub kind: u32,
    pub bytes: Vec<u8>,
}

impl Command {
    pub fn text(value: &str) -> Self {
        Self {
            kind: 1,
            bytes: value
                .encode_utf16()
                .chain(Some(0))
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }

    fn decode(&self) -> Option<String> {
        if !matches!(self.kind, 1 | 2)
            || self.bytes.len() > 65536
            || !self.bytes.len().is_multiple_of(2)
        {
            return None;
        }
        let words: Vec<_> = self
            .bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        let (&0, text) = words.split_last()? else {
            return None;
        };
        if text.contains(&0) {
            return None;
        }
        String::from_utf16(text).ok()
    }
}

pub(super) trait CommandStore {
    fn read(&self, key: &str) -> io::Result<Option<Command>>;
    /// Never create a missing key/value; compare again immediately before writing.
    fn replace(&mut self, key: &str, expected: &Command, value: &Command) -> io::Result<bool>;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    key: String,
    original: Command,
    replacement: Command,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    launcher: PathBuf,
    install: Option<PathBuf>,
    enabled: bool,
    entries: Vec<Entry>,
}

pub(super) struct Session {
    path: PathBuf,
    state: Journal,
    _lock: File,
}

fn absolute(path: &Path) -> bool {
    path.is_absolute() && !path.components().any(|c| matches!(c, Component::ParentDir))
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
}

/// Return whether this is a `StartMenuInternet` command, or reject the key shape.
fn command_key(key: &str) -> Option<bool> {
    if key.len() > 16384 || key.chars().any(char::is_control) {
        return None;
    }
    let lower = key.to_ascii_lowercase();
    let parts: Vec<_> = lower.split('\\').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return None;
    }
    match parts.as_slice() {
        ["software", "classes", name, "shell", "open", "command"]
            if !name.starts_with('.')
                && !name.starts_with("nomadportable.")
                && *name != "applications" =>
        {
            Some(false)
        }
        ["software", "classes", "applications", _, "shell", "open", "command"] => Some(false),
        ["software", "clients", "startmenuinternet", _, "shell", "open", "command"] => Some(true),
        _ => None,
    }
}

fn replacement(key: &str, launcher: &Path) -> Option<Command> {
    let exe = launcher.to_str()?;
    if exe.contains(['"', '\0']) {
        return None;
    }
    Some(Command::text(&if command_key(key)? {
        format!("\"{exe}\"")
    } else {
        format!("\"{exe}\" -- \"%1\"")
    }))
}

/// Only recognized browser registration arguments are repairable. Preserve
/// customized commands and never copy arbitrary arguments (possibly secrets).
fn original_allowed(key: &str, value: &Command, install: &Path) -> bool {
    let Some(menu) = command_key(key) else {
        return false;
    };
    let Some(text) = value.decode() else {
        return false;
    };
    let Some(exe) = super::command_exe(&text) else {
        return false;
    };
    let path = Path::new(exe);
    if !super::path_is_under(install, path) || fs_safety::ensure_file(path).is_err() {
        return false;
    }
    let trimmed = text.trim_start();
    let end = exe.len() + if trimmed.starts_with('"') { 2 } else { 0 };
    let Some(tail) = trimmed.get(end..) else {
        return false;
    };
    if !tail.is_empty() && !tail.starts_with(char::is_whitespace) {
        return false;
    }
    let args: Vec<_> = tail.split_whitespace().collect();
    if menu {
        return args.is_empty();
    }
    // Known Chromium and Gecko registration forms, with one URL placeholder.
    let mut placeholders = 0;
    for arg in args {
        match arg.to_ascii_lowercase().as_str() {
            "%1" | "\"%1\"" | "%l" | "\"%l\"" => placeholders += 1,
            "--" | "--single-argument" | "-osint" | "-url" | "-requestpending" => {}
            _ => return false,
        }
    }
    placeholders == 1
}

impl Session {
    pub fn open(launcher: &Path, install: Option<&Path>) -> io::Result<Self> {
        if !absolute(launcher) || launcher.to_str().is_none() {
            return Err(invalid());
        }
        fs_safety::ensure_file(launcher)?;
        let base = launcher.parent().ok_or_else(invalid)?;
        let directory = base.join("Nomad");
        fs_safety::create_dir_all(&directory)?;
        let lock_path = directory.join("registry-repair.lock");
        fs_safety::ensure_file(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
            options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        }
        let lock = options.open(lock_path)?;
        lock.try_lock().map_err(io::Error::from)?;
        let path = directory.join("nomad.registry-repairs.json");
        fs_safety::ensure_file(&path)?;
        let mut state = match File::open(&path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes)?;
                if bytes.len() > MAX_BYTES {
                    return Err(invalid());
                }
                serde_json::from_slice::<Journal>(&bytes).map_err(|_| invalid())?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Journal {
                version: 1,
                launcher: launcher.to_owned(),
                install: None,
                enabled: true,
                entries: Vec::new(),
            },
            Err(e) => return Err(e),
        };
        if state.version != 1 || state.entries.len() > MAX_ENTRIES {
            return Err(invalid());
        }
        if !same_path(&state.launcher, launcher) {
            if !state.entries.is_empty() {
                return Err(invalid());
            }
            launcher.clone_into(&mut state.launcher);
            state.install = None;
        }
        if let Some(root) = install {
            if state
                .install
                .as_ref()
                .is_some_and(|previous| !same_path(previous, root))
                && !state.entries.is_empty()
            {
                return Err(invalid());
            }
            state.install = Some(root.to_owned());
        }
        if let Some(root) = &state.install {
            if !absolute(root)
                || root.parent().is_none_or(|p| !same_path(p, base))
                || !root
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(crate::config::valid_install_dir_name)
            {
                return Err(invalid());
            }
            fs_safety::ensure_directory(root)?;
        }
        let mut keys = std::collections::HashSet::new();
        for entry in &state.entries {
            if !keys.insert(entry.key.to_ascii_lowercase())
                || replacement(&entry.key, launcher).as_ref() != Some(&entry.replacement)
                || !state
                    .install
                    .as_ref()
                    .is_some_and(|root| original_allowed(&entry.key, &entry.original, root))
            {
                return Err(invalid());
            }
        }
        Ok(Self {
            path,
            state,
            _lock: lock,
        })
    }

    fn save(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.state).map_err(|_| invalid())?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        fs_safety::atomic_write(&self.path, &bytes)
    }

    pub fn enable(&mut self) -> io::Result<()> {
        self.state.enabled = true;
        self.save()
    }

    pub fn repair(&mut self, store: &mut impl CommandStore, key: &str) -> io::Result<bool> {
        if !self.state.enabled {
            return Ok(false);
        }
        let Some(root) = &self.state.install else {
            return Err(invalid());
        };
        let Some(desired) = replacement(key, &self.state.launcher) else {
            return Ok(false);
        };
        let Some(current) = store.read(key)? else {
            return Ok(false);
        };
        if current == desired || !original_allowed(key, &current, root) {
            return Ok(false);
        }
        let entry = Entry {
            key: key.to_owned(),
            original: current.clone(),
            replacement: desired.clone(),
        };
        if let Some(existing) = self
            .state
            .entries
            .iter_mut()
            .find(|e| e.key.eq_ignore_ascii_case(key))
        {
            *existing = entry;
        } else {
            if self.state.entries.len() >= MAX_ENTRIES {
                return Err(invalid());
            }
            self.state.entries.push(entry);
        }
        // Persist the prospective write first. If compare/write fails, undo is
        // still safe because it only restores an exact recorded replacement.
        self.save()?;
        store.replace(key, &current, &desired)
    }

    pub fn undo(&mut self, store: &mut impl CommandStore) -> io::Result<()> {
        // A live watcher must see this before it can observe restored commands.
        self.state.enabled = false;
        self.save()?;
        for entry in &self.state.entries {
            store.replace(&entry.key, &entry.replacement, &entry.original)?;
        }
        self.state.entries.clear();
        // Retain the disabled journal even when empty, until explicit register.
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const KEY: &str = r"Software\Classes\TestBrowserHTML\shell\open\command";
    const MENU: &str = r"Software\Clients\StartMenuInternet\TestBrowser\shell\open\command";

    #[derive(Default)]
    struct MemoryStore {
        values: BTreeMap<String, Command>,
        writes: usize,
        fail: bool,
        race: bool,
        journal: Option<PathBuf>,
    }

    impl CommandStore for MemoryStore {
        fn read(&self, key: &str) -> io::Result<Option<Command>> {
            Ok(self.values.get(key).cloned())
        }
        fn replace(
            &mut self,
            key: &str,
            expected: &Command,
            desired: &Command,
        ) -> io::Result<bool> {
            if let Some(path) = &self.journal {
                let disk: Journal = serde_json::from_slice(&std::fs::read(path)?).unwrap();
                assert!(
                    disk.entries.iter().any(|e| e.key == key
                        && e.original == *expected
                        && e.replacement == *desired),
                    "repair must be durable before mutation"
                );
            }
            if self.fail {
                return Err(io::Error::other("injected registry failure"));
            }
            if self.race {
                self.values
                    .insert(key.to_owned(), Command::text("user changed this"));
                self.race = false;
            }
            if self.values.get(key) != Some(expected) {
                return Ok(false);
            }
            self.values.insert(key.to_owned(), desired.clone());
            self.writes += 1;
            Ok(true)
        }
    }

    struct Fixture {
        directory: tempfile::TempDir,
        launcher: PathBuf,
        install: PathBuf,
        original: Command,
        store: MemoryStore,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let launcher = directory.path().join("Nomad-Test.exe");
            let install = directory.path().join("Browser");
            let original = Command::text(&format!(
                "\"{}\" --single-argument %1",
                install.join("chrome.exe").display()
            ));
            let mut store = MemoryStore::default();
            store.values.insert(KEY.to_owned(), original.clone());
            Self {
                directory,
                launcher,
                install,
                original,
                store,
            }
        }
        fn session(&self) -> Session {
            Session::open(&self.launcher, Some(&self.install)).unwrap()
        }
    }

    #[test]
    fn journal_precedes_writes_and_undo_preserves_raw_type_and_bytes() {
        for kind in [1, 2] {
            let mut f = Fixture::new();
            f.original.kind = kind;
            f.store.values.insert(KEY.to_owned(), f.original.clone());
            let mut session = f.session();
            f.store.journal = Some(session.path.clone());
            assert!(session.repair(&mut f.store, KEY).unwrap());
            assert!(!session.repair(&mut f.store, KEY).unwrap());
            assert_eq!(session.state.entries[0].original, f.original);
            f.store.journal = None;
            drop(session);
            let mut session = f.session();
            session.undo(&mut f.store).unwrap();
            assert_eq!(f.store.values[KEY], f.original);
            assert!(session.state.entries.is_empty());
            drop(session);
            let mut session = f.session();
            assert!(
                !session.repair(&mut f.store, KEY).unwrap(),
                "undo must survive a new watcher session"
            );
            session.enable().unwrap();
            assert!(session.repair(&mut f.store, KEY).unwrap());
        }
    }

    #[test]
    fn failed_journal_write_prevents_registry_mutation() {
        let mut f = Fixture::new();
        let mut session = f.session();
        // A directory at the destination deterministically rejects atomic_write.
        std::fs::create_dir(&session.path).unwrap();
        assert!(session.repair(&mut f.store, KEY).is_err());
        assert_eq!(f.store.writes, 0);
        assert_eq!(f.store.values[KEY], f.original);
    }

    #[test]
    fn failed_registry_write_leaves_a_safe_retry_record() {
        let mut f = Fixture::new();
        let mut session = f.session();
        f.store.fail = true;
        assert!(session.repair(&mut f.store, KEY).is_err());
        drop(session);
        let mut session = f.session();
        assert_eq!(session.state.entries.len(), 1);
        f.store.fail = false;
        session.undo(&mut f.store).unwrap();
        assert_eq!(f.store.values[KEY], f.original);
        assert_eq!(f.store.writes, 0);
    }

    #[test]
    fn failed_undo_retains_disabled_state_and_records_for_retry() {
        let mut f = Fixture::new();
        let mut session = f.session();
        session.repair(&mut f.store, KEY).unwrap();
        f.store.fail = true;
        assert!(session.undo(&mut f.store).is_err());
        drop(session);
        let mut session = f.session();
        assert!(!session.state.enabled);
        assert_eq!(session.state.entries.len(), 1);
        f.store.fail = false;
        session.undo(&mut f.store).unwrap();
        assert_eq!(f.store.values[KEY], f.original);
    }

    #[test]
    fn user_edits_and_deleted_values_survive_undo() {
        for deleted in [false, true] {
            let mut f = Fixture::new();
            let mut session = f.session();
            session.repair(&mut f.store, KEY).unwrap();
            if deleted {
                f.store.values.remove(KEY);
            } else {
                f.store
                    .values
                    .insert(KEY.to_owned(), Command::text("custom command"));
            }
            let before = f.store.values.clone();
            session.undo(&mut f.store).unwrap();
            assert_eq!(f.store.values, before);
            assert_eq!(f.store.writes, 1);
        }
    }

    #[test]
    fn compare_before_write_preserves_a_concurrent_edit() {
        let mut f = Fixture::new();
        let mut session = f.session();
        f.store.race = true;
        assert!(!session.repair(&mut f.store, KEY).unwrap());
        session.undo(&mut f.store).unwrap();
        assert_eq!(f.store.values[KEY], Command::text("user changed this"));
        assert_eq!(f.store.writes, 0);
    }

    #[test]
    fn browser_reregistration_updates_the_snapshot() {
        let mut f = Fixture::new();
        let mut session = f.session();
        session.repair(&mut f.store, KEY).unwrap();
        let changed = Command::text(&format!(
            "\"{}\" -osint -url \"%1\"",
            f.install.join("firefox.exe").display()
        ));
        f.store.values.insert(KEY.to_owned(), changed.clone());
        session.repair(&mut f.store, KEY).unwrap();
        session.undo(&mut f.store).unwrap();
        assert_eq!(f.store.values[KEY], changed);
    }

    #[test]
    fn custom_arguments_foreign_paths_and_unsafe_keys_are_untouched() {
        let mut f = Fixture::new();
        let mut session = f.session();
        for command in [
            format!(
                "\"{}\" --token secret %1",
                f.install.join("chrome.exe").display()
            ),
            format!("\"{}\" %1", f.install.join("../foreign.exe").display()),
            format!("\"{}\" %1", f.launcher.display()),
            format!("\"{} -- %1", f.install.join("chrome.exe").display()),
        ] {
            f.store
                .values
                .insert(KEY.to_owned(), Command::text(&command));
            assert!(!session.repair(&mut f.store, KEY).unwrap());
        }
        for key in [
            r"Software\Classes\NomadPortable.test\shell\open\command",
            r"Software\Classes\..\shell\open\command",
            r"Software\UserChoice",
        ] {
            f.store.values.insert(key.to_owned(), f.original.clone());
            assert!(!session.repair(&mut f.store, key).unwrap());
        }
        assert!(
            !session.path.exists(),
            "skipped commands must not be persisted"
        );
        assert_eq!(f.store.writes, 0);
    }

    #[test]
    fn start_menu_command_round_trip() {
        let mut f = Fixture::new();
        let mut session = f.session();
        let original = Command::text(&format!("\"{}\"", f.install.join("chrome.exe").display()));
        f.store.values.insert(MENU.to_owned(), original.clone());
        assert!(session.repair(&mut f.store, MENU).unwrap());
        assert_eq!(
            f.store.values[MENU],
            Command::text(&format!("\"{}\"", f.launcher.display()))
        );
        session.undo(&mut f.store).unwrap();
        assert_eq!(f.store.values[MENU], original);
    }

    #[test]
    fn malformed_and_oversized_journals_and_other_launchers_fail_closed() {
        let mut f = Fixture::new();
        let mut session = f.session();
        session.repair(&mut f.store, KEY).unwrap();
        let path = session.path.clone();
        session.save().unwrap();
        let valid = std::fs::read(&path).unwrap();
        drop(session);
        for invalid in [b"{broken".to_vec(), vec![b' '; MAX_BYTES + 1]] {
            std::fs::write(&path, invalid).unwrap();
            assert!(Session::open(&f.launcher, Some(&f.install)).is_err());
        }
        std::fs::write(&path, valid).unwrap();
        assert!(Session::open(&f.launcher.with_file_name("Other.exe"), Some(&f.install)).is_err());
        assert!(Session::open(&f.launcher, Some(&f.install.with_file_name("Other"))).is_err());
    }

    #[test]
    fn tampered_entries_are_rejected_before_undo() {
        let mut f = Fixture::new();
        let mut session = f.session();
        session.repair(&mut f.store, KEY).unwrap();
        session.state.entries[0].original = Command::text(r#""C:\Other\browser.exe" %1"#);
        session.save().unwrap();
        drop(session);
        assert!(Session::open(&f.launcher, Some(&f.install)).is_err());
        assert_eq!(f.store.writes, 1);
    }

    #[test]
    fn lock_serializes_repairs_and_undo() {
        let f = Fixture::new();
        let session = f.session();
        assert!(Session::open(&f.launcher, Some(&f.install)).is_err());
        drop(session);
        assert!(Session::open(&f.launcher, Some(&f.install)).is_ok());
    }

    #[test]
    fn cleared_journal_can_rebind_after_a_move_but_stays_disabled() {
        let mut f = Fixture::new();
        let mut session = f.session();
        session.repair(&mut f.store, KEY).unwrap();
        session.undo(&mut f.store).unwrap();
        drop(session);
        let moved_launcher = f.launcher.with_file_name("Renamed.exe");
        let mut session = Session::open(&moved_launcher, Some(&f.install)).unwrap();
        assert!(!session.repair(&mut f.store, KEY).unwrap());
        session.enable().unwrap();
        assert!(session.repair(&mut f.store, KEY).unwrap());
    }

    #[test]
    fn linked_journal_directory_and_browser_executables_are_refused() {
        let mut f = Fixture::new();
        let foreign = f.directory.path().join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        crate::tests::owned_directory_link(&f.directory, &f.install, &foreign);
        assert!(Session::open(&f.launcher, Some(&f.install)).is_err());
        assert_eq!(f.store.writes, 0);
        let other = Fixture::new();
        let state = other.launcher.parent().unwrap().join("Nomad");
        let other_foreign = other.directory.path().join("foreign");
        std::fs::create_dir(&other_foreign).unwrap();
        crate::tests::owned_directory_link(&other.directory, &state, &other_foreign);
        assert!(Session::open(&other.launcher, Some(&other.install)).is_err());
        assert_eq!(std::fs::read_dir(&foreign).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&other_foreign).unwrap().count(), 0);
        // Keep the fake registry untouched even when the executable traverses a link.
        let nested = f.install.join("chrome.exe");
        f.store.values.insert(
            KEY.to_owned(),
            Command::text(&format!("\"{}\" %1", nested.display())),
        );
        assert!(!original_allowed(KEY, &f.store.values[KEY], &f.install));
    }

    #[test]
    fn failed_opt_out_write_cannot_restore_commands() {
        let mut f = Fixture::new();
        let mut session = f.session();
        session.repair(&mut f.store, KEY).unwrap();
        let before = f.store.values.clone();
        // Fault injection in an owned temp directory: deny journal replacement.
        std::fs::remove_file(&session.path).unwrap();
        std::fs::create_dir(&session.path).unwrap();
        assert!(session.undo(&mut f.store).is_err());
        assert_eq!(f.store.values, before);
        assert_eq!(f.store.writes, 1);
    }

    #[test]
    fn registry_keys_with_nul_cannot_truncate_the_native_target() {
        let mut f = Fixture::new();
        let mut session = f.session();
        let key = KEY.replace("TestBrowserHTML", "TestBrowserHTML\0other");
        f.store.values.insert(key.clone(), f.original.clone());
        assert!(!session.repair(&mut f.store, &key).unwrap());
        assert_eq!(f.store.writes, 0);
        assert!(!session.path.exists());
    }

    #[test]
    fn malformed_raw_commands_are_not_decoded() {
        for command in [
            Command {
                kind: 3,
                bytes: vec![0, 0],
            },
            Command {
                kind: 1,
                bytes: vec![0],
            },
            Command {
                kind: 1,
                bytes: vec![0, 0, 0, 0],
            },
            Command {
                kind: 1,
                bytes: vec![0, 216, 0, 0],
            },
        ] {
            assert!(command.decode().is_none());
        }
    }
}
