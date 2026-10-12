//! Explicit registration uses a durable cleanup plan before creating HKCU entries.
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{app_key_path, classes_path, RegState, RegistryError, Result, REGISTERED_APPS_KEY};
use crate::fs_safety;

const MAX_STATE_BYTES: u64 = 64 * 1024;

fn invalid_state() -> RegistryError {
    RegistryError::Sidecar(
        "invalid or mismatched registration record; preserve it for review".into(),
    )
}

fn legacy_state(browser_id: &str) -> Result<RegState> {
    if browser_id.is_empty()
        || browser_id.len() > 128
        || !browser_id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err(invalid_state());
    }
    Ok(RegState {
        version: 1,
        browser_id: browser_id.to_owned(),
        launcher: None,
        keys: vec![classes_path(browser_id), app_key_path(browser_id)],
        values: vec![(
            REGISTERED_APPS_KEY.to_owned(),
            format!("NomadPortable.{browser_id}"),
        )],
    })
}

// Refuse redirects before canonicalization can hide them. Tests use an inert,
// absent executable under an existing temporary parent.
fn canonical_launcher(exe: &Path) -> Result<PathBuf> {
    if !exe.is_absolute() {
        return Err(invalid_state());
    }
    fs_safety::ensure_file(exe)?;
    let base = exe.parent().ok_or_else(invalid_state)?.canonicalize()?;
    let path = base.join(exe.file_name().ok_or_else(invalid_state)?);
    Ok(PathBuf::from(
        path.to_str()
            .ok_or_else(invalid_state)?
            .to_ascii_lowercase(),
    ))
}

fn scoped_state(browser_id: &str, launcher: &Path) -> Result<RegState> {
    legacy_state(browser_id)?;
    if !launcher.is_absolute()
        || launcher.file_name().is_none()
        || launcher
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(invalid_state());
    }
    let text = launcher
        .to_str()
        .filter(|s| !s.contains(['"', '\0']))
        .ok_or_else(invalid_state)?;
    let identity = hex::encode(Sha256::digest(
        format!("{browser_id}\0{}", text.to_ascii_lowercase()).as_bytes(),
    ));
    // 38 characters, within Windows' documented 39-character ProgID limit.
    let pid = format!("NomadPortable.{}", &identity[..24]);
    Ok(RegState {
        version: 2,
        browser_id: browser_id.to_owned(),
        launcher: Some(launcher.to_owned()),
        keys: vec![
            format!("Software\\Classes\\{pid}"),
            format!("Software\\NomadPortable\\{identity}"),
        ],
        values: vec![(
            REGISTERED_APPS_KEY.to_owned(),
            format!("NomadPortable.{identity}"),
        )],
    })
}

pub(super) fn owned_state(sidecar: &Path, launcher: &Path) -> Result<Option<RegState>> {
    let Some(state) = read_state(sidecar)? else {
        return Ok(None);
    };
    if state.version == 1 {
        return Err(RegistryError::Sidecar("legacy shared registration cannot be safely removed; run --register-default to preserve it and create a separate entry".into()));
    }
    if state != scoped_state(&state.browser_id, &canonical_launcher(launcher)?)? {
        return Err(RegistryError::Sidecar("registration belongs to another launcher location; register this copy before unregistering it".into()));
    }
    Ok(Some(state))
}

fn archive_record(sidecar: &Path, previous: &RegState) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(previous).map_err(|_| invalid_state())?;
    let directory = sidecar
        .parent()
        .ok_or_else(invalid_state)?
        .join("registration-history");
    fs_safety::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.json", hex::encode(Sha256::digest(&bytes))));
    fs_safety::ensure_file(&path)?;
    if path.try_exists()? {
        if read_state(&path)?.as_ref() != Some(previous) {
            return Err(invalid_state());
        }
    } else {
        fs_safety::write_new(&path, &bytes)?;
    }
    Ok(())
}

pub(super) fn read_state(path: &Path) -> Result<Option<RegState>> {
    fs_safety::ensure_file(path)?;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(invalid_state());
    }
    let state: RegState = serde_json::from_slice(&bytes).map_err(|_| invalid_state())?;
    let expected = match (state.version, state.launcher.as_deref()) {
        (1, None) => legacy_state(&state.browser_id)?,
        (2, Some(launcher)) => scoped_state(&state.browser_id, launcher)?,
        _ => return Err(invalid_state()),
    };
    if state != expected {
        return Err(invalid_state());
    }
    Ok(Some(state))
}

pub(super) struct Value {
    pub key: String,
    pub name: String,
    pub text: String,
}

pub(super) struct Plan {
    state: RegState,
    values: Vec<Value>,
}

impl Plan {
    pub fn new(browser_id: &str, display_name: &str, exe: &Path) -> Result<Self> {
        let state = scoped_state(browser_id, &canonical_launcher(exe)?)?;
        let exe = exe
            .to_str()
            .filter(|s| !s.contains(['"', '\0']))
            .ok_or_else(invalid_state)?;
        let cls = state.keys[0].clone();
        let caps = format!("{}\\Capabilities", state.keys[1]);
        let location = Path::new(exe).parent().ok_or_else(invalid_state)?;
        let label = format!("{display_name} (Nomad Launcher: {})", location.display());
        let description = format!("Privacy-hardened {display_name} \u{2014} Nomad Launcher");
        let icon = format!("{exe},0");
        let pid = cls
            .rsplit('\\')
            .next()
            .ok_or_else(invalid_state)?
            .to_owned();
        let mut values = Vec::new();
        let mut add = |key: String, name: &str, text: String| {
            values.push(Value {
                key,
                name: name.to_owned(),
                text,
            });
        };
        add(cls.clone(), "", label.clone());
        add(
            format!("{cls}\\Application"),
            "ApplicationName",
            label.clone(),
        );
        add(
            format!("{cls}\\Application"),
            "ApplicationIcon",
            icon.clone(),
        );
        add(
            format!("{cls}\\Application"),
            "ApplicationDescription",
            description.clone(),
        );
        add(format!("{cls}\\DefaultIcon"), "", icon);
        add(
            format!("{cls}\\shell\\open\\command"),
            "",
            format!("\"{exe}\" -- \"%1\""),
        );
        add(caps.clone(), "ApplicationName", label);
        add(caps.clone(), "ApplicationDescription", description);
        for ext in [".htm", ".html", ".shtml", ".xhtml"] {
            add(format!("{caps}\\FileAssociations"), ext, pid.clone());
        }
        for protocol in ["http", "https", "ftp"] {
            add(format!("{caps}\\URLAssociations"), protocol, pid.clone());
        }
        // Advertise the candidate only after its command/capabilities are written.
        add(REGISTERED_APPS_KEY.to_owned(), &state.values[0].1, caps);
        Ok(Self { state, values })
    }

    fn persist(&self, sidecar: &Path) -> Result<()> {
        if let Some(previous) = read_state(sidecar)? {
            if previous.browser_id != self.state.browser_id {
                return Err(invalid_state());
            }
            if previous != self.state {
                archive_record(sidecar, &previous)?;
            }
        }
        let bytes = serde_json::to_vec_pretty(&self.state).map_err(|_| invalid_state())?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(invalid_state());
        }
        fs_safety::atomic_write(sidecar, &bytes)?;
        Ok(())
    }

    pub fn apply(
        &self,
        sidecar: &Path,
        mut write: impl FnMut(&Value) -> io::Result<()>,
    ) -> Result<()> {
        // A prepared record describes every possible partial write. Keep it on
        // failure so registration can be retried or explicitly removed.
        self.persist(sidecar)?;
        for value in &self.values {
            write(value).map_err(RegistryError::PartialRegister)?;
        }
        Ok(())
    }
}

pub(super) fn remove_owned(
    sidecar: &Path,
    launcher: &Path,
    mut remove_key: impl FnMut(&str) -> io::Result<()>,
    mut remove_value: impl FnMut(&str, &str) -> io::Result<()>,
) -> Result<()> {
    let state = owned_state(sidecar, launcher)?.ok_or(RegistryError::NotRegistered)?;
    let mut failed = 0;
    for key in &state.keys {
        if !super::is_nomad_owned_key(key) {
            return Err(invalid_state());
        }
        if let Err(error) = remove_key(key) {
            if error.kind() != io::ErrorKind::NotFound {
                failed += 1;
            }
        }
    }
    for (key, name) in &state.values {
        if !super::is_nomad_owned_value(key, name) {
            return Err(invalid_state());
        }
        if let Err(error) = remove_value(key, name) {
            if error.kind() != io::ErrorKind::NotFound {
                failed += 1;
            }
        }
    }
    finish_unregistration(sidecar, failed)
}

/// A failed removal must keep the recovery record. A failed record deletion is
/// reported too, rather than claiming a completed unregister with stale state.
pub(super) fn finish_unregistration(sidecar: &Path, failed: usize) -> Result<()> {
    if failed > 0 {
        return Err(RegistryError::PartialUnregister { failed });
    }
    fs_safety::ensure_file(sidecar)?;
    std::fs::remove_file(sidecar)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separate_portable_copies_have_disjoint_registration_paths() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let a = Plan::new("firefox", "Firefox", &first.path().join("Nomad.exe")).unwrap();
        let b = Plan::new("firefox", "Firefox", &second.path().join("Nomad.exe")).unwrap();
        assert!(a.state.keys.iter().all(|key| !b.state.keys.contains(key)));
        assert!(a
            .state
            .values
            .iter()
            .all(|value| !b.state.values.contains(value)));
    }

    #[test]
    fn plan_is_durable_before_the_first_registry_write() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("Nomad/nomad.reg-state.json");
        let plan = Plan::new("firefox", "Firefox", &directory.path().join("Nomad.exe")).unwrap();
        let mut writes = 0;
        plan.apply(&sidecar, |_| {
            assert_eq!(
                read_state(&sidecar).unwrap(),
                Some(
                    scoped_state(
                        "firefox",
                        &canonical_launcher(&directory.path().join("Nomad.exe")).unwrap()
                    )
                    .unwrap()
                )
            );
            writes += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(writes, 16);
    }

    #[test]
    fn every_registry_write_failure_remains_tracked_and_retryable() {
        use std::collections::BTreeMap;
        for fail_at in 0..16 {
            for fail_after_write in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let sidecar = directory.path().join("state.json");
                let exe = directory.path().join("Nomad.exe");
                let plan = Plan::new("firefox", "Firefox", &exe).unwrap();
                let mut values = BTreeMap::new();
                let mut attempt = 0;
                let result = plan.apply(&sidecar, |value| {
                    assert!(read_state(&sidecar).unwrap().is_some());
                    let failing = attempt == fail_at;
                    attempt += 1;
                    if !failing || fail_after_write {
                        values.insert((value.key.clone(), value.name.clone()), value.text.clone());
                    }
                    if failing {
                        Err(io::Error::other("injected write failure"))
                    } else {
                        Ok(())
                    }
                });
                assert!(matches!(result, Err(RegistryError::PartialRegister(_))));
                assert_eq!(attempt, fail_at + 1, "stop at the first failure");
                let state = read_state(&sidecar).unwrap().unwrap();
                for (key, name) in values.keys() {
                    assert!(
                        state
                            .keys
                            .iter()
                            .any(|root| key == root || key.starts_with(&format!("{root}\\")))
                            || state.values.contains(&(key.clone(), name.clone())),
                        "partial write must be covered by cleanup record"
                    );
                }
                plan.apply(&sidecar, |value| {
                    values.insert((value.key.clone(), value.name.clone()), value.text.clone());
                    Ok(())
                })
                .unwrap();
                assert_eq!(values.len(), 16);
                assert_eq!(
                    values[&(
                        format!(r"{}\shell\open\command", plan.state.keys[0]),
                        String::new()
                    )],
                    format!("\"{}\" -- \"%1\"", exe.display())
                );
                assert_eq!(
                    values[&(
                        REGISTERED_APPS_KEY.to_owned(),
                        plan.state.values[0].1.clone()
                    )],
                    format!(r"{}\Capabilities", plan.state.keys[1])
                );
            }
        }
    }

    #[test]
    fn persistence_failure_prevents_all_registry_writes() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("state.json");
        let plan = Plan::new("firefox", "Firefox", &directory.path().join("Nomad.exe")).unwrap();
        std::fs::create_dir(&sidecar).unwrap();
        let mut writes = 0;
        assert!(plan
            .apply(&sidecar, |_| {
                writes += 1;
                Ok(())
            })
            .is_err());
        assert_eq!(writes, 0);
    }

    #[test]
    fn failed_refresh_preserves_the_previous_record_and_makes_no_writes() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("state.json");
        let plan = Plan::new("firefox", "Firefox", &directory.path().join("Nomad.exe")).unwrap();
        plan.persist(&sidecar).unwrap();
        let before = std::fs::read(&sidecar).unwrap();
        let original_permissions = std::fs::metadata(&sidecar).unwrap().permissions();
        let mut read_only = original_permissions.clone();
        read_only.set_readonly(true);
        std::fs::set_permissions(&sidecar, read_only).unwrap();
        let mut writes = 0;
        let result = plan.apply(&sidecar, |_| {
            writes += 1;
            Ok(())
        });
        std::fs::set_permissions(&sidecar, original_permissions).unwrap();
        assert!(result.is_err());
        assert_eq!(writes, 0);
        assert_eq!(std::fs::read(&sidecar).unwrap(), before);
    }

    #[test]
    fn invalid_or_other_browser_records_are_preserved_without_registry_writes() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("state.json");
        let plan = Plan::new("firefox", "Firefox", &directory.path().join("Nomad.exe")).unwrap();
        let canonical = serde_json::to_string(&legacy_state("firefox").unwrap()).unwrap();
        let foreign = serde_json::to_vec(&legacy_state("helium").unwrap()).unwrap();
        let cases = [
            b"{broken".to_vec(),
            vec![b' '; usize::try_from(MAX_STATE_BYTES).unwrap() + 1],
            foreign,
            canonical
                .replace("\"version\":1", "\"version\":2")
                .into_bytes(),
            canonical.replacen('{', "{\"unknown\":1,", 1).into_bytes(),
            canonical.replace("Software", "Unowned").into_bytes(),
        ];
        for bytes in cases {
            std::fs::write(&sidecar, &bytes).unwrap();
            let mut writes = 0;
            assert!(plan
                .apply(&sidecar, |_| {
                    writes += 1;
                    Ok(())
                })
                .is_err());
            assert_eq!(writes, 0);
            assert_eq!(std::fs::read(&sidecar).unwrap(), bytes);
        }
    }

    #[test]
    fn invalid_browser_identifiers_cannot_expand_the_cleanup_plan() {
        for id in [
            "",
            "../other",
            "firefox\\Other",
            "firefox\0other",
            "firefox.HTML",
            "UPPER",
        ] {
            assert!(legacy_state(id).is_err());
        }
    }

    #[test]
    fn registration_and_removal_reject_redirected_records() {
        let directory = tempfile::tempdir().unwrap();
        let foreign = directory.path().join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        let linked = directory.path().join("Nomad");
        crate::tests::owned_directory_link(&directory, &linked, &foreign);
        let sidecar = linked.join("state.json");
        let plan = Plan::new("firefox", "Firefox", &directory.path().join("Nomad.exe")).unwrap();
        let mut writes = 0;
        assert!(plan
            .apply(&sidecar, |_| {
                writes += 1;
                Ok(())
            })
            .is_err());
        assert!(read_state(&sidecar).is_err());
        assert_eq!(writes, 0);
        assert_eq!(std::fs::read_dir(&foreign).unwrap().count(), 0);
    }

    #[test]
    fn failed_unregistration_keeps_the_record_and_reports_record_removal_errors() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("state.json");
        let plan = Plan::new("firefox", "Firefox", &directory.path().join("Nomad.exe")).unwrap();
        plan.persist(&sidecar).unwrap();
        let before = std::fs::read(&sidecar).unwrap();
        assert!(matches!(
            finish_unregistration(&sidecar, 1),
            Err(RegistryError::PartialUnregister { failed: 1 })
        ));
        assert_eq!(std::fs::read(&sidecar).unwrap(), before);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // A handle without delete sharing deterministically blocks removal.
            let handle = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
                .open(&sidecar)
                .unwrap();
            let result = finish_unregistration(&sidecar, 0);
            drop(handle);
            assert!(
                result.is_err(),
                "failed sidecar deletion must not report success"
            );
            assert_eq!(std::fs::read(&sidecar).unwrap(), before);
        }
        finish_unregistration(&sidecar, 0).unwrap();
        assert!(!sidecar.exists());
    }

    #[test]
    fn unregistering_one_copy_preserves_the_other_copy() {
        use std::{cell::RefCell, collections::BTreeMap};
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let a_exe = first.path().join("Nomad.exe");
        let b_exe = second.path().join("Nomad.exe");
        let a_path = first.path().join("state.json");
        let b_path = second.path().join("state.json");
        let a = Plan::new("firefox", "Firefox", &a_exe).unwrap();
        let b = Plan::new("firefox", "Firefox", &b_exe).unwrap();
        let values = RefCell::new(BTreeMap::new());
        for (plan, path) in [(&a, &a_path), (&b, &b_path)] {
            plan.apply(path, |v| {
                values
                    .borrow_mut()
                    .insert((v.key.clone(), v.name.clone()), v.text.clone());
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(values.borrow().len(), 32);
        remove_owned(
            &a_path,
            &a_exe,
            |root| {
                values
                    .borrow_mut()
                    .retain(|(key, _), _| key != root && !key.starts_with(&format!("{root}\\")));
                Ok(())
            },
            |key, name| {
                values
                    .borrow_mut()
                    .remove(&(key.to_owned(), name.to_owned()));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(values.borrow().len(), 16);
        for value in &b.values {
            assert_eq!(
                values
                    .borrow()
                    .get(&(value.key.clone(), value.name.clone())),
                Some(&value.text)
            );
        }
        assert!(!a_path.exists());
        assert!(b_path.exists());
    }

    #[test]
    fn copied_record_cannot_remove_original_registration() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let original = Plan::new("firefox", "Firefox", &first.path().join("Nomad.exe")).unwrap();
        let copied_path = second.path().join("state.json");
        original.persist(&copied_path).unwrap();
        let before = std::fs::read(&copied_path).unwrap();
        let deletes = std::cell::Cell::new(0);
        assert!(remove_owned(
            &copied_path,
            &second.path().join("Nomad.exe"),
            |_| {
                deletes.set(deletes.get() + 1);
                Ok(())
            },
            |_, _| {
                deletes.set(deletes.get() + 1);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(deletes.get(), 0);
        assert_eq!(std::fs::read(&copied_path).unwrap(), before);
        let copy = Plan::new("firefox", "Firefox", &second.path().join("Nomad.exe")).unwrap();
        copy.apply(&copied_path, |_| Ok(())).unwrap();
        assert_eq!(read_state(&copied_path).unwrap().unwrap(), copy.state);
        let archived = std::fs::read_dir(second.path().join("registration-history"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(read_state(&archived).unwrap().unwrap(), original.state);
    }

    #[test]
    fn legacy_migration_archives_the_shared_record_without_writing_shared_keys() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("state.json");
        let exe = directory.path().join("Nomad.exe");
        let legacy = legacy_state("firefox").unwrap();
        std::fs::write(&sidecar, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let deletes = std::cell::Cell::new(0);
        assert!(remove_owned(
            &sidecar,
            &exe,
            |_| {
                deletes.set(deletes.get() + 1);
                Ok(())
            },
            |_, _| {
                deletes.set(deletes.get() + 1);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(deletes.get(), 0);
        let plan = Plan::new("firefox", "Firefox", &exe).unwrap();
        plan.apply(&sidecar, |value| {
            assert!(!legacy
                .keys
                .iter()
                .any(|key| value.key == *key || value.key.starts_with(&format!("{key}\\"))));
            assert!(!legacy
                .values
                .contains(&(value.key.clone(), value.name.clone())));
            let archived = std::fs::read_dir(directory.path().join("registration-history"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            assert_eq!(read_state(&archived).unwrap().unwrap(), legacy);
            Ok(())
        })
        .unwrap();
        assert_eq!(read_state(&sidecar).unwrap().unwrap().version, 2);
    }

    #[test]
    fn blocked_history_archive_prevents_migration_and_registry_writes() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("state.json");
        let legacy = serde_json::to_vec(&legacy_state("firefox").unwrap()).unwrap();
        std::fs::write(&sidecar, &legacy).unwrap();
        std::fs::write(
            directory.path().join("registration-history"),
            "block directory creation",
        )
        .unwrap();
        let plan = Plan::new("firefox", "Firefox", &directory.path().join("Nomad.exe")).unwrap();
        let mut writes = 0;
        assert!(plan
            .apply(&sidecar, |_| {
                writes += 1;
                Ok(())
            })
            .is_err());
        assert_eq!(writes, 0);
        assert_eq!(std::fs::read(&sidecar).unwrap(), legacy);
    }

    #[test]
    fn cleanup_failure_retains_owned_state_for_retry() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("state.json");
        let exe = directory.path().join("Nomad.exe");
        let plan = Plan::new("firefox", "Firefox", &exe).unwrap();
        plan.persist(&sidecar).unwrap();
        assert!(matches!(
            remove_owned(
                &sidecar,
                &exe,
                |_| Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected")),
                |_, _| Ok(())
            ),
            Err(RegistryError::PartialUnregister { failed: 2 })
        ));
        assert!(sidecar.exists());
        remove_owned(
            &sidecar,
            &exe,
            |_| Err(io::Error::from(io::ErrorKind::NotFound)),
            |_, _| Err(io::Error::from(io::ErrorKind::NotFound)),
        )
        .unwrap();
        assert!(!sidecar.exists());
    }

    #[test]
    fn identity_is_stable_for_case_and_distinct_for_browser_and_filename() {
        let directory = tempfile::tempdir().unwrap();
        let exe = directory.path().join("Nomad.exe");
        let a = Plan::new("firefox", "Firefox", &exe).unwrap();
        let again = Plan::new("firefox", "Firefox", &exe.with_file_name("NOMAD.EXE")).unwrap();
        let renamed = Plan::new("firefox", "Firefox", &exe.with_file_name("Other.exe")).unwrap();
        let other_browser = Plan::new("helium", "Helium", &exe).unwrap();
        assert_eq!(a.state, again.state);
        assert_ne!(a.state.keys, renamed.state.keys);
        assert_ne!(a.state.keys, other_browser.state.keys);
        let pid = a.state.keys[0].rsplit('\\').next().unwrap();
        assert!(pid.len() <= 39);
        assert!(pid.chars().all(|c| c.is_ascii_alphanumeric() || c == '.'));
        assert_eq!(
            read_state(&directory.path().join("absent.json")).unwrap(),
            None
        );
    }

    #[test]
    fn interrupted_migration_reuses_the_archive_on_retry() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("state.json");
        let old = serde_json::to_vec(&legacy_state("firefox").unwrap()).unwrap();
        std::fs::write(&sidecar, &old).unwrap();
        let permissions = std::fs::metadata(&sidecar).unwrap().permissions();
        let mut read_only = permissions.clone();
        read_only.set_readonly(true);
        std::fs::set_permissions(&sidecar, read_only).unwrap();
        let plan = Plan::new("firefox", "Firefox", &directory.path().join("Nomad.exe")).unwrap();
        let mut writes = 0;
        let result = plan.apply(&sidecar, |_| {
            writes += 1;
            Ok(())
        });
        std::fs::set_permissions(&sidecar, permissions).unwrap();
        assert!(result.is_err());
        assert_eq!(writes, 0);
        assert_eq!(std::fs::read(&sidecar).unwrap(), old);
        plan.apply(&sidecar, |_| Ok(())).unwrap();
        assert_eq!(
            std::fs::read_dir(directory.path().join("registration-history"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn tampered_scoped_paths_cannot_expand_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("state.json");
        let exe = directory.path().join("Nomad.exe");
        let mut plan = Plan::new("firefox", "Firefox", &exe).unwrap();
        plan.state.keys[0] = classes_path("firefox");
        std::fs::write(&sidecar, serde_json::to_vec(&plan.state).unwrap()).unwrap();
        let deletes = std::cell::Cell::new(0);
        assert!(remove_owned(
            &sidecar,
            &exe,
            |_| {
                deletes.set(deletes.get() + 1);
                Ok(())
            },
            |_, _| {
                deletes.set(deletes.get() + 1);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(deletes.get(), 0);
        assert!(sidecar.exists());
    }
}
