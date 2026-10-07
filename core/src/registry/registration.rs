//! Explicit registration uses a durable cleanup plan before creating HKCU entries.
use std::io::{self, Read};
use std::path::Path;

use super::{
    app_key_path, classes_path, prog_id, RegState, RegistryError, Result, REGISTERED_APPS_KEY,
};
use crate::fs_safety;

const MAX_STATE_BYTES: u64 = 64 * 1024;

fn invalid_state() -> RegistryError {
    RegistryError::Sidecar(
        "invalid or mismatched registration record; preserve it for review".into(),
    )
}

fn planned_state(browser_id: &str) -> Result<RegState> {
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
        keys: vec![classes_path(browser_id), app_key_path(browser_id)],
        values: vec![(
            REGISTERED_APPS_KEY.to_owned(),
            format!("NomadPortable.{browser_id}"),
        )],
    })
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
    if state != planned_state(&state.browser_id)? {
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
        let state = planned_state(browser_id)?;
        fs_safety::ensure_file(exe)?;
        let exe = exe
            .to_str()
            .filter(|s| !s.contains(['"', '\0']))
            .ok_or_else(invalid_state)?;
        let cls = classes_path(browser_id);
        let caps = format!("{}\\Capabilities", app_key_path(browser_id));
        let label = format!("{display_name} (Nomad Launcher)");
        let description = format!("Privacy-hardened {display_name} \u{2014} Nomad Launcher");
        let icon = format!("{exe},0");
        let pid = prog_id(browser_id);
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
        add(
            REGISTERED_APPS_KEY.to_owned(),
            &format!("NomadPortable.{browser_id}"),
            caps,
        );
        Ok(Self { state, values })
    }

    fn persist(&self, sidecar: &Path) -> Result<()> {
        if read_state(sidecar)?.is_some_and(|previous| previous != self.state) {
            return Err(invalid_state());
        }
        let bytes = serde_json::to_vec_pretty(&self.state).map_err(|_| invalid_state())?;
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
    fn plan_is_durable_before_the_first_registry_write() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("Nomad/nomad.reg-state.json");
        let plan = Plan::new("firefox", "Firefox", &directory.path().join("Nomad.exe")).unwrap();
        let mut writes = 0;
        plan.apply(&sidecar, |_| {
            assert_eq!(
                read_state(&sidecar).unwrap(),
                Some(planned_state("firefox").unwrap())
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
                        format!(r"{}\shell\open\command", classes_path("firefox")),
                        String::new()
                    )],
                    format!("\"{}\" -- \"%1\"", exe.display())
                );
                assert_eq!(
                    values[&(
                        REGISTERED_APPS_KEY.to_owned(),
                        "NomadPortable.firefox".to_owned()
                    )],
                    r"Software\NomadPortable\firefox\Capabilities"
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
        let canonical = serde_json::to_string(&planned_state("firefox").unwrap()).unwrap();
        let foreign = serde_json::to_vec(&planned_state("helium").unwrap()).unwrap();
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
            assert!(planned_state(id).is_err());
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
}
