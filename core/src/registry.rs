//! Windows default-browser registration via `HKCU`.
//!
//! Writes only to `HKCU\Software\Classes\...` and
//! `HKCU\Software\RegisteredApplications` — never `HKLM`. On registration,
//! every written path is recorded in a `nomad.reg-state.json` sidecar beside
//! the launcher so [`unregister`] can remove exactly those keys without
//! touching anything else.
//!
//! # Windows Default-apps integration
//!
//! After calling [`register`] the launcher appears in *Settings → Default apps*.
//! The user must click it there to assign HTTP/HTTPS — Windows enforces this
//! since Windows 8 and cannot be bypassed without a UAC-requiring `HKLM` write.

use std::path::Path;

use serde::{Deserialize, Serialize};

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("registry operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("sidecar parse failed: {0}")]
    Sidecar(String),
    #[error("not registered — run with --register-default first")]
    NotRegistered,
    #[error(
        "{failed} registry entr(y/ies) could not be removed; the registration \
         record was kept so --unregister-default can be retried"
    )]
    PartialUnregister { failed: usize },
}

pub type Result<T> = std::result::Result<T, RegistryError>;

// ── Sidecar data ──────────────────────────────────────────────────────────────

/// Data written to `nomad.reg-state.json` on registration.
///
/// Consumed by [`unregister`] to delete exactly the keys we wrote.
#[derive(Debug, Serialize, Deserialize)]
struct RegState {
    version: u32,
    browser_id: String,
    /// `HKCU`-relative paths whose entire subtrees are deleted on unregister.
    keys: Vec<String>,
    /// `(key_path, value_name)` pairs whose values are deleted on unregister.
    values: Vec<(String, String)>,
}

// ── ProgId / app-key naming ───────────────────────────────────────────────────

fn prog_id(browser_id: &str) -> String {
    format!("NomadPortable.{browser_id}.HTML")
}

fn app_key_path(browser_id: &str) -> String {
    format!("Software\\NomadPortable\\{browser_id}")
}

fn classes_path(browser_id: &str) -> String {
    format!("Software\\Classes\\{}", prog_id(browser_id))
}

// ── Sidecar deletion safety ─────────────────────────────────────────────────

/// `HKCU`-relative key prefixes that [`register`] legitimately creates. On
/// unregister, `delete_subkey_all` is refused for any key outside these so a
/// tampered sidecar cannot turn cleanup into deletion of an unrelated `HKCU`
/// subtree (CWE-610 — the sidecar is a local-write trust boundary).
const OWNED_KEY_PREFIXES: &[&str] = &[
    "Software\\Classes\\NomadPortable.",
    "Software\\NomadPortable\\",
];

/// The single `HKCU` key under which [`register`] writes a
/// `RegisteredApplications` value.
const REGISTERED_APPS_KEY: &str = "Software\\RegisteredApplications";

/// Whether `key_path` names a subtree Nomad owns and may delete wholesale.
/// Comparison is case-insensitive (registry keys are) and requires a non-empty
/// child segment after the prefix, so the namespace container itself is spared.
fn is_nomad_owned_key(key_path: &str) -> bool {
    let lower = key_path.to_ascii_lowercase();
    OWNED_KEY_PREFIXES.iter().any(|prefix| {
        let p = prefix.to_ascii_lowercase();
        lower.len() > p.len() && lower.starts_with(&p)
    })
}

/// Whether `(key_path, value_name)` is the lone `RegisteredApplications` value
/// Nomad writes — the only value `unregister` is permitted to delete.
fn is_nomad_owned_value(key_path: &str, value_name: &str) -> bool {
    key_path.eq_ignore_ascii_case(REGISTERED_APPS_KEY) && value_name.starts_with("NomadPortable.")
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(windows)]
mod win {
    use std::path::Path;

    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    use super::{
        app_key_path, classes_path, is_nomad_owned_key, is_nomad_owned_value, prog_id, RegState,
        RegistryError, Result, REGISTERED_APPS_KEY,
    };

    pub(super) fn register(
        browser_id: &str,
        display_name: &str,
        exe_path: &Path,
        sidecar: &Path,
    ) -> Result<()> {
        let exe_str = exe_path.to_str().ok_or_else(|| {
            RegistryError::Sidecar("exe path contains non-UTF-8 characters".to_owned())
        })?;
        let icon_str = format!("{exe_str},0");
        let command_str = format!("\"{exe_str}\" -- \"%1\"");
        let pid = prog_id(browser_id);
        let app_label = format!("{display_name} (Nomad Launcher)");
        let app_desc = format!("Privacy-hardened {display_name} \u{2014} Nomad Launcher");

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        // 1. ProgId definition under HKCU\Software\Classes\NomadPortable.{id}.HTML
        let cls = classes_path(browser_id);
        let (cls_key, _) = hkcu.create_subkey(&cls)?;
        cls_key.set_value("", &app_label)?;

        let (app_sub, _) = cls_key.create_subkey("Application")?;
        app_sub.set_value("ApplicationName", &app_label)?;
        app_sub.set_value("ApplicationIcon", &icon_str)?;
        app_sub.set_value("ApplicationDescription", &app_desc)?;

        let (icon_sub, _) = cls_key.create_subkey("DefaultIcon")?;
        icon_sub.set_value("", &icon_str)?;

        let (cmd_sub, _) = cls_key.create_subkey("shell\\open\\command")?;
        cmd_sub.set_value("", &command_str)?;

        // 2. Capabilities under HKCU\Software\NomadPortable\{id}\Capabilities
        let app_path = app_key_path(browser_id);
        let caps_path = format!("{app_path}\\Capabilities");
        let (caps_key, _) = hkcu.create_subkey(&caps_path)?;
        caps_key.set_value("ApplicationName", &app_label)?;
        caps_key.set_value("ApplicationDescription", &app_desc)?;

        let (file_assoc, _) = caps_key.create_subkey("FileAssociations")?;
        for ext in [".htm", ".html", ".shtml", ".xhtml"] {
            file_assoc.set_value(ext, &pid)?;
        }

        let (url_assoc, _) = caps_key.create_subkey("URLAssociations")?;
        for proto in ["http", "https", "ftp"] {
            url_assoc.set_value(proto, &pid)?;
        }

        // 3. RegisteredApplications entry
        let app_reg_name = format!("NomadPortable.{browser_id}");
        let (reg_apps_key, _) = hkcu.create_subkey(REGISTERED_APPS_KEY)?;
        reg_apps_key.set_value(&app_reg_name, &caps_path)?;

        // 4. Notify the shell so Default-apps picker refreshes.
        notify_shell();

        // 5. Record what we wrote so unregister() can clean up precisely.
        let state = RegState {
            version: 1,
            browser_id: browser_id.to_owned(),
            keys: vec![cls, app_path],
            values: vec![(REGISTERED_APPS_KEY.to_owned(), app_reg_name)],
        };
        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| RegistryError::Sidecar(e.to_string()))?;
        if let Some(parent) = sidecar.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(sidecar, json)?;

        Ok(())
    }

    pub(super) fn unregister(sidecar: &Path) -> Result<()> {
        if !sidecar.exists() {
            return Err(RegistryError::NotRegistered);
        }

        let json = std::fs::read_to_string(sidecar)?;
        let state: RegState =
            serde_json::from_str(&json).map_err(|e| RegistryError::Sidecar(e.to_string()))?;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        let mut failed: usize = 0;

        for key_path in &state.keys {
            // Defense-in-depth: refuse to delete anything the sidecar claims
            // that Nomad would not itself have created (CWE-610).
            if !is_nomad_owned_key(key_path) {
                tracing::warn!(
                    key = %key_path,
                    "refusing to delete registry key outside the Nomad namespace (tampered sidecar?)"
                );
                continue;
            }
            // A NotFound is fine (key already gone); anything else is a real
            // leftover that must keep the sidecar alive for a retry.
            if let Err(e) = hkcu.delete_subkey_all(key_path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(key = %key_path, error = %e, "could not delete registry key");
                    failed += 1;
                }
            }
        }

        for (key_path, value_name) in &state.values {
            if !is_nomad_owned_value(key_path, value_name) {
                tracing::warn!(
                    key = %key_path,
                    value = %value_name,
                    "refusing to delete registry value outside the Nomad namespace (tampered sidecar?)"
                );
                continue;
            }
            match hkcu.open_subkey_with_flags(key_path, KEY_WRITE) {
                Ok(key) => {
                    if let Err(e) = key.delete_value(value_name) {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            tracing::warn!(
                                key = %key_path,
                                value = %value_name,
                                error = %e,
                                "could not delete registry value"
                            );
                            failed += 1;
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // parent gone
                Err(e) => {
                    tracing::warn!(
                        key = %key_path,
                        error = %e,
                        "could not open registry key for value deletion"
                    );
                    failed += 1;
                }
            }
        }

        notify_shell();

        if failed > 0 {
            // Removing the sidecar now would orphan the leftover entries with
            // no record of them; keep it so unregistering can be retried.
            return Err(RegistryError::PartialUnregister { failed });
        }
        let _ = std::fs::remove_file(sidecar);
        Ok(())
    }

    fn notify_shell() {
        // Declare SHChangeNotify without pulling in the large Win32_UI_Shell feature set.
        #[link(name = "shell32")]
        extern "system" {
            fn SHChangeNotify(
                w_event: i32,
                u_flags: u32,
                dw_item1: *const std::ffi::c_void,
                dw_item2: *const std::ffi::c_void,
            );
        }
        // SAFETY: SHCNE_ASSOCCHANGED (0x0800_0000) with SHCNF_DWORD (0x0003) takes
        // no items — both pointers are null. This is a standard shell notification.
        unsafe {
            SHChangeNotify(
                0x0800_0000i32,
                0x0003u32,
                std::ptr::null(),
                std::ptr::null(),
            );
        }
    }
}

// ── Public API (Windows) ──────────────────────────────────────────────────────

/// Registers the launcher as a default-browser candidate in `HKCU`.
///
/// Writes `ProgId`, capabilities, and `RegisteredApplications` entries so the
/// launcher appears in *Settings → Default apps*. All written paths are
/// recorded in `sidecar` for clean removal by [`unregister`].
///
/// Calling this again on an already-registered launcher is idempotent: it
/// overwrites the existing entries with the current exe path.
///
/// # Errors
/// Returns [`RegistryError::Io`] if a registry write or sidecar write fails.
#[cfg(windows)]
pub fn register(
    browser_id: &str,
    display_name: &str,
    exe_path: &Path,
    sidecar: &Path,
) -> Result<()> {
    win::register(browser_id, display_name, exe_path, sidecar)
}

/// Removes the registration created by [`register`], reading the list of
/// written paths from `sidecar`.
///
/// Deletes only the keys and values recorded at registration time — no
/// guessing, no collateral damage to other applications.
///
/// # Errors
/// Returns [`RegistryError::NotRegistered`] when the sidecar is absent,
/// [`RegistryError::Io`] on read/delete failures.
#[cfg(windows)]
pub fn unregister(sidecar: &Path) -> Result<()> {
    win::unregister(sidecar)
}

// ── Non-Windows stubs ─────────────────────────────────────────────────────────

#[cfg(not(windows))]
pub fn register(
    _browser_id: &str,
    _display_name: &str,
    _exe_path: &Path,
    _sidecar: &Path,
) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn unregister(_sidecar: &Path) -> Result<()> {
    Err(RegistryError::NotRegistered)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Sidecar round-trip: verify the JSON encodes and decodes cleanly without
    // touching the real registry (platform-agnostic test).
    #[test]
    fn sidecar_round_trips_without_registry() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar_path = dir.path().join("nomad.reg-state.json");

        // Write a synthetic sidecar directly.
        let state = RegState {
            version: 1,
            browser_id: "test-browser".to_owned(),
            keys: vec![
                "Software\\Classes\\NomadPortable.test-browser.HTML".to_owned(),
                "Software\\NomadPortable\\test-browser".to_owned(),
            ],
            values: vec![(
                "Software\\RegisteredApplications".to_owned(),
                "NomadPortable.test-browser".to_owned(),
            )],
        };
        let json = serde_json::to_string_pretty(&state).unwrap();
        std::fs::write(&sidecar_path, &json).unwrap();

        // Re-parse and verify fields.
        let loaded: RegState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.browser_id, "test-browser");
        assert_eq!(loaded.keys.len(), 2);
        assert_eq!(loaded.values.len(), 1);
        assert_eq!(loaded.values[0].0, "Software\\RegisteredApplications");
        assert_eq!(loaded.values[0].1, "NomadPortable.test-browser");
    }

    #[test]
    fn unregister_without_sidecar_returns_not_registered() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar = dir.path().join("nomad.reg-state.json");
        let err = unregister(&sidecar).unwrap_err();
        assert!(
            matches!(err, RegistryError::NotRegistered),
            "expected NotRegistered, got {err}"
        );
    }

    #[test]
    fn owned_key_validation_accepts_nomad_keys_only() {
        // The exact keys register() records:
        assert!(is_nomad_owned_key(
            "Software\\Classes\\NomadPortable.firefox.HTML"
        ));
        assert!(is_nomad_owned_key(
            "Software\\NomadPortable\\ungoogled-chromium"
        ));
        // Registry keys are case-insensitive:
        assert!(is_nomad_owned_key(
            "software\\classes\\nomadportable.firefox.html"
        ));
        // A tampered sidecar must not be able to nuke unrelated HKCU subtrees:
        assert!(!is_nomad_owned_key("Software"));
        assert!(!is_nomad_owned_key("Software\\Classes"));
        assert!(!is_nomad_owned_key("Software\\Microsoft\\Windows"));
        assert!(!is_nomad_owned_key("Software\\NomadPortable")); // container, no child
        assert!(!is_nomad_owned_key("Software\\Classes\\NomadPortableEvil")); // missing the dot
    }

    #[test]
    fn owned_value_validation_is_scoped_to_registered_applications() {
        assert!(is_nomad_owned_value(
            "Software\\RegisteredApplications",
            "NomadPortable.firefox"
        ));
        assert!(!is_nomad_owned_value(
            "Software\\Microsoft\\Windows",
            "NomadPortable.firefox"
        ));
        assert!(!is_nomad_owned_value(
            "Software\\RegisteredApplications",
            "SomeOtherApp"
        ));
    }

    #[test]
    fn prog_id_uses_browser_id() {
        assert_eq!(
            prog_id("ungoogled-chromium"),
            "NomadPortable.ungoogled-chromium.HTML"
        );
        assert_eq!(prog_id("firefox"), "NomadPortable.firefox.HTML");
    }

    // Full registry round-trip: writes to HKCU and cleans up.
    // Only runs on Windows because the registry is Windows-only.
    #[cfg(windows)]
    #[test]
    fn register_writes_sidecar_and_unregister_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar = dir.path().join("nomad.reg-state.json");
        let exe = std::env::current_exe().unwrap();

        register("nomad-test-reg", "Test Registry Browser", &exe, &sidecar)
            .expect("register must succeed");
        assert!(sidecar.exists(), "sidecar must be created by register");

        let json = std::fs::read_to_string(&sidecar).unwrap();
        let state: RegState = serde_json::from_str(&json).expect("sidecar must be valid JSON");
        assert_eq!(state.browser_id, "nomad-test-reg");
        assert_eq!(state.version, 1);
        assert!(
            !state.keys.is_empty(),
            "register must record at least one key"
        );

        unregister(&sidecar).expect("unregister must succeed");
        assert!(!sidecar.exists(), "unregister must remove the sidecar");
    }
}
