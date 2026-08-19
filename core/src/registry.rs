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

// ── Self-registration repair ──────────────────────────────────────────────────
//
// Browsers can register *themselves* as URL/HTML handlers (the "Make default"
// button in their settings). For a Nomad-managed install that registration
// points straight at the browser exe inside the portable tree — bypassing the
// launcher, so the browser starts with its default host-profile location
// (%LOCALAPPDATA%) instead of the portable profile. The result is a second,
// empty-profile instance on every clicked link, whose data Nomad's trace scrub
// then deletes on exit. `repair_self_registration` reroutes exactly those
// commands through the launcher; it never touches a registration that points
// outside the launcher's own install tree.

/// Extracts the executable path from a `shell\open\command` string: the
/// quoted first token when the command starts with `"`, the first
/// whitespace-separated token otherwise.
fn command_exe(command: &str) -> Option<&str> {
    let s = command.trim_start();
    if let Some(rest) = s.strip_prefix('"') {
        rest.split('"').next()
    } else {
        s.split_whitespace().next()
    }
    .filter(|exe| !exe.is_empty())
}

/// Component-wise, ASCII-case-insensitive "is `path` strictly inside `root`".
/// Pure string comparison — the paths come from registry values and may not
/// exist on disk, so filesystem canonicalization is not an option.
fn path_is_under(root: &Path, path: &Path) -> bool {
    let norm = |p: &Path| -> Vec<String> {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
            .collect()
    };
    let root = norm(root);
    let path = norm(path);
    // An empty root is a prefix of everything; treat it as matching nothing so
    // a caller that derives the root from a bare file name cannot widen a
    // containment check into "any path on the machine".
    !root.is_empty() && path.len() > root.len() && path[..root.len()] == root[..]
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(windows)]
mod win {
    use std::path::Path;

    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    use super::{
        app_key_path, classes_path, command_exe, is_nomad_owned_key, is_nomad_owned_value,
        path_is_under, prog_id, RegState, RegistryError, Result, REGISTERED_APPS_KEY,
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

    pub(super) fn repair_self_registration(install_dir: &Path, launcher_exe: &Path) -> usize {
        let Some(launcher_str) = launcher_exe.to_str() else {
            return 0; // non-UTF-8 launcher path — nothing sane to write
        };
        // An empty install_dir would make path_is_under match every path on the
        // machine, turning the sweep below into a rewrite of every handler in
        // HKCU. Callers derive it from a browser exe path, so refuse the
        // degenerate case rather than trusting them.
        if install_dir.as_os_str().is_empty() {
            return 0;
        }
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let mut repaired = 0;

        // 1. Every ProgId under HKCU\Software\Classes whose open command runs a
        //    binary inside our install tree.
        let url_command = format!("\"{launcher_str}\" -- \"%1\"");
        repaired += repair_classes_commands(&hkcu, install_dir, &url_command);

        // 2. Start-Menu-Internet clients (launch-without-URL surface).
        let smi_command = format!("\"{launcher_str}\"");
        if let Ok(clients) = hkcu.open_subkey("Software\\Clients\\StartMenuInternet") {
            let names: Vec<String> = clients
                .enum_keys()
                .filter_map(std::result::Result::ok)
                .collect();
            for name in names {
                let key_path =
                    format!("Software\\Clients\\StartMenuInternet\\{name}\\shell\\open\\command");
                if repair_command_key(&hkcu, &key_path, install_dir, &smi_command) {
                    repaired += 1;
                }
            }
        }

        repaired
    }

    /// Sweeps every `ProgId` under `HKCU\Software\Classes` and reroutes the
    /// ones whose `shell\open\command` runs a binary inside `install_dir`.
    ///
    /// Deliberately not limited to the `ProgId`s currently selected via
    /// `UserChoice`. A third-party redirector (Winhance's `OpenWebSearch`
    /// stub, `MSEdgeRedirect`, …) commonly owns the http/https `UserChoice`
    /// slot and dispatches onward to the browser's own `ProgId` — so the
    /// `ProgId` that actually launches the browser is frequently not the
    /// selected one. Scanning only `UserChoice` left those commands pointing
    /// straight at the browser exe, which is the bug this sweep closes.
    ///
    /// Safety is carried entirely by `path_is_under` in [`repair_command_key`]:
    /// a command is rewritten only when its executable lives strictly inside
    /// this launcher's own install tree. Other browsers, other Nomad
    /// launchers, and system installs are never touched (SPEC §10).
    ///
    /// `Software\Classes` holds a few thousand keys on a typical machine and
    /// most have no `shell\open\command`, so this is a few thousand failed
    /// opens — cheap relative to the launch it runs alongside.
    fn repair_classes_commands(hkcu: &RegKey, install_dir: &Path, url_command: &str) -> usize {
        let Ok(classes) = hkcu.open_subkey("Software\\Classes") else {
            return 0;
        };
        let mut repaired = 0;
        let names: Vec<String> = classes
            .enum_keys()
            .filter_map(std::result::Result::ok)
            .collect();
        for name in names {
            // Extension keys (".html") name a ProgId rather than carrying a
            // command; Nomad's own ProgId already routes through the launcher.
            if name.starts_with('.') || name.starts_with("NomadPortable.") {
                continue;
            }
            // `Applications\<exe>` is a container of per-exe handlers, one
            // level deeper than an ordinary ProgId. Chromium registers itself
            // there too, so descend instead of skipping.
            if name.eq_ignore_ascii_case("Applications") {
                repaired += repair_applications_commands(hkcu, install_dir, url_command);
                continue;
            }
            let key_path = format!("Software\\Classes\\{name}\\shell\\open\\command");
            if repair_command_key(hkcu, &key_path, install_dir, url_command) {
                repaired += 1;
            }
        }
        repaired
    }

    /// Per-exe "Open with" handlers under
    /// `HKCU\Software\Classes\Applications\<exe>\shell\open\command`.
    fn repair_applications_commands(hkcu: &RegKey, install_dir: &Path, url_command: &str) -> usize {
        let Ok(apps) = hkcu.open_subkey("Software\\Classes\\Applications") else {
            return 0;
        };
        let names: Vec<String> = apps
            .enum_keys()
            .filter_map(std::result::Result::ok)
            .collect();
        let mut repaired = 0;
        for name in names {
            let key_path = format!("Software\\Classes\\Applications\\{name}\\shell\\open\\command");
            if repair_command_key(hkcu, &key_path, install_dir, url_command) {
                repaired += 1;
            }
        }
        repaired
    }

    /// Rewrites the default value of `key_path` to `replacement` when its
    /// current command launches an executable strictly inside `install_dir`.
    /// Returns whether a rewrite happened.
    pub(super) fn repair_command_key(
        hkcu: &RegKey,
        key_path: &str,
        install_dir: &Path,
        replacement: &str,
    ) -> bool {
        let Ok(key) = hkcu.open_subkey_with_flags(key_path, KEY_READ | KEY_WRITE) else {
            return false;
        };
        let Ok(current) = key.get_value::<String, _>("") else {
            return false;
        };
        let Some(exe) = command_exe(&current) else {
            return false;
        };
        if !path_is_under(install_dir, Path::new(exe)) {
            return false;
        }
        if current == replacement {
            return false; // already routed through this launcher
        }
        match key.set_value("", &replacement.to_owned()) {
            Ok(()) => {
                tracing::info!(
                    key = %key_path,
                    old = %current,
                    "rerouted browser self-registration through the Nomad launcher"
                );
                true
            }
            Err(e) => {
                tracing::warn!(key = %key_path, error = %e, "could not repair self-registration");
                false
            }
        }
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

/// Reroutes browser self-registrations through the launcher.
///
/// Sweeps every `ProgId` under `HKCU\Software\Classes` (including the per-exe
/// `Applications\<exe>` handlers) plus the `StartMenuInternet` clients, and
/// rewrites any `shell\open\command` whose executable lives strictly inside
/// `install_dir` so it invokes `launcher_exe` instead (`"<launcher>" -- "%1"`
/// for URL handlers). Commands pointing anywhere else — other browsers, other
/// Nomad launchers, system installs — are never touched.
///
/// The sweep is not restricted to the `ProgId`s currently selected via
/// `UserChoice`: a third-party redirector often holds that slot and dispatches
/// onward to the browser's own `ProgId`, so the command that actually launches
/// the browser is frequently not the selected one.
///
/// Best-effort: individual failures are logged and skipped. Returns the
/// number of commands rewritten.
#[cfg(windows)]
#[must_use]
pub fn repair_self_registration(install_dir: &Path, launcher_exe: &Path) -> usize {
    win::repair_self_registration(install_dir, launcher_exe)
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

#[cfg(not(windows))]
#[must_use]
pub fn repair_self_registration(_install_dir: &Path, _launcher_exe: &Path) -> usize {
    0
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
    fn command_exe_parses_quoted_and_bare_commands() {
        assert_eq!(
            command_exe(r#""C:\Portables\Helium\Browser\chrome.exe" --single-argument %1"#),
            Some(r"C:\Portables\Helium\Browser\chrome.exe")
        );
        assert_eq!(
            command_exe(r"C:\tools\browser.exe %1"),
            Some(r"C:\tools\browser.exe")
        );
        assert_eq!(
            command_exe(r#"  "C:\a b\x.exe""#),
            Some(r"C:\a b\x.exe"),
            "leading whitespace and embedded spaces must be handled"
        );
        assert_eq!(command_exe(""), None);
        assert_eq!(command_exe("\"\" %1"), None, "empty quoted exe is invalid");
    }

    #[test]
    fn path_is_under_is_case_insensitive_and_strict() {
        let root = Path::new(r"C:\Portables\Helium\Browser");
        assert!(path_is_under(
            root,
            Path::new(r"C:\Portables\Helium\Browser\chrome.exe")
        ));
        assert!(path_is_under(
            root,
            Path::new(r"c:\portables\helium\browser\sub\chrome.exe")
        ));
        // The root itself is not *under* the root.
        assert!(!path_is_under(root, root));
        // Siblings — the launcher beside the install dir must never match.
        assert!(!path_is_under(
            root,
            Path::new(r"C:\Portables\Helium\Nomad-Helium.exe")
        ));
        // Prefix of a component name is not containment.
        assert!(!path_is_under(
            root,
            Path::new(r"C:\Portables\Helium\BrowserEvil\chrome.exe")
        ));
    }

    // Repair round-trip against a synthetic HKCU key (Windows-only: registry).
    #[cfg(windows)]
    #[test]
    fn repair_command_key_rewrites_only_commands_inside_install_dir() {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let base = "Software\\Classes\\NomadPortable.test-repair.HTML";
        let key_path = format!("{base}\\shell\\open\\command");
        let (key, _) = hkcu.create_subkey(&key_path).unwrap();

        let install_dir = Path::new(r"C:\Portables\TestBrowser\Browser");
        let replacement = r#""C:\Portables\TestBrowser\Nomad-Test.exe" -- "%1""#;

        // Command pointing inside the install dir: must be rewritten.
        key.set_value(
            "",
            &r#""C:\Portables\TestBrowser\Browser\chrome.exe" --single-argument %1"#.to_owned(),
        )
        .unwrap();
        assert!(win::repair_command_key(
            &hkcu,
            &key_path,
            install_dir,
            replacement
        ));
        let rewritten: String = hkcu.open_subkey(&key_path).unwrap().get_value("").unwrap();
        assert_eq!(rewritten, replacement);

        // Second pass is a no-op (already routed through the launcher).
        assert!(!win::repair_command_key(
            &hkcu,
            &key_path,
            install_dir,
            replacement
        ));

        // Command pointing elsewhere: must be left alone.
        let foreign = r#""C:\Program Files\Other\browser.exe" %1"#.to_owned();
        key.set_value("", &foreign).unwrap();
        assert!(!win::repair_command_key(
            &hkcu,
            &key_path,
            install_dir,
            replacement
        ));
        let untouched: String = hkcu.open_subkey(&key_path).unwrap().get_value("").unwrap();
        assert_eq!(untouched, foreign);

        hkcu.delete_subkey_all(base).unwrap();
    }

    /// Regression: the repair used to derive its candidate `ProgId`s solely
    /// from the http/https `UserChoice` values. When a third-party redirector
    /// (Winhance's `OpenWebSearch` stub, `MSEdgeRedirect`, …) owns that slot
    /// and dispatches onward to the browser's own `ProgId`, the one that
    /// actually launches the browser was never examined — so clicked links
    /// kept opening the browser exe directly, on the host profile, in a
    /// second instance.
    #[cfg(windows)]
    #[test]
    fn repair_rewrites_progids_that_are_not_the_userchoice_selection() {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let install_dir = Path::new(r"C:\Portables\NomadTestSweep\Browser");
        let launcher = Path::new(r"C:\Portables\NomadTestSweep\Nomad-Test.exe");

        // A ProgId the user never selected, pointing into the install tree —
        // exactly what a browser's own "Make default" leaves behind.
        let ours = "Software\\Classes\\NomadTestSweepHTM.unselected";
        let ours_cmd = format!("{ours}\\shell\\open\\command");
        hkcu.create_subkey(&ours_cmd)
            .unwrap()
            .0
            .set_value(
                "",
                &r#""C:\Portables\NomadTestSweep\Browser\chrome.exe" --single-argument %1"#
                    .to_owned(),
            )
            .unwrap();

        // A per-exe "Open with" handler, one level deeper.
        let app = "Software\\Classes\\Applications\\nomadtestsweep-chrome.exe";
        let app_cmd = format!("{app}\\shell\\open\\command");
        hkcu.create_subkey(&app_cmd)
            .unwrap()
            .0
            .set_value(
                "",
                &r#""C:\Portables\NomadTestSweep\Browser\chrome.exe" -- "%1""#.to_owned(),
            )
            .unwrap();

        // A foreign handler that must survive untouched.
        let foreign_cmd = "Software\\Classes\\NomadTestSweepHTM.foreign\\shell\\open\\command";
        let foreign_value = r#""C:\Program Files\Other\browser.exe" %1"#.to_owned();
        hkcu.create_subkey(foreign_cmd)
            .unwrap()
            .0
            .set_value("", &foreign_value)
            .unwrap();

        let repaired = win::repair_self_registration(install_dir, launcher);

        let expected = format!("\"{}\" -- \"%1\"", launcher.display());
        let got: String = hkcu.open_subkey(&ours_cmd).unwrap().get_value("").unwrap();
        assert_eq!(
            got, expected,
            "a ProgId inside the install tree must be rerouted even when it is \
             not the UserChoice selection"
        );
        let got_app: String = hkcu.open_subkey(&app_cmd).unwrap().get_value("").unwrap();
        assert_eq!(
            got_app, expected,
            "Applications\\<exe> handlers must be swept too"
        );
        let got_foreign: String = hkcu
            .open_subkey(foreign_cmd)
            .unwrap()
            .get_value("")
            .unwrap();
        assert_eq!(
            got_foreign, foreign_value,
            "a command pointing outside the install tree must never be touched"
        );
        assert!(repaired >= 2, "both in-tree commands must be counted");

        hkcu.delete_subkey_all(ours).unwrap();
        hkcu.delete_subkey_all(app).unwrap();
        hkcu.delete_subkey_all("Software\\Classes\\NomadTestSweepHTM.foreign")
            .unwrap();
    }

    /// An empty root must match nothing. Otherwise a caller that derives
    /// `install_dir` from a bare exe name — whose parent is `""` — would turn
    /// the sweep into "rewrite every handler command in `HKCU`".
    #[test]
    fn path_is_under_rejects_an_empty_root() {
        assert!(!path_is_under(
            Path::new(""),
            Path::new(r"C:\Program Files\Other\browser.exe")
        ));
    }

    #[cfg(windows)]
    #[test]
    fn repair_self_registration_refuses_an_empty_install_dir() {
        assert_eq!(
            win::repair_self_registration(Path::new(""), Path::new(r"C:\x\Nomad.exe")),
            0
        );
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
