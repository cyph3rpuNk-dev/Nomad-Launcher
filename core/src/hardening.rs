//! Privacy-hardening file writers for both Gecko- and Chromium-family browsers
//! (SPEC §5).
//!
//! Chromium hardening is primarily applied via launch flags (`build_launch_args`
//! in `lib.rs`), but two JSON files in the user-data-dir also need seeding so
//! that `chrome://flags` reflects the same state and so profile-level prefs
//! that are not exposed as `--flag` switches (HTTPS-only, Privacy Sandbox m1,
//! Safe Browsing, …) are applied. The Gecko path uses `user.js`,
//! `policies.json`, and the autoconfig pair (`autoconfig.js` + `nomad.cfg`).

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::browsers::{BrowserError, Result};

const MARKER_BEGIN: &str = "// === Nomad Launcher hardening — begin ===";
const MARKER_END: &str = "// === Nomad Launcher hardening — end ===";

/// Preserve an already-correct managed file, including on read-only bundles.
/// Unreadable existing bytes cannot establish correctness and must fail.
fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::fs_safety::ensure_file(path)?;
    match std::fs::read(path) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    crate::fs_safety::atomic_write(path, bytes)?;
    Ok(())
}

/// Writes `user_js_content` into `<profile_dir>/user.js`, fenced by Nomad
/// markers so successive writes replace only the managed section.
///
/// Any content the user has added outside the markers is preserved unchanged.
/// The profile directory is created if it does not exist. If `user.js` does
/// not yet exist, the managed block is written as the entire file.
///
/// # Errors
/// Returns [`BrowserError::Io`] if the directory cannot be created, the file
/// cannot be written, or an *existing* `user.js` cannot be read (non-UTF-8,
/// locked, …) — treating an unreadable file as empty would overwrite the
/// user's own prefs with just the managed block. Required launch preparation
/// propagates the error and stops before browser creation.
pub fn write_user_js(profile_dir: &Path, user_js_content: &str) -> Result<()> {
    crate::fs_safety::create_dir_all(profile_dir)?;
    let path = profile_dir.join("user.js");
    crate::fs_safety::ensure_file(&path)?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let managed = format!("{MARKER_BEGIN}\n{user_js_content}\n{MARKER_END}");
    let new_content = if existing.contains(MARKER_BEGIN) {
        replace_fenced(&existing, &managed)
    } else if existing.is_empty() {
        managed
    } else {
        format!("{existing}\n\n{managed}")
    };
    write_if_changed(&path, new_content.as_bytes())?;
    Ok(())
}

/// Removes the Nomad-managed block from `<profile_dir>/user.js`, preserving any
/// content the user added outside the markers. If the managed block was the
/// file's only content, the file is deleted entirely.
///
/// Used for browsers that opt out of Nomad's `user.js` management by declaring
/// an empty `user_js` payload (e.g. Mullvad Browser, which manages its own
/// prefs and must not be made fingerprint-distinguishable from its crowd). It
/// also self-heals a profile a prior Nomad version may have written into.
///
/// # Errors
/// Returns [`BrowserError::Io`] if the file exists but cannot be rewritten or
/// removed, or existing bytes cannot be read as UTF-8.
pub fn remove_managed_user_js(profile_dir: &Path) -> Result<()> {
    let path = profile_dir.join("user.js");
    crate::fs_safety::ensure_file(&path)?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if !existing.contains(MARKER_BEGIN) {
        return Ok(()); // no Nomad block — leave the user's own file untouched
    }
    let stripped = strip_fenced(&existing);
    if stripped.trim().is_empty() {
        std::fs::remove_file(&path)?;
    } else {
        crate::fs_safety::atomic_write(&path, stripped.as_bytes())?;
    }
    Ok(())
}

/// Writes `policies_content` into `<install_dir>/distribution/policies.json`.
///
/// Creates the `distribution/` subdirectory if it does not exist. Called at
/// install time on the stage directory, so the file is swapped in atomically.
///
/// # Errors
/// Returns [`BrowserError::Io`] if the directory or file cannot be written, and
/// [`BrowserError::Parse`] for an invalid root or policies object.
pub fn write_policies_json(install_dir: &Path, policies_content: &str) -> Result<()> {
    validate_policy_payload(policies_content)?;
    let dist = install_dir.join("distribution");
    crate::fs_safety::create_dir_all(&dist)?;
    write_if_changed(&dist.join("policies.json"), policies_content.as_bytes())?;
    Ok(())
}

/// Writes the Gecko autoconfig pair into `install_dir`:
/// - `defaults/pref/autoconfig.js` — pointer file Gecko reads at startup to
///   discover and load the .cfg.
/// - `nomad.cfg` — the actual `lockPref()` payload, derived from `LibreWolf`'s
///   official settings.
///
/// This mechanism is the same one used by `LibreWolf`, Tor Browser, and
/// Mozilla Enterprise. The cfg is evaluated before any profile loads, so it
/// applies hardening reliably even on a fresh first-launch profile —
/// something profile-level `user.js` cannot guarantee.
///
/// # Errors
/// Returns [`BrowserError::Io`] if any directory or file write fails.
pub fn write_autoconfig(
    install_dir: &Path,
    autoconfig_content: &str,
    cfg_content: &str,
) -> Result<()> {
    let pref_dir = install_dir.join("defaults").join("pref");
    crate::fs_safety::create_dir_all(&pref_dir)?;
    write_if_changed(
        &pref_dir.join("autoconfig.js"),
        autoconfig_content.as_bytes(),
    )?;
    write_if_changed(&install_dir.join("nomad.cfg"), cfg_content.as_bytes())?;
    Ok(())
}

/// Removes the autoconfig pair written by [`write_autoconfig`], so
/// `[hardening] enabled = false` actually stops applying the locked prefs
/// rather than merely not refreshing them.
///
/// Both files are deleted by exact name — `defaults/pref/autoconfig.js` and
/// `nomad.cfg` — never the directories, which the browser also populates with
/// its own files (`channel-prefs.js`, …). Callers must invoke this only for
/// browsers that actually declare an autoconfig payload: `LibreWolf` and
/// Mullvad ship their own pair and Nomad never writes theirs, so theirs must
/// never be removed either.
///
/// Missing files are not an error — the profile may never have been hardened.
///
/// # Errors
/// Returns [`BrowserError::Io`] if a file exists but cannot be removed.
pub fn remove_autoconfig(install_dir: &Path) -> Result<()> {
    let targets = [
        install_dir
            .join("defaults")
            .join("pref")
            .join("autoconfig.js"),
        install_dir.join("nomad.cfg"),
    ];
    for path in targets {
        crate::fs_safety::ensure_file(&path)?;
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Seeds Chromium's `Local State` and (optionally) `Default/Preferences` JSON
/// files inside `user_data_dir`, recursively merging the supplied defaults with
/// any existing user values.
///
/// Merge rules:
/// - **Objects**: recursive merge — user-set keys are preserved, missing keys
///   are added from the defaults.
/// - **Arrays**: appended; entries already present are kept as-is. The
///   `browser.enabled_labs_experiments` array is treated specially: matches
///   are made on the `<basename>` part before `@` so a user-modified
///   `<flag>@2` is left alone even when our default is `<flag>@1`.
/// - **Scalars**: only set when the key is absent. Once a user has changed a
///   value via the browser UI, we do not roll it back unless the key is in
///   `LOCKED_SCALAR_PATHS`. Those required values (including `DoH` mode/resolver)
///   are re-enforced from the payload on every enabled-hardening launch.
///
/// Either `local_state_json` or `preferences_json` may be `None`. The
/// `Default/` profile directory is created if absent so `Preferences` can be
/// written even on a fresh user-data-dir.
///
/// # Errors
/// Returns [`BrowserError::Io`] on filesystem failure and
/// [`BrowserError::Parse`] when the JSON payloads (ours or existing on-disk)
/// fail to parse.
pub fn write_chromium_state(
    user_data_dir: &Path,
    local_state_json: Option<&str>,
    preferences_json: Option<&str>,
) -> Result<()> {
    if let Some(payload) = local_state_json {
        let path = user_data_dir.join("Local State");
        merge_json_file(&path, payload)?;
    }
    if let Some(payload) = preferences_json {
        let default_dir = user_data_dir.join("Default");
        crate::fs_safety::create_dir_all(&default_dir)?;
        let path = default_dir.join("Preferences");
        merge_json_file(&path, payload)?;
    }
    Ok(())
}

/// Writes Chromium's `initial_preferences` JSON template next to `chrome.exe`.
///
/// Chromium consults this file **only** when creating a brand-new profile
/// (`Default/Preferences` does not yet exist) and copies its contents into the
/// new profile, computing valid `Secure Preferences` MACs itself.  This is the
/// canonical mechanism for setting MAC-protected keys like
/// `extensions.ui.developer_mode` without triggering the tampering-reset path
/// that hits when those keys are written directly to an established profile.
///
/// For an existing profile, the file is silently ignored by Chromium — so
/// callers may invoke this on every launch without side effects.
///
/// # Errors
/// Returns [`BrowserError::Io`] when the file cannot be written.
pub fn write_chromium_initial_preferences(install_dir: &Path, payload: &str) -> Result<()> {
    let path = install_dir.join("initial_preferences");
    crate::fs_safety::create_dir_all(install_dir)?;
    write_if_changed(&path, payload.as_bytes())?;
    Ok(())
}

/// Builds the `initial_preferences` payload Chromium consumes when creating a
/// brand-new profile, by merging the profile-pref hardening defaults
/// (`profile_prefs`, i.e. `preferences.json`) into the first-run `template`
/// (which carries MAC-protected keys like `extensions.ui.developer_mode`).
///
/// This is required because Chromium's first-run pipeline **regenerates
/// `Default/Preferences` from `initial_preferences`**, discarding any
/// `Default/Preferences` that [`write_chromium_state`] wrote beforehand — so on
/// a fresh profile the hardening prefs would otherwise only take effect from
/// the *second* launch (verified by runtime test against ungoogled-chromium).
/// Routing them through `initial_preferences` makes them active on first run.
///
/// Keys present in `template` win on conflict (none expected today). Local
/// State prefs are intentionally excluded — they live in a separate store that
/// Chromium merges rather than regenerates, so they already survive first run.
///
/// # Errors
/// [`BrowserError::Parse`] when either payload is not valid JSON.
pub fn build_initial_preferences(template: &str, profile_prefs: &str) -> Result<String> {
    let base: Value = serde_json::from_str(template)
        .map_err(|e| BrowserError::Parse(format!("invalid initial_preferences template: {e}")))?;
    let overlay: Value = serde_json::from_str(profile_prefs)
        .map_err(|e| BrowserError::Parse(format!("invalid Chromium preferences payload: {e}")))?;
    if !base.is_object() || !overlay.is_object() {
        return Err(BrowserError::Parse(
            "initial preferences payloads must contain JSON objects".to_owned(),
        ));
    }
    let merged = merge_value(base, overlay);
    serde_json::to_string(&merged)
        .map_err(|e| BrowserError::Parse(format!("could not serialize initial_preferences: {e}")))
}

/// Dot-separated paths to scalar values that Nomad re-applies from its
/// hardening defaults on every launch.  Unlike ordinary scalars (which use
/// "user wins" semantics so browser UI changes survive), these keys control
/// privacy-critical features that must not be silently re-enabled by the
/// browser or a tampered user-data-dir.
const LOCKED_SCALAR_PATHS: &[&str] = &[
    // Default/Preferences
    "safebrowsing.enabled",
    "https_only_mode_enabled",
    "privacy_sandbox.m1.topics_enabled",
    "privacy_sandbox.m1.fledge_enabled",
    "privacy_sandbox.m1.ad_measurement_enabled",
    // Local State
    "dns_over_https.mode",
    "dns_over_https.templates",
];

/// Walks a nested JSON object by a `.`-separated path.  Returns `None` when
/// any segment is absent or the traversal hits a non-object node.
fn get_by_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for key in path.split('.') {
        cur = cur.as_object()?.get(key)?;
    }
    Some(cur)
}

/// Writes `val` into `root` at the `.`-separated `path`, creating any missing
/// intermediate objects. Returns an error when a non-final path segment is not an
/// object (i.e. a scalar blocks the descent).
fn set_by_path(root: &mut Value, path: &str, val: Value) -> Result<()> {
    let mut keys: Vec<&str> = path.split('.').collect();
    let last = keys
        .pop()
        .ok_or_else(|| BrowserError::Parse("empty required preference path".to_owned()))?;
    let mut cur = root;
    for key in keys {
        let Value::Object(m) = cur else {
            return Err(BrowserError::Parse(format!(
                "required preference {path} has a non-object container"
            )));
        };
        cur = m.entry(key).or_insert_with(|| Value::Object(Map::new()));
    }
    let Value::Object(m) = cur else {
        return Err(BrowserError::Parse(format!(
            "required preference {path} has a non-object container"
        )));
    };
    m.insert(last.to_owned(), val);
    Ok(())
}

/// Reads `path` (treating only missing files as an empty object), parses
/// `defaults_json`, merges with `merge_value` semantics, then re-applies all
/// entries from [`LOCKED_SCALAR_PATHS`] from the defaults so that
/// privacy-critical settings cannot be silently re-enabled by the browser.
/// Writes the result back as compact JSON (Chromium also writes prefs without
/// indentation).
fn merge_json_file(path: &Path, defaults_json: &str) -> Result<()> {
    crate::fs_safety::ensure_file(path)?;
    let defaults: Value = serde_json::from_str(defaults_json)
        .map_err(|e| BrowserError::Parse(format!("invalid Chromium hardening payload: {e}")))?;
    let mut existed = true;
    let existing: Value = match std::fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => serde_json::from_str(&s).map_err(|e| {
            BrowserError::Parse(format!(
                "could not parse existing JSON at {}: {e}",
                path.display()
            ))
        })?,
        Ok(_) => {
            return Err(BrowserError::Parse(
                "existing Chromium settings file is empty".to_owned(),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            existed = false;
            Value::Object(Map::new())
        }
        Err(e) => return Err(e.into()),
    };
    if !defaults.is_object() || !existing.is_object() {
        return Err(BrowserError::Parse(
            "Chromium settings must contain a JSON object".to_owned(),
        ));
    }
    let mut merged = merge_value(existing.clone(), defaults.clone());
    for &locked in LOCKED_SCALAR_PATHS {
        if let Some(enforced) = get_by_path(&defaults, locked) {
            set_by_path(&mut merged, locked, enforced.clone())?;
        }
    }
    if existed && merged == existing {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        crate::fs_safety::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(&merged)
        .map_err(|e| BrowserError::Parse(format!("could not serialize merged JSON: {e}")))?;
    crate::fs_safety::atomic_write(path, &bytes)?;
    Ok(())
}

/// Recursive deep-merge. `existing` wins for scalars; objects are merged
/// key-by-key; arrays are merged by appending entries from `defaults` that are
/// not already in `existing`. Arrays at the `enabled_labs_experiments` key
/// match on the `<basename>` before `@` so user-customised options are kept.
fn merge_value(existing: Value, defaults: Value) -> Value {
    match (existing, defaults) {
        (Value::Object(mut e), Value::Object(d)) => {
            for (k, dv) in d {
                let merged = match e.remove(&k) {
                    Some(ev) => merge_array_aware(&k, ev, dv),
                    None => dv,
                };
                e.insert(k, merged);
            }
            Value::Object(e)
        }
        // If types disagree (e.g. user replaced an object with a scalar), prefer existing.
        (existing, _) => existing,
    }
}

/// Per-key merge. Arrays are appended (with a special-case for the <chrome://flags>
/// list). Nested objects recurse via [`merge_value`]. Scalars keep the existing
/// value, so a user-modified pref is never rolled back to our default.
fn merge_array_aware(key: &str, existing: Value, defaults: Value) -> Value {
    match (existing, defaults) {
        (Value::Array(mut e), Value::Array(d)) => {
            if key == "enabled_labs_experiments" {
                let basenames: std::collections::HashSet<String> = e
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.split('@').next().unwrap_or(s).to_owned())
                    .collect();
                for entry in d {
                    let Some(s) = entry.as_str() else { continue };
                    let base = s.split('@').next().unwrap_or(s);
                    if !basenames.contains(base) {
                        e.push(Value::String(s.to_owned()));
                    }
                }
            } else {
                for entry in d {
                    if !e.contains(&entry) {
                        e.push(entry);
                    }
                }
            }
            Value::Array(e)
        }
        (ev @ Value::Object(_), dv @ Value::Object(_)) => merge_value(ev, dv),
        (existing, _) => existing,
    }
}

fn validate_policy_payload(payload: &str) -> Result<Value> {
    let root: Value = serde_json::from_str(payload)
        .map_err(|e| BrowserError::Parse(format!("invalid browser policies JSON: {e}")))?;
    if !root.is_object() || !root.get("policies").is_some_and(Value::is_object) {
        return Err(BrowserError::Parse(
            "browser policies must contain a policies object".to_owned(),
        ));
    }
    Ok(root)
}

/// Injects (or replaces) the `uBlock0@raymondhill.net` entry in the
/// `ExtensionSettings` section of `policies_json` with a `file://` URL
/// pointing at `xpi_path`, so Firefox installs the extension without
/// contacting AMO.
///
/// The `policies` object is required. `ExtensionSettings` is created if absent;
/// the curated payload does not declare that section, so the entry is added
/// without silently accepting a malformed policy object.
///
/// # Errors
/// Returns an error for malformed/nonobject policies or an invalid local path;
/// never silently returns an uninjected payload.
pub(crate) fn inject_ublock_policy(policies_json: &str, xpi_path: &Path) -> Result<String> {
    let url = reqwest::Url::from_file_path(xpi_path).map_err(|()| {
        BrowserError::Parse("cached extension requires an absolute local file path".to_owned())
    })?;
    let mut root = validate_policy_payload(policies_json)?;
    let policies = root
        .get_mut("policies")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| BrowserError::Parse("missing policies object".to_owned()))?;
    let ext = policies
        .entry("ExtensionSettings")
        .or_insert_with(|| json!({}));
    let ext_settings = ext.as_object_mut().ok_or_else(|| {
        BrowserError::Parse("ExtensionSettings must contain an object".to_owned())
    })?;
    ext_settings.insert("uBlock0@raymondhill.net".to_owned(), json!({
        "install_url": url.as_str(), "installation_mode": "normal_installed", "private_browsing": true
    }));
    serde_json::to_string_pretty(&root)
        .map_err(|e| BrowserError::Parse(format!("could not serialize browser policies: {e}")))
}

/// Replaces the Nomad-managed fenced section in `existing` with `managed_block`.
///
/// `managed_block` must already contain both markers. Content before the begin
/// marker and after the end marker is preserved unchanged. If the end marker is
/// absent (malformed file), the replacement runs to end-of-file.
fn replace_fenced(existing: &str, managed_block: &str) -> String {
    let Some(begin) = existing.find(MARKER_BEGIN) else {
        return format!("{existing}\n\n{managed_block}");
    };
    let end = existing[begin..]
        .find(MARKER_END)
        .map_or(existing.len(), |rel| begin + rel + MARKER_END.len());
    format!(
        "{}{}{}",
        &existing[..begin],
        managed_block,
        &existing[end..]
    )
}

/// Removes the Nomad-managed fence (`MARKER_BEGIN`..`MARKER_END`) from
/// `existing`, returning the surrounding content unchanged.
fn strip_fenced(existing: &str) -> String {
    let Some(begin) = existing.find(MARKER_BEGIN) else {
        return existing.to_owned();
    };
    let end = existing[begin..]
        .find(MARKER_END)
        .map_or(existing.len(), |rel| begin + rel + MARKER_END.len());
    format!("{}{}", &existing[..begin], &existing[end..])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn correct_readonly_managed_files_are_accepted_without_rewriting() {
        let temp = tempfile::tempdir().unwrap();
        write_user_js(temp.path(), "user_pref(\"fixture\", true);").unwrap();
        write_policies_json(temp.path(), r#"{"policies":{"DisableAppUpdate":true}}"#).unwrap();
        write_autoconfig(temp.path(), "// pointer\n", "// config\n").unwrap();
        write_chromium_initial_preferences(temp.path(), "{}").unwrap();
        let paths: Vec<_> = [
            "user.js",
            "distribution/policies.json",
            "defaults/pref/autoconfig.js",
            "nomad.cfg",
            "initial_preferences",
        ]
        .iter()
        .map(|name| temp.path().join(name))
        .collect();
        let saved: Vec<_> = paths
            .iter()
            .map(|path| std::fs::metadata(path).unwrap().permissions())
            .collect();
        for path in &paths {
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(path, permissions).unwrap();
        }
        let results = [
            write_user_js(temp.path(), "user_pref(\"fixture\", true);"),
            write_policies_json(temp.path(), r#"{"policies":{"DisableAppUpdate":true}}"#),
            write_autoconfig(temp.path(), "// pointer\n", "// config\n"),
            write_chromium_initial_preferences(temp.path(), "{}"),
        ];
        for (path, permissions) in paths.iter().zip(saved) {
            std::fs::set_permissions(path, permissions).unwrap();
        }
        for result in results {
            assert!(
                result.is_ok(),
                "matching read-only file must not require a write: {result:?}"
            );
        }
        let state = temp.path().join("Local State");
        let original = r#"{ "dns_over_https": { "mode": "secure" } }"#;
        std::fs::write(&state, original).unwrap();
        let saved = std::fs::metadata(&state).unwrap().permissions();
        let mut permissions = saved.clone();
        permissions.set_readonly(true);
        std::fs::set_permissions(&state, permissions).unwrap();
        let unchanged = write_chromium_state(
            temp.path(),
            Some(r#"{"dns_over_https":{"mode":"secure"}}"#),
            None,
        );
        let changed = write_chromium_state(
            temp.path(),
            Some(r#"{"dns_over_https":{"mode":"off"}}"#),
            None,
        );
        std::fs::set_permissions(&state, saved).unwrap();
        assert!(unchanged.is_ok());
        assert!(changed.is_err());
        assert_eq!(std::fs::read_to_string(state).unwrap(), original);
    }

    #[test]
    fn required_json_shape_failures_preserve_existing_state() {
        for original in [
            "[]",
            "false",
            "null",
            "",
            " ",
            r#"{"dns_over_https":false}"#,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let file = temp.path().join("Local State");
            std::fs::write(&file, original).unwrap();
            assert!(write_chromium_state(
                temp.path(),
                Some(r#"{"dns_over_https":{"mode":"secure"}}"#),
                None
            )
            .is_err());
            assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn required_payload_shapes_are_rejected_before_overwriting_policy_or_seed() {
        let temp = tempfile::tempdir().unwrap();
        write_policies_json(temp.path(), r#"{"policies":{"DisableAppUpdate":true}}"#).unwrap();
        let file = temp.path().join("distribution/policies.json");
        let original = std::fs::read(&file).unwrap();
        for bad in ["bad", "[]", "{}", r#"{"policies":false}"#] {
            assert!(write_policies_json(temp.path(), bad).is_err());
            assert_eq!(std::fs::read(&file).unwrap(), original);
        }
        for bad in ["[]", "false", "null"] {
            assert!(build_initial_preferences(bad, "{}").is_err());
            assert!(build_initial_preferences("{}", bad).is_err());
        }
    }

    #[test]
    fn removal_of_unreadable_user_preferences_fails_without_erasing_them() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("user.js");
        let original = b"// unreadable comment \xff\nuser_pref(\"mine\", true);";
        std::fs::write(&file, original).unwrap();
        assert!(remove_managed_user_js(temp.path()).is_err());
        assert_eq!(std::fs::read(file).unwrap(), original);
    }

    #[test]
    fn local_extension_policy_url_round_trips_reserved_characters() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp
            .path()
            .join("space # percent % unicode \u{03c0}")
            .join("uBlock0.xpi");
        let payload = inject_ublock_policy(r#"{"policies":{}}"#, &path).unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        let url = reqwest::Url::parse(
            value
                .pointer("/policies/ExtensionSettings/uBlock0@raymondhill.net/install_url")
                .unwrap()
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(url.to_file_path().unwrap(), path);
        assert!(url.fragment().is_none());
        assert!(
            inject_ublock_policy(r#"{"policies":{}}"#, Path::new("relative/uBlock0.xpi")).is_err()
        );
    }

    #[test]
    fn unreadable_chromium_preferences_are_preserved_without_resetting_to_defaults() {
        let fixture = tempfile::tempdir().unwrap();
        let profile = fixture.path().join("Default");
        std::fs::create_dir_all(&profile).unwrap();
        let path = profile.join("Preferences");
        let original = b"private preferences \xff\xfe";
        std::fs::write(&path, original).unwrap();
        assert!(write_chromium_state(fixture.path(), None, Some(r#"{"x":true}"#)).is_err());
        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[cfg(windows)]
    #[test]
    fn failed_preferences_replacement_preserves_existing_bytes() {
        use std::os::windows::fs::OpenOptionsExt;
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("Local State");
        let original = br#"{"custom":"keep"}"#;
        std::fs::write(&path, original).unwrap();
        // Reads and writes are allowed, but replacement is denied. A truncate
        // writer changes the file; a staged replacement must fail safely.
        let handle = std::fs::File::options()
            .read(true)
            .share_mode(
                windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
            )
            .open(&path)
            .unwrap();
        let result = write_chromium_state(fixture.path(), Some(r#"{"new":true}"#), None);
        assert!(result.is_err(), "a locked replacement must fail");
        drop(handle);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
    }

    #[test]
    fn profile_writers_and_removal_reject_linked_profile_directories() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("instance");
        let foreign = temp.path().join("foreign");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(&foreign).unwrap();
        let original = format!("{MARKER_BEGIN}\nowned block\n{MARKER_END}\n");
        std::fs::write(foreign.join("user.js"), &original).unwrap();
        crate::tests::owned_directory_link(&temp, &base.join("profile"), &foreign);
        let profile = base.join("profile");
        assert!(write_user_js(&profile, "new block").is_err());
        assert!(remove_managed_user_js(&profile).is_err());
        assert!(write_chromium_state(&profile, Some("{}"), Some("{}")).is_err());
        assert_eq!(
            std::fs::read_to_string(foreign.join("user.js")).unwrap(),
            original
        );
        assert_eq!(std::fs::read_dir(&foreign).unwrap().count(), 1);
    }

    #[test]
    fn write_user_js_errors_on_unreadable_existing_file_instead_of_clobbering() {
        // Regression: an existing-but-unreadable user.js (e.g. a non-UTF-8
        // comment the user pasted) used to be treated as empty via
        // unwrap_or_default(), and the rewrite deleted everything the user
        // had outside the fence.
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path();
        let user_js = profile.join("user.js");
        let latin1_pref = b"// caf\xE9 \xE0 la carte\nuser_pref(\"mine\", true);\n";
        std::fs::write(&user_js, latin1_pref).unwrap();

        let err = write_user_js(profile, "user_pref(\"a\", 1);")
            .expect_err("a non-UTF-8 user.js must fail the write, not be clobbered");
        assert!(matches!(err, BrowserError::Io(_)), "got {err:?}");
        assert_eq!(
            std::fs::read(&user_js).unwrap(),
            latin1_pref,
            "the user's file must be left byte-for-byte untouched"
        );
    }

    #[test]
    fn replace_fenced_with_missing_end_marker_replaces_to_eof() {
        // A truncated fence (begin marker, no end marker) is treated as
        // extending to EOF: user content *before* the fence survives, the
        // damaged managed tail is replaced wholesale, and the file heals to
        // a well-formed single fence on the next write.
        let existing = format!("user_pref(\"mine\", true);\n{MARKER_BEGIN}\ndamaged tail, no end");
        let managed = format!("{MARKER_BEGIN}\nuser_pref(\"a\", 1);\n{MARKER_END}");
        let healed = replace_fenced(&existing, &managed);
        assert!(healed.starts_with("user_pref(\"mine\", true);\n"));
        assert!(!healed.contains("damaged tail"));
        assert_eq!(healed.matches(MARKER_BEGIN).count(), 1);
        assert_eq!(healed.matches(MARKER_END).count(), 1);
        assert!(healed.ends_with(MARKER_END));
    }

    #[test]
    fn waterfox_omits_dns_overrides_without_dropping_other_hardening() {
        use crate::browsers::{floorp::Floorp, waterfox::Waterfox, BrowserFamily, Hardening};
        use crate::Arch;
        let Hardening::GeckoProfile {
            user_js,
            cfg: Some(waterfox),
            policies: Some(policies),
            ..
        } = Waterfox::new(Arch::X64).hardening()
        else {
            panic!("missing Waterfox payloads");
        };
        let Hardening::GeckoProfile {
            cfg: Some(floorp), ..
        } = Floorp::new(Arch::X64).hardening()
        else {
            panic!("missing Floorp autoconfig");
        };
        assert_eq!(
            floorp.strip_suffix(include_str!("../payloads/firefox/dns.cfg")),
            Some(waterfox),
            "all non-DNS autoconfig must remain identical across both adapters"
        );
        for payload in [waterfox, user_js, policies] {
            for line in payload.lines().map(str::trim) {
                if line.starts_with("//") {
                    continue;
                }
                assert!(!line.contains("network.trr.") && !line.contains("doh-rollout."));
            }
        }
        assert!(!policies.contains("DNSOverHTTPS"));
        assert!(floorp.contains("defaultPref(\"network.trr.mode\", 5);"));
        assert!(floorp.contains("https://dns.quad9.net/dns-query"));
        assert!(user_js.contains("user_pref(\"privacy.resistFingerprinting\", true);"));
        // Floorp's user.js still supplies its TRR-first user preference.
        let Hardening::GeckoProfile { user_js, .. } = Floorp::new(Arch::X64).hardening() else {
            unreachable!();
        };
        assert!(user_js.contains("user_pref(\"network.trr.mode\", 2);"));
    }

    #[test]
    fn waterfox_dns_upgrade_replaces_stale_autoconfig_and_preserves_user_choices() {
        use crate::browsers::{waterfox::Waterfox, BrowserFamily, Hardening};
        use crate::Arch;
        let Hardening::GeckoProfile {
            user_js,
            autoconfig: Some(pointer),
            cfg: Some(cfg),
            ..
        } = Waterfox::new(Arch::X64).hardening()
        else {
            panic!("missing Waterfox autoconfig");
        };
        // Fresh, explicitly disabled and custom-resolver profiles: do not guess
        // which saved choices were intentional or reset them during migration.
        for user_choice in [
            "",
            "user_pref(\"network.trr.mode\", 5);\n",
            "user_pref(\"network.trr.mode\", 3);\nuser_pref(\"network.trr.uri\", \"https://resolver.example/dns-query\");\nuser_pref(\"network.trr.use_ohttp\", false);\n",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let install = dir.path().join("Browser");
            let profile = dir.path().join("Data");
            std::fs::create_dir_all(&profile).unwrap();
            std::fs::write(profile.join("user.js"), user_choice).unwrap();
            std::fs::write(profile.join("prefs.js"), user_choice).unwrap();
            let old = format!("{cfg}\ndefaultPref(\"network.trr.mode\", 5);\n");
            write_autoconfig(&install, pointer, &old).unwrap();
            for _ in 0..2 {
                write_autoconfig(&install, pointer, cfg).unwrap();
                write_user_js(&profile, user_js).unwrap();
                let actual = std::fs::read_to_string(install.join("nomad.cfg")).unwrap();
                assert_eq!(actual, cfg);
                assert!(!actual.contains("network.trr.mode"));
                let managed = std::fs::read_to_string(profile.join("user.js")).unwrap();
                assert!(managed.starts_with(user_choice));
                assert_eq!(managed.matches(MARKER_BEGIN).count(), 1);
                assert_eq!(std::fs::read_to_string(profile.join("prefs.js")).unwrap(), user_choice);
            }
        }
    }

    #[test]
    fn waterfox_dns_upgrade_refuses_a_non_file_cfg_target() {
        use crate::browsers::{waterfox::Waterfox, BrowserFamily, Hardening};
        use crate::Arch;
        let Hardening::GeckoProfile {
            autoconfig: Some(pointer),
            cfg: Some(cfg),
            ..
        } = Waterfox::new(Arch::X64).hardening()
        else {
            panic!("missing Waterfox autoconfig");
        };
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("nomad.cfg")).unwrap();
        assert!(write_autoconfig(dir.path(), pointer, cfg).is_err());
        assert!(dir.path().join("nomad.cfg").is_dir());
    }

    #[test]
    fn gecko_autoconfig_keeps_general_extension_security_updates_user_configurable() {
        use crate::browsers::{floorp::Floorp, waterfox::Waterfox};
        use crate::{Arch, BrowserFamily, Hardening};
        for hardening in [
            Floorp::new(Arch::X64).hardening(),
            Waterfox::new(Arch::X64).hardening(),
        ] {
            let Hardening::GeckoProfile { cfg: Some(cfg), .. } = hardening else {
                panic!("expected shared Gecko autoconfig");
            };
            for pref in [
                "extensions.update.enabled",
                "extensions.update.autoUpdateDefault",
            ] {
                assert!(cfg.contains(&format!("defaultPref(\"{pref}\", true);")));
                assert!(!cfg.contains(&format!("lockPref(\"{pref}\",")));
                assert!(!cfg.contains(&format!("defaultPref(\"{pref}\", false);")));
            }
        }
    }

    #[test]
    fn site_fix_preferences_upgrade_all_three_gecko_profiles_without_clobbering_user_content() {
        use crate::browsers::{floorp::Floorp, librewolf::Librewolf, waterfox::Waterfox};
        use crate::{Arch, BrowserFamily, Hardening};

        let profiles = [
            ("floorp", Floorp::new(Arch::X64).hardening()),
            ("librewolf", Librewolf::new(Arch::X64).hardening()),
            ("waterfox", Waterfox::new(Arch::X64).hardening()),
        ];
        for (id, hardening) in profiles {
            let Hardening::GeckoProfile { user_js, .. } = hardening else {
                panic!("{id} must use a Gecko profile");
            };
            let dir = tempfile::tempdir().unwrap();
            let before = "user_pref(\"user.before\", 1);\n";
            let after = "\nuser_pref(\"user.after\", 2);\n";
            let old = "user_pref(\"privacy.trackingprotection.allow_list.baseline.enabled\", false);\n\
                       user_pref(\"privacy.trackingprotection.allow_list.convenience.enabled\", false);";
            std::fs::write(
                dir.path().join("user.js"),
                format!("{before}{MARKER_BEGIN}\n{old}\n{MARKER_END}{after}"),
            )
            .unwrap();
            write_user_js(dir.path(), user_js).unwrap();
            let upgraded = std::fs::read_to_string(dir.path().join("user.js")).unwrap();
            assert!(upgraded.starts_with(before) && upgraded.ends_with(after));
            for pref in [
                // Gecko's first-use migration disables both lists under Strict
                // unless the profile records that the category migration is done.
                "privacy.trackingprotection.allow_list.hasMigratedCategoryPrefs",
                "privacy.trackingprotection.allow_list.baseline.enabled",
                "privacy.trackingprotection.allow_list.convenience.enabled",
            ] {
                let enabled = format!("user_pref(\"{pref}\", true);");
                assert_eq!(upgraded.matches(&enabled).count(), 1, "{id}: {pref}");
                assert!(!upgraded.contains(&format!("user_pref(\"{pref}\", false);")));
            }
            write_user_js(dir.path(), user_js).unwrap();
            assert_eq!(
                std::fs::read_to_string(dir.path().join("user.js")).unwrap(),
                upgraded
            );
        }
    }

    #[test]
    fn write_user_js_creates_fenced_file_on_fresh_profile() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        write_user_js(&profile, "user_pref(\"a\", 1);").unwrap();
        let content = std::fs::read_to_string(profile.join("user.js")).unwrap();
        assert!(content.contains(MARKER_BEGIN));
        assert!(content.contains(MARKER_END));
        assert!(content.contains("user_pref(\"a\", 1);"));
    }

    #[test]
    fn write_user_js_replaces_managed_section_on_second_write() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path();
        write_user_js(profile, "user_pref(\"a\", 1);").unwrap();
        write_user_js(profile, "user_pref(\"b\", 2);").unwrap();
        let content = std::fs::read_to_string(profile.join("user.js")).unwrap();
        assert!(
            !content.contains("user_pref(\"a\", 1);"),
            "old pref must be replaced"
        );
        assert!(content.contains("user_pref(\"b\", 2);"));
        assert_eq!(
            content.matches(MARKER_BEGIN).count(),
            1,
            "exactly one begin marker"
        );
        assert_eq!(
            content.matches(MARKER_END).count(),
            1,
            "exactly one end marker"
        );
    }

    #[test]
    fn write_user_js_preserves_user_content_before_markers() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path();
        let user_pref = "user_pref(\"user.custom\", true);\n";
        std::fs::write(profile.join("user.js"), user_pref).unwrap();
        write_user_js(profile, "user_pref(\"a\", 1);").unwrap();
        let content = std::fs::read_to_string(profile.join("user.js")).unwrap();
        assert!(
            content.contains("user_pref(\"user.custom\", true);"),
            "user content before markers must be preserved"
        );
        assert!(content.contains(MARKER_BEGIN));
    }

    #[test]
    fn write_user_js_preserves_user_content_after_markers() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path();
        let initial = format!(
            "{MARKER_BEGIN}\nuser_pref(\"a\", 1);\n{MARKER_END}\nuser_pref(\"user.after\", true);\n"
        );
        std::fs::write(profile.join("user.js"), &initial).unwrap();
        write_user_js(profile, "user_pref(\"b\", 2);").unwrap();
        let content = std::fs::read_to_string(profile.join("user.js")).unwrap();
        assert!(
            content.contains("user_pref(\"user.after\", true);"),
            "user content after markers must be preserved"
        );
        assert!(
            !content.contains("user_pref(\"a\", 1);"),
            "old managed pref must be replaced"
        );
        assert!(content.contains("user_pref(\"b\", 2);"));
    }

    #[test]
    fn remove_managed_user_js_deletes_file_when_only_managed_block() {
        // A profile whose user.js holds nothing but a Nomad block (the Mullvad
        // regression: an empty payload + WebRTC override) must be removed
        // entirely, leaving no Nomad-written file behind.
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path();
        write_user_js(
            profile,
            "user_pref(\"media.peerconnection.enabled\", false);",
        )
        .unwrap();
        assert!(profile.join("user.js").exists());

        remove_managed_user_js(profile).unwrap();
        assert!(
            !profile.join("user.js").exists(),
            "a user.js containing only the Nomad block must be deleted"
        );
    }

    #[test]
    fn remove_managed_user_js_preserves_user_content() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path();
        std::fs::write(
            profile.join("user.js"),
            "user_pref(\"user.custom\", true);\n",
        )
        .unwrap();
        write_user_js(profile, "user_pref(\"a\", 1);").unwrap();

        remove_managed_user_js(profile).unwrap();
        let content = std::fs::read_to_string(profile.join("user.js")).unwrap();
        assert!(
            content.contains("user_pref(\"user.custom\", true);"),
            "user content must survive removal of the Nomad block"
        );
        assert!(!content.contains(MARKER_BEGIN), "Nomad block must be gone");
        assert!(!content.contains("user_pref(\"a\", 1);"));
    }

    #[test]
    fn remove_managed_user_js_is_a_noop_when_no_file_or_no_block() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path();
        // No file at all.
        remove_managed_user_js(profile).unwrap();
        // A user-owned file with no Nomad markers must be left untouched.
        std::fs::write(profile.join("user.js"), "user_pref(\"only.mine\", 1);\n").unwrap();
        remove_managed_user_js(profile).unwrap();
        assert_eq!(
            std::fs::read_to_string(profile.join("user.js")).unwrap(),
            "user_pref(\"only.mine\", 1);\n"
        );
    }

    #[test]
    fn write_policies_json_creates_distribution_dir_and_file() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("firefox");
        std::fs::create_dir_all(&install).unwrap();
        write_policies_json(&install, r#"{"policies":{}}"#).unwrap();
        let content = std::fs::read_to_string(install.join("distribution/policies.json")).unwrap();
        assert_eq!(content, r#"{"policies":{}}"#);
    }

    #[test]
    fn write_policies_json_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("firefox");
        write_policies_json(&install, r#"{"policies":{"old":1}}"#).unwrap();
        write_policies_json(&install, r#"{"policies":{"new":2}}"#).unwrap();
        let content = std::fs::read_to_string(install.join("distribution/policies.json")).unwrap();
        assert!(content.contains("\"new\":2"));
        assert!(!content.contains("\"old\":1"));
    }

    #[test]
    fn write_chromium_state_seeds_local_state_and_preferences() {
        let dir = tempfile::tempdir().unwrap();
        let udd = dir.path().join("ungoogled-chromium-profile");
        let local_state = r#"{"browser":{"enabled_labs_experiments":["a@1","b@1"]},"dns_over_https":{"mode":"secure","templates":"https://dns.quad9.net/dns-query"}}"#;
        let prefs = r#"{"https_only_mode_enabled":true,"safebrowsing":{"enabled":false}}"#;
        write_chromium_state(&udd, Some(local_state), Some(prefs)).unwrap();

        let written_ls: Value =
            serde_json::from_str(&std::fs::read_to_string(udd.join("Local State")).unwrap())
                .unwrap();
        assert_eq!(written_ls["dns_over_https"]["mode"], "secure");
        let flags = written_ls["browser"]["enabled_labs_experiments"]
            .as_array()
            .unwrap();
        assert!(flags.iter().any(|v| v == "a@1"));
        assert!(flags.iter().any(|v| v == "b@1"));

        let written_prefs: Value = serde_json::from_str(
            &std::fs::read_to_string(udd.join("Default").join("Preferences")).unwrap(),
        )
        .unwrap();
        assert_eq!(written_prefs["https_only_mode_enabled"], true);
        assert_eq!(written_prefs["safebrowsing"]["enabled"], false);
    }

    #[test]
    fn build_initial_preferences_unions_template_and_profile_prefs() {
        // developer_mode (template, MAC-protected) and the profile-pref
        // hardening must both end up in the first-run payload.
        let template = r#"{"extensions":{"ui":{"developer_mode":true}}}"#;
        let prefs = r#"{"https_only_mode_enabled":true,"profile":{"cookie_controls_mode":1}}"#;
        let out = build_initial_preferences(template, prefs).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["extensions"]["ui"]["developer_mode"], true);
        assert_eq!(v["https_only_mode_enabled"], true);
        assert_eq!(v["profile"]["cookie_controls_mode"], 1);
    }

    #[test]
    fn build_initial_preferences_template_wins_on_conflict() {
        let out = build_initial_preferences(r#"{"x":1}"#, r#"{"x":2,"y":3}"#).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["x"], 1,
            "template value must win over the profile-pref overlay"
        );
        assert_eq!(v["y"], 3);
    }

    #[test]
    fn build_initial_preferences_rejects_malformed_payload() {
        assert!(matches!(
            build_initial_preferences("{not json", "{}"),
            Err(BrowserError::Parse(_))
        ));
    }

    #[test]
    fn write_chromium_state_preserves_user_modified_flags_and_prefs() {
        let dir = tempfile::tempdir().unwrap();
        let udd = dir.path().join("profile");
        std::fs::create_dir_all(&udd).unwrap();
        // Pre-existing Local State with a user-modified flag option.
        std::fs::write(
            udd.join("Local State"),
            r#"{"browser":{"enabled_labs_experiments":["a@2","z@1"]},"version":42}"#,
        )
        .unwrap();
        // Pre-existing Preferences: user disabled translate (non-locked — must
        // survive) and flipped https_only to false (locked — must be restored).
        std::fs::create_dir_all(udd.join("Default")).unwrap();
        std::fs::write(
            udd.join("Default").join("Preferences"),
            r#"{"https_only_mode_enabled":false,"translate":{"enabled":true},"user_added":"keep"}"#,
        )
        .unwrap();

        let local_state = r#"{"browser":{"enabled_labs_experiments":["a@1","b@1"]}}"#;
        let prefs = r#"{"https_only_mode_enabled":true,"translate":{"enabled":false},"safebrowsing":{"enabled":false}}"#;
        write_chromium_state(&udd, Some(local_state), Some(prefs)).unwrap();

        let written_ls: Value =
            serde_json::from_str(&std::fs::read_to_string(udd.join("Local State")).unwrap())
                .unwrap();
        let flags: Vec<&str> = written_ls["browser"]["enabled_labs_experiments"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            flags.contains(&"a@2"),
            "user-modified a@2 must be preserved"
        );
        assert!(
            !flags.contains(&"a@1"),
            "default a@1 must not overwrite a@2"
        );
        assert!(flags.contains(&"z@1"), "user-added z@1 must be preserved");
        assert!(
            flags.contains(&"b@1"),
            "missing default b@1 must be appended"
        );
        assert_eq!(written_ls["version"], 42, "unrelated keys must survive");

        let written_prefs: Value = serde_json::from_str(
            &std::fs::read_to_string(udd.join("Default").join("Preferences")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            written_prefs["https_only_mode_enabled"], true,
            "locked scalar must be re-enforced from defaults regardless of user change"
        );
        assert_eq!(
            written_prefs["translate"]["enabled"], true,
            "non-locked scalar must preserve the user-set value"
        );
        assert_eq!(written_prefs["user_added"], "keep");
        assert_eq!(written_prefs["safebrowsing"]["enabled"], false);
    }

    #[test]
    fn locked_scalars_are_re_enforced_after_browser_tampers_with_them() {
        let dir = tempfile::tempdir().unwrap();
        let udd = dir.path().join("profile");
        // Simulate a browser session that re-enabled safe browsing, disabled
        // https-only, and changed the DoH resolver.
        std::fs::create_dir_all(&udd).unwrap();
        std::fs::write(
            udd.join("Local State"),
            r#"{"dns_over_https":{"mode":"off","templates":""}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(udd.join("Default")).unwrap();
        std::fs::write(
            udd.join("Default").join("Preferences"),
            r#"{"safebrowsing":{"enabled":true},"https_only_mode_enabled":false,"privacy_sandbox":{"m1":{"topics_enabled":true,"fledge_enabled":true,"ad_measurement_enabled":true}}}"#,
        )
        .unwrap();

        let local_state =
            r#"{"dns_over_https":{"mode":"secure","templates":"https://dns.quad9.net/dns-query"}}"#;
        let prefs = r#"{"https_only_mode_enabled":true,"safebrowsing":{"enabled":false},"privacy_sandbox":{"m1":{"topics_enabled":false,"fledge_enabled":false,"ad_measurement_enabled":false}}}"#;
        write_chromium_state(&udd, Some(local_state), Some(prefs)).unwrap();

        let ls: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(udd.join("Local State")).unwrap())
                .unwrap();
        assert_eq!(ls["dns_over_https"]["mode"], "secure");
        assert_eq!(
            ls["dns_over_https"]["templates"],
            "https://dns.quad9.net/dns-query"
        );

        let p: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(udd.join("Default").join("Preferences")).unwrap(),
        )
        .unwrap();
        assert_eq!(p["safebrowsing"]["enabled"], false);
        assert_eq!(p["https_only_mode_enabled"], true);
        assert_eq!(p["privacy_sandbox"]["m1"]["topics_enabled"], false);
        assert_eq!(p["privacy_sandbox"]["m1"]["fledge_enabled"], false);
        assert_eq!(p["privacy_sandbox"]["m1"]["ad_measurement_enabled"], false);
    }

    #[test]
    fn write_chromium_state_skips_missing_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let udd = dir.path().join("profile");
        write_chromium_state(&udd, None, None).unwrap();
        assert!(!udd.join("Local State").exists());
        assert!(!udd.join("Default").join("Preferences").exists());
    }

    #[test]
    fn write_chromium_state_rejects_malformed_payload() {
        let dir = tempfile::tempdir().unwrap();
        let udd = dir.path().join("profile");
        let err = write_chromium_state(&udd, Some("{not valid"), None).unwrap_err();
        assert!(matches!(err, BrowserError::Parse(_)));
    }

    #[test]
    fn remove_autoconfig_deletes_the_pair_but_keeps_the_directories() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("firefox");
        write_autoconfig(&install, "pointer\n", "cfg\n").unwrap();
        // A file the browser itself ships alongside ours.
        let vendor = install
            .join("defaults")
            .join("pref")
            .join("channel-prefs.js");
        std::fs::write(&vendor, "vendor").unwrap();

        remove_autoconfig(&install).unwrap();

        assert!(!install.join("defaults/pref/autoconfig.js").exists());
        assert!(!install.join("nomad.cfg").exists());
        assert!(
            vendor.exists(),
            "only our two files are removed by name — never the directory"
        );
        assert!(install.join("defaults").join("pref").is_dir());
    }

    #[test]
    fn remove_autoconfig_is_a_noop_when_never_written() {
        let dir = tempfile::tempdir().unwrap();
        remove_autoconfig(dir.path()).expect("missing files must not be an error");
    }

    #[test]
    fn write_autoconfig_writes_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("firefox");
        std::fs::create_dir_all(&install).unwrap();
        let pointer = "pref(\"general.config.filename\", \"nomad.cfg\");\n";
        let cfg = "null;\nlockPref(\"privacy.resistFingerprinting\", true);\n";
        write_autoconfig(&install, pointer, cfg).unwrap();
        assert_eq!(
            std::fs::read_to_string(install.join("defaults/pref/autoconfig.js")).unwrap(),
            pointer
        );
        assert_eq!(
            std::fs::read_to_string(install.join("nomad.cfg")).unwrap(),
            cfg
        );
    }

    // ── inject_ublock_policy ────────────────────────────────────────────────────

    /// The curated Nomad `policies.json` has no `ExtensionSettings` section, so
    /// the injector must create it (and `policies`) — otherwise uBO is never
    /// installed on Gecko browsers. This is the regression that shipped uBO-less.
    #[test]
    fn inject_ublock_creates_extension_settings_when_absent() {
        let curated = r#"{"policies":{"DisableAppUpdate":true,"DisableTelemetry":true}}"#;
        let temp = tempfile::tempdir().unwrap();
        let xpi = temp.path().join("uBlock0.xpi");
        let out = inject_ublock_policy(curated, &xpi).unwrap();
        let v: Value = serde_json::from_str(&out).expect("output must be valid JSON");

        let ubo = v
            .pointer("/policies/ExtensionSettings/uBlock0@raymondhill.net")
            .expect("uBO entry must be created even when ExtensionSettings was absent");
        assert_eq!(
            ubo.pointer("/installation_mode").and_then(Value::as_str),
            Some("normal_installed")
        );
        let url = ubo
            .pointer("/install_url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            url.starts_with("file:///") && url.ends_with("/uBlock0.xpi"),
            "install_url must be a forward-slashed file:// URL, got: {url}"
        );
        assert!(!url.contains('\\'), "backslashes must be normalised to /");
        // Pre-existing policies must be preserved.
        assert_eq!(
            v.pointer("/policies/DisableAppUpdate")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn inject_ublock_preserves_existing_extension_settings_entries() {
        let with_existing =
            r#"{"policies":{"ExtensionSettings":{"other@ext":{"installation_mode":"blocked"}}}}"#;
        let temp = tempfile::tempdir().unwrap();
        let xpi = temp.path().join("uBlock0.xpi");
        let out = inject_ublock_policy(with_existing, &xpi).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v.pointer("/policies/ExtensionSettings/other@ext/installation_mode")
                .and_then(Value::as_str),
            Some("blocked"),
            "existing ExtensionSettings entries must survive"
        );
        assert!(
            v.pointer("/policies/ExtensionSettings/uBlock0@raymondhill.net")
                .is_some(),
            "uBO must be added alongside existing entries"
        );
    }

    #[test]
    fn inject_ublock_refuses_malformed_or_nonobject_policies() {
        let temp = tempfile::tempdir().unwrap();
        let xpi = temp.path().join("uBlock0.xpi");
        for bad in [
            "this is not json",
            "[]",
            "{}",
            r#"{"policies":false}"#,
            r#"{"policies":{"ExtensionSettings":false}}"#,
        ] {
            assert!(inject_ublock_policy(bad, &xpi).is_err());
        }
    }
}
