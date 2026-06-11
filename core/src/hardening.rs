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
/// user's own prefs with just the managed block. The launch path logs the
/// error and launches without refreshing the block.
pub fn write_user_js(profile_dir: &Path, user_js_content: &str) -> Result<()> {
    std::fs::create_dir_all(profile_dir)?;
    let path = profile_dir.join("user.js");
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
    std::fs::write(&path, new_content)?;
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
/// removed.
pub fn remove_managed_user_js(profile_dir: &Path) -> Result<()> {
    let path = profile_dir.join("user.js");
    let Ok(existing) = std::fs::read_to_string(&path) else {
        return Ok(()); // no file (or unreadable) — nothing to remove
    };
    if !existing.contains(MARKER_BEGIN) {
        return Ok(()); // no Nomad block — leave the user's own file untouched
    }
    let stripped = strip_fenced(&existing);
    if stripped.trim().is_empty() {
        std::fs::remove_file(&path)?;
    } else {
        std::fs::write(&path, stripped)?;
    }
    Ok(())
}

/// Writes `policies_content` into `<install_dir>/distribution/policies.json`.
///
/// Creates the `distribution/` subdirectory if it does not exist. Called at
/// install time on the stage directory, so the file is swapped in atomically.
///
/// # Errors
/// Returns [`BrowserError::Io`] if the directory or file cannot be written.
pub fn write_policies_json(install_dir: &Path, policies_content: &str) -> Result<()> {
    let dist = install_dir.join("distribution");
    std::fs::create_dir_all(&dist)?;
    std::fs::write(dist.join("policies.json"), policies_content)?;
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
    std::fs::create_dir_all(&pref_dir)?;
    std::fs::write(pref_dir.join("autoconfig.js"), autoconfig_content)?;
    std::fs::write(install_dir.join("nomad.cfg"), cfg_content)?;
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
///   value via the browser UI, we do not roll it back.
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
        std::fs::create_dir_all(&default_dir)?;
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
    std::fs::create_dir_all(install_dir)?;
    std::fs::write(&path, payload)?;
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
/// intermediate objects.  Does nothing when a non-final path segment is not an
/// object (i.e. a scalar blocks the descent).
fn set_by_path(root: &mut Value, path: &str, val: Value) {
    let mut keys: Vec<&str> = path.split('.').collect();
    let Some(last) = keys.pop() else { return };
    let mut cur = root;
    for key in keys {
        let Value::Object(m) = cur else { return };
        cur = m.entry(key).or_insert_with(|| Value::Object(Map::new()));
    }
    if let Value::Object(m) = cur {
        m.insert(last.to_owned(), val);
    }
}

/// Reads `path` (treating missing or empty files as an empty object), parses
/// `defaults_json`, merges with `merge_value` semantics, then re-applies all
/// entries from [`LOCKED_SCALAR_PATHS`] from the defaults so that
/// privacy-critical settings cannot be silently re-enabled by the browser.
/// Writes the result back as compact JSON (Chromium also writes prefs without
/// indentation).
fn merge_json_file(path: &Path, defaults_json: &str) -> Result<()> {
    let defaults: Value = serde_json::from_str(defaults_json)
        .map_err(|e| BrowserError::Parse(format!("invalid Chromium hardening payload: {e}")))?;
    let existing: Value = match std::fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => serde_json::from_str(&s).map_err(|e| {
            BrowserError::Parse(format!(
                "could not parse existing JSON at {}: {e}",
                path.display()
            ))
        })?,
        _ => Value::Object(Map::new()),
    };
    let mut merged = merge_value(existing, defaults.clone());
    for &locked in LOCKED_SCALAR_PATHS {
        if let Some(enforced) = get_by_path(&defaults, locked) {
            set_by_path(&mut merged, locked, enforced.clone());
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(&merged)
        .map_err(|e| BrowserError::Parse(format!("could not serialize merged JSON: {e}")))?;
    std::fs::write(path, bytes)?;
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

/// Injects (or replaces) the `uBlock0@raymondhill.net` entry in the
/// `ExtensionSettings` section of `policies_json` with a `file://` URL
/// pointing at `xpi_path`, so Firefox installs the extension without
/// contacting AMO.
///
/// The `policies` and `ExtensionSettings` objects are created if absent — the
/// curated Nomad `policies.json` does not declare an `ExtensionSettings`
/// section, so the entry must be added from scratch rather than merged into an
/// existing one.
///
/// Returns the modified JSON string on success, or the original unchanged
/// string if the document is not a JSON object (e.g. parse failure).
pub(crate) fn inject_ublock_policy(policies_json: &str, xpi_path: &Path) -> String {
    let url = format!("file:///{}", xpi_path.to_string_lossy().replace('\\', "/"));
    let Ok(mut root) = serde_json::from_str::<Value>(policies_json) else {
        return policies_json.to_owned();
    };
    // The document root must be an object to host the "policies" key.
    let Some(root_obj) = root.as_object_mut() else {
        return policies_json.to_owned();
    };
    // Ensure "policies" -> "ExtensionSettings" exist as objects, creating each
    // if the curated payload did not declare it.
    let policies = root_obj.entry("policies").or_insert_with(|| json!({}));
    let Some(policies_obj) = policies.as_object_mut() else {
        return policies_json.to_owned();
    };
    let ext = policies_obj
        .entry("ExtensionSettings")
        .or_insert_with(|| json!({}));
    let Some(ext_settings) = ext.as_object_mut() else {
        return policies_json.to_owned();
    };
    ext_settings.insert(
        "uBlock0@raymondhill.net".to_owned(),
        json!({
            "install_url": url,
            "installation_mode": "normal_installed",
            "private_browsing": true
        }),
    );
    serde_json::to_string_pretty(&root).unwrap_or_else(|_| policies_json.to_owned())
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
        let xpi = Path::new(r"C:\Portables\Floorp\Nomad\Gecko-extensions\uBlock0.xpi");
        let out = inject_ublock_policy(curated, xpi);
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
        let xpi = Path::new("/tmp/uBlock0.xpi");
        let out = inject_ublock_policy(with_existing, xpi);
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
    fn inject_ublock_returns_original_on_malformed_json() {
        let bad = "this is not json";
        let out = inject_ublock_policy(bad, Path::new("/tmp/uBlock0.xpi"));
        assert_eq!(out, bad, "malformed input must be returned unchanged");
    }
}
