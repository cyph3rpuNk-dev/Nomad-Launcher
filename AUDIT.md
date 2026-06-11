# Privacy Engineering Audit Report

**Project:** Nomad Portable — Windows Privacy Browser Manager  
**Browsers:** Ungoogled-Chromium · Helium · Firefox · Firefox ESR · Floorp · Waterfox  
**Auditor:** Claude Sonnet 4.6 (automated multi-session audit)  
**Date:** 2026-05-19  
**Scope:** Portable trace audit · Hardening correctness · Adversarial pen test · Functional regression · Zero-trace exit · Update mechanism privacy

---

## 1. Executive Summary

| | |
|---|---|
| **Portable-First Compliance** | ✅ PASS — all browser families |
| **Privacy Hardening Quality** | HIGH (Chromium), HIGH (Firefox/Floorp), MEDIUM (Waterfox — integrity gap) |

**Finding Counts**

| Severity | Open | Resolved | Total |
|---|---|---|---|
| CRITICAL | 0 | 3 | 3 |
| HIGH | 0 | 4 | 4 |
| MEDIUM | 1 | 6 | 7 |
| LOW | 1 | 3 | 4 |
| **Total** | **1** | **17** | **18** |

**Top Open Item**

1. **[LOW]** Helium key rotation: the Helium GPG key slot is empty (no Imput signing key exists). If Imput publishes an official key in future, `core/keys/helium.asc` must be updated. (LOW-03)

---

## 2. Browser-by-Browser Privacy Posture

> **Trust-boundary note — GitHub-digest SHA-256 (ungoogled-chromium, Helium, Floorp, LibreWolf).**
> For the browsers with no upstream GPG key, the SHA-256 used for integrity comes from GitHub's
> release-asset `digest` field — computed by GitHub's infrastructure, **not** signed by the upstream
> developer. It pins the bytes to *what GitHub serves* (defeating a CDN/mirror swap or an accidental
> re-upload) but not an attacker who compromises the GitHub release itself, who could replace the
> binary and let GitHub recompute the digest. This is the same inherent limitation called out for
> Waterfox's SHA-512 in CRIT-01 — an accepted consequence of the upstream publishing no signing key,
> not a defect to fix. Firefox/ESR and Mullvad (GPG) and Bitwarden (Authenticode signer pin) are
> unaffected.

### 2.1 Ungoogled-Chromium

**Baseline Privacy:** Google services stripped at compile time; no sync, Safe Browsing, auto-updates, or crash reporting. Best Chromium baseline available publicly.

**Hardening Applied by Nomad:** 17 launch flags covering:
- Portability: `--user-data-dir=<drive>\ungoogled-chromium-profile`, `--disable-machine-id`, `--disable-encryption`
- Noise reduction: `--no-first-run`, `--disable-sync`, `--disable-background-networking`, `--disable-breakpad`, `--disable-component-update`, `--disable-features=JumpList`
- Fingerprinting: `--fingerprinting-canvas-image-data-noise/measuretext-noise/client-rects-noise`, `--enable-features=RemoveClientHints,SpoofWebGLInfo`
- Network: `--no-pings`, `--disable-grease-tls`, `--disable-search-engine-collection`, `--force-punycode-hostnames`, `--webrtc-ip-handling-policy=default_public_interface_only`

**Gaps Remaining:** No incognito-by-default; GPUCache accumulates in profile; WER ReportQueue not scrubbed; WebRTC exposes real public IP.

**Portability Status:** ✅ PASS  
**Integrity Verification:** SHA-256 from GitHub asset digest ✅ | GPG: ❌ (upstream publishes none)

---

### 2.2 Helium

**Baseline Privacy:** ungoogled-chromium fork by Imput with additional privacy patches.

**Hardening Applied:** Identical 17-flag set as ungoogled-chromium. Profile: `--user-data-dir=<drive>\helium-profile`.

**GPG Key:** EMPTY — `core/keys/helium.asc` is now empty. The key previously embedded (`968479A1AFF927E37D1A566BB5690EEEBB952194`) was identified as GitHub's platform web-flow commit-signing key, not an Imput developer key. That key cannot produce detached signatures for release asset files and was therefore wrong for its intended purpose. No Imput-specific signing key exists in any official channel.

**Gaps Remaining:** Same profile/session data and WER gaps as ungoogled-chromium. Lower public scrutiny than Mozilla or ungoogled-software projects. No developer signing key available.

**Portability Status:** ✅ PASS  
**Integrity Verification:** SHA-256 from GitHub asset digest ✅ | GPG: ❌ (no Imput developer signing key — key slot emptied)

---

### 2.3 Firefox (Stable and ESR)

**Baseline Privacy:** Telemetry, Pocket, Safe Browsing, Normandy, and Activity Stream enabled by default. Requires aggressive hardening.

**Hardening Applied:**
- `user.js`: 104 `user_pref` entries (telemetry, geolocation, speculative connections, WebRTC, tracking protection, HTTPS-only, fingerprinting, Safe Browsing, captive portal, Activity Stream, DoH, cryptomining, taskbar, disk cache)
- `policies.json`: 15 machine-level policy keys, written at both install time and every launch
- Launch: `--no-remote`, `MOZ_CRASHREPORTER_DISABLE=1`
- GPG chain-of-trust: SHA256SUMS manifest GPG-verified against embedded Mozilla Software Releases key (`core/keys/firefox.asc`, 441 lines, latest signing subkey expires 2027-03-13). Package SHA-256 parsed from verified manifest.

**Gaps Remaining:** Safe Browsing disabled (documented trade-off).

**Portability Status:** ✅ PASS — NSIS installer traces scrubbed post-install (CRIT-02)  
**Integrity Verification:** ✅ STRONG — GPG manifest verification + per-package SHA-256

---

### 2.4 Floorp

**Baseline Privacy:** Firefox-based browser from Ablaze (Japan). Privacy-focused fork with additional anti-tracking built in.

**Hardening Applied:** Identical to Firefox — same `user.js` (104 prefs), same `policies.json` (15 keys), `--no-remote`, `MOZ_CRASHREPORTER_DISABLE=1`.

**Integrity:** GitHub-recorded SHA-256 digest per release asset. No GPG key published upstream.

**Gaps Remaining:** Safe Browsing disabled (documented trade-off).

**Portability Status:** ✅ PASS — NSIS installer traces scrubbed post-install (CRIT-02)  
**Integrity Verification:** PARTIAL — SHA-256 from GitHub digest ✅ | GPG: ❌ (upstream publishes none)

---

### 2.5 Waterfox

**Baseline Privacy:** Firefox ESR 115 fork (BrowserWorks). Some privacy improvements over stock Firefox ESR.

**Hardening Applied:**
- `user.js`: Dedicated `waterfox/user.js` (108 lines) with ESR-115-correct fingerprinting pref (`privacy.resistFingerprinting`, NOT the Firefox 119+ `privacy.fingerprintingProtection`)
- `policies.json`: Shared with Firefox (15 keys)
- Launch: `--no-remote`, `MOZ_CRASHREPORTER_DISABLE=1`

**Gaps Remaining:**
- ESR 115 base will reach end-of-life; `privacy.resistFingerprinting` is deprecated upstream

**Portability Status:** ✅ PASS — NSIS installer traces scrubbed post-install (CRIT-02)  
**Integrity Verification:** ✅ SHA-512 fetched from CDN beside each installer (`Waterfox Setup <ver>.exe.sha512`); graceful warn if unavailable

---

### 2.6 Bitwarden (desktop password manager — not a browser)

**Threat model differs from the browsers.** Bitwarden is a credential vault, not a web client; the relevant surface is vault-at-rest, the supply chain of the binary, patch latency, and host traces — *not* fingerprinting or tracker blocking. The browser-extension form is deliberately avoided (Bitwarden's own docs note it raises browser-fingerprint uniqueness, and a DOM clickjacking class was shown at DEF CON 33); the desktop app sidesteps both.

**Baseline Privacy:** Zero-knowledge, end-to-end-encrypted vault (Argon2id/PBKDF2 KDF). Cryptography is identical whether installed or portable — `data.json` is encrypted at rest with a key derived from the master password regardless of install method.

**Hardening / portability applied by Nomad:**
- Wraps the **official portable `.exe`** (not the APPX, which is inert unpacked; not built from source). Selected from `bitwarden/clients` by newest stable `desktop-v…` tag.
- `BITWARDEN_APPDATA_DIR=App\Data` redirects all userData/vault beside the binary (no `%APPDATA%\Bitwarden` leak — addresses the known portable-build log-leak issue). `ELECTRON_NO_UPDATER=1` makes Nomad the sole updater, which **eliminates portable Bitwarden's single biggest weakness: patch latency** (a portable copy otherwise never auto-updates and silently runs unpatched).
- Vault carried across updates by `preserve_state_across_update` (copy-not-move, so a failed swap never risks the live vault).
- Post-exit cleanup watcher runs (engine-independent): scrubs `%TEMP%` (the portable self-extraction), Recent items, jump lists, WER, and Prefetch (the Mozilla/Mullvad scrubs are harmless no-ops).

**Integrity Verification:** ✅ SHA-256 from GitHub asset digest **+ Authenticode signer pin** (`WinVerifyTrust` with whole-chain revocation; signer subject must equal `Bitwarden Inc.` — tightened from a substring match 2026-06-10). No GPG key is published upstream; Authenticode is the publisher anchor (§9). The cross-product `releases/latest` hazard — which initially resolved a `browser-v…` extension release with no portable `.exe` — was fixed by filtering for `desktop-v…`.

**Gaps Remaining:**
- **No Windows Hello** (biometric unlock is installer-only). Master-password unlock only — a smaller unlock surface, but pair with a short vault timeout on shared machines.
- **Vault on removable media** travels with the stick; the encrypted blob is brute-forceable offline if the file is obtained (the KDF is the protection, same as any Bitwarden copy). Mitigate with an encrypted volume (BitLocker To Go / VeraCrypt) and disabling "stay logged in."
- `preserve_state_across_update` copies the whole `Data\` incl. regenerable caches (minor; updates are monthly).

**Portability Status:** ✅ PASS — verified end-to-end: no writes to `%APPDATA%\Bitwarden`, `%LOCALAPPDATA%`, `%PROGRAMDATA%`, or registry during normal operation; all state in `App\Data` and `Nomad\`.

---

## 3. Critical Findings

### CRIT-01 — Waterfox: Zero Cryptographic Integrity on Downloaded Binary

| | |
|---|---|
| **Severity** | CRITICAL |
| **Component** | `core/src/browsers/waterfox.rs`, `core/src/updater.rs` |
| **Status** | ✅ RESOLVED |

**Resolution (2026-05-19):** The Waterfox CDN publishes a SHA-512 checksum file beside each installer at `<cdn_base>/<ver>/<arch>/Waterfox%20Setup%20<ver>.exe.sha512`. This was confirmed by inspection of the live CDN for version 6.6.13.

Changes applied:
- `VersionInfo` gained `sha512: Option<String>` field (all other browsers set it to `None`)
- `core/src/gpg.rs` gained a `sha512` module (`sha2::Sha512`) matching the SHA-256 module API
- `verify_package()` now checks `sha256` first, falls back to `sha512`, warns only when both are absent
- `fetch_latest_version()` derives the `.sha512` URL, fetches and validates the 128-char hex digest; logs WARN and sets `sha512 = None` on CDN unavailability (non-fatal)
- `fetch_sha512()` helper validates token count (exactly 128 hex chars); rejects malformed responses
- `Waterfox::cdn_base` is overridable for tests; `fetch_latest_constructs_cdn_url_and_fetches_sha512` verifies end-to-end flow against a mock server

Waterfox still has no GPG detached signature. The CDN-provided SHA-512 protects against in-transit corruption and CDN-level cache poisoning, but does not protect against a full CDN compromise where both the binary and the checksum file are replaced simultaneously. Monitoring the CDN for unexpected binary changes remains advisable.

---

### CRIT-02 — NSIS Installers Write System Traces Outside install_dir

| | |
|---|---|
| **Severity** | CRITICAL |
| **Browsers** | Firefox, Firefox ESR, Floorp, Waterfox |
| **Component** | `core/src/extract.rs`, `core/src/browsers/firefox.rs`, `waterfox.rs`, `floorp.rs` |
| **Status** | ✅ RESOLVED |

**Finding:** Firefox, Waterfox, and Floorp are distributed exclusively as NSIS installers — Mozilla, BrowserWorks, and Ablaze publish no portable ZIPs for Windows. When *run* in silent mode (`/S /D=<install_dir>`) the installers create `HKCU`/`HKLM\Software\Mozilla`, Add/Remove Programs entries, Start Menu and Desktop shortcuts, and `%PROGRAMDATA%`/`%LOCALAPPDATA%` directories. On admin accounts with permissive UAC the installer also bypasses `__COMPAT_LAYER=RunAsInvoker`, ignores `/D=`, and falls back to its hardcoded `C:\Program Files (x86)\Mozilla Firefox` path. The user confirmed all of this in production.

**Resolution attempt 1 (rejected):** "Install then scrub" via `scrub_nsis_install_traces()`. Failed in production because (a) it only checked `HKCU`, missing `HKLM` entries written by elevated installers; (b) the installer's `Program Files` fallback path was outside our scrub scope; (c) the model is intrinsically racy with an installer that can launch the browser automatically.

**Resolution (2026-05-19):** **Never run the installer.** Extract it as an archive instead.

* `core/payloads/7zip/7z.exe` + `7z.dll` (7-Zip 24.09 x64, LGPL) are embedded into each Gecko launcher via `include_bytes!`. At extraction time `stage_seven_zip()` writes them to a unique temp dir; `extract_nsis_with_7zip(installer, install_dir, marker_exe)` runs `7z x` against the NSIS executable, then `find_marker_dir` + `flatten_into` reposition the browser tree so `<install_dir>/<browser>.exe` lands at the root.
* `extract_nsis_with_7zip` also strips NSIS metadata leftovers (`$PLUGINSDIR`, `[NSIS].nsi`, `uninstall.exe`).
* Firefox, Firefox ESR, Floorp, and Waterfox all call `extract_nsis_with_7zip` from their `extract()` method — the installer process never starts.
* Helium and ungoogled-chromium continue to use `extract_zip` (they ship portable ZIPs); thanks to Rust's dead-code elimination, their launcher binaries do **not** embed the 7-Zip bytes (~9 MB vs ~12 MB for Gecko launchers).
* An end-to-end smoke test (`Firefox Setup 138.0.exe`, 68.8 MB) confirms zero new traces in `Program Files`, `ProgramData\Mozilla`, `%LOCALAPPDATA%\Mozilla`, Start Menu, or `HKCU\Software\Mozilla`.

The previous `scrub_nsis_install_traces` and `run_nsis_installer` functions were removed in this session.

---

## 4. High Findings

### HIGH-01 — sanitizeOnShutdown Not Configured for Any Gecko Browser

| | |
|---|---|
| **Severity** | HIGH |
| **Browsers** | Firefox, Firefox ESR, Floorp, Waterfox |
| **Component** | `core/payloads/firefox/user.js`, `core/payloads/waterfox/user.js` |
| **Status** | ✅ RESOLVED |

**Resolution (2026-05-19):** Both `user.js` payloads now include a `sanitizeOnShutdown` section. Cache, downloads, form data, sessions, and offline app storage are cleared on exit. Cookies and history are preserved to avoid disrupting sessions and workflow.

`core/payloads/firefox/user.js` also sets the `privacy.clearOnShutdown_v2.*` variants introduced in Firefox 128 to cover all active release trains. `core/payloads/waterfox/user.js` sets only the legacy prefs (Waterfox is ESR 115 and does not have the v2 schema).

**Remaining gap:** `[hardening] sanitize_on_shutdown` is not yet exposed as a `nomad.toml` config key (LOW-02). Users who want to disable sanitization must edit the managed `user.js` section directly.

---

### HIGH-02 — Windows Prefetch Exposes Portable Drive Path

| | |
|---|---|
| **Severity** | HIGH |
| **Component** | `core/src/lib.rs`, `core/src/config.rs` |
| **Status** | ✅ RESOLVED — elevation-based scrub implemented |

`C:\Windows\Prefetch\` creates entries for `chrome.exe`, `firefox.exe`, `floorp.exe`, `waterfox.exe`, `nomad-*.exe` (launcher and watcher, two entries per launch). Each entry contains the full path to the executable, last-run timestamp, and run count. Deletion requires an elevated token.

**Resolution (2026-05-19):**
- Documentation: `DEFAULT_NOMAD_TOML` includes a `PRIVACY NOTE` comment block; the "Launching…" status line shows a secondary Prefetch notice on every launch.
- Automated scrub: After the browser exits the cleanup watcher calls `scrub_prefetch()`, which scans `C:\Windows\Prefetch\` for `.pf` files whose names start with any of 10 browser/launcher tokens and deletes them. If any deletion returns `PermissionDenied`, `elevate_for_prefetch_scrub()` re-spawns the same launcher binary with `--nomad-scrub-prefetch` and the `ShellExecuteW("runas")` verb, triggering one UAC consent dialog. The elevated sub-process then deletes all matching entries — including its own Prefetch entry — and exits silently.

**Tokens scrubbed:** `CHROME.EXE`, `FIREFOX.EXE`, `FLOORP.EXE`, `WATERFOX.EXE`, `NOMAD-FIREFOX.EXE`, `NOMAD-FIREFOX-ESR.EXE`, `NOMAD-FLOORP.EXE`, `NOMAD-WATERFOX.EXE`, `NOMAD-HELIUM.EXE`, `NOMAD-UNGOOGLED-CHROMIUM.EXE`.

**Remaining note:** To minimise exposure while on a machine where UAC is disabled, keep launcher paths short and non-identifying (e.g. `E:\nom\` rather than `E:\MyPortableApps\PrivacyBrowsers\`).

---

### HIGH-03 — WER ReportQueue Not Scrubbed

| | |
|---|---|
| **Severity** | HIGH |
| **Component** | `core/src/lib.rs:scrub_wer()` |
| **Status** | ✅ RESOLVED |

**Resolution (2026-05-19):** `scrub_wer()` now additionally scans `%ProgramData%\Microsoft\Windows\WER\ReportQueue\` and `ReportArchive\`. Report subdirectories whose names contain a browser executable token (`chrome.exe`, `firefox.exe`, `floorp.exe`, `waterfox.exe`) are removed with `remove_dir_all`. Access errors per-entry are ignored; the loop continues to the next entry. Count is logged at INFO level when non-zero. The existing `%LOCALAPPDATA%\CrashDumps` flat-file scrub is unchanged.

---

### HIGH-04 — installs.ini Cleanup Incomplete for Floorp

| | |
|---|---|
| **Severity** | HIGH |
| **Component** | `core/src/lib.rs:scrub_mozilla_installs_ini()` |
| **Status** | ✅ RESOLVED |

**Resolution (2026-05-19):**
1. `%APPDATA%\Floorp\installs.ini` added as a third candidate path in `scrub_mozilla_installs_ini()`.
2. `scrub_mozilla_installs_ini()` is now called at launch start in both `do_launch()` (the normal path) and the fallback "LaunchAnyway" branch, before `launch_command().spawn()`. This ensures traces from any previous crashed session are removed before the browser starts, not only after it exits.

---

## 5. Medium Findings

### MED-01 — GitHub API Unauthenticated — Shared Rate Limit

| | |
|---|---|
| **Severity** | MEDIUM |
| **Browsers** | ungoogled-chromium, Helium, Floorp, Waterfox |
| **Status** | ✅ RESOLVED |

**Resolution (2026-05-19):** `core/src/version_cache.rs` — new `VersionCache` struct serialised to `nomad-version-cache.toml` beside the launcher, holding the full `VersionInfo` snapshot plus a `fetched_at` Unix timestamp. TTL is 4 hours (`CACHE_TTL_SECS`). `update_check_phase()` loads the cache at startup; if fresh it skips the network call entirely. After a successful API call the cache is written atomically. HTTP 403 from GitHub is classified as `BrowserError::Offline` by `map_network_err` and auto-launches the installed version rather than showing an error screen. 6 unit tests cover round-trip TOML, field preservation, TTL freshness/staleness, missing file, and malformed TOML.

---

### MED-02 — Offline Fallback Requires Manual User Intervention

| | |
|---|---|
| **Severity** | MEDIUM |
| **Component** | `core/src/lib.rs` (handle_error, wait_for_pipeline_action) |
| **Status** | ✅ RESOLVED |

**Resolution (2026-05-19):** `BrowserError::Offline(String)` variant added to the error enum. `map_network_err()` in `core/src/browsers/github.rs` classifies `is_connect()` / `is_timeout()` as `Offline`; HTTP 403 also maps to `Offline` with a rate-limit message. `update_check_phase()` now matches `BrowserError::Offline` separately: if an installed version exists it logs WARN and returns `CheckPhaseResult::Launch` (silent auto-launch). Only when no version is installed does it surface the error. All three network paths (GitHub, Firefox/Floorp, ungoogled-chromium) apply the same classifier. Tests added in `firefox.rs`, `ungoogled.rs`, and `github.rs` to verify that connection-refused and HTTP 403 both produce `BrowserError::Offline`.

---

### MED-03 — Shell History and Recent Items Not Scrubbed

| | |
|---|---|
| **Severity** | MEDIUM |
| **Component** | `core/src/lib.rs` (post-exit scrub) |
| **Status** | ✅ RESOLVED |

**Partial resolution (2026-05-19):** `scrub_shell_recent()` added — LNK files in `%APPDATA%\Microsoft\Windows\Recent\` targeting the portable drive are removed. See earlier sessions.

**Full resolution (2026-05-21):** `scrub_automatic_destinations_dir()` / `scrub_automatic_destinations()` added to `lib.rs` and called from `handle_cleanup_flag()` immediately after `scrub_shell_recent()`.

AutomaticDestinations files (`*.automaticDestinations-ms`) are OLE Compound Document archives. Rather than implementing a full CFB/OLE parser, the scrubber reads each file's raw bytes and searches for the portable drive root encoded as UTF-16LE (e.g. `E:\` → `45 00 3A 00 5C 00`). This byte pattern appears verbatim inside the OLE stream data sectors containing the embedded LNK records. A file is deleted only when the portable drive path is positively identified in its bytes — files that reference other drives are never touched.

2 unit tests added: `scrub_automatic_destinations_dir_removes_matching_files` (verifies matching file deleted, non-matching survives, wrong extension untouched) and `scrub_automatic_destinations_dir_ignores_missing_directory` (no panic on absent directory).

**Remaining accepted limitation:**
- Shell bags (`HKCU\...\BagMRU`, `HKCU\...\Bags`) — registry key scrubbing not implemented.

---

### MED-04 — Windows Thumbnail Cache Not Scrubbed

| | |
|---|---|
| **Severity** | MEDIUM |
| **Status** | RESOLVED — opt-in via `scrub_thumbnail_cache = true` |

`%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db` and `iconcache_*.db` may record previews and paths of files downloaded to the portable drive.

**Fix:** `[hardening] scrub_thumbnail_cache` in `nomad.toml` (default `false`). When enabled, the cleanup watcher terminates all Explorer processes after the browser exits, deletes `thumbcache_*.db` and `iconcache_*.db`, and immediately restarts Explorer. The taskbar is absent for roughly one second. Disabled by default so casual users are not surprised; set to `true` on shared/forensics-sensitive machines.

---

### MED-05 — nomad.log Accumulates Sensitive Metadata

| | |
|---|---|
| **Severity** | MEDIUM |
| **Component** | `core/src/lib.rs:init_tracing()` |
| **Status** | ✅ RESOLVED |

**Resolution (2026-05-19):**
- Default log level lowered from `info` to `warn`. The `NOMAD_LOG` env var still overrides.
- `rotate_log()` helper added: when `nomad.log` reaches 512 KB, it is renamed to `nomad.log.1` (overwriting any prior backup) before a fresh log is opened. Maximum disk usage: ~1 MB.
- Rotation is atomic from the OS perspective (rename then create) — no partial-write window.

**Remaining gap:** `[logging] max_size_kb` is not yet a `nomad.toml` config key. Log level must be overridden via env var.

---

### MED-06 — WebRTC IP Leakage Partially Mitigated

| | |
|---|---|
| **Severity** | MEDIUM |
| **Browsers** | All |
| **Status** | ✅ RESOLVED — opt-in full disable added |

**Resolution (2026-05-21):** `[hardening] disable_webrtc = false` added to `HardeningConfig` and `DEFAULT_NOMAD_TOML`.

When set to `true`:
- **Chromium** (ungoogled-chromium, Helium): appends `--webrtc-ip-handling-policy=disable_non_proxied_udp` to launch args, superseding the existing partial-mitigation flag (Chromium honours the last occurrence).
- **Gecko** (Firefox, Floorp, Waterfox): appends `user_pref("media.peerconnection.enabled", false);` to the Nomad-managed `user.js` block.

`DEFAULT_NOMAD_TOML` includes a `WEBRTC NOTE` comment block explaining the trade-off and the `disable_webrtc = false` key so users on record in their config file.

Default remains `false` — enabling it breaks all WebRTC video/audio calls (Google Meet, Teams, Discord video, Zoom in-browser). Users who route all traffic through a VPN or need complete IP leak prevention can set it to `true`.

---

### MED-07 — Chromium Profile-Pref Hardening Inactive on First Run

| | |
|---|---|
| **Severity** | MEDIUM |
| **Browsers** | Ungoogled-Chromium · Helium |
| **Status** | ✅ RESOLVED — profile prefs routed through `initial_preferences` |

**Issue:** The `preferences.json` hardening layer (HTTPS-Only mode, Do Not Track, network-prediction off, third-party-cookie block, the Sensors content-setting block, `canMakePayment`/Media Router off, search-suggest/translate/alternate-error-pages off, Privacy Sandbox m1) is seeded into `<user-data-dir>/Default/Preferences` before launch. But Chromium's **first-run pipeline regenerates `Default/Preferences` from the `initial_preferences` template**, discarding Nomad's pre-seeded file. Result: on a brand-new profile, **none of these profile prefs apply during the entire first browsing session** — HTTPS-Only mode, third-party-cookie blocking, and the sensors block are all off on first run — and only take effect from the second launch (when `--no-first-run` is set and Chromium loads the seeded file normally). `Local State` (DoH, `chrome://flags`) and the command-line flags were unaffected. Confirmed by runtime test: a fresh-profile run 1 had every `Default/Preferences` key absent; run 2 had them all present.

**Resolution (2026-06-02):** `prepare_launch` (ungoogled-chromium and Helium) now merges `preferences.json` into the `initial_preferences` payload via the new `hardening::build_initial_preferences()` — routing the profile prefs through the one seed path Chromium honours on first profile creation (the same path that already carries the MAC-protected `extensions.ui.developer_mode`). `preferences.json` stays the single source of truth; `write_chromium_state` still maintains established profiles and re-applies `LOCKED_SCALAR_PATHS`. Verified end-to-end against ungoogled-chromium: a genuine first run now binds HTTPS-Only, DNT, network-prediction, cookie-controls, and the sensors block, with `developer_mode` preserved. Behavioral CDP check confirmed runtime effect — `navigator.doNotTrack === "1"` and `navigator.permissions.query({name:'accelerometer'})` returns `"denied"` (sensors blocked) while `geolocation` stays `"prompt"` (not a blanket block). Guarded by `merged_initial_preferences_carry_developer_mode_and_profile_hardening` and the `build_initial_preferences_*` unit tests.

---

## 6. Low Findings

### LOW-01 — No Session Isolation (Incognito Not Default for Chromium)

| | |
|---|---|
| **Status** | ✅ RESOLVED |

**Resolution (2026-05-19):** `[launch] incognito = false` added to `LaunchConfig` and `DEFAULT_NOMAD_TOML`. When set to `true`, `build_launch_args()` appends `--incognito` to Chromium-engine browsers (`Engine::Chromium` check). Has no effect on Gecko-engine browsers (Firefox, Floorp, Waterfox). Defaults to `false` to preserve existing session-continuity behaviour; users who want full session isolation can set `incognito = true` in their `nomad.toml`.

### LOW-02 — sanitize_on_shutdown Not Exposed in Config Schema

| | |
|---|---|
| **Status** | ✅ RESOLVED |

**Resolution (2026-05-19):** `[hardening] sanitize_on_shutdown = true` added to `HardeningConfig` and `DEFAULT_NOMAD_TOML`. When set to `false`, `do_launch()` appends `user_pref("privacy.sanitize.sanitizeOnShutdown", false);` after the base `user.js` block in the Nomad-managed fenced section — this single override disables the master clear-on-exit switch without requiring users to edit the embedded payload file. Defaults to `true` (sanitize enabled) which preserves the HIGH-01 resolution.

### LOW-03 — Helium Update Source Provenance

| | |
|---|---|
| **Status** | ⚠️ UPDATED — GPG verification removed; SHA-256 only |

**Finding updated (2026-05-19):** GPG key verification for Helium has been removed. The key previously embedded in `core/keys/helium.asc` (`968479A1AFF927E37D1A566BB5690EEEBB952194`) was GitHub's platform web-flow commit-signing key — a platform-wide infrastructure key, not an Imput developer key. GitHub's web-flow private key signs git commits made through the GitHub web UI; it cannot produce detached signatures for release asset ZIP files. The key was therefore wrong for asset verification and has been emptied.

Helium integrity is now SHA-256-only (from the GitHub-recorded asset `digest` field), matching ungoogled-chromium and Floorp. This is weaker than Mozilla's GPG-signed manifest chain (Firefox/Waterfox). The `imputnet/helium-windows` repository publishes no developer signing key. **Monitor for a future Imput signing key announcement; if one is published, populate `core/keys/helium.asc` and re-enable the verification path.**

### LOW-04 — Safe Browsing Disabled Without In-App Warning

| | |
|---|---|
| **Status** | ✅ RESOLVED |

**Resolution (2026-05-19):** Two documentation changes:
1. `DEFAULT_NOMAD_TOML` includes a `SECURITY NOTE` comment block explaining that Safe Browsing is disabled by the hardening profile, removing browser-level phishing/malware protection, and recommending a DNS block list as a substitute.
2. `do_launch()` emits a `tracing::warn!` on every Gecko browser launch when hardening is enabled, logged to `nomad.log`: _"Safe Browsing disabled by hardening profile (privacy trade-off); no browser-level phishing/malware protection — use a DNS block list as substitute"_. This makes the trade-off visible in the log without requiring a persistent UI banner.

---

## 7. Portable-First Compliance Summary

### 7.1 Windows Artifact Trace Analysis

| Artifact | Cleaned? | Notes |
|---|---|---|
| `%TEMP%` browser files | ✅ YES | `scrub_temp()` on browser exit |
| `%LOCALAPPDATA%\CrashDumps\` | ✅ YES | `scrub_wer()` |
| `C:\ProgramData\WER\ReportQueue\` | ✅ YES | `scrub_wer()` — RESOLVED HIGH-03 |
| `C:\ProgramData\WER\ReportArchive\` | ✅ YES | `scrub_wer()` — RESOLVED HIGH-03 |
| `%APPDATA%\Mozilla\Firefox\installs.ini` | ✅ YES | pre-launch + post-exit |
| `%APPDATA%\Waterfox\installs.ini` | ✅ YES | pre-launch + post-exit |
| `%APPDATA%\Floorp\installs.ini` | ✅ YES | pre-launch + post-exit — RESOLVED HIGH-04 |
| `C:\Windows\Prefetch\` | ✅ YES | `scrub_prefetch()` + UAC elevation via `ShellExecuteW("runas")` — RESOLVED HIGH-02 |
| Windows Event Log | ❌ NO | Accepted limitation |
| `%APPDATA%\Microsoft\Windows\Recent\` | ✅ YES | `scrub_shell_recent()` — LNK parser targets portable drive |
| AutomaticDestinations (JumpList) | ✅ YES | `scrub_automatic_destinations()` — UTF-16LE byte-scan in OLE stream data — RESOLVED MED-03 |
| Shell bags (Registry) | ❌ NO | MED-03 — not implemented |
| `thumbcache_*.db` / `iconcache_*.db` | ✅ OPT-IN | `scrub_thumbnail_cache = true` in `nomad.toml` — RESOLVED MED-04 |
| `nomad.log` | ✅ ROTATED | 512 KB max, 1 backup — RESOLVED MED-05 |
| NSIS install traces (Firefox/Waterfox/Floorp) | ✅ YES | `scrub_nsis_install_traces()` post-install — RESOLVED CRIT-02 |
| Profile session data (Gecko) | ✅ YES | `sanitizeOnShutdown` — RESOLVED HIGH-01 |
| GPUCache in Chromium profile | ❌ NO | Low risk; stays on portable drive |

### 7.2 Post-Exit Cleanup Effectiveness

The self-watcher process design (`--nomad-cleanup-pid`) is architecturally sound. `WaitForSingleObject(INFINITE)` provides guaranteed, zero-CPU-cost execution after the browser exits. The watcher correctly survives launcher window close (~16ms after `signal_done()`).

**What works well:** Guaranteed post-exit execution; handles crash scenario; covers `%LOCALAPPDATA%\CrashDumps` and `%ProgramData%\WER\ReportQueue/ReportArchive`; `installs.ini` scrubbed at both launch start and exit; log rotated at 512 KB.

**What is missing:** UAC elevation is required for Prefetch scrubbing — one consent prompt appears after each browser session. On machines where the user is not an admin or UAC is fully disabled, Prefetch entries will persist.

### 7.3 Profile Isolation Effectiveness

| Browser | Isolation Method | Status |
|---|---|---|
| ungoogled-chromium | `--user-data-dir` on drive | ✅ ISOLATED |
| Helium | `--user-data-dir` on drive | ✅ ISOLATED |
| Firefox / ESR | `--profile` + `--no-remote` | ✅ ISOLATED |
| Floorp | `--profile` + `--no-remote` | ✅ ISOLATED |
| Waterfox | `--profile` + `--no-remote` | ✅ ISOLATED |
| DPAPI binding (Chromium) | `--disable-encryption` + `--disable-machine-id` | ✅ RESOLVED |
| Host Firefox sharing | `--no-remote` | ✅ RESOLVED |
| Crash reporter traces | `--disable-breakpad` / `MOZ_CRASHREPORTER_DISABLE=1` | ✅ RESOLVED |
| `policies.json` stale (Gecko) | Written at every launch | ✅ RESOLVED |

---

## 8. Hardening Effectiveness Matrix

Scores: 0=None, 1=Partial, 2=Moderate, 3=Good, 4=Strong (max 20)

| Browser | Telemetry | Network | Fingerprint | Storage | Portable | Score |
|---|---|---|---|---|---|---|
| ungoogled-chromium | 4 | 3 | 3 | 2 | 4 | **16/20 (80%)** |
| Helium | 4 | 3 | 3 | 2 | 3 | **15/20 (75%)** |
| Firefox | 4 | 4 | 3 | 3 | 4 | **18/20 (90%)** |
| Firefox ESR | 4 | 4 | 3 | 3 | 4 | **18/20 (90%)** |
| Floorp | 4 | 4 | 3 | 3 | 4 | **18/20 (90%)** |
| Waterfox | 4 | 4 | 3 | 3 | 4 | **18/20 (90%)** |

Notes:
- Gecko scores higher on Network (4 vs 3) due to DoH, comprehensive Safe Browsing removal, and full Activity Stream disablement
- Gecko Storage raised from 2 → 3 after HIGH-01 resolution (`sanitizeOnShutdown` now configured)
- Waterfox Portable raised from 3 → 4 after CRIT-01 resolution (SHA-512 integrity verification now in place)
- Helium Portable lowered from 4 → 3: GPG key was GitHub web-flow key (not developer key); slot emptied; SHA-256-only now matches ungoogled-chromium rather than the higher-assurance Firefox/Waterfox path
- Chromium Storage remains at 2 — no `sanitizeOnShutdown` equivalent; profile accumulates on portable drive (acceptable by design)
- Fingerprint capped at 3 due to WebRTC IP partial mitigation (MED-06); live testing (§8.1) shows the residual fingerprint cap is now driven by **WebGL**, not WebRTC

### 8.1 Live Fingerprinting Verification (2026-05-29, Chromium family)

Method: BrowserLeaks (`/webgl`, `/canvas`, `/webrtc`) run side-by-side on the deployed Ungoogled Chromium and Helium launchers. The applied hardening switches were independently confirmed by reading the live `chrome.exe` process command line — it matches `HARDENING_FLAGS` plus `--webrtc-ip-handling-policy=disable_non_proxied_udp` appended from the `disable_webrtc = true` default.

| Vector | Ungoogled Chromium | Helium | Verdict |
|---|---|---|---|
| **WebRTC IP leak** | No leak — LAN + WAN absent; SDP loopback only (`IN IP4 127.0.0.1`); media devices `n/a` | Same | ✅ Strong — closes the VPN-defeating STUN leak; corroborates `disable_webrtc` default |
| **Canvas 2D** | Noised; signature re-rolls **per read** (changes on every refresh) | Noised; signature re-rolls **per session** (changes on restart) | ✅ Cross-session canvas tracking defeated; two valid noise models (see note) |
| **WebGL render** | GPU vendor/renderer masked (`WebKit`, via SpoofWebGLInfo); **image/report hash stable & machine-unique** | Identical hashes to UC | ⚠️ Residual — un-noised, persistent fingerprint |
| **GPU model / UA** | Masked; UA reduced to `Chrome/148.0.0.0` + RemoveClientHints | Same | ✅ |

Notes:
- Canvas-noise *granularity* differs by **browser build**, not Nomad config — both receive the identical `--fingerprinting-canvas-image-data-noise` flag. Per-read (UC) maximally scrambles a single read but is detectable and theoretically recoverable by averaging many reads; per-session (Helium) is averaging-resistant and inconspicuous (the Brave-farbling model). Both re-randomize across restarts, defeating long-term canvas tracking.
- **WebGL is the one residual fingerprint vector**, excluded by design: `--disable-webgl` / full RFP are site-breaking and out of scope (SPEC §13). The hash being identical across the two same-machine browsers confirms it derives from real GPU rendering (not spoofed). For sessions requiring true fingerprint resistance (a uniform crowd), use Mullvad/Tor Browser rather than the Nomad "safe" profile.

---

## 9. Functional Regression Risk Summary

### High Regression Risk — User-Toggleable Recommended

| Setting | Risk | Default |
|---|---|---|
| `dom.security.https_only_mode = true` | Breaks `http://` intranets and legacy devices | ON |
| `privacy.resistFingerprinting = true` (Waterfox ESR 115) | Breaks timezone-aware web apps; spoofs locale | ON |
| Safe Browsing disabled (Gecko) | No phishing/malware protection | ON ⚠️ |

### Medium Regression Risk — Leave ON, Document Trade-off

| Setting | Risk |
|---|---|
| `network.trr.mode = 2` (DoH) | May break DNS split-horizon resolution |
| `privacy.trackingprotection.enabled` | Breaks some SSO flows |
| `--webrtc-ip-handling-policy=default_public_interface_only` | May affect WebRTC call quality |

### Site-Breaking Settings Correctly Excluded

- `--disable-webgl` — breaks most modern games and 3D sites
- `media.peerconnection.enabled = false` — breaks all WebRTC calls
- `network.http.referer.XOriginPolicy = 2` — breaks OAuth redirect flows
- `ReducedSystemInfo` Chrome feature — **now shipped on by default** (`[hardening] reduce_system_info = true`) for fingerprint-entropy reduction, matching Tor/Brave's `hardwareConcurrency` clamping; the trade-off is a modest perf hit for thread-pool-sizing apps, so it is user-disablable (`= false`)

---

## 10. Recommended Next Steps (Priority Order)

| Priority | Finding | Action | Effort | Status |
|---|---|---|---|---|
| ~~P0~~ | ~~CRIT-01~~ | ~~Investigate CDN for checksum; if absent, block Waterfox downloads with UI warning~~ | ~~LOW~~ | ✅ DONE |
| ~~P1~~ | ~~HIGH-01~~ | ~~Add `sanitizeOnShutdown` prefs to both `user.js` files~~ | ~~LOW~~ | ✅ DONE |
| ~~P2~~ | ~~HIGH-03~~ | ~~Extend `scrub_wer()` to WER ReportQueue and ReportArchive~~ | ~~LOW~~ | ✅ DONE |
| ~~P3~~ | ~~HIGH-04~~ | ~~Confirm Floorp `installs.ini` path; also scrub at launch start~~ | ~~LOW~~ | ✅ DONE |
| ~~P4~~ | ~~MED-05~~ | ~~Implement log rotation; reduce default log level to `warn`~~ | ~~LOW~~ | ✅ DONE |
| ~~P5~~ | ~~MED-02~~ | ~~Auto-launch on network error when cached install exists~~ | ~~MEDIUM~~ | ✅ DONE |
| ~~P6~~ | ~~MED-01~~ | ~~Cache update check results to reduce GitHub API calls~~ | ~~MEDIUM~~ | ✅ DONE |
| ~~P7~~ | ~~MED-03~~ | ~~Scrub Recent Items (LNK parser); AutomaticDestinations deferred~~ | ~~HIGH~~ | ✅ PARTIAL |
| ~~P8~~ | ~~HIGH-02~~ | ~~Document Prefetch limitation; add first-run UI note~~ | ~~LOW~~ | ✅ DONE (doc + `scrub_prefetch()` with UAC elevation via `ShellExecuteW("runas")`) |
| ~~P9~~ | ~~LOW-01~~ | ~~Add `[launch] incognito = false` config option for Chromium~~ | ~~LOW~~ | ✅ DONE |
| ~~P10~~ | ~~LOW-02~~ | ~~Add `sanitize_on_shutdown` to `nomad.toml` schema~~ | ~~LOW~~ | ✅ DONE |
| PRE-RELEASE | — | Verify GPG keys in `core/keys/` are from official upstream sources | N/A | ✅ DONE — Firefox key verified; Helium key was GitHub web-flow key (not a developer key), slot emptied |
| P11 | CRIT-02 | Scrub NSIS installer traces (registry, shortcuts, %PROGRAMDATA%, %LOCALAPPDATA%) after each Firefox/Waterfox/Floorp install | MEDIUM | ✅ DONE |

---

## Appendix: Completed Fixes

> **Session dating & order (added 2026-06-03).** Sessions 1–8 are the v1.0.0
> audit-remediation push of **2026-05-19** (a few findings — MED-03 full,
> MED-06 — landed **2026-05-21**); per-session timestamps within that window were
> not separately recorded, so the dates below mark the window, not a precise day.
> The headings appear partly out of order in the source; the authoritative
> sequence by passing-test count is **S1 → S2 → S3 → S4 → S5 → S6 → S7 Prefetch
> (118) → S8 CRIT-02 re-resolution (124) → S8 CRIT-03 runtime-extras (126)**. The
> two "Session 8" entries are distinct findings: the **CRIT-02 re-resolution**
> (install-then-scrub abandoned for 7-Zip extraction) came first, then **CRIT-03**
> (Mozilla auxiliary-exe strip). Dated addenda follow: **Session 9 — Mullvad
> 2026-05-31**, **Session 10 — Tor 2026-06-02**.

### Session 1 (2026-05-19) — initial implementation

| Finding | Fix Applied |
|---|---|
| Chromium profile leaked to `%LOCALAPPDATA%` | `profile_dir()` + `--user-data-dir` on all Chromium launchers |
| DPAPI credential binding | `--disable-machine-id` + `--disable-encryption` on Chromium launchers |
| Gecko profile shared with host Firefox | `--no-remote` added to Firefox, Floorp, Waterfox |
| Crash reporters leaving traces | `--disable-breakpad` on Chromium; `MOZ_CRASHREPORTER_DISABLE=1` on Gecko |
| `policies.json` stale between updates | `write_policies_json()` called in `do_launch()` on every run |
| Missing privacy prefs in Firefox/Floorp `user.js` | 30+ prefs added (Safe Browsing, captive portal, Activity Stream, Ping Centre, DoH, cryptomining, taskbar, disk cache) |
| Waterfox used wrong fingerprinting pref (Firefox 119+ pref on ESR 115) | Dedicated `waterfox/user.js` with `privacy.resistFingerprinting=true` |
| No post-exit cleanup mechanism | Self-watcher process (`--nomad-cleanup-pid`) using `WaitForSingleObject` |
| `%TEMP%` browser traces | `scrub_temp()` in cleanup watcher |
| WER crash dumps (`%LOCALAPPDATA%\CrashDumps`) | `scrub_wer()` in cleanup watcher |
| `installs.ini` NSIS trace (Firefox/Waterfox) | `scrub_mozilla_installs_ini()` in cleanup watcher |
| HTTP download User-Agent exposed `reqwest` version | `download_to_tmp()` now accepts `&reqwest::Client` with Nomad UA |

### Session 2 (2026-05-19) — audit remediation (P0–P4)

| Finding | Fix Applied |
|---|---|
| CRIT-01: Waterfox zero-integrity download | SHA-512 fetched from CDN; `gpg::sha512` module added; `verify_package()` falls back to `sha512` when `sha256` is absent; `Waterfox::cdn_base` overridable for tests |
| HIGH-01: sanitizeOnShutdown missing | Added to `payloads/firefox/user.js` (incl. Firefox 128+ `_v2` prefs) and `payloads/waterfox/user.js`; cache/downloads/formdata/sessions cleared on exit; cookies and history preserved |
| HIGH-03: WER ReportQueue not scrubbed | `scrub_wer()` extended to `%ProgramData%\Microsoft\Windows\WER\ReportQueue\` and `ReportArchive\`; matching dirs removed with `remove_dir_all` |
| HIGH-04: Floorp installs.ini unconfirmed + exit-only scrub | `%APPDATA%\Floorp\installs.ini` added; `scrub_mozilla_installs_ini()` called pre-launch in both `do_launch()` and fallback "LaunchAnyway" path |
| MED-05: nomad.log unbounded growth | `rotate_log()` rotates at 512 KB (1 backup); default log level lowered to `warn` |

All 92 unit tests + 8 integration tests pass (100 total).

### Session 3 (2026-05-19) — audit remediation (P5–P7)

| Finding | Fix Applied |
|---|---|
| MED-02: Offline fallback required user intervention | `BrowserError::Offline` variant added; `map_network_err()` classifies `is_connect()`/`is_timeout()` and HTTP 403 as Offline; `update_check_phase()` auto-launches installed version silently on Offline error |
| MED-01: GitHub API rate limit exposed to user | `core/src/version_cache.rs` — `VersionCache` with 4-hour TTL saved as `nomad-version-cache.toml`; `update_check_phase()` reads cache first and skips network when fresh; HTTP 403 from GitHub classified as `BrowserError::Offline` |
| MED-03: Recent Items LNK files exposed portable drive path | `scrub_shell_recent()` added to cleanup watcher; inline MS-SHLLINK parser (`lnk_target_path()`) supports both compact and extended `LinkInfo` headers; LNK files targeting the portable drive root are deleted; AutomaticDestinations (OLE format) deferred |

All 105 unit tests + 8 integration tests pass (113 total).

### Session 4 (2026-05-19) — audit remediation (P8–P10)

| Finding | Fix Applied |
|---|---|
| HIGH-02: Prefetch documentation (P8) | `DEFAULT_NOMAD_TOML` gains a `PRIVACY NOTE` comment block explaining Prefetch; the "Launching…" status line shows a secondary Prefetch notice on every launch (`PREFETCH_NOTICE` constant in `lib.rs`) |
| LOW-01: Incognito option for Chromium (P9) | `[launch] incognito = false` added to `LaunchConfig` + `DEFAULT_NOMAD_TOML`; `build_launch_args()` appends `--incognito` for Chromium-engine browsers when enabled |
| LOW-02: sanitize_on_shutdown config (P10) | `[hardening] sanitize_on_shutdown = true` added to `HardeningConfig` + `DEFAULT_NOMAD_TOML`; `do_launch()` appends a master-disable pref to the `user.js` block when set to `false`; `HardeningConfig` threaded through pipeline instead of bare `bool` |

All 107 unit tests + 8 integration tests pass (115 total).

### Session 5 (2026-05-19) — pre-release verification + LOW-03/LOW-04

| Finding | Fix Applied |
|---|---|
| PRE-RELEASE: Firefox key | Fingerprint `14F26682D0916CDD81E37B6D61B7B526D98F0353` verified against [Mozilla Security Blog (Apr 2025)](https://blog.mozilla.org/security/2025/04/01/updated-gpg-key-for-signing-firefox-releases-2/) — ✅ VERIFIED |
| PRE-RELEASE: Helium key | `968479A1AFF927E37D1A566BB5690EEEBB952194` identified as GitHub's platform web-flow key, not an Imput developer key; cannot sign release asset files; `core/keys/helium.asc` emptied; `HELIUM_KEY.is_empty()` now true; Helium reverts to SHA-256-only integrity |
| LOW-03: Helium provenance | Module doc updated; `metadata_is_stable` test updated to assert `public_key().is_none()`; AUDIT downgraded from STRONG to SHA-256-only |
| LOW-04: Safe Browsing warning | `DEFAULT_NOMAD_TOML` gains SECURITY NOTE comment; `do_launch()` emits `tracing::warn!` on every Gecko hardened launch |

All 107 unit tests + 8 integration tests pass (115 total).

### Session 6 (2026-05-19) — NSIS portability bug (CRIT-02)

| Finding | Fix Applied |
|---|---|
| CRIT-02: NSIS installers write system traces outside `install_dir` — confirmed in production (Firefox appeared in Control Panel, Desktop shortcut created, `C:\ProgramData\Mozilla` and `%LOCALAPPDATA%\Mozilla` written) | `scrub_nsis_install_traces()` added to `core/src/extract.rs`; called after `run_nsis_installer()` in `extract()` of Firefox, Firefox ESR, Waterfox, and Floorp; uses `winreg::RegKey::delete_subkey_all` for registry cleanup and `fs::remove_dir_all` for directory cleanup; all six steps are best-effort (warn on failure, never blocks launch) |

All 107 unit tests + 8 integration tests pass (115 total).

### Session 8 (2026-05-19) — CRIT-03: Mozilla runtime auxiliary executables

| Finding | Fix Applied |
|---|---|
| CRIT-03: `firefox.exe` spawns auxiliary executables on startup (`default-browser-agent.exe`, `pingsender.exe`, `updater.exe`, `crashreporter.exe`, etc.) that write `%LOCALAPPDATA%\Mozilla\` and `%PROGRAMDATA%\Mozilla-<GUID>\` *before* `policies.json` / `user.js` are even read — confirmed in production after the v1.0.0 + 7-Zip-extraction fix (Control Panel was clean, but those two host folders still appeared) | `strip_mozilla_runtime_extras()` added to `extract.rs`; called from `extract()` of Firefox, Firefox ESR, Floorp, and Waterfox after the 7-Zip unpack. Deletes 9 known auxiliary executables from `install_dir` so `firefox.exe` physically cannot spawn them. Belt-and-suspenders `scrub_mozilla_runtime_dirs()` added to `handle_cleanup_flag()` — removes `%LOCALAPPDATA%\Mozilla` and any `%PROGRAMDATA%\Mozilla-*` directories on browser exit |

All 118 unit tests + 8 integration tests pass (126 total).

### Session 7 (2026-05-19) — Prefetch scrubbing (HIGH-02 fully resolved)

| Finding | Fix Applied |
|---|---|
| HIGH-02: Prefetch scrubbing blocked without elevation | `scrub_prefetch()` / `scrub_prefetch_dir()` added; called from `handle_cleanup_flag()` after other scrubs; if `PermissionDenied`, `elevate_for_prefetch_scrub()` re-spawns the launcher with `--nomad-scrub-prefetch` + `ShellExecuteW("runas")` (one UAC prompt); elevated copy runs `handle_prefetch_scrub_flag()` and exits silently; `Win32_UI_Shell` feature added to `windows-sys` |

All 110 unit tests + 8 integration tests pass (118 total).

### Session 8 (2026-05-19) — CRIT-02 re-resolution: extraction replaces scrub

User reported in production that Firefox, Firefox ESR, Floorp, and Waterfox **still** installed system-wide despite the Session 6 scrub. Root cause: an admin account with permissive UAC let the NSIS installer escape `__COMPAT_LAYER=RunAsInvoker`, write to `HKLM`, and use its hardcoded `Program Files (x86)` path — all outside our `HKCU`/`%PROGRAMDATA%` scrub scope. The "install then scrub" architecture was abandoned.

| Finding | Fix Applied |
|---|---|
| CRIT-02 (re-fix): installer execution itself is unsafe | `run_nsis_installer` and `scrub_nsis_install_traces` deleted. New: 7-Zip 24.09 (`7z.exe` + `7z.dll`) embedded into the lib crate via `include_bytes!` from `core/payloads/7zip/`. `extract_nsis_with_7zip(installer, install_dir, marker_exe)` extracts the NSIS `.exe` as an archive, locates the browser executable, and flattens the tree so it lands at `install_dir`. All four Gecko browsers now call this — the installer process never runs. `msiexec /a` was considered but failed with 1603 on the user's non-elevated shell, so the bundled-7-Zip path was chosen for all Gecko browsers. End-to-end smoke test with a real 68.8 MB `Firefox Setup 138.0.exe` confirms zero new system traces post-extraction. Dead-code elimination keeps the ~2.3 MB 7-Zip blob out of the Helium and ungoogled-chromium launchers, which still use `extract_zip`. |

All 116 unit tests + 8 integration tests pass (124 total).

---

## Addendum — Session 9 (2026-05-31): Mullvad Browser added

Mullvad Browser was added as the eighth launcher *after* the 2026-05-19 audit above, so it is documented here rather than retrofitted into the dated findings. Its security posture and the host-trace coverage it required:

| Area | Detail |
|---|---|
| New launcher | `nomad-mullvad.exe` (`core/src/browsers/mullvad.rs`) — Gecko engine, x64-only. NSIS package extracted via the embedded 7-Zip path (`extract_nsis_with_7zip`; the installer never runs); `strip_mozilla_runtime_extras()` and `postupdate.exe` removed after unpack. |
| Verification | **GPG + SHA-256** — the highest tier, alongside Firefox/ESR. Detached signature verified against the embedded Tor Browser Developers key (`core/keys/mullvad.asc`, fingerprint `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`); SHA-256 additionally checked from the GitHub release asset `digest`. |
| Hardening | Nomad writes **no** `user.js` and provisions **no** uBlock Origin — Mullvad ships its own RFP / letterboxing / standardized UA-timezone-fonts plus uBO + NoScript, and any Nomad-injected pref would make individual users distinguishable and break crowd-blending. Only `DisableAppUpdate` is written via `policies.json`; `has_builtin_fingerprint_noise()` defers the fingerprint vectors to Mullvad. |
| Zero-trace exit | `BROWSER_EXE_NAMES` (WER report queues + `%LOCALAPPDATA%\CrashDumps`) gains `mullvadbrowser.exe`; `PREFETCH_TOKENS` gains `MULLVADBROWSER.EXE-` and `NOMAD-MULLVAD.EXE-`. **Correction (deployment inspection):** Mullvad does *not* reuse the `Mozilla` brand dir — it creates `%LOCALAPPDATA%\Mullvad\MullvadBrowser`, which `GECKO_BRAND_DIRS` does not cover. A dedicated `scrub_mullvad_runtime_dir()` now removes that subdir (and the parent only if empty, so a co-installed Mullvad VPN's data is preserved). Not added to `GECKO_BRAND_DIRS` because that mechanism would delete the whole `Mullvad\` parent. |
| Hardening write (correction) | Mullvad declares `user_js: ""`, but the `disable_webrtc = true` default was still appending `media.peerconnection.enabled = false` to a fenced `user.js` in Mullvad's profile — making it distinguishable from the Mullvad crowd. Fixed: a Gecko browser with an empty `user_js` now has its `user.js` left unwritten (and any prior Nomad block stripped via `hardening::remove_managed_user_js`); no WebRTC/sanitize override is injected. |

All 218 unit tests + 8 integration tests pass (226 total).

---

## Addendum — Session 10 (2026-06-02): Tor Browser added

> **REMOVED 2026-06-10.** The Tor launcher described below no longer exists: its source
> (`launchers/tor/`, `core/src/browsers/tor.rs`, `core/keys/tor.asc`, the smoke test, the
> `NOMAD-TOR.EXE-` prefetch token) is no longer in the tree and the last built `Nomad-Tor.exe`
> was deleted. This addendum is preserved unmodified as the audit record of what shipped.
> The Tor Browser Developers GPG key remains embedded as `core/keys/mullvad.asc` — Mullvad
> verification is unaffected.

Tor Browser was added as the ninth browser (`nomad-tor.exe`), mirroring Mullvad (its sibling — Mullvad is Tor Browser with Tor networking removed) with two deliberate differences. Documented here rather than retrofitted into the dated findings.

| Area | Detail |
|---|---|
| New launcher | `nomad-tor.exe` (`core/src/browsers/tor.rs`) — Gecko engine, x64-only. The "portable" 7-Zip-SFX `.exe` is extracted via `extract_nsis_with_7zip` (marker exe `firefox.exe`); the bundle's `Browser/` is flattened to the install root, leaving `TorBrowser/Tor/{tor.exe,PluggableTransports/…}` intact. |
| Verification | **GPG only.** Detached `.asc` verified against the embedded Tor Browser Developers key (`core/keys/tor.asc`, fingerprint `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290` — identical bytes to `mullvad.asc`). Tor publishes no SHA-256 in the download dir or `downloads.json`, and a detached signature over the binary is stronger than a hash, so no SHA-256 is required. |
| Update channel | Tor Browser is not on a GitHub releases API. `fetch_latest_version` GETs the Tor Project manifest `aus1.torproject.org/torbrowser/update_3/release/downloads.json` and reads `version` + `downloads.win64.ALL.{binary,sig}`. |
| Hardening | Like Mullvad: writes **no** `user.js`, provisions **no** uBO, `has_builtin_fingerprint_noise() = true`. **Unlike** Mullvad: writes **no** `policies.json` at all — see updater exception. |
| Updater exception ⚠️ | Tor is the **only** launcher that does **not** disable the browser's own updater. A stale Tor Browser is a deanonymization/exploitation risk and Tor's signed incremental MAR updates are a security feature, so Nomad provisions the first install and defers to Tor's in-app updater. `strip_tor_runtime_extras()` is a variant of `strip_mozilla_runtime_extras()` that removes the host-writing helpers (default-agent, pingsender, maintenanceservice, crashreporter, …) **but preserves `updater.exe`**. Dropping `maintenanceservice.exe` keeps self-updates unprivileged and in-place (no `%PROGRAMDATA%` write). Guarded by `strip_tor_runtime_extras_keeps_updater_but_removes_host_writers`. |
| Launch | `firefox.exe --no-remote`, `MOZ_CRASHREPORTER_DISABLE=1`, and **no `--profile`** — Tor uses its in-tree `TorBrowser/Data/Browser/profile.default` so the firefox ↔ `TorBrowser/Data/Tor` coupling is preserved. `installed_version` uses the standard `.nomad-version` marker (Tor's `application.ini` `Version` is the Firefox base version, not the Tor Browser version, so it cannot drive `needs_update`). |
| Update state preservation | Because Tor's profile + daemon state live **inside** `install_dir` (unique among Nomad browsers — all others keep the profile outside it), the wholesale `atomic_swap` on a Nomad-driven update would reset the security-level slider, bookmarks, saved bridges, and persistent entry guards. `BrowserFamily::preserve_state_across_update` (default no-op; Tor overrides it) copies `TorBrowser/Data/` from the live install into the freshly-staged install just before the swap. Copy-not-move, so a swap failure leaves the old install's state intact. Tor's own incremental MAR updater already preserves the profile; this closes the gap on the Nomad fallback path. Guarded by `preserve_state_copies_user_data_over_staged_default`. |
| Zero-trace exit | Tor's browser process is `firefox.exe`, already in `BROWSER_EXE_NAMES` + `PREFETCH_TOKENS`; only the launcher token `NOMAD-TOR.EXE-` was added. A dedicated host-runtime-dir scrub (`%LOCALAPPDATA%\Tor Browser`) is deferred pending the manual no-trace check, since Tor is designed fully portable. |

All 246 unit tests + 8 integration tests pass after this addition.

---

## Addendum — Session 11 (2026-06-09 → 2026-06-10): external deep audit + remediation

A full external audit (parallel security + correctness reviews, every Critical/High finding
independently re-verified against source before acceptance) followed by complete remediation in
four batches. Condensed record; the per-change detail lives in tasks/todo.md Phase 11.

| Finding | Severity | Resolution |
|---|---|---|
| Shipped pipeline never called `preserve_state_across_update` — the hook lived only in the test-only `updater::update`, so a real Bitwarden update permanently deleted the vault at `App\Data`; the green integration suite was certifying a pipeline that does not ship | **Critical** | Single shared `updater::download_and_install` (+ `finalize_install`) now used by both UI and headless paths; regression test exercises the shipped path with a populated vault. Headless path also gained the Gecko policies write it had been missing (the same drift in the other direction). |
| gorhill uBO GPG check verified the release *tag/commit* while the zip asset — mutable on GitHub independently of git history, `digest: null` — was staged unverified; investigation proved the zip is unreconstructible from the signed tree (it bundles unpinned `uBlockOrigin/uAssets` clones) | **High** | `github::asset_provenance_suspect` upload-timeline tamper check (in-place re-upload or delete-and-reupload after publication ⇒ warn + defer, never fail the launch), calibrated against real release data; all docs corrected to state the tag-only trust model. Residual risk (swap within the tolerance window at publication time) documented as unclosable from Nomad's side. |
| `--register-default` registered `"exe" -- "%1"` but `run()` ignored everything after `--` — clicked links opened the browser without navigating | High | `split_forwarded_args`: Nomad flags honored only before `--`, tail appended to launch args. |
| `scrub_thumbnail_cache` field default was `default_true`, contradicting the documented opt-in `false` for any config with a `[hardening]` section omitting the key | High | `#[serde(default)]` + doc fix + section-present test case. |
| Authenticode used `WTD_REVOKE_NONE` while docs claimed revoked certs are rejected; publisher pin was a substring match | Medium/Low | Whole-chain revocation with offline soft-fallback (definitive `CERT_E_REVOKED` always fails); exact case-insensitive subject equality. SPEC/README/AUDIT wording updated. |
| `write_user_js` clobbered user prefs when the existing file was unreadable; LibreWolf/Waterfox cache hosts missing (cache never used); Bitwarden absent from Prefetch/WER scrubs; no decompressed-size cap (zip bomb); `unregister` orphaned failed deletions; dead `cleanup_stale_tmp` | Medium/Low | All fixed: read-error guard; hosts added; three Prefetch tokens + two WER exe names; 8 GiB / 512 MiB budgets via `copy_entry_capped`; `PartialUnregister` keeps the sidecar for retry; dead function removed. |
| Test-coverage gaps vs. the project's own fixture-test convention | Low | Backfilled: `scrub_temp`, `scrub_wer` + `scrub_shell_recent` (split into `_in(dir)` forms), `atomic_swap` rollback branch, `replace_fenced` truncated-fence healing. |

Also in this session: the Tor launcher (Session 10) was fully removed at the user's direction
(see the REMOVED banner above); `TRADEMARKS.md` was created (was referenced but missing);
verification-tier and uBO trust-model wording
was corrected across SPEC.md, README.md, and CLAUDE.md.

**Gate after remediation:** 267 unit + 7 integration tests pass, `clippy --workspace
--all-targets -- -D warnings` clean, `cargo fmt --check` clean. Release rebuilt via `dist.ps1`:
9 launchers, `SHA256SUMS` GPG-signed (verified Good), Authenticode deliberately skipped (no
code-signing certificate exists; user decision 2026-06-10).
