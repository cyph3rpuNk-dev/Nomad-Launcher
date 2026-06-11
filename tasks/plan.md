# Implementation Plan: Nomad Portable

## Overview

Nomad Portable is a family of portable Windows browser launchers (`nomad-<browser-id>.exe`), each updating, hardening, branding, and launching one browser. This plan builds the project greenfield as a Rust Cargo workspace: a shared `nomad-core` library plus one thin binary crate per browser.

The strategy is: build the foundation and contracts first, then drive **one browser (ungoogled-chromium) all the way to a working end-to-end launch** as the first vertical slice, then add the UI and cross-cutting features (hardening, branding, registry), then fan out the remaining browsers as parallel verticals against a now-proven pipeline.

ungoogled-chromium is chosen as the first browser because its update source (GitHub releases API) is the simplest and best-documented, and its Chromium engine exercises the launch-flag hardening path.

> **Scope note:** this file is the frozen v1 browser plan (Phases 1–6) — **complete: all checkpoints A–F signed off** (see [todo.md](todo.md)). The unticked `[ ]` boxes below are the original planning checklist, superseded by [todo.md](todo.md) as the live status of record. Post-v1 launchers are tracked in [todo.md](todo.md), not here — **Tor Browser** (Phase 9 — shipped, later removed 2026-06-10; see todo.md) and **Nomad Portable Bitwarden** (Phase 10), the first *non-browser* launcher: the official Bitwarden Electron desktop app wrapped portable + self-updating (`Engine::Electron`, SHA-256 + Authenticode, `App\Data` vault preserved across updates). The pipeline generalized cleanly from "browser" to "portable app" with only additive changes.

## Architecture Decisions

- **Foundation-first, then vertical slices.** The `BrowserFamily` trait, config, downloader, and GPG layer are genuinely shared infrastructure — they are built once up front. After that, each browser is a self-contained vertical slice (impl + launcher crate + embedded key/icon).
- **First browser proves the whole pipeline.** Tasks 4–7 take ungoogled-chromium from config to a launched browser with no UI. This de-risks the entire architecture before any UI or feature work.
- **UI is layered onto a working headless flow.** `run()` works headless first (Phase 2), then the egui status window is wired on top (Phase 3). This keeps the GPU-dependent, hard-to-test UI off the critical correctness path.
- **Cross-cutting features after the first browser, before the rest.** Hardening, branding, and registry land once (Phase 4) so all remaining browsers inherit them.
- **Remaining browsers are parallelizable.** Once the trait and pipeline are proven, Tasks 14–17 are independent and can be done in parallel by separate sessions.

## Dependency Graph

```
Task 1 (workspace skeleton)
   │
Task 2 (core types + BrowserFamily trait)  ◄── the contract everything else depends on
   │
   ├── Task 3 (config.rs)
   ├── Task 4 (downloader.rs)
   ├── Task 5 (gpg.rs)
   │
   └── Task 6 (ungoogled-chromium impl) ── needs 4, 5
          │
       Task 7 (updater.rs + headless run()) ── needs 3, 6      ◄── CHECKPOINT B: first launch
          │
          ├── Task 8 (UI shell) ─ Task 9 (wire UI) ─ Task 10 (taskbar)   ◄── CHECKPOINT C
          │
          ├── Task 11 (profile.rs — portability prefs)
          ├── Task 12 (winresource launcher icon)
          ├── Task 13 (registry.rs)                                       ◄── CHECKPOINT D
          │
          └── Tasks 14–16 (remaining 5 browsers, parallel) ── need 9,11,12  ◄── CHECKPOINT E
                 │
              Task 18 (assets finalization) ─ Task 19 (test sweep + release)  ◄── CHECKPOINT F
```

---

## Task List

### Phase 1: Foundation & Contracts

## Task 1: Cargo workspace skeleton

**Description:** Create the workspace root, the `nomad-core` library crate, and the first launcher binary crate `nomad-ungoogled-chromium`. Add CI and lint configuration. Project must build and the launcher binary must run (printing a placeholder).

**Acceptance criteria:**
- [ ] `nomad-portable/Cargo.toml` workspace defines members `core` and `launchers/ungoogled-chromium`.
- [ ] `launchers/ungoogled-chromium` package is named `nomad-ungoogled-chromium` and builds `nomad-ungoogled-chromium.exe`.
- [ ] GitHub Actions workflow runs `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` on `windows-latest`.

**Verification:**
- [ ] Build succeeds: `cargo build --workspace`
- [ ] Binary runs: `cargo run -p nomad-ungoogled-chromium`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check` pass

**Dependencies:** None
**Files likely touched:** `Cargo.toml`, `core/Cargo.toml`, `core/src/lib.rs`, `launchers/ungoogled-chromium/Cargo.toml`, `launchers/ungoogled-chromium/src/main.rs`, `.github/workflows/ci.yml`, `rustfmt.toml`
**Estimated scope:** S

## Task 2: Core types and `BrowserFamily` trait

**Description:** Define the shared contract in `nomad-core`: `Engine`, `VersionInfo`, `InstalledVersion`, `ProgressSink`, per-module error enums, and the `BrowserFamily` trait exactly as in SPEC §3. No browser implementations yet.

**Acceptance criteria:**
- [ ] `BrowserFamily` trait declares all methods from SPEC §3 (`id`, `display_name`, `engine`, `public_key` returning `Option`, `installed_version`, `fetch_latest_version`, `download`, `verify_signature`, `extract`, `apply_portability_prefs`, `launch_command`).
- [ ] `VersionInfo` carries browser version, engine version, download URL, optional signature URL, expected SHA-256.
- [ ] `lib.rs` carries `#![deny(clippy::all, clippy::pedantic)]`.

**Verification:**
- [ ] Build succeeds: `cargo build -p nomad-core`
- [ ] Clippy clean: `cargo clippy -p nomad-core -- -D warnings`
- [ ] `cargo doc -p nomad-core` renders the trait

**Dependencies:** Task 1
**Files likely touched:** `core/src/lib.rs`, `core/src/browsers/mod.rs`
**Estimated scope:** S

## Task 3: Configuration (`config.rs`)

**Description:** Implement `nomad.toml` load, validate, and default-write per SPEC §4 — `[browser]`, `[update]`, `[launch]` (no `channel` key, no `[hardening]`/`[branding]` sections). Unknown keys must be rejected; missing config must produce a default file beside the `.exe`.

**Acceptance criteria:**
- [ ] Valid `nomad.toml` parses into a typed `Config` struct.
- [ ] Unknown keys and missing required fields return a descriptive typed error.
- [ ] On absent config, defaults are written beside the `.exe` and used.

**Verification:**
- [ ] Unit tests pass: `cargo test -p nomad-core config`
- [ ] Tests cover: valid parse, unknown-key rejection, missing-field rejection, default-write, relative-path preservation

**Dependencies:** Task 2
**Files likely touched:** `core/src/config.rs`, `core/src/lib.rs`
**Estimated scope:** S

### Checkpoint A: Foundation
- [ ] `cargo build --workspace` and `cargo test --workspace` pass
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] Trait and config contracts reviewed with human before building against them

---

### Phase 2: First End-to-End Browser (ungoogled-chromium)

## Task 4: HTTP downloader (`downloader.rs`)

**Description:** Streaming HTTP download to a `.tmp` file beside the destination, reporting progress through `ProgressSink`. Cleans up stale `.tmp` files at start. Uses `reqwest` with `native-tls`.

**Acceptance criteria:**
- [ ] `download(url, dest, progress)` streams to `dest.tmp`, emits 0.0–1.0 progress, renames on success.
- [ ] Failed/partial downloads leave no `dest`; `.tmp` is removed on failure and on next start.
- [ ] Every request and result is logged at `DEBUG`.

**Verification:**
- [ ] Integration test passes: `cargo test --test integration downloader` (uses `httpmock`)
- [ ] Test covers: full download, progress monotonic to 1.0, mid-stream failure cleanup

**Dependencies:** Task 2
**Files likely touched:** `core/src/downloader.rs`, `tests/integration/downloader.rs`
**Estimated scope:** S

## Task 5: GPG verification (`gpg.rs`)

**Description:** Pure-Rust detached-signature verification with the `pgp` crate, plus SHA-256 hash check. `gpg::verify(package, sig, pubkey_bytes)` returns `Ok(())` or a typed `GpgError`.

**Acceptance criteria:**
- [ ] Verifies a valid detached signature against an embedded armored key.
- [ ] Bad signature and tampered payload each return `Err`.
- [ ] Separate `sha256::verify(file, expected)` helper.

**Verification:**
- [ ] Unit tests pass: `cargo test -p nomad-core gpg`
- [ ] Tests use real fixtures: known-good, known-bad signature, tampered payload, hash match/mismatch

**Dependencies:** Task 2
**Files likely touched:** `core/src/gpg.rs`, `tests/fixtures/` (signed sample, keys)
**Estimated scope:** S

## Task 6: ungoogled-chromium `BrowserFamily` implementation

**Description:** First concrete browser. Implement `fetch_latest_version` (GitHub releases API), `installed_version` (parse local install), `extract` (zip), `verify_signature`, `launch_command`, `engine() == Chromium`. `download` delegates to `downloader`.

**Acceptance criteria:**
- [ ] `fetch_latest_version` parses the GitHub releases JSON into `VersionInfo` (version, asset URL, sig URL or none, hash).
- [ ] `installed_version` reads the installed version from the extracted layout.
- [ ] `extract` unpacks the release archive into `install_dir`; `launch_command` targets the browser executable.

**Verification:**
- [ ] Unit tests pass: `cargo test -p nomad-core ungoogled`
- [ ] Tests: `fetch_latest_version` against fixture JSON, `installed_version` against mock dir, `extract` against a small fixture archive
- [ ] Integration: `fetch_latest_version` against `httpmock`

**Dependencies:** Tasks 4, 5
**Files likely touched:** `core/src/browsers/ungoogled.rs`, `core/src/browsers/mod.rs`, `tests/fixtures/`
**Estimated scope:** M

## Task 7: Updater and headless `run()` orchestrator

**Description:** Implement `updater.rs` (compare installed vs latest) and a headless `nomad_core::run()` that wires config → check → download → verify → hash → extract → launch. No UI yet; phases log to `tracing`. Wire `nomad-ungoogled-chromium`'s `main.rs` to call it.

**Acceptance criteria:**
- [ ] `run()` executes the full SPEC §8 flow (minus PREP/UI) and spawns the browser.
- [ ] Up-to-date installs skip download and launch directly.
- [ ] GPG/hash failure aborts before extract and surfaces a typed error.

**Verification:**
- [ ] Integration test passes: `cargo test --test integration pipeline` (mock server → extract → stubbed launch)
- [ ] Manual: `nomad-ungoogled-chromium.exe` in an empty folder downloads and launches the real browser

**Dependencies:** Tasks 3, 6
**Files likely touched:** `core/src/updater.rs`, `core/src/lib.rs`, `launchers/ungoogled-chromium/src/main.rs`, `tests/integration/pipeline.rs`
**Estimated scope:** M

### Checkpoint B: First Browser Launches
- [ ] `nomad-ungoogled-chromium.exe` downloads, verifies, extracts, and launches the browser end-to-end
- [ ] All tests pass; clippy clean
- [ ] Review pipeline correctness with human before adding UI

---

### Phase 3: Status Window UI

## Task 8: UI shell — theme and transient status window

**Description:** Build `ui/theme.rs` (Nomad Chrome-dark palette) and the egui transient window per SPEC §7: title bar, identity card (logo, name, version subtitle, eyebrow, primary/secondary status, progress bar), runtime details card, footer link. Driven by a static `LauncherView` model for now.

**Acceptance criteria:**
- [ ] Window matches the mockup palette and two-card layout.
- [ ] Identity card renders logo + name + version subtitle; progress bar uses track/accent colors.
- [ ] Runtime details card shows Name / Bundle mode / version / Build date rows.

**Verification:**
- [ ] Build succeeds: `cargo build -p nomad-core`
- [ ] Manual: window renders and visually matches `nomad_chrome_dark_mode.html` mockup

**Dependencies:** Task 2
**Files likely touched:** `core/src/ui/mod.rs`, `core/src/ui/identity.rs`, `core/src/ui/theme.rs`
**Estimated scope:** M

## Task 9: Wire UI into `run()`

**Description:** Connect pipeline phase events to the status window: live status lines, progress bar, auto-close on launch, error state with Retry/Launch-anyway/Close, and the `auto_download = false` Update/Launch-current prompt.

**Acceptance criteria:**
- [ ] Each phase (check, download, verify, extract, prep, launch) updates the status lines/progress.
- [ ] Window auto-closes after the browser spawns; stays open on error with action buttons.
- [ ] `auto_download = false` shows the Update / Launch-current prompt and waits.

**Verification:**
- [ ] Manual: run happy path (auto-close), error path (stays open), and `auto_download=false` prompt
- [ ] `cargo test --workspace` still passes

**Dependencies:** Tasks 7, 8
**Files likely touched:** `core/src/lib.rs`, `core/src/ui/mod.rs`
**Estimated scope:** M

## Task 10: Taskbar progress (`taskbar.rs`)

**Description:** `ITaskbarList3` progress overlay via `windows-rs`, isolated behind a safe wrapper. `TBPF_NORMAL` during download, `TBPF_NOPROGRESS` on completion, `TBPF_ERROR` on failure.

**Acceptance criteria:**
- [ ] Taskbar shows download progress; clears on completion; error state on failure.
- [ ] All `unsafe` is confined to `taskbar.rs` behind a safe API.

**Verification:**
- [ ] Build + clippy clean
- [ ] Manual: observe taskbar overlay during a download

**Dependencies:** Task 9
**Files likely touched:** `core/src/taskbar.rs`, `core/src/lib.rs`
**Estimated scope:** S

### Checkpoint C: ungoogled-chromium Fully Working
- [ ] ungoogled-chromium launches end-to-end with the full status window and taskbar progress
- [ ] All tests pass; clippy clean
- [ ] UI reviewed against mockups with human

---

### Phase 4: Cross-Cutting Features

## Task 11: Privacy hardening — framework + Chromium path

**Description:** Implement automated privacy hardening per SPEC §5 — Nomad's core value. Define the `Hardening` enum and the `BrowserFamily::hardening()` method (replacing the removed `apply_portability_prefs`), and wire the `[hardening] enabled` config toggle. Implement the Chromium-family path: a curated "safe", non-site-breaking ungoogled-chromium flag set, appended to the launch command when hardening is enabled. The Gecko `user.js` + `policies.json` path and the LibreWolf thin override are built alongside the Gecko browser verticals (Tasks 15–17), reusing this framework.

**Acceptance criteria:**
- [ ] `Hardening` enum + `hardening()` on the `BrowserFamily` trait; old `apply_portability_prefs` removed everywhere.
- [ ] ungoogled-chromium returns a documented safe flag set; flags are appended at launch only when `[hardening] enabled`.
- [ ] `[hardening] enabled = false` launches with no added flags.
- [ ] No aggressive, site-breaking switches in the safe set (SPEC §13).

**Verification:**
- [ ] Unit tests pass: `cargo test -p nomad-core hardening`
- [ ] Tests: safe flag-set content, `[hardening]` config parse, enabled/disabled toggle

**Dependencies:** Task 7
**Files likely touched:** `core/src/browsers/mod.rs`, `core/src/browsers/ungoogled.rs`, `core/src/config.rs`, `core/src/lib.rs`
**Estimated scope:** M

## Task 12: Launcher icon embedding (`winresource` build script)

**Description:** Establish the compile-time launcher-icon pattern per SPEC §6. Add a `build.rs` using `winresource` to the `nomad-ungoogled-chromium` launcher crate that embeds its `icon.ico` into the `.exe`. This pattern is reused by every later launcher crate. (PE patching of the downloaded browser is deferred to post-v1 — not in scope.)

**Acceptance criteria:**
- [ ] `nomad-ungoogled-chromium` has a `build.rs` + `icon.ico`; the built `.exe` carries the icon.
- [ ] Build works on `windows-latest` CI without external tooling.

**Verification:**
- [ ] Build succeeds: `cargo build -p nomad-ungoogled-chromium`
- [ ] Manual: Explorer shows the embedded icon on `nomad-ungoogled-chromium.exe`

**Dependencies:** Task 7
**Files likely touched:** `launchers/ungoogled-chromium/build.rs`, `launchers/ungoogled-chromium/Cargo.toml`, `launchers/ungoogled-chromium/icon.ico`
**Estimated scope:** S

## Task 13: Default browser registration (`registry.rs`)

**Description:** `--register-default` / `--unregister-default` CLI flags writing only to `HKCU`, tracking written keys in a `nomad.reg-state.json` sidecar for clean unregister.

**Acceptance criteria:**
- [ ] `--register-default` writes `HKCU` keys and records them to the sidecar.
- [ ] `--unregister-default` removes exactly the recorded keys.
- [ ] No `HKLM` writes anywhere.

**Verification:**
- [ ] Unit tests pass: `cargo test -p nomad-core registry` (sidecar round-trip)
- [ ] Manual: register, confirm Nomad appears in Windows default-apps, unregister cleanly

**Dependencies:** Task 7
**Files likely touched:** `core/src/registry.rs`, `core/src/lib.rs`
**Estimated scope:** M

### Checkpoint D: Cross-Cutting Features
- [ ] Portability prefs, launcher icon embedding, and registration all work for ungoogled-chromium
- [ ] All tests pass; clippy clean
- [ ] Review before fanning out to remaining browsers

---

### Phase 5: Remaining Browsers (parallelizable verticals)

## Task 14: Helium launcher

**Description:** `BrowserFamily` impl for Helium (GitHub releases API `imputnet/helium-windows`) + `nomad-helium` launcher crate + embedded GPG key + icon. Helium is ungoogled-chromium-based and uses the same Chromium launch-flag hardening path. GPG key ID: `B5690EEEBB952194`. Versions use 4-component format (e.g. `0.12.3.1`).

**Acceptance criteria:**
- [ ] `fetch_latest_version` parses the GitHub releases API into `VersionInfo` (4-component version, asset URL, sig URL, SHA-256 hash from the release asset `digest` field).
- [ ] GPG signature verification succeeds against the embedded Helium key.
- [ ] `nomad-helium.exe` builds and launches Helium end-to-end.

**Verification:**
- [ ] Unit tests against fixture JSON pass
- [ ] Manual end-to-end launch

**Dependencies:** Tasks 9, 11, 12
**Files likely touched:** `core/src/browsers/helium.rs`, `launchers/helium/`, `core/keys/helium.asc`, `core/assets/icons/`
**Estimated scope:** M

## Task 15: Firefox stable + ESR launchers

**Description:** Gecko-engine impls using the Mozilla Product Details API + `nomad-firefox` and `nomad-firefox-esr` launcher crates. The ESR launcher hardcodes its channel internally (no `channel` config key). First exercise of the Gecko portability `user.js` path and of GPG signature verification (Firefox publishes GPG signatures).

**Acceptance criteria:**
- [ ] Both launchers resolve correct versions and download URLs; ESR channel is hardcoded in `nomad-firefox-esr`.
- [ ] Gecko portability `user.js` is written into the Firefox profile.
- [ ] GPG signature verification succeeds against Firefox's published signature; both launchers build and launch end-to-end.

**Verification:**
- [ ] Unit tests against fixture API responses pass
- [ ] Manual: both launch; `user.js` present and marker-fenced; GPG verification exercised

**Dependencies:** Tasks 9, 11, 12
**Files likely touched:** `core/src/browsers/firefox.rs`, `core/src/browsers/firefox_esr.rs`, `launchers/firefox/`, `launchers/firefox-esr/`, `core/keys/`, `core/assets/icons/`
**Estimated scope:** M

## Task 16: Floorp + Waterfox launchers

**Description:** Gecko-engine impls using GitHub releases APIs + `nomad-floorp` and `nomad-waterfox` launcher crates.

**Acceptance criteria:**
- [ ] Both resolve versions from their GitHub releases; full pipeline works.
- [ ] Both launchers build and launch end-to-end.

**Verification:**
- [ ] Unit tests against fixture JSON pass
- [ ] Manual end-to-end launch for each

**Dependencies:** Tasks 9, 11, 12
**Files likely touched:** `core/src/browsers/floorp.rs`, `core/src/browsers/waterfox.rs`, `launchers/floorp/`, `launchers/waterfox/`, `core/keys/`, `core/assets/icons/`
**Estimated scope:** M

### Checkpoint E: All Six Browsers
- [ ] All 6 launcher binaries build and launch their browsers end-to-end
- [ ] All tests pass; clippy clean
- [ ] Spot-check hardening + branding on one Chromium and one Gecko browser

---

### Phase 6: Polish & Release

## Task 18: Asset finalization and first-run polish

**Description:** Ensure every browser has a real embedded GPG key, branding `.ico`, and hardening payload. Implement the "Open upstream release page" link targets and first-run default-config write for all eight.

**Acceptance criteria:**
- [ ] All 6 browsers have embedded key + icon + hardening payload.
- [ ] Footer link opens the correct upstream release page for each of the 6 browsers.
- [ ] First run with no `nomad.toml` writes correct defaults for all 6 launchers.

**Verification:**
- [ ] `cargo test --workspace` passes
- [ ] Manual: first-run config write and footer link verified for 2 launchers

**Dependencies:** Tasks 14–16
**Files likely touched:** `core/keys/`, `core/assets/`, `core/src/browsers/*`
**Estimated scope:** M

## Task 19: Full test sweep and release build

**Description:** Close test-coverage gaps, ensure CI is green, and produce optimized release builds of all eight binaries.

**Acceptance criteria:**
- [ ] CI green: `fmt`, `clippy -D warnings`, `test --workspace`.
- [ ] `cargo build --release --workspace` produces all 6 `nomad-*.exe` binaries.
- [ ] Each binary depends only on stock Windows 10/11 DLLs.

**Verification:**
- [ ] CI passes on `windows-latest`
- [ ] Manual: dependency check (e.g. `dumpbin /dependents`) on each binary

**Dependencies:** Task 18
**Files likely touched:** `tests/`, `.github/workflows/ci.yml`
**Estimated scope:** M

## Task 20: Hardening sync automation

**Description:** Automate *detection* of upstream changes to the hardening payloads so the curated "safe" sets do not silently drift. A scheduled GitHub Actions workflow watches each upstream, diffs against a checked-in baseline, and opens a PR on change — automation handles detection; curation (deciding what is "safe") stays a human review step (SPEC §5). Covers both engines: ungoogled-chromium `docs/flags.md` and arkenfox `user.js` releases. The upstream `docs/flags.md` and the pinned arkenfox version are checked in as provenance baselines next to the vendored payloads.

**Acceptance criteria:**
- [ ] Scheduled workflow (weekly) diffs upstream ungoogled `docs/flags.md` against the checked-in baseline and opens a PR on change.
- [ ] The PR body explicitly flags any switch in Nomad's active `HARDENING_FLAGS` set that disappeared upstream (silent-deprecation alert).
- [ ] Scheduled workflow watches arkenfox release tags and opens a PR with the new `user.js` and a diff against the pinned version.
- [ ] No upstream change is auto-merged — every PR requires human curation review.

**Verification:**
- [ ] Manual: trigger the workflow against a deliberately stale baseline; confirm a PR is opened with a correct diff
- [ ] PR body wording reviewed for the deprecation-alert case

**Dependencies:** Tasks 15–16 (the Gecko hardening payload must exist to diff against)
**Files likely touched:** `.github/workflows/`, `core/src/browsers/`, vendored baseline files
**Estimated scope:** M

### Checkpoint F: Complete
- [ ] All 6 launchers ship working update → harden → brand → launch flows
- [ ] All SPEC acceptance criteria (§1) met
- [ ] Ready for release review

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| egui status window cannot be tested headlessly in CI | Low | Accepted per SPEC §12; manual smoke test at Checkpoints C and E |
| Gecko profile directory location varies for portable builds | Medium | Resolve and document the portable profile path in Task 11/15 before writing `user.js` |

## Open Questions — RESOLVED

1. **PE resource editor crate** — RESOLVED: PE icon patching of the downloaded browser is deferred to post-v1. v1 embeds each launcher's own icon at compile time via a `winresource` build script (Task 12).
2. **GPG coverage per browser** — RESOLVED: Firefox Stable, Firefox ESR, and Helium get GPG + SHA-256; ungoogled-chromium, Floorp, and Waterfox are SHA-256-only with a `WARN` log.
3. **Identity card version subtitle format** — RESOLVED: uniform `{browser_version} — {engine} {engine_version} (Portable)`; the engine segment is omitted when browser and engine versions are identical.
4. **Hardening scope** — RESOLVED: automated privacy hardening is Nomad's core value (SPEC §5). One curated *safe* profile, no graded presets — Chromium-family gets launch flags, Gecko-family gets a layered `user.js` + `policies.json`, LibreWolf gets a thin `policies.json`-only override. Aggressive, site-breaking measures are out of scope.
5. **`channel` config key for `nomad-firefox-esr`** — RESOLVED: dropped entirely. The ESR launcher hardcodes its channel internally.
