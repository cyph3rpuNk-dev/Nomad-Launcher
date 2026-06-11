# Nomad Portable — Task List

Tracking checklist for [plan.md](plan.md). Mark `[x]` when a task's acceptance criteria and verification all pass.

## Phase 1: Foundation & Contracts
- [x] **Task 1** — Cargo workspace skeleton (core + nomad-ungoogled-chromium + CI) — S
- [x] **Task 2** — Core types and `BrowserFamily` trait — S
- [x] **Task 3** — Configuration (`config.rs`, nomad.toml) — S
- [x] **Checkpoint A** — Foundation builds, tests pass, contracts reviewed

## Phase 2: First End-to-End Browser (ungoogled-chromium)
- [x] **Task 4** — HTTP downloader (`downloader.rs`) — S
- [x] **Task 5** — GPG verification (`gpg.rs`) — S
- [x] **Task 6** — ungoogled-chromium `BrowserFamily` impl — M
- [x] **Task 7** — Updater + headless `run()` orchestrator — M
- [x] **Checkpoint B** — `nomad-ungoogled-chromium.exe` launched ungoogled-chromium 148.0.7778.96-1.1 end-to-end (real download, SHA-256 verified, extracted, launched)

## Phase 3: Status Window UI
- [x] **Task 8** — UI shell: theme + transient status window — M
- [x] **Task 9** — Wire UI into `run()` (phases, auto-close, error, prompt) — M
- [x] **Task 10** — Taskbar progress (`taskbar.rs`) — S
- [x] **Checkpoint C** — ungoogled-chromium fully working with UI, reviewed vs mockups

## Phase 4: Cross-Cutting Features
- [x] **Task 11** — Privacy hardening: framework + Chromium flag path (`hardening()`, `[hardening]` config) — M
- [x] **Task 12** — Launcher icon embedding (`winresource` build script) — S
- [x] **Task 12b** — Browser branding Stage 2: PE icon patching (`branding.rs`,
      `BeginUpdateResourceW`/`UpdateResourceW`/`EndUpdateResourceW` on
      `chrome.exe` + `chrome.dll`; grayscale ICOs; `.branding-patched` marker) — M
- [x] **Task 13** — Default browser registration (`registry.rs`) — M
- [x] **Checkpoint D** — Portability prefs, icon embedding, registration work; reviewed

> Branding Stage 3 (PAK logo patching for the `chrome://settings/help` /
> new-tab logos) is deferred — tracked as a future follow-up.

## Phase 5: Remaining Browsers (parallelizable)
- [x] **Task 14** — Helium launcher (ungoogled-chromium-based; GPG + SHA-256; `imputnet/helium-windows`) — M
- [x] **Task 15** — Firefox stable + ESR launchers — M
- [x] **Task 16** — Floorp + Waterfox launchers — M
- [x] **Checkpoint E** — All 6 browsers build and launch end-to-end

## Phase 6: Polish & Release
- [x] **Task 18** — Asset finalization + first-run polish — M
- [x] **Task 19** — Full test sweep + release build — M
- [x] **Task 20** — Hardening sync automation (watch → diff → draft PR, both engines) — M
- [x] **Checkpoint F** — All SPEC §1 criteria met, ready for release review

## Phase 8: uBO consolidation (post-v1)
- [x] **Task 3** — Confirm uBO coverage: Gecko via AMO-signed XPI, Helium built-in, Ungoogled via gorhill
- [x] **Task 4** — uBO folded into the launch-time updater (`fetch_extension_updates`), gated on `check_on_launch` / `auto_download`
- [x] **Task 6** — Ungoogled Chromium uBO from `gorhill/uBlock` direct, GPG-verified release tag (key `F5630CAE62A14316`), staged via `--load-extension=` (`core/src/extensions.rs`)

## Phase 9: Tor Browser launcher (post-v1) — REMOVED 2026-06-10 (was DONE, verified 2026-06-03)
> **Removed from the codebase.** The source (`launchers/tor/`, `core/src/browsers/tor.rs`,
> `core/keys/tor.asc`, `tor_smoke.rs`, the `NOMAD-TOR.EXE-` prefetch token) and the plan doc
> `nomad-tor-browser-plan.md` are no longer in the tree; the last built `Nomad-Tor.exe` was
> deleted 2026-06-10. The checklist below is the historical record of what shipped — resurrect
> from it if Tor support returns. The deployed instance at `C:\Portables\TorBrowser` lives
> outside the repo and was deliberately left untouched (it contains the user's Tor profile).

Plan + decisions were in `nomad-tor-browser-plan.md` (removed with the launcher). Decisions signed off at the time: keep Tor's own updater (no `DisableAppUpdate`, preserve `updater.exe`); GPG-only verification.
- [x] `core/keys/tor.asc` (Tor Browser Developers key, identical to mullvad.asc)
- [x] `core/src/browsers/tor.rs` — `BrowserFamily` impl (downloads.json channel, GPG-only, empty hardening + no policies, in-tree profile, no `--profile`) + 10 unit tests
- [x] `core/src/extract.rs::strip_tor_runtime_extras` — keeps `updater.exe`; regression test
- [x] Wiring: `browsers::tor` module + `pub use ...Tor`; `NOMAD-TOR.EXE-` prefetch token
- [x] `launchers/tor/` crate (`Nomad-Tor.exe`) — builds; real icon embedded (official Tor onion mark, `assets/tor-logo.svg` → `icon.ico` at 16–256 px)
- [x] Docs: SPEC §2, AUDIT addendum (Session 10), README (table + trade-offs + tree), CLAUDE.md convention bullet
- [x] Gate: 246 unit + 8 integration tests pass, clippy clean, fmt OK
- [x] On-demand provisioning smoke test (`tests/integration/tor_smoke.rs`, `#[ignore]`) — real `downloads.json` → download → GPG verify → extract, asserts `updater.exe`/`tor.exe`/PT present + junk stripped. Run: `cargo test -p nomad-core --test integration -- --ignored tor_provisioning`
- [x] **Update state preservation (Option B)**: `BrowserFamily::preserve_state_across_update` (default no-op; Tor copies `TorBrowser/Data/` into the staged install before `atomic_swap`) so Nomad-driven updates keep the security level, bookmarks, saved bridges, and persistent entry guards. Tor's profile is the only one inside `install_dir`. 2 unit tests.
- [x] Release artifact built — deployed at `C:\Portables\TorBrowser\Nomad-Tor.exe` (11.7 MB, real Tor onion icon). Canonical build output `target\release\Nomad-Tor.exe` is regenerated by `./dist.ps1`; not present in this checkout.
- [x] **Real-bundle provisioning verified** (`C:\Portables\TorBrowser`, 2026-06-02): live `downloads.json` → `15.0.14` → GPG verify → extract all succeeded. Tree confirmed: `firefox.exe` + `updater.exe` (kept) + `tor.exe` + `lyrebird.exe`/`conjure-client.exe` present; Tor's own NoScript preserved; 6 host-writers stripped; **no `user.js`**, **no Nomad `policies.json`**; marker = 15.0.14.
- [x] **No-trace verified**: Tor run created nothing under `%LOCALAPPDATA%\Tor Browser`, `Mozilla` (Local/Roaming/ProgramData), `TorProject`, or CrashDumps. `scrub_tor_runtime_dir` **not needed** — Tor stays within its portable tree.
- [x] **Live GUI checks (verified 2026-06-03)**: `Nomad-Tor.exe` (`C:\Portables\TorBrowser`) opened the Tor Browser window; `tor.exe` daemon bootstrapped a circuit; check.torproject.org confirmed *"Congratulations. This browser is configured to use Tor."* In-app self-update confirmed ("Tor Browser is up to date"; bundle moved 15.0.14→15.0.15 — proves `updater.exe` retention, §9 item 3). Optional obfs4-bridge path (§9 item 2) not exercised — not required for DoD.
- [x] ~~Optional cleanup: the `WARN … Safe Browsing disabled` log line for Tor~~ — obsolete (launcher removed); the same cosmetic inaccuracy still applies to Mullvad if anyone wants it.

## Phase 10: Nomad Portable Bitwarden (post-v1) — VERIFIED END-TO-END
First non-browser launcher: the official Bitwarden desktop app (Electron), wrapped portable + self-updating. Verified on Bitwarden 2026.5.0 at `C:\Portables\Bitwarden`.
- [x] **Step 0 — artifact decision (empirical):** `-x64.appx` runs inert when unpacked (MSIX identity) → DEAD; official portable `.exe` PASSED (window + `BITWARDEN_APPDATA_DIR` override + Authenticode `Bitwarden Inc.` + SHA-256 == GitHub digest). Portable `.exe` is the path.
- [x] `core/src/browsers/bitwarden.rs` — `BrowserFamily` impl (`Engine::Electron`, no GPG, SHA-256 + Authenticode, verify-and-stage `extract`, `App\Data` vault, `preserve_state_across_update`, trimmed `default_config`) + unit tests
- [x] `core/src/authenticode.rs` — `WinVerifyTrust` + signer-subject extraction (`CryptQueryObject`/`CertGetNameStringW`), `unsafe` behind safe wrapper; `windows-sys` WinTrust/Cryptography features added; unsigned-file + subject-match tests
- [x] `Engine::Electron` variant (label "Desktop App"); `BrowserFamily::default_config()` (trait default = browser template; Bitwarden overrides); `Config::load_or_init(dir, default_config)`; `run_with_ui` resolves arch then makes once
- [x] `launchers/bitwarden/` crate (`Nomad-Bitwarden.exe`); official Bitwarden `.ico` embedded + verified
- [x] **Bugfix:** cross-product `releases/latest` resolved a `browser-v…` extension release → switched to listing releases and filtering newest stable `desktop-v…` (`github::fetch_releases` + `prerelease`)
- [x] **Folder layout (user-chosen):** `App\{Bitwarden-Portable.exe,.nomad-version,Data\}` + `Nomad\` + `Nomad-Bitwarden.exe`; vault in `App\Data` preserved across updates
- [x] **End-to-end verified:** live download (344 MB) → SHA-256 → Authenticode → atomic_swap → launch; vault loads from `App\Data`; "already up to date" on re-launch (no needless re-download); no writes to `%APPDATA%\Bitwarden`/`%LOCALAPPDATA%`/registry
- [x] Docs: README (Other apps table + Bitwarden section + verification + tree), SPEC §2/§9/§13, AUDIT §2.6, CLAUDE.md convention bullet + authenticode pointer, CHANGELOG
- [x] Gate: 263 core tests + clippy `-D warnings` + fmt green
- [ ] Optional follow-up: exclude regenerable caches (`Cache`/`GPUCache`) from the `preserve_state_across_update` copy to speed updates (currently copies the whole `Data\` directory)

## Phase 11: External audit + remediation (2026-06-09 → 2026-06-10) — DONE
Findings + resolutions: [AUDIT.md](../AUDIT.md) Addendum Session 11.
- [x] **Critical:** Bitwarden vault wiped on real updates — preserve hook only existed in the test-only `updater::update`; pipeline unified into shared `updater::download_and_install` + `finalize_install`, regression-tested against the shipped path
- [x] **High:** gorhill uBO asset not bound to the tag GPG signature → `github::asset_provenance_suspect` upload-timeline check + honest trust-model docs (zip unreconstructible: unpinned uAssets); `--register-default` dropped the `"%1"` URL → `--` tail forwarded; `scrub_thumbnail_cache` serde default contradicted the opt-in decision
- [x] **Medium/Low:** Authenticode whole-chain revocation + exact publisher equality; decompression budgets (8 GiB / 512 MiB); `write_user_js` unreadable-file guard; LibreWolf/Waterfox cache hosts; Bitwarden Prefetch/WER coverage; `PartialUnregister` keeps sidecar for retry; dead `cleanup_stale_tmp` removed
- [x] Test backfill per convention: `scrub_temp`/`scrub_wer`/`scrub_shell_recent` `_in(dir)` splits, `atomic_swap` rollback, fence heal-to-EOF
- [x] Tor launcher fully removed (user direction; see Phase 9 banner) — stale exe + references cleaned, historical records banner-preserved
- [x] Docs: `TRADEMARKS.md` created (was referenced but missing); verification tiers (Mullvad GPG, Waterfox SHA-512, fail-closed no-hash) and uBO trust model corrected across SPEC/README/CLAUDE; ghost `new_focus` removed from SPEC §3 tree
- [x] Gate: 267 unit + 7 integration tests, clippy `-D warnings`, fmt — green. Release rebuilt (`dist.ps1`): 9 launchers, `SHA256SUMS` GPG-signed (verified Good); Authenticode skipped by decision (no cert)
- [x] **Repo is not under version control** — `git init` + initial commit done (2026-06-10)

## Phase 12: Adversarial re-audit + DLL hardening (2026-06-10) — DONE
Adversarial re-review findings (N-1 through N-8) + resolutions.
- [x] **High (whole-volume scrub):** `scrub_shell_recent` / `scrub_automatic_destinations` skipped when `GetDriveTypeW != DRIVE_REMOVABLE` — no longer wipes system-wide Recent Items / JumpList when run from `C:` or any fixed drive
- [x] **High (prefetch UAC on every exit):** `scrub_prefetch` made opt-in (`[hardening] scrub_prefetch = false` default); UAC elevation only fires when explicitly enabled; SPEC §4/§5 updated
- [x] **High (DLL planting via elevated re-spawn):** `/DEPENDENTLOADFLAG:0x800` added to `.cargo/config.toml` rustflags (protects static imports); `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` added as first call in `nomad_core::run()` (protects runtime `LoadLibrary`). Verified via `dumpbin /LOADCONFIG`: `Dependent Load Flag = 0800` confirmed in release PE.
- [x] **Medium (install_dir confinement):** `run_with_ui` now rejects absolute paths and `..` components before constructing `install_dir` — silent redirection of extraction outside the portable tree is no longer possible
- [x] **Medium (incognito disables uBO):** `ungoogled.rs::launch_command` logs `WARN` when `--incognito` + uBO staged; comma-in-path guard added
- [x] **Medium (non-atomic PAK write):** `apply_pak_patches` now uses temp+rename; power-loss on USB no longer corrupts the PAK permanently
- [x] **Git init + initial commit** — full history from this point forward

---

## Manual verification matrices (run on a real Windows host; not unit-testable)

### Prefetch UAC elevation (HIGH-02) — `scrub_prefetch` / `elevate_for_prefetch_scrub`
The `ShellExecuteW("runas")` elevation path can't be exercised in CI (depends on UAC policy + token elevation state). Confirm manually across the three cases:
- [ ] **Admin account, UAC enabled** → one UAC consent prompt; on accept, the launched browser's matching `.pf` files are removed from `C:\Windows\Prefetch`; the launcher continues normally.
- [ ] **Admin account, UAC disabled** (or an already-elevated shell) → no prompt; the scrub runs silently and succeeds.
- [ ] **Standard (non-admin) account** → UAC prompts for admin credentials; if denied, the launcher must continue cleanly — Prefetch entries persist, **no error dialog**, no crash (the scrub is best-effort).

---

## Open Questions — all RESOLVED
- [x] PE icon patching deferred to post-v1; v1 uses `winresource` compile-time icon embedding
- [x] GPG coverage: Firefox + Firefox ESR get GPG+SHA-256; ungoogled-chromium, Helium, Floorp, Waterfox, and LibreWolf are SHA-256-only + WARN (Helium's key slot was emptied — its upstream signs via GitHub's web-flow key, unusable for asset verification; LOW-03)
- [x] Uniform subtitle: `{browser_version} — {engine} {engine_version} (Portable)`, engine omitted when versions match
- [x] Hardening is Nomad's core value (SPEC §5): one curated *safe* profile — Chromium launch flags, Gecko `user.js` + `policies.json`, LibreWolf thin override; no graded presets
- [x] `channel` config key dropped; ESR launcher hardcodes its channel

## Progress
- v1: complete — all tasks, checkpoints, and Phase 7 signed off

## Known gaps / decisions
- `VersionInfo.sha256` refined to `Option<String>` (matches `signature_url` being optional).
- Verification gap RESOLVED: GitHub records a SHA-256 `digest` field on every release
  asset; `ungoogled.rs` parses it, so ungoogled-chromium downloads get real SHA-256
  verification. Same approach reused for Floorp/Waterfox (Task 16).
