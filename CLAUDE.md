# CLAUDE.md — Nomad Launcher

Portable Windows browser launchers in Rust. One `nomad-<browser>.exe` per browser that downloads, verifies, privacy-hardens, and launches it from its own directory — no installer, no system writes, no persistence.

**Behavioral principles** load from `~/.claude/CLAUDE.md` (Karpathy's four: Think Before Coding, Simplicity First, Surgical Changes, Goal-Driven Execution). This file is the *project-specific application* of those principles, not a restatement.

## Authoritative docs (read before non-trivial work)

- [SPEC.md](SPEC.md) — design contract. §13 (Boundaries) is the canonical "never do" list.
- [AUDIT.md](AUDIT.md) — privacy/security audit. Required reading before touching `extract.rs`, `scrub_*`, hardening payloads, or anything Mozilla-related.
- [tasks/plan.md](tasks/plan.md) + [tasks/todo.md](tasks/todo.md) — current state. v1 is complete (Checkpoints A–F all signed off); active work is post-v1, tracked in [tasks/todo.md](tasks/todo.md) as the live status of record. `plan.md` is the frozen v1 plan, not live status.

## Hard invariants

Violating any of these breaks the product's core promise or reverts a fix that took multiple sessions to land.

1. **Portable-only.** No `HKLM`, no `%APPDATA%` / `%LOCALAPPDATA%` / `%PROGRAMDATA%` writes during normal operation. Registry is `HKCU` only, opt-in via `--register-default`, sidecar-tracked. See SPEC §13.
2. **Never run NSIS installers.** Firefox / Firefox ESR / Floorp / Waterfox are extracted via `extract_nsis_with_7zip` using embedded 7-Zip (`core/payloads/7zip/`). `run_nsis_installer` and `scrub_nsis_install_traces` were deleted on purpose — do not reintroduce. AUDIT CRIT-02.
3. **Strip Mozilla auxiliary executables after extraction.** `default-browser-agent.exe`, `pingsender.exe`, `updater.exe`, `crashreporter.exe`, etc. must be removed by `strip_mozilla_runtime_extras()`. They write `%LOCALAPPDATA%\Mozilla\` *before* `policies.json` / `user.js` are read. AUDIT CRIT-03.
4. **Verify before extracting.** SHA-256 (or SHA-512 for Waterfox) is checked before any unpack. GPG additionally where the upstream publishes a usable key — currently Firefox stable + ESR (Mozilla key) and Mullvad (Tor Browser Developers key). Keys: `core/keys/<browser>.asc`, embedded via `include_bytes!`.
5. **Hardening stays "safe."** The curated profile maximises privacy without breaking sites. Canonical exclusion list lives in SPEC §5 + §13 — defer there, do not re-enumerate.
6. **Vendored payloads, never runtime fetch.** arkenfox-derived `user.js`, Chromium flag sets, 7-Zip binaries, GPG keys are embedded at compile time via `include_str!` / `include_bytes!`. Runtime fetch breaks USB / offline use. **Sanctioned exceptions** — each justified by an artifact we cannot reproduce:
   - **AMO-signed uBlock Origin XPI** (Gecko) downloaded from AMO's `/latest/` at launch — Gecko requires a Mozilla-signed artifact Nomad cannot reproduce.
   - **gorhill uBlock Origin zip** (Ungoogled Chromium) checked via the `gorhill/uBlock` GitHub releases API at launch; the release tag's GPG signature is verified against the embedded gorhill key (`F5630CAE62A14316`) before the zip is downloaded. **Scope of that guarantee:** the signature covers the tag/commit only — release assets are mutable independently of git history, gorhill publishes no asset checksums (`digest: null`), and the zip bundles filter lists pulled from unpinned `uBlockOrigin/uAssets` branches at gorhill's build time, so the zip can be neither signature-bound nor rebuilt from the signed tree. The asset's bytes are trusted to GitHub, with `github::asset_provenance_suspect` (upload-timeline check: in-place re-upload or delete-and-reupload after publication ⇒ warn + defer the update) as tamper evidence against a post-publication asset swap. Do not "fix" this by reconstructing the zip from source — the unpinned uAssets dependency makes that unsound in principle, not just expensive. Staging approach: gorhill's `uBlock0_X.X.X.chromium.zip` is extracted to `<install-dir>/nomad-extensions/uBlock0/` and loaded via `--load-extension=` at launch (see `core/src/extensions.rs` for why `external_extensions.json` and self-packaged CRX were both ruled out). Chromium derives the canonical extension ID `cjpalhdlnbpafiamejdnhcphjbkeiagm` from the `key` field in gorhill's `manifest.json` — no Nomad-side pinning needed. `--load-extension=` surfaces a mild "developer mode" header in `chrome://extensions`; developer mode is seeded on via the `initial_preferences` payload (`extensions.ui.developer_mode = true`).
7. **Reject unknown config keys.** `nomad.toml` parse errors must be loud, never silent.

## Architecture pointers

Cargo workspace. `core/` is the shared lib (`nomad-core`); each `launchers/<browser>/` is a ~3-line binary crate that calls `nomad_core::run(SomeBrowser::new())`.

- `core/src/lib.rs` — orchestration pipeline, `handle_cleanup_flag`, `scrub_*`.
- `core/src/browsers/<browser>.rs` — one `BrowserFamily` impl per browser. Trait in `browsers/mod.rs`.
- `core/src/extract.rs` — `extract_zip`, `extract_nsis_with_7zip`, `strip_mozilla_runtime_extras`.
- `core/src/gpg.rs` — GPG + SHA-256 + SHA-512.
- `core/src/authenticode.rs` — Windows `WinVerifyTrust` signer pinning (Bitwarden); `unsafe` behind a safe wrapper.
- `core/src/hardening.rs` — Gecko `user.js` fence + `policies.json` writer.
- `core/payloads/` — vendored profiles + 7-Zip blobs.
- `core/keys/` — embedded GPG public keys.

## Build, test, run

- `cargo build --workspace`
- `cargo test --workspace` — must stay green
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --check` (see `rustfmt.toml`)
- `./dist.ps1` — release builds of all launchers
- `./check-hardening-drift.ps1` — read-only local drift check for the `arkenfox-user.js` and `ungoogled-flags.md` baselines (the on-demand equivalent of the `hardening-sync.yml` CI watcher, for local-only checkouts); `-ShowDiff` prints line-level changes

## Applying Karpathy's principles to Nomad

The global file states the principles; this section maps them to the Nomad-specific situations where they actually bite.

### Think Before Coding — where assumptions silently go wrong here

- **Adding a hardening flag or pref** → classify against SPEC §13 and arkenfox `[SETUP-HARDEN]` / 4000-series tags. If you're not sure whether it's "safe" or site-breaking, **ask before coding**. The line is judgment-heavy and the cost of guessing wrong is a regression that won't show up in tests.
- **Adding a scrub target** → opt-in (`nomad.toml` key, default off) or opt-out (always on)? AUDIT history is split: `disable_webrtc` opt-in, `sanitizeOnShutdown` opt-out, `scrub_thumbnail_cache` opt-in. Ask which model the user wants.
- **Adopting a new GPG key** → verify provenance against an official upstream channel first. Helium's empty key slot is the precedent — a wrong-purpose key (GitHub's web-flow signing key) was previously embedded and removed. Do not repopulate without explicit confirmation.

### Simplicity First — Nomad-specific overengineering to avoid

- **Do not add runtime browser detection.** Compile-time specialization (one binary per `BrowserFamily`) is load-bearing per SPEC §5.
- **Do not add `nomad.toml` keys for hypothetical needs.** Every existing knob was added in response to a specific AUDIT finding. New knobs need the same justification.
- **Defensive `Result` chains on guaranteed-safe operations are as wrong as `unwrap()`.** Match the surrounding module's style — if it propagates, propagate; if it expects in `main()` startup, do the same.

### Surgical Changes — the most dangerous failure mode in this repo

- **The per-app `BrowserFamily` impls have intentional duplication.** Compile-time specialization keeps dead code eliminated — Chromium launchers don't ship the ~2.3 MB 7-Zip blob because they never call into the NSIS path. **Do not refactor `core/src/browsers/*.rs` for similarity.** Binary-size regressions don't fail tests; they only show up in releases.
- **The Nomad-managed `user.js` block is marker-fenced.** Preserve user prefs outside the fence; re-seed only the fenced content. Never write outside the fence.
- **Vendored payloads in `core/payloads/` are pinned snapshots.** Bump them deliberately via the Task 20 automation (PRs from the upstream-diff workflow), not opportunistically while editing nearby code.

### Goal-Driven Execution — Nomad-specific success criteria

- **New scrub function** → fixture-based unit test in the same pattern as `scrub_automatic_destinations_dir_removes_matching_files` (matching file deleted, non-matching survives, missing dir doesn't panic).
- **New extract path** → end-to-end smoke test with a real installer. Precedent: 68.8 MB `Firefox Setup 138.0.exe` confirmed zero new system traces.
- **Any change** → `cargo test --workspace` 100% pass + `cargo clippy --workspace --all-targets -- -D warnings` clean.
- **Trait / `Engine` / `Config` surface change** → update [SPEC.md](SPEC.md) §3 (the trait signature *and* the crate-layout tree) in the **same** change. SPEC is the design contract; a trait method, `Engine` variant, or `nomad.toml` key that lands in code but not SPEC is the exact drift that left §3 several methods and a whole engine behind (caught + fixed 2026-06-03). Any trait method, `Engine` variant, or `nomad.toml` key added without a matching SPEC §3 edit is drift by definition.
- **"Done" for v1** = all Checkpoints A–F signed off in [tasks/todo.md](tasks/todo.md) — **complete**; v1 shipped and current work is post-v1.

## Style essentials

Only the bits not already enforced by `rustfmt.toml`:

- `#![deny(clippy::all, clippy::pedantic)]` in `core/src/lib.rs` and each launcher `main.rs`. Per-site `#[allow(...)]` requires a comment explaining the exception.
- One `thiserror` `Error` enum per module. No `anyhow` in `nomad-core` (launcher `main.rs` may use it for startup failures).
- No `unwrap()` / `expect()` outside launcher `main()` startup.
- `unsafe` only for Win32 FFI behind safe wrappers with `SAFETY:` comments — currently `taskbar.rs` (COM), `authenticode.rs` (WinVerifyTrust/crypto), `registry.rs` (SHChangeNotify), and `lib.rs` (MessageBoxW, Toolhelp, ShellExecuteW). New `unsafe` needs the same shape: safe wrapper + SAFETY comment.
- `tracing` + `EnvFilter`; default log level is `warn` (lowered from `info` per AUDIT MED-05).
- `reqwest` with `native-tls` — system trust store, never bundle a custom CA.
- Each `.exe` depends only on stock Windows 10/11 DLLs.

## Project conventions

- One binary per browser; runtime browser branching is wrong.
- LibreWolf has its **own minimal `user.js`** (`core/payloads/librewolf/user.js`), not the shared Firefox one. A pref-by-pref diff against the live `librewolf.cfg` showed 44 of 73 Firefox prefs are pure no-ops on LibreWolf (telemetry/Safe-Browsing/etc. are `lockPref`'d or `defaultPref`'d to the same values), Strict ETP subsumes the tracking-protection prefs, and RFP subsumes `fingerprintingProtection`. The minimal file keeps only genuine additions LibreWolf doesn't make: DoH (`network.trr.mode` 2 + Quad9 malware-blocking `network.trr.uri`; LibreWolf ships DoH off), `geo.enabled` off (LibreWolf only disables the OS providers), network-prediction off, WebRTC `default_address_only`, pings/beacons off, the Windows Jump-List trace pref, bookmarks-toolbar visibility, and the shutdown-sanitize block. LibreWolf still shares `firefox/policies.json` and skips the autoconfig pair (`autoconfig.js`/`nomad.cfg`) so `librewolf.cfg` is not clobbered. Never set `privacy.resistFingerprinting` (LibreWolf's RFP stays intact). The `librewolf_user_js_is_minimal*` test guards against re-pointing it at the shared Firefox profile.
- Helium has no usable upstream signing key. SHA-256-only is correct, not a gap to fix.
- The status window is transient. No tray icon, no background process, no persistent state outside the launcher directory.
- **uBlock Origin is always-on for Gecko-family browsers**, opt-out by removing it via `about:addons`. Helium ships its own built-in uBlock fork; Nomad does not provision uBlock for Helium. Ungoogled Chromium provisions uBO directly from gorhill/uBlock releases (GPG-verified tag, extracted to `nomad-extensions/uBlock0/` and loaded via `--load-extension=`). Do not reintroduce `imputnet/ublock-origin-crx` — gorhill direct-source is the required path (Decision 6).
- **Helium ships its own anti-fingerprinting framework ("Helium Noise")** — canvas-pixel noise, AudioContext jitter, and `hardwareConcurrency` randomization (2–16, believable even number), all on by default. Nomad defers those vectors to it: Helium's `HARDENING_FLAGS` omits `--fingerprinting-canvas-image-data-noise`, and Helium overrides `has_builtin_fingerprint_noise() -> true` so `build_launch_args` never layers the ungoogled `ReducedSystemInfo` (clamp-to-2) on top — that clamp would override Helium's superior randomized value. Nomad still supplies the vectors Helium Noise does **not** cover: `--fingerprinting-canvas-measuretext-noise`, `--fingerprinting-client-rects-noise`, `SpoofWebGLInfo`, `RemoveClientHints`. Do not re-add the canvas-pixel flag or force `ReducedSystemInfo` onto Helium. Ungoogled Chromium has no Helium Noise, so it keeps the full flag set including `ReducedSystemInfo`.
- **`scrub_thumbnail_cache = false` is the default** (opt-in). Windows thumbnail and icon caches record file names from portable drives; set `true` to enable scrubbing on exit. The brief Explorer restart is an acceptable trade-off on forensics-sensitive machines.
- **`disable_webrtc = true` is the default.** WebRTC STUN exposes the real WAN IP even through a VPN — it is one of the most common IP-leak vectors. Nomad is a privacy browser; video/audio calls belong in a different browser. Do not revert the default to `false`. If any task touches WebRTC handling, raise the change explicitly rather than quietly flipping the default.
- **Gecko DoH defaults to Quad9 *malware-blocking*** (`network.trr.uri` = `https://dns.quad9.net/dns-query`, 9.9.9.9) on Firefox/Floorp (`nomad.cfg` `defaultPref`, user-overridable) and LibreWolf (`librewolf/user.js`), matching the Chromium `Local State` seed. It is the documented DNS-level substitute for the disabled browser Safe Browsing (README "Trade-offs") — privacy is identical to the No-Filtering endpoint (`dns10.quad9.net`), it just refuses known-malicious domains. **Waterfox is excluded** (ships DNS-over-Oblivious-HTTP via a Fastly relay — stronger IP privacy; setting `trr.mode` would downgrade it) and **Mullvad is excluded** (own DNS). Do not "upgrade" everything to Oblivious DoH: mainline Gecko/Chromium can't configure it (Mozilla removed ODoH for OHTTP, which is not a user-selectable resolver), so Quad9 plain DoH is the only viable path. The `librewolf.rs` DoH test guards the malware-blocking endpoint.
- **Firefox/Floorp use FPP, not RFP.** `privacy.fingerprintingProtection` (FPP, in `firefox/user.js`) is the "safe" non-breaking protection; `privacy.resistFingerprinting` (RFP) is site-breaking (UTC timezones, SSO/login failures, devicePixelRatio image blur, locale→English, wrong-OS downloads — per Mozilla's docs and arkenfox). `nomad.cfg` `defaultPref`s RFP **off**. **Waterfox keeps RFP** — ESR 115 predates FPP and re-asserts it via its own `waterfox/user.js` `user_pref` (overrides the cfg default). **LibreWolf keeps its own RFP** intact. The `hardening_returns_gecko_profile_with_non_empty_user_js` test guards RFP staying off for Firefox/Floorp; do not let a `nomad.cfg` re-sync from LibreWolf re-enable it.
- **ETP "Fix major site issues" (baseline WebCompat allow-list) is ON for Firefox/Floorp** (`privacy.trackingprotection.allow_list.baseline.enabled = true`), the convenience list (`…convenience.enabled`) off. Under Strict ETP it un-blocks only Mozilla's curated, publicly-tracked essential-tracker set (`etp-exceptions.mozilla.org`) so logins/checkout/embeds don't break — it does not broadly weaken protection, and it matches Nomad's "safe" goal. **LibreWolf deliberately leaves it off** (privacy-maximalist — defer to LibreWolf, do not enable). A `firefox.rs` test guards the baseline pref staying on.
- **Mullvad declares an empty `user_js` (`""`) — Nomad writes NO `user.js` for it.** Mullvad ships its own RFP/letterboxing/standardised UA-timezone-fonts + uBO + NoScript (crowd-blending); any Nomad pref would make users distinguishable. The Gecko hardening path skips the `user.js` write — including the WebRTC/sanitize overrides — when `user_js` is empty, and `hardening::remove_managed_user_js` strips any block a prior version left behind. Mullvad creates `%LOCALAPPDATA%\Mullvad\MullvadBrowser` (its own brand dir, *not* covered by `GECKO_BRAND_DIRS`); `scrub_mullvad_runtime_dir` removes just that subdir and the parent only if empty, so a co-installed Mullvad VPN's data is preserved. Verification is GPG (Tor key) + SHA-256.
- **`nomad-bitwarden.exe` is the first non-browser launcher — the official Bitwarden *desktop app* (Electron), not a browser, not built from source.** It reuses the whole pipeline via `BrowserFamily` with a dedicated `Engine::Electron` variant (so the Chromium/Gecko launch-flag gates in `build_launch_args` never fire). The browser extension is ruled out (fingerprinting + DEF CON 33 clickjacking). Load-bearing facts future-you will be tempted to "fix":
  - **Wrap the official portable `.exe`, never the APPX and never build from source.** The `-x64.appx` is *inert* when unpacked (depends on MSIX package identity — spawns an Electron tree but creates no window/userData; verified in Step 0). `build.rs` is lenient (no placeholder-icon guard). Do not reintroduce the APPX or a source build.
  - **Release resolution: list `bitwarden/clients` releases and pick the newest non-prerelease `desktop-v…` tag** (`DEFAULT_RELEASES_URL` = `.../releases?per_page=100`, `latest_desktop_release`). NOT `releases/latest` — that repo interleaves browser-extension/desktop/CLI/web releases, so `latest` returns the wrong product (this was a real shipped bug). `github::fetch_releases` + the `prerelease` field exist for this.
  - **Verification = SHA-256 (GitHub digest) + Authenticode signer pin** (`authenticode::verify_signed_by(package, "Bitwarden Inc.")` called at the top of `extract()` before staging). No GPG key upstream — that is correct, not a gap (Helium precedent), and Authenticode is the publisher anchor. `public_key()` is `None`; `verify_signature` is never called.
  - **`extract()` is verify-and-stage, not unzip.** The portable `.exe` *is* the runnable artifact; `stage_executable` renames it to the stable `Bitwarden-Portable.exe` (split out so the staging test bypasses the signature gate).
  - **Vault lives *inside* `install_dir` at `App\Data`** (`DATA_DIRNAME`), set via `BITWARDEN_APPDATA_DIR` in `launch_command`, plus `ELECTRON_NO_UPDATER=1`. Because the swap replaces `install_dir` wholesale, Bitwarden overrides `preserve_state_across_update` to copy `App\Data` into the stage before `atomic_swap`. Do not move the vault outside `install_dir` without keeping the preserve hook, and do not drop the hook.
  - **Per-app config:** `BrowserFamily::default_config()` (trait default = `config::DEFAULT_NOMAD_TOML`) is overridden to `bitwarden::DEFAULT_CONFIG` — a trimmed `nomad.toml` listing only the keys that affect an Electron app; the browser-only privacy keys (incognito/disable_webrtc/reduce_system_info/enabled/sanitize_on_shutdown/clear_data_on_exit/language/arch) are inert for `Engine::Electron` and omitted. `Config::load_or_init(dir, default_config)` writes the supplied default; `run_with_ui` resolves arch first so `make` is called once. `Bitwarden::new` ignores `arch` (single portable build).
  - **No Windows Hello** (installer-only) — master-password unlock only; do not chase biometric support (it conflicts with zero-footprint). The launcher icon is the official Bitwarden `.ico`.
