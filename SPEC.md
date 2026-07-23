# SPEC.md — Nomad Launcher

## 1. Objective

Nomad Launcher is a family of portable Windows browser launchers. Each launcher is a single self-contained executable, `nomad-<browser-id>.exe`, that updates, privacy-hardens, and launches exactly one browser from a local directory. No installer. No registry writes during normal operation. Distributable to end users as-is.

**Inspiration:** chrlauncher, expanded to cover Firefox-family browsers and more.

**Success criteria for v1.0:**
- User can drop `nomad-<browser-id>.exe` into any folder on any drive and have that browser downloaded, updated, and launched with no installation step.
- All browser binaries are verified against a SHA-256 hash, and against a GPG signature where the upstream publishes one.
- Each launched browser receives Nomad's curated "safe" privacy-hardening profile — launch flags for Chromium-family browsers, a layered `user.js` + `policies.json` for Gecko-family browsers — that maximizes privacy without breaking websites.
- Each launcher executable carries its own browser-branded icon (embedded at compile time).
- A transient status window shows progress during update and launch, then closes itself once the browser starts.
- Config round-trips correctly; accidental config edits produce clear errors, not silent failures.

---

## 2. Browser Support

Each browser (and channel) ships as its own launcher binary. v1 produces nine binaries.

### v1 MVP
| Binary | Browser | Update Source | Signature |
|--------|---------|---------------|-----------|
| `nomad-ungoogled-chromium.exe` | ungoogled-chromium | GitHub releases API (`ungoogled-software/ungoogled-chromium-windows`) | SHA-256 only |
| `nomad-firefox.exe` | Firefox Stable | Mozilla Product Details API (`product-details.mozilla.org`) | GPG + SHA-256 |
| `nomad-firefox-esr.exe` | Firefox ESR | Same API, ESR channel (hardcoded in the launcher) | GPG + SHA-256 |
| `nomad-floorp.exe` | Floorp | GitHub releases API (`Floorp-Projects/Floorp`) | SHA-256 only |
| `nomad-waterfox.exe` | Waterfox | GitHub releases API (`BrowserWorks/waterfox`) | SHA-256 only |
| `nomad-helium.exe` | Helium | GitHub releases API (`imputnet/helium-windows`) | SHA-256 only |
| `nomad-librewolf.exe` | LibreWolf | GitLab releases API (`librewolf-community/browser/windows`) | SHA-256 only |
| `nomad-mullvad.exe` | Mullvad Browser | GitHub releases API (`mullvad/mullvad-browser`) | GPG + SHA-256 |

Notes:
- **Helium** — upstream signs commits via GitHub's web-flow key, which cannot produce detached signatures for release assets; no usable GPG key is available for embedding. SHA-256 only; absence of GPG signature logged at `WARN`.
- **LibreWolf** — ships pre-hardened; Nomad applies a thin `policies.json`-only override rather than the full arkenfox `user.js` stack (see §5). No upstream GPG signing key usable for release asset verification. SHA-256 only.
- **Mullvad Browser** — ships its own complete anti-fingerprinting stack (RFP, letterboxing, standardized UA / timezone / fonts) plus uBlock Origin and NoScript; Nomad applies **no** `user.js` and provisions **no** uBO, writing only a `DisableAppUpdate` `policies.json` (see §5) so its crowd-blending model stays intact. Verified with the Tor Browser Developers GPG key (`core/keys/mullvad.asc`) plus the SHA-256 GitHub asset digest.
- Patching the downloaded browser's own icon resources (PE resource editing) is deferred to post-v1.

### Non-browser apps

The same launcher pipeline (download → verify → stage → atomic-swap → launch) also wraps one non-browser application. It is a deliberate generalization: the value is the portable update/launch machinery, which is engine-agnostic.

| Binary | App | Update Source | Signature |
|--------|-----|---------------|-----------|
| `nomad-bitwarden.exe` | Bitwarden desktop (Electron) | GitHub releases (`bitwarden/clients`, newest stable `desktop-v…` tag) | SHA-256 + Authenticode |

Notes:
- **Bitwarden** — the official portable desktop app, not a browser and not built from source. `engine()` returns the dedicated `Engine::Electron` variant so the Chromium/Gecko-gated launch-flag injection never applies. The repo publishes browser-extension/desktop/CLI/web releases into one stream, so the launcher lists releases and selects the newest non-prerelease tag prefixed `desktop-v` (`releases/latest` would return the wrong product). The `-x64.appx` is **not** used — extracted from its MSIX package it is inert (spawns an Electron tree but creates no window or userData); the portable `.exe` is built for standalone use and is the only viable artifact. Verified with SHA-256 (GitHub asset digest) **plus an Authenticode signer check** (`WinVerifyTrust` with whole-chain revocation + signer subject must equal `Bitwarden Inc.`; see §9) — Bitwarden publishes no GPG key. Made portable and Nomad-updatable via two env vars at launch: `BITWARDEN_APPDATA_DIR` (redirects the vault to `App\Data` *inside* the install dir) and `ELECTRON_NO_UPDATER=1` (disables the built-in updater). Because the vault lives inside `install_dir`, it is carried across the update swap by `preserve_state_across_update`. Ships a trimmed per-app `nomad.toml` via `BrowserFamily::default_config` (browser-only privacy keys omitted). No Windows Hello (installer-only); master-password unlock only.

---

## 3. Architecture

Nomad Launcher is a Cargo workspace with one shared library crate and one binary crate per browser launcher. All shared logic lives in the core crate; each launcher binary is a thin entry point that instantiates a single `BrowserFamily` and hands it to the core runner.

### Crate layout (Cargo workspace)
```
nomad-launcher/
  Cargo.toml                  # workspace root
  core/                       # shared library crate (nomad-core)
    src/
      lib.rs                  # pub fn run(browser: impl BrowserFamily); orchestration + scrub_*
      config.rs               # nomad.toml load/save/validate
      updater.rs              # launch-time update check + atomic-swap driver
      version_cache.rs        # nomad-version-cache.toml (4 h TTL release/uBO cache)
      downloader.rs           # HTTP download with progress
      gpg.rs                  # pure-Rust GPG verification + SHA-256 / SHA-512
      authenticode.rs         # WinVerifyTrust signer pinning (Bitwarden)
      extract.rs              # extract_zip, extract_nsis_with_7zip, strip_mozilla_runtime_extras
      install.rs              # atomic_swap of a staged install over the live install
      hardening.rs            # privacy hardening: Gecko user.js/policies.json writer
      extensions.rs           # Chromium uBO provisioning (gorhill releases → --load-extension)
      branding.rs             # Gecko omni.ja rebrand + userChrome/userContent assets (Focus)
      registry.rs             # optional default browser registration
      taskbar.rs              # taskbar progress (ITaskbarList3)
      ui/
        mod.rs                # transient status window (egui)
        identity.rs           # identity card widget
        theme.rs              # Nomad dark palette
      browsers/
        mod.rs                # BrowserFamily trait + shared types (Engine, Hardening, VersionInfo)
        github.rs             # shared GitHub Releases API helper
        helium.rs
        ungoogled.rs
        firefox.rs            # Firefox stable + ESR (new_esr); no firefox_esr.rs
        floorp.rs
        waterfox.rs
        librewolf.rs
        mullvad.rs
        bitwarden.rs          # non-browser: official Bitwarden desktop app (Engine::Electron)
    keys/                     # embedded ASCII-armored public keys
      firefox.asc
      helium.asc              # placeholder slot — Helium has no usable key (SHA-256 only)
      mullvad.asc
      gorhill.asc             # uBlock Origin release-tag signing key (Chromium uBO)
    payloads/                 # vendored user.js, Chromium flag sets, 7-Zip blobs (include_bytes!/include_str!)
  launchers/                  # one binary crate per browser (+ Bitwarden, a desktop app)
    ungoogled-chromium/       # package nomad-ungoogled-chromium
      Cargo.toml
      build.rs                # winresource: embed launcher icon
      icon.ico
      src/main.rs
    helium/
    firefox/
    firefox-esr/
    floorp/
    waterfox/
    librewolf/
    mullvad/
    bitwarden/                # package nomad-bitwarden (Electron desktop app; reuses the pipeline)
  tests/
    integration/              # integration tests (mock HTTP, fake FS)
    fixtures/                 # test archives, fixture JSON, test keys
```

### Launcher binary

Each `launchers/<browser>/src/main.rs` is minimal — it selects the browser and delegates everything to the core runner:

```rust
fn main() -> std::process::ExitCode {
    nomad_core::run(nomad_core::browsers::Firefox::stable())
}
```

The package name (e.g. `nomad-firefox`) determines the output binary name `nomad-firefox.exe`. Each launcher crate has a `build.rs` that uses `winresource` to embed its browser-branded `icon.ico` into the executable at compile time.

### Core trait

```rust
pub trait BrowserFamily: Send + Sync {
    // ── Required ──────────────────────────────────────────────────────────
    fn id(&self) -> &'static str;            // e.g. "ungoogled-chromium"
    fn display_name(&self) -> &'static str;  // e.g. "Ungoogled Chromium"
    fn engine(&self) -> Engine;              // Chromium | Gecko | Electron
    fn public_key(&self) -> Option<&'static [u8]>; // ASCII-armored PGP key, if upstream signs

    fn installed_version(&self, install_dir: &Path) -> Option<InstalledVersion>;

    // Async methods use RPITIT (`impl Future + Send`), not `async fn` — the
    // trait is object-safe-adjacent and avoids the `async_trait` macro.
    fn fetch_latest_version(&self) -> impl Future<Output = Result<VersionInfo>> + Send;
    fn download(&self, info: &VersionInfo, dest: &Path, progress: ProgressSink)
        -> impl Future<Output = Result<()>> + Send;
    fn verify_signature(&self, package: &Path, sig: &Path) -> Result<()>; // only called when public_key() is Some
    fn extract(&self, package: &Path, install_dir: &Path) -> Result<()>;

    fn hardening(&self) -> Hardening;
    fn launch_command(&self, install_dir: &Path, args: &[String]) -> Command;
    fn upstream_url(&self) -> &'static str;  // status-window footer release link

    // ── Defaulted (override only when a member genuinely differs) ──────────
    fn default_config(&self) -> &'static str { DEFAULT_NOMAD_TOML }              // non-browser apps trim this (Bitwarden)
    fn profile_dir(&self, install_dir: &Path) -> Option<PathBuf> { None }        // Gecko: portable profile dir
    fn preserve_state_across_update(&self, current: &Path, stage: &Path) -> Result<()> { Ok(()) } // Bitwarden
    fn has_builtin_fingerprint_noise(&self) -> bool { false }                   // Helium Noise
    fn accent(&self) -> egui::Color32 { theme::ACCENT }                          // per-launcher accent colour
    fn prepare_launch(&self, install_dir: &Path, cfg: HardeningConfig) -> Result<()> { Ok(()) } // best-effort staging
    fn fetch_extension_updates(&self, install_dir: &Path, cfg: HardeningConfig, opts: UpdateOptions)
        -> impl Future<Output = Result<()>> + Send;                             // default: provision Gecko uBO XPI
}
```

- `Engine` is `Chromium`, `Gecko`, or `Electron`. `Electron` (Bitwarden's desktop app) exists so the Chromium/Gecko launch-flag injection in `build_launch_args` never fires for a non-browser app.
- `public_key()` returns `None` for browsers whose upstream does not publish GPG signatures; verification then falls back to SHA-256 (or SHA-512 for Waterfox), plus Authenticode signer pinning for Bitwarden.
- `VersionInfo` carries: browser version, underlying engine version, download URL, optional signature URL, optional SHA-256 hash, optional SHA-512 hash.
- `InstalledVersion` carries the browser version and engine version parsed from the local install.
- `hardening()` returns the browser's privacy-hardening payload (see §5): `Hardening::LaunchFlags { flags, local_state, preferences }` for Chromium-family browsers (flags appended at launch, JSON state seeded), `Hardening::GeckoProfile { user_js, policies, autoconfig, cfg, ublock_xpi_releases_url }` for Gecko-family browsers (files written into the install).
- `ProgressSink` is a `tokio::sync::watch::Sender<f32>` (0.0–1.0).
- The seven defaulted methods keep the common case to zero boilerplate; only the member named in each trailing comment overrides it.

---

## 4. Configuration

File: `nomad.toml`, sitting beside its launcher `.exe`. Each launcher has its own config, scoped to that one browser — there is no browser array.

```toml
[browser]
install_dir = "browser"      # relative to the .exe directory
arch = "x64"                 # "x64" | "x86" | "arm64"

[update]
check_on_launch = true       # false = skip the update check, launch immediately
auto_download = true         # false = prompt in the status window before downloading

[launch]
language = "en-US"           # passed as --lang to browsers that accept it
extra_args = []              # additional command-line arguments

[hardening]
enabled = true               # false = launch with no privacy hardening applied
clear_data_on_exit = false   # true = wipe Chromium cookies/sessions/history on exit (Chromium-only; breaks "stay signed in")
scrub_prefetch = false       # true = delete Windows Prefetch entries on exit (requires UAC prompt for non-admin accounts)
```

Rules:
- All paths are relative to the `.exe`'s directory (portability guarantee).
- There is no `channel` key — the Firefox ESR launcher hardcodes its channel internally; all other browsers have a single channel.
- Unknown keys are rejected at startup with a descriptive error (no silent ignoring).
- On first run with no `nomad.toml`, a default config is written beside the `.exe` and launch proceeds with defaults.
- Config is read once per launch; there is no live reload (the process is short-lived).

---

## 5. Privacy Hardening

Automated privacy hardening is Nomad's core value. The browsers Nomad manages are privacy-respecting, but none ships fully hardened out of the box — each needs configuration to reach its privacy potential. Nomad applies a curated **"safe" hardening profile** on every launch. The goal is to maximize privacy and reduce tracking and fingerprinting **without breaking website functionality**. Nomad deliberately does *not* apply aggressive, site-breaking measures (e.g. full fingerprint-resistance / RFP, disabling WebGL); those are out of scope.

Each `BrowserFamily` declares its hardening payload through `hardening()`, returning a `Hardening` value:

```rust
enum Hardening {
    /// Chromium-family: flags appended to the launch command, plus optional
    /// JSON state seeds (`Local State`, `Default/Preferences`). See §5 below.
    LaunchFlags {
        flags: &'static [&'static str],
        local_state: Option<&'static str>,
        preferences: Option<&'static str>,
    },
    /// Gecko-family: a marker-fenced user.js, an optional policies.json, an
    /// optional autoconfig pair (autoconfig.js + .cfg), and an optional AMO
    /// uBlock XPI URL — all embedded/resolved at compile time. `autoconfig`
    /// and `cfg` are `None` for forks shipping their own (e.g. LibreWolf);
    /// `ublock_xpi_releases_url` is `None` for browsers bundling uBlock.
    GeckoProfile {
        user_js: &'static str,
        policies: Option<&'static str>,
        autoconfig: Option<&'static str>,
        cfg: Option<&'static str>,
        ublock_xpi_releases_url: Option<&'static str>,
    },
}
```

Hardening runs on every launch (after extraction, and on launches where no update occurred), so a user-edited install is re-seeded each time. It is on by default and controlled by `[hardening] enabled` in `nomad.toml` (§4); when disabled, no flags are added and no files are written.

### Chromium-family (ungoogled-chromium, Helium) — launch flags + state seed

Chromium hardening uses three surfaces with distinct purposes:

1. **Command-line flags** (`HARDENING_FLAGS` in each browser module) — re-applied every launch, cannot be disabled by the user via the browser UI. This is the **enforcement** layer.
2. **`local_state.json` seed** (`payloads/chromium/local_state.json`) — written once into `<user-data-dir>/Local State`, surfaces in `chrome://flags`, and seeds DNS-over-HTTPS to Quad9 secure mode. Reserved for `chrome://flags` toggles that only accept value-typed settings (e.g. `extension-mime-request-handling@2`) and for non-flag config (DoH).
3. **`preferences.json` profile-pref seed** (`payloads/chromium/preferences.json`) — value-typed prefs with no `--flag` switch: HTTPS-Only mode, Do Not Track, network-prediction off, third-party-cookie block, the Sensors content-setting block, `canMakePayment`/Media Router off, search-suggest/translate/alternate-error-pages off, Privacy Sandbox m1. Merged into `<user-data-dir>/Default/Preferences` every launch with **"user-wins"** scalar semantics; a privacy-critical subset (`LOCKED_SCALAR_PATHS` — HTTPS-Only, Safe Browsing off, Privacy Sandbox m1, DoH) is force-re-applied so the browser or a tampered profile cannot silently re-enable it.

**First-run clobber (why surface 3 also rides in `initial_preferences`).** Chromium's first-run pipeline *regenerates* `Default/Preferences` from the `initial_preferences` template next to `chrome.exe`, discarding whatever Nomad wrote to `Default/Preferences` beforehand. So on a brand-new profile the surface-3 seed alone is inactive for the entire first session and only "heals" on the second launch (when `--no-first-run` is set and Chromium loads Nomad's seeded file normally). To make the hardening active on the first run, `prepare_launch` merges `preferences.json` into the `initial_preferences` payload via `hardening::build_initial_preferences()` — the one seed path Chromium honours on first profile creation, the same path that carries the MAC-protected `extensions.ui.developer_mode`. `preferences.json` remains the single source of truth (surface 3 still maintains established profiles); `Local State` is unaffected because Chromium merges that store rather than regenerating it. Verified end-to-end against ungoogled-chromium and guarded by `merged_initial_preferences_carry_developer_mode_and_profile_hardening`.

The command-line set is the **safe subset** of ungoogled-chromium's documented switches:

- **Portability (Windows-mandatory):** `--disable-machine-id`, `--disable-encryption`.
- **Stock Chromium hygiene:** `--disable-sync`, `--disable-background-networking`, `--disable-breakpad`, `--disable-component-update`, `--disable-features=JumpList`, `--no-default-browser-check`, `--disable-top-sites`.
- **Anti-tracking / fingerprinting:** `--disable-search-engine-collection`, `--fingerprinting-canvas-image-data-noise`, `--fingerprinting-canvas-measuretext-noise`, `--fingerprinting-client-rects-noise`, `--force-punycode-hostnames`.
- **Network / TLS privacy:** `--no-pings`, `--disable-grease-tls`, `--http-accept-header=…` (Tor Browser's value, pairs with `--disable-grease-tls`), `--webrtc-ip-handling-policy=default_public_interface_only`.
- **Bundled features** (single `--enable-features=` because Chromium honours only the last one): `RemoveClientHints`, `SpoofWebGLInfo`, `MinimalReferrers` (strips cross-origin referrers, minimises same-origin to origin only — the single biggest passive-tracking mitigation).

Flags upstream marks as **potentially breaking** are excluded from the default set — notably `--disable-webgl`, `disable-beforeunload`, `NoReferrers`, and `NoCrossOriginReferrers`. The one exception Nomad ships **on by default** is the `ReducedSystemInfo` feature (see `reduce_system_info` below): clamping `navigator.hardwareConcurrency` is in line with how Tor/Brave behave, its real-world impact is a modest perf trade-off rather than hard breakage, and it remains user-disablable.

**Optional `[hardening] clear_data_on_exit`** (default `false`) — when `true`, Nomad appends/merges the `ClearDataOnExit` feature into the `--enable-features=` bundle, wiping cookies/sessions/history on every Chromium exit. Off by default because it breaks session continuity (signed out of every site each launch).

**`[hardening] reduce_system_info`** (default `true`, Chromium-family only) — Nomad merges the `ReducedSystemInfo` feature into the same `--enable-features=` bundle: system details exposed via headers/JS are reduced and `navigator.hardwareConcurrency` reports two cores, shrinking fingerprint entropy (CPU-core count is a stable identifier). On by default for the fingerprint reduction; set `false` to disable if you hit slowdowns in apps that size worker/thread pools from `hardwareConcurrency` (in-browser video encoders, some WASM workloads, heavy editors). The serde default is `true`, so configs that omit the key (including those written before the option existed) still get it.

**`[hardening] scrub_prefetch`** (default `false`, all browsers) — when `true`, the cleanup watcher attempts to delete Windows Prefetch entries (`C:\Windows\Prefetch\`) for the launcher and browser executables after each browser exit. Prefetch entries record the full executable path and run timestamps, so removing them reduces forensic traces on the portable medium. Requires administrator privileges: a UAC elevation prompt appears on every browser close for non-admin accounts. Defaults to `false` (opt-in) — the per-exit UAC dialog is disruptive for regular use and would condition users to approve launcher-sourced elevation prompts. Enable only on forensics-sensitive machines where you control the account type. The cleanup watcher skips this step entirely when the flag is absent, so there is no performance cost on the default path. Note: `scrub_shell_recent` and `scrub_automatic_destinations` (Recent Items / JumpList trace removal) are always-on when the launcher is on a **removable drive** (`GetDriveTypeW == DRIVE_REMOVABLE`); they are automatically skipped on fixed drives to prevent wiping the user's system-wide Recent history.

**Helium exception.** Helium ships its own anti-fingerprinting framework ("Helium Noise") that already noises canvas pixels and AudioContext and **randomizes** `hardwareConcurrency` (2–16) by default — a more complete and less detectable approach than the ungoogled flags. So for Helium, Nomad defers those vectors to Helium Noise: it omits `--fingerprinting-canvas-image-data-noise` from Helium's flag set and never applies `ReducedSystemInfo` (gated by `BrowserFamily::has_builtin_fingerprint_noise()`), since `ReducedSystemInfo`'s clamp-to-`2` would override Helium's randomized value. Nomad still supplies the vectors Helium Noise does not cover (`measuretext`/`client-rects` noise, `SpoofWebGLInfo`, `RemoveClientHints`). Ungoogled Chromium has no Helium Noise and keeps the full set.

### Gecko-family (Firefox, LibreWolf, Floorp, Waterfox) — layered profile

Two layers, both written into `install_dir`:

1. **`user.js`** — a Nomad-curated "safe" profile derived from the arkenfox `user.js` template: the arkenfox core sections minus every preference arkenfox itself tags as site-breaking (`[SETUP-WEB]`), aggressive (`[SETUP-HARDEN]`), or optional (sections 4000+, including RFP). The Nomad-written block is fenced with marker comments; preferences outside the fence — including the user's own — are preserved, and the block is re-seeded idempotently on every launch.
2. **`policies.json`** — written to `<install_dir>/distribution/policies.json`. Carries the structural locks `user.js` cannot enforce: disable the browser's built-in updater (Nomad is the sole updater), disable telemetry / studies / crash reporting, disable Pocket and Firefox accounts. This file is fully Nomad-managed.

### LibreWolf — own minimal `user.js`, shares `policies.json`, skips the autoconfig pair

LibreWolf already ships arkenfox-equivalent hardening, so the full Firefox `user.js` is almost entirely redundant on it. A pref-by-pref diff against the live `librewolf.cfg` confirmed it: 44 of 73 Firefox prefs are no-ops (telemetry, Safe Browsing, prefetch, search suggestions, `sessionstore.privacy_level`, referrer trimming, disk cache, HTTPS-only, `app.update` — all `lockPref`'d or `defaultPref`'d to the same values), Strict ETP (`browser.contentblocking.category = "strict"`) subsumes the tracking-protection prefs, and `privacy.resistFingerprinting` subsumes `privacy.fingerprintingProtection`. Many of the redundant prefs are `lockPref`'d, so Nomad could not override them even if it tried.

LibreWolf therefore gets its **own minimal `user.js`** (`payloads/librewolf/user.js`) containing only the genuine additions LibreWolf does not make itself: DoH (`network.trr.mode` 2 — LibreWolf ships it **off** at mode 5, the single biggest divergence), `geo.enabled` off (LibreWolf disables the OS providers but not the API), network-prediction off, WebRTC `default_address_only`, pings/beacons off, the Windows Jump-List host-trace pref, bookmarks-toolbar visibility, and the shutdown-sanitize block. Nomad never sets `privacy.resistFingerprinting`, so LibreWolf's RFP stays intact.

LibreWolf still shares `firefox/policies.json` (the structural updater/telemetry/Pocket locks). What it does **not** receive is Nomad's autoconfig pair (`autoconfig.js` + `nomad.cfg`): LibreWolf ships its own `defaults/pref/local-settings.js` + `librewolf.cfg`, and Nomad must not clobber them (so `autoconfig` and `cfg` are `None` in its `GeckoProfile`). Because each launcher is its own binary built around exactly one `BrowserFamily`, this is a compile-time distinction — there is no runtime browser detection.

### Sourcing and maintenance

The arkenfox-derived profile and the Chromium flag sets are **vendored** — pinned snapshots embedded in `nomad-core` via `include_str!`, never fetched at runtime (runtime fetch would break offline / USB use and add a per-launch failure mode). They are bumped deliberately, tracking upstream arkenfox releases and ungoogled-chromium flag changes.

The AMO-signed uBlock Origin XPI (Gecko) and the gorhill `uBlock0_X.X.X.chromium.zip` (Ungoogled Chromium) are the explicit runtime-fetch exceptions: the AMO XPI is downloaded because Gecko requires a Mozilla-signed artifact that Nomad cannot reproduce; the gorhill zip is fetched after the release tag's GPG signature is verified against the embedded gorhill key (`F5630CAE62A14316`) **and** the asset's upload timeline passes a tamper check (`github::asset_provenance_suspect`). The tag signature authenticates the release event only — GitHub release assets are mutable independently of the signed tag, gorhill publishes no asset checksums, and the zip bundles unpinned `uBlockOrigin/uAssets` content so it cannot be rebuilt from the signed tree — so an asset replaced or re-uploaded after publication is detected by its timeline and the update deferred. Nomad remains the sole updater for the extension binary.

---

## 6. Branding

v1 branding is limited to the launcher executables themselves:

- Each launcher crate embeds a browser-branded `icon.ico` into its `.exe` at compile time via a `winresource` build script. `nomad-firefox.exe` carries a Firefox-branded icon, and so on.
- The status window's identity card displays the browser's logo and brand colors (see §7), matching the Nomad mockups.

Patching the **downloaded browser's** own icon/resource data (PE resource editing) is **deferred to post-v1**. v1 does not modify the browser binaries' resources.

### PE Version Metadata (Windows exe Properties → Details)

Each launcher's `build.rs` sets the following `winresource` fields in addition to the icon:

| Field | Value |
|---|---|
| `FileDescription` | `Nomad Launcher — <DisplayName>` (e.g. `Nomad Launcher — Firefox`) |
| `ProductName` | `Nomad Launcher` |
| `FileVersion` | Nomad Launcher version (e.g. `0.1.0`) — updated at each release |
| `ProductVersion` | Same as `FileVersion` |
| `InternalName` | `nomad-<browser-id>` (e.g. `nomad-firefox`) |
| `OriginalFilename` | `nomad-<browser-id>.exe` (e.g. `nomad-firefox.exe`) |
| `LegalCopyright` | `© 2026 Cyph3rpuNk-dev` |

`CompanyName` is not set. `FileVersion` and `ProductVersion` track the Nomad Launcher release version, not the browser version it manages.

---

## 7. UI — Transient Status Window (egui / eframe)

There is no tray icon and no persistent window. Running `nomad-<browser>.exe` opens a single transient status window that lives only for the duration of the update-and-launch sequence, then closes itself.

### Design language
"Nomad dark" palette — the design tokens (palette + type/spacing/radius/motion
scales) live in `core/src/ui/theme.rs`; see `DESIGN.md` for the full system.
Unified chrome across all nine launchers; per-browser differentiation is the
identity card's logo + name, plus an optional accent override
(`BrowserFamily::accent`, default = the family amber accent). The footer carries
the shared Nomad mark + wordmark.

| Token | Hex | Use |
|-------|-----|-----|
| Background | `#202124` | Window body |
| Card surface | `#292A2D` | Identity card, runtime details card |
| Border / track | `#3C4043` | Card borders, progress-bar track |
| Secondary text | `#9AA0A6` | Labels, captions, detail text |
| Primary text | `#E8EAED` | Browser name, status line, values |
| Accent / link | `#E8B255` | amber accent — progress-bar fill, links, Nomad mark, themed buttons. Family default; per-browser overridable. |
| Eyebrow text | `#80868C` | Tiny uppercase section labels (WCAG AA on the card surface) |

The title bar is the OS-drawn standard decoration reading "`<Browser>` — Nomad
Launcher" (minimize / close); egui does not paint it, so there is no separate
title-bar colour token. Font: **Atkinson Hyperlegible** (SIL OFL, Braille
Institute) — vendored at `core/payloads/fonts/` and embedded; eframe is built
without `default_fonts`, so the bundled Ubuntu/emoji/mono are *not* shipped
(saves ~1.3 MB per launcher). Deterministic across machines, not the host
system font. Window size: **460 × 380 px** (fixed, non-resizable).

### Window layout
A narrow window containing two stacked cards and a footer link.

**1. Identity card** (`#292A2D`, 6 px radius)
- Top row: browser logo (34×34, the browser's own brand colors) + display name (15 px, `#E8EAED`) + version subtitle (11 px, `#9AA0A6`).
- **Version subtitle format (uniform across all nine launchers):** `{browser_version} — {engine} {engine_version} (Portable)`. The ` — {engine} {engine_version}` segment is omitted when the browser version and engine version are identical, leaving `{browser_version} (Portable)`. Examples: `1.19.12b — Firefox 150.0.2 (Portable)`; `148.0.7778.96 (Portable)`.
- A hairline divider separates the identity row from the status block.
- Eyebrow label: `PORTABLE LAUNCHER` (9 px, uppercase, letter-spaced, `#80868C`).
- Primary status line (14 px, `#E8EAED`) — the current phase, e.g. "Checking for updates…", "Downloading 127.0…", "Verifying signature…", "Extracting…", "Writing profile defaults…", "Launching browser…".
- Secondary detail line (11 px, `#9AA0A6`) — a finer-grained sub-step.
- Progress bar (3 px tall, track `#3C4043`, fill `#E8B255`) — driven by `ProgressSink` during download; indeterminate (animated) during check / verify / extract phases.

**2. Runtime details card** (`#292A2D`, 6 px radius)
- Eyebrow label: `RUNTIME DETAILS` (9 px, uppercase, letter-spaced, `#80868C`).
- Key/value rows (11 px; key `#9AA0A6`, value `#E8EAED`):
  - **Name** — runtime id + arch, e.g. `ungoogled-chromium x64`
  - **Bundle mode** — `Self-updating portable`
  - **`<Browser>` version** — the browser's own version
  - **Build date** — build date, or `—` when unknown

**3. Footer** — left: "Open upstream release page" link (`#E8B255`), opens the browser's upstream release page in the system default browser. Right: the shared Nomad brand lockup — the Nomad emblem + `NOMAD` wordmark (the family signature; emblem from `core/payloads/nomad/`, wordmark in the accent; see `DESIGN.md`).

### Behavior
- **Auto-close** — once the browser process is spawned, the window closes itself automatically. No user interaction is required on the happy path.
- **Update available, `auto_download = false`** — the status block shows the new version with two buttons: "Update" and "Launch current". The window waits for the user.
- **Error** — on any failure (network, GPG, hash, extract) the window does *not* auto-close. It shows the error message and offers "Retry" and, where a usable install already exists, "Launch anyway" and "Close".

### Taskbar progress
While the window is open and a download is active, the taskbar button shows the Windows progress overlay via `ITaskbarList3` (`TBPF_NORMAL` during download → `TBPF_NOPROGRESS` on completion → `TBPF_ERROR` on failure).

---

## 8. Update & Launch Flow

Update checks happen only at launch time. There is no background interval loop and no long-lived process.

```
nomad-<browser>.exe started
  ├── load nomad.toml (or write defaults on first run)
  ├── open transient status window with identity card
  │
  ├── if update.check_on_launch == false:
  │     └── go straight to PREP
  │
  ├── status: "Checking for updates…"
  │     fetch_latest_version()  →  VersionInfo
  │     compare with installed_version()
  │
  ├── if up-to-date:
  │     └── go to PREP
  │
  ├── if newer available:
  │     ├── if auto_download == false:
  │     │     wait for user → "Update" or "Launch current"
  │     └── on "Update" (or auto_download == true): go to DOWNLOAD
  │
  DOWNLOAD:
  ├── status: "Downloading <version>…"   (progress bar driven by ProgressSink)
  │     downloader::fetch(url)  →  {tmp_pkg}
  │     if VersionInfo has a signature URL:
  │       downloader::fetch(sig_url)  →  {tmp_sig}
  ├── status: "Verifying signature…"
  │     if public_key() is Some and a signature was fetched:
  │       gpg::verify(tmp_pkg, tmp_sig, public_key())
  │         Err  →  delete tmp files, show error state
  │     else: log WARN "no GPG signature; SHA-256 only"
  │     sha256::verify(tmp_pkg, expected_hash)
  │       Err  →  delete tmp files, show error state
  ├── status: "Extracting…"
  │     browser.extract(tmp_pkg, install_dir)
  │     delete tmp files
  │
  PREP:
  ├── status: "Applying privacy hardening…"
  │     Gecko:    write the marker-fenced user.js + distribution/policies.json
  │     Chromium: no files written — hardening flags are added at LAUNCH
  │
  LAUNCH:
  ├── status: "Launching browser…"
  │     spawn browser.launch_command(install_dir, args)
  │       (Chromium-family: the safe hardening flags are appended here)
  └── auto-close the status window
```

Partial downloads do not survive a crash: any `.tmp` files in `install_dir` are deleted at the start of the next launch.

---

## 9. Signature & Hash Verification

- Every download is verified against the expected SHA-256 hash before extraction.
- Where the upstream publishes a GPG detached signature, the package is additionally verified against an embedded ASCII-armored public key using the `pgp` crate (pure Rust, MIT/Apache-2.0).
- **GPG-verified browsers:** Firefox Stable, Firefox ESR (Mozilla release key) and Mullvad Browser (Tor Browser Developers key, plus the SHA-256 GitHub asset digest). Keys are embedded into `nomad-core` via `include_bytes!` from `core/keys/<browser>.asc`.
- **Authenticode-verified apps:** Bitwarden. It publishes no GPG key, so in addition to the SHA-256 GitHub asset digest, `core/src/authenticode.rs` runs `WinVerifyTrust` (generic-verify policy, no UI, whole-chain revocation checking with a no-revocation fallback when the revocation status is undeterminable) and extracts the signer certificate's subject via `CryptQueryObject`/`CryptMsgGetParam`/`CertGetNameStringW`; the subject must equal `Bitwarden Inc.` (case-insensitive) or the package is rejected before staging. This is a publisher pin on top of the byte pin — the spirit of GPG verification for an artifact with no GPG key. Windows-only; `unsafe` is confined behind a safe wrapper.
- **Hash-only browsers:** ungoogled-chromium, Floorp, Helium, LibreWolf (SHA-256) and Waterfox (SHA-512, from the `.sha512` file published beside each CDN installer). For these, `public_key()` returns `None`, `verify_signature` is not invoked, and the absence of a GPG signature is logged at `WARN` level on every download. For GitHub-released browsers the SHA-256 hash is taken from the release asset's `digest` field (`sha256:…`) recorded by GitHub. If no hash is available from any source, the package is rejected (fail-closed; see `updater::verify_package`).

---

## 10. Registry / Default Browser Registration

- Opt-in only: registration is not performed automatically. It is triggered by running the launcher with `--register-default` (and undone with `--unregister-default`).
- Writes to `HKCU\Software\Classes\...` and `HKCU\Software\RegisteredApplications` only (no UAC, no `HKLM`).
- On register: records written keys to a sidecar `nomad.reg-state.json` beside the `.exe`.
- On unregister: reads the sidecar and removes exactly those keys (no guessing, no collateral damage).
- The registered handler launches `nomad-<browser-id>.exe -- %1` so the launcher mediates URL opens.

### Self-registration repair (automatic, narrowly scoped)

Browsers can register *themselves* as URL/HTML handlers (the "Make default" button in their own settings). For a Nomad-managed install that registration points straight at the browser exe inside the portable tree (e.g. `"...\Browser\chrome.exe" --single-argument %1`), bypassing the launcher entirely: the browser then starts with its default host-profile location (`%LOCALAPPDATA%`) instead of the portable `Data` dir. Every clicked link opens a second, empty-profile instance — and the trace scrub deletes that host profile on exit, which reads as "the browser deleted my logins".

On every launch, `registry::repair_self_registration` therefore inspects the `HKCU` `UserChoice` ProgIds for `http`/`https`/`ftp` and `.htm`/`.html`/`.shtml`/`.xhtml`, plus `HKCU\Software\Clients\StartMenuInternet` clients, and rewrites any `shell\open\command` whose executable lives **strictly inside this launcher's `install_dir`** to route through the launcher (`"<launcher>" -- "%1"`). This is the one registry write permitted outside `--register-default`; it is `HKCU`-only, touches only commands that already point into Nomad's own install tree (never other browsers, other Nomad launchers, or system installs), and repairs state the browser itself wrote about Nomad's files. Combined with the launcher's stable `--user-data-dir`/`--profile`, a clicked URL reaches the already-running portable instance as a new tab (Chromium process singleton; Gecko per-profile remoting — which is also why Gecko launch commands must **not** pass `--no-remote`).

---

## 11. Code Style

- Rust edition 2021.
- `#![deny(clippy::all, clippy::pedantic)]` in `core/src/lib.rs` and each launcher `main.rs`; per-site `#[allow(...)]` with a comment explaining the exception.
- `thiserror` for error types; one `Error` enum per module, no `anyhow` in `nomad-core` (launcher `main.rs` may use it for startup failures).
- `tracing` + `tracing-subscriber` with `EnvFilter` for structured logging.
- `tokio` multi-thread runtime.
- No `unwrap()` / `expect()` outside of launcher `main()` startup initialization.
- All HTTP via `reqwest` with `native-tls` feature on Windows.
- Public keys embedded via `include_bytes!` at compile time; no runtime file reads for keys. Launcher icons embedded at build time via `winresource`.
- No `unsafe` except in the `taskbar.rs` COM interface calls, isolated behind a safe wrapper.

---

## 12. Testing Strategy

### Unit tests (`#[cfg(test)]` in each module of `nomad-core`)
- `config.rs` — valid `nomad.toml` parses correctly; unknown keys return error; missing required fields return error; relative paths are preserved as-is.
- `gpg.rs` — verify against known-good test fixture (real small signed file); known-bad signature returns `Err`; tampered payload returns `Err`; SHA-256 match/mismatch.
- `hardening.rs` — the Gecko `user.js` is written marker-fenced with the curated safe profile and `policies.json` into `distribution/`; user prefs outside the fence are preserved; re-running is idempotent. Chromium `hardening()` yields the expected safe flag set.
- Each `BrowserFamily` impl — `installed_version()` parses version from mock directory layout; `fetch_latest_version()` parses from a fixture JSON/HTML response.

### Integration tests (`tests/integration/`)
- Use `httpmock` to serve fixture responses.
- Full pipeline: mock server → download → verify → extract → portability prefs → check installed version.
- Config: write a `nomad.toml` variant, load it, verify resulting state.

### What is NOT tested automatically
- egui rendering of the status window (no headless GPU in CI).
- Windows taskbar COM APIs (smoke-tested manually on target hardware).
- Actual browser downloads from live upstream URLs.

### CI (GitHub Actions, `windows-latest`)
```yaml
- cargo fmt --check
- cargo clippy --workspace --all-targets -- -D warnings
- cargo test --workspace
```

---

## 13. Boundaries

### Always do
- Verify the SHA-256 hash before extracting any downloaded archive; additionally verify the GPG signature where the upstream publishes one.
- Use paths relative to the `.exe` directory — never absolute, never `%APPDATA%`.
- Fence Nomad-written preferences (`user.js` keys) with clear markers so users can identify and remove them.
- Apply only the curated "safe" hardening profile; keep it idempotent and preserve user preferences outside the Nomad fence.
- Log every outbound network request and its result at `DEBUG` level; log a `WARN` when no GPG signature is available.
- Write downloads to `.tmp` files; clean up on failure or at the start of the next launch.
- Reject unknown config keys with a clear error message.

### Ask user before (prompt in the status window, not silent)
- Writing any registry key (even `HKCU`) — only via the explicit `--register-default` flag, with one automatic exception: the self-registration repair (§10), which rewrites only `HKCU` handler commands that already point inside the launcher's own install tree.
- Deleting or replacing an existing browser installation directory during an update.
- Downloading when `auto_download = false` (the window waits on the "Update" button).

### Never do
- Write to `HKLM` (requires elevation and breaks the portability promise).
- Execute a downloaded binary that has not passed hash (and, where applicable, GPG or Authenticode) verification.
- **Bitwarden:** use the `-x64.appx` (inert when unpacked), build it from source, or run any NSIS/web installer — only the official portable `.exe` is wrapped. Do not relocate the vault (`App\Data`) outside `install_dir` *without* keeping the `preserve_state_across_update` copy, and do not drop the Authenticode signer check.
- Modify the downloaded browser's binaries or resources in v1 (PE resource patching is post-v1).
- Store credentials, tokens, or personally identifiable information anywhere.
- Silently ignore config parse errors or unknown keys.
- Apply aggressive, site-breaking hardening (full RFP / fingerprint-resistance, `--disable-webgl`, arkenfox `[SETUP-HARDEN]` / optional-section prefs); those are explicitly out of scope (§5).
- Hardcode or bundle a custom CA; use the system trust store.
- Make any `.exe` depend on a DLL not present in a stock Windows 10/11 installation.