# SPEC.md — Nomad Launcher

## 1. Objective

Nomad Launcher is a family of portable Windows browser launchers. Each launcher is a single self-contained executable, `nomad-<browser-id>.exe`, that updates, privacy-hardens, and launches exactly one browser from a local directory. No installer. No new default-browser registration during normal operation; existing browser self-registrations may be repaired as specified in §10. Distributable to end users as-is.

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

Each browser (and channel) ships as its own launcher binary. v1 produces six binaries.

### v1 MVP
| Binary | Browser | Update Source | Signature |
|--------|---------|---------------|-----------|
| `nomad-ungoogled-chromium.exe` | ungoogled-chromium | GitHub releases API (`ungoogled-software/ungoogled-chromium-windows`) | SHA-256 only |
| `nomad-floorp.exe` | Floorp | GitHub releases API (`Floorp-Projects/Floorp`) | SHA-256 only |
| `Nomad-Waterfox.exe` | Waterfox | GitHub version metadata (`BrowserWorks/waterfox`), Waterfox CDN installer/checksum | SHA-512 only |
| `nomad-helium.exe` | Helium | GitHub releases API (`imputnet/helium-windows`) | SHA-256 only |
| `Nomad-LibreWolf.exe` | LibreWolf | Codeberg releases API (`librewolf/bsys6`), `dl.librewolf.net` packages/checksums | SHA-256 only |
| `nomad-mullvad.exe` | Mullvad Browser | GitHub releases API (`mullvad/mullvad-browser`) | GPG + SHA-256 |

Notes:
- **Helium** — upstream signs commits via GitHub's web-flow key, which cannot produce detached signatures for release assets; no usable GPG key is available for embedding. SHA-256 only; absence of GPG signature logged at `WARN`.
- **LibreWolf** — ships pre-hardened; Nomad applies its own minimal `user.js` and shared `policies.json`, preserving LibreWolf's autoconfig (see §5). No upstream GPG signing key usable for release asset verification. SHA-256 only.
- **Mullvad Browser** — ships its own complete anti-fingerprinting stack (RFP, letterboxing, standardized UA / timezone / fonts) plus uBlock Origin and NoScript; Nomad applies **no** `user.js` and provisions **no** uBO, writing only a `DisableAppUpdate` `policies.json` (see §5) so its crowd-blending model stays intact. Verified with the Tor Browser Developers GPG key (`core/keys/mullvad.asc`) plus the SHA-256 GitHub asset digest.
- Ungoogled Chromium receives verified PE icon and PAK logo overlays during staging; see §6.

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
      version_cache.rs        # nomad-version-cache.toml (6 h TTL target-scoped release/uBO cache)
      protocol_freshness.rs   # local metadata/cooldown advice for launch-only handlers
      downloader.rs           # HTTP download with progress
      gpg.rs                  # pure-Rust GPG verification + SHA-256 / SHA-512
      authenticode.rs         # WinVerifyTrust signer verification utility
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
        floorp.rs
        waterfox.rs
        librewolf.rs
        mullvad.rs
    keys/                     # embedded ASCII-armored public keys
      helium.asc              # placeholder slot — Helium has no usable key (SHA-256 only)
      mullvad.asc
      gorhill.asc             # uBlock Origin release-tag signing key (Chromium uBO)
    payloads/                 # vendored user.js, Chromium flag sets, 7-Zip blobs (include_bytes!/include_str!)
  launchers/                  # one binary crate per browser
    ungoogled-chromium/       # package nomad-ungoogled-chromium
      Cargo.toml
      build.rs                # winresource: embed launcher icon
      icon.ico
      src/main.rs
    helium/
    floorp/
    waterfox/
    librewolf/
    mullvad/
  tests/
    integration/              # integration tests (mock HTTP, fake FS)
    fixtures/                 # test archives, fixture JSON, test keys
```

### Launcher binary

Each `launchers/<browser>/src/main.rs` is minimal — it selects the browser and delegates everything to the core runner:

```rust
fn main() -> std::process::ExitCode {
    nomad_core::run(nomad_core::Floorp::new, ICON, None)
}
```

The package name (e.g. `nomad-floorp`) determines the output binary name `nomad-floorp.exe`. Each launcher crate has a `build.rs` that uses `winresource` to embed its browser-branded `icon.ico` into the executable at compile time.

### Core trait

```rust
pub trait BrowserFamily: Send + Sync {
    // ── Required ──────────────────────────────────────────────────────────
    fn id(&self) -> &'static str;            // e.g. "ungoogled-chromium"
    fn display_name(&self) -> &'static str;  // e.g. "Ungoogled Chromium"
    fn engine(&self) -> Engine;              // Chromium | Gecko | Electron
    fn staged_install_layout(&self) -> StagedInstallLayout; // mandatory executable/runtime layout
    fn public_key(&self) -> Option<&'static [u8]>; // ASCII-armored PGP key, if upstream signs

    fn package_target(&self) -> PackageTarget; // x64/x86/arm64, or portable for one artifact
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
    fn default_config(&self) -> &'static str { DEFAULT_NOMAD_TOML }              // adapter-specific defaults
    fn profile_dir(&self, install_dir: &Path) -> Option<PathBuf> { None }        // Gecko: portable profile dir
    fn preserve_state_across_update(&self, current: &Path, stage: &Path) -> Result<()> { Ok(()) } // adapter-specific state
    fn has_builtin_fingerprint_noise(&self) -> bool { false }                   // Helium Noise
    fn accent(&self) -> egui::Color32 { theme::ACCENT }                          // per-launcher accent colour
    fn prepare_launch(&self, install_dir: &Path, cfg: HardeningConfig) -> Result<()> { Ok(()) } // best-effort staging
    fn fetch_extension_updates(&self, install_dir: &Path, cfg: HardeningConfig, opts: UpdateOptions)
        -> impl Future<Output = Result<()>> + Send;                             // default: provision Gecko uBO XPI
}
```

- `Engine` is `Chromium`, `Gecko`, or `Electron`. `Electron` exists so the Chromium/Gecko launch-flag injection in `build_launch_args` never fires for a non-browser app.
- `public_key()` exposes a detached package-signing key: `Some` requires the package signature, and a missing signature cannot fall back to a hash. `None` uses the adapter's hash/other verification path.
- `VersionInfo` carries: browser version, underlying engine version, download URL, optional signature URL, optional SHA-256 hash, optional SHA-512 hash.
- Stable browser release versions are ordered numerically, including numeric packaging revisions and a trailing `esr` suffix. Older or unorderable releases fail before download/staging, including target changes and legacy-target migration. Obsolete cached metadata triggers a fresh lookup; rejected fresh metadata does not replace the cache.
- `InstalledVersion` carries the browser version, engine version and optional package-selection target (`x64`, `x86`, `arm64` or `portable`). Legacy markers omit the target and require a verified replacement before being treated as current. `BrowserFamily::package_target()` identifies the adapter selector; cache reuse and up-to-date decisions require a matching known target. `portable` remains readable for legacy single-artifact records. Targets identify package selection; Nomad does not independently validate executable machine types.
- `hardening()` returns the browser's privacy-hardening payload (see §5): `Hardening::LaunchFlags { flags, local_state, preferences }` for Chromium-family browsers (flags appended at launch, JSON state seeded), `Hardening::GeckoProfile { user_js, policies, autoconfig, cfg, ublock_xpi_releases_url }` for Gecko-family browsers (files written into the install).
- `ProgressSink` is a `tokio::sync::watch::Sender<f32>` (0.0–1.0).
- The seven defaulted methods keep the common case to zero boilerplate; only the member named in each trailing comment overrides it.

---

### Staged layout validation

Every adapter declares its Chromium, Gecko, or self-contained portable-app
layout. The shared finalizer checks required nonempty regular files before
preparation and after overlays, before writing a version marker or swapping.
Missing files, directory placeholders, symlinks and Windows reparse-point paths
fail closed, independently of optional browser-specific hooks or hardening.
See [the required file contracts](docs/UPDATE-SAFETY.md#update-transaction).

### Filesystem boundaries

Use fixed package basenames within exclusively created staging. Check original
paths and ancestors for symlinks/reparse points before portable-state operations;
validate copied/promoted trees and remove only owned temporary files on failure.
The headless updater shares the configured folder-name constraints. See
[Filesystem paths before mutation](docs/UPDATE-SAFETY.md#filesystem-paths-before-mutation)
for scope and the concurrent-drive-writer limitation.

### Settings and managed-extension failure handling

Preference read failures must not reset existing settings to defaults. Prepare
and flush file replacements before promotion; preserve the original on failure.
Managed extension replacements are staged/validated before swap, retain rollback
state, and update cached versions only after promotion. Carry the working Chromium
extension into staged browser updates. See
[Settings and extension preservation](docs/UPDATE-SAFETY.md#settings-and-extension-preservation).

### Update concurrency and recovery

`Nomad/install.lock` serializes each portable folder across launcher processes.
The GUI keeps the OS lock through recovery, update prompts, staging, swap, launch
preparation and spawn, including fallback launch. Headless updates retain it for
the update transaction. A competing GUI invocation offers Retry or Close, with
no fallback writes; separate portable folders can operate independently. The OS
releases the lock when the owning process exits. Its empty file remains on disk.

Recovery failures abort dependent update work. Failed backup restoration leaves
stage and backup intact; swap refuses an unrecovered backup. Protocol launches
and disabled headless checks skip staging recovery. See
[Update and instance safety](docs/UPDATE-SAFETY.md) for the full contract.

## 4. Configuration

File: `Nomad/nomad.toml`, inside the `Nomad/` subfolder beside its launcher `.exe`. Each launcher has its own config, scoped to that one browser — there is no browser array.

```toml
[browser]
install_dir = "Browser"      # one folder name beside the .exe directory
arch = "x64"                 # "x64" | "x86" | "arm64"

[update]
check_on_launch = true       # false = skip the update check, launch immediately
auto_download = true         # false = prompt in the status window before downloading
remind_on_protocol = true    # local advisory on links; false = opt out

[launch]
language = "en-US"           # Chromium/Helium UI language; omit or blank for browser default
extra_args = []              # additional command-line arguments
incognito = false            # Chromium/Helium private windows

[hardening]
enabled = true               # false = stop applying hardening; persisted profile values may remain
sanitize_on_shutdown = true  # managed Gecko shutdown clearing
scrub_thumbnail_cache = false  # try clearing unlocked caches; never stop Explorer
recover_missed_cleanup = true  # DPAPI-protected attributed retry; isolation qualification pending
disable_webrtc = true        # managed Gecko peer connections off; Chromium UDP restricted
reduce_system_info = true    # Ungoogled Chromium only; defer to Helium Noise
clear_data_on_exit = false   # true = wipe Chromium cookies/sessions/history on exit (Chromium-only; breaks "stay signed in")
```

Rules:
- `browser.install_dir` is exactly one normal Windows-safe folder name beside
  the launcher. Reject empty/current/parent, absolute, root-relative,
  drive-relative, UNC, and nested paths; reject `Data`/`Nomad` case-insensitively,
  Windows device names (including extensions), reserved characters, controls,
  and trailing dots/spaces. Validate during deserialization before update or
  launch work; validate first-run defaults before creating configuration files.
  Staging and backup remain siblings of that folder, and the portable profile
  and Nomad state remain beside the launcher. Invalid existing configurations
  fail visibly without automatic migration or deletion.
- There is no `channel` key — every browser has a single channel.
- Unknown keys are rejected at startup with a descriptive error (no silent ignoring).
- On first run with no `Nomad/nomad.toml`, default configuration is written in the `Nomad/` subfolder beside the `.exe` and launch proceeds with defaults.
- Config is read once per launch; there is no live reload (the process is short-lived).

---

## 5. Privacy Hardening

Nomad applies browser-specific privacy defaults while preserving portable profiles. These settings reduce some tracking and fingerprinting but can break sites; there is no universal compatibility or anonymity guarantee. Mullvad retains its upstream privacy preferences. Waterfox explicitly enables RFP, LibreWolf retains its upstream RFP, and Helium retains its own noise framework. Browser-specific choices and security trade-offs are described below.

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
    /// optional autoconfig pair (autoconfig.js + .cfg), and an optional
    /// uBlock AMO metadata URL — all embedded/resolved at compile time. `autoconfig`
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

Hardening runs on every launch (after extraction, and on launches where no update occurred), so a user-edited install is re-seeded each time. It is on by default and controlled by `[hardening] enabled` in `nomad.toml` (§4).

Required file preparation runs on normal, fallback and protocol-style launches.
Privacy/policy writes, declared autoconfig-pair completeness, hardening withdrawal,
and adapter portability preparation propagate a typed `BrowserError::Preparation`.
Failure prevents command creation, registry repair and a new cleanup watcher;
the GUI offers Retry/Close and rejects a stale Launch anyway action. An ordinary
update failure may still offer fallback, which must pass the same preparation.
Malformed/nonobject JSON and nonobject containers blocking enforced scalar
paths are errors; unreadable user.js withdrawal is an error too. Already-matching
managed file contents are not rewritten; Chromium merges compare parsed values
and retain original formatting when no update is needed. This is per-file
validation/atomic replacement, not a multi-file transaction or proof that the
browser accepts every setting. See [required-settings safety](docs/HARDENING-FAILURE-SAFETY.md).


**Disabling hardening stops applying launch flags and removes managed Gecko files; it does not restore a pristine profile.** Gecko values already persisted to `prefs.js` can remain after the managed fence/autoconfig is removed. The two families differ because their hardening lives in different places:

- **Chromium** hardening is launch flags, which simply stop being passed. The profile seeds (`Local State`, `Default/Preferences`) stay, because they were merged into the browser's own stores with user-wins semantics and cannot be cleanly un-merged; what stops is the re-enforcement of `LOCKED_SCALAR_PATHS`, which is the most that can be withdrawn. The profile-storage switches in `CHROMIUM_PORTABILITY_FLAGS` are unaffected either way — they are not hardening (see below).
- **Gecko** hardening is files that persist between launches, so `remove_gecko_hardening` withdraws them: the Nomad-managed `user.js` fence (content outside the markers is preserved) and, for browsers that declare one, the autoconfig pair `defaults/pref/autoconfig.js` + `nomad.cfg`. Skipping the write alone left the previous fence and the locked `nomad.cfg` in force — a user who turned the setting off to unbreak a site saw no change at all, and `lockPref` values cannot be overridden from `about:config`. LibreWolf and Mullvad declare `autoconfig: None` and ship their own pair, which Nomad never writes and therefore never removes.
- Existing `distribution/policies.json` is deliberately **kept** when hardening is disabled, including any injected uBO `ExtensionSettings`. Vendor policies overwritten earlier cannot be restored from this file. Disabled hardening does not refresh this policy overlay in a replacement browser bundle; retaining it in an existing bundle is not a guarantee it survives an update. Policy compatibility remains browser/version dependent.

### Chromium-family (ungoogled-chromium, Helium) — launch flags + state seed

Chromium hardening uses three surfaces with distinct purposes:

1. **Command-line flags** (`HARDENING_FLAGS` in each browser module) — re-applied every launch, cannot be disabled by the user via the browser UI. This is the **enforcement** layer.
2. **`local_state.json` seed** (`payloads/chromium/local_state.json`) — merged into `<user-data-dir>/Local State` on enabled-hardening launches, surfaces in `chrome://flags`, and re-enforces DNS-over-HTTPS mode and the Quad9 resolver on every hardened launch (`LOCKED_SCALAR_PATHS`), including existing profiles. Reserved for `chrome://flags` toggles that only accept value-typed settings (e.g. `extension-mime-request-handling@2`) and for non-flag config (DoH).
3. **`preferences.json` profile-pref seed** (`payloads/chromium/preferences.json`) — value-typed prefs with no `--flag` switch: HTTPS-Only mode, Do Not Track, network-prediction off, third-party-cookie block, the Sensors content-setting block, `canMakePayment`/Media Router off, search-suggest/translate/alternate-error-pages off, Privacy Sandbox m1. Merged into `<user-data-dir>/Default/Preferences` every launch with **"user-wins"** scalar semantics; a privacy-critical subset (`LOCKED_SCALAR_PATHS` — HTTPS-Only, Safe Browsing off, Privacy Sandbox m1, DoH) is force-re-applied so the browser or a tampered profile cannot silently re-enable it.

**First-run clobber (why surface 3 also rides in `initial_preferences`).** Chromium's first-run pipeline *regenerates* `Default/Preferences` from the `initial_preferences` template next to `chrome.exe`, discarding whatever Nomad wrote to `Default/Preferences` beforehand. So on a brand-new profile the surface-3 seed alone is inactive for the entire first session and only "heals" on the second launch (when `--no-first-run` is set and Chromium loads Nomad's seeded file normally). When `[hardening] enabled = true`, `prepare_launch` merges `preferences.json` into the `initial_preferences` payload via `hardening::build_initial_preferences()` — the seed path Chromium honours on first profile creation, the same path that carries the MAC-protected `extensions.ui.developer_mode`. `preferences.json` remains the single source of truth (surface 3 still maintains established profiles); `Local State` is unaffected because Chromium merges that store rather than regenerating it. Verified end-to-end against ungoogled-chromium and guarded by `merged_initial_preferences_carry_developer_mode_and_profile_hardening`.

With hardening disabled, both Chromium adapters rewrite the first-run seed with the base developer-mode template only; Helium keeps the updater-disable preference on unreviewed builds; the reviewed x64 0.19.2.1 flat capability preserves existing update choices and service consent. This replaces stale hardened seeds without resetting existing user profile preferences. Seed parse/write errors propagate from launch preparation rather than permitting a launch with stale defaults. Toggle and failed-replacement regressions use owned temporary fixtures; no browser is launched by those tests.

**Profile-storage switches are not hardening and are never gated on `[hardening] enabled`.** `--disable-machine-id`, `--disable-encryption`, and `--disable-features=DeviceBoundSessions` live in `CHROMIUM_PORTABILITY_FLAGS` (`browsers/mod.rs`) and are applied by `launch_command`, beside `--user-data-dir`, on every launch. They decide *how the profile is stored*, not how private it is, and toggling them reformats an existing profile:

- The host machine ID seeds the `Secure Preferences` MACs that protect tracked preferences, `extensions.settings` among them. Change the seed and every MAC fails validation, so Chromium's tracked-preference enforcement clears the protected values, the extension registry comes up empty, and `ExtensionGarbageCollector` deletes the now-unreferenced directories under `Default\Extensions`.
- The encryption switch decides whether cookies and auth tokens are DPAPI-sealed to the host OS user. Data written in one mode cannot be decrypted in the other, and Chromium drops rows it cannot read.
- `DeviceBoundSessions` (Chrome 146+) binds sessions to the host TPM.

Gating these on the config toggle is what made `[hardening] enabled = false` → `true` wipe a user's extensions and sign-ins (#38). Keep them in `launch_command`, which takes no config, rather than in `build_launch_args`, which exists to interpret config. When hardening *is* enabled its `--disable-features=` bundle is a superset and wins by position (Chromium honours only the last occurrence); guarded by `hardening_disable_features_bundle_wins_over_the_portability_one`.

The command-line set is the **safe subset** of ungoogled-chromium's documented switches:

- **Stock Chromium hygiene:** `--disable-sync`, `--disable-background-networking`, `--disable-breakpad`, `--disable-component-update`, `--disable-features=JumpList`, `--no-default-browser-check`, `--disable-top-sites`.
  `--disable-component-update` is a security/privacy trade-off, not a protection
  against revoked certificates. In the reviewed Chromium source it gates component
  registration, including CRLSet. Ungoogled's normal service endpoints are also
  neutralized upstream, so removing the flag alone is not a refresh fix. The
  adapter supplies a standing security-data disclosure to the runtime details
  card, independently of hardening, and logs it during required preparation.
  No component downloader, custom update URL, policy/profile migration or flag
  change is added by this disclosure. See [pinned source and limits](docs/UNGOOGLED-COMPONENT-UPDATES.md).
- **Anti-tracking / fingerprinting:** `--disable-search-engine-collection`, `--fingerprinting-canvas-image-data-noise`, `--fingerprinting-canvas-measuretext-noise`, `--fingerprinting-client-rects-noise`, `--force-punycode-hostnames`.
- **Network / TLS privacy:** `--no-pings`, `--webrtc-ip-handling-policy=default_public_interface_only`. Nomad deliberately does not supply a Tor Accept header or disable TLS GREASE. With `disable_webrtc = true`, Chromium uses `disable_non_proxied_udp`, which restricts UDP rather than disabling WebRTC; TCP and proxied UDP can remain available.
- **Bundled features** (single `--enable-features=` because Chromium honours only the last one): `RemoveClientHints`, `SpoofWebGLInfo`, `MinimalReferrers` (strips cross-origin referrers, minimises same-origin to origin only — the single biggest passive-tracking mitigation).

Flags upstream marks as **potentially breaking** are excluded from the default set — notably `--disable-webgl`, `disable-beforeunload`, `NoReferrers`, and `NoCrossOriginReferrers`. The one exception Nomad ships **on by default** is the `ReducedSystemInfo` feature (see `reduce_system_info` below): clamping `navigator.hardwareConcurrency` is in line with how Tor/Brave behave, its real-world impact is a modest perf trade-off rather than hard breakage, and it remains user-disablable.

**Optional `[hardening] clear_data_on_exit`** (default `false`) — when `true`, Nomad appends/merges the `ClearDataOnExit` feature into the `--enable-features=` bundle, wiping cookies/sessions/history on every Chromium exit. Off by default because it breaks session continuity (signed out of every site each launch).

**`[hardening] reduce_system_info`** (default `true`, Chromium-family only) — Nomad merges the `ReducedSystemInfo` feature into the same `--enable-features=` bundle: system details exposed via headers/JS are reduced and `navigator.hardwareConcurrency` reports two cores, shrinking fingerprint entropy (CPU-core count is a stable identifier). On by default for the fingerprint reduction; set `false` to disable if you hit slowdowns in apps that size worker/thread pools from `hardwareConcurrency` (in-browser video encoders, some WASM workloads, heavy editors). The serde default is `true`, so configs that omit the key (including those written before the option existed) still get it.

**`[hardening] scrub_prefetch`** is a retired compatibility key (default `false`). Both boolean values remain accepted without rewriting existing configurations. It no longer deletes Prefetch files or requests elevation. The old name-prefix matching could affect unrelated installed browsers and removed launchers, so its deletion/elevation implementation and token list have been removed. A true legacy value logs a retirement warning when cleanup is scheduled; the legacy internal flag exits without a Prefetch action. Windows execution records remain. Automatic Recent/WER cleanup continues to require instance attribution.

**Helium exception.** Helium ships its own anti-fingerprinting framework ("Helium Noise") that already noises canvas pixels and AudioContext and **randomizes** `hardwareConcurrency` (2–16) by default — a more complete and less detectable approach than the ungoogled flags. So for Helium, Nomad defers those vectors to Helium Noise: it omits `--fingerprinting-canvas-image-data-noise` from Helium's flag set and never applies `ReducedSystemInfo` (gated by `BrowserFamily::has_builtin_fingerprint_noise()`), since `ReducedSystemInfo`'s clamp-to-`2` would override Helium's randomized value. Nomad still supplies the vectors Helium Noise does not cover (`measuretext`/`client-rects` noise, `SpoofWebGLInfo`, `RemoveClientHints`). Ungoogled Chromium has no Helium Noise and keeps the full set.

**Helium updater portability rule.** The reviewed x64 0.19.2.1 release
requires a normal flat Chromium layout before component updates are permitted.
Its native WinSparkle guard rejects layouts without the installed/versioned
module-directory structure, including Nomad's flat bundle. For this capability,
Nomad omits `--disable-component-update`, seeds the native update preference
to true for first-run profiles and preserves every byte of existing profile
preferences, including off choices and service consent.

Unknown/older/newer versions, missing target identity and unreviewed targets
keep `helium.services.browser_updates = false` and the component-disable switch,
independent of hardening. They can still launch/update through Nomad. A reviewed
build with an incomplete or linked layout fails preparation before preference
writes. Malformed existing preferences are preserved and fail visibly.
Component access still requires native service/schema consent and the user's
update preference; it is not proof that a component download succeeded.
See [Helium component-update safety](docs/HELIUM-COMPONENT-UPDATES.md) for source
revisions, endpoints, upgrade instructions and required live checks.

### Gecko-family (LibreWolf, Floorp, Waterfox) — layered profile

Two layers, written to separate profile and installation locations:

1. **`user.js`** — written to the portable profile returned by `profile_dir` (`Data/` for these browsers), outside the replaceable installation. A Nomad-curated "safe" profile derived from the arkenfox `user.js` template: the arkenfox core sections minus every preference arkenfox itself tags as site-breaking (`[SETUP-WEB]`), aggressive (`[SETUP-HARDEN]`), or optional (sections 4000+, including RFP). The Nomad-written block is fenced with marker comments; preferences outside the fence — including the user's own — are preserved, and the block is re-seeded idempotently on every launch.
2. **`policies.json`** — written to `<install_dir>/distribution/policies.json`. Carries the structural locks `user.js` cannot enforce: disable the browser's built-in updater (Nomad is the sole updater), disable telemetry / studies / crash reporting, disable Pocket and Firefox accounts. This file is fully Nomad-managed. Shared autoconfig defaults general extension update checking and automatic updating to enabled without locking those preferences; other installed extensions retain their browser update path.

### Waterfox — preserve upstream DNS defaults and user choices

Floorp and Waterfox share the non-DNS `firefox/nomad.cfg` autoconfig. Floorp
appends `firefox/dns.cfg`; Waterfox does not. Neither Waterfox's managed `user.js`,
autoconfig nor policies set TRR/provider/rollout preferences. This removes the
previous shared mode-5 default on the next hardened launch, including existing
installations and staged updates. Explicit saved user choices are not reset.
Reviewed upstream 6.7.6 defaults to mode 2 with OHTTP enabled, using a Waterfox
relay and Cloudflare endpoint. Mode 2 permits native DNS fallback and does not
supply Quad9 malware filtering. Scoped Windows 11 x64 6.7.6 browser-log tests
observed OHTTP address responses normally and native/system resolution during
a program-scoped HTTPS outage at startup. The two runs used different disposable
profiles; neither is an OS packet capture or an every-lookup guarantee. See
[Waterfox DNS evidence](docs/WATERFOX-DNS-DEFAULTS.md).

### LibreWolf — own minimal `user.js`, shares `policies.json`, skips the autoconfig pair

LibreWolf already ships arkenfox-equivalent hardening, so the full Firefox `user.js` is almost entirely redundant on it. A pref-by-pref diff against the live `librewolf.cfg` confirmed it: 44 of 73 Firefox prefs are no-ops (telemetry, Safe Browsing, prefetch, search suggestions, `sessionstore.privacy_level`, referrer trimming, disk cache, HTTPS-only, `app.update` — all `lockPref`'d or `defaultPref`'d to the same values), Strict ETP (`browser.contentblocking.category = "strict"`) subsumes the tracking-protection prefs, and `privacy.resistFingerprinting` subsumes `privacy.fingerprintingProtection`. Many of the redundant prefs are `lockPref`'d, so Nomad could not override them even if it tried.

LibreWolf therefore gets its **own minimal `user.js`** (`payloads/librewolf/user.js`) containing only the genuine additions LibreWolf does not make itself: DoH (`network.trr.mode` 2 — LibreWolf ships it **off** at mode 5, the single biggest divergence), `geo.enabled` off (LibreWolf disables the OS providers but not the API), network-prediction off, WebRTC `default_address_only`, pings/beacons off, the Windows Jump-List host-trace pref, bookmarks-toolbar visibility, and the shutdown-sanitize block. Nomad never sets `privacy.resistFingerprinting`, so LibreWolf's RFP stays intact.

LibreWolf still shares `firefox/policies.json` (the structural updater/telemetry/Pocket locks). What it does **not** receive is Nomad's autoconfig pair (`autoconfig.js` + `nomad.cfg`): LibreWolf ships its own `defaults/pref/local-settings.js` + `librewolf.cfg`, and Nomad must not clobber them (so `autoconfig` and `cfg` are `None` in its `GeckoProfile`). Because each launcher is its own binary built around exactly one `BrowserFamily`, this is a compile-time distinction — there is no runtime browser detection.

### Sourcing and maintenance

Floorp, LibreWolf, and Waterfox's managed `user.js` payloads set both
`privacy.trackingprotection.allow_list.baseline.enabled` and
`privacy.trackingprotection.allow_list.convenience.enabled` to `true` for ETP's
major/minor site fixes. This deliberately permits the browser's curated tracking
exceptions for compatibility while keeping Strict mode. The values are not
locked; the existing managed-profile mechanism reapplies them at startup with
hardening enabled, including existing profiles. Browser version support and the
effective checkbox state require live verification; uBlock rules are independent.
The payload also sets `privacy.trackingprotection.allow_list.hasMigratedCategoryPrefs`
to `true` before first browser startup. This records Nomad's explicit opt-in and
prevents Gecko's one-time Strict/Custom migration from disabling both lists when
the privacy settings are first opened.

The arkenfox-derived profile and the Chromium flag sets are **vendored** — pinned snapshots embedded in `nomad-core` via `include_str!`, never fetched at runtime (runtime fetch would break offline / USB use and add a per-launch failure mode). They are bumped deliberately, tracking upstream arkenfox releases and ungoogled-chromium flag changes.

The AMO-signed uBlock Origin XPI (Gecko) and the gorhill `uBlock0_X.X.X.chromium.zip` (Ungoogled Chromium) are the explicit runtime-fetch exceptions.

The AMO XPI is downloaded because Gecko requires a Mozilla-signed artifact that Nomad cannot reproduce. Nomad reads its version, exact file URL, and SHA-256 digest from one AMO add-on metadata response; the GUID must be `uBlock0@raymondhill.net` and the file status `public`. Missing/malformed hashes or mismatched XPI bytes fail before staging. The digest depends on AMO metadata over HTTPS, while the browser performs Mozilla signature validation at installation. The local signature-file check is only a layout check. Version discovery no longer follows a mutable `/latest/` redirect or guesses from filenames.

The gorhill ZIP is fetched only after its GitHub asset metadata supplies a valid `sha256:<64 hex characters>` digest, the release tag's GPG signature verifies against the embedded gorhill key (`F5630CAE62A14316`), and the upload timeline passes `github::asset_provenance_suspect`. ZIP bytes must match the digest before extraction; absent, malformed or mismatched digests leave the installed extension and cache untouched. The tag signature authenticates the tag/commit only. GitHub's asset digest provides archive integrity dependent on GitHub metadata, not a publisher signature over the ZIP; the timeline check remains additional evidence against asset replacement. Already-current installed files are not rehashed. Nomad remains the sole updater for the extension binary.

---

## 6. Branding

Branding covers launcher assets and the supported Ungoogled Chromium overlays:

- Each launcher crate embeds a browser-branded `icon.ico` into its `.exe` at compile time via a `winresource` build script. `nomad-floorp.exe` carries a Floorp-branded icon, and so on.
- The status window's identity card displays the browser's logo and brand colors (see §7), matching the Nomad mockups.
- Ungoogled Chromium uses [`core/src/branding.rs`](core/src/branding.rs) and
  [`core/src/branding/chromium.rs`](core/src/branding/chromium.rs) to patch PE icon
  resources and PAK logos after package verification. The mandatory staged
  compatibility check verifies required files and overlays before promotion;
  failure preserves the working installation. A `.branding-patched` fingerprint
  controls repeat application. Cosmetic rebranding of an existing installation
  logs failures and retries next launch; it does not bypass staged update checks.
  Other launchers do not supply this branding configuration.

### PE Version Metadata (Windows exe Properties → Details)

Each launcher's `build.rs` sets the following `winresource` fields in addition to the icon:

| Field | Value |
|---|---|
| `FileDescription` | `Nomad Launcher — <DisplayName>` (e.g. `Nomad Launcher — Floorp`) |
| `ProductName` | `Nomad Launcher` |
| `FileVersion` | Nomad Launcher version (e.g. `0.1.0`) — updated at each release |
| `ProductVersion` | Same as `FileVersion` |
| `InternalName` | `nomad-<browser-id>` (e.g. `nomad-floorp`) |
| `OriginalFilename` | `nomad-<browser-id>.exe` (e.g. `nomad-floorp.exe`) |
| `LegalCopyright` | `© 2026 Cyph3rpuNk-dev` |

`CompanyName` is not set. `FileVersion` and `ProductVersion` track the Nomad Launcher release version, not the browser version it manages.

---

## 7. UI — Transient Status Window (egui / eframe)

There is no tray icon and no persistent window. Running `nomad-<browser>.exe` opens a single transient status window that lives only for the duration of the update-and-launch sequence, then closes itself.

The window title is `Nomad Launcher - <DisplayName>`, using a plain hyphen
(for example, `Nomad Launcher - Floorp`). All six launchers use this format.

### Design language
"Nomad dark" palette — the design tokens (palette + type/spacing/radius/motion
scales) live in [`core/src/ui/theme.rs`](core/src/ui/theme.rs); identity rendering
is implemented in [`core/src/ui/identity.rs`](core/src/ui/identity.rs).
Unified chrome across all six launchers; per-browser differentiation is the
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

The title bar is the OS-drawn standard decoration reading "Nomad Launcher -
`<Browser>`" (minimize / close); egui does not paint it, so there is no separate
title-bar colour token. Font: **Atkinson Hyperlegible** (SIL OFL, Braille
Institute) — vendored at `core/payloads/fonts/` and embedded; eframe is built
without `default_fonts`, so the bundled Ubuntu/emoji/mono are *not* shipped
(saves ~1.3 MB per launcher). Deterministic across machines, not the host
system font. Window size: **460 × 380 px** (fixed, non-resizable).

### Window layout
A narrow window containing two stacked cards and a footer link.

**1. Identity card** (`#292A2D`, 6 px radius)
- Top row: browser logo (34×34, the browser's own brand colors) + display name (15 px, `#E8EAED`) + version subtitle (11 px, `#9AA0A6`).
- **Version subtitle format (uniform across all six launchers):** `{browser_version} — {engine} {engine_version} (Portable)`. The ` — {engine} {engine_version}` segment is omitted when the browser version and engine version are identical, leaving `{browser_version} (Portable)`. Examples: `1.19.12b — Firefox 150.0.2 (Portable)`; `148.0.7778.96 (Portable)`.
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

**3. Footer** — left: "Open upstream release page" link (`#E8B255`), opens the browser's upstream release page in the system default browser. Right: the shared Nomad brand lockup — the Nomad emblem + `NOMAD` wordmark (the family signature; emblem from `core/payloads/nomad/`, wordmark in the accent; see [`core/src/ui/identity.rs`](core/src/ui/identity.rs)).

### Behavior
- **Auto-close** — once the browser process is spawned and has not failed during the start-up watch, the window closes itself automatically. No user interaction is required on the happy path.
- **Start-up watch** — process creation alone is not a launch. The new process is polled for one second; if it ends in that time with a Windows NTSTATUS error (`0xC0000000`–`0xCFFFFFFF`, for example `0xC0000135` when a required DLL is missing), the launch is reported as an error, "browser launched" is not logged and the cleanup watcher is not started. This applies to the normal and "Launch anyway" paths. Ordinary exit codes are not failures, because a browser's first process may exit at once after handing over to a running instance. Before spawning, the launcher adds `SEM_FAILCRITICALERRORS` to its own error mode, which the browser inherits, so a load failure ends the new process at once instead of leaving it alive behind a Windows "System Error" dialog for as long as the user leaves that dialog open. A process still alive after the watch counts as launched.
- **Error layout** — the window has a fixed size. The action buttons are laid out first and a message too long for the remaining space scrolls, so Retry, "Launch anyway" and Close are always reachable.
- **Protocol maintenance reminder** — enabled by `[update] remind_on_protocol` (default true, including older configs that omit it). Unknown/seven-day-old relevant metadata checks or a recorded version differing from the installed record show Continue opening link / Close. Continue acknowledges the reminder for 24 hours; Close cancels without acknowledgment. No update/check/provisioning occurs. Runtime details are hidden in this phase and long advice scrolls so the action row remains reachable. The folder lock is held while awaiting the choice; a competing launcher may need Retry. Reminders are advisory, not a freshness guarantee. [Scope, records and limits](docs/PROTOCOL-UPDATE-FRESHNESS.md).
- **Update available, `auto_download = false`** — the status block shows the new version with two buttons: "Update" and "Launch current". The window waits for the user.
- **Error** — on any failure (network, GPG, hash, extract) the window does *not* auto-close. It shows the error message and offers "Retry" and, where a usable install already exists, "Launch anyway" and "Close". If fallback process creation fails, the error remains visible with Retry/Close only; no cleanup watcher starts and success is not signaled. Retry returns to the existing pipeline loop. Successful process creation retains the normal auto-close behavior; it does not prove the browser completed startup.

### Taskbar progress
While the window is open and a download is active, the taskbar button shows the Windows progress overlay via `ITaskbarList3` (`TBPF_NORMAL` during download → `TBPF_NOPROGRESS` on completion → `TBPF_ERROR` on failure).

---

## 8. Update & Launch Flow

Update checks happen only on direct launcher invocations. OS protocol launches are launch-only and skip browser/managed-extension checks. There is no background update interval; one detached cleanup coordinator remains while the owned browser session is running. Users who open only registered links must run the launcher directly to obtain updates.

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
  ├── require a signature URL when public_key() is Some:
  │     missing → verification error before stage creation/download
  ├── status: "Downloading <version>…"   (progress bar driven by ProgressSink)
  │     downloader::fetch(url)  →  {tmp_pkg}
  │     if VersionInfo has a signature URL:
  │       downloader::fetch(sig_url)  →  {tmp_sig}
  ├── status: "Verifying signature…"
  │     if public_key() is Some:
  │       require tmp_sig and gpg::verify(tmp_pkg, tmp_sig, public_key())
  │         missing/unreadable/invalid → error, no extraction or swap
  │     else: use the adapter's hash/other verification path
  │     sha256::verify(tmp_pkg, expected_hash)
  │       Err  →  delete tmp files, show error state
  ├── status: "Extracting…"
  │     browser.extract(tmp_pkg, install_dir)
  │     delete tmp files
  │
  PREP:
  ├── status: "Applying privacy hardening…"
  │     Gecko:    write the marker-fenced user.js + distribution/policies.json
  │     Chromium: merge Local State/Preferences and write initial preferences; add hardening flags at LAUNCH
  │
  LAUNCH:
  ├── status: "Launching browser…"
  │     spawn browser.launch_command(install_dir, args)
  │       (Chromium-family: the safe hardening flags are appended here)
  │     watch the new process for 1 s; an NTSTATUS exit is an error, not a launch
  └── auto-close the status window
```

Partial downloads do not survive a crash: any `.tmp` files in `install_dir` are deleted at the start of the next launch.

### Launch language

`build_launch_args` adds a nonblank `launch.language` as one `--lang=<value>`
argument for `Engine::Chromium` (Ungoogled Chromium and Helium), after trimming
surrounding whitespace. This is independent of hardening. It precedes
`extra_args`, so an explicit `--lang=...` there takes precedence. Unset/blank
values add no switch; Gecko and Electron receive no generated language flag.
The browser decides available locales and fallback; changing this preference
requires a full browser restart. It does not install language packs or change
Nomad's own UI language.

---

## 9. Signature & Hash Verification

- Every download is verified against the expected SHA-256 hash before extraction.
- An adapter exposing a package-signing key requires a valid GPG detached package signature, verified with `pgp` against the embedded key. Missing signature metadata is rejected before stage creation/download; failed downloads and unreadable/invalid signatures abort before extraction. A matching hash cannot bypass this requirement.
- **GPG-verified browsers:** Mullvad Browser (Tor Browser Developers key, plus the SHA-256 GitHub asset digest). Keys are embedded into `nomad-core` via `include_bytes!` from `core/keys/<browser>.asc`.
- **Hash-only browsers:** ungoogled-chromium, Floorp, Helium, LibreWolf (SHA-256) and Waterfox (SHA-512, from the `.sha512` file published beside each CDN installer). For these, `public_key()` returns `None`, `verify_signature` is not invoked, and the absence of a GPG signature is logged at `WARN` level on every download. For GitHub-released browsers the SHA-256 hash is taken from the release asset's `digest` field (`sha256:…`) recorded by GitHub. If no hash is available from any source, the package is rejected (fail-closed; see `updater::verify_package`).

---

## 10. Registry / Default Browser Registration

- Opt-in only: registration is not performed automatically. It is triggered by running the launcher with `--register-default` (and undone with `--unregister-default`).
- Writes to `HKCU\Software\Classes\...` and `HKCU\Software\RegisteredApplications` only (no UAC, no `HKLM`).
- On register: atomically saves the complete cleanup plan in
  `Nomad/nomad.reg-state.json` before the first HKCU write. Reject invalid,
  oversized, unknown-schema or different-browser prior state without replacing
  it. Retain the record after a failed write for explicit retry or removal.
- On unregister: validates the version-2 record against the current launcher location and exact
  planned keys/values and removes those entries. Missing entries are harmless;
  registry failures retain the record. Failure to remove the record is also an
  error. The record describes a prepared attempt, not a completion marker.
- Registration names derive from SHA-256 of the browser ID and canonical parent
  plus launcher filename (ASCII case folded). ProgIDs use 24 digest hex characters
  after `NomadPortable.`; capability roots and RegisteredApplications names use
  the full digest. The version-2 record contains its bound launcher path and the
  Windows picker label includes the folder. A copied record cannot authorize
  removal at its original location.
- A same-browser legacy or copied record is archived under
  `Nomad/registration-history/` before replacing the active plan. No historical
  registry entries are changed by migration. Version-1 records are accepted for
  preservation, but refused for deletion. The user selects the new entry in
  Windows Settings; Nomad never rewrites UserChoice.
- The registered handler launches `"nomad-<browser-id>.exe" -- "%1"` so the
  launcher mediates URL/file opens. Require exactly one non-empty target after
  the separator; reject missing targets, additional arguments, and targets
  whose first non-whitespace character is `-` or `/` (Windows Gecko also
  treats `/` as a switch prefix; Chromium trims whitespace before parsing).
  Validate before internal flag dispatch, configuration, ownership, update, or
  browser work. Preserve an accepted target verbatim as one positional argument.
  A separator without a target fails rather than falling back to direct-launch
  provisioning. Error messages do not echo target contents.

### Self-registration repair (automatic, narrowly scoped)

Browsers can register *themselves* as URL/HTML handlers (the "Make default" button in their own settings). For a Nomad-managed install that registration points straight at the browser exe inside the portable tree (e.g. `"...\Browser\chrome.exe" --single-argument %1`), bypassing the launcher entirely: the browser then starts with its default host-profile location (`%LOCALAPPDATA%`) instead of the portable `Data` dir. Every clicked link opens a second, empty-profile instance — and older cleanup could delete that host profile on exit, which read as "the browser deleted my logins". Shared host profiles are now preserved.

`registry::repair_self_registration` therefore sweeps **every** ProgId under `HKCU\Software\Classes` (including the per-exe `Applications\<exe>` handlers) plus the `HKCU\Software\Clients\StartMenuInternet` clients, and repairs recognized browser `shell\open\command` values whose executable lives **strictly inside this launcher's `install_dir`** to route through the launcher (`"<launcher>" -- "%1"`). This is the one registry write permitted outside `--register-default`; it is `HKCU`-only, touches only commands that already point into Nomad's own install tree (never other browsers, other Nomad launchers, or system installs), and repairs state the browser itself wrote about Nomad's files. Combined with the launcher's stable `--user-data-dir`/`--profile`, a clicked URL reaches the already-running portable instance as a new tab (Chromium process singleton; Gecko per-profile remoting — which is also why Gecko launch commands must **not** pass `--no-remote`).

Two properties of the sweep are load-bearing:

- **It is not restricted to the ProgIds currently selected via `UserChoice`.** A third-party redirector (Winhance's `OpenWebSearch` stub, MSEdgeRedirect, …) commonly owns the `http`/`https` `UserChoice` slot and dispatches onward to the browser's own ProgId — so the command that actually launches the browser is frequently not the selected one. Scanning only `UserChoice` left those commands pointing straight at the browser exe. Safety requires validated command/key shapes, ordinary filesystem paths, install-directory containment and a durable repair journal; an empty `install_dir` is refused outright so containment can never degenerate into "every path".
- **It runs before launch, during the session, and after browser exit.** The user clicks "Make default" *inside* the browser, mid-session. Until the command is rewritten, every clicked link starts a second browser on its host profile instead of opening a tab in the portable instance. The detached cleanup watcher therefore watches `HKCU\Software\Classes` with `RegNotifyChangeKeyValue` for as long as the browser runs and re-runs the repair once each burst of changes settles (`selfreg_watch.rs`). A per-install named mutex keeps this to one watcher when several link clicks have each spawned one. The watcher re-runs the repair once more after the browser tree is down. Both derive `install_dir` from the launched browser executable's own path.

Automatic repair uses a separate versioned journal at
`Nomad/nomad.registry-repairs.json`, with a persistent per-folder file lock shared
by repair, register and unregister operations. Each original default value's raw
bytes and type are saved atomically before compare/write. Only recognized
Chromium/Gecko arguments with one URL placeholder (or an argument-free Start Menu
command) are eligible; custom arguments, relative/traversing paths and filesystem
aliases are refused. Command contents are not logged.

`--unregister-default` durably disables automatic repair, then conditionally
restores recorded commands and removes the Nomad picker registration. Only an
exact recorded replacement is restored; later edits and missing values are
preserved. Failures retain the disabled journal for retry. A successful undo
retains an empty disabled journal; successful explicit registration reenables it.
The helper must honor this state on its next sweep. A journal with outstanding
records cannot be rebound to a moved/renamed launcher or changed installation
path. Unregister before relocation, then register again. Legacy repairs without
snapshots cannot be recovered. See [registry repair safety](docs/REGISTRY-SAFETY.md)
for limits and testing.

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
- Isolate `unsafe` Windows API calls behind safe Rust interfaces and document their safety assumptions. Current uses include taskbar COM, Authenticode, PE resource branding, registry notifications/repair, cleanup, the pre-launch error mode, and launcher DLL-search configuration; they are not confined to `taskbar.rs`.

---

## 12. Testing Strategy

### Unit tests (`#[cfg(test)]` in each module of `nomad-core`)
- `config.rs` — valid `nomad.toml` parses correctly; unknown keys return error; missing required fields return error; valid single folder names are preserved as-is; unsafe installation-folder settings fail before file changes.
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
- cargo clippy --workspace --all-targets --locked -- -D warnings
- cargo test --workspace --locked
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
- Downloading/replacing an existing browser installation when `auto_download = false`. The default `auto_download = true` permits verified replacement during a direct launcher invocation without another prompt. Protocol invocations never update.
- Downloading when `auto_download = false` (the window waits on the "Update" button).

### Never do
- Delete shared host browser directories, profiles, or Gecko `installs.ini`
  maps. The absence of an executable does not prove ownership: system-wide
  binaries can keep real profiles under `%LOCALAPPDATA%`. Automatic cleanup
  requires a matching portable-instance marker and a browser image contained
  in that owned folder. Only individual Recent shortcuts with unambiguous
  resolved targets inside the folder and WER reports with one exact absolute
  `AppPath` matching that browser image may be removed. Preserve unrelated
  same-drive shortcuts, shared temp files, standalone crash dumps, compound Jump
  Lists, malformed/unreadable/oversized metadata, and reparse-point paths.
  Recent links may carry IDList, local LinkInfo and relative records; all
  supported stored representations must identify the same existing ordinary
  target strictly inside the owned folder. Reject unsupported namespace/override
  records, network/environment targets and conflicting known-folder anchors.
  Never call Shell Link Resolve, execute a shortcut, or search for moved targets;
  see [Recent shortcut safety](docs/RECENT-SHORTCUT-SAFETY.md).
  WER scanning covers the current user's Local AppData and ProgramData queues
  and archives only. AppPath must pass the owned-folder boundary before any
  filesystem lookup, and reparse/parent/device/network paths are refused. Remove
  only flat report folders with at most 256 ordinary files; preflight all files
  for Windows read/write sharing conflicts, reread attribution, remove ordinary
  attachments including dumps, then delete Report.wer last and the empty folder.
  Preserve nested/linked/unsupported trees and reports that fail access preflight.
  Partial attachment deletion can leave a report for a later session's retry.
  Recorded missed cleanup can be retried under the original Windows user/computer
  and canonical portable path, after ownership and idle checks. There is still
  no guarantee against concurrent path replacement or non-Nomad process starts.
  Do not disable WER or request elevation. See [WER cleanup safety](docs/WER-CLEANUP-SAFETY.md).
  Pre-launch missed-session recovery is restricted to individually attributed
  Recent/WER records. It never deletes shared browser profiles, replays opt-in
  cache actions, repairs registry state or starts/terminates a process. See
  [missed-cleanup recovery](docs/MISSED-CLEANUP-RECOVERY.md).
- Write to `HKLM` (requires elevation and breaks the portability promise).
- Execute a downloaded binary that has not passed hash (and, where applicable, GPG or Authenticode) verification.
- Modify downloaded binaries before verification, or bypass required staged overlay validation. The supported PE/PAK branding overlays in §6 are deliberate post-verification modifications.
- Upload browser credentials, tokens, profile contents or personal browsing data through the launcher. Local browser profiles intentionally persist user data; local logs/registry journals can contain identifying paths. Nomad does not encrypt these records.
- Silently ignore config parse errors or unknown keys.
- Add site-breaking hardening without a browser-specific rationale and disclosure. Waterfox explicitly enables RFP; LibreWolf retains its upstream RFP. Avoid describing all browser profiles as universally compatible (§5).
- Hardcode or bundle a custom CA; use the system trust store.
- Make any `.exe` depend on a DLL not present in a stock Windows 10/11 installation.
