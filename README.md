# Nomad Launcher

Single-file portable Windows browser launchers, one per browser. Drop the `.exe` anywhere — including a USB drive — and it downloads, GPG-verifies (where the upstream signs), privacy-hardens, and launches the browser. When you close the browser, Nomad scrubs the host-system traces Windows leaves behind on its own.

No installer. No `HKLM` writes. No persistent services or scheduled tasks. No `%APPDATA%`. The browser lives in the launcher's directory and dies with it.

**Status:** Functionally complete and in daily use.

*Inspired by [chrlauncher](https://github.com/henrypp/chrlauncher).*

---

## Supported browsers

| Launcher | Browser | Signature |
|---|---|---|
| `Nomad-Chromium.exe` | [Ungoogled Chromium](https://github.com/ungoogled-software/ungoogled-chromium) | SHA-256 |
| `Nomad-Firefox.exe` | Firefox Stable | GPG + SHA-256 |
| `Nomad-Firefox-ESR.exe` | Firefox ESR | GPG + SHA-256 |
| `Nomad-Floorp.exe` | [Floorp](https://floorp.app) | SHA-256 |
| `Nomad-Waterfox.exe` | [Waterfox](https://www.waterfox.net) | SHA-256 |
| `Nomad-Helium.exe` | [Helium](https://github.com/imputnet/helium-windows) | SHA-256 |
| `Nomad-LibreWolf.exe` | [LibreWolf](https://librewolf.net) | SHA-256 |
| `Nomad-Mullvad.exe` | [Mullvad Browser](https://mullvad.net/en/browser) | GPG + SHA-256 |

### Other portable apps

Nomad also wraps one non-browser app using the same download → verify → portable-launch pipeline:

| Launcher | App | Signature |
|---|---|---|
| `Nomad-Bitwarden.exe` | [Bitwarden](https://bitwarden.com) — desktop password manager (not a browser) | SHA-256 + Authenticode |

See [Nomad Portable Bitwarden](#nomad-portable-bitwarden) for how it differs from the browser launchers.

---

## Getting started

1. Copy the launcher `.exe` to any folder (USB drive, network share, local directory — anywhere you have write access).
2. Run it.

On the first run Nomad creates a `Nomad/` subfolder, writes a default `nomad.toml` into it, then downloads and launches the browser. A transient status window shows download progress and closes automatically once the browser starts.

No elevation required. Nothing is written outside the launcher's own directory during normal operation.

### Verifying the launcher you downloaded

Release builds ship a `SHA256SUMS` manifest and a detached GPG signature
`SHA256SUMS.asc`, signed with the Nomad release key:

- **Key:** `Nomad Launcher` (release signing key)
- **Fingerprint:** `4D92 5DAD 1DB4 405C 99EA 1FD3 9984 5DA3 20CD 1F37`

```sh
# 1. Import the release key (shipped as nomad-release-signing-key.asc) and
#    confirm the fingerprint matches the one above.
gpg --import nomad-release-signing-key.asc
gpg --fingerprint 4D925DAD1DB4405C99EA1FD399845DA320CD1F37

# 2. Verify the manifest is authentic, then check the binary against it.
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS   # or: certutil -hashfile Nomad-Firefox.exe SHA256
```

A `Good signature` from the fingerprint above means the manifest is genuine; the
`sha256sum -c` step then confirms your `.exe` matches it.

---

## On-disk layout

Every launcher creates exactly this structure beside its `.exe` on first run:

```
C:\Portables\Firefox\
├── Browser\              # the browser install (firefox.exe lives here)
├── Data\                 # the browser's profile (managed by the browser itself)
├── Nomad\                # everything Nomad owns
│   ├── nomad.toml                  # config
│   ├── nomad.log                   # rotating log
│   ├── nomad-version-cache.toml    # cached update-check result
│   ├── nomad.reg-state.json        # default-browser registration sidecar (only after --register-default)
│   └── Gecko-extensions\           # Gecko-only: staged uBlock XPI
│       └── uBlock0.xpi
└── Nomad-Firefox.exe
```

The shape is identical across every **browser** launcher — `Data/` is the profile directory for all browsers, and Chromium-family installs don't get a `Gecko-extensions/` folder. The browser's profile directory is left untouched by Nomad; only `Nomad/` and its contents are ours. (`Nomad-Bitwarden.exe` uses a slightly different shape — its vault lives in `App\Data` *inside* the install dir; see [Nomad Portable Bitwarden](#nomad-portable-bitwarden).)

To reset a launcher to first-run state, delete its `Nomad/` folder. To wipe everything (including the downloaded browser and your profile), delete the whole launcher directory.

---

## Configuration

`nomad.toml` lives in a `Nomad/` subfolder beside the launcher (see [On-disk layout](#on-disk-layout) below). Each launcher has its own independent config file.

```toml
[browser]
install_dir = "browser"      # relative to the .exe — where the browser is stored
arch = "x64"                 # "x64" | "x86" | "arm64"

[update]
check_on_launch = true       # false = skip update check, go straight to launch
auto_download = true         # false = show "Update / Launch current" prompt

[launch]
language = "en-US"           # --lang passed to browsers that accept it
extra_args = []              # additional arguments appended to the browser command
incognito = false            # true = launch Chromium browsers in --incognito mode

[hardening]
enabled = true               # false = launch with no privacy hardening
sanitize_on_shutdown = true  # false = disable Gecko clear-on-exit prefs
scrub_thumbnail_cache = false  # true = scrub thumbcache on exit (briefly restarts Explorer)
clear_data_on_exit = false   # true = wipe Chromium cookies/history/sessions on exit
disable_webrtc = true        # false = restricted mode (public interface only; WAN IP still via STUN)
reduce_system_info = true    # false = disable Chromium ReducedSystemInfo (it sets hardwareConcurrency=2 for less fingerprint entropy; may slow thread-pool-sizing apps)
```

Unknown keys are rejected at startup with a descriptive error — silent misconfiguration is not possible.

---

## Nomad Portable Bitwarden

`Nomad-Bitwarden.exe` wraps the **official Bitwarden desktop app** (an Electron application), not a browser. The browser extension is deliberately *not* used: Bitwarden's own docs note the extension increases browser-fingerprint uniqueness, and a DOM-based extension clickjacking class was demonstrated at DEF CON 33 (2025). The desktop app avoids both — and Nomad makes it portable and self-updating.

It rides the same pipeline as the browsers (download → verify → stage → atomic-swap → launch), with these app-specific differences:

- **Artifact:** the official `Bitwarden-Portable-<version>.exe` from the [`bitwarden/clients`](https://github.com/bitwarden/clients) releases. That repo publishes multiple products into one release stream, so Nomad selects the newest stable release tagged `desktop-v…` (the APPX is *not* used — extracted from its MSIX package it runs inert).
- **Verification:** SHA-256 against the GitHub asset digest **plus an Authenticode signer check** — the binary must be signed by `Bitwarden Inc.` (validated with `WinVerifyTrust`) before it is staged. Bitwarden publishes no GPG key, so there is none to embed.
- **On-disk layout (differs from the browsers):**

  ```
  C:\Portables\Bitwarden\
  ├── App\                      # the Bitwarden binary (replaced on update)
  │   ├── Bitwarden-Portable.exe
  │   ├── .nomad-version
  │   └── Data\                 # your vault / login (BITWARDEN_APPDATA_DIR)
  ├── Nomad\                    # config, log, version cache
  └── Nomad-Bitwarden.exe
  ```

  The vault lives in `App\Data` *inside* the install dir. Because the update swap replaces `App\` wholesale, Nomad copies `Data\` onto the staged install before the swap (`preserve_state_across_update`), so your login survives updates.
- **Portability:** launched with `BITWARDEN_APPDATA_DIR=App\Data` (redirects all user data) and `ELECTRON_NO_UPDATER=1` (disables the app's built-in updater so Nomad is the sole updater).
- **Trimmed config:** Bitwarden ships its own `nomad.toml` listing only the keys that affect it (`install_dir`, `[update]`, `extra_args`, `scrub_thumbnail_cache`). The browser-only privacy keys (`incognito`, `disable_webrtc`, `reduce_system_info`, the Gecko/Chromium hardening) do nothing for an Electron app and are omitted.
- **No Windows Hello.** Biometric unlock requires Bitwarden's signed installer; portable/extracted installs are master-password-only (a smaller unlock surface). Pair it with a short vault timeout.
- **First run downloads ~344 MB** (the full Electron app); later launches are instant and only re-download on a version bump.

---

## Privacy hardening

Nomad applies a curated **"safe" hardening profile** on every launch. The goal is maximum privacy without breaking website functionality. Aggressive, site-breaking measures (full fingerprint-resistance, `--disable-webgl`, arkenfox `[SETUP-HARDEN]`) are deliberately excluded.

### Chromium-family (Ungoogled Chromium, Helium)

A fixed set of launch flags applied on every invocation (cannot be overridden via the browser UI):

- **Portability:** `--disable-machine-id`, `--disable-encryption`
- **Hygiene:** `--disable-sync`, `--disable-background-networking`, `--disable-breakpad`, `--disable-component-update`, `--disable-features=JumpList`, `--no-default-browser-check`, `--disable-top-sites`
- **Anti-tracking / fingerprinting:** `--disable-search-engine-collection`, canvas noise, client-rects noise, measureText noise, `--force-punycode-hostnames`
- **Network privacy:** `--no-pings`, `--disable-grease-tls`, `--http-accept-header` (Tor Browser value), WebRTC restricted to public interface
- **Features:** `RemoveClientHints`, `SpoofWebGLInfo`, `MinimalReferrers` (cross-origin referrer stripping)
- **DNS-over-HTTPS** seeded to Quad9 secure mode via `Local State`

Locked-down `chrome://flags`-style state is also seeded into `<user-data-dir>/Local State` and `<user-data-dir>/Default/Preferences` — seven privacy-critical scalar keys (Safe Browsing, HTTPS-only mode, Privacy Sandbox m1, DoH mode/templates) are re-applied from Nomad's defaults on every launch, so a tampered profile cannot silently re-enable them.

**uBlock Origin:** for Ungoogled Chromium, sourced directly from [gorhill/uBlock](https://github.com/gorhill/uBlock) GitHub releases (`uBlock0_X.X.X.chromium.zip`). Before download, the release tag's GPG signature is verified against gorhill's embedded signing key (key ID `F5630CAE62A14316`) — this proves the release is gorhill's, but covers the tag only: GitHub release assets are mutable and gorhill publishes no asset checksums, so the zip's upload timeline is additionally checked and an asset replaced or re-uploaded after publication is refused (the update is skipped; the launch never fails). The zip is then extracted to `nomad-extensions/uBlock0/` and loaded via `--load-extension=` at launch. **Helium ships with uBlock Origin built in** (its own [imputnet/uBlock](https://github.com/imputnet/uBlock) soft-fork), so Nomad does not provision uBO for it. There is no in-browser extension install or update path on Chromium, consistent with the locked-profile design. uBO's *extension binary* is updated by Nomad's launch-time updater; uBO's *filter lists* continue to update over the network during a session, independently of the binary.

### Gecko-family (Firefox, Floorp, Waterfox, LibreWolf, Mullvad)

Two layers written into the install directory on every launch:

1. **`user.js`** — Nomad's curated safe profile derived from the [arkenfox user.js](https://github.com/arkenfox/user.js) template: the arkenfox core minus every preference arkenfox itself tags as site-breaking or aggressive. The Nomad-written block is fenced with marker comments; any preferences you add outside the fence are preserved across relaunches.
2. **`distribution/policies.json`** — structural locks the browser cannot override: disables the browser's built-in updater (Nomad is the sole updater), disables telemetry / studies / crash reporting, disables Pocket and Firefox accounts. Also provisions uBlock Origin from a locally cached `.xpi` file (sourced once from AMO at provisioning time) — no per-launch connection to addons.mozilla.org.

LibreWolf is treated the same as the other Gecko browsers here, even though it ships pre-hardened. The reason: LibreWolf's portable ZIP from `dl.librewolf.net` does not bundle uBlock Origin (only the `.exe` installer build does), so we provision it the same way we do for upstream Firefox. We do **not** overwrite LibreWolf's own `librewolf.cfg` / autoconfig pair.

**Mullvad Browser is the exception — Nomad does not harden it.** It ships its own comprehensive anti-fingerprinting (Tor-derived `resistFingerprinting`, letterboxing, standardized user-agent / timezone / fonts) plus uBlock Origin and NoScript pre-installed, all built around a crowd-blending model where every user looks identical. Nomad writes **no** `user.js` and provisions **no** uBlock Origin for it — any added preference would make individual users distinguishable and defeat that model. The only policy written is `DisableAppUpdate` (Nomad is the sole updater); Mullvad's own bundled configuration is left untouched. Verification is GPG (the Tor Browser Developers signing key) plus the SHA-256 GitHub asset digest.

**Floorp dashboard removed.** Floorp ships its own "Floorp Start" new-tab page with a sponsored tile and several non-stock UI surfaces (a Workspaces selector, a Panel Sidebar). Nomad disables all three via `floorp.design.configs`, `floorp.workspaces.enabled`, and `floorp.panelSidebar.enabled` so portable Floorp looks and feels like stock Firefox. The empty-state bookmarks-toolbar hint is also hidden globally (`browser.toolbars.bookmarks.visibility = "never"`).

### WebRTC (both families)

WebRTC is **fully disabled by default** (`[hardening] disable_webrtc = true`). WebRTC STUN requests expose your real WAN IP to any site that asks — including through a VPN, where it is one of the most common and least-obvious IP-leak vectors. Nomad is a privacy browser; video and audio calls belong in a different browser.

To re-enable WebRTC, set `disable_webrtc = false` in `nomad.toml`. This restores the *restricted* mode — WebRTC is limited to the public-facing interface (no LAN/local IP leakage) but your real WAN IP is still visible via STUN. VPN users: choose a provider with explicit WebRTC/IP-leak protection and verify your setup at [browserleaks.com/webrtc](https://browserleaks.com/webrtc) before re-enabling.

### Updates (both families)

Every browser normally ships its own auto-updater that polls the vendor on a background schedule — often while the browser is closed — leaking your IP and build/version on the vendor's clock, and some updaters attach a persistent install ID. Nomad locks those updaters off (a `DisableAppUpdate` policy, the updater binaries stripped after extraction, `--disable-component-update` on Chromium) and becomes the **sole updater**: no background update service, no scheduled phone-home. The only update contact is a plain, ID-less manifest fetch that runs **when you launch** the browser — gated by `[update] check_on_launch` and a short version-cache TTL, not a daemon's timer.

This is an update-channel win, not a browsing-privacy one. And it has a cost (see [Trade-offs](#trade-offs-you-should-know-about) below): you only get patched when you run the launcher, so a rarely-used browser can fall behind.

### Trade-offs you should know about

Privacy hardening is not free. Things you lose under the default profile:

- **Browser-level Safe Browsing is off.** Safe Browsing phones home to Google or Mozilla every ~30 minutes with URL prefix hashes; the trade-off was unacceptable for a "no traces" launcher. You lose browser-level phishing/malware URL protection. As a substitute, Nomad points DoH at **Quad9's malware-blocking resolver** (`dns.quad9.net`) by default on Chromium, Helium, Firefox, Floorp, and LibreWolf — it refuses known phishing/malware domains at the DNS layer (privacy is identical to the no-filtering endpoint; Quad9 just declines to resolve known-bad domains). The two exceptions: **Waterfox** uses its own DNS-over-Oblivious-HTTP (stronger IP privacy via a Fastly relay, but no malware blocklist), and **Mullvad** uses its own DNS — on those two, lean on uBlock Origin plus your own network-layer filtering.
- **Studies, telemetry, and crash reporting are off.** You won't contribute crash data back upstream. If you hit a reproducible bug in Firefox, please report it manually.
- **Sponsored content is off.** Sponsored top sites, Pocket, sponsored stories — all off. (Floorp's sponsored "Cubesoft" tile is also disabled.)
- **Explorer briefly restarts on exit — only if you opt in.** Thumbnail/icon cache scrubbing is off by default. If you enable it with `[hardening] scrub_thumbnail_cache = true`, the scrub terminates and restarts Explorer to flush the cache files, and the taskbar flickers for a moment.
- **WebRTC is off.** All WebRTC-based video and audio calls (Google Meet, Teams, Discord video, Zoom in-browser, etc.) will not work. Set `[hardening] disable_webrtc = false` to re-enable the restricted mode; see [WebRTC](#webrtc-both-families) above.
- **Browser and extension auto-update is disabled.** Nomad is the sole updater — the browser's own updater is locked off via `policies.json`, and Ungoogled Chromium has no extension install path. uBO's *extension binary* is updated by Nomad at launch (when `[update] check_on_launch = true`); uBO's *filter lists* update themselves over the network during a session. If Nomad isn't running, neither the browser nor the uBO binary is getting updates.
- **Mullvad Browser is launched completely unmodified.** It ships its own anti-fingerprinting stack and relies on every user looking identical (the *anonymity set*); Nomad applies **no** `user.js`, **no** prefs, and **no** uBO to it. Repackaging-not-modifying is the whole point — for true fingerprint resistance use Mullvad Browser rather than the Nomad "safe" profile on another browser.
- **Profile encryption (DPAPI) is off on Chromium.** Required for portability — DPAPI binds the profile to the host user account. Cookies and passwords in the profile are stored unencrypted on disk. Mitigate by keeping the launcher on an encrypted volume (BitLocker To Go or VeraCrypt), and avoid saving passwords in the browser on machines you don't control.

If any of these trade-offs aren't right for you, set `[hardening] enabled = false` in `nomad.toml` to launch with no hardening at all and configure the browser yourself.

### What Nomad does *not* protect against — scope & status

Nomad's threat model is **portable, low-trace browsing on a Windows host you don't fully control** — it minimizes browser telemetry and the trail Windows leaves on disk. It is **not**:

- **An anonymity tool.** For real fingerprint resistance, use **Mullvad Browser** (which Nomad launches unmodified), or get **Tor Browser** directly from the Tor Project (Nomad does not bundle it). The "safe" hardening profile on the other browsers reduces tracking but does **not** make you anonymous, and a **residual WebGL fingerprint remains** — disabling WebGL breaks too many sites to be a "safe" default (see the BrowserLeaks notes in [AUDIT.md](AUDIT.md)).
- **A guarantee against a compromised host.** If the machine has malware, a keylogger, or an attacker with admin rights, no browser launcher can defend you. Chromium profile encryption (DPAPI) is also off for portability — keep the drive on an encrypted volume.
- **Independently audited.** The review in [AUDIT.md](AUDIT.md) is the project's **own** audit; Nomad has **not** had a third-party security audit. Use it accordingly.

What you *can* rely on: every download is integrity-checked before it runs — GPG where the upstream publishes a key, SHA-256/512 otherwise, and an Authenticode signer-pin for Bitwarden (see [Verification](#verification)).

---

## Post-exit cleanup (the host-trace scrubber)

In-browser hardening only addresses what the browser itself records. Windows is the second half of the threat model — it logs paths, names, and metadata across roughly a dozen system locations completely outside the browser's control. A portable browser that ignores this leaves a trail back to the USB drive every time it runs.

When the browser process exits, Nomad spawns a detached watcher that waits for the full process tree to settle (background-task children, updater stubs, etc.) and then deletes the host-side artefacts Windows wrote during the session:

| Location | What gets removed | Why it leaks |
|---|---|---|
| `%TEMP%\` | Chromium `scoped_dir*`, `.org.chromium.*`, `chrome_*`; Mozilla `mozilla-temp-*`, `.moz_extension*` | Browsers stage downloads, extensions, sandbox state here |
| `%APPDATA%\Microsoft\Windows\Recent\*.lnk` | Shortcuts whose target lives on the portable drive | Windows auto-creates these when documents are opened |
| `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | Jump List databases mentioning the portable drive path | Pinned/recent entries in the taskbar Jump List |
| `%LOCALAPPDATA%\CrashDumps\` | Crash dumps for `chrome.exe`, `firefox.exe`, `floorp.exe`, `librewolf.exe`, `mullvadbrowser.exe`, `waterfox.exe` | Windows Error Reporting writes here on any crash |
| `%ProgramData%\Microsoft\Windows\WER\Report{Queue,Archive}\` | WER report subdirectories for the same exe names | System-wide WER queues holding crash metadata |
| `%LOCALAPPDATA%\{Mozilla, Firefox, Floorp, Noraneko, Waterfox, LibreWolf}\` | Gecko runtime working dirs | `nsXREDirProvider` hardcodes these — `--profile` does not redirect them |
| `%ProgramData%\{Mozilla, Floorp, Noraneko, Waterfox, LibreWolf}-<HASH>\` | Install-hash dirs Gecko creates for elevated updates | Same Mozilla machinery |
| `%APPDATA%\Mozilla\Firefox\installs.ini` | Profile-to-install registration files | Written by NSIS installers and `firefox.exe` itself |

Two scrub paths need extra handling:

- **Windows Prefetch** (`C:\Windows\Prefetch\`) — Prefetch records the full path to every executable run, and removing entries requires administrator privileges. Nomad attempts the scrub unprivileged first; if that fails it re-spawns itself with `runas` (the standard UAC prompt). Decline the UAC dialog if you'd rather skip it — the rest of the cleanup is unaffected.
- **Thumbnail cache** (`%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db`, `iconcache_*.db`) — **Off by default (opt-in).** Scrubbing it briefly restarts Explorer (the taskbar flickers for a moment), so it is not enabled by default. Set `[hardening] scrub_thumbnail_cache = true` in `nomad.toml` to enable it on forensics-sensitive machines.

The watcher is a detached child of the same launcher binary — there's no second `.exe`. It exits when its work is done; no service, no scheduled task.

---

## Verification

Every download is verified before extraction:

- **SHA-256** — checked against the hash published in the upstream release metadata.
- **GPG** — for Firefox and Firefox ESR, the package is additionally verified against the Mozilla release-signing key embedded in the launcher binary at compile time (no runtime key fetch). Missing or invalid signatures abort the download.
- **Authenticode** — for Bitwarden (which publishes no GPG key), the downloaded `.exe` is additionally checked with `WinVerifyTrust` (including revocation when the revocation servers are reachable) and its signer subject must equal `Bitwarden Inc.` before it is staged.
- **URL host pinning** — download URLs are checked against a hardcoded allowlist of trusted hosts (GitHub, Mozilla, AMO, the LibreWolf and Waterfox CDNs) before any request is made.

Browsers without an upstream signing key Nomad can use — Floorp, Waterfox, Helium, LibreWolf — are SHA-256-verified only. The absence of a GPG signature is logged at `WARN` level on every download so the trade-off is visible. (Helium's case is unusual: the upstream signs commits via GitHub's web-flow key, which cannot produce detached signatures for release assets, so there is no usable key for Nomad to embed.)

**uBlock Origin verification:**
- **Gecko browsers (Firefox, Floorp, Waterfox, LibreWolf):** the Mozilla-signed XPI downloaded from AMO is authenticated against the embedded AMO signature (`META-INF/mozilla.rsa` + `META-INF/mozilla.sf`). An unsigned XPI is rejected and deleted before staging.
- **Ungoogled Chromium:** the gorhill release tag's GPG signature is verified against the embedded gorhill key (`F5630CAE62A14316`) before the zip is downloaded — proving gorhill published the release. The signature covers the tag/commit only, not the zip bytes (release assets are mutable and gorhill publishes no asset checksums), so the asset's upload timeline is also checked for tamper evidence: an asset modified or re-uploaded after publication defers the update with a warning.

---

## Building from source

**Requirements:** Rust 1.77+, Windows 10/11 (or cross-compile with MSVC target).

For a development build (debug profile, fast compile, no packaging):

```
cargo build --workspace
```

For a release build:

```powershell
.\dist.ps1
```

`dist.ps1` runs `cargo build --workspace --release`, then writes a `SHA256SUMS` file over the launchers and — when the `NOMAD_SIGNING_KEY` environment variable is set to the Nomad release key — a detached `SHA256SUMS.asc` signature beside it. The finished launchers land in `target/release/` as `Nomad-<browser>.exe`; ship those together with `SHA256SUMS` (and `SHA256SUMS.asc`). See [Verifying a release](#verifying-a-release) for how downstream users check them.

Run the test suite with `cargo test --workspace` and the lint gate with `cargo clippy --workspace --all-targets -- -D warnings` — both should pass clean before any release.

The build embeds each browser-branded icon into its `.exe` via `winresource` — no separate packaging step is needed. The Helium `build.rs` will abort if its icon placeholder has not been replaced with the real brand icon.

---

## Verifying a release

Release builds ship two integrity files alongside the `Nomad-<browser>.exe` launchers:

- **`SHA256SUMS`** — SHA-256 of every launcher, in `sha256sum -c` format.
- **`SHA256SUMS.asc`** — a detached GPG signature of `SHA256SUMS`, made with the Nomad release key.

> **Note:** the Nomad release signing key is being introduced. Once published, its public key lives at `nomad-release.asc` in the repository root, fingerprint `<RELEASE-KEY-FINGERPRINT>`. Until then, releases carry `SHA256SUMS` only (unsigned).

To verify a download:

```bash
# 1. Import the Nomad release public key (once)
gpg --import nomad-release.asc

# 2. Confirm SHA256SUMS itself is authentic (signed by the Nomad release key)
gpg --verify SHA256SUMS.asc SHA256SUMS
#    Expect: Good signature from "Nomad Launcher Releases ..."
#    and confirm the reported key fingerprint matches the one published above.

# 3. Confirm each binary matches the now-trusted checksums
sha256sum -c SHA256SUMS          # Linux / macOS / Git Bash
```

On Windows PowerShell without `sha256sum`, compare a hash by hand:

```powershell
(Get-FileHash .\Nomad-Chromium.exe -Algorithm SHA256).Hash.ToLower()
# must equal the Nomad-Chromium.exe line in SHA256SUMS
```

The trust chain: your verification of the published fingerprint → `SHA256SUMS.asc` proves `SHA256SUMS` is genuine → the listed hashes prove each `.exe` is intact. Note these are GPG/checksum integrity guarantees, **not** an Authenticode signature — Windows SmartScreen and antivirus do not consult them, so a fresh download may still show an "unknown publisher" prompt.

---

## Architecture

```
nomad-launcher/
  core/                   # nomad-core library crate — all shared logic
    src/
      lib.rs              # run() entry point, launch/update/cleanup flow
      config.rs           # nomad.toml load/validate (deny_unknown_fields)
      updater.rs          # launch-time update check
      downloader.rs       # HTTP download with ProgressSink
      gpg.rs              # pure-Rust GPG verify + SHA-256
      authenticode.rs     # WinVerifyTrust signer pinning (Bitwarden)
      hardening.rs        # Gecko user.js + policies.json writer
      registry.rs         # optional HKCU default-browser registration
      taskbar.rs          # ITaskbarList3 Windows taskbar progress
      ui/                 # egui/eframe transient status window
      browsers/           # BrowserFamily implementations
    tests/                # httpmock-driven integration tests
      integration/        # downloader / pipeline / ungoogled end-to-end
    keys/                 # embedded ASCII-armored GPG public keys
    payloads/             # vendored hardening payloads (user.js, policies.json, flags)
  launchers/              # one thin binary crate per browser
    ungoogled-chromium/   # Nomad-Chromium.exe
    firefox/
    firefox-esr/
    floorp/
    waterfox/
    helium/
    librewolf/
    mullvad/                # Nomad-Mullvad.exe
    bitwarden/              # Nomad-Bitwarden.exe (Electron password manager, not a browser)
  dist.ps1                # release build script (cargo build --release --workspace)
```

All hardening payloads are **vendored** — embedded at compile time via `include_str!`, never fetched at runtime. This keeps the launchers fully functional offline and on USB drives with no network access for anything other than the browser update check itself.

---

## Default browser registration (optional)

```
Nomad-Firefox.exe --register-default
Nomad-Firefox.exe --unregister-default
```

Writes to `HKCU\Software\Classes\...` only (no UAC). Registration state is recorded in `Nomad/nomad.reg-state.json` (alongside the rest of Nomad's bookkeeping — see [On-disk layout](#on-disk-layout)); unregister reads that file and removes exactly those keys, no guessing.

---

## Portability guarantee

Nomad writes only within its own directory and `HKCU` (when explicitly asked). It never touches `%APPDATA%`, `%LOCALAPPDATA%`, `HKLM`, or any path not relative to the `.exe` during normal operation. Moving the entire launcher folder to a different drive or machine requires no reconfiguration.

Note that *during* a browser session, Windows itself writes to host paths regardless — that's what the [post-exit cleanup watcher](#post-exit-cleanup-the-host-trace-scrubber) is for.

---

## Troubleshooting

**Nothing seems to happen when I run the launcher.**
First-run downloads can take 30–90 seconds before the status window has anything to show. If after a minute the window has not opened, check `Nomad/nomad.log` beside the `.exe` for a network or verification error. If the log is empty, Windows SmartScreen may be silently quarantining the executable — check Windows Security → Protection History.

**The browser launched but uBlock Origin isn't installed.**
On first launch, the XPI is provisioned but the browser may take an extra restart to pick it up. If `Nomad/Gecko-extensions/uBlock0.xpi` exists but `about:addons` doesn't show uBlock, close the browser fully and re-launch. If it still won't install, check that the file is signed (Mozilla AMO signature): `unzip -l Nomad/Gecko-extensions/uBlock0.xpi | grep META-INF` should show `META-INF/mozilla.rsa` and `META-INF/mozilla.sf`.

**uBlock Origin didn't update to the latest version / I want to force a re-provision.**
Nomad checks for a newer uBO binary at each launch when `[update] check_on_launch = true`. To force a re-provision manually, delete the staged file and re-launch:
- Gecko browsers: delete `Nomad/Gecko-extensions/uBlock0.xpi`
- Ungoogled Chromium: delete `Browser/default_apps/uBlock0.crx`

Note: uBO's *filter lists* always update over the network during a session regardless of this setting — only the *extension binary itself* is managed by Nomad.

**My browser profile reset / I lost my bookmarks.**
You probably deleted `Data/` instead of `Nomad/`. The browser's profile is the `Data/` folder; deleting it wipes the browser's data. Deleting `Nomad/` only resets Nomad's bookkeeping (config, log, version cache). See [On-disk layout](#on-disk-layout).

**The status window says "no GPG signature" — is that a problem?**
That's an informational warning for browsers whose upstream doesn't publish a usable signing key (Floorp, Waterfox, Ungoogled Chromium, Helium, LibreWolf). The download is still SHA-256 verified against the hash GitHub records for each release asset. See [Verification](#verification).

**I want to reset to a clean state without re-downloading the browser.**
Delete the `Nomad/` folder. Next launch will recreate it with defaults; the `Browser/` folder and your profile are untouched.

**I'm behind a corporate proxy / firewall and the update check fails.**
Set `[update] check_on_launch = false` in `Nomad/nomad.toml`. The launcher will skip the update check entirely and use whatever is currently installed in `Browser/`. You can update manually by deleting `Browser/` and re-running.

---

## License

Licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work shall be dual-licensed as above, without any additional terms or conditions.

## Third-party components & trademarks

Nomad bundles, inside its launcher binaries, two third-party components under their own licenses: the **Atkinson Hyperlegible** font (SIL OFL 1.1) and **7-Zip 24.09** (LGPL-2.1, distributed unmodified — source at <https://www.7-zip.org/>). Their license texts ship in the `licenses/` folder of each release alongside `THIRD-PARTY-NOTICES.txt`.

The browsers and apps Nomad launches — Firefox, Mullvad Browser, Ungoogled Chromium, Helium, Floorp, Waterfox, LibreWolf, and Bitwarden — are downloaded from their official sources at runtime and remain the property of their respective owners under their own licenses. **Their names and logos are trademarks of their respective owners.** Nomad is an **independent project** and is **not affiliated with, endorsed by, or sponsored by** any of them. See [TRADEMARKS.md](TRADEMARKS.md) for the per-product trademark posture.
