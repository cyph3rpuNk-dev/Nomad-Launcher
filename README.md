<h1 align="center">
  <img src="core/payloads/nomad/nomad.png" width="220" alt="Nomad Launcher">
</h1>

<p align="center">
  <a href="https://github.com/cyph3rpuNk-dev/Nomad-Launcher/releases/latest"><img src="https://img.shields.io/github/v/release/cyph3rpuNk-dev/Nomad-Launcher?label=version" alt="Latest release"></a>
  <a href="https://github.com/cyph3rpuNk-dev/Nomad-Launcher/releases"><img src="https://img.shields.io/github/downloads/cyph3rpuNk-dev/Nomad-Launcher/total" alt="Total downloads"></a>
  <a href="https://github.com/cyph3rpuNk-dev/Nomad-Launcher/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/cyph3rpuNk-dev/Nomad-Launcher/ci.yml?branch=main&label=build" alt="CI status"></a>
  <a href="https://github.com/cyph3rpuNk-dev/Nomad-Launcher/issues"><img src="https://img.shields.io/github/issues/cyph3rpuNk-dev/Nomad-Launcher" alt="Open issues"></a>
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue" alt="License"></a>
</p>

Single-file portable Windows browser launchers. Drop the `.exe` anywhere — USB drive, network share, local folder — and it downloads, GPG-verifies (where upstream signs), privacy-hardens, and launches the browser. When you close the browser, Nomad scrubs the host traces Windows leaves behind.

No installer. No `HKLM` writes. No persistent services. No `%APPDATA%`. The browser lives in the launcher's directory and dies with it.

**Status:** Functionally complete and in daily use. *Inspired by [chrlauncher](https://github.com/henrypp/chrlauncher).*

<p align="center">
  <img src="docs/launcher.png" width="520" alt="Nomad Launcher downloading and updating Firefox">
</p>

---

## Supported browsers

| Launcher | Browser | Verification |
|---|---|---|
| `Nomad-Firefox.exe` | Firefox Stable | GPG + SHA-256 |
| `Nomad-Firefox-ESR.exe` | Firefox ESR | GPG + SHA-256 |
| `Nomad-Mullvad.exe` | [Mullvad Browser](https://mullvad.net/en/browser) | GPG + SHA-256 |
| `Nomad-LibreWolf.exe` | [LibreWolf](https://librewolf.net) | SHA-256 |
| `Nomad-Floorp.exe` | [Floorp](https://floorp.app) | SHA-256 |
| `Nomad-Waterfox.exe` | [Waterfox](https://www.waterfox.net) | SHA-512 |
| `Nomad-Chromium.exe` | [Ungoogled Chromium](https://github.com/ungoogled-software/ungoogled-chromium) | SHA-256 |
| `Nomad-Helium.exe` | [Helium](https://github.com/imputnet/helium-windows) | SHA-256 |
| `Nomad-Bitwarden.exe` | [Bitwarden](https://bitwarden.com) desktop (not a browser) | SHA-256 + Authenticode |

---

## Getting started

1. Copy the `.exe` to any folder you have write access to.
2. Run it.

On first run Nomad creates a `Nomad/` subfolder, writes a default `nomad.toml`, then downloads and launches the browser. A status window shows progress and closes once the browser starts. No elevation required.

---

## Configuration

`nomad.toml` lives in the `Nomad/` subfolder beside each launcher. Unknown keys are rejected at startup — silent misconfiguration is not possible.

```toml
[browser]
install_dir = "browser"      # relative to the .exe
arch = "x64"                 # "x64" | "x86" | "arm64"

[update]
check_on_launch = true       # false = skip update check
auto_download = true         # false = prompt before downloading

[launch]
language = "en-US"
extra_args = []
incognito = false

[hardening]
enabled = true
sanitize_on_shutdown = true
disable_webrtc = true        # WebRTC is off by default — real WAN IP leaks through VPNs via STUN
scrub_thumbnail_cache = false  # opt-in: briefly restarts Explorer on exit
clear_data_on_exit = false   # Chromium only: wipe cookies/history/sessions on exit
reduce_system_info = true    # Chromium only: ReducedSystemInfo fingerprint hardening
```

---

## Privacy hardening

Nomad applies a curated **"safe" hardening profile** — maximum privacy without breaking sites. Aggressive, site-breaking measures are deliberately excluded.

**Chromium (Ungoogled Chromium, Helium):** launch flags disable sync, telemetry, JumpList, and machine ID; enable canvas/rects/measureText noise, WebRTC restriction, and referrer stripping. DoH is seeded to Quad9 secure mode. uBlock Origin is loaded via `--load-extension=` (sourced from [gorhill/uBlock](https://github.com/gorhill/uBlock) releases, GPG-verified tag).

**Gecko (Firefox, Floorp, Waterfox):** a fenced `user.js` (arkenfox-derived, safe subset) and a `policies.json` (disables updater, telemetry, Pocket) are written on every launch. uBlock Origin is provisioned from a locally cached AMO-signed `.xpi`.

**LibreWolf** ships pre-hardened, so Nomad applies a lighter touch. It gets its own minimal `user.js` — not the shared Firefox one — that adds only what LibreWolf doesn't already do: Quad9 malware-blocking DoH, `geo.enabled` off, network prediction off, WebRTC restricted, and the shutdown sanitize block. LibreWolf's own `librewolf.cfg` and autoconfig pair are never touched, and `privacy.resistFingerprinting` is left intact. uBlock Origin is provisioned the same way as Firefox (the portable ZIP doesn't bundle it).

**Mullvad Browser** is launched completely unmodified — it ships its own crowd-blending anti-fingerprinting stack and any added pref would make users distinguishable.

### Trade-offs

- **Safe Browsing is off.** Substitute: DoH points at Quad9's malware-blocking resolver by default.
- **WebRTC is off.** Video/audio calls (Meet, Teams, Discord) won't work. Set `disable_webrtc = false` to restore restricted mode.
- **Chromium profile encryption (DPAPI) is off** for portability — keep the drive on an encrypted volume.
- **Browser auto-update is disabled.** Nomad is the sole updater; you're only patched when you run the launcher.
- **Mullvad is unmodified.** No `user.js`, no uBO provisioning — Nomad defers entirely to Mullvad's own stack.

Set `[hardening] enabled = false` to launch with no hardening and configure the browser yourself.

---

## Post-exit cleanup

When the browser closes, Nomad runs a detached watcher that scrubs the host traces Windows writes on its own:

| Location | What gets removed |
|---|---|
| `%TEMP%\` | Chromium and Mozilla temp files |
| `%APPDATA%\...\Recent\` | `.lnk` shortcuts targeting the portable drive |
| `%APPDATA%\...\AutomaticDestinations\` | Jump List entries mentioning the portable path |
| `%LOCALAPPDATA%\CrashDumps\` | Crash dumps for the launched browser |
| `%LOCALAPPDATA%\{Mozilla, Firefox, Floorp, …}\` | Gecko runtime working dirs |
| `C:\Windows\Prefetch\` | Prefetch entries (requires UAC — decline to skip) |

Thumbnail cache scrubbing is opt-in (`scrub_thumbnail_cache = true`) — it briefly restarts Explorer.

---

## On-disk layout

```
C:\Portables\Firefox\
├── Browser\              # browser install
├── Data\                 # browser profile
├── Nomad\
│   ├── nomad.toml
│   ├── nomad.log
│   └── nomad-version-cache.toml
└── Nomad-Firefox.exe
```

To reset to first-run state, delete `Nomad/`. To wipe everything, delete the whole folder.

---

## Building from source

Requires Rust 1.77+ on Windows 10/11.

```powershell
cargo build --workspace          # debug build
.\dist.ps1                       # release build → target/release/Nomad-<browser>.exe
cargo test --workspace           # test suite
cargo clippy --workspace --all-targets -- -D warnings
```

`dist.ps1` also writes a `SHA256SUMS` manifest and — when `NOMAD_SIGNING_KEY` is set — a detached `SHA256SUMS.asc` signature.

---

## Verifying a release

```bash
# Import the Nomad release key and confirm the fingerprint:
# 4D92 5DAD 1DB4 405C 99EA 1FD3 9984 5DA3 20CD 1F37
gpg --import nomad-release-signing-key.asc
gpg --fingerprint 4D925DAD1DB4405C99EA1FD399845DA320CD1F37

# Verify the manifest, then check your binary against it
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

On Windows PowerShell: `(Get-FileHash .\Nomad-Firefox.exe -Algorithm SHA256).Hash.ToLower()` and compare against the `SHA256SUMS` line.

---

## Default browser registration

```powershell
Nomad-Firefox.exe --register-default
Nomad-Firefox.exe --unregister-default
```

Writes to `HKCU` only (no UAC). State is tracked in `Nomad/nomad.reg-state.json`.

---

## Troubleshooting

**Nothing happens on launch.** First-run downloads take 30–90 seconds. Check `Nomad/nomad.log` for errors. If the log is empty, Windows SmartScreen may be quarantining the `.exe` — check Windows Security → Protection History.

**"Windows protected your PC" on first launch.** Expected, not a malware detection. The launchers are unsigned, so Microsoft Defender SmartScreen flags them as "unrecognized" until they accrue download reputation — this happens to any new unsigned executable, not just Nomad. The binary is unmodified and still verifiable against `SHA256SUMS`. To run it: click **More info** → **Run anyway**, or clear the download mark first with `Unblock-File .\Nomad-Firefox.exe` (PowerShell) or right-click → Properties → tick **Unblock**. Don't disable SmartScreen system-wide to work around this — the per-file unblock is the correct scope.

**uBlock Origin isn't installed.** Close and re-launch once. If it still doesn't appear, check that `Nomad/Gecko-extensions/uBlock0.xpi` exists and contains `META-INF/mozilla.rsa`.

**To force a uBO re-provision:** delete `Nomad/Gecko-extensions/uBlock0.xpi` (Gecko) or `Browser/default_apps/uBlock0.crx` (Chromium) and re-launch.

**I lost my bookmarks.** You deleted `Data/` (the browser profile) instead of `Nomad/` (Nomad's bookkeeping). They are separate folders.

**"No GPG signature" warning.** Informational only — Floorp, Waterfox, Helium, LibreWolf, and Ungoogled Chromium don't publish a usable signing key. The download is still SHA-256 verified.

**Behind a proxy / update check fails.** Set `[update] check_on_launch = false` in `nomad.toml`.

---

## FAQ

**Does this require administrator privileges?**
No. Everything runs as the current user. The optional `--register-default` flag writes to `HKCU` only — no UAC prompt.

**Where does the browser get installed?**
In a `Browser/` folder beside the launcher (see [On-disk layout](#on-disk-layout)). Nothing is written to `Program Files`, `%APPDATA%`, `%LOCALAPPDATA%`, or any system location during normal operation.

**Does it work from a USB drive?**
Yes. The launcher and its `Browser/` and `Data/` folders are fully portable — move them anywhere and they behave the same.

**Does it leave anything behind after I delete it?**
Runtime traces Windows writes on its own are scrubbed when the browser closes (see [Post-exit cleanup](#post-exit-cleanup)). Delete the launcher's folder and nothing remains. If you used `--register-default`, run `--unregister-default` first to remove the `HKCU` entries.

**What happens if a download fails verification?**
The launcher aborts before extracting or running anything. Any existing install is left untouched.

**What if I'm already on the latest version?**
Nomad keeps a local version cache (6-hour TTL). Within that window it skips the network check entirely and launches immediately.

**Can each launcher have its own `nomad.toml`?**
Yes. Every launcher reads the `nomad.toml` in its own `Nomad/` folder independently.

---

## Compatibility

| Component | Requirement |
|---|---|
| Operating system | Windows 10 or Windows 11 (64-bit) |
| Launcher build | `x86_64-pc-windows-msvc` |
| Browser architecture | `x64` (default), `x86`, or `arm64` — selectable via `[browser] arch` |
| Runtime dependencies | None beyond stock Windows 10/11 DLLs |
| Network | Required for first run and update checks |

---

## Acknowledgements

Nomad launches and builds on the work of these projects:

- [Firefox](https://www.mozilla.org/firefox/) / Firefox ESR, [Floorp](https://floorp.app), [Waterfox](https://www.waterfox.net), [LibreWolf](https://librewolf.net), [Mullvad Browser](https://mullvad.net/en/browser), [Ungoogled Chromium](https://github.com/ungoogled-software/ungoogled-chromium), [Helium](https://github.com/imputnet/helium-windows), and [Bitwarden](https://bitwarden.com).
- [arkenfox/user.js](https://github.com/arkenfox/user.js) — basis for the Gecko "safe subset" `user.js`.
- [uBlock Origin](https://github.com/gorhill/uBlock) — provisioned automatically for the Gecko launchers (AMO-signed XPI) and Ungoogled Chromium (GPG-verified gorhill release). Helium ships its own built-in fork, so Nomad does not provision it there.

Nomad is an independent project and is not affiliated with, endorsed by, or sponsored by any of the projects above. See [TRADEMARKS.md](TRADEMARKS.md).

---

## License

MIT or Apache 2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

Nomad bundles **Atkinson Hyperlegible** (SIL OFL 1.1) and **7-Zip 24.09** (LGPL-2.1) inside its binaries. License texts ship in `licenses/` alongside each release.

The browsers Nomad launches are the property of their respective owners. Nomad is an independent project, not affiliated with or endorsed by any of them. See [TRADEMARKS.md](TRADEMARKS.md).
