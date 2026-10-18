# User guide

[Back to the overview](../README.md) · [Verify a release](VERIFYING-RELEASES.md) · [Privacy and cleanup](PRIVACY.md)

- [Requirements](#compatibility)
- [First run](#first-run)
- [Folder layout and resetting settings](#on-disk-layout)
- [Configuration](#configuration)
- [Default browser registration](#default-browser-registration)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Retired launchers](#retired-launchers)

## Compatibility

| Component | Requirement |
|---|---|
| Operating system | Windows 10 or Windows 11 (64-bit) |
| Launcher build | `x86_64-pc-windows-msvc` |
| Browser architecture | `x64` by default; `x86` and `arm64` availability varies by browser and upstream release |
| Runtime dependencies | Launchers: stock Windows components and a usable Direct3D 12 hardware or system software adapter. Floorp itself also needs the Microsoft Visual C++ Redistributable (x64) |
| Network | Required for first run and update checks |

## First run

Download and [verify a launcher](VERIFYING-RELEASES.md), then run it directly
from its own dedicated folder. Keep one browser family per folder.

The first direct run creates `Nomad/instance.toml` and a default
`Nomad/nomad.toml`, then downloads and launches the browser. A small status
window shows progress and closes once the browser is up.

Normal launching, updating and cleanup do not request administrator rights.
Windows Prefetch records are preserved; the legacy `scrub_prefetch` option
is retired and has no effect.

## On-disk layout

```
C:\Portables\Floorp\
├── Browser\              # browser install
├── Data\                 # browser profile
├── Nomad\
│   ├── instance.toml             # permanent browser-family ownership
│   ├── install.lock              # persistent file; OS lock protects update/launch
│   ├── nomad.toml                # user configuration
│   ├── nomad.log
│   ├── nomad-version-cache.toml
│   ├── managed-extension-check.json # latest successful managed-uBlock metadata lookup
│   ├── protocol-update-reminder.json # last acknowledged local reminder
│   ├── nomad.reg-state.json      # present after default registration
│   ├── nomad.registry-repairs.json # repair history and enabled/disabled state
│   └── registry-repair.lock       # persistent lock file; do not delete
└── Nomad-Floorp.exe
```

A portable folder is owned by exactly one launcher family. Do not place
different Nomad launcher executables beside the same `Browser/`, `Data/`, and
`Nomad/` directories. The ownership marker makes a mismatch fail visibly
instead of letting, for example, Helium replace a Chromium bundle.

To reset generated settings, close the browser and delete only
`Nomad/nomad.toml`; Nomad recreates it on the next direct launch. Do not delete
or edit `Nomad/instance.toml` while keeping `Browser/` or `Data/`, because it is
the guard that prevents another launcher family from claiming those paths.

For a completely fresh start, first run `--unregister-default` if registration
was enabled, close the browser, and then delete the entire portable folder.

## Configuration

Each launcher reads the `nomad.toml` in its own `Nomad/` subfolder. Unknown keys are rejected at startup, so a typo in the file shows up as an error instead of being silently ignored.

```toml
[browser]
install_dir = "Browser"      # one folder name beside the .exe
arch = "x64"                 # "x64" | "x86" | "arm64"

[update]
check_on_launch = true       # false = skip update check
auto_download = true         # false = prompt before downloading
remind_on_protocol = true    # local reminders when opening links; false = opt out

[launch]
language = "en-US"           # Chromium/Helium UI language; omit or blank for browser default
extra_args = []
incognito = false

[hardening]
enabled = true
sanitize_on_shutdown = true
disable_webrtc = true        # Gecko peer connections off; Chromium non-proxied UDP restricted
scrub_thumbnail_cache = false  # opt-in: try clearing unlocked caches; never stop Explorer
clear_data_on_exit = false   # Chromium only: wipe cookies/history/sessions on exit
reduce_system_info = true    # Chromium only: ReducedSystemInfo fingerprint hardening
```

`launch.language` requests the UI language for Ungoogled Chromium and Helium
using `--lang=<value>`, even when hardening is disabled. Surrounding whitespace
is trimmed; omitting the key or leaving it blank adds no language switch.
`extra_args = ["--lang=de"]` overrides `language` because extra arguments come
later ([Chromium switch handling](https://chromium.googlesource.com/chromium/src/+/main/base/command_line.cc)).
Nomad does not apply this setting to Gecko browsers; use their own
language settings. Available translations and fallback behavior belong to the
browser. Fully exit the browser before relaunching to apply a changed value.
Existing configs containing `language = "en-US"` now request English on Chromium
and Helium; remove that line to retain the browser's own language selection.

Release caches and successful install markers record the selected package
target. Metadata from another target is refreshed. Changing `arch` requires
verified package replacement even when the version number is unchanged. Older caches are
refreshed; older install markers remain readable but their unknown target
requires one verified replacement before Nomad can report them current.
Automatic-download settings still apply, and offline/protocol launches can
continue using the existing installation.
Nomad refuses older releases even when changing targets or migrating an older
install marker. Unknown version formats stop the update for review; they are
not compared as plain text. Older cached releases trigger a fresh lookup.
See [Package targets and legacy records](UPDATE-SAFETY.md#package-targets-and-legacy-records)
and [Downgrade protection](UPDATE-SAFETY.md#downgrade-protection).

`install_dir` must be one Windows-safe folder name beside the launcher, such
as `Browser`, `App`, or `Custom Browser`. Empty names, `.`/`..`, absolute or
drive-relative paths, nested paths such as `Apps/Browser`, and `Data` or
`Nomad` (in any letter case) are rejected. Windows device names, invalid
characters, and names ending in a space or dot are also rejected. This keeps
updates from replacing the profile or launcher state and keeps `Data/` and
`Nomad/` beside the launcher.

Existing symlinks or Windows junctions/reparse points in installation, staging,
backup, state or profile write paths are refused before mutation. Keep these as
ordinary directories/files; Nomad does not automatically move or delete an
invalid link or its target. Downloads use fixed filenames within fresh staging.
See [Filesystem paths before mutation](UPDATE-SAFETY.md#filesystem-paths-before-mutation).

If an existing config uses one of these values, Nomad reports a configuration
error instead of updating or launching. Close the browser and back up the
portable folder before correcting the setting. Changing the setting does not
move an existing installation or profile; keep the old files until the folder
layout has been reviewed.

## Default browser registration

**Recommended way to make a Nomad browser your default:**

1. Close the browser.
2. Run the launcher once with `--register-default`, for example
   `Nomad-Floorp.exe --register-default`.
3. Open Windows **Settings → Apps → Default apps**, find the entry named
   "*Browser* (Nomad Launcher: *folder*)", and set it as the default. Pick that entry,
   not the browser's own entry.

Clicked links then always go through the launcher and open as a new tab in the
browser that is already running, on your portable profile.

```powershell
Nomad-Floorp.exe --register-default
Nomad-Floorp.exe --unregister-default
```

Writes to `HKCU` only, so there is no UAC prompt. State is tracked in `Nomad/nomad.reg-state.json`.
The cleanup record is saved before the first registry write. If registration
fails or is interrupted, retry `--register-default` to finish it, or run
`--unregister-default` to remove its partial entries. Keep the record until
recovery succeeds; its presence alone does not mean registration completed.
Each launcher location gets separate registration names, and the Windows picker
label includes its folder. Registering or unregistering one portable copy leaves
other locations' entries intact.

When upgrading an older shared registration, `--register-default` preserves its
record under `Nomad/registration-history/` and creates a separate entry. Select
that new folder-labelled entry in Windows Default apps. The old shared entry is
left in place because Nomad cannot prove which copy owns it. Unregistering an old
shared record, or a record copied from another folder, is refused; register the
current copy first. Historical records are retained for manual review.

When Windows invokes a registered Nomad browser for a URL or file, the launcher
requires an existing browser installation and skips all browser and extension
update work. It forwards the URL to the same executable and portable profile,
allowing the browser's normal single-instance handoff to open a tab in the existing
window. This applies to every Nomad browser, Chromium- and Firefox-based alike. Run the launcher directly when you want to install or update software.

The registered command accepts exactly one non-empty URL or file target after
`--`. Missing or additional arguments and targets whose first non-whitespace
character is `-` or `/` are rejected before configuration or browser work. This prevents link
invocations from overriding browser launch switches. Windows file targets
should use a drive-qualified path (for example `C:\My Files\page.html`) or a
`file://` URL; spaces within one target are preserved. Configure intentional
browser switches through `[launch] extra_args`.

Before moving or renaming a registered launcher, run `--unregister-default` from
its original location. After moving it, run `--register-default` from the new path.
Outstanding automatic-repair records are bound to their original paths; Nomad
retains them and refuses repair or registration if those paths no longer match.

Browsers can also register themselves. If you use the browser's own "make this my default" button, Windows records the browser executable rather than the launcher, and a clicked link then starts a second copy of the browser on its default profile under `%LOCALAPPDATA%` or `%APPDATA%` instead of opening a tab in the portable one. That second copy has none of your extensions or sign-ins, and older versions then deleted its profile when the browser closed.

To prevent that, each launch inspects the `HKCU` handler entries and repairs recognized browser commands whose executable is inside the launcher's browser installation, so those links go through the launcher and land in the portable profile. Because the "make default" button is normally used while the browser is open, the launcher's background helper also watches those entries for the whole session and rewrites a new self-registration within about a second, and checks once more after the browser exits. Links clicked in that first second can still open a separate copy; using `--register-default` as described above avoids even that. Handlers pointing anywhere else, including other browsers and separately installed copies of the same browser, are left as they are. This is the only registry write Nomad makes without being asked, and it is confined to `HKCU`.

Automatic repairs are recorded before writing in `Nomad/nomad.registry-repairs.json`.
`--unregister-default` restores recorded commands only while they still contain
Nomad's exact replacement, preserving subsequent changes and deleted handlers.
It also disables automatic repairs until `--register-default` succeeds again,
including repairs by a helper that is already running. This works even if you
never registered the Nomad entry in Windows Settings. Custom command arguments
are left alone. Repairs made by older versions cannot be reconstructed.
Keep the journal and its lock file; see [registry repair safety](REGISTRY-SAFETY.md)
for failure recovery and concurrency limits.

## Troubleshooting

**Nothing happens on launch.** First-run downloads take 30 to 90 seconds. Check `Nomad/nomad.log` for errors. If the log is empty, Windows SmartScreen may be quarantining the `.exe`; look in Windows Security → Protection History.

**"Required browser settings failed".** Nomad stopped before creating a browser
process because required settings could not be read, validated, written or
removed. Close the browser fully, check the named path and permissions, and
restore valid settings from your own backup where needed; then choose Retry.
Launch anyway is unavailable for this error. Earlier files in the preparation
sequence may already have changed; this is not a rollback of the whole profile.
See [failure handling and validation scope](HARDENING-FAILURE-SAFETY.md).

**"The browser did not start", or a missing `VCRUNTIME140` / `MSVCP140` message.** The browser was installed, but Windows could not load it. Floorp depends on the Microsoft Visual C++ runtime and its installer does not ship it, so Floorp cannot start on a Windows where that runtime was never installed. Install the x64 [Microsoft Visual C++ Redistributable](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist) from Microsoft, then run the launcher again. In testing only Floorp was affected. Nomad asks Windows to end such a start immediately instead of showing its own "System Error" box, watches the new browser for one second, and shows this message if the start failed. A browser that fails later than that is not detected.

**"Launch failed: window error" / won't start in a virtual machine.** The Windows status window uses Direct3D 12 through wgpu and the system FXC shader compiler. It can use an available hardware or Windows software adapter; an OpenGL driver or separate Visual C++ runtime installation is not required by the launcher. Check the guest graphics support and driver if window creation fails. See `Nomad/nomad.log` beside the launcher; setting `NOMAD_LOG=debug` for that launch records more diagnostics. See [validation scope and pending checks](AUDIT-STATUS.md) for current Windows and VM coverage.

**"Windows protected your PC" on first launch.** A SmartScreen reputation
warning is not by itself a malware verdict, but it should not be ignored
blindly. Verify the binary against `SHA256SUMS` and the build attestation first.
If verification succeeds, unblock only that file; do not disable SmartScreen
system-wide.

**uBlock Origin isn't installed in a Nomad-managed Gecko browser.** Close and re-launch once. If it still doesn't appear, check the launcher log for AMO metadata, SHA-256 verification, or file-replacement errors. `Nomad/Gecko-extensions/uBlock0.xpi` must exist; signature-file names alone do not prove its integrity.

**To retry Nomad-managed uBO provisioning:** close the browser and launcher,
then rename the affected staged copy as a backup:

- LibreWolf, Floorp and Waterfox: rename
  `Nomad/Gecko-extensions/uBlock0.xpi` to `uBlock0.xpi.saved`.
- Ungoogled Chromium: rename `Browser/nomad-extensions/uBlock0/` to
  `Browser/nomad-extensions/uBlock0.saved/`. If the sibling
  `Browser/nomad-extensions/uBlock0.backup/` also exists, rename it
  to a separate saved name too; Nomad can otherwise reuse that recovery copy.
  Substitute your configured installation folder for `Browser`.

Choose unused backup names. Start Nomad directly while online with hardening
and automatic downloads enabled; a URL/file handoff does not provision software.
Keep the saved copy until the replacement works. These paths do not apply to
Helium or Mullvad, which ship their own extensions. This does not reset extension
settings stored in the browser profile.

**I lost my bookmarks.** You deleted `Data/` (the browser profile) instead of `Nomad/` (Nomad's bookkeeping). They are separate folders.

**"No GPG signature" warning.** Informational. Floorp, Waterfox, Helium, LibreWolf, and Ungoogled Chromium don't publish a usable signing key, so those downloads are hash-verified: Waterfox uses SHA-512; the others use SHA-256.

**"CRLSet refresh not assured".** This is a standing disclosure, not a measured
component version. Nomad does not maintain Ungoogled Chromium's revocation data,
and the reviewed upstream normal update endpoints are neutralized. Checking for
a browser update does not check CRLSet freshness. See
[component-update evidence and remaining gap](UNGOOGLED-COMPONENT-UPDATES.md).

**"Update check reminder" when opening a link.** This uses saved local metadata,
without making an update request. Continue opens the link as before; Close cancels
it. Close the browser and run Nomad directly with update checks enabled to perform
maintenance. To opt out, set `[update] remind_on_protocol = false`. Acknowledging
the reminder does not record a successful check or installation.

**Behind a proxy / update check fails.** Set `[update] check_on_launch = false` in `nomad.toml`.

## FAQ

**Does this require administrator privileges?**
Normal launching, updates, and default registration run as the current user.
Cleanup does not request elevation. The legacy Prefetch option is a no-op.

**Where does the browser get installed?**
Durable browser files and profile data stay in `Browser/` and `Data/` beside
the launcher. Windows and the browser may create temporary runtime artifacts
elsewhere; Nomad cleans supported traces after exit. Default-browser registration
and handler repair write only to `HKCU`.

**Does it work from a USB drive?**
Yes. Close the browser before moving the complete portable folder. If it was
registered as the default browser, unregister it at the old path before moving
and register again at the new path; location-bound records are not portable
registration identities.

**Does it leave anything behind after I delete it?**
Not completely. Nomad performs best-effort cleanup, but Windows retains some
execution records described under [What Nomad cannot scrub](PRIVACY.md#what-nomad-cannot-scrub).
Before deleting a registered portable folder, run `--unregister-default` or
select another default browser in Windows Settings. Deleting the portable folder
then removes Nomad's durable browser, profile, and configuration data.

**What happens if a download fails verification?**
The launcher aborts before extracting or running anything. Any existing install is left untouched.

**Why does Chromium say it is newer than the certified major?**
Older launchers used a fixed Chromium major-version ceiling. The updated launcher
checks the verified browser's layout and identifies its branding resources by
image content before replacing the working installation. Compatible major-version
updates therefore need no ceiling bump. Install a rebuilt launcher containing
this change to migrate; meanwhile, **Launch anyway** opens your existing browser.
Actual incompatible resources still block an update and preserve the working copy.

**What if I'm already on the latest version?**
Nomad keeps a local version cache with a 6-hour TTL. Within that window it skips the browser-version metadata check. Extension checks can still contact their upstream services. An entry recorded at a moment when the upstream hash was unavailable is discarded rather than reused, so a temporary problem upstream doesn't leave updates failing verification until the cache expires.

**Can each launcher have its own `nomad.toml`?**
Each separate portable instance has its own `Nomad/nomad.toml`. Different
browser families must not share the same portable folder.

## Retired launchers

Firefox, Firefox ESR, and Bitwarden launchers are no longer built. Existing
installations, profiles, vaults, and Windows registrations are not removed or
migrated; retain the old launcher if you need to unregister it.
