# Helium component-update safety

## Scope

Nomad permits upstream component access for x64 Helium **0.19.2.1** only when
the installed marker identifies that target/version and the ordinary flat
Chromium bundle passes the required layout checks. Unreviewed versions/targets
retain the browser-update preference block and `--disable-component-update`;
they can still be updated/launched through Nomad. Reviewing a later capability
requires checking the native installer guard again.

This separates the browser-installer path from upstream security-component
access for a specific reviewed build. It does not implement a new Nomad
component downloader or weaken archive/hash/signature verification.

## Reviewed upstream evidence

Windows release tag `0.19.2.1` resolves to
`3556eb13ac8bb9c5a7e42c87da9734dbe430bf18`, with Chromium source revision
`9aa23f3cd9e5e6bcb91c8c8029b738e8da2de493` (Chromium 155.0.8059.39).
The published x64 portable ZIP SHA-256 is
`8623c04201a0a45a97920c7acdaa3a9f022260c66d6dfe78e7dcb323d4d2d89c`.
This records source/package provenance, not an at-rest integrity check.

Verified in upstream source:

- [Windows updater glue](https://github.com/imputnet/helium-windows/blob/3556eb13ac8bb9c5a7e42c87da9734dbe430bf18/patches/helium/windows/updater/glue.patch)
  adds `installer::CanUpdateInstallation`. It requires the registered/default
  install directory to match the executable's directory **and** the loaded
  module directory to match its versioned child directory. Automatic updater
  initialization, manual About-page checks and the installer callback all
  reject unsupported layouts.
- [Component update patch](https://github.com/imputnet/helium/blob/9aa23f3cd9e5e6bcb91c8c8029b738e8da2de493/patches/helium/core/component-updates.patch)
  gates component access on services enabled, schema acceptance and
  `helium.services.browser_updates`. It permits CRLSet and Widevine components
  and routes requests through the configured Helium service origin's `/com`.
- [Updater preference](https://github.com/imputnet/helium/blob/9aa23f3cd9e5e6bcb91c8c8029b738e8da2de493/patches/helium/core/add-updater-preference.patch)
  confirms the shared control. Nomad cannot simply force it off while expecting
  security components to update.
- [Service preferences](https://github.com/imputnet/helium/blob/9aa23f3cd9e5e6bcb91c8c8029b738e8da2de493/patches/helium/core/services-prefs.patch)
  supplies the default origin `https://services.helium.imput.net`; users may
  configure another valid service origin. These runtime update requests are
  distinct from Nomad's GitHub browser-bundle checks.

Inference requiring live validation: the authenticated flat bundle loads its
root `chrome.dll` beside `chrome.exe`, so the versioned-module condition cannot
be satisfied. Nomad requires all declared flat runtime files and rejects links
before allowing this capability. A hostile host/drive writer remains outside
the threat model. Future upstream source or package changes require new review.

## User choice and migration

Fresh profiles receive the upstream update preference enabled, but Nomad never
accepts service terms/schema on the user's behalf. Existing Preferences are
validated and preserved byte-for-byte for the reviewed capability. A false
value might be an old Nomad override or the user's choice; Nomad does not guess.

For an existing reviewed flat profile, open Settings > Privacy and security >
Helium services. If setup is incomplete, select Complete setup and review the
service choices first. Review the service disclosure and choose whether to enable
**Allow automatic browser updates**. The label includes component updates.
Native installer updates remain ineligible for the reviewed flat layout.
Leaving the preference or service access off also leaves component refresh off.
Older/unreviewed builds must not use this migration advice; their preference
continues to be forced off until their installer behavior is reviewed.

Browser runtime component traffic uses upstream verification and consent.
Nomad protocol invocations themselves still do no browser-bundle or managed
extension provisioning; they only launch the installed profile. The browser
can perform its own consented runtime updates after either launch origin.

## Validation and remaining limits

Inert tests cover the exact build/target, fresh profiles, preserved off/on and
consent settings, unknown/older/newer versions, missing target/marker, incomplete
or linked layout, malformed settings and resulting command-line switches.
They never launch a browser, mutate the host registry or download components.

Before release, use a disposable Windows Sandbox with the patched launcher:

1. Install the reviewed build through Nomad's normal verified pipeline.
2. Confirm `chrome://version` identifies 0.19.2.1/Chromium 155 and the flat
   executable/profile paths, with no Nomad component-disable switch.
3. Test fresh and existing profiles. Preserve bookmarks/uBlock and user choices.
4. After an explicit service/update opt-in, inspect `chrome://components` and
   request a CRLSet update. Record version/status and network destination.
5. Open About Helium and verify automatic/manual browser-installer updates stay
   disabled for this layout; record that no installer/download appears outside
   the portable tree. Observe background behavior and repeat after relaunch.
6. Exercise an older/unreviewed fixture separately: update preference false and
   component-disable switch must remain, even with Nomad hardening disabled.

A source/inert-test pass is not evidence of a successful CRLSet refresh or the
absence of installer side effects in Windows. Partial live results are recorded
below; remaining checks are pending.
Ungoogled Chromium's component-update suppression is a separate open issue.

## Live Sandbox results (screenshots dated 2026-10-13)

The user ran the local unsigned x64 test launcher on Windows Sandbox, from
base `e5e6fa0d2d70bdfdd675ac5b5c2b1134c84096ee` plus this capability patch.
Launcher SHA-256:
`FAE26E64AFD0B49D8CB9633EE0E3D11297EFD2F3D0A5F8EEADD48B1F1456BA42`.
Current Helium source and lockfile match the recorded test-build metadata.
This is not a signed release or CI artifact.

| Check | Evidence and result |
| --- | --- |
| Browser/version | User screenshot: Helium 0.19.2.1 / Chromium 155.0.8059.39 (64-bit). Log: owned guest executable at `C:\NomadSmoke\HeliumComponents\Browser\chrome.exe`. |
| Consent gate | Before setup, the services page required Complete setup and CRLSet was 0.0.0.0 with component updates disabled. After user-completed setup, service access and automatic updates were enabled. Nomad did not accept setup/service consent. |
| CRLSet refresh | User screenshot: **10833 / Updated**. After a full browser exit and relaunch: **10833 / Up-to-date**. Exported component manifest metadata also records version 10833. |
| Service preservation | Post-relaunch selected settings: `browser_updates: True`, `schema_version: 1`; services enabled absent (native default). The user confirmed enabled UI controls remained. |
| Bookmark/uBlock | User confirmed the test bookmark and built-in uBlock present and preserved after relaunch. Full bookmark/extension data were not exported; the expected bookmark-file hash reference was absent. This is UI evidence, not independent profile verification. |
| Installer layout | User-run read-only inspection: PID 7636 loaded `chrome.dll` beside `chrome.exe`; no versioned `Browser/0.19.2.1` child and no component-disable switch. |
| About/installer snapshot | With service access and automatic updates enabled, About shows the version without update controls/status or visible installer UI. No `chrome_new.exe`, `PendingSystemUpdate` or running `helium_update_helper.exe` was present at inspection. |
| Widevine | Remains **0.0.0.0 / Update error**. Cause and DRM functionality were not established. |

**Inference from pinned source plus observed paths:** the native
`CanUpdateInstallation` rule excludes this ordinary flat layout. Its two
required directory comparisons demand the executable at the install root and
the module in that root's versioned child. The helper did not invoke or
instrument the native function. The About page and marker/process snapshot are
consistent with that inference; they are not a complete installer/network
history or proof that no side effect ever occurred.

Runtime SHA-256 inventory agrees between the user's inspection transcript and
the guest export (not an independent match against host-extracted upstream files):

- `chrome.exe`: `A7EFCB9F8C830AD2C6BD059DA38774B2E83411196E696602D08D4B6A4E4BE00D`
- `chrome.dll`: `36B703C1B1B563558181F3AA42BDE16D21EC6A0B5E0E658989D59D77B2627B7D`

### Preserved evidence and limits

The guest archive was received and independently validated on the host:

- SHA-256: `845A05D6B509588F9020DD29F2C4CE8AC0CDC9B10836AEF2C3F8E242E971D797`.
- Size: 4,011 bytes; 6 collected files plus manifest; 9 hash-only references.
- Exact archive allowlist, declared sizes/digests, source/build identity,
  selected service values and CRLSet metadata passed without extraction.
- Refusal checks covered archive/digest mismatch, private files, path traversal,
  linked entries and altered component inventory.
- No full profiles, cookies, history, bookmark contents, packages or browser
  binaries were archived. Hash-only references are guest-recorded inventory,
  not host reads of the original files.
- The private single-upload receiver completed and exited; no firewall settings
  were changed. The exporter passed PowerShell 5.1 syntax and host-refusal checks.

Archive and `HOST-VERIFICATION.json` reside in the ignored fixture:
`target/helium-components-e5e6fa0-ebfa255756cd43ee949f302d3a38e0f2/evidence-transfer-e6ab4c903be145bb8fc59bfbed21758b/received/`.
The user-provided layout transcript is in its `host-evidence/` directory.
Screenshots were inspected as conversation attachments; their supplied local
paths were unavailable for archive copying, so original screenshot files are
not included in the host evidence archive.

Remaining limits: migration from a previously forced-off profile, live behavior
of unreviewed/older versions, actual component network destinations, instrumented
native eligibility and exhaustive installer side-effect history were not tested.
Widevine remains unresolved. The broader independent review and release hold
are unchanged; this evidence does not clear every finding or approve publication.
