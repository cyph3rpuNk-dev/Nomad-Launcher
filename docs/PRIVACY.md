# Privacy and cleanup

[Back to the overview](../README.md) · [Configuration](USER-GUIDE.md#configuration) · [Security policy and threat model](../SECURITY.md)

- [Privacy hardening](#privacy-hardening)
- [Trade-offs](#trade-offs)
- [Post-exit cleanup](#post-exit-cleanup)
- [What Nomad cannot scrub](#what-nomad-cannot-scrub)

## Privacy hardening

Nomad applies an opinionated privacy baseline intended for general browsing.
Some defaults intentionally trade functionality for privacy; review the
trade-offs below. To manage the browser yourself, set `[hardening] enabled = false`.

Turning it off stops applying privacy defaults and launch flags while keeping
portability settings. For new Chromium profiles, `initial_preferences` contains
privacy defaults only while hardening is enabled. Switching it off replaces
that seed with developer mode. Helium's updater block applies to unreviewed
builds; the reviewed x64 0.19.2.1 flat bundle preserves existing component-update
choices and service consent. If a required seed cannot be updated, launch stops. Existing Chromium
profile preferences are not automatically reset; change previously saved
values through the browser settings.

Chromium still starts on the portable profile with machine-ID binding, DPAPI
encryption, and TPM session binding switched off. These control how the profile
is stored. Changing them on an existing profile makes Chromium discard your
extensions and sign you out, so they are applied whichever position the
hardening toggle is in.

On Gecko, the `user.js` block and locked preference file that Nomad wrote are
removed, and anything you added yourself is left in place. `policies.json`
stays, because nothing in it breaks a site and it is what installs uBlock Origin.

What each browser family gets:

**Chromium (Ungoogled Chromium, Helium):** launch flags disable sync, telemetry, and JumpList, and enable fingerprint-noise features, WebRTC restriction, and referrer stripping. Helium keeps its own canvas-pixel noise and system-information behavior. DoH mode and the Quad9 resolver are re-enforced on each hardened launch; browser UI changes to those settings are overwritten on the next Nomad launch. Ungoogled Chromium loads uBlock Origin via `--load-extension=`, sourced from [gorhill/uBlock](https://github.com/gorhill/uBlock) releases with a GPG-verified tag, verified SHA-256 asset digest and upload-timeline check. Helium uses its built-in uBlock fork instead. The machine-ID and encryption switches are applied separately for portability.

**Gecko (Floorp, Waterfox):** a fenced `user.js` (a safe subset derived from arkenfox) and a `policies.json` that disables the updater, telemetry, and Pocket are written on every launch. uBlock Origin is provisioned from a locally cached AMO-signed `.xpi`, verified against the SHA-256 digest in AMO metadata before replacement. The browser validates its Mozilla signature at installation.

**LibreWolf** ships pre-hardened, so Nomad applies a lighter touch. It gets its own minimal `user.js` rather than the shared Gecko one, adding Quad9 malware-blocking DoH, `geo.enabled` off, network prediction off, WebRTC restricted, site-compatibility exceptions, and the shutdown sanitize block. LibreWolf's own `librewolf.cfg` and autoconfig pair are never touched, and `privacy.resistFingerprinting` is left intact. uBlock Origin is provisioned the same way as for Floorp and Waterfox, since the portable ZIP doesn't bundle it.

**Site compatibility (Floorp, LibreWolf, Waterfox):** with Nomad hardening enabled, both Enhanced Tracking Protection options, "Fix major site issues" and "Fix minor site issues", are enabled in the managed profile. Strict mode remains selected. These browser exceptions can restore blocked logins, videos, or comments by permitting some elements that may contain trackers; they do not guarantee every site works or change uBlock Origin's rules. An updated launcher applies the preferences to new and existing profiles on the next launch. They are not locked, but Nomad's `user.js` reapplies them at browser startup while hardening is enabled.

**Mullvad Browser** keeps its upstream anti-fingerprinting preferences. Nomad applies no managed `user.js` and provisions no uBlock package, but writes a `DisableAppUpdate` policy and removes auxiliary updater/crash-reporting executables from the extracted bundle. It is not a byte-for-byte untouched upstream installation.

### Trade-offs

- Safe Browsing is disabled by Nomad's hardening in Chromium and the managed Gecko profiles. DNS filtering does not replace browser-level phishing/malware protection. Chromium uses Quad9 secure DoH; Floorp and LibreWolf request Quad9 with system-DNS fallback. Waterfox retains upstream DNS defaults and explicit user choices; Nomad no longer overrides its DNS transport/provider preferences. Reviewed Waterfox 6.7.6 defaults to oblivious DNS through a Waterfox relay and Cloudflare, with system-DNS fallback (mode 2). This is not Quad9 malware filtering or a fail-closed guarantee; scoped Windows 11 tests observed OHTTP address responses normally and native/system DNS resolution during a simulated HTTPS outage at startup. These browser-log observations do not establish encryption of every lookup or the OS resolver's wire transport. Older Nomad autoconfig disabled Waterfox encrypted DNS; the corrected launcher replaces that managed file on the next hardened launch without resetting explicit profile choices. See [Waterfox DNS evidence](WATERFOX-DNS-DEFAULTS.md). Mullvad retains its upstream security preferences.
- With `disable_webrtc = true`, Floorp, LibreWolf and Waterfox disable peer connections. Chromium and Helium restrict non-proxied UDP but still allow TCP/proxied UDP; WebRTC is not fully disabled and this does not guarantee IP anonymity. Mullvad retains its upstream behavior. Turning the option off stops adding the override; persisted Gecko preferences may need adjustment in the browser.
- Chromium profile encryption (DPAPI) is off so the profile stays usable on any machine. This applies whether or not hardening is enabled. Anyone who can read an unencrypted drive may recover browsing data and usable session cookies/tokens. Store sensitive portable profiles on an encrypted volume.
- Nomad handles browser-bundle updates on direct launcher invocations. Gecko policies disable the built-in updater. For the reviewed x64 Helium 0.19.2.1 flat bundle, upstream rejects installer updates by layout, so Nomad permits the native security-component path instead of forcing its coupled update preference off. Other Helium versions/targets retain the preference and command-line block. Failed mandatory preparation prevents launch.
- Floorp and Waterfox keep general extension updates enabled by default and user-configurable. Nomad provisions uBlock separately; other installed extensions use their browser update service. These update contacts are separate from telemetry.
- OS link/file launches deliberately skip browser and Nomad-managed extension update checks. By default, a local reminder appears when a relevant check is unknown or at least seven days old, or cached metadata indicates an uninstalled version. Continue opens the link without updating; Close cancels it. Continue acknowledges reminders for 24 hours. Run Nomad directly with update checks enabled to maintain the browser and managed uBlock. `[update] remind_on_protocol = false` disables the reminders, independently of hardening. Seven days is a reminder interval, not a promise of security or automatic updating; ignored reminders can still leave software outdated indefinitely. See [link-launch update reminders](PROTOCOL-UPDATE-FRESHNESS.md).
- Ungoogled Chromium's CRLSet certificate-revocation refresh is not assured. Nomad's default component-disable flag suppresses component registration; the reviewed Windows build also neutralizes its normal service endpoints upstream. Removing the flag or disabling hardening alone does not restore that normal update path. The launcher shows **Security data: CRLSet refresh not assured** and logs the limitation. A current browser bundle does not prove fresh revocation data. See [Ungoogled Chromium component limits](UNGOOGLED-COMPONENT-UPDATES.md).
- Helium component access is permitted only for the reviewed x64 0.19.2.1 flat bundle. It uses Helium services and the browser's signed-component verification, including CRLSet certificate-revocation data. Existing update choices and service consent are preserved: profiles left off by older Nomad versions need an explicit choice to enable "Allow automatic browser updates" in Helium services. The label covers components too; the reviewed flat bundle's native installer guard still rejects browser-installer updates. See [Helium component-update safety](HELIUM-COMPONENT-UPDATES.md) for the live CRLSet/relaunch observations and remaining installer-validation limits.
- Mullvad retains upstream privacy behavior, with the updater policy and bundle changes described above.

Settings updates use complete staged replacements rather than truncating active
files. A required privacy/policy write, portability preparation, or managed
Gecko-settings removal failure stops browser launch and shows **Retry** or
**Close**. **Launch anyway** cannot bypass it; fallback after an update error
runs the same required settings checks. Invalid existing Chromium JSON and unreadable user.js are preserved
for repair instead of being treated as empty. These are file/preparation checks,
not proof of effective browser preferences. See
[required-settings failures and limits](HARDENING-FAILURE-SAFETY.md).
Managed uBlock
updates retain the working copy until extraction/verification and replacement
succeed; Chromium's managed extension also survives a browser-bundle update when
the next extension check is offline. Interrupted extension swaps retain a backup
for recovery. See [Settings and extension preservation](UPDATE-SAFETY.md#settings-and-extension-preservation).

## Post-exit cleanup

When the browser closes, a detached watcher performs best-effort cleanup of
host traces that can be attributed to this portable instance. It requires a
valid `Nomad/instance.toml` matching the launcher family and an existing browser
executable resolved inside the owned folder. Missing or ambiguous ownership
causes automatic host cleanup to be skipped.

| Location | What gets removed automatically |
|---|---|
| `%APPDATA%\Microsoft\Windows\Recent\` | Individual `.lnk` files with an unambiguous local target resolved inside this portable folder |
| `%ProgramData%\Microsoft\Windows\WER\{ReportQueue,ReportArchive}\` and `%LOCALAPPDATA%\Microsoft\Windows\WER\{ReportQueue,ReportArchive}\` | Attributed flat report folders and their ordinary attachments, after one absolute `AppPath` matches this exact browser image and Windows file-access checks succeed |

Shortcut cleanup is scoped to the portable folder, on fixed or removable
drives. Other shortcuts on the same drive are preserved. Shortcuts with
competing target records, unreadable or oversized metadata, and cleanup source
paths through symlinks or junctions are left alone. Place the launcher in a dedicated folder;
automatic cleanup is skipped at a drive root. Common Windows IDList,
Unicode and relative-path records are supported only when their stored targets
agree. Unsupported formats and missing targets remain intact; Nomad does not
search for moved files or execute shortcuts. See
[Recent shortcut safety](RECENT-SHORTCUT-SAFETY.md) for the bounded parser,
Windows fixture coverage and remaining limits.

Shared browser directories under `%LOCALAPPDATA%` and `%ProgramData%`, Gecko
`installs.ini` files, shared `%TEMP%` files, standalone `CrashDumps`, and compound Jump
List files are preserved. Browser names and missing executables do not prove
that those files belong to Nomad: a system-wide browser keeps its profile in a
different folder from its executable, and a Jump List can contain unrelated
entries alongside a portable one. No shared profiles, cookies, registrations,
or empty vendor parents are deleted before launch or after exit.

WER cleanup checks the current user's Local AppData and machine-wide stores,
not other users' profiles. Linked, nested and over-budget reports, and reports
that fail file-access preflight, are preserved. At most 256 ordinary files per
flat report are supported.
Attachments inside an attributed report, including dump files, are deleted;
standalone dumps such as `%LOCALAPPDATA%\CrashDumps` are preserved because a
browser basename does not prove ownership. Memory dumps can contain sensitive
browser memory, potentially including page content or account data
([Microsoft minidump documentation](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_type)).
Cleanup does not disable Windows Error Reporting or undo reports already sent.
An attachment deletion failure can leave a partially removed report;
`Report.wer` stays for a later session's retry.
Recorded cleanup missed after a worker crash, power loss or drive removal can
be retried on a later launcher invocation, including a link launch. This defaults
on independently of privacy hardening; set `[hardening] recover_missed_cleanup = false`
to stop recording and retrying. `Nomad/cleanup-pending/` retains encrypted,
records of the browser and original portable paths using nested Windows user/
machine DPAPI protection, until a completed scoped attempt. Separation depends
on Windows key contexts; a fresh-Sandbox check refused the nested record but
decrypted a machine-only comparison blob. Different-user and independently
keyed-machine validation remain pending. Recovery requires a decryptable record
at its original path,
a matching owned instance, both folder locks and a conservative idle check.
Busy, unqueryable or ambiguously located same-name browser processes prevent
cleanup. Moved folders and unreadable records are preserved; write failures and
older sessions without records cannot be recovered. Shared cache clearing and
registry actions are never replayed. See [missed-cleanup recovery](MISSED-CLEANUP-RECOVERY.md)
for retention, bounds, Windows validation gaps and remaining races.
See [WER cleanup safety](WER-CLEANUP-SAFETY.md) for checks and test limits.

This conservative cleanup can leave host traces, including profiles created
when a browser was launched outside Nomad. Use `--register-default` so links
reach the portable profile; review any old stray profiles separately.

One owned cleanup coordinator handles a portable browser session. Additional
link launches exit their duplicate cleanup workers without repeating exit
actions. The first coordinator uses the opt-in settings from the launch that
created it; configuration changes take effect in the next session.

Thumbnail/icon cache clearing remains an explicit opt-in
(`scrub_thumbnail_cache = true`). It attempts to delete only unlocked cache
files and never terminates or restarts Explorer; files in use remain. These
shared caches are separate from automatic attributed cleanup.

Prefetch clearing is retired: matching an executable name cannot distinguish
this portable instance from unrelated installed browsers. Existing
`scrub_prefetch = true` configurations still load, but only produce a retirement
warning when cleanup is scheduled; no Prefetch files are deleted and no UAC
prompt is requested. You can remove the obsolete key from your configuration.

### What Nomad cannot scrub

Windows keeps execution records Nomad does not remove: Prefetch, Amcache and ShimCache (program execution history), SRUM (per-application network usage), the NTFS USN journal's record of deleted files, Windows event logs, and the pagefile. Some require administrator rights to alter; others cannot be safely attributed or removed without harming the system. Nomad does not promise to hide execution paths or provide forensic erasure.

Cleanup reduces some directly attributed traces. Shared and unattributed
traces can remain visible during a casual inspection, and Windows keeps
execution records. Review the full threat model in [SECURITY.md](../SECURITY.md).
