# Update and instance safety

This document records the architecture behind Nomad's update safeguards. It is
normative for code that changes installation, update, branding, protocol
handoff, or portable-folder layout.

## Why changes used to reappear

A Nomad browser update is a bundle replacement, not an in-place browser patch.
The new upstream archive is extracted to a staging directory and then replaces
the active `Browser/` directory. Any manual change made inside `Browser/` is
therefore upstream-owned state and is expected to disappear at the next swap.

Nomad reapplies declared overlays after an update. The Chromium help-page logo
is one such overlay: it replaces grit-numbered resources in
`chrome_100_percent.pak` and `chrome_200_percent.pak`. Those numeric IDs can
change between Chromium majors. Older code safely skipped a missing or
wrong-sized resource, but incorrectly treated the rebuilt PAK as successful and
could write `.branding-patched`. That marker suppressed future retries, making
the reverted icon appear permanent.

The rebuild changes the contract: every required resource must be found and
match its expected dimensions, and every target must be written, before the
branding marker can exist. A newly downloaded browser is branded while it is
still staged. If any required overlay is incompatible, the atomic swap is
aborted and the currently working browser remains in place.

## Required preparation before launch

Every launch origin uses the same required privacy/policy and portability
preparation, including fallback and an existing-browser protocol invocation.
A preparation error stops launch and offers Retry/Close. Launch anyway after
an update error still runs this preparation and cannot bypass a failure.
Gecko hardening withdrawal also must complete before launch. Shape-invalid
settings are preserved for repair rather than interpreted as empty defaults.
See [required-settings failure safety](HARDENING-FAILURE-SAFETY.md) for exact
checks, tests, already-correct read-only files and runtime limits.

Enabled-hardening staged Gecko policy/autoconfig errors stop finalization before
the version marker and swap. Active-profile preparation runs after a successful
swap, so a later profile failure can leave the new browser installed while launch
is stopped. Its successful swap is not rolled back by a profile-write error.
Managed settings use individual atomic replacements, not a multi-file transaction.

## Update transaction

Each portable folder uses `Nomad/install.lock` to serialize launcher attempts.
The GUI retains an exclusive OS file lock from recovery through update prompts,
download, verification, extraction, swap, launch preparation and browser spawn,
including fallback launch. Headless updates hold it across recovery and the
entire update. Different configured installation names in the same folder share
this lock. Other portable folders remain independent.

A competing GUI launch offers Retry or Close and cannot launch a fallback while
another launcher owns the lock. The OS releases the lock when the process exits,
including on a crash. The empty lock file remains on disk; its presence does not
mean an update is running. Never delete it to unblock a launcher.

Recovery runs only when update checks are enabled, under that same lock. A
missing active install is restored from backup before any stage is deleted. If
restoration or stale-directory cleanup fails, the update stops and reports the
error. A failed restore preserves both backup and stage. Swap refuses an existing
backup rather than discarding a potentially unique working copy. If promotion
and rollback both fail, the backup remains for recovery on the next direct run.
Protocol launches and disabled headless checks do not restore, delete or swap
staging/backup directories. Protocol launches still acquire the GUI lock before
launch preparation so they cannot race an active update.
Their optional maintenance reminder reads local cache/check/acknowledgment state
under that lock. It cannot enable update permissions, perform a lookup, recover
staging or provision software. Continue resumes required preparation and the
existing-browser handoff; Close cancels. See [protocol update freshness](PROTOCOL-UPDATE-FRESHNESS.md).


```text
resolve release
      |
      v
compatibility gate ---- incompatible ---> keep current install, report error
      |
      v
download -> authenticate -> extract to staging
                              |
                              v
                  apply and verify overlays
                              |
                     failure  |  success
                       |      v
                       |   write version marker
                       |      |
                       |      v
                       +-> no swap   atomic swap -> launch
```

### Promotion and rollback boundary

Successful promotion ends the automatic rollback window. `atomic_swap_locked`
attempts to restore the old bundle only if the stage-to-active rename fails.
After that rename succeeds, it removes the old backup best-effort before browser
startup; it does not wait for a healthy window or navigation. Later profile
preparation or browser-startup failure does not automatically restore the old
bundle. An orphaned backup is cleanup/recovery state, not a promised rollback
slot. These are rename transactions, not a filesystem durability guarantee.

The [native Windows 11 qualification](NATIVE-SWAP-RECOVERY-QUALIFICATION.md)
passed an induced failed promotion with restoration, blocked backup restoration
with retained state, subsequent retail direct-launch recovery and successful
promotion, using one authenticated same-version Helium bundle and a real profile.
Its interruption was authored; physical crashes, media loss, combined promotion/
rollback failure and real version-transition compatibility were not qualified.

**v1.0.9 owner disposition (2026-10-16):** the owner explicitly accepted the
disclosed remaining transition/interruption/media-loss coverage limits and the
lack of automatic health rollback after successful promotion. Those tests remain
unqualified and the structural limit remains; no updater behavior or guarantee
changed. [Exact acceptance and delivery boundary](RELEASE-READINESS.md#remaining-scope-acceptance-2026-10-16).

Authentication and compatibility answer different questions. A valid digest or
signature proves that a package matches what upstream published. The
compatibility gate proves that this launcher understands that package's layout
and required overlays. Both must pass.

Every browser adapter declares a required `StagedInstallLayout`. The shared
GUI/headless finalizer validates it before hardening or browser-specific hooks,
and checks it again after preparation/overlays before recording a version or
swapping. A hook returning success cannot bypass this mandatory layout gate.

| Layout | Required nonempty regular files |
|---|---|
| Chromium (Helium, Ungoogled Chromium) | Declared root executable, `chrome.dll`, `resources.pak`, `icudtl.dat`, `chrome_100_percent.pak`, `chrome_200_percent.pak` |
| Gecko (Floorp, LibreWolf, Mullvad, Waterfox) | Declared root executable, `xul.dll`, `application.ini`, `omni.ja`, `browser/omni.ja` |

Missing, empty, unreadable or wrong-type required entries fail closed. The stage
root and required path components must be ordinary entries, not symlinks or
Windows reparse points. Checks only inspect metadata; they never launch a browser
or installer, create a profile, or replace authentication. They cover critical
layout files rather than proving the complete package can run on every host.

The Gecko contract follows Mozilla's [package manifest](https://github.com/mozilla-firefox/firefox/blob/main/browser/installer/package-manifest.in)
and [omnijar packager](https://github.com/mozilla-firefox/firefox/blob/main/python/mozbuild/mozpack/packager/formats.py).
These layouts are explicit compatibility contracts. An upstream layout change
must be reviewed before changing the required files; do not skip the gate to
install an incompatible release.

Ungoogled Chromium compatibility is checked against the authenticated staged
artifact instead of a maximum major version. Both GUI and headless updates must
find the required executable, DLL, resource bundle, ICU data, and both logo PAKs.
The launcher decodes reviewed upstream logo references and locates each logo by
its pixels and dimensions, independently of grit resource numbers. PNG
recompression and resource renumbering are supported; matching dimensions alone
are insufficient. Missing, changed, malformed, or ambiguous logos fail closed.
PAK aliases retain their canonical resource indexes when the archive is rebuilt.

All required branding must be applied before the version marker and swap. A
branding marker supplied in an upstream archive is discarded. On Windows, the
patched PAKs are read back to verify the replacements. No browser or downloaded
installer is executed by compatibility checks. Profiles remain outside staging.

The Windows Chromium compatibility workflow runs the production authenticated
download, extraction, and branding path against the current release in a
temporary directory. The weekly upstream check runs the same test. A new major
with compatible artifacts needs no launcher rebuild; an actual upstream layout
or artwork change still requires a reviewed compatibility update. This cannot
guarantee compatibility with arbitrary future browser changes.

Floorp's weekly check goes beyond metadata parsing: it downloads the current
release, verifies its published SHA-256, extracts it to a temporary directory,
checks the configured executable exists, and checks that the version marker
survives the swap. It never launches the browser or writes user configuration.

## One folder, one browser family

All launchers historically used the same relative names (`Browser/`, `Data/`,
and `Nomad/`). Placing Nomad-Chromium and Nomad-Helium in one folder therefore
let either executable interpret and replace the other's state. This is the most
credible code-level explanation for Helium appearing after a Chromium update.

`Nomad/instance.toml` now records the stable browser ID that owns the portable
folder. The first launcher to use an unclaimed folder writes it atomically.
Every later run must match it. A mismatch or corrupt marker fails closed before
the updater can touch `Browser/` or `Data/`.

For an existing portable folder without a marker, launch the browser that
already owns that folder once after upgrading Nomad. It will claim the folder.
Move any other Nomad launcher executables into their own empty directories.
Never edit `instance.toml` to convert a folder between browser families; move or
back up the profile and create a fresh instance instead.

## Installation folder boundary

The configured `browser.install_dir` must be one Windows-safe folder name
directly beside the launcher, such as `Browser` or `App`.
Configuration deserialization rejects paths and the reserved sibling names
`Data` and `Nomad` in any letter case, including ambiguous trailing-dot/space
spellings. Windows device names and invalid name characters are rejected too.

The update replaces this folder wholesale. Keeping the installation separate
from `Data` and `Nomad` prevents a bad setting from swapping out the profile or
launcher configuration. Requiring a direct child also preserves the layout
assumption used to locate sibling profiles, extension caches, and update state.
Invalid settings stop processing before staging recovery, downloads, or swaps.
Existing files are not moved or deleted to repair a bad setting automatically.

## Filesystem paths before mutation

URL metadata never supplies a local download basename. Browser packages use
`nomad-package.zip`, `nomad-package.exe`, or `nomad-package.bin` inside staging;
only a recognized URL-path suffix selects the format. Query strings, fragments,
drive names, separators and upstream executable names cannot become local paths
or collide with the staged browser's executable.

Shared filesystem checks inspect the original path and existing ancestors before
canonicalization, directory creation, reads/writes, or transactional cleanup.
Installation, stage, backup, state and profile paths must use ordinary entries;
existing symlinks, Windows junctions/reparse points, wrong types and parent-path
components fail closed. Invalid links and their targets are left untouched.
The public/headless updater enforces the same installation folder-name rules as
configuration. Staging must be newly created after locked recovery; an existing
stage is never silently adopted for a download.

ZIP destinations are checked before entry writes. The bundled extractor's raw
tree is checked before marker discovery and promotion. State preservation
precedes the staged version marker.
Configuration, ownership, logs, hardening, branding and cache writers share these
checks too. Download/cache temporary files use exclusive creation; failure cleanup
removes only a temporary file created by that operation. Existing temporary files
are preserved; a stale cache temp requires review rather than automatic deletion.

These checks reject pre-existing filesystem aliases. They are not a transaction
of directory handles and cannot defeat a hostile process that replaces paths
between checks and operations, or a compromised host/portable drive. The existing
[drive-write-access threat boundary](../SECURITY.md#what-nomad-does-not-defend-against)
still applies. The bundled extractor remains responsible for its own archive
format handling; the checks do not execute downloaded installers or browsers.

## Package targets and legacy records

`BrowserFamily::package_target()` identifies the adapter's package selector:
`x64`, `x86`, or `arm64` for browsers; `portable` remains readable for legacy
single-artifact records. Cache records and successful `.nomad-version` markers carry this
target. Cached metadata must have a matching known target as well as pass the
existing freshness, URL and integrity-material checks. Cross-target and legacy
records cause a fresh release lookup; uBlock version state is preserved.

GUI and headless update decisions compare both version and target. A same-version
architecture change requires verified replacement. The new marker is written
only after authentication, mandatory layout checks, preparation and state
preservation succeed, and is promoted with the staged bundle. Failed updates
keep the prior marker, install and profile. The target describes package
selection, not an independent PE-machine or runtime-compatibility check.

Legacy markers remain readable with an unknown target; no architecture is
guessed and no marker is rewritten just to label an existing binary. With
updates enabled, one verified replacement is needed to establish its target;
`auto_download = false` still prompts. Offline fallback and protocol/disabled
update launches retain existing behavior and may use the current installation.
Unknown-target extension-only caches remain usable for uBlock version state,
but never for browser-package selection. Target changes and legacy migration
also obey the downgrade protection below.

Tests cover the target matrix, legacy records, GUI cache hits/misses, marker
promotion, and same-version target replacement using local HTTP and inert
owned fixtures. They do not download or execute a real browser.

## Downgrade protection

Update decisions order stable browser release versions numerically. Supported
formats are dotted decimal components, an optional numeric packaging revision
after a hyphen (including dotted revisions), Firefox's `esr` suffix, and legacy
`v`/`G` prefixes. Revisions are package-build numbers, not SemVer prereleases.
Trailing zero components compare equally for ordering; revision components are
compared only after the main release components. Inputs are limited to 128 bytes,
16 components per part and unsigned 64-bit numbers. Unknown labels, prerelease
syntax, malformed components and overflow fail closed instead of lexical ordering.

The shared GUI/headless checks reject any offered release below the installed
browser version, regardless of target or a legacy marker's missing target.
Same-version target changes and verified legacy-target migration remain allowed.
The install path repeats the check under its instance lock before stage creation
or package download. There is no automatic downgrade override.

An older/unorderable cached release is treated as a miss so it cannot suppress
a fresh lookup. Fresh older/unorderable metadata is rejected before cache writes,
update prompts, download or swap. The existing browser, marker, cache and profile
remain available; the usual error UI may launch the current installation.
Disabled/protocol update checks and offline fallback retain existing behavior.

This orders the adapter's browser release metadata. It does not independently
inspect the executable's version or engine, authenticate unsigned metadata,
or defend against a compromised host/drive writer. Unknown upstream release
formats or nonstandard installed markers need review rather than guessing.
Regression tests use local HTTP and inert owned temporary files; live upstream
version formats and real browser behavior have not been checked here.

## Required package signatures

Production and live release monitoring share
`updater::validate_verification_metadata`: adapters with an embedded package key
require a signature URL; other adapters require SHA-256 or SHA-512 metadata.
Missing material is rejected before staging or downloading, including cached
releases. This preflight checks availability only. Package verification applies
the same requirement to the downloaded signature file and still verifies bytes
cryptographically before extraction.

`BrowserFamily::public_key()` is a requirement for detached package-signature
verification, not a preference. If it returns `Some` (currently Mullvad), both
GUI and headless install paths reject a release with no signature URL before
creating a stage or downloading the package. This applies to cached metadata
too. `updater::verify_package` independently rejects a missing signature file
even when the SHA-256 or SHA-512 digest matches. An unreadable/invalid signature
or a failed signature download also aborts before extraction and promotion.
The active installation, version marker and profile remain intact.

Hash-only adapters retain their existing verification paths. No trust anchors or
extension signature policies change in this fix.
Tests use local mock HTTP and inert files in owned temporary directories;
live-upstream compatibility and signing-key freshness are separate checks.

## Settings and extension preservation

Chromium preference merges accept missing files as first-run state; empty files,
other read errors and invalid/nonobject existing JSON stop the write. An unreadable file
must never be silently replaced with defaults. Hardening writers prepare and
flush a complete replacement in an exclusively created sibling directory before
promoting it. The old settings file is never opened for truncation. Replacement
is per file; two separate settings files are not a multi-file transaction.

Windows replacement uses [ReplaceFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)
with metadata/ACL preservation and an owned backup path. Documented native
failures can move the original to the backup; Nomad attempts restoration before
cleaning up. A failed restoration retains the private directory and reports the
original's location. Read-only settings remain untouched. These checks do not
serialize writes by a running browser or protect against a hostile drive writer.

Chromium uBlock downloads require a well-formed GitHub SHA-256 asset digest,
a verified gorhill tag/commit GPG signature, and an acceptable upload timeline.
The ZIP bytes must match the digest before extraction or staging. Missing,
malformed or mismatched digests preserve the installed extension and version
cache. GitHub's digest is not a gorhill signature over the ZIP: archive integrity
still trusts GitHub metadata. The tag signature and timeline checks remain
independent requirements. Already-current and deferred updates do not download
or rehash the existing extension. See GitHub's
[release asset digest documentation](https://docs.github.com/en/rest/releases/assets).

Chromium uBlock updates extract into `uBlock0.stage`, enforce the decompressed
budget and ordinary-path checks, and require a parseable manifest with a nonempty
version before touching the active `uBlock0` directory. This is a minimum layout
check, not a full Chromium manifest/schema or runtime validation. An OS file lock
serializes extension transactions. The old directory moves to `uBlock0.backup`
only for promotion; a failed promotion attempts rollback and never discards the
remaining backup. Interrupted swaps restore a valid backup on the next update.
The launch path can use that valid backup if the current directory is unavailable.
The browser-update preserve-state hook also carries the working extension into
the staged browser so a subsequent offline check does not erase it.

Gecko XPI provisioning uses the [AMO add-on metadata API](https://mozilla.github.io/addons-server/topics/api/addons.html)
to resolve the version, file URL and SHA-256 digest together. Metadata must
identify `uBlock0@raymondhill.net`, a public file, a nonempty version, and a
well-formed SHA-256 hash. Nomad downloads that file URL over HTTPS, verifies the
bounded bytes against the digest, checks signature-file presence, and only then
writes an owned private stage. It no longer probes `/latest/` with HEAD or guesses
versions from filenames. A release changing during the download cannot silently
pair one version's cache record with another version's bytes.

The hash trusts AMO metadata; signature-file presence is only a layout check.
The browser performs cryptographic Mozilla signature verification at installation.
Already-current cached files are not rehashed, and `auto_download = false` still
defers downloads. Failed metadata resolution, download, verification or promotion
leaves the prior XPI and extension version cache unchanged; version records
advance only after successful promotion. Protocol launch remains free of
extension provisioning. Tests use inert files, mock HTTP and owned temporary
folders; they never install an extension into a running browser.

## Chromium hardening toggle and first-run settings

Helium and Ungoogled Chromium seed `preferences.json` into
`Browser/initial_preferences` only when `[hardening] enabled = true`. Disabled
hardening writes the base developer-mode template. Helium separately blocks
component/updater access for unreviewed versions/targets; the reviewed x64
0.19.2.1 flat layout permits consented component updates while the upstream
installer eligibility guard excludes that layout. This
matches the existing gating of Chromium privacy flags and profile-state seeds.
The portable profile/storage switches remain required in either mode.

Launch preparation rewrites the first-run seed on every attempt, including
true-to-false toggles, so stale privacy defaults cannot reach a future fresh
profile. Parse/write errors propagate and block preparation; the atomic writer
preserves the old seed on replacement failure. Chromium consults this seed for
new profiles. Disabling hardening does not reset values already saved in an
existing profile, because Nomad cannot distinguish past defaults from the
user's own choices. Existing Helium preferences are preserved byte-for-byte
for the reviewed component capability; unreviewed builds still force the
updater-disable field. See [Helium component-update safety](HELIUM-COMPONENT-UPDATES.md)
for the exact capability, consent rules and recorded Sandbox results.
Tests cover fresh/existing profiles,
false/true/false toggles, and read-only replacement failures using inert owned
temporary files. Live Helium results and their limits are recorded separately.

## Network and extraction budgets

All production HTTP clients share `core/src/network.rs`: a 15-second connect
timeout, a 30-second per-read stall timeout, and a total request deadline of
60 seconds for metadata or 20 minutes for package/extension-archive transfers.
These are built-in safeguards, not `nomad.toml` options. Redirect protections
and signature/digest verification remain required. Metadata includes browser
release and AMO add-on JSON, signed checksum files, signatures and tag
verification responses.

Metadata responses are streamed into buffers capped at 16 MiB; Chromium
extension ZIP and Gecko XPI responses use 128 MiB. Both declared lengths and bytes
actually received are checked, including chunked responses. Browser package file
downloads retain the 1 GiB cap. Metadata connection/timeouts use the existing
offline fallback; package failures follow the existing error/retry/fallback flow.
Oversized responses are failures. Failed transfers preserve the prior
destination and remove only their own partial temporary file. Optional extension
checks keep their existing graceful failure behavior.

Browser ZIP extraction retains its cumulative 8 GiB decompressed cap; Chromium
extension ZIP extraction retains 512 MiB. The bundled 7-Zip extraction path now
has a 10-minute deadline and checks its raw output tree against 8 GiB and
100,000 entries, before flattening or promotion. The watchdog polls every
50 milliseconds plus scan time, checks the deadline during traversal, and
terminates and reaps the owned extractor on failure. Standard streams are
discarded and the Windows console is hidden. Downloaded installers are never
executed. A failed staged extraction leaves the active browser/profile intact.

The 7-Zip output cap is observed, not an OS disk quota: writes can overshoot
between scans, and OS process/filesystem calls can take longer than a deadline.
ZIP byte caps are enforced while copying; they are not CPU/memory quotas for
the archive parser. These limits bound individual operations, not the sum of
several sequential update requests or a hostile host. Tests use delayed local
HTTP, inert ZIPs, and a child test helper in owned temporary folders.

## Direct launch versus protocol launch

The registry command uses `"Nomad-<browser>.exe" -- "%1"`. A `--` separator
requires exactly one non-empty URL/file target. Reject missing targets, extra
arguments, and targets whose first non-whitespace character is `-` or `/`
before internal flag dispatch or configuration/ownership work. A separator without a target must not become
a direct launch that may provision software. Accepted target contents stay
unchanged as one positional browser argument; error messages do not echo them.
Use a drive-qualified path or `file://` URL for Windows file targets.

That OS protocol path is launch-only:

- it requires an existing version marker and browser installation;
- it disables browser update checks and automatic downloads;
- it disables extension provisioning that is coupled to update checks;
- it forwards the URL to the same executable and portable profile used by a
  direct launch, allowing Chromium's normal single-instance handoff to open a
  tab in the existing window.

A direct launcher invocation remains the only path that may install or update
software. This keeps ordinary link clicks from becoming hidden provisioning
events and makes unexpected installs attributable and reproducible. The
[already-running Helium qualification](LIVE-PROTOCOL-HANDOFF-QUALIFICATION.md)
exercised native URL/file cancellation and delivery to the original browser with
its cleanup coordinator retained. The [subsequent Windows-selected fixture](WINDOWS-SHELL-HANDOFF-QUALIFICATION.md)
qualified Helium HTTP/HTML handoff and HTTPS dispatch through actual ShellExecute
after user selection. HTTPS content and other browser/platform combinations
remain separate; that fixture explicitly disabled the already-tested reminder.

## Fallback process creation

"Launch anyway" still performs mandatory browser preparation before attempting
to create the process. If process creation fails, the launcher shows the error
and waits for Retry or Close. It does not automatically mark the attempt done,
offer another fallback bypass, or start cleanup for a process that never existed.
Retry hands control back to the existing pipeline loop; Close ends the attempt.

Only a spawn that passes the one-second immediate-failure watch invokes the
post-spawn callback, starts a cleanup worker and signals the window to close.
An NTSTATUS failure during that interval is reported as failed startup. This
is not proof of a usable browser window or successful navigation. Ordinary
remoting exits can be successful. Cleanup workers acquire one owned per-folder
`Nomad/cleanup.lock`; duplicates exit without repeating post-exit actions.
The OS releases this coordination lock when its worker exits, including a
crash. A separate default-on journal records owned image/path intent before
spawn, under the install lock. Later GUI direct/protocol launch attempts can
retry attributed Recent/WER cleanup before update work, under both locks and a
conservative idle check. Post-exit cleanup takes the same install lock before
deletion, including nested browser layouts. Journal failures permit launch with
a warning; missed sessions without a usable record remain unrecoverable.
[Recovery scope, data and test limits](MISSED-CLEANUP-RECOVERY.md) apply; shared
cache actions and registry operations are never replayed.
Existing preparation, branding and ownership rules still apply.

Tests use an absent absolute executable in an owned temporary folder and
controlled error/success results with in-memory UI choices. The success result
is inert; no browser, registry repair, cleanup watcher or hardware probe runs.

## Success markers

Markers are assertions, not hints. Code may write a success marker only after
the corresponding postcondition has been verified. Missing targets, skipped
resources, partial writes, or incompatible layouts leave the marker absent so
the operation is retried after the launcher is updated. Tests must cover both
the success path and every fail-closed condition.

## Cleanup ownership boundary

Neither ordinary nor fallback launch deletes host browser state. Post-exit
automatic cleanup requires the launcher's matching instance marker and a
browser executable that resolves inside the owned portable folder. A missing
marker, mismatched family, relative/foreign image path, or reparse-point path
fails closed and leaves host traces intact.

Recent cleanup removes only individual links whose safely parsed local target
resolves inside this folder; it does not use a drive letter as an ownership
boundary. Recognized local IDList, LinkInfo, Unicode and relative records must
all agree on one existing target. Bounded known-folder anchors must also match
the stored IDList prefix and current built-in folder mapping. Unsupported or
conflicting records, network/environment targets, and missing targets are
preserved. The Windows decoder loads metadata from memory and requests RAWPATH;
it never calls Resolve, saves the shortcut, executes a target or searches for
moved files. See [Recent shortcut safety](RECENT-SHORTCUT-SAFETY.md) for the
format allowlist, native trust boundary and Windows test limits. WER cleanup
requires one absolute `AppPath` in bounded, valid UTF-8 or UTF-16 `Report.wer`
metadata that identifies this exact existing browser image. Both current-user
Local AppData and machine-wide ProgramData queues/archives are covered. AppPath
is checked against the owned folder before lookup and must pass reparse/path
checks before canonicalization. Only flat reports with at most 256 ordinary
files are supported. Windows sharing checks preflight every attachment before
mutation; attribution is reread through the metadata handle. Attachments,
including dumps inside that attributed report, are removed before Report.wer;
the last operation removes an empty folder, without recursive deletion. Reports
that fail access preflight, or contain linked/nested/over-budget entries, are
preserved. An attachment
failure leaves attribution for a later completed session's retry, although
partial deletion can occur. These checks do not prevent a hostile writer's
concurrent replacement. File metadata reads are capped at 64 KiB. See
[WER cleanup safety](WER-CLEANUP-SAFETY.md) for coverage and remaining limits.

Host browser/profile directories, Gecko install maps, shared temporary files,
standalone crash dumps, and whole compound Jump Lists are never automatic deletion
targets. A matching brand name, filename, or missing executable is not proof
that a file belongs to the portable instance. Unknown ownership means leaving
a trace. Explicit thumbnail/icon-cache clearing keeps its documented opt-in
behavior. Prefetch deletion and its UAC path are retired: the legacy config
key and internal flag cannot delete host records. Regression tests cover old
configuration/argument compatibility without real host cleanup or elevation.

## Ungoogled Chromium component data

Browser release checks and verified bundle replacement do not certify CRLSet
freshness. Nomad's default flags suppress component registration, and the pinned
Windows/core source review finds neutralized normal service URLs. Removing the
flag or disabling hardening alone does not restore the default service path.
The launcher therefore discloses the gap without globally enabling unreviewed
component behavior. Existing profile/component files are not changed or deleted
by that disclosure. [Ungoogled component-update safety](UNGOOGLED-COMPONENT-UPDATES.md)
records source pins, the inert endpoint reproduction, limits and pending live
validation. The separately reviewed Helium capability is browser-service consent
based; its result must not be generalized to Ungoogled Chromium.
