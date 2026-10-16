# Update freshness for link-only users

## Behavior and user control

**Verified in code:** A registered URL/file launch remains launch-only.
`LaunchOrigin::Protocol` forces both check and download permissions off inside
`core/src/lib.rs:646`, even if a caller passes permissive options. With
`[update] remind_on_protocol = true` (default, including legacy configs), a
local maintenance reminder can appear before runtime creation/preparation.
Its buttons are Continue opening link and Close, without an update action.
Continue does not change update permissions or bypass required hardening;
Close cancels the handoff. The existing target is not put into the reminder
or acknowledgment. Stale UI actions restore the reminder instead of triggering
fallback/update behavior (`core/src/lib.rs:425`).

**Verified in code:** `core/src/protocol_freshness.rs:24` reads only saved local
metadata. A reminder is due when the browser check or relevant Nomad-managed
uBlock lookup is missing/invalid/future-dated or at least seven days old, or
when metadata records a version differing from the installed record. Browser
records require the selected package target, plausible distribution URL,
integrity material and an orderable non-older version. These checks establish
advisory record plausibility, not authenticity of local state or archives.
Helium/Mullvad built-in extensions are not classified as Nomad-managed checks.

**Verified in code:** Continue writes a schema/browser/target/timestamp
acknowledgment. A matching acknowledgment suppresses reminders for less than
24 hours; zero/future timestamps and other browser/target records cannot hide
them. The cooldown can suppress a newly known update too. Close does not save
an acknowledgment. Failed acknowledgment writes log a warning and still permit
the existing-browser handoff; the reminder may recur. Reminders run under the
portable-folder lock, so other launcher attempts can require Retry while a
prompt remains open. No background scheduler or automatic maintenance process
is started.

**Documented:** Run Nomad directly with update checks enabled to maintain the
browser and managed uBlock; close the browser first. Setting
`[update] remind_on_protocol = false` opts out, independently of hardening and
`check_on_launch`. It does not stop the already-enabled direct update checks or
their metadata receipts. Old configs acquire the default in memory without a
rewrite; newly generated configs include the option. Older launcher versions
that reject unknown keys cannot read a config containing this new option.

## Local data and network inventory

**Verified in code:** Browser lookup time remains the existing `fetched_at` in
`Nomad/nomad-version-cache.toml`. Cache hits and skipped/failed checks do not
refresh it. Future-dated caches no longer count as fresh even for the six-hour
normal direct-check cache. Cache reads are bounded at 64 KiB and refuse linked
paths; reminder and extension receipts use 4 KiB bounded reads. Invalid or
oversized state causes conservative advice rather than a freshness assertion.

**Verified in code:** A successful managed-extension metadata lookup writes
`Nomad/managed-extension-check.json` with schema, lookup time and reported
version, via individual atomic replacement (`core/src/version_cache.rs:212`).
AMO records follow add-on identity/public-version/digest/URL validation
(`browsers/mod.rs:127`). Chromium's gorhill receipt records the successful
release-version response before asset/signature/download checks
(`browsers/ungoogled.rs:528`). A deferred or failed installation may therefore
have a new lookup receipt while the installed version stays unchanged.
The installed-version cache and existing extension bytes are not replaced just
because a lookup succeeded. Failed/offline metadata requests do not create a
successful receipt. Receipt-write failure leaves the previous record, logs a
warning and does not block launch.

**Verified in code:** `Nomad/protocol-update-reminder.json` stores only schema,
browser id, package target and last acknowledgment time. It contains no opened
URL/file target, query/token, per-link event list or counter. Both JSON files are
plaintext local advisory state, retained until overwritten or manually removed;
there is no automatic deletion schedule. They reveal maintenance/acknowledgment
timing to someone who can read the drive. Reading advisory state does not send
it anywhere. This change adds no endpoint: direct browser and extension checks
use the existing adapter/AMO/GitHub endpoints, while the protocol reminder makes
no updater network request. The browser itself may still make network requests
and maintain its own built-in extension/components under its existing settings.

## Limits and verification

**Inference / design limit:** A seven-day reminder threshold balances notice
frequency and repeated link launches; it is not a safe vulnerability window.
It does not guarantee updates are installed promptly or at all. Users can
continue, opt out, remain offline, or leave checks disabled indefinitely. Local
state and the system clock are not authenticated; a hostile writer can alter
records and a backward clock can cause extra reminders. The data does not
prove current installed bytes, active extension status, filter-list freshness,
upstream security, component refresh or Nomad self-update. Missing/legacy
installed-extension metadata can cause conservative false-positive advice.
Fresh browser metadata alone cannot establish a fresh managed-extension lookup.
The core guarantee remains no protocol provisioning, rather than automatic
security freshness.

**Tested:** On Windows 11 build 26200, nine new inert regressions cover independent
browser/extension ages, the exact seven-day boundary, missing/future/unorderable
records, deferred versions, built-in extension exclusion, 24-hour acknowledgment
expiry, browser/target scope, bounded/linked state preservation, future cache
rejection, separate lookup/install state, legacy/opt-out config and GUI layout.
Pipeline fixtures test Continue/Close and a stale Launch anyway action with
permissive update options. Continue reaches a deliberate required-settings
failure before command creation; Close creates no acknowledgment or command.
No actual browser, cleanup watcher, installer or host configuration change was
used for these new checks. AMO/gorhill deferred-download mocks also check receipts
without archive/signature downloads. Existing failed-XPI-promotion tests still
preserve extension bytes and installed-cache bytes.

**Tested:** `pwsh -NoProfile -File scripts/check.ps1` passed formatting, strict
Clippy, 508 core tests + 12 integration tests + two metadata regressions (522
total), safety fixtures and the clean dependency audit. Four native registry
and eight live-upstream/download tests remain ignored.
`cargo +1.92 check --workspace --all-targets --locked --target
x86_64-pc-windows-msvc --target-dir target/msrv-1.92` passed compilation.
Logs: `target/protocol-freshness-check.log` and
`target/protocol-freshness-msrv-check.log`.

**Not tested in the initial fixture campaign:** Actual Windows URL/file handoff
through this new visible prompt,
Windows 10 rendering/execution, interaction with a live running browser, and
cross-machine clocks. Headless egui tests verify fixed-window button bounds,
not a native display screenshot. A disposable Windows 10/11 check should compare
URL/file handoff before/after Continue, confirm Close cancels, capture the prompt,
inspect the two local receipts, and verify no package fetch/staging recovery was
triggered. These checks remain pending; no remote CI result is claimed.

Delivery is local/uncommitted on `codex/privacy-security-followup`, base
`ca4633d676ddac433eff4248950de8242d90405a`, alongside the preceding Recent,
WER and required-hardening working-tree changes. v1.0.9 remains on hold.

## Subsequent native prompt qualification

**Tested:** the production Helium launcher ran four native protocol-argument
cases in an offline Windows 11 Sandbox: URL Close/Continue and file Close/Continue.
Close left no browser, page request or acknowledgment; Continue opened the public
guest-loopback URL/local HTML and saved the bounded acknowledgment. Browser
metadata and authored staging/backup sentinels retained hashes despite permissive
update config. The previous URL acknowledgment was archived only within the new
fixture to expose the file prompt. No managed-extension receipt was created.
The [qualification record](BROWSER-STARTUP-HANDOFF-QUALIFICATION.md#native-protocol-reminder-and-handoff)
contains build/input hashes, native control/image evidence, typed host verification
and exact limits. Native argv handoff is now exercised; Windows association
resolution and Windows 10 remain separate. The [already-running Helium follow-up](LIVE-PROTOCOL-HANDOFF-QUALIFICATION.md)
now records URL/file Close/Continue with original browser/worker identity, native
bookmark preservation and coordinator-lock exits; other live-browser combinations
remain unqualified. A [subsequent Windows-selected Shell fixture](WINDOWS-SHELL-HANDOFF-QUALIFICATION.md)
exercised actual HTTP/HTML handoff and HTTPS dispatch after the user selected the
Nomad candidate; its reminder was explicitly disabled to isolate OS dispatch.
HTTPS content and other browser/platform combinations remain separate.
The prompt's explanatory text appeared low contrast, recorded as a minor UI
follow-up. No production behavior was changed for this evidence checkpoint.
