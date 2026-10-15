# Disposable recovery integration with Helium

**Status: Windows 11 Helium interrupted-worker/direct-relaunch scenario passed;
host evidence verified and preserved.** Validation used local working changes on
`codex/privacy-security-followup`, base
`ca4633d676ddac433eff4248950de8242d90405a`. See the audit checkpoint and Git history
for subsequent local delivery. This does not clear the v1.0.9 hold or the 3/5
audit rating.

## What this checks

**Verified in code:** `scripts/prepare-recovery-integration-sandbox.ps1` builds a
real local unsigned `Nomad-Helium.exe` with locked dependencies and an explicit
Windows x64 target, checks the launcher artifact requirements, and records the
working source inventory before/after compilation. It does not download or run
a browser, invoke DPAPI, stop a process, register anything or clean host stores.

`scripts/sandbox-recovery/Run-Recovery-Integration.ps1` is a separate manually
invoked guest workflow. Its exact Sandbox account/profile/input-root guards must
not be spoofed. They prevent accidental host use, not a malicious host. The
normal gate runs only `test-recovery-integration.ps1` authored metadata fixtures;
it never invokes the guest workflow. The user authorizes the real-browser test
by opening this dedicated Sandbox configuration.

Inside a fresh guest the test uses the production launcher, browser, detached
watcher, DPAPI journal and normal startup replay. It supplies no alternate Rust
cleanup implementation. Unlike the earlier inert native suite, production
cleanup scans the disposable guest's real Recent/current-user/ProgramData WER
locations. The specifically authored artifacts are a Windows WScript shortcut,
two synthetic flat `Report.wer` directories, inert attachments and a standalone
inert dump. Real Windows-generated WER forms remain a separate pending check.

## Run sequence

Prepare on the host:

```powershell
pwsh -NoProfile -File scripts/prepare-recovery-integration-sandbox.ps1
```

Open the generated `Nomad-Recovery-Integration.wsb` in a fresh Sandbox. The
startup command invokes `-Phase Fresh`. If its PowerShell window does not
appear, run this inside the guest:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\NomadInput\Run-Recovery-Integration.ps1 -Phase Fresh
```

1. Let Nomad install the pinned reviewed Helium 0.19.2.1. Leave Helium service
   setup untouched, do not make it the default browser, and enter no personal
   data. Bookmark `about:blank` as **Nomad recovery test**, confirm built-in
   uBlock visually, and keep Helium open.
2. Run the same helper with `-Phase Interrupt`. It requires the expected live
   browser, installed marker, unchanged initial config and armed journal.
   It retains the watcher process handle before comparing CIM image, command
   arguments, PID and creation time with the retained object's start time.
   Only that exact corroborated worker is terminated; no browser or name-based
   termination occurs. It creates fresh token-named guest artifacts and freezes
   Nomad update checks in the exact helper-owned config for the relaunch test.
3. Close Helium normally, including all windows. Run `-Phase Relaunch`.
   The helper refuses a running/unqueryable/other `chrome.exe`, confirms journal
   and trace preservation after the interrupted worker, then starts Nomad.
   It requires recovery logging before the new browser launch, retirement of
   the old journals, removal of the attributed shortcut/report, preservation
   of the foreign shortcut/report and standalone dump, and unchanged config,
   installed marker and public bookmark URL.
4. Confirm the bookmark and built-in uBlock visually, send output, and keep the
   guest open until the host verifies and preserves the exported evidence.

`-Phase Status` is read-only. `-Phase Export` captures diagnostics without a
browser launch/termination or cleanup. Failure/incomplete exports are preserved
but cannot satisfy the host success verifier. Interrupted/relaunch phases refuse
repetition; do not delete state to make a failed attempt look successful. A new
fresh Sandbox is needed for a new complete attempt.

## Data and network boundaries

**Verified configuration:** Networking is enabled for the pinned GitHub API
metadata and browser package download; metadata must match the fixed release
URL/name/SHA-256 before Nomad can run, and Nomad verifies package bytes before
extracting them. No release executable is downloaded/extracted on the host by
preparation. Subsequent Nomad relaunch checks are disabled only in this disposable
instance. Browser traffic is not disabled by that config; leave service consent
untouched. These tests do not qualify all browser network destinations or DNS.
Known fixture endpoints are `api.github.com/repos/imputnet/helium-windows/releases/tags/0.19.2.1`
and the fixed GitHub release asset URL, including its HTTPS redirects. Optional
bookmark URL `https://example.com/` is accepted, but `about:blank` avoids navigation.

vGPU, clipboard, audio/video and printer sharing are disabled. Only the newly
owned test input is mapped read-only and a dedicated evidence output mapped
writable. Browser binaries/profile, DPAPI state and synthetic guest host traces
stay in the guest. Guest graphics/runtime dependencies can still fail; preparation
is not proof that the browser opens. No host profile is imported.

Exports contain bounded test state/stage results and the test instance's Nomad
log, plus their hash receipt. They include guest paths, process IDs/start observations,
public bookmark URL, and hashes of config/marker/foreign artifacts/protected
journal bytes. They do not copy profiles, cookies, password stores, browser memory,
DPAPI keys or raw real crash dumps. Dedicated mapped output persists; host
verification should be copied to an unmapped snapshot before closing the guest.

The read-only host function `Test-RIExport` in repository
`Recovery-Integration-Helpers.ps1` checks bounded schema/path/hash/provenance,
typed stage assertions and production log evidence. Use the repository version,
not any guest-supplied executable. It verifies bytes and reported assertions,
not a compromised guest, original code execution history or independently replayed
browser operations. Built-in uBlock preservation requires user confirmation.

## Remaining limits

This simulates interruption of one cleanup worker, followed by a normal browser
close and direct launch. It does not physically interrupt power/storage, establish
journal durability across device loss, or exercise protocol handoff, query denial,
registry repair, Windows 10, independent users/machines, real WER crash forms or
other browser families. The earlier second-Sandbox machine-only decryption
failure remains recorded; no isolation assertion or acceptance gate is weakened.
A successful integration result would narrow the production-path gap only.


## Local validation (2026-10-14)

**Tested:** Offline integration metadata/safety fixtures passed on PowerShell 5.1
and 7. They reject wrong PID/image/command/start identity, extra scrub arguments,
non-guest context, non-public bookmark URL, traversing/incomplete evidence,
changed hashes and false/string assertion fields. No native browser/DPAPI or
watcher termination occurred in these regressions.

**Tested:** `pwsh -NoProfile -File scripts/check.ps1` passed formatting, strict
Clippy, 532 core + 12 integration + 2 metadata Rust tests (546 passed, 16 ignored),
existing safeguards, the new offline integration safety suite, and a clean
advisory result. Gate mocks confirm an integration-safety failure stops Cargo.
Log: `target/recovery-integration-check.log`. `git diff --check` passed.
Rust code is unchanged for this preparation; the earlier Rust 1.92 result is
historical and was not rerun. Guest/browser integration and remote CI remain
pending. The build-only package command records its own compiler/artifact/source
results without executing the resulting launcher on the host.


## INFO logging setup correction (2026-10-14)

**Observed:** The first actual browser setup reached the user's bookmark/uBlock
check, but `-Phase Interrupt` refused its required watcher-event count. That
refusal is before obtaining or terminating a process, creating synthetic host
artifacts, or changing the initial configuration. The original package and its
input manifest are preserved; no integration pass is claimed.

**Verified in code:** The original guest helper started Nomad without setting
`NOMAD_LOG`; `core/src/lib.rs::init_tracing` defaults to WARN, whereas watcher
spawn and startup recovery messages are INFO. This is a test-setup bug. The exact
observed missing/duplicate log count still requires exported guest diagnostics;
it is not established merely from the generic original exception.

**Verified in code / tested:** `Start-RILauncher` now enables INFO for each guest
launcher start, so detached watcher children inherit it, then restores the
caller's prior logging environment on success or failure. It requires the
Sandbox input guard and the exact token-owned launcher path. Authored scoped
mocks on PowerShell 5.1/7 verify child logging and restoration for absent/WARN/
DEBUG prior values and failed startup, without starting any process. Real-format
log fixtures require one positive bounded watcher PID and reject missing,
duplicate, zero or overflowing IDs. Exact live handle/image/command/start-time
checks remain unchanged; no process is selected by guessing or basename.

**Next action:** While the original browser/Sandbox remain open, run its original
helper with `-Phase Export`. This safely exports the bounded initial state/log
and an incomplete receipt through the existing dedicated mapping. The host
must verify and preserve that attempt before closing it. Use a newly prepared
corrected package in a fresh Sandbox for the full test; do not overwrite mapped
inputs, synthesize missing INFO events, repeat Fresh in the existing guest, or
reuse an unverified process ID. Its normal success verifier must reject the
incomplete export. Browser integration remains pending.


**Tested correction checks:** Canonical `pwsh -NoProfile -File scripts/check.ps1`
passed again (546 tests, 16 ignored, formatting, strict Clippy, safety regressions
and clean dependency audit); log `target/recovery-integration-logging-check.log`.
PowerShell 5.1/7 mock fixtures and `git diff --check` passed. Original package
`recovery-integration-60787c95be9b4ecead7c8d68dce2d49c` input hashes still match
its original manifest. A corrected package will have its own frozen source/input
manifest; compilation does not execute guest integration. Diagnostic export and
production-path recovery remain pending; changes remain local/uncommitted.


## Active-log capture correction and preserved partial attempt (2026-10-14)

**Observed / tested:** The original Export copied `STATE.json` and `nomad.log`
then failed while `Get-FileHash` reopened the actively held source log. It did
not finish its guest receipt. The existing mapped output has been copied to an
unmapped host snapshot:
`target/recovery-integration-60787c95be9b4ecead7c8d68dce2d49c/VerifiedEvidence/integration-2e6e09376bac46c1b25d4ed82bb1f533-e8a3644935ae4cb6b1d04f918810c5f1/`.

**Host-verified partial observation:** Both copied output files were bounded,
hashed, preserved and rechecked. State SHA-256:
`1B309883F52FBDCCFF7F9C7C2A5133C66C87989F7E41AFB7DA4C827B2AC5D03C`;
log SHA-256:
`0A07F8CF7AD40D7647D3157BBBE075D5F27D1BA530F712E75FD72EA22F0CD36D`.
The 417-byte copied log contains only WARN entries and zero watcher-spawn events,
corroborating the earlier INFO setup omission. The copied state identifies token
`2e6e09376bac46c1b25d4ed82bb1f533`. The original input manifest is saved beside
`HOST-PARTIAL-VERIFICATION.json`; original mapped input hashes still match it.

The guest receipt and live-source hash confirmation remain missing. This snapshot
is a preservation of incomplete copied output, not a fabricated complete transfer
receipt, attestation of the guest's source identity, or interruption/recovery pass.
Nothing is removed from the original output. Initial bookmark/uBlock presence
remains the user's observation. The copied diagnostics suffice to preserve this
setup attempt before opening a new corrected fresh Sandbox.

**Verified in code / tested:** `Read-RIBytesSnapshot` holds one read handle with
ReadWrite/Delete sharing, reads no more than the initially observed bounded
length, rejects premature EOF/source shrink and refuses oversized or inaccessible
inputs. Live log reads and exports use this helper. Export writes a new destination
and checks its bytes against the captured buffer's SHA-256; it never compares a
later live-file hash against the earlier capture. Capture describes a bounded
prefix, not an atomic/immutable view, complete log history or independent execution
attestation. Continued appends/rotation can leave later events outside the capture;
concurrent overwrites are not authenticated. The success verifier still requires
its existing typed stage and recovery-log assertions.

PowerShell 5.1/7 regressions passed with a real held writer on an authored file
in an owned temporary directory: snapshot/read works without releasing it, later
appends leave prior copied bytes unchanged, and exclusive sharing, oversize,
destination overwrite and empty-file cases are exercised. No browser, DPAPI or
process termination ran. Microsoft's [FileShare documentation](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileshare?view=netframework-4.8.1)
describes the sharing controls; no elevated handle override is attempted.

Keep original package inputs intact. Use a newly prepared package containing both
INFO setup and shared-read fixes in a fresh Sandbox. Do not retry the old export
script or try to kill the browser to force a hash comparison. Full integration,
independent users/machines, physical interruptions and release qualification remain
pending; work is local/uncommitted and v1.0.9 stays on hold.


**Tested shared-capture correction checks:** Canonical gate passed again: 546
Rust tests, 16 ignored, formatting, strict Clippy, offline safety fixtures and
clean dependency audit; log `target/recovery-integration-snapshot-check.log`.
PowerShell 5.1/7 held-writer/mock regressions and whitespace checks passed.
The unmapped partial snapshot was rechecked with its explicit missing-receipt/
live-source limitations. No browser or watcher was run/stopped by host tests.
A fresh package with both corrections records its own source/input hashes;
older packages remain preserved and should not be used for the next attempt.
Guest integration, remote CI and release remain pending; work is uncommitted.


## Helium interrupted-worker recovery verified (2026-10-14)

**Tested / host-verified:** Corrected package
`target/recovery-integration-d09983fe97064b0fa60e36ea35ec9738/` completed the real
Helium 0.19.2.1 interrupted-worker/normal-close/direct-relaunch scenario on Windows
build 26100. The user initially omitted the test bookmark, causing a read-only
precondition refusal; after creating it, the same guest successfully continued.
No guard or bookmark assertion was changed to accept that omission.

Session token: `dabb00bb8a144343b797984aa3d80b71`; export token:
`183477d1ed2f4df0a8bea94b6e8a4d6c`. The repository `Test-RIExport` verifier passed
all five copied-file hashes, provenance, typed stage assertions and log checks.
Additional host reads confirmed all three package inputs and 179 source files
matched the frozen build inventory before this documentation update. Journal
metadata agrees across saved state, interruption and closed-session records.

**Tested / observed in preserved log:** Initial browser PID 8092 spawned watcher
6900. The helper reports terminating only that retained/corroborated worker while
Helium remained running, with captured termination exit -1. After normal browser
close, intent and authored fixtures remained. Direct relaunch removed the owned
Windows-created Recent shortcut and synthetic WER report, retired **one** recorded
cleanup intent, skipped updates under the frozen test config, then spawned browser
5392 and a new watcher 6828. The recovery entry precedes the new browser launch.
This is not a claim that every pending record, including new launch intent, vanished.

**Guest assertions / user confirmation:** Foreign shortcut/report and standalone
inert dump hashes, frozen Nomad config, installed-version marker and public
`about:blank` bookmark were preserved. The user also confirmed **Nomad recovery
test** and built-in uBlock remained present after relaunch. The original guest
`ubo_confirmation` field remains pending visual confirmation; that receipt is
unaltered. The separate host report/user observation records the later response.
No profile, cookie store, password store or memory dump was copied to the host.

**Preserved and reverified:** All five evidence files, unchanged guest receipt
and build manifest are in an unmapped snapshot under the package's
`VerifiedEvidence/integration-dabb00bb8a144343b797984aa3d80b71-183477d1ed2f4df0a8bea94b6e8a4d6c/`,
with `HOST-VERIFICATION.json` and `USER-CONFIRMATION.txt`. Receipt SHA-256:
`0F0753325EB337AD7792A05A6EF42A2FA3B3CD8F5498604F044847E5C6DD6F9F`.
Source snapshot:
`548375976831F69EE738E73EA9B327E1523A5B9BE597E638746426C8590D9136`;
launcher:
`0D78C6E43AEC7CD5CB9B6A327BB3B3BBCB15DF6D8F23CB2B53FD0AA910E707C5`.
Base remains `ca4633d676ddac433eff4248950de8242d90405a`. Hash agreement verifies
copied bytes/reported results, not a compromised guest or signed source attestation.
The log is a bounded capture through the newly started watcher, not complete history.
Earlier incomplete setup/export evidence and the second-Sandbox refusal failure
remain preserved; they are not rewritten as passes.

**Disposition:** The current guest may be closed after this host snapshot check.
This closes the tested Windows 11 Helium direct-relaunch recovery scenario only.
Independent users/machines, physical interruption/storage durability, Windows 10,
protocol handoff, other families/query denial, genuine WER crash forms and broader
browser/DNS/component/installer behavior remain pending. Ungoogled CRLSet refresh
restoration is unresolved. Rating remains 3/5 and v1.0.9 stays on hold.

Only documentation and owned evidence artifacts changed for this record. The
previous canonical gate result remains 546 passed/16 ignored with strict Clippy,
formatting, safety fixtures and clean dependency audit
(`target/recovery-integration-snapshot-check.log`); it was not rerun solely for
these documentation changes. Work is local/uncommitted/unpushed.
