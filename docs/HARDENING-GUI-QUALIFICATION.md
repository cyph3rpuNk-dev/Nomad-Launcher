# Required-settings native GUI qualification

## Result and exact scope (2026-10-15)

**Tested:** the production Helium launcher on Windows 11 Sandbox
(`10.0.26100.0`) refused malformed required Local State JSON. Its native window
exposed visible, enabled Retry and Close buttons, with no Launch anyway.
Retry with the malformed bytes unchanged produced another refusal. Repairing
only that disposable JSON allowed Retry to start the verified portable browser.
A second malformed-file case exercised Close and exited without browser launch.

Source: `187771c43ad5bb2eb266cfb0447b5ef84ca80928`. The preceding Windows
metadata correction was committed locally at that hash. This qualification
required no production change. Its documentation was first prepared on
`codex/hardening-error-gui` and is included in the subsequent local browser-
qualification checkpoint. There is no push, remote CI or release result.

| Observation | Evidence / limit |
|---|---|
| First refusal and blocked Retry | Native UI Automation tree, malformed-file hash, zero owned browser processes, and pipeline-error count increasing from 1 to 2. Initial INFO-log absence is not proof of watcher absence. |
| Repair and Retry | Eight exact-image browser processes, one native browser window, the intended Data argument and one exact-image/command-line cleanup watcher were observed. |
| Saved settings after repair | HTTPS-only true, Safe Browsing false and DNS mode secure were read from the disposable files. These are saved requests, not proof of effective browser settings or traffic. |
| Separate Close case | Native HWND/process identity, visible Retry/Close, zero owned browser/watcher processes; actual Close InvokePattern exited the launcher. Numeric exit code was unavailable (`null`), so exit 0 is not claimed. |
| Preservation | Browser EXE/DLL, installed version marker, instance identity, test configuration and a public profile sentinel retained their hashes. This is not a real-user bookmark/account preservation test. |
| Final state | Zero owned launcher/browser/watcher processes; protected files and the second malformed JSON unchanged. Earlier native metadata originals/copies also retained all four hashes. |

**Verified in code:** [required preparation](../core/src/lib.rs):1184 wraps local
settings errors; [error handling](../core/src/lib.rs):1468 disables fallback for
preparation errors; [native error rendering](../core/src/ui/mod.rs):388 offers
Retry/Close and gates Launch anyway on fallback eligibility. This run exercises
the direct-launch Chromium Local State path. Existing inert tests separately
cover fallback/protocol-style and staged-overlay refusals.

## Disposable fixture and controls

**Tested:** the agent operated the guest directly through Windows Sandbox CLI;
no user command pasting or browser interaction was required. The existing
metadata guest remained networking-disabled, with zero active non-loopback
interfaces and zero default routes. Its original Recent/WER records remained
outside this new instance. Only dedicated input/output folders were mapped.

A pinned official [Helium 0.19.2.1 release](https://github.com/imputnet/helium-windows/releases/tag/0.19.2.1)
ZIP was downloaded on the host and checked against that release API's required
SHA256 and length (197,068,948 bytes) before guest extraction or execution. This
trusts GitHub HTTPS metadata; it is not publisher-signature verification.
The ZIP inventory was bounded and checked for paths before extraction into a
new owned guest root; 75 entries totalled 435,717,787 uncompressed bytes. The
flat bundle and test marker were imported, so Nomad's download/update/extraction
pipeline is not qualified by this run.

The new instance used `check_on_launch = false`, `auto_download = false` and
hardening enabled. Its malformed file and profile sentinel were authored test
data. Service setup was left untouched; the helper did not accept consent.
No default-handler registration or persistent host configuration was requested.
The successful browser launch ran Nomad's normal guest cleanup watcher. Final
hash inspection confirmed that the previous guest's original metadata survived.

**Documented / tested automation:** Microsoft's
[UI Automation testing model](https://learn.microsoft.com/en-us/dotnet/framework/ui-automation/using-ui-automation-for-automated-testing)
provides control inspection/invocation. The controller checked exact executable
paths and creation times, then
[native HWND process ownership](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowthreadprocessid)
and titles before accessing the owned launcher. The browser received only
[normal window-close requests](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.closemainwindow?view=netframework-4.8.1),
with no forced termination. These operational checks do not attest a hostile host.

## Commands and retained evidence

**Tested build:** `cargo build -p nomad-helium --release --locked --target
x86_64-pc-windows-msvc --message-format json-render-diagnostics` passed. The
unique actual Cargo artifact passed the unchanged production PE metadata guard
(static CRT/imports, architecture, CFG and System32 import policy).

**Tested guest:** `wsb.exe exec --id 30d3142c-e105-42f7-9ace-e32023b9696c
--command 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden
-ExecutionPolicy Bypass -File C:\NomadInput\HardeningGui\Invoke-With-Diagnostic-V4.ps1
-Phase <phase>' --run-as ExistingLogin --raw`, using separately frozen controller
versions as recorded below. Host code checked each guest ExitCode before dependent
work. The phases were Start, InspectError, RetryBlocked, RepairRetry,
InspectBrowser, CloseBrowser, StartCloseCase, InspectError and CloseError.

| Identity | SHA256 |
|---|---|
| Local unsigned launcher | `6A179521EF7289A61B5F541BCAFBCA5AFF26D167D4DCCAE2D78E0D351182AC93` |
| Official pinned Helium ZIP | `8623C04201A0A45A97920C7ACDAA3A9F022260C66D6DFE78E7DCB323D4D2D89C` |
| Original four-input manifest | `ADA9E259F57600020AA9F4C9B2204333B838C45E6A61D71A935FB9CD65AB6BC1` |

The local ignored package is
`target/hardening-gui-12cc3596ac0f4f5498a9444e31fba6fb`. Its unmapped
`VerifiedEvidence/required-error-76bf9dc4f81b41b0ad4cb81a4e6bd64b/HOST-VERIFICATION.json`
retains nine linked phase receipts, source/build inventory, helpers and selected
diagnostics/images: 52 retained files with byte-identical copy/hash checks.
Raw guest profile, logs and Windows metadata were not exported. Local helpers
and evidence are not shipped launcher features or CI artifacts.

**Tested host verification:** `Verify-Hardening-Gui.py` checked token/commit,
manifest/input digests, pinned release metadata, typed assertions, actual native
process counts, UI button sets, final idle/preservation and earlier metadata
conservation. String-boolean, boolean-as-count, unexpected watcher and added
Launch anyway mutations were refused. Verification validates selected guest
assertions and copies; it is not independent observation of every guest event.

The following failed or partial controller attempts remain preserved:

- The first UI inspection refused AccessKit's zero UIA ProcessId. V2 retained
  the refusal and added native HWND-owner checks; it did not change the launcher.
- V2's successful-browser inspection incorrectly required INFO log messages.
  Nomad defaults to warn. V3 checked native owned process identities instead.
  Initial missing INFO events are not used to establish watcher absence.
- V3 requested normal browser closure, then encountered an already-exited child
  PID. V4 completed inspection with zero browser processes already at entry;
  no forced close was used and that recovery call is not counted as a new close
  request.
- The first PrintWindow image was DPI-cropped. A separate DPI-aware capture
  showed the complete owned error window and visible buttons; both are retained.
- The first host verifier expected a preservation field omitted by Retry's
  receipt. The corrected verifier used the actual schema and retained helper
  assertions rather than inventing an exported field.

## Validation and remaining work

**Tested:** production Rust remained identical to committed `187771c`; its final
canonical gate already passed 551 tests (17 ignored), strict Clippy, formatting,
safety fixtures and the dependency audit with the existing RSA exception, and
Rust 1.92 checking passed. This follow-up adds a successful release compilation,
scoped native GUI evidence and document checks. Evidence-only documentation
changes do not imply another full gate or any remote check.

**Tested document/evidence recheck:** five changed documents passed strict UTF-8,
LF and whitespace checks; 89 local file/heading links passed. All 52 retained
evidence files and 119 unchanged production source/build inputs were rechecked
against their preserved hashes.

**Observed UI limitation:** the status header still says Launching while the
error explains that launch stopped; the long error scrolls. The complete image
shows Retry/Close within the window. This run does not correct that wording.

**Not tested:** Windows 10, native Gecko/fallback/protocol/staged-error UI,
read-denied ACLs, concurrent writers, whole-profile rollback, effective browser
policy/extension/network behavior, accounts or real-user profile migration.
The existing staged-fixture preservation tests are not a native replacement
rollback test. The rating stays 3/5 and the v1.0.9 hold remains; see the
[current checklist](RELEASE-READINESS.md).
