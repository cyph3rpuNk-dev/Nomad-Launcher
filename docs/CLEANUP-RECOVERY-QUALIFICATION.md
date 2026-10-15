# Disposable cleanup-recovery qualification

**Status:** Primary Windows 11 inert fixture passed and host evidence verified.
The second-Sandbox refusal test failed: the nested blob was refused, but the
machine-only blob decrypted. Broader native/release qualification remains pending. Base
`ca4633d676ddac433eff4248950de8242d90405a`, branch
`codex/privacy-security-followup`. The tested source inventories included working
recovery/privacy changes. See the audit checkpoint and Git history for subsequent
local delivery; no push, remote CI or release result is claimed here.

## Scope and boundaries

**Verified in code:** `core/src/cleanup_recovery/sandbox_tests.rs` is compiled only
for Windows lib tests, not launcher binaries. Four ignored functions implement
an explicit native suite, two inert child helpers and a later foreign-context
observation. The normal gate never runs them. A separate ordinary token test
rejects path/shell injection without creating processes or invoking DPAPI.

The suite exercises the production nested DPAPI codec, bounded journal read/
arm/replay logic, strict native process query and coordination locks. A copied
inert lib-test executable acts as the browser image; it never launches a real
browser, navigates, downloads, creates registrations or changes browser profiles.
Cleanup receives only explicitly supplied fake Recent/WER roots. This is a
native module integration fixture, not an end-to-end production launcher/watcher.

**Verified in code / operational guard:** The runner and native tests require
Sandbox's default `WDAGUtilityAccount` and its profile path. A fresh 32-digit
hex token selects `C:/NomadRecoveryQualification/<token>` and an owner marker
must match before the Rust suite proceeds. These checks prevent ordinary
accidental host invocation; environment/account checks are not a security
attestation against a malicious host. Do not fake them to run on personal stores.
No elevation or temporary user creation is requested by the tests. DPAPI may
create/use Windows key state inside the disposable guest.

## Prepare and run

From the repository on the host:

```powershell
pwsh -NoProfile -File scripts/prepare-cleanup-recovery-sandbox.ps1
```

**Verified in code:** Preparation records HEAD, working-tree status, compiler
versions and a sorted SHA-256 inventory of tracked/untracked nonignored source
files. A locked, explicit x64 MSVC `cargo test --lib --no-run` builds the harness;
source hashes are compared before/after compilation. Cargo's JSON artifact
record selects exactly one test executable. Inputs are copied to a newly owned
`target/cleanup-recovery-native-<guid>/Input` with a build/hash manifest. This is
a local unsigned test harness, not a release artifact or signed source attestation.
It is compiled using existing project/dependency settings; the GUI-specific
release artifact guard is not applied to this console test image.

Open the generated `Nomad-Recovery-Native.wsb` in a **fresh** Sandbox. The logon
command opens PowerShell, verifies input hashes, copies the harness into the
owned guest fixture and runs the primary suite automatically. Keep the console
output and Sandbox open for independent host validation. Rerunning the runner
creates another fresh token/fixture and preserves earlier output.

**Documented / verified configuration:** Networking, vGPU, clipboard, microphone,
video and printer sharing are disabled in this `.wsb`. Only `Input` is mapped
read-only and the new dedicated `Output` directory writable. No personal host
folder/profile is mapped. Writable mapped output persists after closing Sandbox;
[Microsoft's configuration documentation](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)
explains these settings and logon commands. The suite does not enumerate graphics
adapters; disabling vGPU does not imply Windows has no graphics activity.

## Assertions in the primary suite

**Tested in the Windows 11 primary inert fixture; verified record below:**

- Native protected public payload round trip, malformed/tampered blob refusal,
  and absence of that literal payload in ciphertext. This sample does not prove
  general confidentiality or resistance to key theft.
- Idle/Running/Unknown classification using exact inert child images; a same-name
  child outside the owned root blocks deletion. Only exact children created by
  this fixture are terminated; no name-based process termination is used.
- Pending journal/report preservation while a matching process or coordinator
  is active. A child arms a native record and holds the cleanup lock, then its
  parent terminates that inert worker. The parent checks cross-process decryption,
  OS lock release and attributed fake WER cleanup/record retirement.
- Temporarily missing image and moved-folder preservation, then recovery after
  restoring the original image/root. This simulates path availability changes,
  not physical drive removal or actual power loss.
- Foreign fake reports and standalone authored dump sentinels remain intact.
  All `.dmp` fixture contents start with `INERT`; no real memory dump is exported.

Helpers have a 45-second self-exit bound, readiness waits are 15 seconds and the
runner's suite deadline is 180 seconds. Assertion/startup failures preserve
fixtures and exported diagnostic evidence. The runner terminates only its exact
harness child on timeout; orphan helpers self-exit. Old results are not overwritten.

## Evidence and independent verification

The guest exports selected fixture/diagnostic files into
`C:/NomadRecoveryOutput/primary-<token>/files`, which maps to the host package's
`Output/primary-<token>/files`. A bounded `GUEST-RECEIPT.json` records phase, token,
base/source/harness hashes, OS version, exit/failure, copied-file hashes and
hash-only references for large inert executables. Ciphertext exports contain
only public test payloads or inert fake-path intent. Fixture marker/report paths
and DPAPI format metadata can remain observable. No real profile, credential,
private key, user dump or upstream package is collected. Source inventories can
identify repository paths; the test image can embed source/build path strings.

**Verified in code:** Export walks only the owned fixture, refuses links/over-
budget traversal or oversized evidence, checks inert dump prefixes and compares
copied hashes. It neither deletes guest fixtures nor invokes an HTTP transfer.
Mapped output is limited to the dedicated package directory. Hash-only references
are observations, not independent proof of large guest file contents.

On the host, after a guest run, use the **repository** verifier:

```powershell
. ./scripts/sandbox-recovery/Verify-Cleanup-Recovery-Evidence.ps1
Test-CleanupRecoveryEvidence -InputDirectory '<package>/Input' -OutputDirectory '<package>/Output/primary-<token>'
```

It performs read-only bounded metadata/path/hash checks, verifies harness/base/
source receipt agreement, inventories result/log files and requires the exact
one-test success summary and native assertion booleans. It refuses failed,
missing, traversing, device-name, trailing-dot, duplicated, linked, oversized
and changed evidence. Native assertions must be actual booleans, not strings.
Hash agreement and guest assertions do not authenticate a compromised guest or
independently reproduce its native operations. Do not execute an exported file
or use a script supplied by the guest as the host verifier.

## Foreign-context and remaining qualification

A later `-Phase Foreign` can read primary public-payload blobs through a separate
read-only `C:/NomadForeignInput` mapping. Its ignored test records nested and
machine-layer refusal separately. Prepare that mapping only after primary host
verification; the first `.wsb` does not run this phase. A fresh Sandbox instance
may reuse/cloned key material; a result is a second-context observation, not proof
of distinct computer keys. Unexpected successful decryption requires investigation.
[DPAPI's contract](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
includes roaming user keys and machine-scope sharing, motivating separate cases.

Different-user isolation on the same real computer, independently keyed VMs,
actual restart/power-loss/drive-removal durability, query-denial races, Windows
10 execution, captured Explorer/WER artifacts and full production browser/watcher
behavior remain unverified. This preparation does not resolve Ungoogled CRLSet
refresh, remaining DNS/browser/Helium checks, rating 3/5 or the v1.0.9 hold.

## Local checks

**Tested:** `pwsh -NoProfile -File scripts/check.ps1` passed formatting, strict
Clippy, 532 core + 12 integration + two metadata tests (546 total), existing
safeguards, new evidence-metadata regressions and clean dependency audit.
Sixteen tests remain ignored: four native registry, eight live-upstream/download
and four guest-only qualification/helpers. PowerShell 5.1 and 7 evidence fixtures
passed using authored metadata and owned temporary directories. Native guest
operations were not run by those fixtures. The canonical gate's mock wiring
also proves a recovery-fixture failure stops dependent Cargo work.

Logs: `target/cleanup-native-preparation-check.log`; package creation records its
Cargo command/JSON artifacts and source snapshot beside the generated inputs.
Rust 1.92 workspace/all-target checking also passed with the locked explicit
Windows x64 target; log: `target/cleanup-native-preparation-msrv.log`. The
package builder completed without running its native harness. Cargo.lock and
staged index remain unchanged. Guest execution and subsequent host verification
are still required before reporting any native result.


## First guest observations and exit-capture correction (2026-10-14)

**Tested / observed:** Two primary fixture logs from Windows build 26100 report
one test passed, all native result booleans true and empty stderr. The host
independently checked 23 exported file hashes per run against the recorded
source/harness identity. Tokens are `3041a53915aa48e2bd6bc213ffb99ae9` and
`68d9de122a8c4832bf675f7199450c55`, under the original package's `Output/`.
Each saved `HOST-PARTIAL-VERIFICATION.json` marks qualification incomplete:
both original guest receipts contain `exit_code: null`. No receipt was edited
or exit value inferred from the success text. These observations support the
reported native assertions but do not meet the complete host verification gate.

**Verified in code / tested:** The runner now uses a dedicated
`Invoke-RecoveryProcess.ps1` helper with `ProcessStartInfo`, shell execution off,
no child window, an explicitly retained process handle, asynchronous stdout/
stderr draining and a required numeric exit code. Failed start/timeout/capture
preserves diagnostics and cannot become success. Microsoft's
[Process.ExitCode contract](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.exitcode?view=netframework-4.8.1)
describes the completed process status and redirect-draining requirement;
exact root cause within PowerShell's previous Start-Process wrapper is not
instrumented. Regression fixtures on PowerShell 5.1 and 7 retain real inert
no-profile child exit codes 0 and 7, reject a timeout and reject a null receipt.
They do not launch a browser, call DPAPI or provision software on the host.
The canonical gate passed again: 546 tests, strict Clippy, formatting, safety
fixtures and clean dependency audit (`target/cleanup-exit-capture-fix-check.log`).
The new helper is a fourth hash-verified package input. Native core code and
its already built harness bytes are unchanged; corrected receipt capture needs
one new guest run. Original inputs/evidence are retained for provenance, and
no commit/push/release or completed native qualification is claimed.


The live mapped input refuses file rename/replacement while the current Sandbox
holds it. Original input bytes therefore remain intact. The corrected runner
can instead be placed in the explicit `C:/NomadInput/ExitCaptureFollowup`
subdirectory with its own four-input build manifest, leaving the original root
manifest/scripts and both old receipts untouched. The runner permits only that
named follow-up location in addition to its original input root. Follow-up export
still uses the same dedicated `C:/NomadRecoveryOutput` mapping. Rerun this
subdirectory's runner, not the original root script, for corrected capture.


## Primary fixture verified (2026-10-14)

**Tested:** The corrected same-guest rerun
`fab950f9929949ccb45aaf5f079b4c79` completed in 2.44 seconds on Windows build
26100 with one exact native test passed, captured exit code 0 and empty stderr.
All eleven native assertion fields are true. The repository host verifier passed
for 23 copied files, source/harness identity, typed result fields and completion
log. Eight large-file hash-only references remain guest observations.

**Tested / preserved:** A separate unmapped host snapshot was copied and checked
again under the original package's
`VerifiedEvidence/primary-fab950f9929949ccb45aaf5f079b4c79/`.
`HOST-VERIFICATION.json` records this scoped primary pass and remaining cases.
Guest receipt SHA-256 is
`1CEED1E110CB5300870837DAD85B151438850B6784A7344FFF8B43344694403D`;
harness SHA-256 remains
`7272742C9CD467ECE24E440B1F0940C466F42CC090DF7F4155480BE94C1D0A5C`,
with source snapshot
`45BAD83CF757194B180E18BF3BAA7C7B24CED45224C48737853889F2768A3493`.
Original null-exit receipts and their partial reports remain unchanged. This
supersedes the earlier pending primary fixture status, not other qualification.

**Prepared only:** `Nomad-Recovery-Foreign.wsb` maps only the corrected four-input
harness/scripts and the two verified public-payload ciphertext blobs read-only,
plus a new dedicated writable `ForeignOutput`. Opening it in a fresh Sandbox
runs `-Phase Foreign`. Primary evidence is preserved, so the first guest may be
closed before opening it. This was the preparation state; the failed foreign
observation recorded below supersedes it. Its outcome concerns a
second disposable context; same-machine different-user refusal, independently
keyed machines and cloned key-store behavior are separate questions.

No code change or local gate rerun was needed to record this result/create the
XML fixture. The most recent canonical gate remains 546 tests, 16 ignored, strict
Clippy/safeguards and clean dependency audit; Rust 1.92 passed previously. Changes
are local/uncommitted/unpushed. Rating remains 3/5 and v1.0.9 remains on hold.

## Foreign-context refusal failed (2026-10-14)

**Tested / host-verified evidence:** Run `a38f529946ae4984a38dfa95df4cadca`
on Windows build 26100 completed the exact foreign test in 0.02 seconds with
exit code **101**, zero passed and one failed. The four exported files match
their recorded SHA-256 hashes and the corrected build/source/harness identity.
The normal success verifier rejected the run. The original receipt is unchanged;
its SHA-256 is
`4682EE196405F430784F837E0B222F2EBF77C39982FD2753E4AF130465242D28`.

**Tested:** `nested_blob_refused: true`; `machine_blob_refused: false`.
The production nested-codec sample could not be opened in the second context;
the separate machine-only public-payload sample could. The conjunction required
by `qualify_foreign_context` therefore failed at the captured source line 354.
The refusal of the nested blob does not identify its exact failing DPAPI layer,
prove all journal records safe, or qualify other users/computers.

**Inference / unresolved:** Reused or cloned machine key material is consistent
with this observation. Neither key-store identity nor the exact cause was
instrumented. A fresh Sandbox is not demonstrated to be an independently keyed
computer. Microsoft's [DPAPI contract](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
describes machine-scope sharing and user roaming exceptions; it does not establish
unique keys for each Sandbox instance. Do not inspect/export private keys to
investigate this public-payload fixture, and do not weaken its refusal assertion.

**Preserved:** An unmapped host snapshot under the original package's
`VerifiedEvidence/foreign-a38f529946ae4984a38dfa95df4cadca/` retains the receipt,
four evidence files, build manifest and `HOST-PARTIAL-VERIFICATION.json`.
Hash-only harness observations remain distinct from copied evidence. The primary
pass remains scoped and valid; this foreign run is an evidence-verified failure.
No further identical Sandbox rerun is needed to count this result.

**Next qualification:** Use explicitly authorized disposable environments with
independent Windows initialization and a separately created user context. A
cloned image or new Sandbox session cannot substitute for that setup. The current
runner's Sandbox-only guards must not be bypassed to run on personal host stores.
Plan a separately guarded fixture if those environments become available.
Production browser/watcher, Windows 10, physical interruption and query-denial
cases remain pending. Rating stays 3/5; v1.0.9 stays on hold. No production/test
code or verifier acceptance rule changed for this evidence record.


## Later real-browser integration observation (2026-10-14)

The separate real Helium 0.19.2.1 Windows 11 interrupted-worker/normal-close/
direct-relaunch workflow now passed and all five exported evidence files were
host-verified and preserved. [Its exact scope and provenance](RECOVERY-BROWSER-INTEGRATION.md#helium-interrupted-worker-recovery-verified-2026-10-14)
remain distinct from this lib-test fixture and the failed second-Sandbox refusal
observation. Other browser/protocol/independent-context/physical-interruption/
Windows 10/query-denial cases remain pending; no earlier receipt/assertion was
modified. This narrows one production-path gap without clearing the release hold.
