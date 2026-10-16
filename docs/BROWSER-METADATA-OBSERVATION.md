# Offline browser metadata capture observation

## Result and source (2026-10-16)

**Tested: inconclusive for new cleanup coverage.** An offline Windows 11 Sandbox
ran an authenticated Helium 0.19.2.1 bundle directly with a new guest-only profile
and public loopback page. The page rendered and requested the expected beacon.
Neither a command-line debug-URL request nor a subsequent Windows breakpoint
API call produced an observed exit of the original browser process or a matching
Report.wer in the four conventional queue/archive stores within the capture
windows. No report bytes were available for a new cleanup replay. This is not a
cleanup failure finding and does not close natural-crash/navigation coverage.

Production source was clean at `7df460048f55ac76bfa5cfc599aec82d0e8da9ea`.
The capture helpers and observations are ignored local evidence artifacts, not
launcher features or routine gate tests. Production Rust, configuration defaults,
registry behavior, endpoints and cleanup functions were not changed. The
[previous Windows Shell/custom-WER qualification](WINDOWS-METADATA-QUALIFICATION.md)
continues to cover its original captured forms.

| Observation | Result | Limit |
|---|---|---|
| Public browser navigation | Expected HTTP page and script beacon received from the launched guest session. | Direct guest browser launch, not a retail Nomad launch or Explorer interaction. |
| Command-line crash URL | Request sent; original process did not exit within 25 seconds; no matching report captured in the next 20 seconds. | A request is not evidence that the internal crash handler executed. |
| Native breakpoint follow-up | DebugBreakProcess returned success after retained-handle PID/image checks. Original process still had no observed exit; nine owned browser processes remained in the final snapshot. | API success is not proof of unhandled exception, process termination or WER creation. |
| WER report capture | Zero matching reports captured in user/machine ReportQueue/ReportArchive; no metadata read refusals reported by either capture loop. | Does not cover other stores, later activity, WER policy, browser crash stores or every possible report schema. |
| Process/event diagnostic | Snapshot had no WerFault/WerFaultSecure process and no selected matching event rows. The event query returned System.Exception. | No successful event-log query or complete process/reporting history is claimed. |
| Recent filename observation | No token-named .lnk found. | Filename filtering is not full target resolution or proof that no Recent/Jump List data was created. |

## Isolation and inputs

**Tested preparation:** Sandbox networking, vGPU, clipboard, audio/video and
printer sharing were disabled. Only a dedicated read-only Input folder and a
writable selected-output folder were mapped. Both fault helpers verified zero
active non-loopback interfaces and default routes before any browser/fault call.
There was no host browser launch, personal profile import, host cleanup, custom
WER report submission, dump-registration call or WER policy/consent modification.
Automatic browser/OS crash artifacts were not inspected as memory or exported.
Raw report/profile/dump content, if any, stayed inside the discarded guest.

The reused official x64 archive was checked against the saved immutable-release
asset digest before host copying and again before guest extraction:

- Archive SHA256: `8623C04201A0A45A97920C7ACDAA3A9F022260C66D6DFE78E7DCB323D4D2D89C`.
- Guest chrome.exe SHA256: `A7EFCB9F8C830AD2C6BD059DA38774B2E83411196E696602D08D4B6A4E4BE00D`.
- Guest chrome.dll SHA256: `36B703C1B1B563558181F3AA42BDE16D21EC6A0B5E0E658989D59D77B2627B7D`.

Archive entries, links, expanded sizes and extraction paths were checked before
extracting into a fresh owned guest root. The browser image/module identities
are guest assertions linked to the verified archive, not independent host reads
of the guest's mapped module. The direct browser arguments included the portable
Data path and sync/background/component/crash-reporter blocking flags. This was
not the complete retail hardening/profile/watcher path; service setup remained
untouched. No new upstream browser download or component service request occurred.

## Fault and capture boundary

The initial helper retained the original Process handle while serving the
loopback page, sent `chrome://inducebrowsercrashforrealz/` through a second browser
invocation, and waited boundedly for exit/metadata. The original no-exit result
was retained unchanged. The separate follow-up pinned that observation and its
own script hashes, rechecked the owned main PID, exact image/profile command and
archive-derived image hash, then checked the retained handle's PID/image through
native APIs before signalling it once.

Microsoft documents [DebugBreakProcess](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-debugbreakprocess)
as causing a breakpoint exception; handling/termination depends on the target's
exception/debugger behavior. This record asserts only the observed successful
API return and absence of an observed process exit/report in the bounded window.
It does not diagnose a handler, WER policy or root cause. No unrelated process,
Explorer instance or reporting service was terminated. No personal-host process
was faulted. The tests did not deliberately trigger a spontaneous application
bug, and their attempted faults must not be relabelled as natural crashes.

Capture reads were limited to ordinary bounded Report.wer files in the intended
guest stores, requiring one exact matching AppPath before copying. Attachments
were not read for content. Because no candidate was captured, production cleanup
was never invoked against either original stores or replay copies in this run.
An authored report, rewritten AppPath or altered Windows policy was not introduced
to manufacture a new pass.

## Commands and selected evidence

Local package: `target/browser-crash-metadata-f32b55a2b6fe48e58fffa6305c2ed18a`.
Campaign: `4fbde68df6cb47238876325c42cb0e07`.
Owned Sandbox: `4b125443-e827-42f8-b9fd-8e7358e58111`.

1. `wsb start --config <frozen offline XML> --raw`, then `wsb connect --id <id>`.
   The first ExistingLogin readiness call failed before connection; the later
   call succeeded. No alternate user or System context was used.
2. The configured guest logon ran `C:\NomadInput\Run-Browser-Metadata.ps1`.
3. A separately frozen read-only progress helper confirmed the original capture
   was complete and its owned browser remained running.
4. `wsb exec --id <id> --run-as ExistingLogin --command 'powershell.exe -NoProfile
   -ExecutionPolicy Bypass -File C:\NomadInput\Fault2\Run-Fault.ps1' --raw`.
5. A separately frozen process/event diagnostic exported selected counts only.
6. Host `Verify-Selected-Evidence.py` checked typed schemas, explicit non-success
   boundaries, campaign/input/observation linkage, archive identity and unchanged
   production-source hashes against Git blobs. Six mutated type/outcome/linkage/
   exit cases were refused. Bounded selected files were copied byte-for-byte to
   unmapped VerifiedEvidence; the archive is a hash-only reference there.
7. After every preserved digest was rechecked, `wsb stop --id <exact id> --raw`
   returned zero. Final inventory showed the owned guest absent. The original
   verification report retains its pre-discard pending status; a separate disposal
   record links it without rewriting it.

Desktop control was unavailable after initialization/reset/retry. The helpers
used the supported Sandbox CLI for controlled process operations, not terminal
UI automation. No screenshot or visual crash-dialog observation is claimed.

| Record | SHA256 |
|---|---|
| Original observation | `206E1B107FBE6284211D8CB6FCBCB04A3BAF638FE2D51066DCE1817164C7647E` |
| Breakpoint follow-up | `99678649C3E5256E05B41C5DCB889B34CEEEA396BBCAEB1AFBD9773D45E27197` |
| Host selected verification | `408745E1AA77E9E4C0C78A4E1EEFFCA6A1E6D708304D1384E7DE7BC45DCD8076` |
| Separate disposal verification | `B1FB88D9BB94034E5087EEB87D69861D52C27A68B325D1EF7D5772339BC49DA9` |

Sixteen selected/helper/provenance files plus verification and disposal reports
are preserved outside guest-writable mappings. These verify the selected guest
assertions and provenance, not a hostile guest, complete telemetry or cleanup
coverage. The native API follow-up and its failure to establish a crash/report
remain explicit; no original receipt was changed to imply success.

## Validation and remaining work

PowerShell syntax and actual personal-host refusal checks passed for both active
capture helpers. Host selected-evidence verification, six negative verifier cases,
copy preservation and exact-ID disposal passed. New tracked changes are evidence
documentation only: UTF-8/LF, local links/anchors and whitespace were checked.
No new Rust, core test, dump collection or production regression was added merely
because no report was obtained. The full canonical 558-pass/18-ignored, Rust 1.92
and six release PE-guard results at `f560926` remain the latest code validation;
no redundant full gate, remote CI, push or release pass is claimed here.

Natural browser-crash Report.wer capture/replay, real Explorer navigation,
genuine user-store variants and Windows 10 remain unqualified. Resume with a
supported reproducible guest scenario and original bounded bytes; otherwise make
an explicit release-scope decision for that remaining coverage gap. Do not repeat
the completed custom API report case and call it a natural-crash result. CRLSet
has its separate v1.0.9 owner acceptance; independent VM isolation is separately
deferred and unverified. Rating 3/5 and the overall release hold remain.
