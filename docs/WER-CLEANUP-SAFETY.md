# WER cleanup safety

## Scope and data retention

Post-exit cleanup scans `Microsoft\Windows\WER\ReportQueue` and
`ReportArchive` below `%LOCALAPPDATA%` for the current user and `%ProgramData%`
for machine-wide reports. It does not enumerate other users' profiles, WER
`Temp`, standalone `%LOCALAPPDATA%\CrashDumps`, custom dump locations, browser
crash-reporting stores, or Windows kernel dumps. Missing stores are not created.

Before any report deletion, the portable instance marker and existing browser
image must validate. Folder names, browser basenames, PID suffixes and
`AppName` are not attribution. Bounded valid UTF-8 (optional BOM) or UTF-16LE
with BOM text must contain exactly one absolute `AppPath` identifying that
exact existing browser image. Duplicate keys, embedded NULs, invalid encoding,
missing/relative paths and unknown attribution preserve the report. This is a
conservative text-field reader, not a full Report.wer schema validator.

The AppPath must be lexically inside the owned portable folder before filesystem
lookups. Parent components, network/device paths and reparse points are refused.
Windows drive-absolute and verbatim-drive paths are accepted; ASCII case
variants are compared using Windows case-insensitive path semantics before
canonicalization confirms the image. Different executables even within the
same portable folder are not this browser image.

Attributed report attachments are diagnostic data too. Successful cleanup
removes ordinary attachments, including `.dmp`/`.hdmp` files within that report,
then `Report.wer` and the empty report directory. Standalone dumps remain
because their executable basename does not distinguish an installed browser
from a portable one. Dump contents can include process memory and private data;
page content and account material are possible examples, not findings from any
inspected user dump ([Microsoft minidump types](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_type)).
The older blanket statement that raw dumps are preserved omitted attributed
report attachments; the public docs now distinguish these two cases.

## Safe deletion and limits

Only flat report directories with at most 256 ordinary files, including one
Report.wer filename, are supported. Nested directories, linked entries,
unsupported file types, oversized metadata and failures of access preflight
preserve the report. Metadata reads are limited to 64 KiB; attachment contents are not read
or parsed. File sizes are not deletion quotas.

All files are opened before mutation. On Windows their handles deny concurrent
read/write sharing while permitting the cleanup's own deletion. Existing
readers or writers, even those allowing delete sharing, therefore prevent
cleanup of the entire report. Attribution is reread through the held metadata
handle before deletion. Attachments are deleted in deterministic order with
their guards held, each handle is closed after unlinking, and Report.wer is
removed last. An attachment-deletion failure preserves attribution so a later
completed browser session can retry. There is no recursive deletion: new entries
must leave the final directory nonempty, causing remove_dir to fail.

This is best effort, not an atomic directory transaction. Some attachments may
be removed before a later attachment fails. A directory-removal failure or a
new entry can leave an unattributed remainder after metadata deletion. Metadata
checks/handles do not eliminate hostile path replacement races, and Windows
remains trusted. The file-count limit is per report, not a total cleanup-time
or store-size budget. No privileges are requested, no service is stopped, and
no WER consent, policy, registry value or upload setting is changed.

Cleanup cannot undo reports already uploaded or stop a report from being sent
before browser exit. WER is independent Windows reporting infrastructure
([Microsoft WER overview](https://learn.microsoft.com/en-us/windows/win32/wer/windows-error-reporting)).
Default-on [missed-cleanup recovery](MISSED-CLEANUP-RECOVERY.md) can revisit
recorded sessions under the original Windows context/path and a strict idle
check. It uses this same attributed scanner and preserves pending intent on
access/deletion failures. An ordinary completed session also revisits reports.
Unsupported metadata is still preserved; completion means a scoped attempt,
not that every report was deleted. Unavailable/moved images leave traces.

## Evidence and regression fixtures

The previous implementation scanned only ProgramData and canonicalized AppPath
without first rejecting aliases. The revised `core/src/cleanup.rs` covers both
conventional roots and refuses aliased images before deletion. The `file`
project's Windows error-report format definition independently records both
conventional locations ([upstream format definition](https://github.com/file/file/blob/master/magic/Magdir/windows));
Microsoft documents machine-wide WER storage and queue behavior
([WER report troubleshooting](https://learn.microsoft.com/en-us/windows-server/failover-clustering/troubleshooting-using-wer-reports)).
These references do not prove that every Windows build stores every crash here.

Local tests use authored synthetic report-shaped UTF-8/UTF-16 metadata, inert
executables and dump placeholders under explicitly owned temporary fake-host
roots. They are not captured real Windows reports. New regressions cover:

- user/machine queues and archives, dump/XML attachments and misleading names;
- unrelated images, other owned executables, missing images, duplicate/NUL/invalid
  metadata, parent paths and image/root junctions;
- linked/nested/over-budget reports and the exact 256-file boundary;
- Windows case and verbatim drive paths, refused network/device paths;
- active reader handles preserving the whole report, then successful retry;
- a real Windows delete-sharing failure after an earlier attachment was removed,
  preserving Report.wer and succeeding after the blocking handle closes.

No real host WER report or crash dump is read, deleted, generated or uploaded by
these fixtures. They do not launch/crash a browser, invoke WER APIs or change
persistent user/system configuration. Local Windows tests were run on Windows
11 build 26200. Native file-share tests do not establish real WER activity or
compatibility with Windows 10's serialized report variants.

Natural Windows 10/11 browser-crash Report.wer captures and live browser-crash
cleanup remain unverified. A later [Windows 11 custom API-report replay](WINDOWS-METADATA-QUALIFICATION.md)
qualifies that narrower OS-serialized metadata case, not natural crash forms. For further qualification, use a disposable Sandbox/VM with an inert
owned instance and unrelated-report sentinels. Retain the original encoding of
captured metadata and label any AppPath rebinding/redactions; replay under owned
fake-host roots before considering live deletion. Never test against real host
reports or share actual memory dumps. OS uploads, nonstandard/custom stores and
native crash recovery need separate disposable validation. Microsoft documents configurable standalone
LocalDumps storage independently of other WER behavior
([user-mode dumps](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps));
Nomad does not change those settings.

## Windows-generated custom report replay (2026-10-15)

**Tested in an offline Windows 11 Sandbox:** native WER APIs queued two inert
noncritical custom reports with controlled owned/foreign application paths.
Both original ProgramData reports were UTF-16LE with BOM and were retained
without rebinding, redaction or encoding conversion. Copies were replayed through
the production scanner under fake user/machine queue/archive roots. Attributed
copies/attachments were removed; foreign reports/attachments, a standalone inert
sentinel and the source captures were preserved, including repeated cleanup.
The existing WER production logic needed no correction for this captured form.

No browser was crashed or launched, memory dump requested, original live WER
store passed to cleanup or raw report content exported. Queue-only submission
and disabled networking were fixture controls, not a new Nomad WER policy.
Four replay placements are not four captured OS variants. [Full provenance,
commands and limitations](WINDOWS-METADATA-QUALIFICATION.md) retain the distinction
from natural crashes, live service races and Windows 10. The full final gate
passed 551 Rust tests (17 ignored); Rust 1.92 passed. Work is local/uncommitted.
