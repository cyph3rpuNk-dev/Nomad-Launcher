# Windows-created cleanup metadata qualification

## Result and source state (2026-10-15)

**Tested:** Windows 11 Sandbox (`10.0.26100.0`) created two Recent links through
the native Shell API and two custom noncritical WER reports. Original bytes
were replayed through Nomad's real cleanup functions under fake-host roots.
The baseline exposed a Recent-link coverage defect; a narrow parser correction
then passed, including a final build after Clippy refactoring. WER replay and
all unrelated-sentinel preservation assertions passed in every run.

Baseline commit: `fcd3c010def7eecbdc9cb1059976de6c1f13d5eb`, on the new local
branch `codex/windows-cleanup-metadata`. The baseline production Shell Link
parser hash matched that commit's Git blob. The correction depends on the
uncommitted-at-collection `core/src/shell_link.rs` change and its new regression
and guarded replay tests, included in this local correction checkpoint. No push, remote CI or release is claimed.

| Run | Native test result | Owned Recent copy | Attributed WER copies | Unrelated data |
|---|---|---|---|---|
| Frozen baseline | Exit 101, qualification failed | Preserved; target not accepted | Four removed | Preserved |
| Initial correction | Exit 0 | Removed after corroboration | Four removed | Preserved |
| Final refactored build | Exit 0 | Removed after corroboration | Four removed | Preserved, including repeated cleanup |

The four WER copies replay the same captured owned report in fake user/machine
queue/archive layouts. They are not four independently captured crash variants.
No original OS Recent link or WER queue directory was passed to cleanup.
A separate final guest inspection also matched all four original OS records and
their capture copies by hash, with zero active non-loopback interfaces/default
routes. Its selected record is preserved beside the final host verification.

## Recent-link defect and narrow correction

**Verified in code:** `core/src/shell_link.rs:348` previously allowed the low
StringData/IDList flags and `EnableTargetMetadata`, but refused
`DisableKnownFolderTracking` (`0x00200000`). Both Shell-generated links carried
`0x0020009B`, so the baseline preserved the owned link before native target
corroboration. This confirms a real coverage gap in the previously broadened
parser; the earlier WScript.Shell tests did not establish this Shell-API variant.

**Documented by Microsoft:** [LinkFlags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/ae350202-3ba9-4790-9e9e-98935f4ee5af)
defines this flag as ignoring SpecialFolder/KnownFolder translation records.
**Verified in code:** the correction permits that one bit, retains the full
owned-target/IDList/RAWPATH/relative-path agreement checks, and refuses the bit
combined with either folder-translation record. It does not treat ignored
anchors as ownership evidence. Unknown flags, environment/installer overrides,
missing/foreign targets and aliases retain their existing refusal paths.

**Tested:** `disabled_folder_tracking_does_not_relax_owned_target_or_override_checks`
accepts an existing owned target and refuses foreign/missing targets and override
flags. The existing Windows known-folder translation test now includes a native
link whose translation records conflict with the tracking-disable flag; it is
preserved. The final full gate includes the retained malformed/conflicting/native
metadata regressions. No target file or executable is deleted by link cleanup.

## Capture and replay boundaries

**Tested preparation:** a fresh Sandbox configuration set Networking, clipboard,
audio/video and printer sharing to Disable; only dedicated read-only Input and
writable Output folders were mapped. The completed Waterfox guest was first
rechecked idle/restored and retired because this installation allows one Sandbox
session. Native capture verified zero up non-loopback interfaces and zero default
routes before WER calls. The guest remained offline during replay.

**Documented / tested Shell API:**
[SHAddToRecentDocs](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shaddtorecentdocs)
was called with `SHARD_PATHW` for two existing inert `.txt` files: one under the
owned Portable directory and one outside it. This creates Windows Recent records
without opening those documents. Executable paths are filtered by Windows, so
text documents were intentional. These are actual Shell-serialized links, not
manually assembled bytes or a recorded Explorer/browser navigation session.

**Documented / tested WER API:**
[WerReportCreate](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-werreportcreate)
created noncritical custom events with public fixture parameters and controlled
application paths. [WerReportSubmit](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-werreportsubmit)
used consent NotAsked and flags `324`: QUEUE (4), NO_CLOSE_UI (64), NO_ARCHIVE
(256). Both calls returned HRESULT 0 and result Queued (1); handles closed with
HRESULT 0. Consent Approved, dump/file registration, application crashes and
browser execution were not requested. Queueing can permit later reporting in a
networked environment; the disabled Sandbox network and its zero-interface/route
observations are part of this fixture, not a general WER suppression feature.

The original reports were found in the guest ProgramData ReportQueue, at 35,186
and 36,460 bytes, UTF-16LE with BOM. Both had the supplied exact AppPath and public
fixture token. Capture retained bytes unchanged; no AppPath rebinding, redaction
or encoding conversion was performed. The queue's generated folder names did
not match the first collector's overly specific prefix, so its partial receipt
remains unchanged. A bounded read-only diagnostic and separately frozen additive
collector copied those existing reports; no WER or Shell creation was rerun.

**Verified in code / tested replay:** the explicit ignored test
`cleanup::metadata_sandbox_tests::qualify_windows_metadata` checks the guest,
fixed root, tokens, session marker, offline declaration, capture schema and
file sizes/hashes before creating each fresh fake-host root. It uses only
`cleanup::scrub_fixture`, never `scrub_host_traces` with real environment roots.
Recent folder depth is retained so stored relative targets need no modification.
Each root includes owned/foreign metadata and public inert attachment/standalone
sentinels; the `.dmp` sentinel is text, not a captured memory dump. Original
capture bytes and the ownership marker remain unchanged after both attempts.
These guards are operational checks, not protection against a malicious host.

## Commands, preservation and verification

The agent used Windows Sandbox CLI as the disposable ExistingLogin user. The
local ignored package is
`target/windows-metadata-cb664947fd5b49b589e1a12eab68550a`.
Its capture/packaging helpers are local evidence artifacts; they are not shipped
launcher features or part of the routine gate. Sequence:

1. `Capture-Windows-Metadata.ps1` created the native records and partial receipt.
2. `Supplement/Collect-Queued-Metadata.ps1` collected the already queued reports.
3. `Replay/Baseline/Run-Windows-Metadata-Replay.ps1` reproduced the failure.
4. Separate Corrected and Final wrappers each selected only
   `--exact cleanup::metadata_sandbox_tests::qualify_windows_metadata --ignored --nocapture --test-threads=1`.
   No other ignored/live test was selected. Each run used a fresh fixture root.
5. `Verify-Metadata-Evidence.py` and `Verify-Metadata-Final-Evidence.py` verified
   selected schemas, actual integer exits/booleans, digests, manifest/session
   linkage, native-result serialization hashes, stable source snapshots and the
   expected baseline/follow-up source delta. Mutated exit/linkage/string-boolean
   fixtures were refused. No raw metadata was transferred or replayed on host.

| Identity | SHA256 |
|---|---|
| Original capture manifest | `622B9138B120868F9BA6F2B8A4E36D2E494B48444E3EB50978D0EFD498B90C8E` |
| Four-file qualification input | `EA1593C7587C3C0958F538BAB16E9329C85F42200CD21EBA295450BEAAAF3141` |
| Baseline harness | `70142477EE649F27679C18FD35435C22E50329871115E878800B5D8464DB17A3` |
| Final harness | `0E013641F7D1673E69E69BFBAE20496455AB029A8628C5992BB03F84B2A3E80C` |
| Failing baseline receipt | `D2E70AA927820E2EEC7AA128A6184DD4E1639AE5317F2DCE0B8AF52CA179CF5E` |
| Passing final receipt | `99C4BAA6DE56F4A0500CE7BD2ACF0358E58A4540FEE14C36D9B34023B6E90CE4` |

Unmapped `VerifiedEvidence/metadata-233158794ae8457ebb067cad93965c14` and
`metadata-final-233158794ae8457ebb067cad93965c14` snapshots retain byte-identical
selected exports, frozen manifests/helpers, source inventory and scoped
HOST-VERIFICATION.json records. The final snapshot separately retains the three
reviewed Rust source files with hashes matching its 194-file source inventory.
Original report/link bytes and native stdout/stderr remain inside the offline
guest only. Binary references are hashes, not independent host reads of original
guest modules. Host verification checks exported assertions, not a compromised
guest or an independent replay of the original Windows stores.

A mistaken use of the production GUI-launcher PE guard initially refused the
console test binary. Execution waited for a metadata-only console-harness guard:
only the expected subsystem changed from 2 to 3 in a separate local checker;
architecture, import/static-CRT, CFG and System32 metadata checks were retained.
The production guard was not changed. The failing attempt remains recorded.

## Final validation and limits

**Tested:** `pwsh -NoProfile -File scripts/check.ps1` passed: 551 Rust tests,
17 ignored, formatting, strict Clippy, safety fixtures and structured dependency
audit with the existing RSA exception. The explicit guest qualification is the
new ignored test; the normal gate does not create native Recent/WER records.
`cargo +1.92 check --workspace --all-targets --locked --target
x86_64-pc-windows-msvc --target-dir target/msrv-1.92` passed for the final Rust
source. Logs: `target/windows-metadata-final-check.log` and
`target/windows-metadata-final-msrv.log`. Earlier Clippy failures were resolved
by extracting validation/output helpers; lint policy was not weakened. The final
refactored binary was replayed and verified after those changes.

**Not tested:** natural browser-crash Report.wer variants, genuine user-store
WER variants, live WER-service file races/uploads, actual Explorer/browser
navigation, Windows 10, physical interruption and independent-machine recovery.
A custom API report is genuine Windows serialization but does not close those
cases. Broader metadata, recovery and revocation-data gaps, rating 3/5 and the
release hold remain. This checkpoint is committed locally on the branch above; it is not pushed.
