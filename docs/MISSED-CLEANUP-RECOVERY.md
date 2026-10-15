# Missed-cleanup recovery

This follow-up was validated locally on `codex/privacy-security-followup`,
based on `ca4633d676ddac433eff4248950de8242d90405a`, alongside the Recent/WER,
required-settings, protocol-freshness and Ungoogled component changes. See the
audit checkpoint and Git history for local delivery. No push, remote CI, release
or installed-launcher change is claimed here.

## Behavior and controls

**Verified in code:** `core/src/cleanup_recovery.rs` records intent for attributed
host cleanup before browser process creation. Normal and fallback GUI launch
paths arm it after required preparation; `core/src/lib.rs` retries records after
acquiring the per-folder install lock and before update/runtime work. Direct
and registered link/file launches use the same hook. A retry never downloads,
updates, launches or terminates software, or repairs the registry. Headless
update-only checks do not arm or replay browser sessions.

`[hardening] recover_missed_cleanup = true` is the default, including older
configs omitting the key. It is independent of `[hardening] enabled`. False
stops new recording, startup replay and normal retirement of pending records;
ordinary attributed post-exit cleanup remains. Existing records are preserved.
Manual removal of `Nomad/cleanup-pending/` while all Nomad/browser processes are
closed discards retry intent; it does not clear host traces.

**Verified in code:** Only the existing individually attributed Recent shortcut
and current-user/ProgramData WER scanners are retried. Ownership requires a
matching browser-family `Nomad/instance.toml`, existing ordinary browser image,
canonical original root/image paths and no filesystem links/reparse points.
Missing images/markers, moved folders, wrong browser/schema, malformed/oversized
records, unreadable ciphertext or an unavailable binding cannot authorize cleanup.
There is no search for moved images and no plaintext fallback. Records do not
attest executable bytes or an instance-generation UUID; drive writers and a
compromised host remain outside the trust model.

Recovery never replays thumbnail/icon-cache clearing, Prefetch clearing,
registry repair, browser-profile changes or shared host-directory deletion.
[Recent shortcut](RECENT-SHORTCUT-SAFETY.md) and [WER](WER-CLEANUP-SAFETY.md)
parsing/deletion limits remain unchanged.

## Binding and data inventory

**Verified in code:** The serialized body contains only schema 1, browser ID,
canonical portable root and canonical existing browser image. `NativeBinding`
first calls user-scope `CryptProtectData`, then wraps the result with machine-
scope protection. Reading unwraps machine then user. Both operations forbid UI,
use null optional entropy/description/prompt pointers and release returned
Windows allocations. Nomad does not request DPAPI audit flags or elevation.
The operating system and its cryptographic key handling remain trusted.

**Documented upstream / inference:** Microsoft documents ordinary user-scope
protection, a roaming-profile exception, machine-scope protection shared by
users on that computer and a tamper-detection MAC. The nested design is intended
to require both the original computer and user context, including where user
keys roam. This is API-contract reasoning, not a measured native guarantee.
See [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
and [CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata).
It does not protect against key theft, same-context malware, cloned/restored
Windows key stores or a hostile administrator.

| Data | Location / retention | Exposure and limits |
|---|---|---|
| Protected schema/browser/original paths | `Nomad/cleanup-pending/pending-<16 hex digits>.bin`; until a completed scoped attempt or manual removal, with no age expiry | Version prefix, filename and filesystem times remain observable; the opaque DPAPI blob may carry OS format/key metadata. Intended user/machine binding is not volume encryption. |
| Coordination file | `Nomad/cleanup.lock`, plus existing `Nomad/install.lock`; files persist after handles/OS locks release | Empty-file presence does not prove a live worker or successful cleanup. |
| Recovery warnings/completion count and existing cleanup path logs | Existing `Nomad/nomad.log`, under its existing retention behavior | Errors/cleanup can identify paths; ciphertext is not logged. No URL/history/credential record, new telemetry client, endpoint or per-link counter is added. |
| Attributed host artifacts | Original user's Recent and Local AppData/ProgramData WER roots | Existing scanners may delete individual shortcuts and flat attributed report attachments, including dumps. Shared profiles, standalone dumps, other users' stores and unsupported metadata remain. |

No host-directory list, raw SID, timestamp, PID or forwarded target is serialized
in the body. Filenames use an opaque collision-resistant token generated with
Rust's randomized hasher and process-local sequence; it is not an authentication
secret. Nomad has no new HTTP request here. OS DPAPI/key-store/domain behavior
has not been instrumented; no claim of zero OS side effects/network is made.
Profile encryption and plaintext logs/configuration are unchanged.

**Verified in code:** Each record is capped at 64 KiB. A complete directory listing
must stay within 32 recognized records and 64 total entries before replay starts.
Duplicate current-context root/image intent is reused. Foreign/unreadable entries
are not evicted; accumulated records can prevent future recording. At exact
directory capacity, an existing current-context record can be reused but a new
record is refused before it could make later replay exceed the listing budget. New files use
exclusive creation and `sync_all` before spawn. Partial write failure removes
only the newly created file; recording failure warns and permits launch.
Syncing a file is not proof of durable directory metadata or storage-controller
behavior during power loss. Records can survive a failed spawn; their presence
is intent, not proof that a browser ran.

## Quiescence, locks and retirement

**Verified in code:** `core/src/cleanup_process.rs` uses a Windows process snapshot,
case-insensitive ordinal basename comparison and queried Unicode image paths.
A matching image inside the original lexical root means Running. A same-name
image outside that prefix, a denied/failed query or an incomplete snapshot means
Unknown. Only a completed enumeration with no relevant/ambiguous candidate is
Idle; vanished PIDs can be skipped. Verbatim prefixes/slashes are normalized;
foreign short/mapped/UNC aliases are not resolved to assert they are unrelated.
Microsoft documents the enumeration termination contract in
[Process32NextW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32nextw).
Consequently a separately installed running Chrome can postpone Chromium/Helium
cleanup. This conservative availability trade-off also applies to ordinary
post-exit cleanup, independently of the recovery option.

Recovery acquires `Nomad/cleanup.lock` nonblocking while holding `install.lock`;
post-exit workers hold the coordinator lock and acquire `install.lock` nonblocking
before deletion. Nested executable paths select the outer bundle folder, so both
paths lock the same portable parent. Contention preserves pending intent; these
nonblocking operations avoid deadlock. The existing advisory PID/tree wait is
not deletion authority. New direct/protocol Nomad spawns are serialized against
the final idle check and deletion.

**Inference / residual risk:** This does not freeze Windows. A non-Nomad/direct
browser start or hostile filesystem writer can race the final snapshot/check.
Helpers with different executable basenames are not all tracked. A duplicate
watcher can exit just before the coordinator's last idle check observes activity;
remaining intent then requires another launcher attempt. There is no complete
history of process/download activity or promise that cleanup finishes at exit.

**Verified in code:** A record is retired only after a completed scoped scanner
attempt and a bounded reread matching the original record bytes. Access/listing,
ownership or attributable deletion failures retain it. Partially removed WER
attachments can therefore be retried after their handles close. Unsupported or
unattributed metadata is preserved by design and can coexist with a completed
attempt; some unreadable/over-budget metadata keeps intent pending indefinitely.
Retirement does not mean trace-free Windows. WER uploads are not undone. The
32-record budget does not impose a total host-store scan-time budget; file-count
limits remain per report. Concurrent replacement after comparisons remains a
structural risk on a hostile writable drive.

Drive removal cannot clean the original host while the folder is unavailable.
Return to the original machine/user/path with the required image/marker to make
another attempt. Old launches without records, lost storage writes, lost Windows
keys and manually deleted journal records cannot be reconstructed. Foreign
records carried to a new host do not authorize cleanup on that host.

## Validation and remaining qualification

**Tested:** On Windows 11 build 26200:

```powershell
pwsh -NoProfile -File scripts/check.ps1
cargo +1.92 check --workspace --all-targets --locked --target x86_64-pc-windows-msvc --target-dir target/msrv-1.92
```

The canonical gate passed formatting, strict Clippy, 531 core + 12 integration +
two metadata tests (545 total), safeguard fixtures and clean dependency audit.
Four native registry and eight live-upstream/download tests remain ignored.
Rust 1.92 workspace/all-target compilation passed. Logs are
`target/cleanup-recovery-check.log` and `target/cleanup-recovery-msrv.log`.
Cargo.lock is unchanged. No new dependencies or network endpoints were added.

Twenty-one new regressions cover simulated wrong computer/user bindings, schema/
browser/root/image mismatches, absent ownership, copied-to-moved-folder records,
active/unknown process decisions, coordinator contention, bounded malformed
records/directories and exact capacity, no plaintext fallback, changed/locked record retirement,
linked journal/image paths, deduplication, independent opt-out/defaults, lexical
process boundaries and the nested-image install lock. One integration fixture
uses authored WER-shaped metadata and an inert dump under fake host roots: an
actual Windows sharing handle blocks deletion and retains intent; closing it
allows attributed cleanup/retirement while a standalone dump sentinel remains.

**Not tested:** Binding tests inject a fake codec; they do not execute DPAPI or
prove encryption, native machine/user separation, key retention or tamper
handling. Process-state tests inject decisions or compare literal paths; they do
not test the new native snapshot/query pipeline against a running browser.
No real browser, watcher, crash, power interruption, drive removal, WER upload,
user profile or host cleanup was exercised for this change. Windows 10 and real
Explorer/WER captures remain untested. CI and release validation remain separate.

The next qualification should use disposable Windows 10/11 VMs with inert owned
instances and explicit fake-host roots. Check native protection round trips,
other-user/other-machine refusal, restart retention and malformed blobs; capture
process/query-denial results; simulate interrupted workers and unavailable drives,
then confirm preservation before any real-session deletion. Never use personal
host stores or sensitive memory dumps as regression fixtures. This scoped local
mitigation does not raise the audit rating from 3/5 or clear the v1.0.9 hold.


## Disposable native qualification prepared (2026-10-14)

The separate [Sandbox qualification runbook](CLEANUP-RECOVERY-QUALIFICATION.md)
now describes an ignored native lib-test harness, offline package preparation,
a dedicated mapped evidence directory and read-only host verification. Preparing
or compiling this package is not a native result. The canonical gate keeps all
four guest-only tests ignored and runs only inert metadata/token regressions.
The earlier 545-test recovery result above remains historical; the preparation
follow-up adds one token regression and evidence/gate-wiring fixtures. Native
DPAPI/process/interrupted-worker results remain pending until the guest executes
and the host validates its exported files.


The corrected Windows 11 primary fixture now passed with captured exit code 0,
and the host independently verified/preserved all 23 exported files and eleven
native assertion fields. This qualifies the same-context codec, inert process/
lock integration and attributed fake-host replay for that fixture. It does not
qualify different users/machines, physical interruptions, production browsers/
watchers or Windows 10. [Exact verified provenance and next-context preparation](CLEANUP-RECOVERY-QUALIFICATION.md#primary-fixture-verified-2026-10-14)
supersede earlier pending primary status without widening the tested scope.

## Second-Sandbox binding observation (2026-10-14)

**Tested / host-verified:** The foreign-context refusal test failed with exit
101. All four copied evidence files and their source/harness provenance were
verified and preserved. The nested production-codec sample was refused; the
machine-only comparison sample decrypted. This does not demonstrate replay of
a production recovery record in another context. It does invalidate treating
fresh Sandbox instances as measured independent machine-key contexts. Shared/
cloned key material is a possible explanation, not an established root cause.

The failure remains recorded; no assertion or production codec was relaxed.
Different-user and independently initialized machine qualification remain
pending. [The failed observation and preserved provenance](CLEANUP-RECOVERY-QUALIFICATION.md#foreign-context-refusal-failed-2026-10-14)
supersede the foreign preparation status. The primary fixture pass remains
limited to its earlier same-context/inert cases; rating 3/5 and release hold remain.


## Real Helium interrupted-worker/direct-relaunch scenario (2026-10-14)

**Tested / host-verified:** Windows 11 Helium 0.19.2.1 now exercised production
launcher/watcher/DPAPI/replay after interrupting its exact owned cleanup worker
and closing the browser normally. One old intent was retired before relaunch;
the authored owned Recent shortcut/WER report were removed while foreign fixtures,
standalone dump, frozen config, installed marker and public bookmark were preserved.
The user confirmed built-in uBlock and the bookmark remained. Five evidence files,
receipt and build identity were checked and preserved in an unmapped host snapshot.
[Scoped result and exact provenance](RECOVERY-BROWSER-INTEGRATION.md#helium-interrupted-worker-recovery-verified-2026-10-14).

This qualifies that direct-launch Windows 11 scenario, not protocol/other-browser
paths, independent user/machine binding, physical durability, Windows 10, real WER
crash forms, or complete production coverage. The second-Sandbox machine-only
comparison failure remains recorded. Earlier unqualified production-path status
is superseded only for this exercised scenario; rating 3/5 and release hold remain.
