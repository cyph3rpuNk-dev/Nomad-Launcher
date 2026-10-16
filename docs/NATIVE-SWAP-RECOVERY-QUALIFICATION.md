# Native bundle promotion and recovery qualification

## Result and exact scope

**Tested:** receipts dated 2026-10-16 UTC record a scoped pass in an offline
Windows 11 Sandbox (`10.0.26100.0`). Source was committed checkpoint
`ddaa365555bc5457acf79638cf1eddeeea039fa8`; production Rust is unchanged from
`187771c`. No production code, browser preference, endpoint or dependency was
changed for this qualification.

| Scenario | Observed result |
|---|---|
| Failed promotion after the old bundle moves to backup | A native sharing violation blocked the staged-directory rename. The production rollback event occurred; the entire ordinary-file inventory of the old bundle was restored, stage retained and closed profile unchanged. |
| Interrupted state with blocked restoration | An authored mid-swap state had no active bundle and retained old backup plus candidate stage. A native sharing violation refused restoration; both inventories and the closed profile remained intact. |
| Next direct retail launch | After releasing the blocking handle, the unmodified GUI launcher restored the old bundle before removing stage. Its actual restoration event, local fixture page, saved bookmark and uBlock toolbar entry were observed. |
| Successful promotion and subsequent launch | The active bundle exactly matched the staged candidate inventory; backup/stage were absent and the closed profile unchanged during promotion. The retail launcher then opened the fixture with bookmark/uBlock still present. |

Baseline and all three subsequent launches closed normally. Final inspection
found zero owned browser/launcher/watcher processes, the expected promoted
variant, exactly one fixture bookmark and the original public profile sentinel.
uBlock toolbar presence is not a blocking-effectiveness test.

## What the code actually promises

**Verified in code:** [install.rs](../core/src/install.rs) implements
`atomic_swap_locked`: rename old to backup, promote stage, attempt rollback if
promotion fails, then best-effort remove backup after successful promotion.
`recover_staging_locked` restores backup only when the active installation is
absent. A failed restore returns before deleting stage; an existing active
installation permits stale-backup cleanup. [The finalizer](../core/src/updater.rs)
performs required staged preparation before calling the swap.

**Verified in code:** the completed promotion is the rollback boundary, not a
browser-health check. Nomad does not retain a guaranteed old bundle until a
usable browser window/navigation is established. A later profile-preparation or
browser-startup failure does not automatically restore the old version. An old
backup left by a deletion failure is not a supported user rollback slot.
[Update safety](UPDATE-SAFETY.md#promotion-and-rollback-boundary) records this
limit. Earlier checklist wording, “post-replacement rollback,” mixed this absent
health feature with the failed-rename rollback that is now qualified.

## Fixture, native fault and preservation method

**Tested input:** every bundle came from the same authenticated official Helium
0.19.2.1 x64 archive, 197,068,948 bytes, SHA256
`8623C04201A0A45A97920C7ACDAA3A9F022260C66D6DFE78E7DCB323D4D2D89C`.
The retained prior official release metadata supplies its GitHub HTTPS digest;
this is same-source integrity trust, not a publisher package signature. No new
network provider or verification bypass was introduced. The production adapter
repeated digest verification before extraction; six required runtime files were
checked. Genuine version markers remained 0.19.2.1/x64. An inert
`public-variant.txt` distinguished Baseline/StageA/StageB/StageC trees; these are
authored labels, not real upstream releases or a version-transition test.

A separate guarded console helper linked the actual Cargo-built Nomad core and
called its public `install::atomic_swap` and `install::recover_staging` wrappers,
including their real instance locks. It opened the exact owned stage or backup
directory with a nonsharing handle and `FILE_FLAG_BACKUP_SEMANTICS`, then released
the handle after the call. Both induced errors were Windows error 32. Microsoft's
[CreateFileW contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
documents directory handles and sharing restrictions affecting rename/deletion.
Expected API refusal qualified only when the required preservation assertions
also passed; the helper then exited zero. There were no controller failures.

The interrupted state was deliberately authored by renaming the owned old bundle
to backup. No power loss, drive removal or physical crash was induced. The blocked
restore and failed promotion were separate cases; simultaneous failed promotion
and failed rollback were not exercised.

Whole ordinary-file inventories compare sorted relative paths, lengths and
SHA256 hashes before/after each native operation, with the real browser and its
watcher closed. Empty directories, alternate streams, ACLs and timestamps are not
covered. This proves closed-profile file preservation during those operations,
not byte identity across browser sessions; normal browser runs change profile
files. Raw inventories, profiles, logs and bookmarks remained in the guest.

The native browser UI created the bookmark; no Bookmarks JSON was authored.
Subsequent accessibility inspection showed “Edit bookmark for this tab” and
uBlock Origin. Closed-profile parsing confirmed exactly one fixture URL/name.
Protected EXE/DLL, installed marker, configuration, cache and public sentinel
hashes were checked separately. Browser service setup was left untouched.

The retail direct launch used enabled update checks and an authored fresh cache
from that known verified same-version release, avoiding online work in the
offline guest. Actual startup recovery therefore ran; this is not an online
release lookup/download/update qualification. Guest interfaces/default routes
were checked absent. Only owned fixed paths/processes and public local HTML
were used; no personal-host browser or persistent host configuration changed.

## Commands, verification and retained evidence

**Tested commands:**

```text
cargo build -p nomad-helium --release --locked --target x86_64-pc-windows-msvc --message-format json-render-diagnostics
cargo test -p nomad-core --lib --locked --target x86_64-pc-windows-msvc install::tests:: -- --test-threads=1
```

Release compilation passed; the 17 targeted installation regressions passed
(0 failed/ignored, 529 filtered). Production GUI PE checks passed unchanged.
The helper passed a separate console-subsystem guard retaining the x64,
static-CRT, import, CFG and System32 requirements. Build/link arguments and the
actual Cargo artifact inventory are preserved.

**Tested guest invocation:**

```text
wsb.exe exec --id 26553b69-5239-4291-acd4-ea4fc6cf8f3c --command 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\NomadInput\BrowserQualification\SwapQualification\Invoke-Swap.ps1 -Phase <phase>' --run-as ExistingLogin --raw
```

Both CLI and guest exit results were checked before dependent work. Phases were
Prepare, Start/Inspect/Bookmark/Close, StageA/Fault, Start/Inspect/Close,
StageB/Interrupt, Start/Inspect/Close, StageC/Promote and Start/Inspect/Close/Final.
Prepare and Bookmark each exported two selected receipts, for 23 total.

**Tested host verification:** the retained `Verify-Swap.py` checked all eight
input hashes against original and read-only mapped copies, receipt schema and
identity, typed assertions, chronology, native JSON hashes, candidate-tree
linkage, OS errors, restoration event, native bookmark/uBlock controls, normal
closure and final idle state. Four unsafe mutations (string boolean,
boolean-as-count, wrong variant and altered native result) were refused.
An unmapped snapshot retained and rehashed 39 files plus its verification report,
including frozen Rust/PowerShell helpers, selected receipts, build/PE/regression
records and a 155-file production/source inventory. Binaries/archive are
hash references. Selected guest assertions are not adversarial attestation or
an independent replay of raw profile state.

| Input | SHA256 |
|---|---|
| Production Helium launcher | `6A179521EF7289A61B5F541BCAFBCA5AFF26D167D4DCCAE2D78E0D351182AC93` |
| Native console helper | `1C55F4A11607780AB11A36EC1EF50D6C2D7B0D54CB1BB0AB2C7B7155B81A18BA` |
| Original input manifest | `CB04099724D6B4562AD020A2DB859AAEE0E097CD2C6A4A4D8CF7E628CC326D0B` |

Local ignored package:
`target/native-swap-recovery-4d38b5532a11465680e7dd18646fcf90`;
report: `VerifiedEvidence/swap-3214508f2f4b4db1881f6a8e601720e9/HOST-VERIFICATION.json`.
These artifacts are not shipped launcher features or remote CI results.

## Remaining limits

This closes the bounded Windows 11 native failed-promotion/blocked-restore/
next-direct-recovery/successful-promotion checks above. Windows 10, real old-to-new
profile compatibility, disk-full/media-loss/natural-crash cases, combined failed
promotion and failed rollback, and automatic rollback after a completed promotion
are not qualified. The last is not an implemented feature to unlock by rerunning
a test. No broader durability guarantee follows from a sequence of renames.

The prior canonical gate (551 passed, 17 ignored; formatting, strict Clippy,
safety fixtures and audit with the existing RSA exception) and Rust 1.92 results
remain applicable to unchanged Rust. This follow-up adds release compilation,
targeted regressions, scoped runtime evidence and document checks, not a new full
gate or remote CI run. CRLSet freshness and independent Windows recovery isolation
remain separate in the [release checklist](RELEASE-READINESS.md). Rating 3/5 and
the release hold remain; no push, tag or publication was performed.
