# Windows-selected URL and HTML handoff qualification

## Scoped result

**Tested:** receipts dated 2026-10-16 UTC record production source
`4c94a882a3036c0b96ea87823f92e858a410ad03` in an offline Windows 11 Sandbox
(`10.0.26100.0`) with Helium 0.19.2.1. Production Rust remained unchanged from
`187771c`; no production behavior, dependency, endpoint or preference was changed.

Unlike the earlier [protocol-argument tests](LIVE-PROTOCOL-HANDOFF-QUALIFICATION.md),
these calls supplied only a URL or HTML filename to Windows's normal
`ProcessStartInfo.UseShellExecute = true` path. No launcher command was substituted
by the controller. The user selected the folder-labelled Nomad candidate for
HTTP, HTTPS and .html in guest Windows Default apps. Readback confirmed all three
actual UserChoice ProgIDs and all three native Shell command queries matched it.

| Case | Observed result |
|---|---|
| HTTP with no browser running | Windows started the exact Nomad launcher with one target after `--`. The portable browser requested the public loopback page; one exact route receipt was recorded. |
| Local HTML with browser running | Windows dispatched a filename containing spaces through Nomad. The local HTML's public image beacon reached the owned loopback server. The original portable browser main process and worker persisted. |
| HTTPS with browser running | Windows started Nomad with the exact HTTPS target and retained the same portable browser/worker. This was dispatch only: the loopback server had no TLS service; successful HTTPS content was not claimed. |

The same browser main PID 1284 and original worker PID 3760 were recorded across
all three cases, with executable/creation-time checks and the intended portable
Data argument. One owned launcher process remained after each handoff. Browser
EXE/DLL, installed/instance markers, configuration, public Data sentinel and
authored stage/backup sentinel hashes remained unchanged. No bookmark, account,
extension activation/effectiveness, whole-profile byte preservation or native
window-title observation is claimed by this particular fixture.

**Tested final closure:** the user closed Helium normally; native inspection
found zero owned browser and launcher processes. The server stopped via its
owned flag, recorded one HTTP and one HTML receipt without deadline expiry, and
its process was absent at final inspection. The browser was never force-killed.

## Registration, selection and safe cleanup

**Verified in code / tested:** a separate guarded console helper linked Cargo's
actual Nomad core and called `registry::register` for two owned launcher copies
and `registry::unregister_launcher` for the second. Native Shell queries resolved
each copy to its own exact command, `"<launcher>" -- "%1"`; distinct location-based
ProgIDs were independently derived from the production identity rule. Removing
copy B preserved copy A's sidecar hash and command. This exercises the shared
production API, not the retail `--register-default` message box/CLI interaction.

**Tested:** preselection snapshots of the three UserChoice keys retained their
presence, value types and SHA256 values. The user then made the actual selections
in Settings. Command lookup alone had returned a candidate even while recorded
UserChoice still named unavailable Edge; the verifier therefore required both
selected ProgIDs and the subsequent real ShellExecute/page observations. A
registered ProgID or successful command query alone is not a default-handoff pass.
Microsoft documents the native query as an association-string lookup in
[AssocQueryStringW](https://learn.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-assocquerystringw).

The computer-use native pipe was unavailable after retry and a clean reset.
No alternate app UI Automation or injected desktop input was used in this turn.
The user performed Default-apps selection and normal browser closure; selected
ProgIDs, process state and public receipts were independently read back through
ordinary command/native APIs. No protected UserChoice hash was forged, no
certificate/security warning was bypassed, and no host default was changed.

**Operator observation / tested cleanup:** Edge was not available for restoring
the previously recorded MSEdgeHTM choices. The selected test candidate was left
intact, rather than removing it while selected or writing UserChoice directly.
After independent host evidence preservation, the user confirmed discarding the
disposable guest. Closing its window left the background guest in CLI inventory;
following that confirmed discard request, `wsb.exe stop --id
26553b69-5239-4291-acd4-ea4fc6cf8f3c --raw` exited zero. A subsequent `wsb.exe list
--raw` returned an empty running-environment list. This verifies guest disposal,
not individual copy-A unregistration or restoration of original UserChoice hashes.
The earlier pre-discard report remains immutable; a separate linked disposal
report records the completed cleanup.

## Fixture controls and evidence

**Tested input:** a fresh owned copy of the saved official Helium 0.19.2.1 x64
ZIP matched its public release API digest and length before extraction/execution:
197,068,948 bytes, SHA256
`8623C04201A0A45A97920C7ACDAA3A9F022260C66D6DFE78E7DCB323D4D2D89C`.
This is GitHub HTTPS digest trust, not a publisher package signature. Bounded ZIP
path/inventory checks preceded this import. It does not qualify the automatic
updater/download/extraction pipeline.

The disposable configuration deliberately allowed update checks/downloads but
set `remind_on_protocol = false`, isolating OS association dispatch from the
[separately qualified reminder UI](PROTOCOL-UPDATE-FRESHNESS.md#subsequent-native-prompt-qualification).
The real protocol entry forced launch-only behavior; authored stage/backup
sentinels remained intact. All phases checked zero active non-loopback interfaces
and default routes. The public server bound only an ephemeral loopback port.
HTTPS targeted that non-TLS loopback endpoint: no external TLS contact, successful
TLS navigation or certificate-bypass result is implied. Raw browser profile,
bookmarks and logs were not exported. Only controlled public receipts, selected
registry fields/hashes, process assertions and helper/build inventories were kept.

**Tested commands:**

```text
cargo build -p nomad-helium --release --locked --target x86_64-pc-windows-msvc --message-format json-render-diagnostics
cargo test -p nomad-core --lib --locked --target x86_64-pc-windows-msvc registry::registration::tests:: -- --test-threads=1
wsb.exe exec --id 26553b69-5239-4291-acd4-ea4fc6cf8f3c --command 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\NomadInput\BrowserQualification\ShellAssociation\<controller>.ps1 -Phase <phase>' --run-as ExistingLogin --raw
```

Release compilation, the unchanged production GUI PE guard and a separate
console-subsystem guard passed. The console guard retained static-CRT/import,
x64, CFG and System32 requirements. All 17 inert registration regressions passed
(0 failed/ignored, 529 filtered). These are not the separately ignored native HKCU
unit tests, which were not rerun on the host.

**Preserved controller failures:** the first RegisterBoth and original read-only
inspector exited 1 after a helper used PowerShell's reserved PID variable. The
corrected read-only inspection confirmed copy A's registration and native command;
V3 then used the exact production canonical Windows path and completed the two-
copy operations. V3's UserChoice comparison falsely reported changes because of
Hashtable/PSCustomObject ordering; independently compared typed before/after
snapshots were identical. V4 corrected normalization and required actual selected
ProgIDs for acceptance. Original scripts, manifests, false fields and diagnostic
bytes remain preserved; no production fix or rewritten pass is claimed.

**Tested host verification:** `Verify-Shell-Handoff.py` checked input hashes in
original/read-only mapped locations, controller/parent manifests, 18 bounded
receipts, actual selected ProgIDs and commands, derived scoped identities,
Shell target arguments, profile/process linkage, route receipts, protected state,
normal closure and server stop. Five unsafe mutations were refused: string
boolean, wrong selected ProgID, replacement browser PID, HTTPS-content overclaim
and boolean-as-zero process count. The unmapped snapshot retains 52 rehashed
files plus its host report, including all failed/corrected helpers, operator
observations, build/PE/test records and a 155-file unchanged source inventory.
Selected guest assertions do not attest a compromised guest or independently
replay raw profile state.

Local package: `target/shell-association-0b0779bb6926424e914efad20062461c`.
The original manifest SHA256 is
`5E14D14343DF3037DFDDEB9349D3AC3E525E75D3E4AF243B815D49002CD008B1`;
the local launcher remains
`6A179521EF7289A61B5F541BCAFBCA5AFF26D167D4DCCAE2D78E0D351182AC93`.
Reports:
`VerifiedEvidence/shell-handoff-30f7c4d6743d4531bbdec7de7c83bf0d/HOST-VERIFICATION.json`
and `VerifiedEvidence/disposal-30f7c4d6743d4531bbdec7de7c83bf0d/DISPOSAL-VERIFICATION.json`.
The disposal record links the immutable host report and rechecks all 52 hashes.

## Disposition and limits

The bounded Windows-selected Helium HTTP/HTML handoff and HTTPS dispatch track is
completed. Other browsers/platforms, HTTPS content, combinations with multiple
original windows, already-running/fresh combinations beyond this matrix, retail
registration dialogs and individual unregister-A/restoration are not qualified.
Normal direct-launch maintenance and browser updater/security-data gaps are
separate. No production change or new full canonical/remote CI run follows.
The prior 551-test/17-ignored canonical and Rust 1.92 results still apply to
unchanged Rust. Document links/encoding/whitespace and retained evidence were
checked separately. The [release checklist](RELEASE-READINESS.md) retains the
CRLSet and independent-Windows-context risks, rating 3/5 and release hold.
No push, tag or publication was performed.
