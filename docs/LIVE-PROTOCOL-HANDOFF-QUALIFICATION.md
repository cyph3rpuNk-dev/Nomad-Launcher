# Protocol handoff into an already-running browser

## Result and scope

**Tested:** on 2026-10-16 UTC, unmodified production Helium launcher source
`9e0188f9bd193aa579fa57ac892809ca23daea1a` passed four protocol-argument cases
in an offline Windows 11 Sandbox (`10.0.26100.0`) with Helium 0.19.2.1 already
running. Production Rust remained unchanged from `187771c`.

| Case | Observation |
|---|---|
| URL Close | Native Close canceled the prompt. No public target request or acknowledgment appeared; original browser main process and cleanup worker remained. |
| URL Continue | Native Continue opened the public loopback page in the original browser; its baseline tab remained and the server recorded the intended request. |
| File Close | Native Close canceled. A separate read-only native tab inspection confirmed the file target absent while baseline and prior URL tabs remained; no acknowledgment appeared. |
| File Continue | Native Continue opened the intended local HTML tab in the original browser alongside baseline/prior URL tabs. |

All four prompts exposed exactly the visible, enabled Continue opening link and
Close controls. Both continuations saved only the expected four-field advisory
acknowledgment. Neither restarted/replaced the original browser's main process
or cleanup worker. Protected EXE/DLL, version/instance markers, configuration,
cache, authored stage/backup sentinels and public profile sentinel retained hashes.
The native-created baseline bookmark was present exactly once after normal close;
uBlock toolbar controls were observed, without claiming blocking effectiveness.

**Tested cleanup coordination:** browser main PID 4692 and original worker PID
2836 retained executable/creation-time identity. The two continuation launches
spawned transient duplicate workers: debug logs recorded two coordinator-lock
exits, with just one `cleanup watcher started` event for the session. There was
one remaining owned launcher process (the original worker) at each handoff
inspection. This does not claim no extra process was spawned or prove every
possible link race. After normal browser closure, all owned browser/launcher/
worker processes were absent. The public server stopped through its owned flag
and exited; final server process count was zero. No process was forcibly killed.

## Fixture and boundaries

**Tested input:** the existing saved official Helium 0.19.2.1 release metadata's
SHA256 and length were checked against the 197,068,948-byte archive before guest
extraction/execution:
`8623C04201A0A45A97920C7ACDAA3A9F022260C66D6DFE78E7DCB323D4D2D89C`.
This is GitHub HTTPS digest trust, not a publisher package signature. Bounded ZIP
path/inventory checks preceded extraction (75 entries, 435,717,787 output bytes).
The known version/identity markers were authored. This import is not an automatic
updater/download/extraction-pipeline qualification.

The instance initially launched with updates disabled. After creating the baseline
bookmark through native UI, the controller changed only its disposable Nomad
configuration to permissive update options, authored a ten-day-old release cache
and inert stage/backup sentinels, then invoked the real `-- <target>` entry point.
The protocol path preserved those hashes despite permissive saved options. The
frozen controller also refused an unexpected managed-extension-check receipt.
The selected log check found four protocol-branch events and no automatic-download,
backup-restore or stale-stage-deletion event. No OS packet capture or universal absence-of-network proof is claimed.
All phases checked zero active non-loopback interfaces/default routes; the only
server bound an ephemeral loopback port and served one public route.

The URL acknowledgment was archived within this new guest fixture to expose the
file prompt, retaining its hash. Existing browser service setup/consent was left
untouched. The authored baseline `launch.extra_args` also opened additional
baseline tabs during forwarding, and setup tabs were present. Exact-one-tab
behavior is not claimed; target delivery and original browser identity are.

**Verified in code:** [protocol dispatch](../core/src/lib.rs) forces launch-only
permissions before required preparation and handoff. Its cleanup worker acquires
the per-instance coordinator lock before post-exit work. The
[reminder](../core/src/protocol_freshness.rs) reads bounded advisory state and
records browser/target/time on Continue; it does not perform an update lookup.
The current code and these selected observations support this bounded result.
They do not establish Windows Default-apps association selection, another browser
family, multiple original windows, every race, Windows 10 or hostile-host safety.
No registry/default-app change was made. No personal-host browser was launched.

## Commands, host verification and preservation

**Tested:** release compilation and the unchanged production GUI PE guard passed.
The actual Cargo output was selected, rather than assuming a release path:

```text
cargo build -p nomad-helium --release --locked --target x86_64-pc-windows-msvc --message-format json-render-diagnostics
cargo test -p nomad-core --lib --locked --target x86_64-pc-windows-msvc protocol_freshness::tests:: -- --test-threads=1
```

All four reminder regressions passed (0 failed/ignored, 542 filtered). These are
inert local tests. The separate guest controller invoked native UI through exact
image/creation-time/HWND identity checks:

```text
wsb.exe exec --id 26553b69-5239-4291-acd4-ea4fc6cf8f3c --command 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\NomadInput\BrowserQualification\LiveProtocol\Invoke-Live.ps1 -Phase <phase>' --run-as ExistingLogin --raw
```

Both host CLI and guest ExitCode were checked before dependent work. The separate
`Inspect-Cancelled-File.ps1` used a supplemental manifest linked to the unchanged
original manifest and checked tab absence before File Continue. No guest phase
failed. Source review corrected a worker-argv matcher before any guest invocation;
that preflight script/manifest pair is preserved, not counted as a failed run.

**Tested host verification:** `Verify-Live.py` checked all six main inputs plus
the supplemental script/manifest in original and read-only mapped locations,
public release digest/length, 23 typed phase receipts, chronology, UI button sets,
original PID linkage, target tabs, acknowledgment shape, coordinator counts,
protected state assertions, native bookmark count and final closure/server state.
String boolean, boolean-as-process-count, unexpected Update-button and replacement
browser-identity mutations were refused. The unmapped snapshot retained and
rehashed 42 files plus its report, including frozen controllers, selected receipts,
public release metadata, build/PE/test logs and a 155-file source inventory.
Raw guest profiles, bookmarks and logs were not exported. Host review validates
selected guest assertions, not compromised-guest attestation or independent raw
profile replay. Helpers/artifacts are local ignored evidence, not shipped features.

| Input | SHA256 |
|---|---|
| Production launcher | `6A179521EF7289A61B5F541BCAFBCA5AFF26D167D4DCCAE2D78E0D351182AC93` |
| Final main manifest | `60E7B8065AF454CE4F2504CA4C0E245BC3D0329284B6207E1679AE2F5998F2CB` |
| Cancellation-inspection manifest | `CA079729DC329819AA5ED9F5AF913ED9127E99E69923B8A57BC59721DE29BF14` |

Local package: `target/live-protocol-0edb52e726d2400eaffe09f09b805981`;
report: `VerifiedEvidence/live-a5694d8a79cc4be3bfa0e1d980016683/HOST-VERIFICATION.json`.

## Disposition

This closes the bounded already-running Helium/native protocol-argument track,
complementing the [fresh-browser prompt cases](BROWSER-STARTUP-HANDOFF-QUALIFICATION.md#native-protocol-reminder-and-handoff).
Windows association resolution and other live-browser/platform combinations
remain separate. There is no production behavior change or new full canonical
gate/remote CI result. The prior 551-test/17-ignored canonical and Rust 1.92
results remain applicable to unchanged Rust. Document links/encoding/whitespace
and retained evidence were checked separately. The
[readiness checklist](RELEASE-READINESS.md) retains the CRLSet and independent-
Windows-context gaps, rating 3/5 and release hold. No push, tag or publication
was performed.
