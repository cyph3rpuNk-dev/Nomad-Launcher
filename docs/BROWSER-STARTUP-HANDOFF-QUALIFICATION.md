# Mullvad startup and protocol-prompt qualification

## Result and source state

**Tested:** saved receipts dated 2026-10-16 UTC record a fresh offline Windows 11
Sandbox (`10.0.26100.0`) running production launchers from committed source
`187771c43ad5bb2eb266cfb0447b5ef84ca80928`.

- Mullvad 15.0.25 passed signed-package verification, production-adapter
  extraction, startup with an initially absent profile, normal close, and
  relaunch. uBlock Origin, NoScript and Mullvad Browser Extension were recorded
  active on both runs. The authored profile sentinel retained its exact bytes.
- Helium 0.19.2.1 exercised four native freshness-prompt cases: URL Close,
  URL Continue, file Close and file Continue. Both cancellations left no
  acknowledgment or browser; Continue opened the intended public page/file.
  Browser metadata and authored stage/backup sentinels retained their hashes.
- Both browsers, their owned launchers/watchers and the loopback server were
  closed at final inspection. No production code change was needed.

These are scoped passes. The local documentation checkpoint on
`codex/browser-release-qualification` also includes the preceding
[required-settings GUI evidence](HARDENING-GUI-QUALIFICATION.md). No push,
remote CI, release or independent-Windows-context result is implied.

## Mullvad verification and startup

**Documented upstream:** [Mullvad's signature guide](https://mullvad.net/en/help/verifying-mullvad-browser-signature)
identifies the Tor Browser Developers primary key. **Verified in code:**
[the adapter](../core/src/browsers/mullvad.rs) pins that key, requires a detached
signature, extracts the installer as an archive and selects `Data/Profile`.

**Tested:** the official latest-release API selected 15.0.25 and supplied the
96,653,272-byte x64 package's required SHA256. Both package and detached signature
were retrieved from its exact GitHub release. A local helper linked the actual
compiled Nomad core and called the production Mullvad signature verifier and
SHA256 checker. Both passed; in-memory tampered bytes failed both checks.
The embedded key was not refreshed or replaced for this run.

The helper's extraction mode refused host execution, required the fixed guest
identity, token/owner marker and a fresh exact destination. It repeated
verification in the guest before calling the production adapter's extraction.
The installer itself was never run. Four required runtime files were checked.
A test version marker was then authored from the verified release metadata.
This import exercises extraction/startup, not Nomad's automatic download/update
or transactional promotion pipeline.

**Tested native behavior:** no `Data/Profile` directory was pre-created. The
launcher opened the public local fixture, producing ten owned browser processes
and one window titled `Nomad Mullvad qualification` on each run. Profile files
were created at the intended portable path. The only written policy was
`DisableAppUpdate: true`; no profile user.js was present. Exact browser EXE,
xul.dll, installed marker, test configuration and fixture page retained hashes.
A public sentinel created after the first normal close retained its expected
bytes through relaunch and final closure.

**Tested extension evidence:** public manifests identified uBlock Origin 1.75.0,
NoScript 13.6.36.1984 and Mullvad Browser Extension 0.9.10. The two selected
extensions.json inspections reported the corresponding IDs active, without
user/app disable flags. This is browser-recorded activation, not proof of
blocking effectiveness. The native accessibility subtree was empty; no browser
accessibility/security preference was changed to force inspection. No bookmark,
account, cookie, live anti-fingerprinting or network-leak test is claimed.

## Native protocol reminder and handoff

**Verified in code:** [protocol origin selection](../core/src/lib.rs):375 and
[effective update permissions](../core/src/lib.rs):492 force protocol checks and
downloads off. [Local freshness state](../core/src/protocol_freshness.rs)
controls the reminder and acknowledgment independently of browser provisioning.

**Tested fixture:** a separate Helium instance used hardening enabled and
`check_on_launch = true`, `auto_download = true`, `remind_on_protocol = true`.
Its legitimate-format browser cache was authored ten days stale. Distinct
public files under Browser.stage and Browser.backup were intentional recovery
sentinels. The verified pinned ZIP was bounded/path-checked before extraction.
This was an imported bundle, not a new updater-install test.

All four invocations used the registered command's actual argument shape:
`Nomad-Helium.exe -- "<one target>"`. This exercised the production protocol
entry and native prompt. Windows association registration/ShellExecute resolution
was not repeated, and the browser was closed before each case.

| Case | Observed native result |
|---|---|
| URL Close | Only Continue opening link and Close were visible/enabled. Close exited with no browser, acknowledgment or accepted page request. |
| URL Continue | Continue opened a guest-loopback HTTP page. The server recorded one exact-token route request and the native browser exposed its expected page title. A four-field acknowledgment was saved. |
| File Close | The same two prompt actions appeared. Close left no browser or acknowledgment and did not hand off the file. |
| File Continue | Continue opened the exact public local HTML fixture; its expected page title was observed and an acknowledgment was saved. |

The loopback listener bound only `127.0.0.1` on a dynamically selected port. It
served a single fixed public route/body, with bounded input and a deadline;
external networking stayed disabled. It stopped through its owned stop flag,
with one accepted target request total. It was a test fixture, not a new Nomad
endpoint or service. Browsers received normal window-close requests only.

The first Continue acknowledgment was moved unchanged to an owned test archive
before the file cases, deliberately removing its 24-hour prompt suppression.
That reset affected only the newly authored fixture. Neither Close saved an
acknowledgment. Continue acknowledgments contained only schema/browser/target/
timestamp; managed-extension lookup receipts remained absent for this browser
with built-in extensions. The browser cache, image/marker/configuration and both
stage/backup sentinels remained unchanged. Four protocol-branch log events were
recorded. No package fetch, promotion or recovery activity was found in these
selected observations. Absence of every network attempt is not established by
an OS packet capture; the conclusion also relies on the code's forced permissions.

**Observed UI follow-up:** the complete DPI-aware prompt image showed visible,
functional buttons, but explanatory text had low contrast. Presentation cleanup
remains a separate minor UI task; no such correction was made or qualified here.

## Commands, identities and host verification

**Tested build:** `cargo build -p nomad-mullvad --release --locked --target
x86_64-pc-windows-msvc --message-format json-render-diagnostics` passed. The
production PE guard passed for the actual launcher. The local console helper
passed a separate console-subsystem checker retaining the production import,
static-CRT, x64, CFG and System32 policy; launcher requirements were unchanged.
Initial direct-rustc attempts omitted dependency/native search directories and
failed before execution. The successful helper used Cargo's actual recorded
artifact and native link paths. No dependency or trust policy was weakened.

**Tested guest command:** `wsb.exe exec --id 26553b69-5239-4291-acd4-ea4fc6cf8f3c
--command 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden
-ExecutionPolicy Bypass -File C:\NomadInput\BrowserQualification\Invoke-Qualification.ps1
-Task <Mullvad|Protocol> -Phase <phase>' --run-as ExistingLogin --raw`.
The host checked guest ExitCode before each dependent phase. Helpers used exact
owned image/creation-time/HWND checks and UI Automation InvokePattern; no
personal-host browser or persistent host configuration was involved.

| Input | SHA256 |
|---|---|
| Mullvad official package | `47165100223852119FB12A3E52CA7A254AA94E6D0DA5F2AFF11BA96A2BEB5549` |
| Local Mullvad launcher | `7DD81A41BA25D71F3B079173D0D33887106388B07D89A57447E13CF8A7A518E1` |
| Local Helium launcher | `6A179521EF7289A61B5F541BCAFBCA5AFF26D167D4DCCAE2D78E0D351182AC93` |
| Production-linked console helper | `0202F975943A4F08B6D93A5EA0F4C77A660D77FD5E37A04B5A31A06CFC064CC3` |
| Original input manifest | `7355FA44B87F3EFEB439D66B818CD602E6B54C3AA16116C52668FE7EFC536DCC` |

**Tested host verification:** `Verify-Browser-Qualification.py` checked all input
hashes, parent/addon linkage, 29 typed phase receipts, extension activation,
policy shape, four prompt/action cases, acknowledgment schema, preservation,
server shutdown and final idle state. String-boolean, boolean-as-process-count
and unexpected Update-button mutations were refused. An unmapped snapshot
retains 52 byte-identical hashed files, including source/build inventories,
frozen helpers, selected results and the owned-window image. Binary/archive
references are hashes. Raw browser profiles/logs were not exported.

Local package:
`target/browser-qualification-21ae32a55f164d91ac7cdd8750e19f5a`;
verification:
`VerifiedEvidence/browser-and-prompt-92d1b57e072a44589199d85b6d982b39/HOST-VERIFICATION.json`.
This checks selected guest assertions and preservation, not a compromised guest
or an independent host replay of raw browser state. Helpers/evidence are local
ignored artifacts, not shipped launcher features or CI results.

## Remaining limits

Production Rust remained unchanged from `187771c`. Its recorded canonical gate
passed 551 tests (17 ignored), formatting, strict Clippy, safety fixtures and the
dependency audit with the existing RSA exception; Rust 1.92 passed. This record
adds release compilation and scoped runtime evidence, not another full gate.
Document links/encoding/whitespace and retained evidence were checked separately.

Windows 10, online updater delivery, already-running browser/Windows association
combinations, account/profile migration and independent Windows recovery isolation
remain unqualified. The [subsequent native swap qualification](NATIVE-SWAP-RECOVERY-QUALIFICATION.md)
covers failed promotion, blocked restore, direct-launch recovery and successful
promotion within its same-version fixture; no post-success health rollback
exists. These runs do not resolve the Ungoogled Chromium CRLSet gap. Rating 3/5 and the release hold remain; the
[current checklist](RELEASE-READINESS.md) distinguishes completed evidence from
remaining risks and coverage decisions.
