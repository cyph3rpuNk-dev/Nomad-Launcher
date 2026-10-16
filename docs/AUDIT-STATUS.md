# Audit status

For the current consolidated disposition, read [release readiness](RELEASE-READINESS.md).
The sections below are chronological evidence; earlier pending/delivery statements
retain their historical scope and may be superseded by later records.

Baseline reviewed 2026-10-07 against `f37c9a9`; documentation follow-up against
`1b13fb8` on `rebuild/foundation`.
This reconciles the original handoff findings with the current source and local
commit history. It is a scoped static follow-up, not a new exhaustive security
audit. The handoff's compiler versions, test counts, line numbers and pending
work list are historical.

## Verification and delivery

The baseline canonical gate passed on the source tree committed as
`f37c9a9`: 471 unit tests plus 12 integration tests (483 total), formatting,
Clippy, release/build/CI safeguard fixtures, and dependency audit with the
sole documented `RUSTSEC-2023-0071` exception. Rust 1.92 workspace/all-target
checking passed. These results are carried forward from the preceding
validation; the gate was not rerun merely to write this checklist.

Live signing-key coverage passed for Firefox, Firefox ESR, Mullvad and uBlock.
The Mullvad checksum fixture was cryptographically verified with GPG and
Nomad's Rust verifier. The refreshed 7-Zip extractor ran against inert temporary
ZIP fixtures. No installer or browser was launched.

The four native HKCU tests have now passed in Windows Sandbox with a static-runtime
test build (see below). The experimental Firefox baseline also passed its exercised
startup/profile/Windows-integration checks. Broader browser/update validation and
GitHub CI remain pending; the signing-key check does not replace them.
Test counts measure examples exercised, not code coverage; no coverage percentage
has been measured.

Code fixes and documentation cleanup are local commits; the live-check results
are committed as `a83ef02`; the isolated smoke-test runbook is committed as
`6f51fe5`. Runtime/renderer fixes and their Sandbox records are committed as
`4d29106`; the Chromium update/failure/recovery records are committed as `d73e353`.
The branch was subsequently pushed and opened as draft PR #68. It has not been
merged, published or copied into the user's portable installations. At the baseline review,
`origin/main..HEAD` contained 24 commits using the local tracking ref. No remote
fetch was performed, so this is not GitHub's independently verified current state.

## Original findings

"Fixed" means the specified code defect has a committed mitigation and local
regression coverage; delivery and live-system validation remain separate.
F-numbers refer to the original handoff. Paths below identify current evidence.

| Finding | Current disposition | Evidence / local commit |
|---|---|---|
| F1/F2: broad host-directory cleanup | Fixed. Shared profiles, registration maps, temporary files, standalone dumps and compound Jump Lists are preserved. Attributed WER report attachments, including dumps, may be removed; see the WER follow-up below. Deletion requires instance attribution. | [`cleanup.rs`](../core/src/cleanup.rs), `ffbd1e0`. |
| F3: forwarded browser switches | Fixed. Exactly one supported URL/file argument; switch-like and extra arguments are rejected before configuration or browser construction. | `split_forwarded_args` / `validate_forwarded_args` in [`lib.rs`](../core/src/lib.rs), `1bc3fdc`. |
| F4/F10: unsafe or nested installation folders | Fixed. A single Windows-safe, nonreserved folder component is required. Filesystem aliases and instance ownership are checked separately. | [`config.rs`](../core/src/config.rs), [`fs_safety.rs`](../core/src/fs_safety.rs), [`instance.rs`](../core/src/instance.rs); `cd93fad`, `1734e26`. |
| F5: unbounded network waits | Fixed. Shared connection, read and total deadlines, plus metadata/archive byte limits. | [`network.rs`](../core/src/network.rs), [`downloader.rs`](../core/src/downloader.rs), `87caecd`. |
| F6: missing required signature falls back to hash | Fixed in production. Signature-bearing adapters fail closed before staging. The follow-up below aligns live monitoring with this requirement. | [`updater.rs`](../core/src/updater.rs), `c01e3c7`. |
| F7: Gecko XPI signature-file names treated as integrity | Mitigated. AMO metadata binds identity, version, URL and SHA-256; bytes are verified before staging. Mozilla signature verification remains Firefox's responsibility. | [`browsers/mod.rs`](../core/src/browsers/mod.rs), `4280eb0`; [trust limits](UPDATE-SAFETY.md). |
| F8: unbounded Chromium extension download / tag does not cover ZIP | Download bounded; GitHub asset digest required and verified. The tag signature still does not authenticate ZIP bytes: archive integrity depends on GitHub metadata. | [`browsers/github.rs`](../core/src/browsers/github.rs), [`browsers/ungoogled.rs`](../core/src/browsers/ungoogled.rs); `87caecd`, `89e2529`. |
| F9: untracked registry repair | Fixed for new repairs. Write-ahead journal and compare-before-restore undo; explicit registrations are recoverable and location-scoped. Unknown historical originals cannot be reconstructed. | [`registry/repair_journal.rs`](../core/src/registry/repair_journal.rs), [`registry/registration.rs`](../core/src/registry/registration.rs); `f00175c`, `5975143`, `87360f8`; [limits](REGISTRY-SAFETY.md). |
| F11: architecture-independent caches and update decisions | Fixed. Cache, install marker and update decisions share the package target. | [`version_cache.rs`](../core/src/version_cache.rs), [`updater.rs`](../core/src/updater.rs), `e2f2dd2`. |
| F12: fallback spawn errors / discarded branding outcome | Spawn failures now surface and wait for retry/close (`c0de3be`). Staged mandatory overlays fail before promotion. Existing-install cosmetic branding deliberately logs failures and retries next launch; the ignored boolean there is not an unreported installer success. | `finish_fallback_spawn` / `apply_branding` in [`lib.rs`](../core/src/lib.rs); `ensure_branding` in [`branding.rs`](../core/src/branding.rs). |
| F13: obsolete embedded 7-Zip | Fixed as of review: 26.04, verified package/file hashes, x64 integrity regression and current license notices. Future freshness remains maintenance work. | [`extract.rs`](../core/src/extract.rs), [`manifest.json`](../core/payloads/7zip/manifest.json), `f37c9a9`; [provenance](VENDORED-DEPENDENCIES.md). |
| F14: browser downgrades / unknown extension version | Browser downgrades and unorderable versions are rejected (`d221e9d`). Gecko uses AMO's explicit version without the `unknown` fallback (`4280eb0`). Extension rollback policy is separate from browser downgrade protection. | [`version_order.rs`](../core/src/version_order.rs), [`updater.rs`](../core/src/updater.rs), [`browsers/mod.rs`](../core/src/browsers/mod.rs). |
| F15: build, signing and CI safeguards | Fixed locally: locked Cargo operations, required distribution inputs, protected signing flow, explicit job permissions and release-asset safeguards. Actual publishing remains unrun. | [`dist.ps1`](../dist.ps1), [`scripts/check.ps1`](../scripts/check.ps1), [build safety](BUILD-SAFETY.md); `7cd3f4b`, `8950a4e`. |
| F16: documentation drift | Documentation reconciled locally for the listed contradictions, including configuration/profile paths, resource overlays, unsafe-code scope, UI references and extension recovery. This is a scoped correction, not an exhaustive documentation audit. | [`SPEC.md`](../SPEC.md), [`README.md`](../README.md). |

Other completed work includes disabling Helium's built-in updater independently
of hardening (`bfd4880`), preserving settings/extensions on failed replacement
(`7c011f5`), transaction locks/recovery (`60a838e`), staged browser layout checks
(`248dc69`), and Chromium first-run hardening toggles (`b3cca7b`).

The reported Mullvad update failure now has a reproduced cause and fix: a missing
signing subkey, refreshed under the same primary fingerprint (`f37c9a9`). See
[the signed-fixture and binding evidence](VENDORED-DEPENDENCIES.md).

## Verification-monitoring follow-up (2026-10-07)

The local follow-up shares the integrity-material policy between
`updater::validate_verification_metadata`, package verification, and the live
release checker. A required signature URL cannot fall back to SHA-256 or
SHA-512. Hash-only adapters without a digest now fail before stage creation or
download. Metadata availability does not establish package authenticity;
cryptographic verification remains mandatory.

An offline regression reproduced the previous false success before the fix.
The policy matrix covers signed/hash-only adapters, signature presence, and
SHA-256/SHA-512/no digest. A mocked pipeline regression confirms zero requests
and no stage/backup creation when a hash-only adapter lacks a digest.
The canonical gate passed for this follow-up: 472 unit tests and 14 integration
checks (486 total), formatting, Clippy, safeguard fixtures, and dependency audit
with the same documented RSA exception. Rust 1.92 all-target checking passed.
At that validation, ignored live/HKCU checks and GitHub CI remained unrun;
see the current live metadata results below.
Committed locally as `af8772a`.

## Launch-language follow-up (2026-10-07)

`launch.language` now produces one `--lang=<value>` argument for Ungoogled
Chromium and Helium, independently of hardening. Surrounding whitespace is
trimmed; unset/blank values add no switch. An explicit language switch in
`extra_args` takes precedence. Gecko and Bitwarden do not receive a generated
language switch. Existing Chromium/Helium configs with `language = "en-US"`
now request English; removing the setting retains the browser's own selection.

Offline regressions reproduced the missing switch before the fix and inspect
all nine adapters' commands without spawning processes. They cover hardening
on/off, engine scope, blank values, overrides, and single-argument boundaries.
Browser locale availability, UI behavior, and full-restart behavior still need
smoke testing. The combined local gate passed: 475 unit tests plus 14 integration
tests (489 total), formatting, Clippy, safeguard fixtures, and dependency audit
with the documented RSA exception. Rust 1.92 all-target checking passed. Ignored
live/HKCU tests and GitHub CI were unrun at that point. Language handling is committed locally
as `1b13fb8`; verification monitoring is committed as `af8772a`.

## Documentation follow-up (2026-10-07)

Reconciled SPEC with configuration under `Nomad/`, profile `user.js` outside the
browser bundle, LibreWolf's minimal hardening, and current PE/PAK overlays.
Replaced missing design-document references with existing UI modules and
corrected the claimed scope of unsafe Windows API code. README now names the
actual extension staging paths and distinguishes Nomad-managed provisioning
from Helium/Mullvad's bundled extensions. Floorp and Mullvad comments now match
nonexecuting extraction and the separate `Data/Profile` location.

Only documentation and Rust comments changed. Committed locally as `67cde4a`. The canonical gate passed
again: 489 tests, formatting, Clippy, safeguard fixtures, and dependency audit
with the documented RSA exception. All 56 local Markdown file targets in the
three edited documents exist, and both Rust diffs were checked as comments only.
Rust 1.92 validation is carried forward from the language commit; it was not
rerun for comment-only changes. Live/HKCU tests and GitHub CI were unrun at
that point; the metadata checks have since run as recorded below.

## Live upstream metadata validation (2026-10-07)

Executed on `67cde4a` using
`cargo test -p nomad-core --test upstream_live --locked -- --ignored --nocapture`.
All nine x64 metadata checks passed; the two offline regressions in that test
binary were filtered out by `--ignored` (they passed in the canonical gate).

| Adapter | Resolved version | Package verification metadata |
|---|---|---|
| Firefox | 157.0.1 | SHA-256 from authenticated checksum manifest |
| Firefox ESR | 140.17.0esr | SHA-256 from authenticated checksum manifest |
| Floorp | 12.19.0 | SHA-256 |
| Waterfox | 6.7.5 | SHA-512 |
| LibreWolf | 157.0-1 | SHA-256 |
| Mullvad | 15.0.24 | Required detached signature URL and SHA-256 |
| Ungoogled Chromium | 154.0.8037.97-1.1 | SHA-256 |
| Helium | 0.18.3.1 | SHA-256 |
| Bitwarden | 2026.9.1 | SHA-256 |

This exercised real upstream resolution, the shared verification-metadata
preflight, and adapter update compatibility checks. Firefox authenticates its
checksum manifest during resolution; its lack of a package-signing key in the
printed metadata summary does not mean signature verification was skipped.
No browser package was downloaded, extracted, installed, or launched by this
suite. Mullvad package signatures, Bitwarden Authenticode, staged layouts,
required overlays and browser behavior still need their separate checks.
Other architectures were not tested. These are point-in-time upstream results.

The live results records are committed locally as `a83ef02`. The canonical gate and Rust
1.92 results above are carried forward; neither was rerun merely to record
these live runs.

## Live package extraction and overlays (2026-10-07)

Executed on `67cde4a` using
`cargo test -p nomad-core --test upstream_extract --locked -- --ignored --nocapture`.
Both tests passed (2 passed, 0 failed) in 26 seconds on Windows:

- Floorp: real upstream resolution, package download and verification, extraction,
  staged update promotion, configured launch-target existence, and installed
  version-marker checks.
- Ungoogled Chromium: real upstream resolution, package download and verification,
  extraction, production staged compatibility and mandatory PE/PAK branding
  checks, update promotion, executable/branding-marker/version-marker checks.
  The test also asserted that no `Data/` profile directory was created.

Each test used its own `tempfile::tempdir()` and exercised the shared updater.
The bundled extractor ran; downloaded browser installers and browser executables
were not launched. The tests did not use the user's portable installations or
profiles. Exact resolved versions were not printed by this suite; the preceding
metadata table records the separate metadata run, not an extraction-test manifest.

This closes the two extraction/overlay checks for this run, not all-browser
installation coverage. Browser startup, extension acceptance, existing-profile
updates, offline launch, rollback/retry and real Windows integration remain
separate validation. No runtime source was changed for these live checks.

## Windows Sandbox validation (2026-10-11)

The user exercised a Firefox baseline in Windows Sandbox using an isolated
source snapshot of `6f51fe5`, static-CRT linkage and an experimental wgpu/DX12
renderer. Production runtime source, build configuration and lockfile were
unchanged during that experiment; subsequent production changes are recorded below. The original binaries required `VCRUNTIME140.dll`; the glow status
window failed both with vGPU disabled and enabled. The experimental build removes
the inspected external CRT imports and renders/launches in the GPU-enabled guest.
These experiments establish viable directions, not completed production fixes.

| Check | Result / evidence |
|---|---|
| Four native HKCU tests | Passed serially in the first guest; screenshot-confirmed exit codes 0. |
| Firefox install/startup and portable paths | Firefox 157.0.1 x64 running from the disposable `Browser/`, using sibling `Data/`; screenshots and version marker. |
| Extension acceptance | uBlock Origin enabled in Firefox; metadata reports version 1.75.0, active and not user-disabled. Blocking behavior was not tested. |
| Full exit/relaunch | No remaining Firefox processes before launch and exit 0 are screenshot-confirmed; bookmark and enabled extension persistence are user-confirmed. |
| Hardening off/on preservation | Both launches exited 0 with the helper reporting false then true; bookmark and enabled extension preservation are user-confirmed. Individual effective preferences were not inspected. |
| Offline launch | Guest adapter disabled, launcher exited 0, adapter re-enabled, extension enabled; screenshot-confirmed. The offline bookmark observation and Internet reachability after re-enable were not separately confirmed. |
| Registration and Windows defaults | Version-2 owner/plan and actual HKCU command/capabilities checked; folder-labelled entry selected for HTTP/HTTPS and .htm/.html. |
| URL/local HTML handoff | Open-window routing retained the same Firefox PID; closed-browser routing reopened the existing install. Marker/executable hashes stayed unchanged. Closed-mode bookmark/extension preservation and no provisioning UI are user-confirmed. |
| Unclaimed empty-instance URL refusal | Expected ownership error and exit 1; helper confirmed no browser/profile, marker, config or extension cache created. |
| Two-copy registration and second removal | Separate picker entries and disjoint registrations; second unregister exited 0 and removed its owned state while inspected primary registration and HTTP/HTTPS/HTML defaults stayed unchanged. |
| Primary unregister and retained data | Exit 0; planned keys/value/sidecar absent. Firefox, version marker and bookmark-database hashes unchanged. |

Guest browser/registry actions were user-executed and observed through screenshots
or reports. No real browser or HKCU test ran on the host. Static-runtime host
unit tests passed (475, with four HKCU tests ignored there); trial builds, helper
syntax and applicable inert text/path fixtures passed. The full canonical gate
and GitHub CI were not rerun for these experiments. Detailed hashes, screenshot
names, commands, helper correction and limitations are in
[the dated validation record](SANDBOX-VALIDATION-2026-10-11.md).

The default warning log's generic Firefox package-signature message does not
capture the earlier GPG-signed checksum-manifest authentication: that and package
hash success are debug events in the inspected source. It is not evidence of a
missing-signature fallback. Authenticated package resolution was not independently
reconstructed from this warning-only guest log.

Both guest registrations are now removed. Guest files, profile, backups and logs
remain; closing Sandbox discards them. No fixture folders were deleted. New
validation results are local and uncommitted.

## Production runtime and renderer safeguards (2026-10-11)

Implemented locally after the experimental baseline, on `rebuild/foundation`:

- `.cargo/config.toml` statically links the Windows MSVC CRT while retaining CFG
  and `/DEPENDENTLOADFLAG:0x800`. The gate, MSRV and Windows CI commands now pass
  an explicit Windows target so host build scripts/proc macros stay separate.
- `core/Cargo.toml` and `core/src/ui/mod.rs` select wgpu/DX12 on Windows, pin the
  system FXC compiler and exclude external compiler/Agility/debug-layer requests.
  Non-Windows tooling retains glow. The UI failure message and guides reflect
  Direct3D rather than OpenGL.
- `scripts/artifact-guard.ps1` checks bounded PE metadata, direct/delayed imports,
  GUI/x64 format, CFG metadata and the exact System32-only dependent-load flag.
  `dist.ps1` requires the guard/config and checks built, staged and promoted files.
  Unsafe artifacts cannot proceed to signing or a completion manifest.
- New inert artifact fixtures and extended distribution/CI failure fixtures
  cover external CRT imports, malformed metadata, missing hardening, required
  inputs and explicit targets. No fixture launches a browser or writes real HKCU.

Validation completed on the local working tree:

- Canonical gate: 490 Rust tests passed (476 unit + 14 integration), formatting,
  Clippy, dependency audit with only the existing RSA exception, and offline
  safeguard fixtures. Four native HKCU tests remain ignored on the host.
- Artifact fixtures: four accepted and 18 rejected metadata cases. Distribution
  fixtures: 33 cases; CI failure/wiring fixtures: eight cases plus workflow/set
  checks. Artifact/distribution fixtures also passed Windows PowerShell 5.1.
- `cargo +1.92 check --workspace --all-targets --locked --target
  x86_64-pc-windows-msvc --target-dir target/msrv-runtime-renderer` passed.
- Unsigned `dist.ps1` built and promoted all nine launchers. Their direct/delayed
  imports and hardening checks passed; the original dynamic-runtime Firefox
  artifact is rejected for `VCRUNTIME140.dll`. Signing variables were removed
  only from the build child's environment; no real signing/publishing ran.

The artifact guard's x64 load-config offsets were corrected after checking a real
binary (PE32+ retains the two SEH fields). The stock import allowlist also includes
OpenGL32; a positive fixture prevents treating this OS DLL as an external runtime.
These corrections are covered by the final fixtures and real-artifact checks.

All nine supported-build artifacts and a hash manifest are staged in the existing
read-only Sandbox input mapping. The guest helper creates fresh Firefox/Chromium
instances and enables debug logging only for its launcher child. The user ran
Firefox mode; screenshot `Screenshot 2026-10-11 141934.png` confirms launcher
exit code 0, `SHA256SUMS GPG signature verified`, package `SHA-256 hash verified`,
and `browser launched` with PID `4932`, executable
`C:\NomadSmoke\Production\Firefox\Browser\firefox.exe`. The wgpu log explicitly
selects the AMD Radeon 780M integrated adapter using DX12. It also lists Microsoft
Basic Render Driver as an available CPU adapter, but this run did not exercise
software rendering. Supported-build launcher/graphics initialization, Firefox
manifest/package verification and browser process startup therefore pass in this
Windows 11 guest. Firefox's visible window/profile path, persistence and Windows
integration on this specific build remain separate observations; prior detailed
checks cover the experimental build. The user then ran Chromium mode; screenshot
`Screenshot 2026-10-11 143056.png` shows launcher exit code 0, package `SHA-256
hash verified`, and browser launch from
`C:\NomadSmoke\Production\Chromium\Browser\chrome.exe`, with Ungoogled Chromium
visibly displaying `chrome://ungoogled-first-run`. Its DX12 selection log again
names the AMD Radeon 780M. Supported-build Chromium verification/startup therefore
passes in this guest. Screenshot `Screenshot 2026-10-11 144613.png` of
`chrome://version` confirms Chromium `155.0.8059.39` (64-bit, Ungoogled Chromium),
Windows 11 24H2 build `26100.9445`, executable
`C:\NomadSmoke\Production\Chromium\Browser\chrome.exe`, and profile
`C:\NomadSmoke\Production\Chromium\Data\Default`. Its command line includes the
expected instance-local `--user-data-dir`, `--lang=en-US`, and a `--load-extension`
path under this browser's `nomad-extensions\uBlock0`. This establishes portable
path/argument evidence; extension acceptance and individual flag effects are not
proved by command-line presence. Screenshot `Screenshot 2026-10-11 145202.png`
then shows uBlock Origin `1.75.0` in `chrome://extensions`, switch on, with no
visible Errors button or warning on its card. Initial Chromium extension
acceptance/enabled state therefore passes; blocking behavior and state across
relaunch/hardening/update transitions remain untested. A hash-validating
supported-build relaunch helper was prepared and parsed without executing it;
it requires the chosen browser to fully exit and reuses the same instance with
child-only debug logging. Screenshot `Screenshot 2026-10-11 150310.png` then
shows no Chrome processes remaining before supported relaunch, launcher exit code
0, and installed-marker hash unchanged. The user explicitly confirmed that the
bookmark remained and uBlock Origin was still enabled. Supported Chromium full
exit/relaunch and profile/extension preservation therefore pass. A supported-build
hardening-toggle helper was prepared and parsed, retaining the original config,
scoping changes to the hardening enabled boolean, requiring the browser to stop,
and verifying the supported launcher hash. Its pure text off/on preservation
fixture passed. Screenshot `Screenshot 2026-10-11 151815.png` shows supported
Chromium off mode reporting `hardening.enabled = false`, the retained original
config backup, and launcher exit code 0; Chromium is visibly open. The test
bookmark and enabled extension are not displayed or explicitly confirmed in this
off-phase screenshot at that checkpoint. Screenshot
`Screenshot 2026-10-11 152905.png` subsequently confirms on mode reporting
`hardening.enabled = true` and launcher exit code 0 (both off/on commands are
visible). The user confirmed the bookmark and uBlock Origin remained intact in
response to the requested both-phase checks. Supported Chromium hardening-toggle
preservation therefore passes by user report, with successful setting/launch
steps screenshot-confirmed. Individual effective privacy settings were not tested.
A supported offline helper was prepared and parsed, preserving the previous
adapter-selection/disconnection/finally-restoration guards while validating the
supported artifact and enabling child-only debug logs. Screenshot
`Screenshot 2026-10-11 153442.png` shows guest Ethernet disabled, supported launcher
exit code 0 while disconnected, and the adapter re-enabled. The user confirmed
bookmark/uBlock preservation. Debug output shows the gorhill uBlock update check
skipped after a network-request error, followed by browser launch from the existing
supported Chromium folder. Supported Chromium offline launch and preservation
therefore pass, including an observed extension-update network-failure fallback.
This is not a browser-update download-failure/rollback test; Internet reachability
after adapter re-enable was not independently checked. A guest-only language
helper was prepared and parsed with scoping/preservation and rejection fixtures;
it backs up the original config, changes only launch language/extra_args, guards
against intervening config edits, and supports fr/explicit-de-override/omitted-key
phases plus restoration. Screenshot `Screenshot 2026-10-11 154600.png` shows
French phase exit code 0, `--lang=fr`, unchanged supported Chromium executable/
profile paths, and French UI labels; the user also confirmed the UI appeared in
French. Configured French locale selection therefore passes for this package.
Bookmark/extension state during this phase was not separately confirmed.
The user subsequently confirmed German UI with the explicit argument override
and retained bookmark/uBlock Origin. This is a user-reported override/preservation
pass. Screenshot `Screenshot 2026-10-11 162820.png` additionally confirms exit
code 0 for both override and default phases, with English New Tab/All Bookmarks
labels visible after the default phase. Screenshot `Screenshot 2026-10-11 163353.png`
shows no `--lang` argument and the same supported executable and portable profile
paths in `chrome://version`. The user confirms the bookmark remains and uBlock
Origin is enabled. Omitted-language launch/preservation therefore passes for this
package. Screenshot `Screenshot 2026-10-11 164109.png` confirms the restore phase
completed with exit code 0; the user confirms English UI and retained bookmark
and enabled uBlock Origin. The language sequence and original-config restoration
are complete. Screenshot `Screenshot 2026-10-11 165906.png` confirms supported
Chromium registration exit code 0, matching ownership/registry checks and the
folder-labeled candidate in Windows Default apps. Screenshot
`Screenshot 2026-10-11 170159.png` confirms manual default selection with HTTP,
HTTPS, .htm and .html assigned to this supported Chromium instance. Screenshot
`Screenshot 2026-10-11 170611.png` shows HTTPS/local HTML tabs in the existing
Chromium window, original window PID 3012 retained, and unchanged browser binary
and installed marker. The user confirms everything is intact. Open-window shell
handoff passes. Screenshot `Screenshot 2026-10-11 170947.png` shows closed-mode
handoff completed without errors after the stopped-browser precondition, with
browser binary and installed marker unchanged. The user subsequently confirms
both pages reopened with bookmark/uBlock Origin intact and no installation/update
window. Supported Chromium open- and closed-browser handoff pass. Screenshot
`Screenshot 2026-10-11 171701.png` confirms unregistration exit code 0, removal of
planned registry keys/value and ownership sidecar, and unchanged Chromium binary,
installed marker, Bookmarks and Preferences hashes. Registration cleanup passes;
browser/profile folders, backups and guest logs are retained. Software
rendering is not selected in this run either. Supported Firefox's actual profile
path has not yet been confirmed separately.
Only the Windows x64 target is installed locally;
non-Windows compile/graphics and live Windows 10 checks were unavailable/unrun.
GitHub CI has not run. Runtime/renderer changes and validation records were
subsequently committed as `4d29106`, with update/recovery results in `d73e353`.

Supported-build Firefox SHA-256:
`79E64AD13B338F80719A0D38B8B68356AE845B0371698B994A3D65B455AE0C6B`.
Supported-build Chromium SHA-256:
`4935165932B7721EFDDF84BD1937106F2D8B9547F1A2DD712C0A3CA176353D9C`.

## Remaining maintenance work

| Priority | Item | Severity / certainty | Location and next action |
|---|---|---|---|
| 1 | Supported-build runtime/renderer validation | **Original high-severity runtime dependency and medium graphics limitation are addressed locally; supported Firefox and Chromium launcher startup is confirmed in Sandbox.** Static CRT and Windows DX12/system FXC are implemented, Rust 1.92/gate and all nine artifact checks pass. | Supported Firefox debug logs confirm DX12 initialization, signed manifest/package hash verification and browser spawn. Both supported Firefox and Chromium now pass verification/startup. Chromium version, portable profile/binary paths and default language argument are confirmed. Initial Chromium extension acceptance and full-exit preservation are confirmed; Chromium hardening off/on preservation is also confirmed; Offline Chromium launch/preservation now passes too; French language selection and user-reported German override/preservation are confirmed; omitted-language launch/preservation also passes; original configuration restoration passes; supported Chromium registration, default selection, open/closed handoff and unregistration pass; supported Firefox profile/integration evidence remains separate; Windows 10/software-adapter coverage remains pending. Preserve experimental records separately. |
| 2 | Large orchestration modules | **Low, confirmed maintainability concern; defect impact is a hypothesis.** `lib.rs` is 3,854 lines including tests, combining CLI, UI pipeline, launch, registry integration and cleanup watcher handling. `browsers/mod.rs` is 1,267 lines including tests, mixing the family contract with Gecko provisioning. | Extract cohesive internal modules after behavior fixes, preserving the public contract and failure-path tests. Line counts alone do not establish poor coverage or a bug. |

Do not reopen a closed finding merely because the old handoff still lists it.
Likewise, a green local gate does not close unrun end-to-end validation.

## Validation and delivery still pending

| Work | Evidence needed / scope |
|---|---|
| Windows registration and URL handoff | Experimental Firefox baseline passed registration/default selection, open/closed HTTPS/local HTML handoff, unclaimed-instance refusal, separate picker entries and both unregister checks. Supported Chromium also passed registration/default selection, open/closed HTTPS/HTML handoff and unregistration. Other supported-build/family cases and claimed-but-uninstalled refusal remain unrun. |
| Portable browser smoke tests | Firefox portable profile, enabled uBlock, relaunch, hardening off/on and offline launch are exercised in the experimental build. Supported-build Firefox verification/startup and Chromium verification/startup, version 155.0.8059.39, portable paths and language/load-extension arguments are confirmed. Chromium uBlock Origin 1.75.0 acceptance/enabled state is now screenshot-confirmed; full exit/relaunch preservation is now confirmed. Authentic Chromium 154-to-155 update, mid-download failure/preservation, fallback and successful retry now pass. Other browser families and post-swap rollback coverage remain pending. Chromium offline bookmark preservation was user-confirmed; extension blocking behavior was not captured; supported Firefox debug authentication evidence and Chromium hash/startup evidence are now collected. |
| Historical Helium cross-machine sign-in report | Still needs reproduction. The handoff references issue #54, but current GitHub status and root cause were not checked here. Portability flags alone do not prove cookie portability. Use a disposable account/profile and a controlled move between machines. |
| Historical local artifacts | The handoff reports a nested Mullvad browser tree, stale associations and a stray LibreWolf host profile. These were not re-inspected or removed; they are historical reports, not current verified state. Cleanup needs a separate inventory and user approval. |
| Review, CI and release | Obtain approval for push/PR creation, run GitHub CI, review/merge within authorized scope, build and verify release artifacts, and obtain approval for publishing/deployment. None follows automatically from a local commit. |

Prepared [the isolated Windows smoke-test runbook](SMOKE-TESTS.md), including
exact native-registry test filters and disposable-instance build/setup steps.
The runbook is partially exercised by the Sandbox session above. On 2026-10-07, both
PowerShell examples were parsed without execution and the four exact registry
test names were verified with `--list`. The canonical local gate passed with
489 tests, formatting, Clippy, safeguard fixtures and dependency audit using
the documented RSA exception. These are prior-run results, not a fresh run on
2026-10-11; the temporary gate log is no longer present.

Initially on 2026-10-11, no isolated environment was available and the user
requested preparation only. The user subsequently authorized Windows Sandbox
setup and executed the four native HKCU tests there, as recorded above.

Authentic Chromium 154.0.8037.97-1.1 is now installed in the separate
`Production\UpdateChromium` fixture. Screenshot `Screenshot 2026-10-11 233851.png`
confirms the verified installation, generated version marker and actual portable
browser/profile paths; the user confirms the test bookmark and enabled uBlock.
Screenshot `Screenshot 2026-10-11 235249.png` confirms interruption after 32,768
partial package bytes, guest adapter re-enablement, the expected pipeline network
error, removal of the partial download, and unchanged older-browser/profile/
configuration hashes. Controlled download failure and preservation pass.
Screenshot `Screenshot 2026-10-11 235552.png` shows fallback Chromium still at
154.0.8037.97 in the same UpdateChromium portable profile; the user confirms the
test bookmark and enabled uBlock Origin. Fallback launch/preservation passes.
Screenshot `Screenshot 2026-10-12 000401.png` confirms retry exit code 0, package
SHA-256 verification, a changed browser binary and the generated 155.0.8059.39-1.1
marker. `chrome://version` shows engine 155.0.8059.39 in the same UpdateChromium
portable profile. The helper confirms retained bookmark name/URL, uBlock manifest
1.75.0, unchanged configuration/identity and absent stage/backup folders; the user
confirms the bookmark and enabled uBlock Origin. Authentic 154-to-155 update,
interrupted-download preservation, fallback launch and successful retry pass.
This pre-swap failure does not exercise rollback after a bundle replacement.

Guest evidence is now preserved under the host Documents folder at
`Nomad-Launcher-Evidence\2026-10-11-12-5accfcf6`. The 266,609-byte archive contains
56 evidence files and 14 hash-only references. Its SHA-256 matches the guest
console screenshot, and every exported file checksum and archive path passed
independent host verification. Four available screenshots, helper scripts and
audit documents are also retained; 40 earlier referenced screenshots were not
found at their recorded source paths and are listed in the host manifest.
Browser/profile contents are excluded; this is evidence preservation, not a
backup of the disposable installations. The temporary receiver was stopped.

Recommended next step: select remaining validation coverage or proceed with
separately authorized push/CI/review. The supported Chromium registration/handoff/
removal and exercised update/failure sequences are complete, and their guest
logs/test metadata have been exported. Static runtime and renderer implementation, the canonical
gate, MSRV and artifact checks are complete locally; broader guest checks and
GitHub CI remain separate.
Defer the optional module split until behavior validation.

## Draft PR and first CI results (2026-10-12)

`rebuild/foundation` was pushed at `67b8c16` and draft
[PR #68](https://github.com/cyph3rpuNk-dev/Nomad-Launcher/pull/68) opened against
main. All 33 published commits were checked for author/committer identity and
full-message attribution. No merge or release publication was performed.

Dependency advisories, Rust 1.92 compatibility and Actions static analysis passed.
The [Windows canonical check](https://github.com/cyph3rpuNk-dev/Nomad-Launcher/actions/runs/38210395672/job/114683031722)
and Chromium Compatibility jobs failed at Clippy on the same nine test-only
assertions. CI's Rust 1.99 introduces `clippy::assert_is_empty`; the host has
Rust/Clippy 1.98.1. The assertions were changed locally to explicit equality or
inequality comparisons, preserving the conditions checked and lint policy.

The local canonical gate passed after this fix: 490 Rust tests, formatting,
Clippy, safeguard fixtures and dependency audit with the documented RSA exception.
Rust 1.92 workspace/all-target checking also passed. Full logs are retained in
`target/pr68-ci-fix-gate.log` and `target/pr68-ci-fix-msrv.log`. The test assertion
fix and status update were subsequently committed and pushed as `f1b9ec2`.

## CI rerun and junction-fixture correction (2026-10-12)

CI on `f1b9ec2` passed Clippy, dependency advisories, Rust 1.92 compatibility and
Actions static analysis. The [Windows test job](https://github.com/cyph3rpuNk-dev/Nomad-Launcher/actions/runs/38212122177/job/114688413262)
and Chromium Compatibility jobs then failed 16 unit tests at the shared
`owned_directory_link` fixture's path-character assertion, before those tests
could exercise their safety predicates.

A new regression reproduced the same assertion failure locally with `~` in an
owned temporary directory. The Rust fixture now accepts this Windows short-path
character while preserving root containment and rejecting shell expansion/
metacharacters before calling cmd. Added a successful junction regression and a
percent-sign refusal regression. A full-gate run with TEMP/TMP set only in the
child process to an owned tilde-containing path also exposed the same restriction
in the PowerShell build fixture; its path whitelist received the same narrow fix.

The reproduced-environment gate passed after both fixture fixes: 492 Rust tests,
formatting, Clippy, artifact/build/CI safeguard fixtures and dependency audit with
the documented RSA exception. Rust 1.92 workspace/all-target checking passed.
Logs: `target/pr68-junction-fix-gate.log` and `target/pr68-junction-fix-msrv.log`.
The fixture correction and this record are local and await commit/push approval.
PR #68 remains draft with failed checks on `f1b9ec2`; CI has not run on the
fixture correction. Live Chromium archive/build steps were not reached in those
failed workflows.

## Merge validation and v1.0.9 preparation (2026-10-12)

The junction-fixture correction above was committed and pushed as `36eda10`.
All nine PR checks passed. The owner merged PR #68 into main as
`70f044c77f55080b84f2e71c8f727bfcf5b61db3`. Main-branch CI, Rust 1.92,
dependency audit, Chromium Compatibility, Actions static analysis, and Scorecard
all passed. These results supersede the earlier pending/failed CI status.

[Chromium Compatibility on the merge](https://github.com/cyph3rpuNk-dev/Nomad-Launcher/actions/runs/38216758798)
verified the live archive/layout/overlays and built the validated launcher artifact.
The artifact is for review; it is not a tagged, attested release.

Release preparation is on `release/v1.0.9`: workspace and lockfile package versions
are advanced together, with release notes in `RELEASE-NOTES-v1.0.9.md`. Upstream
dependency versions are unchanged. Commit/push, release tagging, the attested draft
build, the owner's offline manifest signature, and publication remain pending.
The remaining live-platform/browser/recovery coverage gaps above remain open.

Local validation of the v1.0.9 preparation passed: 492 Rust tests, formatting,
Clippy, safeguard fixtures, and dependency auditing with the documented RSA
exception. Rust 1.92 workspace/all-target checking also passed. Four native HKCU
tests and nine live-upstream tests remain intentionally ignored in the local
gate; the earlier Sandbox and merged-main CI evidence is recorded separately.
Logs: `target/release-prep-v1.0.9-gate.log` and
`target/release-prep-v1.0.9-msrv.log`. Release-branch CI has not run yet.

## Supported launcher removals (2026-10-12)

The owner merged release preparation in PR #69 as `4cb30b7`. Release work is
paused for the requested removal of Bitwarden, standard Firefox, and Firefox ESR.
The workspace and distribution now contain six launchers: Chromium, Floorp,
Helium, LibreWolf, Mullvad, and Waterfox. The removed launcher crates and the
Bitwarden and Firefox adapters are gone, together with the embedded Mozilla key
`core/keys/firefox.asc` and its signing-key coverage check; no remaining adapter
used that key. The shared Gecko payloads under `core/payloads/firefox/` remain
because Floorp, Waterfox, and LibreWolf use them. Documentation and signing-key
checks reflect this supported set. Historical Sandbox evidence above remains a
record of the Firefox versions tested, not coverage of a supported launcher.

Distribution regression fixtures reject stale standard Firefox, Firefox ESR, and
Bitwarden binaries. Shared updater state-preservation and invalid-stage
regressions remain covered with an inert adapter. Gecko staging, hardening
withdrawal, and target-recording regressions that used the Firefox adapter now
use Floorp, and the shared-payload assertions moved to the Floorp adapter test.
The 12 tests of the Firefox adapter itself were removed with it. Existing
portable installations, profiles, vaults, and registration records are not
deleted or migrated by this source change.

Local validation passed: the canonical gate completed with 466 Rust tests,
formatting, Clippy, artifact guards, 36 build safeguard cases, release/CI
safeguards, and dependency auditing with the documented RSA exception. Rust 1.92
workspace/all-target checking passed. Four native HKCU tests, six live-upstream
tests, and two upstream extraction tests remain intentionally ignored. No fresh
live-browser or Sandbox checks were run for this removal, and
`scripts/check-signing-keys.sh` was not rerun against the network.

Logs: `target/remove-firefox-esr-gate.log` and `target/remove-firefox-esr-msrv.log`.
The earlier seven-launcher run is in `target/remove-launchers-gate.log` and
`target/remove-launchers-msrv.log`.
These changes merged in PR #70 after its checks passed. Release tagging, signing,
and publication remain pending.

## History cleanup and socket fixture follow-up (2026-10-12)

The owner approved correcting one historical commit identity and three merge
authors. A separate mirror backup was retained before rewriting 50 commits across
11 remote branches. Every rewritten tree and commit message matched its original;
all release tags remained unchanged. The atomic push used an explicit lease for
each branch. Release and Chromium Compatibility were temporarily disabled and
restored to active afterwards. Rewritten main is `b0b231e`; older hashes in this
document identify historical evidence. No release assets were rebuilt or replaced.

Main's Chromium Compatibility run 38270579753 failed in the oversized-XPI socket
fixture with Windows `WouldBlock` (10035). Both raw-socket fixtures accepted from
non-blocking listeners without restoring blocking mode. A delayed-request
regression reproduced a connection abort locally before the correction. Both
fixtures now restore blocking mode before applying bounded read/write timeouts.
This changes test code only.

The canonical gate passed with 467 Rust tests, formatting, Clippy, safeguard
fixtures, and dependency audit. The delayed-request regression and both affected
tests passed 30 repetitions each (90 executions). Logs are
`target/socket-repro.log`, `target/socket-fix-gate.log`, and
`target/socket-fix-repeat.log`. Rust 1.92 workspace/all-target checking also passed
(`target/socket-fix-msrv.log`). Ignored HKCU/live-upstream/extraction tests were
not run. The fix is local on `codex/fix-socket-fixtures`; publishing and fresh
Chromium Compatibility results remain pending.

## Socket fix delivery, signing-key coverage and Floorp Sandbox validation (2026-10-12)

The socket-fixture correction merged as PR #71; main is `4c4071a`. CI, Chromium
Compatibility, static analysis and Scorecard all passed on that commit, which
supersedes the pending statement at the end of the previous section. Duplicate
PR #65 was closed without merging.

`scripts/check-signing-keys.sh` then passed against live upstream metadata with an
isolated GPG home: Mullvad Browser's current signature issuer `316C1FACD62D07D9`
and uBlock Origin 1.75.0's issuer `F5630CAE62A14316` are both present in the
embedded keys. This compares issuer IDs with embedded keys; it downloads no
browser and verifies no package. No trust anchor changed. Log:
`target/signing-key-check-2026-10-12.log`.

### Floorp in Windows Sandbox

Earlier live Gecko evidence used the removed Firefox launcher, so Floorp was
exercised in a fresh Windows Sandbox session (Windows 11 Enterprise 10.0.26100).
The launcher was the unsigned `Nomad-Floorp.exe` built by Chromium Compatibility
run 38280168531 from `4c4071a`, SHA-256
`bd3b5c41d9d31dcaaa066bed2911479e5f1dff230c7100e900fb72391b1a76e7`, verified
against that run's `SHA256SUMS` on the host and again inside the guest. Only one
read-only input folder was mapped; clipboard, audio/video input and printers were
disabled, networking and GPU sharing enabled. Guest commands were typed by the
user. Results rest on host screenshots of the guest, and on the user's report
where stated. Raw guest files were not exported.

The launcher resolved Floorp 12.20.1, verified the installer's SHA-256, extracted
it, and provisioned uBlock Origin 1.75.0 after AMO digest verification. Before
that, two release lookups failed with `error sending request` and the launcher
refused to continue with nothing installed. The user reports a slow host VPN at
the time and that the download began once it was switched off; that cause was
not independently verified.

Two defects were found on the first start:

- **Floorp cannot start on Windows without the Visual C++ runtime.**
  `floorp.exe` exited with `0xC0000135` and Windows reported
  `VCRUNTIME140_1.dll was not found`. `vcruntime140.dll`, `vcruntime140_1.dll`
  and `msvcp140.dll` were absent from both the guest's `System32` and the
  installed browser folder. The official 12.20.1 installer (GitHub digest
  `5e76245db2af763c59bc53dcf06ab391869752e230fa93dfa905ac9baaa3184b`, matched
  and listed on the host with the bundled 7-Zip without executing it) contains
  none of them, so Nomad's extraction did not drop them. A host-side string
  check of each installed portable browser's main executable found the same
  dependency without bundled files only for Floorp; LibreWolf and Waterfox
  bundle the three DLLs, and the Chromium, Helium and Mullvad executables do not
  reference them. That check is a heuristic, not a dependency audit.
- **The launcher reported that failed start as a success.** It logged
  `browser launched`, exited 0 and showed no error. The watcher's `OpenProcess`
  failed 26 ms after spawn and no Floorp process existed five seconds later; the
  profile folder held only Nomad's own `user.js`.

Neither defect was introduced by the launcher removals. Both remain open; how to
address them before v1.0.9 is an owner decision.

To continue, the Microsoft Visual C++ Redistributable x64 14.44.35211.0 was
installed inside the guest only, from Microsoft's download link, after its
Authenticode signature validated as Microsoft Corporation. Every result below is
therefore for clean Windows 11 plus that runtime:

| Check | Result |
|---|---|
| Start through the launcher | Pass. `about:support` shows the program at `C:\NomadSmoke\Production\Floorp\Browser\floorp.exe`, the profile at `...\Floorp\Data`, and enterprise policies active. |
| Close and relaunch | Pass. Exit 0 and unchanged version marker on three relaunches; bookmark and enabled uBlock Origin retained (user report, later screenshot-confirmed). |
| Hardening off/on | Pass. Off removed `nomad.cfg`, `autoconfig.js` and the managed `user.js` block and kept `policies.json`; on restored all of them and `nomad.toml` matched its saved original hash. Effective preference behavior was not inspected. |
| Offline launch | Pass with cached release metadata: guest adapter disabled, launcher exit 0, browser launched, adapter restored. Only the extension update check reached the network path and fell back; an offline browser release lookup was not exercised. |
| Registration | Pass. Exit 0; owner, location-scoped key plan and HKCU command/capabilities matched; the picker entry names the instance folder. The user selected it for `.htm`, `.html`, HTTP and HTTPS; Windows also assigned FTP, which was not verified. |
| URL and local HTML handoff | Pass with the browser open (window process retained) and closed (no provisioning or update); pages opened in the same portable profile, shown by restored session tabs. Marker and executable unchanged. |
| Unregistration | Pass. Exit 0; planned keys, registered-app value and sidecar absent; `floorp.exe`, version marker and `places.sqlite` hashes unchanged. |

Floorp left `C:\ProgramData\Noraneko-1de4eec8-1241-4177-a864-e594e8d1fb38`
(three small updater/shortcut records) and empty `Floorp` folders under the
guest user's local and roaming application data. They were still present after
the browser exited. This matches the documented conservative cleanup, which
preserves shared browser directories it cannot attribute.

Not exercised for Floorp: update from an older version, interrupted download and
retry, post-replacement rollback, a second copy, an empty instance refusing
protocol provisioning, extension blocking behavior, Windows 10 and software
rendering. Waterfox, LibreWolf, Mullvad and Helium still have no live coverage.

Evidence is preserved outside the repository at
`Documents\Nomad-Launcher-Evidence\2026-10-12-floorp-4c4071a` on the owner's
machine: 16 screenshots, the guest helper scripts and Sandbox configuration, the
launcher manifest, a results README and a checksum list. No release tag, signing
or publication has been performed.

## Start-up failure reporting (2026-10-12)

The Floorp documentation merged as PR #72; main is `c5a252e`. The owner chose to
correct the launcher's false launch report and to document Floorp's runtime
requirement before v1.0.9.

`do_launch` and the "Launch anyway" fallback treated successful process creation
as a launch. Both now start the browser through `spawn_browser`, which polls the
new process for one second. A process that ends in that window with a Windows
NTSTATUS error (`0xC0000000`-`0xCFFFFFFF`) is returned as the new
`BrowserError::Startup`: the error screen stays open, "browser launched" is not
logged and the cleanup watcher is not started. `0xC0000135` names the Visual C++
Redistributable as the usual cause. Ordinary exit codes remain a successful
launch, because a browser's first process may exit immediately after handing
over to a running instance or to a child. Verification, update, ownership and
registry behavior are unchanged, and no browser is installed or modified.

Five tests cover this with inert `cmd.exe` and `ping.exe` children in place of a
browser: loader-failure and crash codes are refused, ordinary exit codes and a
still-running process count as launched, only the NTSTATUS error range is
classified as a failure, and the fallback path keeps the error visible without
starting post-launch work. With the watch temporarily bypassed, the two
regression tests and the watch-length test failed; the change was then restored
byte-for-byte. `do_launch` itself is not called by a test, because its
preparation step runs the HKCU self-registration repair; its use of
`spawn_browser` is a one-line substitution reviewed by reading.

Limits. The watch is one second, so a browser that fails later is not detected.
The Sandbox helper started the launcher from Windows PowerShell with shell
execution disabled, and Floorp then exited silently within 26 ms; started
directly with `Start-Process`, the same `floorp.exe` instead showed Windows'
missing-DLL dialog and stayed alive until it was dismissed. The silent exit may
therefore depend on an error mode inherited from the parent process. Starting
the launcher from Explorer on a Windows without the runtime was not tested. If
Windows shows its dialog there, the process outlives the watch, the launcher
still reports a launch, and Windows' message is the only notice. The corrected
launcher has not been run against a real browser or in Sandbox.

README now states that Floorp needs the Microsoft Visual C++ Redistributable
(x64) and adds a troubleshooting entry; SPEC describes the start-up watch.
Nomad does not download, bundle or install that runtime.

Local validation passed: the canonical gate with 472 Rust tests, formatting,
Clippy, artifact guards, 36 build safeguard cases, release/CI safeguards and the
dependency audit with the documented RSA exception; Rust 1.92 workspace and
all-target checking also passed. Four HKCU, six live-upstream and two extraction
tests remain intentionally ignored. Logs: `target/startup-failure-gate.log` and
`target/startup-failure-msrv.log`.

## Start-up watch in Sandbox and Explorer-launch follow-up (2026-10-12)

The start-up watch merged as PR #73; main is `8cff3e8`, with CI, Chromium
Compatibility, static analysis and Scorecard passing. The four merged working
branches from this cycle were deleted after their tips were confirmed in main.

The CI-built `Nomad-Floorp.exe` from `8cff3e8` (Chromium Compatibility run
38314176711, SHA-256
`a40be9278f81b86fb8990c7faef7008b55134a33b0e86b8195b01013b5e8edfa`) was
exercised in a second fresh Windows Sandbox session without the Visual C++
runtime, with the same isolation settings. Guest commands were typed by the
user; results rest on host screenshots.

| Case | Result |
|---|---|
| Launcher double-clicked in Explorer, runtime absent | Not caught. Windows showed `floorp.exe - System Error`, `VCRUNTIME140.dll was not found`. The launcher logged `browser launched` and started the cleanup watcher; the failed process stayed alive for 1 min 44 s until the dialog was dismissed. The profile held only Nomad's `user.js`. |
| Launcher started from Windows PowerShell, runtime absent | Caught. The error screen showed the missing-runtime message; the log has `browser failed to start` and no launch or watcher line. The launcher still exited 0 after the user closed the error. The three-line message pushed Retry, "Launch anyway" and Close below the fixed-size window. |
| Launcher double-clicked, runtime installed in the guest | Pass. Floorp started (11 processes, 116 profile files), `browser launched` was logged and the watcher ran. The first `floorp.exe` process had exited within about 25 ms of creation and was correctly treated as a launch. |

The first two rows differ because of the inherited Windows error mode. Windows
PowerShell reports `SEM_FAILCRITICALERRORS` (measured on the host as `0x8001`),
and child processes inherit it, so a load failure ends the browser at once. A
launcher started from Explorer has the default mode, so Windows shows its own
dialog and keeps the failed process alive beyond the one-second watch. This
confirms the limit recorded in the previous section.

Follow-up changes:

- `spawn_browser` now adds `SEM_FAILCRITICALERRORS` to the launcher's error mode
  before creating the browser process, on both launch paths. The browser
  inherits it. Microsoft recommends that applications set this mode; every
  earlier Sandbox browser run in this audit already had it through the
  PowerShell helpers. Windows' own dialog for this class of failure is no longer
  shown for the launcher or the browser; Nomad's error screen replaces it.
- The missing-runtime message is shortened to fit two lines.
- The error screen reserves the button row first and lets a long message scroll,
  so the buttons cannot leave the fixed-size window. A headless layout test at
  the real window size measured the button row at 327-345 pt for a one-line
  message, 341-359 pt for the missing-runtime message, and 351-369 pt for longer
  messages, inside a body that ends at 372 pt.

Three tests were added. The error-mode test failed with the call bypassed, and
the layout test failed while the message area was unconstrained (buttons at
355-373 pt); both pass with the changes. The layout test checks geometry, not
rendered pixels.

Local validation passed: the canonical gate with 475 Rust tests, formatting,
Clippy, artifact guards, 36 build safeguard cases, release/CI safeguards and the
dependency audit with the documented RSA exception; Rust 1.92 workspace and
all-target checking also passed. Logs: `target/startup-dialog-gate.log` and
`target/startup-dialog-msrv.log`. The follow-up has not been run in Sandbox: the
Explorer-launch case with the runtime absent, and the visible error screen,
still need a live check. Evidence for the session above is preserved outside the
repository at `Documents\Nomad-Launcher-Evidence\2026-10-12-floorp-startup-8cff3e8`.

## Gecko site-compatibility defaults (2026-10-13)

The owner requested enabling both "Fix major site issues" and "Fix minor site
issues" under Strict ETP for Floorp, LibreWolf, and Waterfox. Mozilla's preferences
UI binds these to `privacy.trackingprotection.allow_list.baseline.enabled` and
`privacy.trackingprotection.allow_list.convenience.enabled`. Floorp's shared
payload previously enabled baseline but disabled convenience; the Waterfox and
LibreWolf payloads did not explicitly set either preference. All three now set
both to true. No ETP category or uBlock rule was changed. This permits browser
compatibility exceptions that can allow tracking elements.

The preferences are supplied through the existing fenced `user.js` mechanism
with Nomad hardening enabled, for both new and existing profiles. They are not
locked; managed values are reapplied at browser startup. A regression upgrades
an older managed block with both values false, checks all three adapters'
payloads, preserves surrounding user content, and verifies repeated writes are
idempotent. Browser startup, upstream preference locks/migrations, and checkbox
appearance were not exercised: these still need live validation for each browser.

Local canonical validation passed with 473 Rust tests, formatting, Clippy, 36
build safeguard cases, remaining safeguard fixtures, and dependency audit with
the documented RSA exception. Rust 1.92 workspace/all-target checking passed.
Logs: `target/gecko-site-compatibility-gate.log` and
`target/gecko-site-compatibility-msrv.log`. Ignored HKCU and live upstream tests
were not run. Changes are local on `codex/gecko-site-compatibility`; PR #74's
Explorer startup/button fix remains separate. No commit, push, or CI run has
been performed for this compatibility change.

## First-start ETP migration follow-up (2026-10-13)

PR #75 merged the preference change as `8824273`. Its main Chromium Compatibility
run 38375297765 initially failed with a GitHub 403 rate limit, then passed on the
owner-approved rerun, including archive verification and artifact building.

The CI-built Floorp launcher (SHA-256
`8aa0550a47ad8ea73e567a35b2cd000bae18110369de45c179965e0065eb3a1f`)
was used in a fresh Windows Sandbox with the Microsoft-signed Visual C++ x64
runtime installed successfully in the guest. Floorp 12.20.1's first-start settings
screenshot showed Strict selected but both site-fix checkboxes unchecked. The
subsequent `about:config` screenshot showed both enabled preferences false,
`hasMigratedCategoryPrefs` true, and no lock on the enabled preferences. These
observations supersede any assumption that profile-file values prove the live UI.

Mozilla's Firefox 157.0.1
[exception-list service](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_157_0_1_RELEASE/netwerk/url-classifier/UrlClassifierExceptionListService.sys.mjs)
sets the migration marker and disables both lists for Strict/Custom profiles if
that marker was previously false. Floorp's runtime lock identifies Firefox
157.0.1. This source behavior is consistent with the observed first-start failure.
The three Nomad payloads now record the explicit opt-in by setting
`privacy.trackingprotection.allow_list.hasMigratedCategoryPrefs` true before
startup, together with both enabled preferences. No preference is locked.

The profile-upgrade regression failed before adding the marker and passes with
it for Floorp, LibreWolf, and Waterfox. Canonical validation passed (473 Rust
tests and all safeguard fixtures), as did Rust 1.92 workspace/all-target checking.
Logs: `target/gecko-migration-regression-before.log`,
`target/gecko-site-migration-gate.log`, and `target/gecko-site-migration-msrv.log`.
The regression checks managed profile contents, not execution of Gecko's service.
Fresh-profile and restart validation of the corrected build remain pending;
LibreWolf and Waterfox effective behavior remains untested. Follow-up changes are
local on `codex/gecko-site-fixes-migration`, uncommitted and unpushed.

The owner then closed Floorp completely and used the same `8824273` launcher to
relaunch. Screenshot `Screenshot 2026-10-13 060817.png` shows Strict selected and
both site-fix checkboxes checked, with launcher exit 0 and the expected launcher
hash. The helper also printed the previous on-disk `prefs.js` values as false;
the running browser's settings UI is the effective-state evidence, since that
file may retain the last saved session's values until clean exit. This confirms
the existing build's settings apply after the migration has completed. It does
not validate first startup with the corrected payload or the other two browsers.

The corrected local Floorp build was then started in the separate, previously
absent `C:\NomadSmoke\SiteFixes\FloorpMigration` instance. Screenshot
`Screenshot 2026-10-13 061451.png` confirms Strict selected and both site-fix
checkboxes checked on the first opening of Privacy & Security, with launcher
exit 0 and all three preferences true in the managed `user.js`. The helper
verified launcher SHA-256
`C1F7F7C0418D4F66E2BDC8D6C2384F68AD8EFF2242BA69CD575A2CC4CB3EB5C9`.
This is an unsigned local release-mode test build based on `8824273`, with patch
SHA-256 `A9D55FEA0790E8BE7893E5D08DBB5CA68D70A6B96B726DDBCDCFFEE8AB6C06F7`;
it is not a CI or published release artifact. The binary passed the artifact
guard before being copied to the read-only Sandbox input. This establishes
first-start behavior for Floorp 12.20.1; corrected-build restart/persistence and
LibreWolf/Waterfox live coverage remain pending.

After a full close and relaunch through `Test-Floorp-Migration.ps1 -Mode Relaunch`,
the owner confirmed both checkboxes, the `Nomad site fixes test` bookmark, and
enabled uBlock Origin remained intact. This completes the corrected local
Floorp build's first-start and restart checks. The restart observations are
user-confirmed; no additional screenshot or raw profile export was supplied.

### LibreWolf settings verification and download limitation

The direct Sandbox download of LibreWolf 157.0.1-1 was very slow and failed with
`offline or rate-limited: error decoding response body`; two failures are visible
in screenshot `Screenshot 2026-10-13 073350.png`. A ten-second file-growth sample
had earlier received 12,910,592 bytes, so it was intermittently progressing.
The owner reported no VPN. Bounded host probes of the official CDN showed marked
route variation: Rome delivered approximately 8-300 KiB/s in curl/reqwest samples,
while the observed Paris route delivered approximately 3-5 MiB/s. Nomad's
reqwest/native-TLS client transferred 16 MiB from the Paris route in about five
seconds. Its slow-route sample timed out with an underlying `operation timed out`
error, exposed to the user as `error decoding response body`. These are host
measurements; the guest route comparison did not complete, so the guest's exact
route and underlying failure were not independently established. No permanent
DNS override, endpoint replacement, or download-policy change was made.

The owner instead completed the download in a new host test folder using
`Nomad-LibreWolf.exe`. Its SHA-256 matched the original `8824273` CI artifact,
`56511A43760C50ABC91E424D017D2A3EE0C0436C0E7A2FC73EBB263778DC8295`.
The host screenshot showed both site-fix checkboxes selected. At the owner's
request, only the downloaded `Browser` bundle and its authentic installed marker
were copied into the read-only Sandbox input. All 61 copied files matched the
source SHA-256 inventory. The host `Data` and `Nomad` folders were excluded.

The corrected local launcher (SHA-256
`7E5A498FB13E3E1A8413225359B5DB3CFDDC293D7972A4BAB2BE86B88D9F9787`)
then launched the imported bundle in the previously absent guest instance
`C:\NomadSmoke\SiteFixes\LibreWolfImportedMigration`, with a fresh profile and
browser update checks disabled only in that disposable instance. Screenshot
`Screenshot 2026-10-13 073350.png` shows launcher exit 0, all three managed
preferences true, Strict selected, and both checkboxes checked. This validates
LibreWolf's first-start effective settings with the corrected payload; it does
not establish a successful Sandbox package download. Restart, bookmark/extension
preservation, and Waterfox settings verification remain pending.

The owner subsequently confirmed that both LibreWolf checkboxes, the
`Nomad site fixes test` bookmark, and enabled uBlock Origin remained intact after
a full close and relaunch through `Test-LibreWolf-Imported.ps1 -Mode Relaunch`.
This completes first-start and restart settings checks for the corrected local
LibreWolf launcher using the imported bundle. The restart result is user-confirmed;
no additional screenshot was supplied. Waterfox verification remains pending.

### Waterfox first-start check

Screenshot `Screenshot 2026-10-13 074337.png` shows the corrected local Waterfox
launcher (SHA-256
`441EF7318B1229E7B485E844C6FA451450AE311AF36A9F6F48B530317E222019`)
starting the previously absent `C:\NomadSmoke\SiteFixes\WaterfoxMigration`
instance with exit 0. Its package SHA-512 and uBlock XPI AMO SHA-256 verification
are visible in the console. All three managed allow-list preferences are true;
the settings UI shows Strict and both site-fix checkboxes selected on first
start. The screenshot also shows Waterfox's existing Resist Fingerprinting
notice, which this change does not alter. Restart and bookmark/extension
preservation remain pending. This is the unsigned local test build, not CI or
release validation.

The owner confirmed both Waterfox checkboxes, the `Nomad site fixes test`
bookmark, and enabled uBlock Origin remained intact after a full close and
relaunch through `Test-Gecko-Migration.ps1 Waterfox -Mode Relaunch`. The restart
result is user-confirmed; the requested version-marker output was not supplied,
so this record does not assert the exact installed Waterfox release.

The corrected local builds now have first-start UI evidence and user-confirmed
restart/bookmark/extension preservation for Floorp, LibreWolf, and Waterfox.
These checks establish the requested defaults and persistence, not general
website compatibility, upstream-list effectiveness, or all-browser validation.
The LibreWolf bundle import and disabled guest update checks remain explicit
limitations. The migration follow-up is still local, uncommitted and unpushed.

## Delivered settings/title changes and PR #74 Explorer validation (2026-10-13)

The migration follow-up merged in PR #76 as `f267a56`; all nine PR checks and
merged-main workflows passed. PR #77 then merged the shared title format
`Nomad Launcher - <DisplayName>` as `6acd935`, again with all PR/main checks
passing. The actual CI-built Floorp title was observed in Sandbox, with exit 0,
unchanged installed marker, and owner-confirmed bookmark/uBlock preservation.

Session evidence is preserved at
`Documents\Nomad-Launcher-Evidence\2026-10-13-final-session-6acd935`. Its guest
archive is 58,060 bytes, SHA-256
`6CCDA928B7A5DC3062A3783C014AA3EB27C07FB7384F10532F5724B71C357DE6`.
All 27 exported files matched their manifest hashes, with 34 additional hash-only
references. Scope/path checks passed before extraction. The temporary receiver
closed and its upload credential was removed. Original screenshot PNGs were not
available at their attachment paths; the host summary identifies the images and
records conversation observations without claiming the PNGs were archived.
Exported markers confirm Waterfox 6.7.5. Selected extension metadata corroborates
active uBlock Origin 1.75.0 in Floorp and Waterfox; LibreWolf's selected export
contained no matching add-on record, so its enabled-state result remains
owner-confirmed. The owner accepted LibreWolf's Sandbox download interruption
as non-blocking; the exact guest cause is unconfirmed and no downloader changed.

PR #74's original CI build `6bf2b595b787512390337b2acc93a30e09fd6e41` was then
tested in a fresh Windows Sandbox, using its run 38323528288 artifact. Floorp
launcher SHA-256:
`72F3DE7AECE2757444C6ED870BA5A052F74E5B095AA5FEC3DF4881D0A8AF3AF1`.
This snapshot predates the title/settings changes; the old title in its
screenshots does not indicate a regression in current main.

- With `vcruntime140.dll`, `vcruntime140_1.dll` and `msvcp140.dll` absent, an
  Explorer double-click produced Nomad's `0xC0000135` startup error. Retry,
  Launch anyway, and Close were visible. The read-only status output confirmed
  parent `explorer.exe`, zero Floorp processes, and `browser failed to start`
  plus the pipeline error at 17:26 UTC. No successful-launch/watcher event was
  recorded for that attempt. Screenshots 122709 and 123114 are the UI evidence.
- The owner installed Microsoft Visual C++ x64 14.44.35211.0 inside the guest
  only. The helper reported a valid Microsoft signature, installer exit 0,
  SHA-256 `CC0FF0EB1DC3F5188AE6300FAEF32BF5BEEBA4BDD6E8E445A9184072096B713B`,
  and all three DLLs present afterwards.
- A subsequent Explorer launch produced `browser launched` at 17:46 UTC and
  11 running Floorp processes. The watcher logged `OpenProcess failed` for the
  initial PID, consistent with a short-lived startup process, then waited for the 11
  remaining processes by executable path. The blank-titled Nomad process in
  this status output was the cleanup watcher. Earlier error lines in the same
  log belong to the pre-install attempt. The installed marker is Floorp 12.20.1.

This validates the tested PR #74 build's missing-runtime Explorer path and normal
launch with the runtime, plus the visible error buttons. It does not establish
late-crash detection, every long-message scrolling case, or a new all-browser
startup campaign. The follow-up is being integrated locally with `6acd935`,
preserving its title and migration defaults. The refreshed PR checks have not
run, and no GitHub merge or release has been performed.

The local integration passed the canonical gate with 476 Rust tests, formatting,
Clippy, 36 build safeguard cases, the remaining safeguard fixtures, and dependency
audit with the documented RSA exception. Rust 1.92 workspace/all-target checking
also passed. Logs: `target/pr74-integration-gate.log` and
`target/pr74-integration-msrv.log`. Four native HKCU, six live-upstream, and two
extraction tests remain intentionally ignored. The combined source retains
`Nomad Launcher - <DisplayName>` and the migration marker in all three Gecko
payloads. Changes are local on `codex/pr74-integration`, with a history-preserving
merge prepared but not committed or pushed.

Startup-session evidence is independently verified at
`Documents\Nomad-Launcher-Evidence\2026-10-13-pr74-startup-6bf2b59`. The archive
is 4,764 bytes, SHA-256
`16FCC4B2786A7DE1CC15599ACFBC5F21F332A8418076687342601922961A528C`.
All six exported files matched their manifest hashes, with eight hash-only
references; scope/path checks passed before extraction. The guest was Windows 11
Enterprise 10.0.26100, and all three runtime DLLs were present at export. The
receiver completed and closed, its listening port was confirmed closed, and its
one-use upload credential was removed. The permanent directory includes the
archive, receipt, verification report, extracted records, helper snapshots,
integration logs, and a checksum inventory. Original screenshot PNGs were not
available at the supplied attachment paths and are not included.

## PR #74 delivery and final CI artifact review (2026-10-13)

The history-preserving integration was committed as `88be5b9`, pushed to the
existing PR #74 branch, and merged with owner approval as
`3202cce78dfb720070d4173359fbf83be0090140`. All nine PR checks passed. One live
Chromium verification run initially returned HTTP 403 (rate limit exceeded);
the other run for the same commit passed, and the failed job passed on rerun.
No source change or verification bypass was needed for that failure.

All four workflows for merged main passed: CI (38457591280), Chromium
Compatibility (38457591311), Zizmor (38457591302), and Scorecard (38457591267).
This supersedes the pending integration/CI statements above.

The merged-main `chromium-compatible-launchers` artifact (ID 11844529286) was
downloaded into `target/release-review-v1.0.9-3202cce`. Its 42,197,911-byte ZIP
matched GitHub's SHA-256 digest before extraction:
`5c4182ebf45c3f95f31f6d445052be884daef2d852bbe60c560871dde5622b8f`.
Bounded archive/path checks passed. All six expected launchers (Chromium,
Floorp, Helium, LibreWolf, Mullvad, Waterfox) matched `SHA256SUMS` and passed the
PE artifact guard without execution. The artifact includes license files and
third-party/trademark notices; `VERIFICATION.json` records the review.

These are CI review builds, not a tagged or attested release. The published
release remains v1.0.8. A v1.0.9 tag, release-workflow build, provenance review,
owner's offline checksum-manifest signature, and publication remain pending.
The documented live-platform, browser and post-replacement recovery gaps are
unchanged. No launcher was executed or host configuration changed for this
artifact review.

## Privacy/security follow-up, first local patch (2026-10-13)

Base tree: `e86307a944d98cae20d5d64dab5f4008c0eb69a3`, identical to
release candidate `bc3f8891af4ae8e86de706c09a9b0896d8df785f`. This entry
records local implementation/validation, not a pushed commit or release approval.

- Floorp/Waterfox autoconfig now defaults general extension updates to enabled
  without locking those preferences. Nomad's separate uBlock verification remains.
- Cleanup workers acquire an owned per-folder `Nomad/cleanup.lock`; duplicate
  workers exit before exit actions. The OS releases the lock when its worker dies.
  This does not replay cleanup missed after power loss or drive removal.
- Opt-in thumbnail clearing never terminates/restarts Explorer. On Windows it
  holds a handle that denies readers/writers while deleting; active readers are
  preserved even when their handles permit deletion. Shared unlocked cache files
  can still be removed, and complete clearing is not guaranteed.
- Dependency audit requires clean JSON output, captures stderr and rejects
  registry diagnostics even with exit zero. Fixtures cover the observed timeout
  behavior, malformed/missing output, vulnerabilities and warning categories.
- Public/configuration descriptions now distinguish restricted Chromium WebRTC
  from disabled Gecko peer connections and disclose retained profile data,
  update bypass on protocol launches, component-update suppression and the broad
  legacy Prefetch scope. The third-party notice identifies 7-Zip 26.04.

`pwsh -NoProfile -File scripts/check.ps1` passed after these code changes:
466 core unit tests, 12 integration tests and 2 upstream-metadata regressions,
plus artifact, build, release, CI and audit fixtures. Dependency audit completed
with a clean structured report and no registry diagnostics. Native registry and
live-upstream tests remain ignored; no browser, real host cleanup or installer
was run. Real Windows handles were tested only on owned temporary cache fixtures.

Release remains on hold. Still open: a safe security-component update path
(Helium couples component access to the disabled browser-updater preference),
visible freshness handling for users who only launch links, path-attributed
Prefetch handling, real Recent/WER coverage, critical hardening failure reporting,
cleanup recovery and effective browser/DNS/extension-update validation. This
patch does not close the full independent review or raise its rating by itself.

## Helium component capability follow-up (2026-10-13)

The preceding patch was committed locally as
`e5e6fa0d2d70bdfdd675ac5b5c2b1134c84096ee` on
`codex/privacy-security-followup`; it has not been pushed.

Source inspection of Helium Windows 0.19.2.1 found the newer native
installer-eligibility guard introduced by upstream #408. The reviewed source
requires an installed/versioned module directory and rejects Nomad's ordinary
flat bundle for automatic checks, manual About-page checks and installer runs.
See [Helium component-update safety](HELIUM-COMPONENT-UPDATES.md) for pinned
source revisions, the published package digest and the live-validation gap.

The next local patch permits components only for the reviewed x64 0.19.2.1
marker plus validated flat layout. It removes the component-disable switch
for that capability and seeds the native update default in first-run profiles.
Existing Preferences and service/schema consent remain byte-for-byte unchanged.
A false preference may be an old Nomad override or a user choice; enabling it
requires an explicit browser-settings choice. Other versions/targets retain
both the preference and command-line block. This does not block Nomad browser
updates for unreviewed versions and does not add a component downloader.

The Windows canonical gate passed: 471 core unit tests, 12 integration tests
and 2 metadata regressions (485 total), plus safeguard fixtures and the completed
structured dependency audit. A separate read-only live metadata check passed:
`helium_release_is_verifiable` resolved 0.19.2.1 with required SHA-256. No browser
or installer was launched and no component was downloaded by these checks.

The capability patch is local/uncommitted. Release remains on hold pending
Sandbox evidence that CRLSet refresh succeeds while automatic/manual installer
updates remain ineligible, including first-run and existing profiles.
Ungoogled Chromium component updates, link-only freshness handling and the
other independent-review findings remain open.

A local unsigned test launcher was built with
`cargo build --release --locked --target x86_64-pc-windows-msvc -p nomad-helium`
and passed the metadata-only PE guard. Its SHA-256 is
`FAE26E64AFD0B49D8CB9633EE0E3D11297EFD2F3D0A5F8EEADD48B1F1456BA42`.
The previous generated executable was preserved before building.

Prepared fixture:
`target/helium-components-e5e6fa0-ebfa255756cd43ee949f302d3a38e0f2/Nomad-Helium-Components.wsb`.
The host payload is read-only and contains no host profile. It opens instructions
only; a Sandbox-account-guarded helper invokes Nomad with freshly fetched, pinned
0.19.2.1 release metadata. No installed-version marker or browser binaries are
fabricated/imported. Relaunch preserves the guest instance and profile and
refreshes the test's authentic pinned metadata. XML/PowerShell 5.1 syntax and
the host-refusal path passed. No Sandbox/browser was started by preparation.

### Partial live Helium observations

User-provided Sandbox output and screenshots dated 2026-10-13 identify the
unsigned test launcher above and reviewed Helium 0.19.2.1 / Chromium 155.0.8059.39.
Initial service setup was incomplete and component access was disabled. After
user-completed setup with service access/updates enabled, CRLSet changed from
0.0.0.0 to **10833**, status **Updated**. This is a live component-refresh pass
for this guest, not a universal installer-safety or release pass. The user also
confirmed the test bookmark and built-in uBlock present. Widevine reported an
update error and remains unverified. About showed the browser version without
updater controls; native installer blocking, side effects, relaunch preservation,
network destinations and an older blocked-profile migration remain pending.

Screenshots were inspected as conversation attachments. Their supplied local
paths were unavailable when archive copying was attempted; no screenshot files
have been archived in the fixture. No personal browser profile was copied. These
results do not close the other outstanding independent-review findings.

The subsequent user-run Relaunch check shows the first browser exited fully
and another launch used the same reviewed instance. CRLSet remained **10833 /
Up-to-date**, the service update preference and schema acceptance persisted,
and the user confirmed bookmark/uBlock and enabled service controls remained.
This closes that observed relaunch check. Widevine remains an unexplained update
error. Installer runtime evidence and previously blocked-profile migration are
still pending. A Sandbox-guarded read-only helper was prepared to inspect the
loaded executable/DLL paths against the reviewed upstream eligibility rule;
the subsequent output and inference are recorded below.

The user subsequently ran the read-only layout inspector: the main process
loaded `Browser/chrome.dll` beside `Browser/chrome.exe`, the versioned child
was absent, and no component-disable switch was present. Applying the reviewed
upstream installer rule to those observed paths excludes this flat layout;
this remains a **source-rule inference**, not an instrumented native-function
result. No pending installer markers/helper were present in this snapshot.
The user-provided transcript is preserved in the ignored fixture; About with
services enabled, independent guest evidence transfer, network destination
capture and a formerly blocked-profile migration remain pending. No broad
absence of installer side effects or release clearance is claimed.

The final supplied About/services screenshots show automatic updates and service
access enabled while About has no update controls/status or visible installer
UI. Together with the loaded-path snapshot and pinned upstream source, this
supports the reviewed flat-layout separation. It is not an instrumented native
function result or exhaustive installer/network history. A bounded Sandbox-only
exporter (full profiles, cookies/history/bookmark contents and binaries excluded)
passed syntax/host-refusal checks; the private single-upload receiver is ready.
Independent archive transfer and validation remain pending, along with Widevine,
network destination capture and previously blocked-profile migration.

### Helium guest evidence independently preserved

The guest exported 6 collected files plus manifest and 9 hash-only references.
Host ZIP size is 4,011 bytes and SHA-256 matches the guest:
`845A05D6B509588F9020DD29F2C4CE8AC0CDC9B10836AEF2C3F8E242E971D797`.
Independent in-memory validation checked exact archive paths, every declared
file size/digest, build/source identity, selected service settings and CRLSet
manifest version 10833. Malformed/private archive refusal checks passed.
No extraction or full profile/browser-binary copying was performed. The private
single-upload receiver completed and exited; no firewall settings were changed.

Evidence and `HOST-VERIFICATION.json` are preserved under the ignored fixture's
`evidence-transfer-e6ab4c903be145bb8fc59bfbed21758b/received/` directory.
The guest launcher hash matches test-build metadata, and runtime executable/DLL
hash inventory agrees with the user's prior transcript. The source/lockfile still
match the tested launcher metadata. Original screenshot files were unavailable
at the supplied local paths and remain conversation-only evidence. The expected
bookmark-file reference is absent; bookmark/uBlock preservation remains the
user's UI confirmation. Hash-only references are not independently computed
host hashes of the original guest files.

This completes independent preservation for the observed CRLSet-refresh and
relaunch session. The native installer conclusion remains a source-rule
inference supported by loaded paths and About/marker snapshots. Widevine,
older blocked-profile migration, live older-version handling and runtime network
capture remain unverified. Capability changes remain local/uncommitted, the
first patch remains unpushed, and release is still on hold.

## Prefetch retirement follow-up (2026-10-14)

The verified Helium capability/evidence patch was committed locally as
`dad9a993f4277ff7fd0fd0ba7b458afe9d9e5e3a` on
`codex/privacy-security-followup`. It and the preceding first patch are unpushed.

The next local patch retires Windows Prefetch deletion instead of attempting
ownership attribution from an executable-name prefix. The prefix list,
filesystem deletion routine and `ShellExecuteW` UAC path have been removed.
New cleanup worker arguments cannot include the retired scrub request; old
cleanup arguments ignore it, and a standalone legacy internal invocation only
logs a retirement notice and exits successfully. Existing boolean config keys
remain parseable without rewriting users' configuration. A true legacy value
logs a warning when cleanup is scheduled; new defaults omit the obsolete key.

Regression coverage checks legacy-config compatibility, both hardening modes,
absence of the retired worker argument, preservation of the separate thumbnail
request, legacy cleanup-flag parsing and the standalone no-op entry point.
No real host Prefetch files, UAC prompts, browser launch or installers were used.
The Windows canonical gate `pwsh -NoProfile -File scripts/check.ps1` passed:
471 core unit tests, 12 integration tests, 2 metadata regressions (485 total),
plus artifact/build/release/CI/audit fixtures and a completed clean dependency
audit without registry-check diagnostics. Native registry/live-upstream tests
remain ignored. `git diff --check` also passed.

README, SECURITY, SPEC, generated-config notes and UPDATE-SAFETY now state that
Windows Prefetch/execution paths remain and that cleanup does not request
elevation. The UPDATE-SAFETY description of always blocking Helium's updater was
also stale after the capability change: its file history last changed in the
first patch (`e5e6fa0`), whereas `dad9a99` changed the reviewed capability.
It now points to the exact consent/version/layout exception and live evidence.

This closes the broad Prefetch-deletion/elevation defect in the current working
tree; it does not provide forensic erasure. The retirement patch is local and
uncommitted. Still open: real Recent shortcut/WER coverage, missed-cleanup
recovery, critical hardening-write failure handling, link-only update freshness,
Ungoogled Chromium component handling, browser/DNS/runtime verification and the
remaining Helium limitations. Release remains on hold; no push/tag/release or
CI success is claimed for these local changes.

## Recent shortcut cleanup follow-up (2026-10-14)

The completed Prefetch retirement was committed locally as
`ca4633d676ddac433eff4248950de8242d90405a` on
`codex/privacy-security-followup`. The three follow-up commits remain unpushed.
The following Recent shortcut changes are uncommitted working-tree changes on
that base; they are not part of the release candidate or evidence-tested Helium
launcher.

**Verified in code:** The old exact `HasLinkInfo`-only gate rejected ordinary
Windows-created links with additional target/metadata records. It has been
replaced by the bounded parser/corroborator in `core/src/shell_link.rs:22` and
`core/src/shell_link.rs:330`, called from `core/src/cleanup.rs:209`. Recognized
local IDList, LinkInfo, Unicode and relative records must agree on an existing
ordinary target strictly inside the claimed portable folder. Built-in folder
anchor IDs/offsets are corroborated against their stored prefix and current
mapping (`core/src/shell_link.rs:573`). Unknown/override/network records,
conflicting representations, missing targets and reparse paths are preserved.
The old unused permissive parser and its synthetic-only tests were removed.

**Verified in code:** The Windows backend loads bounded bytes in memory and
requests native RAWPATH (`core/src/shell_link.rs:617`). It does not invoke
Resolve, Save, ShellExecute or target execution. Native decoding is still a
Windows trust boundary; PropertyStore internals are not independently parsed,
and filesystem metadata checks are not race-proof against a hostile writer.
The patch adds Windows API features to the existing `windows-sys` dependency;
`Cargo.lock` is unchanged.

**Tested:** `cargo test --locked --target x86_64-pc-windows-msvc -p nomad-core
windows_created_ -- --nocapture` passed all six native fixture tests on Windows
11 build 26200. The explicitly marked fixture helper saves links with Windows'
`WScript.Shell`, targeting inert owned files only. Fake host roots verify
removal of attributed ordinary/non-ASCII targets and preservation of unrelated
same-drive/sibling targets, missing files, conflicting IDLists/relative records,
unsupported/malformed metadata and incorrect folder mappings/offsets. IDList-only
coverage includes a derived fixture with optional LinkInfo removed; adverse
cases deliberately mutate real serialized metadata. Mixed slash styles in the
initial test target caused Windows to omit LinkInfo; normalizing test paths
provides real LinkInfo coverage without changing production refusal rules.

**Tested:** `pwsh -NoProfile -File scripts/check.ps1` passed formatting,
Clippy with warnings denied, 478 core unit tests, 12 integration tests and two
metadata regressions (492 total), artifact/build/release/CI/audit fixtures, and
a completed clean dependency audit without registry diagnostics. Four native
registry tests and eight live download/upstream tests remain ignored. No real
host Recent cleanup, browser launch, installer, persistent configuration writes
or hardware probes were used. `git diff --check` passed. The separate
`cargo +1.92 check --workspace --all-targets --locked --target
x86_64-pc-windows-msvc --target-dir target/msrv-1.92` compatibility check also
passed; this is compilation/type checking, not an additional MSRV runtime test.

**Documented:** README, SECURITY, SPEC and UPDATE-SAFETY now distinguish
recognized agreeing records from unsupported/conflicting records. The new
[Recent shortcut safety](RECENT-SHORTCUT-SAFETY.md) describes the allowlist,
native API choices, upstream Microsoft contracts and residual limits. The prior
docs were last changed by `ca4633d` before this parser existed; the earlier
synthetic-only implementation did not substantiate ordinary Windows shortcut
coverage.

**Not tested / remaining:** Windows 10 and Explorer-generated Recent links from
actual browsing sessions have not been replayed for this patch. Native decoder
side effects/network activity were not instrumented. Real WER coverage,
per-user WER handling, missed-cleanup recovery, critical hardening-write failure
handling, link-only update freshness, Ungoogled Chromium component handling,
other browser/DNS runtime checks and remaining Helium limitations remain open.
Release remains on hold; no push, merge, tag, release or remote CI result is
claimed for this working-tree patch.

## WER ownership and coverage follow-up (2026-10-14)

Base HEAD remains `ca4633d676ddac433eff4248950de8242d90405a` on
`codex/privacy-security-followup`. The preceding Recent shortcut patch was
already uncommitted and in scope at the start of this follow-up. WER changes
and documentation are also local/uncommitted. No branch push, merge, tag,
release or remote CI result is claimed.

**Verified in code:** The previous WER implementation scanned only ProgramData
queues/archives and called canonicalize on AppPath without rejecting target aliases.
That allowed an alias to an owned image to pass attribution and did not cover
per-user reports. The revised host paths include LOCALAPPDATA
(`core/src/cleanup.rs:18`); both conventional roots use the same scanner
(`core/src/cleanup.rs:424`). AppPath must be one bounded valid text field and
identify the exact existing browser image. Owned-folder lexical checks precede
filesystem lookups; reparse, parent, network and device paths are refused
(`core/src/cleanup.rs:310`). Embedded NULs and duplicate fields preserve reports
(`core/src/cleanup.rs:242`). Other images within the owned folder are insufficient.

**Verified in code:** WER deletion no longer uses recursive remove_dir_all.
Preflight accepts at most 256 ordinary files in one flat report folder and
opens all files with Windows sharing guards before mutation
(`core/src/cleanup.rs:347`). Linked/nested/unreadable/over-budget reports remain
untouched at preflight. Attribution is reread through its held metadata handle,
attachments are unlinked in deterministic order, Report.wer is removed last,
and only an empty folder can be removed (`core/src/cleanup.rs:376`). An
attachment deletion failure can leave partial contents but retains attribution
for a later completed session. A new entry/final directory error after metadata
removal can still leave an unattributed remainder; this is not a transaction
or hostile-host race defense. No privileges, WER APIs or reporting settings
are changed.

**Documented / corrected mismatch:** The current-user WER gap was confirmed
in the prior code and is addressed by this patch. The hypothesis that raw dumps
are always preserved was too broad: attributed report directories could already
contain deleted dump attachments, while standalone CrashDumps were kept.
README, SECURITY, SPEC, UPDATE-SAFETY and the earlier summary row now distinguish
these cases, disclose sensitive memory retention and OS upload limits, and link
[WER cleanup safety](WER-CLEANUP-SAFETY.md). Git history shows the committed
cleanup code was last changed by `e5e6fa0`, while README, SECURITY, SPEC and
UPDATE-SAFETY were last changed by `ca4633d` before this WER implementation.
The preceding uncommitted Recent patch did not add per-user WER coverage.

**Tested:** `cargo test --locked --target x86_64-pc-windows-msvc -p nomad-core
cleanup::tests -- --nocapture` passed all 27 cleanup tests on Windows 11 build
26200. Eight new WER regressions cover user/machine queues and archives,
UTF-8-BOM/UTF-16LE report-shaped metadata, ordinary dump/XML attachments,
unrelated/misleading-name reports, invalid/duplicate/NUL/missing-image metadata,
other owned executables, image/root junctions, parent/device/network paths,
nested/linked/over-budget reports and the exact file-count boundary. Native
sharing tests preserve an active reader, then retry successfully; a DELETE-only
handle causes a real partial deletion failure, leaves Report.wer, then allows
successful retry when closed. These are inert authored synthetic fixtures,
not real captured WER reports or memory dumps.

**Tested:** `pwsh -NoProfile -File scripts/check.ps1` passed formatting, strict
Clippy, 486 core unit tests, 12 integration tests and two metadata regressions
(500 total), artifact/build/release/CI/audit fixtures, and the completed clean
dependency audit without registry diagnostics. Four native registry tests and
eight live-upstream/download tests remain ignored. The separate
`cargo +1.92 check --workspace --all-targets --locked --target
x86_64-pc-windows-msvc --target-dir target/msrv-1.92` compatibility check passed
(compilation, not another runtime run). Logs are
`target/wer-cleanup-targeted.log`, `target/wer-cleanup-check.log` and
`target/wer-cleanup-msrv-check.log`. Cargo.lock is unchanged; no real host
report/dump access, deletion, crash generation, upload, browser launch,
installer, persistent user/system configuration change or hardware probe was
used. `git diff --check` passed.

**Not tested / remaining:** Real Windows 10/11 Report.wer captures and live
browser-crash cleanup are unverified. Synthetic text/sharing fixtures prove
these ownership and failure-path controls, not every OS serialization or store
location. Standalone/custom/browser dump stores, WER uploads before cleanup,
missed-session recovery and concurrency remain residual limits. Other audit
priorities, including critical hardening-write failures, link-only update
freshness, Ungoogled Chromium components and remaining browser/Helium runtime
gaps, remain open. The privacy/security rating is not reassessed upward and
v1.0.9 stays on hold.

## Required hardening-failure follow-up (2026-10-14)

Base remains `ca4633d676ddac433eff4248950de8242d90405a` on
`codex/privacy-security-followup`. Recent and WER working-tree changes were
already uncommitted at the start; this required-settings change is also local
and uncommitted. Cargo.lock is unchanged. No push, merge, tag, release or remote
CI result is claimed.

**Verified in code / corrected gap:** Earlier active-launch privacy/policy writes
and hardening withdrawal could warn and continue. Update-error fallback skipped
those writes entirely. Required preparation now propagates typed failure
(`core/src/lib.rs:1097`, `core/src/lib.rs:1442`, `core/src/browsers/mod.rs:406`)
and runs for normal, fallback and protocol-style launches. The error UI offers
Retry/Close and rejects stale Launch anyway clicks (`core/src/lib.rs:1345`).
Malformed/nonobject JSON, blocked enforced scalar paths, incomplete declared
autoconfig, and unreadable withdrawal are refused rather than silently skipped.
Staged required-overlay errors precede the success marker and swap
(`core/src/updater.rs:317`). See [exact scope and limits](HARDENING-FAILURE-SAFETY.md).

**Verified in code:** Correct managed-file bytes and semantically unchanged
Chromium JSON are retained, including tested read-only files
(`core/src/hardening.rs:22`, `core/src/hardening.rs:331`). Extension-policy
file URLs round-trip reserved/Unicode characters. Safe Browsing logging no
longer calls DNS filtering a substitute or attributes an empty vendor-managed
user.js payload to Nomad's privacy profile. Optional extension fetching and
actual browser policy acceptance remain separate concerns.

**Documented / corrected mismatches:** README, SECURITY, SPEC and UPDATE-SAFETY
now describe launch refusal, fallback parity, withdrawal failures and per-file
rather than whole-profile atomicity. README/SPEC also correct the stale blanket
Helium updater-disable claim: reviewed x64 0.19.2.1 preserves existing service
consent/update choices. SPEC no longer describes Local State as a one-time
write or guarantees that retained policies cannot affect site compatibility.
Git history shows these public documents and lib/hardening were last changed
by `ca4633d` before the working-tree follow-ups; the reviewed Helium capability
was committed earlier in `dad9a99`, making the old blanket claim stale.

**Tested:** Canonical `pwsh -NoProfile -File scripts/check.ps1` passed with
499 core + 12 integration + two metadata tests (513 total), strict Clippy,
formatting, safety fixtures and the clean dependency audit. Thirteen new
regressions use inert owned fixtures for required settings, withdrawal, encoded
URLs, read-only no-ops, GUI-state fallback refusal and pre-swap preservation.
Four native registry and eight live-upstream/download tests remain ignored.
Rust 1.92 workspace/all-target locked compilation also passed. Logs and exact
commands are in [required-settings safety](HARDENING-FAILURE-SAFETY.md).
No real browser, installer, cleanup, persistent host configuration change or
hardware probe was used for this follow-up.

**Not tested / remaining:** Actual GUI/browser enforcement, Windows 10 execution,
read-denied ACLs and hostile concurrent modification remain unverified. Earlier
successful file writes can remain after a later failure; post-swap profile errors
do not roll back the new bundle. Link-only update freshness, Ungoogled Chromium
components, missed-cleanup recovery, real captured Recent/WER artifacts and
remaining browser/DNS/Helium runtime checks remain open. Rating stays 3/5 and
v1.0.9 remains on hold. Next priority is link-only update freshness without
violating the launch-only protocol invariant.

## Protocol update-freshness follow-up (2026-10-14)

Base remains `ca4633d676ddac433eff4248950de8242d90405a` on
`codex/privacy-security-followup`. Recent, WER and required-hardening changes
were already uncommitted and remain in scope. This change is local/uncommitted
as well; no push, merge, tag, release or remote CI is claimed.

**Verified in code:** A protocol origin forces check/download options off at the
pipeline boundary (`core/src/lib.rs:645`). Its default-on local reminder
(`core/src/lib.rs:425`, `core/src/protocol_freshness.rs:24`) gives Continue opening
link/Close for unknown/seven-day-old metadata or a recorded uninstalled version.
It cannot start an update. Continue acknowledges advice for 24 hours, then runs
normal required launch preparation. Close cancels. Opt-out is
`[update] remind_on_protocol = false`; it defaults true when absent. No new
endpoint, forwarded-target logging or per-link counter is added.

**Verified in code:** Managed-extension successful lookup time/version is a
separate bounded atomic receipt (`core/src/version_cache.rs:212`), not an
installed-version-cache rewrite. Deferred/failed promotions retain installed
cache bytes and working extension bytes. Future browser cache timestamps cannot
suppress a direct refresh. Unknown, malformed, oversized or linked advisory
state cannot assert freshness. [Data, controls and limits](PROTOCOL-UPDATE-FRESHNESS.md)
cover plaintext records, indefinite retention, clocks, cooldown behavior and
browser-managed components/extensions.

**Documented / disposition:** The link-only indefinite-freshness gap is mitigated
with visible local advice, not eliminated. Users can continue/opt out indefinitely.
The seven-day interval is a reminder policy, not a security promise or update
schedule. README, SPEC, SECURITY and UPDATE-SAFETY now describe that distinction
and the two new local state files; no claim of automatic protocol updates is made.

**Tested:** Canonical `pwsh -NoProfile -File scripts/check.ps1` passed formatting,
strict Clippy, 508 core + 12 integration + two metadata tests (522 total), safety
fixtures and clean dependency audit. Nine new inert regressions cover age/deferred
metadata, scoped cooldowns, cache/receipt bounds and links, independent lookup
versus installation state, legacy/opt-out config, fixed-window layout, Continue,
Close, stale actions and protocol-option enforcement. AMO/gorhill deferred mocks
also verify receipts, and existing failed-promotion preservation tests still pass.
Four native registry/eight live-upstream/download tests remain ignored. Rust 1.92
workspace/all-target compilation passed; exact commands/logs are in the linked
runbook. No real browser, installer, watcher or persistent host mutation was used
for this follow-up. Cargo.lock is unchanged.

**Not tested / remaining:** Native Windows handoff/rendering/live-browser behavior
and Windows 10 execution need disposable validation. Metadata is not attested
freshness or installed-byte/extension/filter verification. The privacy/security
rating remains 3/5 and v1.0.9 remains on hold. Ungoogled Chromium component-update
handling is the next priority; missed-cleanup recovery, captured Recent/WER
artifacts and remaining browser/DNS/Helium runtime checks remain open.

## Ungoogled Chromium component follow-up (2026-10-14)

Base remains `ca4633d676ddac433eff4248950de8242d90405a` on
`codex/privacy-security-followup`; this and the preceding Recent/WER/hardening/
protocol reminder changes are local and uncommitted. No push, merge, tag,
release or remote CI result is claimed.

**Verified in code:** The default hardening component-disable flag remains;
Ungoogled's adapter now supplies a standing CRLSet limitation to the launcher's
runtime details (`core/src/browsers/ungoogled.rs:309`, `core/src/lib.rs:605`,
`core/src/ui/mod.rs:420`) and logs it during required preparation. This display
is independent of the hardening toggle and does not query or migrate profiles.
No endpoint, component downloader, permissions or update flags were changed.

**Verified in pinned upstream source / inference:** Windows release
155.0.8059.39-1.1 packaging commit `989b4382364baaddb8b3180e1eb1030ca96a7273`
uses core `ffeb45a2bb88bc56a1dfed31410aeb10e9efcd5a` (155.0.8059.39, revision 1).
Chromium's startup flag guard suppresses component registration, while CRLSet
registration still exists. The prescribed Windows source build rewrites the
normal service URLs to placeholder domains. Removing a Nomad flag alone does
not restore that normal service path; this is source-based inference, not live
proof of the published binary. [Pinned evidence and source links](UNGOOGLED-COMPONENT-UPDATES.md)
also distinguish CRLSet freshness from ordinary TLS/CT/DNS controls and Helium's
separate consented service.

**Documented / corrected mismatch:** README, SECURITY, SPEC and UPDATE-SAFETY
now disclose the two barriers and do not imply a launcher flag is the whole
cause or that toggling hardening restores freshness. A current verified browser
bundle is not proof of current revocation data. The retained flag may also
prevent discovering/loading existing CRLSet data through registration; that
runtime effect is unverified. UPDATE-SAFETY's stale acceptance of empty Chromium
settings was corrected to match the preceding required-hardening patch, which
refuses empty/nonobject existing settings. Git history shows these documents
last committed in `ca4633d`; the later working-tree hardening change had already
made the old empty-file sentence stale.

**Tested:** An owned offline text script verified 24 source snapshots against
saved SHA-256 values and reproduced endpoint rewriting. Twenty-seven pinned
Windows patches were searched; the relevant private-token patch was read.
Source archives were read in memory, not executed or unpacked into browser
installations. No component-service or real-browser contact occurred.
Canonical `pwsh -NoProfile -File scripts/check.ps1` passed formatting, strict
Clippy, 510 core + 12 integration + two metadata tests (524 total), safety
fixtures and clean dependency audit. Two new regressions cover disclosure,
unchanged flag/URL behavior and fixed-window button bounds. Four native registry
and eight live-upstream/download tests remain ignored. Rust 1.92 workspace/
all-target compilation passed, including the updated local UI preview example.
Cargo.lock is unchanged. Exact commands, pins, logs and omitted work are linked
above.

**Remaining:** This completes the scoped source review and launcher disclosure,
not CRLSet refresh restoration. Published-binary/network/runtime validation,
existing component loading and any secure refresh design remain open. The
rating stays 3/5 and v1.0.9 stays on hold. Next priority is missed-cleanup
recovery after crash/power loss/drive removal, with remaining captured Recent/
WER and browser/DNS/Helium checks still pending.


## Missed-cleanup recovery follow-up (2026-10-14)

Base remains `ca4633d676ddac433eff4248950de8242d90405a` on
`codex/privacy-security-followup`. This and the preceding Recent/WER/required-
settings/protocol/component changes remain local and uncommitted; nothing is
staged. No commit, push, merge, remote CI, tag or release result is claimed.

**Verified in code:** `[hardening] recover_missed_cleanup` defaults true,
independently of `enabled` (`core/src/config.rs:241`). GUI direct and registered
link/file launch attempts retry pending owned cleanup after taking the install
lock and before update/runtime work (`core/src/lib.rs:688`). Required preparation
precedes arming before both normal/fallback spawns (`core/src/lib.rs:1155`,
`core/src/lib.rs:1503`). The new journal serializes browser family and original
canonical root/image paths, uses nested Windows user/machine DPAPI protection,
exclusive synced writes, bounded reads/listing, deduplication and no foreign
record eviction (`core/src/cleanup_recovery.rs:32`, `:135`, `:180`). Failed arming
warns and permits launch. There is no plaintext fallback.

**Verified in code:** Recovery only invokes attributed Recent/WER cleanup;
shared profiles/cache actions, Prefetch, registry repair and process creation/
termination are not replayed (`core/src/cleanup_recovery.rs:258`). Matching
ownership, ordinary existing image/path and original root are required. Running,
unknown/denied/ambiguous same-name processes, moved/unreadable records and lock
contention preserve intent. The strict native process check fails closed on
incomplete enumeration (`core/src/cleanup_process.rs:110`). Ordinary post-exit
cleanup also takes the install lock and requires this proof (`core/src/lib.rs:1845`);
the advisory PID/tree wait is not deletion authority. Nested images select the
outer bundle folder's lock (`core/src/cleanup.rs:49`). Completed scoped attempts
retire only unchanged bounded record bytes; scanner/deletion failures keep intent
for retry (`core/src/cleanup.rs:166`, `core/src/cleanup_recovery.rs:224`).

**Documented upstream / inference:** The nested binding follows Microsoft's
[DPAPI contract](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata),
including its roaming-profile exception. Requiring original user and computer
is the intended design; native binding across sessions/accounts/machines remains
unverified. Ciphertext/format metadata, filesystem times and existing path logs
remain observable. The journal does not encrypt browser profiles/logs or defend
against stolen keys, malicious drive writers or a compromised host. The linked
[data inventory, retention, controls and limits](MISSED-CLEANUP-RECOVERY.md)
records defaults/opt-out, 32-record/64-entry/64-KiB bounds, exact-capacity behavior,
no eviction/expiry and manual removal. No new Nomad endpoint/client is added;
OS key-store/domain behavior has not been instrumented.

**Documented / disposition:** Earlier statements in this audit that no replay
exists describe the pre-patch state. Hypothesis 5 is now mitigated for recorded
sessions under the original context/path, not refuted as a universal guarantee.
Old unrecorded sessions, failed/lost writes, moved/absent images, lost keys,
unsupported metadata and non-Nomad process/path races can still leave traces.
Completion is an attributed scan attempt, not trace-free Windows or proof that
all reports were removed. Shared opt-in actions never replay. README, SECURITY,
SPEC, UPDATE-SAFETY and Recent/WER runbooks now describe that distinction.

**Tested:** Canonical `pwsh -NoProfile -File scripts/check.ps1` passed formatting,
strict Clippy, 531 core + 12 integration + two metadata tests (545 total), safeguard
fixtures and clean dependency audit. Rust 1.92 workspace/all-target compilation
passed. Twenty-one new regressions use injected fake context codecs/process
states, literal path comparisons and owned inert roots. Real Windows file-share
handles prove a busy authored WER fixture preserves intent, then cleanup/record
retirement succeeds after release while an unrelated standalone dump stays.
Wrong simulated machine/user, moved scope, missing ownership, unknown/running
process decisions, coordinator contention, malformed/linked/over-budget state,
no plaintext fallback, duplicate intent, changed/locked retirement, nested-image
locking and directory capacity have preservation coverage. Cargo.lock and staged
index are unchanged. Commands/logs and fixture limits are in the linked runbook.
Four native registry/eight live-upstream/download tests remain ignored.

**Not tested / next priority:** Native DPAPI round trips/foreign-user or foreign-
machine refusal, the new native snapshot/query path against real browsers,
interrupted workers, power loss, drive removal and Windows 10 execution need
disposable validation. No real browser, watcher, crash, WER upload or personal
host cleanup was exercised for this patch. Captured Explorer/WER artifacts and
remaining browser/DNS/Helium checks remain pending; Ungoogled CRLSet restoration
is still unresolved. Next priority is disposable native recovery qualification
before publishing. Rating remains 3/5 and v1.0.9 remains on hold.


## Native cleanup-recovery qualification preparation (2026-10-14)

This follow-up is still local/uncommitted on `codex/privacy-security-followup`
at base `ca4633d676ddac433eff4248950de8242d90405a`; previous working-tree fixes
remain in scope and unchanged in disposition. No commit, push, merge, CI, tag,
release or native Sandbox test result is claimed.

**Verified in code:** A Windows-only lib-test module adds four explicitly ignored
native suite/helper functions (`core/src/cleanup_recovery/sandbox_tests.rs`).
Production launcher binaries do not contain this module. The primary suite uses
actual DPAPI, bounded journal logic, process-path queries and file coordination,
but routes deletion only to owned fake host roots. It checks running/ambiguous
inert images, cross-process intent, an intentionally terminated inert worker,
missing/restored images, moved/original paths and foreign-report/dump preservation.
Public-payload encryption/tamper samples are not a general crypto proof. A later
foreign-context function is an observation, not isolated same-machine/different-
user qualification or proof of independent machine keys.

**Verified in code:** Preparation builds without running the harness, pins its
Cargo JSON artifact and a before/after source inventory, and creates a fresh
`.wsb` package with read-only inputs and a dedicated writable output mapping.
The logon command runs the guest-only fixture after the user opens that file.
Networking/clipboard/device sharing are disabled. Export refuses linked,
over-budget and oversized evidence, copies only selected inert fixture files,
and records hashes/diagnostics. The repository host verifier performs read-only
bounded schema/path/hash/provenance/assertion/log checks, including Windows
reserved device names and typed booleans. Operational Sandbox account/path/owner
checks prevent accidental host use, not malicious guard spoofing. Source hashes
and guest reports are not signed attestations. No personal host folder is mapped,
and no browser/registry/account provisioning is performed. The full data/mapping/
retention limits and pending cases are in [the runbook](CLEANUP-RECOVERY-QUALIFICATION.md).

**Tested:** Canonical `pwsh -NoProfile -File scripts/check.ps1` passed formatting,
strict Clippy, 532 core + 12 integration + two metadata tests (546 total),
safeguard fixtures and clean dependency audit. New ordinary token and offline
export-metadata regressions ran without native guest operations. The latter
passed on PowerShell 5.1 and 7, including owned-junction refusal/unlink, traversal,
reserved devices, aliases, duplicate entries, invalid sizes/hashes, provenance,
failed-run and string-for-boolean rejection. Gate mocks verify recovery-fixture
failure stops dependent Cargo operations. Four new native suite/helper tests
remain ignored, alongside four native registry and eight live-upstream/download
cases (16 ignored total). Rust 1.92 workspace/all-target compilation passed.
Logs are `target/cleanup-native-preparation-check.log` and
`target/cleanup-native-preparation-msrv.log`. Package preparation completed;
its inputs/build manifest and `.wsb` are under an owned
`target/cleanup-recovery-native-<guid>` folder. Cargo.lock and index are unchanged.

**Remaining / next action:** Open the newly prepared `.wsb` in a fresh Sandbox,
retain its console output, and independently verify the mapped receipt/files
before closing the guest or claiming a native pass. This does not execute the
full production watcher/launcher or browser, physically remove a drive, interrupt
power, test access-denied process queries or prove different-user/machine key
isolation. Those and Windows 10/real captured artifact/browser/DNS/Helium checks
remain pending. Ungoogled CRLSet restoration is still unresolved. Rating 3/5 and
the v1.0.9 hold remain.


## Recovery guest evidence / receipt follow-up (2026-10-14)

**Tested / observed:** Two Windows Sandbox build 26100 primary logs report the
native fixture suite passed (2.69s and 2.51s). Each exports 23 files plus eight
hash-only references. The host independently verified the 23 copied file hashes,
source record and harness SHA-256
`7272742C9CD467ECE24E440B1F0940C466F42CC090DF7F4155480BE94C1D0A5C`.
Result assertions cover DPAPI samples, native image states, interrupted inert
worker lock release/cross-process replay, moved/missing image preservation and
owned/foreign fake WER behavior. These remain module fixtures, not production
browser/watcher, power-loss, drive-removal or different-user/machine validation.

**Verified / blocked completion:** Both original receipts saved a null process
exit code. The normal host verifier rejected them; independent partial reports
preserve that limitation and the unchanged original receipts. No exit code is
fabricated from logs and no fully verified native pass is claimed. The
[runbook](CLEANUP-RECOVERY-QUALIFICATION.md#first-guest-observations-and-exit-capture-correction-2026-10-14)
records exact tokens and provenance.

**Verified in code / tested:** A dedicated no-shell/no-window process helper now
retains the native process handle before waiting, drains redirected output and
requires a numeric code. New PowerShell 5.1/7 fixtures check inert child codes 0/7,
timeout refusal and null-receipt refusal. Canonical gate passed again (546 tests,
formatting, strict Clippy, safeguards and clean dependency audit); log
`target/cleanup-exit-capture-fix-check.log`. Core/harness bytes are unchanged.
Original mapped inputs/evidence will be retained before promoting the four-input
corrected runner/manifest. A same-guest rerun and full host verification remain
required. This is local/uncommitted on `codex/privacy-security-followup` at base
`ca4633d676ddac433eff4248950de8242d90405a`; index/Cargo.lock unchanged. Rating 3/5
and the v1.0.9 hold remain.


## Recovery primary native fixture verified (2026-10-14)

**Tested:** Corrected rerun `fab950f9929949ccb45aaf5f079b4c79` passed the exact
native lib test in 2.44 seconds on Windows build 26100, with captured exit code 0,
empty stderr and eleven true assertion fields. The repository host verifier
independently checked 23 copied file hashes, base/source/harness identity, typed
results and completion log. A separate unmapped host snapshot was copied and
reverified under the original package's `VerifiedEvidence/primary-<token>/`,
with a saved `HOST-VERIFICATION.json`. Eight hash-only executable references are
observations; large guest executable bytes were not independently copied/verified.
Guest receipt hash is
`1CEED1E110CB5300870837DAD85B151438850B6784A7344FFF8B43344694403D`;
harness/source hashes and precise cases are in the
[verified primary record](CLEANUP-RECOVERY-QUALIFICATION.md#primary-fixture-verified-2026-10-14).
The two null-exit observations and original inputs remain preserved and partial.

**Disposition:** Primary inert same-context DPAPI samples, native process-path
classification, interrupted inert worker lock release/cross-process intent replay,
moved/missing image preservation and attributed fake WER cleanup are now covered
by this Windows 11 fixture. This does not prove full production watcher/browser
behavior, different-user isolation, independently keyed machines, physical power
loss/drive removal, query-denial cases, Windows 10 or captured Explorer/WER forms.
A new `Nomad-Recovery-Foreign.wsb` is prepared with only verified public-payload
blobs/read-only test inputs and dedicated writable output. The preparation
state is superseded by the failed foreign observation below.
Second-context refusal is an observation, not proof that Sandbox keys are unique.

Only documentation and owned evidence/configuration artifacts changed for this
record; prior canonical gate remains 546 passed/16 ignored with strict Clippy,
safeguards and clean dependency audit, and Rust 1.92 passed. Branch remains
`codex/privacy-security-followup`, base `ca4633d676ddac433eff4248950de8242d90405a`,
with local uncommitted changes and no push/merge/release. Rating 3/5 and the v1.0.9
hold remain; Ungoogled CRLSet and other recorded runtime gaps remain unresolved.

## Recovery foreign-context refusal failed (2026-10-14)

**Tested / host-verified evidence:** Windows 11 second-Sandbox run
`a38f529946ae4984a38dfa95df4cadca` failed in 0.02 seconds with actual exit 101.
The host checked all four copied files, typed result fields, failure logs and
base/source/harness provenance. The normal success verifier rejected it. An
unmapped snapshot and `HOST-PARTIAL-VERIFICATION.json` preserve the unchanged
receipt and failed result; no complete qualification pass is claimed.

**Tested:** The nested recovery-codec sample was refused, while the machine-only
comparison sample decrypted. **Inference:** Reused/cloned machine key material
could explain it; the cause and exact nested failure layer are unmeasured. This
is not evidence that a production recovery journal decrypted across users or
independently initialized machines. Neither fresh Sandbox isolation nor full
user/machine separation is qualified. No assertion was weakened and no key
material was inspected/exported. [Full result and next qualification](CLEANUP-RECOVERY-QUALIFICATION.md#foreign-context-refusal-failed-2026-10-14).

Documentation and owned evidence artifacts alone changed. The prior canonical
gate (546 passed, 16 ignored) and MSRV result are historical, not rerun for this
record. All implementation changes remain local/uncommitted. Rating 3/5 and the
v1.0.9 hold remain; independent context and broader runtime gaps are still open.


## Production recovery/browser integration preparation (2026-10-14)

**Verified in code / prepared only:** A separate guest-only Helium workflow now
builds a locked x64 local launcher with artifact/source checks and prepares a
fresh Sandbox. It tests the production DPAPI journal/watcher/replay with a real
browser, Windows-created shortcut and synthetic owned/foreign WER fixtures.
Only an exact retained and corroborated watcher handle may be terminated; the
user closes the browser normally. It checks old intent retirement, scoped trace
removal, foreign/standalone preservation, config/marker/bookmark preservation
and recovery-before-launch logging. The [runbook](RECOVERY-BROWSER-INTEGRATION.md)
details paths, network/data export, failure handling and remaining limits.

The ordinary gate includes authored process/evidence safety regressions only,
with mock wiring to stop Cargo if they fail. Native integration is NOT RUN merely
because the package or scripts exist. No host browser/profile/registry/DPAPI or
cleanup mutation is requested by preparation. Existing primary and foreign
qualification evidence remains preserved; different-user/machine and physical
interruption gaps, rating 3/5 and the v1.0.9 hold remain. Work is local/uncommitted;
validation/build results will be recorded separately after execution.


**Tested local preparation checks:** PowerShell 5.1 and 7 authored integration
safety fixtures passed. Canonical gate passed again: 546 Rust tests, 16 ignored,
formatting/strict Clippy, safety fixtures and clean dependency audit
(`target/recovery-integration-check.log`). The gate now refuses dependent Cargo
work after an integration-fixture failure. Whitespace checks passed. No actual
launcher/browser, DPAPI, watcher termination or host cleanup ran in these checks;
guest integration remains pending and no remote CI/commit/publication is claimed.


## Recovery integration logging setup correction (2026-10-14)

**Observed / verified in code:** The user confirmed real Helium opened, the
public test bookmark was created, built-in uBlock was present and service setup
was untouched. The Interrupt helper then refused its required watcher-event
count before any process termination or fixture/config mutation. Its original
startup omitted `NOMAD_LOG=info` even though watcher/recovery evidence relies on
INFO events; Nomad defaults to WARN. The current guest's actual event count/log
still needs diagnostic export. No production recovery failure or integration
pass is established by this setup exception.

The guest launcher-start wrapper now enables INFO and restores prior environment
values, including on failed start. PowerShell 5.1/7 scoped mock regressions passed
without a real process launch. Missing/duplicate/invalid watcher PID events remain
refused, and retained live-handle/image/arguments/creation-time checks are unchanged.
Original mapped package inputs stay intact. Export/preserve the initial guest's
bounded diagnostics before opening a corrected fresh package. The [runbook](RECOVERY-BROWSER-INTEGRATION.md#info-logging-setup-correction-2026-10-14)
records provenance and limitations. Work remains local/uncommitted; no release
or remote CI result is claimed, and the v1.0.9 hold remains.


**Tested correction checks:** Canonical `pwsh -NoProfile -File scripts/check.ps1`
passed again (546 tests, 16 ignored, formatting, strict Clippy, safety regressions
and clean dependency audit); log `target/recovery-integration-logging-check.log`.
PowerShell 5.1/7 mock fixtures and `git diff --check` passed. Original package
`recovery-integration-60787c95be9b4ecead7c8d68dce2d49c` input hashes still match
its original manifest. A corrected package will have its own frozen source/input
manifest; compilation does not execute guest integration. Diagnostic export and
production-path recovery remain pending; changes remain local/uncommitted.


## Recovery integration active-log export correction (2026-10-14)

**Observed / preserved partial evidence:** Original diagnostic export failed when
rehashing the source log held by the live watcher. Its copied state/log are now
bounded, hashed and preserved in an unmapped host snapshot with the original
input manifest and `HOST-PARTIAL-VERIFICATION.json`. The copied log has only WARN
entries and zero watcher-spawn events, corroborating the missing INFO setup.
The missing guest receipt/live-source hash and unestablished guest source identity
are explicit. This is incomplete copied-output preservation, not a completed
transfer or native interruption/recovery pass. No worker was stopped at the prior
watcher-identification refusal.

**Verified in code / tested:** Shared read handles now capture bounded log/file
prefixes without releasing the writer. Exports hash the captured buffer and new
copy, rather than comparing against a live source that can change. Live-log reads
use the same path. PowerShell 5.1/7 authored held-writer fixtures passed for shared
capture, later append preservation, exclusive/oversize/overwrite refusal and empty
files. Capture is not an atomic history or guest attestation; success acceptance
rules remain unchanged. [Exact partial provenance and capture limits](RECOVERY-BROWSER-INTEGRATION.md#active-log-capture-correction-and-preserved-partial-attempt-2026-10-14).

The old mapped inputs/evidence remain intact; use a new package with both logging
and shared-read fixes. Host browser/DPAPI/cleanup was not run by these regression
fixtures. Production integration and release still await guest execution. No
commit/push/remote CI/release result is claimed.


**Tested shared-capture correction checks:** Canonical gate passed again: 546
Rust tests, 16 ignored, formatting, strict Clippy, offline safety fixtures and
clean dependency audit; log `target/recovery-integration-snapshot-check.log`.
PowerShell 5.1/7 held-writer/mock regressions and whitespace checks passed.
The unmapped partial snapshot was rechecked with its explicit missing-receipt/
live-source limitations. No browser or watcher was run/stopped by host tests.
A fresh package with both corrections records its own source/input hashes;
older packages remain preserved and should not be used for the next attempt.
Guest integration, remote CI and release remain pending; work is uncommitted.


## Helium production-path recovery scenario verified (2026-10-14)

**Tested / host-verified:** Corrected Windows 11 guest session
`dabb00bb8a144343b797984aa3d80b71` passed interrupted watcher -> normal browser
close -> direct Nomad relaunch with real Helium 0.19.2.1. The host verified all
five copied evidence files, typed stage assertions, package provenance and the
recovery-before-relaunch log sequence. Three input/179 source hashes matched the
frozen inventory before recording this result. Saved journal metadata agrees
across state/interruption/closed phases. Initial watcher 6900 was interrupted;
one old cleanup record was retired before the new browser 5392/watcher 6828.

**Guest assertions / user observation:** The owned Windows-created shortcut and
synthetic WER report were removed; foreign shortcut/report and standalone inert
dump were preserved, alongside frozen config, installed marker and public test
bookmark. The user confirmed bookmark and built-in uBlock remained present.
An unmapped host snapshot preserves the unchanged receipt, five files, build
manifest, scoped `HOST-VERIFICATION.json` and separate user confirmation.
[Full provenance, scope and remaining cases](RECOVERY-BROWSER-INTEGRATION.md#helium-interrupted-worker-recovery-verified-2026-10-14).
Earlier missing-INFO/partial-export observations remain preserved; the omitted
bookmark precondition was satisfied before retry without weakening checks.

**Remaining:** Different-user/independent-machine isolation, real power/storage
interruptions, Windows 10, protocol/other-family/query-denial cases, genuine WER
forms and browser/DNS/component/installer checks remain unqualified. Ungoogled
CRLSet restoration remains unresolved. The foreign-context machine-only decryption
failure is unchanged. Rating 3/5 and v1.0.9 hold remain. Only documentation/evidence
changed here; the prior gate (546 passed, 16 ignored) remains historical, not rerun.
Branch `codex/privacy-security-followup` remains local/uncommitted/unpushed.


## Local commit checkpoint (2026-10-14)

The owner requested a local commit of the accumulated privacy/security follow-up:
attributed Recent/WER cleanup, fail-closed required settings, advisory protocol
freshness, Ungoogled CRLSet disclosure, bounded missed-cleanup recovery and the
associated regression/Sandbox workflows and documentation. Source changes belong
to `codex/privacy-security-followup`; Git history identifies the resulting local
checkpoint. Earlier dated statements that work was uncommitted describe the
state at those observations. Frozen guest build manifests and original receipts
remain unchanged and retain their pre-commit base/source identities.

Validation records include the canonical gate (546 tests passed, 16 ignored,
formatting, strict Clippy, safety fixtures and clean dependency audit), earlier
Rust 1.92 checking, PowerShell 5.1/7 safeguards, host-verified primary native
fixtures and the real Windows 11 Helium interrupted-worker/direct-relaunch pass.
The second-Sandbox machine-only refusal failure and earlier incomplete outputs
remain recorded, without rewritten assertions or broadened qualification claims.
Generated executables, logs, guest artifacts and unmapped evidence snapshots under
`target/` remain local and are excluded from the source commit.

The owner authorized this local commit only. Push/PR/merge, remote CI and release
publication are separate actions. Remaining runtime/isolation/physical-durability/
Windows 10 and Ungoogled CRLSet gaps keep the audit rating at 3/5 and v1.0.9 on hold.


## Helium DNS observation preparation (2026-10-14)

**Prepared only / verified in code:** The next runtime check observes a public
nonce hostname with seeded Quad9 secure DoH, then an unreachable loopback DoH
resolver in a fresh closed guest profile. Source-linked DNS/HTTPS response events
are distinguished from saved preferences and unrelated requests. Raw NetLog stays
in the guest; only bounded public observations and receipt/hash references are
exported. No total packet-leak absence or browser DNS pass is claimed.
The [runbook](BROWSER-DNS-QUALIFICATION.md) explains paths, endpoints, privacy,
retention, restore/refusal behavior and measurement limits.

**Tested:** Offline authored source-correlation, privacy filtering, config-argument,
closed-browser/change-preservation, restore and evidence-integrity fixtures passed
on PowerShell 5.1 and 7. Gate wiring rejects dependent Cargo work if DNS fixtures
fail. These tests do not launch a browser or change host DNS. Changes are local/
uncommitted on `codex/privacy-security-followup`, based on `920a829`.
Fresh Sandbox observations and independent selected-output verification remain
pending. Prior recovery/isolation/component limits, rating 3/5 and v1.0.9 hold
remain. Full gate/build results will be recorded after execution; no push, PR,
remote CI or release has been performed for this preparation.


**Tested full local gate:** `pwsh -NoProfile -File scripts/check.ps1` passed:
546 Rust tests, 16 ignored, formatting, strict Clippy, offline safety fixtures and
clean dependency audit. Log: `target/helium-dns-preparation-check.log`.
PowerShell 5.1/7 DNS fixtures passed; whitespace checks passed. No actual DNS
observation or remote CI is established. The separate MSRV check is historical,
not rerun for these PowerShell/documentation-only changes. Package compilation
and input/source validation are preparation, not guest execution.


## Helium baseline collector refusal (2026-10-14)

**User-reported:** CollectBaseline in the first DNS package failed its finalized
JSON/schema/correlation stage. No observation receipt or DNS success was recorded.
The capture remains in the guest, and no failure-resolver mutation is authorized
by this result. The root cause is not established by the generic error.

**Prepared / tested scope:** A read-only `Inspect-Dns-Capture.ps1` diagnostic was
added under the existing mapped Input/DnsDiagnostics directory. Original four
inputs still match their frozen manifest. It reads only the bounded closed-browser
capture, reports JSON conversion versus a whitelisted parser refusal or exception
type/line, and suppresses raw values and arbitrary exception text. It exports
nothing and performs no launch, DNS/profile write or cleanup. Syntax and host-
execution refusal were checked; actual guest diagnostic/result remains pending.
Earlier source inventory describes the original package, not this later diagnostic.
The earlier full gate is historical; no new full-gate/native DNS pass is claimed.


## Signed NetLog source-ID correction (2026-10-14)

**User-reported diagnostic:** The original baseline is valid JSON (591,492 bytes,
2,364 events), with event/phase dictionaries present. The original parser refused
`Invalid event identity or phase`; no baseline DNS result is yet established.

**Verified in code / upstream source:** The parser erroneously required source
IDs to be nonnegative. Chromium initializes a separate partition at int32 minimum
and serializes uint32 IDs via signed int32. Negative IDs can therefore be valid.
[Source partition](https://raw.githubusercontent.com/chromium/chromium/main/net/log/net_log.cc)
and [entry serialization](https://raw.githubusercontent.com/chromium/chromium/main/net/log/net_log_entry.cc).
This is a confirmed parser defect; its role in this particular guest refusal
still needs the existing-capture follow-up, not an assumed DNS pass.

**Tested / prepared:** Signed int32 IDs and matching dependency IDs are now
accepted without converting signs or merging identities. Zero selected IDs,
non-integer/out-of-range IDs, wrong endpoints and unrelated requests remain
refused. PowerShell 5.1/7 signed-partition and JSON-round-trip fixtures passed,
alongside altered-correction-file/receipt refusal. A separately hashed collector
can reprocess the original closed-browser capture, report negative-ID count and
whether the frozen parser reproduced its refusal, export only selected observations
and update collection bookkeeping. Original four package inputs/manifests remain
unchanged. Browser, raw capture, DNS/profile choices are not rewritten or relaunched.
Original build source identity and corrected analysis provenance are separate.
Actual corrected guest result and independent host evidence checking remain pending.


**Tested correction gate / prepared mapping:** Canonical local gate passed
(`target/helium-dns-signed-id-check.log`): formatting, strict Clippy, 546 Rust tests
passed / 16 ignored, offline safeguards and clean dependency audit. Windows
PowerShell host execution of the recollector refused at its guest guard. Two
correction inputs were copied/hash-checked under the existing readonly mapping;
original four inputs still match the original build manifest. Correction manifest
SHA256: `2749671A7E5C9E83B8D77B29762A3DF93E551AABB40B6EA82AD4B8F165670C43`.
Guest reanalysis and host selected-output verification remain pending. Work stays
local/uncommitted; no push, remote CI or release result is claimed.


## Helium secure DNS baseline selected evidence verified (2026-10-14)

**Guest observation / host-verified selected evidence:** Session
`e68ca8a1ffab42afa571297eec5b6725` reports three source-correlated Quad9 DoH
transactions and replies, with saved secure DNS choices matching the test. Host
checks validated the selected observation/receipt hash, four original inputs,
two corrected-analysis inputs and their correction manifest, provenance and the
three selected begin -> DoH dependency -> reply sequences. Replies have rcode 0,
net_error 0 and no answers; this establishes the observed DNS transport, not a
working test web page. No recognized classic/system probe attempt was reported.
Raw NetLog was not transferred/replayed independently and total packet-leak absence
is explicitly false. Helium-services URL-job host names appear in the filtered
inventory; this alone does not establish successful connections or telemetry.

The capture contained 74 negative source-ID events, reproducing the original
parser identity refusal; corrected analysis completed on those same guest bytes.
Original browser source hash `A7CAB4C1A426D61A43413735038B0339F457FE224D64BBBFD9B6B29461DC29AD`
and correction manifest `2749671A7E5C9E83B8D77B29762A3DF93E551AABB40B6EA82AD4B8F165670C43`
remain distinct. Receipt SHA256:
`930F422437DCF44E7D87F028FCEAE2139C2C8642A6C1D0E4C4C684BAA8F20AA3`.
An unmapped `VerifiedEvidence/baseline-e68ca8a1ffab42afa571297eec5b6725-0ac94ab819554540a1e570ad044c3d18`
snapshot retains unchanged selected files, original/correction script manifests
and a scoped host verification record; the launcher is a checked hash-only
reference and raw capture remains guest-only.

**Next / prepared only:** A separately hashed existing-session continuation uses
the corrected parser for controlled resolver failure, collection and restoration.
Its source excludes Fresh/provisioning and preserves the validated resolver-
mutation functions. PowerShell 5.1/7 continuation guards/syntax, identical safety
functions and offline DNS fixtures passed. The original four inputs and baseline
correction inputs are preserved. Controlled failure and subsequent restoration
still require guest execution and host evidence review; no fail-closed runtime
claim is made yet. All broader audit gaps/rating 3/5/release hold remain. Changes
are local/uncommitted; no push or remote CI has run for this work.


**Tested continuation gate / prepared inputs:** Canonical gate passed again
(`target/helium-dns-continuation-check.log`): 546 tests passed, 16 ignored,
formatting, strict Clippy, offline safety fixtures and clean dependency audit.
The prepared DnsContinuation input manifest SHA256 is
`F8AF10436C9CABE1217E3BB59EF9F75786E8A1C3C35D9A6EF559597B0BD4549E`.
All four continuation copies match their sources; original inputs and baseline
correction still verify. This reuses the original launcher bytes, with separately
identified workflow inputs; no fresh compilation or guest failure/restore result
is claimed. No production Rust change or host DNS/profile mutation occurred.


## Prelaunch resolver-fault fixture invalid (2026-10-14)

**Guest observation / host-verified selected evidence:** Failure session
`e68ca8a1ffab42afa571297eec5b6725` produced an inconclusive result: three target
transactions, zero correlated loopback DoH attempts, saved resolver mismatch,
no recognized plain target attempt. Filtered URL-job hosts include Quad9/Helium
services; this does not itself prove successful connections. Original receipt
SHA256 `B6237D1DA2FC704D60F16F25F0978A1DF33556D7834A75D64DA6CE5FD6DD70B3`,
observation and four continuation inputs matched their hashes. Six unchanged
selected/provenance files plus a scoped HOST-VERIFICATION record are preserved
in an unmapped VerifiedEvidence/failure snapshot; launcher is hash-only, raw
capture is guest-only. No outage or fallback-absence test is qualified.

**Verified in code / tested:** `hardening.rs:287-288` lists both DoH fields in
`LOCKED_SCALAR_PATHS`; `merge_json_file` reapplies their payload values after
merging. The existing exact locked-scalar regression passed (one test) on the
Windows x64 target. **Inference supported by code and saved-choice mismatch:**
Nomad replaced the helper's prelaunch loopback override with secure Quad9 before
browser creation. The test design overlooked this enforcement; it is not evidence
of a production secure-DNS failure. Production hardening is unchanged. The user
reported Restore confirmed/restored Quad9; a read-only guest Status check remains
pending rather than claiming independent restoration verification.

Current source refuses the invalid FailClosed phase before state/profile/launch
actions; historical mapped inputs are preserved unchanged. PowerShell 5.1/7
refusal, syntax, restore and correlation fixtures passed. README/SPEC, the public
writer comment and runbook now describe required DoH re-enforcement instead of
implying all scalar/resolver choices survive the next hardened launch. The live
runbook withdraws invalid outage instructions. A replacement must cause an actual
transport failure while retaining required settings; it is not prepared/run yet.
Baseline selected secure-reply evidence remains valid. Broader runtime/isolation/
revocation gaps and rating 3/5/v1.0.9 hold remain. Changes stay local/uncommitted.


**Validation after fixture retirement:** The first full gate stopped at a new
Rust documentation-markdown lint before workspace tests; that log is retained.
The comment lint and an encoding error in this edit were corrected, preserving
unrelated Unicode text. Canonical rerun passed (`target/helium-dns-invalid-fixture-check-corrected.log`):
546 tests passed, 16 ignored, formatting, strict Clippy, offline safety fixtures
and clean dependency audit. Focused locked-scalar test and PowerShell 5.1/7
fixture refusals passed. Production Rust behavior and historical mapped inputs
are unchanged. Guest read-only restoration status and a replacement outage test
remain pending; no remote CI, commit or publishing action occurred.


## Replacement DNS transport-fault preparation (2026-10-14)

**User observation:** The preserved continuation's read-only Status reported zero
browser processes, secure mode and `https://dns.quad9.net/dns-query` after Restore.
This confirms saved values in the user's console; it is not actual traffic proof.

**Prepared / verified in code:** An existing-session, guest-only replacement
keeps enforced secure Quad9 and original browser/launcher identity. Two exact
owned program-scoped outbound TCP/UDP 443 block rules provide a transport fault;
the helper does not block DNS 53 or change DNS/profile preferences. It requires
usable enabled guest firewall policy, without enabling global settings. It uses a
new probe/capture nonce, records restore intent and an owned config backup before
changes, validates rules/filters in active and persistent stores, and restores
only its rules/config. All rules are validated before deletion; changed/foreign
rules, running browsers and user-changed config are refused. Historical inputs,
receipts, baseline and invalid-attempt snapshots remain intact. The [runbook](BROWSER-DNS-QUALIFICATION.md#program-scoped-guest-https-outage-replacement-fixture)
details data, scope, failure handling and limits. Blocking matching browser 443
traffic is not a blanket DNS-leak or host-network claim.

**Tested offline:** PowerShell 5.1/7 source-correlation/fallback, exact rule ownership,
pre-deletion validation, restore/preservation and typed-fixture evidence regressions
passed with local mocks and inert temporary files. Host execution refused before
firewall/profile commands; no real host firewall rule or browser action ran. Native
guest setup/outage/collection/rule removal remains pending. The 3/5 rating, broader
privacy/security gaps and release hold remain. Changes are local/uncommitted;
full-gate and separately hashed preparation results will be recorded after running.


**Tested transport preparation gate / frozen inputs:** Canonical gate passed
(`target/helium-dns-transport-preparation-check.log`): 546 tests passed, 16 ignored,
formatting, strict Clippy, offline safety regressions and clean dependency audit.
PowerShell 5.1/7 mocked ownership/restoration/fixture tests passed. Four new input
copies under the existing readonly Input/DnsFault mapping were hash-checked.
Manifest SHA256:
`FABC8B78AD60626C6922D4420034BE459FEB79ABBD765DA59C48A4FDD7B3F0BB`.
The original launcher is reused, not rebuilt; original/correction/continuation
receipts and input hashes still verify. A separate user-confirmation record
preserves the reported saved secure/Quad9 restoration without changing the prior
failure receipt or host verification. No real firewall rule, browser launch or
DNS/profile mutation ran on the host. Guest transport fault, collection and owned
rule/config restoration are NOT RUN by preparation and remain pending.
Changes stay local/uncommitted; no remote CI, push or release is claimed.


## Transport fault restored before collection (2026-10-14)

**User-reported / verified selected restoration:** The fault Start helper reported
success, then the user invoked Restore before Collect. Restore exported token
`8e215f4c4aa4489b8ff15b554f7d560f` / export
`0e166f74dadb4a3e9ea9ae4740c9dc78`. Collect refused the restored intent, as designed.
The host checked all four frozen fault inputs, receipt/result scope and hash,
typed zero-rules/config-restored/secure-Quad9 fields and identical config hashes.
Receipt SHA256 `9AB95EFFABEF5B7FC40EF0D815D3F4EF8AD81F6FA9867E709AA6C2A4C202EF81`.
Six unchanged selected/provenance files are retained in an unmapped VerifiedEvidence
restore snapshot, with a scoped host record and hash-only launcher reference.
No live host firewall replay or outage/fallback qualification is claimed.

**Prepared / tested offline:** A separate read-only post-restore capture recovery
requires unchanged original inputs, restored/started/uncollected intent, closed
browser, saved secure Quad9/config hash and no owned rules now in either store.
It reanalyzes the existing bounded capture, exports selected fields and leaves
state/profile/config/raw files alone. Historical startup checks are separated
from unavailable active-at-collection checks; `qualified_fault_fixture` stays
false. PowerShell 5.1/7 syntax/host-refusal, altered-restoration and false recovered-
qualification fixtures passed. Original inputs/receipts remain frozen. The
[runbook](BROWSER-DNS-QUALIFICATION.md#restore-before-collect-recovery) records scope
and limits. Guest recovery/correlation and selected host checking remain pending.
Current changes are local/uncommitted; no new browser or firewall action is run
by host preparation. Full gate results are recorded after execution; broader
privacy/security gaps, rating 3/5 and the release hold are unchanged.


**Tested recovery gate / frozen mapped inputs:** Canonical local gate passed
(`target/helium-dns-restored-recovery-check.log`): 546 tests passed, 16 ignored,
formatting, strict Clippy, offline safeguards and clean dependency audit.
PowerShell 5.1/7 post-restore scope, host refusal and altered-restoration fixtures
passed. Four Input/DnsFaultRecovery copies matched their sources; manifest SHA256
`BBB72783008F8A95DB1BD8D6D421923D8C0AD07BF20F554A19814768616D4DE7`.
Original fault inputs/restore receipt rechecked unchanged. These are preparation
results; actual recovered guest events and host selected-copy validation remain
pending. Work remains local/uncommitted, without push, remote CI or release.


## Recovered Helium DNS capture reviewed (2026-10-14)

**Tested guest observation / verified selected copied records:** Post-restore
recovery exported `failed_doh_no_plain_attempt_in_capture`: four target
transactions, four correlated Quad9 DoH attempts, no recognized plain target
attempt. Host `Test-DnsEvidenceExport` passed against frozen Input/DnsFaultRecovery;
`Test-DnsRestoreExport` revalidated the original fault inputs and restoration
record. Four selected begin/attempt/failed-end sequences and their ordering,
source IDs, endpoint and negative results were independently checked in the
selected export. Raw NetLog remains guest-only and was not independently replayed.

Recovery receipt SHA256:
`C4AEDA6FF61ABDD979BE4B504730F2FCF48BBE49577619C5CB56A83BEBBA1713`.
Thirteen unchanged selected/provenance/verifier files are preserved outside the
Sandbox mappings, with a scoped HOST-VERIFICATION.json and hash-only launcher/raw
references. Original inputs, receipts and prior verification records were retained.
The guest reports owned rules absent now, matching restored config and secure
Quad9; host checks validate those typed copied assertions, not live firewall state.

**Unqualified full fault:** Restore preceded Collect. Recovery retains
`qualified_fault_fixture = false` and `rules_during_capture_rechecked = false`;
historical startup checks do not substitute for capture-close rule verification.
The result supports a capture-scoped failed-DoH observation without a recognized
plain target attempt, not total packet-leak absence or complete outage qualification.
See the [result and limits](BROWSER-DNS-QUALIFICATION.md#recovered-capture-result-2026-10-14).

Evidence-only preservation/documentation adds no production behavior change.
The prior canonical local gate remains the recorded validation for the workflow;
it was not rerun for this evidence record. No remote CI or publication is claimed.
Current DNS work remains local/uncommitted. Broader privacy/security gaps, rating
3/5 and the release hold remain unchanged.


## Fresh Helium DNS fixture completed (2026-10-14)

**Tested guest / verified selected records:** A fresh Windows 11 Helium 0.19.2.1
session completed Baseline, Start, normal browser closure, Collect and Restore
in order. Normal operation recorded three Quad9 DoH replies. The outage capture
recorded four correlated attempts: three QUIC protocol-error completions and one
aborted operation, with no recognized plain target attempt. The aborted operation
is retained separately rather than counted as another completed transport failure.
Owned-rule/profile checks ran in the guest before collection; secure Quad9 remained
configured. Restore reported zero owned rules and matching original/restored config
hashes. The host verified both exports, frozen inputs, selected sequence ordering,
reviewed browser/module identities and baseline/fault/restore session linkage.
See [scope, upstream error definitions and receipts](BROWSER-DNS-QUALIFICATION.md#fresh-controlled-fixture-completed-2026-10-14).

Base commit remains `920a8294afde63b4a9629433025a7f69a8eb6075`; the new package
manifest includes the working changes and source inventory. Source SHA256:
`04F93821D9466F2C4A033D2358DD0643545F8FA05A34B805CC2F1F6F87BE2A42`.
Launcher SHA256:
`D878000B40C578EAA48927A9C22CBD1F39B5862B1A1AB59265781B6EBCAC272B`.
Fresh session: `5aaec5e79bce4cbdb7a3960f09833ffd`;
fault: `eb40d791ba494fd78dc2d2b04fe3b70e`.
Failure receipt SHA256:
`79E0238858E985BF6C40F27EF23A86795CA2D9C539B414C4DDB4B20E5648BF43`.
Restore receipt SHA256:
`80DA05360A98560CCE882D9A38EA70C581EE4F50BD276375E999C0ADFD44421F`.
Unmapped baseline/failure/restore snapshots each preserve eight unchanged files
plus HOST-VERIFICATION.json; raw capture/profile stayed guest-only.

**Scoped conclusion:** This closes the Collect-before-Restore guest-fixture gap
for the exercised version/hostname/interval. It does not establish all-packet leak
absence, live host firewall replay, indefinite outage behavior, resolver bootstrap
privacy, other browser families/versions or other platforms/networks. Earlier
invalid and Restore-before-Collect records remain unchanged and unqualified for
their original scope. No production code changed. Evidence documentation and
whitespace were checked; the prior canonical workflow gate remains historical.
Current changes stay local/uncommitted on `codex/privacy-security-followup`.
Broader audit gaps, rating 3/5, remote CI and release hold remain unchanged.


## DNS commit checkpoint (2026-10-14)

Commit scope: bounded DNS NetLog correlation, disposable Helium preparation,
read-only diagnostics/recovery, exact-program transport-fault ownership and
restoration helpers, offline failure/privacy regressions and canonical gate
wiring. README/SPEC and the Rust comment now accurately describe DoH values as
re-enforced at hardened launch. Production browser behavior is unchanged.
The Windows 11 Helium baseline, Collect-before-Restore outage observation and
restoration records are documented above; older partial/invalid records retain
their original scope. Ignored local target evidence is not staged in the commit.

**Tested:** `pwsh -NoProfile -File scripts/check.ps1` passed for this checkpoint:
546 Rust tests passed, 16 ignored, formatting, strict Clippy, offline safety
fixtures and clean structured dependency audit with the documented RSA advisory
exception. Log: `target/helium-dns-precommit-check.log`. Windows 10, ignored live/
registry tests and remote CI were not run by this gate. MSRV results from the
prior production checkpoint are historical; no runtime Rust behavior changed.

Publication is separate from this local commit. Next work is the outstanding
Ungoogled Chromium CRLSet runtime gap: determine what the reviewed published
build actually registers/loads and whether a supported authenticated refresh
path exists. A newer browser bundle, a removed flag or a manually copied list
cannot stand in for fresh verified revocation data. Independent-key recovery,
genuine Windows 10/11 Recent/WER coverage and other browser/runtime checks remain
separate gaps. The rating stays 3/5 and the release hold remains.


## Ungoogled Chromium default runtime snapshot (2026-10-14)

**Tested guest / verified selected copied evidence:** A fresh Windows 11 x64
155.0.8059.39-1.1 fixture built from committed `a59035c` opened after one Retry
following a response-body download failure. The user screenshot says no
components are installed. Status reports the component-disable/background-network
switches present, no component-URL override, a neutralized updater-host literal
in the loaded module's file and no CertificateRevocation directory in this fresh
profile. Literal presence is not active routing; file/directory absence is not
proof of every certificate-verifier state. Loaded version/refresh are not claimed.

The host verified the four frozen workflow inputs, receipt scope, selected bytes/
hash, typed assertions and screenshot. Receipt SHA256:
`967FEDCE5A454A2801009623DF932D99157848AAD6BC6290BB8492CD8D9ED2B0`.
Nine unchanged evidence/provenance/screenshot files plus HOST-VERIFICATION.json
are preserved outside Sandbox mappings. Full profiles, network logs and browser
binaries were not exported. [Exact identities, checks and limits](UNGOOGLED-COMPONENT-UPDATES.md#windows-11-default-runtime-snapshot-2026-10-14)
distinguish guest module inventory from independent host binary attestation.

**Remaining:** This closes the observed default-component-page/published-module
literal snapshot gap. It does not restore fresh CRLSet data, measure updater
traffic, validate loading of an existing component or establish the effect of
removing a switch. A supported authenticated refresh path still needs design and
validation. Current source/documentation already discloses the limitation; no
production flag, endpoint or trust check was changed to obtain this result.
Different-user/independent-machine recovery, genuine Recent/WER and wider browser/
platform runtime checks remain separate gaps. Rating 3/5 and release hold remain.

The completed DNS work is committed locally as `a59035c`; these two evidence
document updates were uncommitted at collection. Their whitespace/UTF-8/LF and
preserved copy checks passed; the prior 546-test canonical gate is historical,
not rerun for this evidence-only update. Subsequent branch publication does not
establish remote CI or release qualification.


## CRLSet-only refresh feasibility review (2026-10-14)

**Verified pinned source / scoped inference:** The native unpacker verifies CRX
signatures against component key requirements before extraction, and CRLSet's
policy pins SPKI SHA256 `75daf8cb77684033654c97e5c51bcd817b1eeb112ce1a4338cf5725eedb84397`.
The referenced fetch utility extracts raw data without performing that verification.
Normal registration includes other components; URL overrides are debug controls
for the shared service. Cached-data selection/loading depends on registration
and its manifest/file checks are not a new CRX signature verification on each load.
The verifier's current-sequence comparison does not alone prove a durable launcher
rollback/freshness policy. No supported narrow route was identified in the inspected
interfaces; this is not an exhaustive negative claim about every custom build.

**Tested offline:** Twenty pinned source snapshots were hash-checked and the
publisher-hash-derived component ID matched the pinned fetch utility. No upstream
code or verifier was executed, component endpoint contacted, list downloaded,
profile written or browser launched during this investigation. The
[feasibility record and upstream capability proposal](CRLSET-REFRESH-FEASIBILITY.md)
include exact source links, unavailable paths, candidate dispositions and a
concrete signed-data-only interface/acceptance contract. The proposal is local;
it has not been posted or sent upstream.

No production workaround, provider consent, endpoint, dependency or flag change
was introduced. Previous runtime evidence remains unchanged. These documentation
changes were uncommitted at this review checkpoint; the prior `a59035c` gate is
historical. The supported
refresh gap remains unresolved and requires separately validated browser/loading
capability before an integration can be represented as a fix. Rating 3/5 and the
release hold remain.

## Waterfox DNS default conflict confirmed (2026-10-15)

The fresh x64 6.7.6 Sandbox screenshots show mode 5, OHTTP true and the upstream
Waterfox/Cloudflare endpoints. The shared autoconfig disabled TRR despite the
Waterfox payload comment promising upstream defaults. After normal closure,
selected guest settings were exported and host-verified against the frozen
inputs; original evidence is preserved. This does not establish DNS traffic.

A local correction separates the shared non-DNS autoconfig from Floorp-only
DNS defaults and preserves Waterfox upstream/user choices. Explicit saved DNS
choices are not reset. The corrected settings/relaunch check below now passed; mode 2
allows native fallback and does not provide Quad9 malware filtering. See
[Waterfox DNS defaults, provenance and limits](WATERFOX-DNS-DEFAULTS.md).

The correction's canonical gate passed locally: 549 Rust tests, 16 ignored,
formatting, strict Clippy, offline safety fixtures and structured dependency
audit (the existing documented RSA exception remains). These offline results
do not establish network behavior or remote CI/release qualification.

### Waterfox corrected settings and relaunch result

The user confirmed mode 2 on first corrected launch, then mode 2, OHTTP true,
the authored **Nomad DNS test** bookmark and enabled uBlock Origin after normal
closure and one helper relaunch. These are user text confirmations, without a
corrected-build screenshot. Final guest collection reports original config
restoration, unchanged installed marker and the expected corrected autoconfig;
all seven selected DNS user values remain absent. Host verification checked
selected bytes, provenance and the six original/corrected input files and
preserved eight unchanged evidence/helper files. Receipt SHA256:
`85E0AC589BA86A6FD04BFC3881252546B70500569F711A3F073B6E0962062139`.

The settings/preservation check is complete for this instance; actual OHTTP/DNS
traffic and broader platform/profile coverage remain unverified. Mode 2 allows
native DNS fallback. The full limitations and provenance are in
[Waterfox DNS defaults](WATERFOX-DNS-DEFAULTS.md). No production installation or
release was performed; subsequent commit/push delivery does not extend these
test results. The broader audit/release hold remains.

## Waterfox runtime DNS observations completed (2026-10-15)

**Tested guest / host-verified selected evidence:** The clean `4951d05` unsigned
x64 launcher with Waterfox 6.7.6 observed two completed OHTTP address-response
sequences normally. A fresh disposable guest with the same pinned binaries and
a program-scoped HTTPS block present at startup observed native/system probe
resolution, status-0 native completion records and effective request mode 2.
This supersedes the earlier statement that all Waterfox traffic/fallback remains
unverified, only for these two specific runs. The original confirmation-domain
probe remains inconclusive.

The two temporary guest rules were verified at closure/collection, removed,
and separately inspected as absent in both stores. Original test config and
selected DNS fields were preserved. The host verified bounded typed selected
exports, exact digests, public-format/numeric correspondence, helper provenance,
192 source hashes and byte-identical preservation outside guest-writable output.
PowerShell 5.1/7 offline outage safety fixtures passed. Raw logs/profiles stayed
inside their disposable guests. [Exact result, commands, receipts and limits](WATERFOX-DNS-DEFAULTS.md#runtime-address-responses-and-startup-outage-fallback-2026-10-15)
are recorded separately from the settings/relaunch check.

**Inference / remaining:** Mode 2 permits native/system fallback when encrypted
DNS is unavailable. That is consistent with upstream policy, not evidence that
the successful normal DoH test failed. Native/system resolution does not prove
plaintext OS packets. Broader browser/platform/profile coverage, independent-key
recovery and genuine Windows-generated Recent/WER fixtures remain separate gaps.
Ungoogled CRLSet refresh remains unresolved; rating 3/5 and the release hold stay.
Only documentation is being committed; experimental target helpers/evidence are
not part of the production change. No push, CI or release result follows from
this local record.

**Tested before this documentation commit:** `pwsh -NoProfile -File
scripts/check.ps1` passed on Windows: 550 Rust tests passed, 16 ignored,
formatting, strict Clippy, offline safety fixtures and the structured dependency
audit with the existing documented RSA advisory exception. Log:
`target/waterfox-dns-evidence-check.log`. No new Rust/runtime change was needed.
Remote checks for this new local documentation commit have not run.

## Windows Shell/queued-WER metadata qualification (2026-10-15)

**Confirmed in baseline / corrected locally:** native Shell Recent links from a
networking-disabled Windows 11 Sandbox carried `DisableKnownFolderTracking`,
which the committed parser refused. The baseline same-byte fake-host replay
failed with exit 101 because the owned shortcut remained. The correction allows
only that documented bit, preserves full target agreement and refuses ignored
KnownFolder/SpecialFolder-record combinations. Both initial and final refactored
harnesses passed with exit 0 using the unchanged captured bytes. All unrelated
sentinels, the source captures and ownership marker were preserved.

**Tested WER scope:** Windows queued two custom noncritical reports with exact
controlled AppPath values. Unmodified UTF-16LE metadata passed existing WER
cleanup in four fake-root placements. No WER production change was needed.
These are custom API reports, not natural browser-crash variants; no real host
cleanup, browser crash, dump request or raw metadata export was performed.

**Verified selected evidence:** both baseline and final receipts, bounded typed
outputs, all input hashes and 194 final source hashes, result serialization,
source delta, and byte-identical unmapped host preservation passed. The original
partial collector and failing baseline retain their original verdicts. The
[qualification record](WINDOWS-METADATA-QUALIFICATION.md) contains commands,
receipt/build identities and operational boundaries.

**Tested final source:** canonical gate passed 551 Rust tests, 17 ignored,
formatting, strict Clippy, safety fixtures and the structured dependency audit
with the existing RSA exception. Rust 1.92 workspace/all-target checking passed.
The final refactored binary was replayed in the offline guest after lint fixes.
Changes are included in this local correction checkpoint on
`codex/windows-cleanup-metadata`, base `fcd3c01`.
No remote CI, push or release is claimed. Windows 10, actual Explorer/browser
navigation, natural crash/user-store WER forms, independent-context recovery and
CRLSet freshness remain open; rating 3/5 and release hold remain.

## Required-settings native GUI follow-up (2026-10-15)

**Tested:** after committing the Windows metadata correction as `187771c`, a
release build of that exact production source passed PE checks and ran in the
existing offline Windows 11 Sandbox with a digest-verified Helium 0.19.2.1 import.
Malformed required Local State stopped launch; native UI exposed Retry/Close
without Launch anyway. Retry repeated the error until the authored JSON was
repaired, then started the exact portable browser with one native owned watcher.
A second malformed case closed through the actual Close button without launch.
Protected EXE/DLL, version/identity/configuration markers and profile sentinel
retained hashes. The browser closed without force; final owned process count
was zero. Earlier original Recent/WER records and captures were also unchanged.

**Verified selected evidence:** nine phase receipts and 52 unmapped retained
files passed host schema/hash/provenance, typed assertion and UI-button checks;
unsafe mutation cases were refused. Initial UIA ProcessId/logging assumptions,
a normal-close child-exit race, cropped image and verifier-schema failure remain
recorded with their corrections. No numeric launcher exit-zero claim follows
from the Close receipt's unavailable exit code. The
[qualification record](HARDENING-GUI-QUALIFICATION.md) distinguishes these from
production failures and saved requests from effective settings.

Only evidence documentation is uncommitted on `codex/hardening-error-gui`.
The existing 551-test/17-ignored canonical and Rust 1.92 results still apply to
unchanged Rust; release compilation and scoped native interaction add evidence,
not remote CI. Other native origins/platforms, staged rollback, independent
Windows contexts and CRLSet freshness remain open. Rating 3/5 and release hold
remain; no push or publication was performed.

## Mullvad startup and native protocol-prompt follow-up

**Tested, receipts dated 2026-10-16 UTC:** production source remained `187771c`.
A signed/hash-verified official Mullvad 15.0.25 package passed production adapter
extraction inside a fresh offline Windows 11 Sandbox. No profile directory was
pre-created. Startup, normal close and relaunch passed; uBlock, NoScript and the
Mullvad extension were recorded active on both runs. Only the updater policy was
written, no profile user.js was present, and exact protected files/public sentinel
were preserved. This is a signed import/startup test, not automatic updater or
real-user bookmark/account migration qualification.

**Tested native handoff:** four Helium freshness-prompt cases exercised the
production `-- <target>` entry: URL/file Close canceled without acknowledgment or
browser; Continue opened the public guest-loopback URL/local HTML and saved the
expected acknowledgment. Permissive update config left cache and authored stage/
backup sentinels unchanged. Native UI controls and one complete prompt image were
captured. Windows association resolution and already-running-browser combinations
were not repeated. Prompt explanatory text appeared low contrast; it is recorded
as a minor presentation follow-up, not a functional pass for every UI property.

**Verified selected evidence:** 29 typed receipts, all input hashes/addon linkage,
activation/policy/prompt semantics, preserved files and final idle/server shutdown
passed host review. Three unsafe verifier mutations were refused; 52 unmapped
files were preserved and rehashed. Exact commands, identities and limits are in
the [combined qualification](BROWSER-STARTUP-HANDOFF-QUALIFICATION.md).

The local `codex/browser-release-qualification` documentation checkpoint includes
these results and the preceding required-settings GUI evidence. Rust is unchanged;
its prior 551-test/17-ignored canonical and Rust 1.92 results still apply. Mullvad
release compilation/PE checks and the scoped runtime results add evidence without
claiming remote CI. Independent Windows recovery, CRLSet freshness, native
post-replacement rollback and remaining platform variants stay open. No push,
tag or publication was performed; rating 3/5 and the release hold remain.

## Native bundle promotion and recovery follow-up (2026-10-16 UTC)

**Tested:** committed source `ddaa365` (production Rust unchanged from `187771c`)
ran in the existing offline Windows 11 Sandbox with separate owned fixtures.
The production-linked helper induced OS error 32 during staged promotion after
the old bundle had moved to backup: production rollback restored the old tree,
kept stage and left the closed profile's ordinary-file inventory unchanged.
An authored mid-swap state plus a blocked backup restore retained backup/stage
and profile. The next unmodified retail direct launch restored the old browser
before stage cleanup. Successful promotion then exactly matched the candidate
tree and preserved the closed profile. Four normal browser launches/closes
retained the native-created bookmark, uBlock toolbar entry and public sentinel;
final owned process count was zero.

**Verified selected evidence:** 23 typed phase receipts, all eight input hashes
in two locations, candidate linkage/native JSON hashes, native UI/restore event,
normal closures and final state passed host review. Four unsafe verifier
mutations were refused; 39 files plus the report were retained outside the
guest-writable mapping with a 155-file source inventory. Release compilation,
GUI/console PE guards and 17 targeted install regressions passed. Exact identities,
commands, preservation method and limits are in the [qualification](NATIVE-SWAP-RECOVERY-QUALIFICATION.md).

**Verified in code:** completed promotion removes the backup best-effort before
browser startup. Later startup/profile failure does not automatically roll back.
This is a disclosed structural limit, not an outstanding test that can enable a
missing feature. The old “post-replacement rollback” wording is superseded by
this boundary and the bounded completed cases. Identical authentic Helium
0.19.2.1 bundles had authored variant labels; no real version transition,
physical crash, media loss, or combined promotion/rollback failure is claimed.

This documentation-only checkpoint adds no Rust behavior change. Prior canonical
551-test/17-ignored and Rust 1.92 results remain applicable; no new full gate or
remote CI was claimed. The [readiness checklist](RELEASE-READINESS.md) carries
forward completed checks and separates CRLSet/independent-Windows gaps and
remaining fault/platform coverage. Rating 3/5 and release hold remain. No push,
tag or publication was performed.

## Already-running Helium protocol handoff (2026-10-16 UTC)

**Tested:** exact source `9e0188f` (Rust unchanged from `187771c`) ran in the
existing offline Windows 11 Sandbox with a separate digest-verified Helium
0.19.2.1 import. Native URL/file Close/Continue prompts preserved the original
browser main process and cleanup worker. URL cancellation made no public target
request; file cancellation left the target tab absent. Continue delivered the
public loopback URL/local HTML into that same browser alongside the baseline.
Two duplicate cleanup workers exited through the coordinator lock; just one
worker-start event was recorded. Native-created bookmark, uBlock toolbar presence,
protected files and authored stage/backup/profile sentinels were retained. Normal
browser closure and owned server shutdown left all fixture processes absent.

**Verified selected evidence:** all main/supplemental input hashes, 23 typed
receipts, chronological UI/PID/target/acknowledgment/coordinator observations,
closed bookmark count and final idle state passed host review. Four unsafe
verifier mutations were refused; 42 files plus the verification report were
retained outside the guest-writable mapping, with a 155-file source inventory.
Release compilation, GUI PE checks and four targeted reminder regressions passed.
The [qualification](LIVE-PROTOCOL-HANDOFF-QUALIFICATION.md) records exact commands,
input identities, pre-execution matcher correction and fixture limitations.

The scoped live-browser protocol-argument track is completed. No registry/default-
app association resolution, other browser family, Windows 10, packet capture or
extension-effectiveness result is claimed. Raw profile/bookmark/log data remains
in the guest. Production behavior is unchanged; prior canonical/MSRV results
remain applicable, with no new full gate or remote CI claim. CRLSet freshness,
independently initialized Windows recovery and other specific coverage limits
remain in the [checklist](RELEASE-READINESS.md). Rating 3/5 and release hold remain.
No push, tag or publication was performed.

## Windows-selected Helium Shell handoff (2026-10-16 UTC)

**Tested:** production source `4c94a88` (Rust unchanged from `187771c`) ran in the
offline Windows 11 guest with a separate authenticated Helium 0.19.2.1 import.
The user selected HTTP/HTTPS/.html in Default apps. Selected ProgIDs plus native
command queries matched the exact launcher. Normal Windows ShellExecute supplied
only each target: cold HTTP reached the public server; a local HTML filename with
spaces produced its image-beacon receipt in the live browser; HTTPS dispatched
to that same session but had no TLS content success. Original main/worker identity,
portable Data argument, protected files and stage/backup/profile sentinels passed.
The user closed the browser normally; all test processes were verified absent.

**Tested registration:** a production-linked guarded helper registered two copies
with distinct derived identities and resolved Shell commands. Removing copy B
preserved A. It exercised the shared registry API, not retail message boxes. The
initial PID-variable/controller failure, canonical-path correction and false
Hashtable comparison fields remain preserved; independent typed UserChoice hashes
were unchanged before operator selection. No production defect/fix was inferred.

**Verified selected evidence:** 18 bounded receipts, main/additional input hashes,
identity/target/process/profile linkage, public routes, selected choice and final
idle state passed host review. Five unsafe verifier mutations were refused; 52
files plus an immutable report were retained with a 155-file unchanged source
inventory. Release compilation, GUI/console PE guards and 17 inert registration
regressions passed. [Exact scope and identities](WINDOWS-SHELL-HANDOFF-QUALIFICATION.md)
distinguish this from HTTPS navigation, other families/platforms and raw-profile replay.

**Cleanup:** computer-use native pipe was unavailable after retry/reset; the user
performed Windows selection, normal closure and confirmed guest discard. Edge was
unavailable for restoring the old selections, so the active candidate was not
removed while selected and UserChoice was never written directly. The closed
window left the background Sandbox running; the authorized exact-ID CLI stop
exited zero and final inventory was empty. A separate disposal report links/rechecks
the original snapshot without rewriting its pre-discard pending status. No
individual unregister-A or restored-default-hash success is claimed.

The local `codex/windows-shell-associations` checkpoint is documentation only.
Prior canonical 551-test/17-ignored and Rust 1.92 results remain applicable; no
new full gate or remote CI was claimed. The completed bounded Shell matrix is
carried forward in [readiness](RELEASE-READINESS.md); other browser/platform
combinations, CRLSet freshness and independently initialized Windows recovery
remain separate. Rating 3/5 and release hold remain. No push, tag or publication
was performed.

## Independent Windows recovery package preparation (2026-10-16)

**Verified in code:** a separate Windows lib-test-only module exercises production
native binding and journal logic with known public payloads and an inert owned
instance. Its native test is ignored and requires enrolled disposable VM inputs,
fixed paths/accounts, a pinned same-source transfer bundle and offline runner.
The four phases distinguish source, another local user, an independently
initialized machine and return to the original user. Direct unprotect errors are
required for refusal; scope-mismatch retention alone cannot qualify isolation.
No production runtime or original Sandbox guard was changed.

**Tested:** canonical safety fixtures, formatting, strict Clippy and all 553 Rust
tests passed (18 ignored). The full canonical command then failed dependency
auditing: the pre-existing locked `zip 2.4.2` was reported as yanked. It reported
zero matching vulnerability advisories under the existing RSA exception, but the
deny-warnings gate correctly refused the warning. Cargo manifests/lockfile and
audit exceptions are unchanged. Treat dependency remediation as a separate next
priority, not a passing audit. Rust 1.92 workspace/all-targets check and Windows
PowerShell 5.1 metadata fixtures passed. The new regressions reject altered or
mixed bundles, missing phases, mistyped assertions, unsafe names/links, failed
native exits, false context relationships and ordinary-host runner invocation.
The initial too-long test function failed Clippy and was split before this run.
Logs: `target/vm-recovery-validation-9936920862714a969b6032dba2975841/`.

**Not tested:** none of the four native VM phases has run. Tooling does not create
VMs/accounts or attest independent initialization. Two separately initialized
trusted disposable Windows VMs and reviewed operator provenance remain required.
The [runbook](INDEPENDENT-WINDOWS-RECOVERY.md) pins the phase order, selected public
exports, host checks and limits. No personal-host DPAPI operation, browser launch,
registry/configuration change, VM creation or key export was performed by this
preparation. There is no new hostile-host, roaming, forensic or durability claim.
Rating 3/5 and release hold remain; CRLSet disposition is separate. No push, tag,
release or remote CI pass is claimed.

## Yanked ZIP dependency remediation (2026-10-16)

**Verified in code:** based on `a779970`, `core/Cargo.toml` and `Cargo.lock` replace
`zip 2.4.2` with `9.0.4` and its required dependency graph. Explicit features keep
the previous AES/Bzip2/Deflate/Deflate64/LZMA/time/XZ/Zstd set without adding the
new optional PPMd/legacy decoders. Browser ZIP extraction, Chromium extension
extraction and Gecko XPI layout inspection propagate the new fallible filename
API. Existing ownership, traversal, reparse, size and transaction controls remain.
The XPI check still checks signature-file presence only; browser validation and
AMO hash verification retain their separate roles. No endpoint, telemetry,
configuration default, audit exception or verification bypass is added.

**Upstream checked:** current [crates.io release metadata](https://crates.io/api/v1/crates/zip)
reported both 2.4.2 and 8.6.0 yanked, and 9.0.4 stable/non-yanked with Rust 1.88
minimum. The [9.0.4 release](https://github.com/zip-rs/zip2/releases/tag/v9.0.4)
and [tagged manifest](https://github.com/zip-rs/zip2/blob/v9.0.4/Cargo.toml)
were read; Cargo selected/verified the registry package using its lockfile digest.
Registry metadata does not by itself establish publisher trust or future support.

**Tested:** full canonical gate passed: safety regressions, formatting, strict
Clippy, 558 Rust tests passed / 18 ignored, and a clean structured dependency
audit using the unchanged documented RSA exception. `cargo +1.92 check
--workspace --all-targets --locked --target x86_64-pc-windows-msvc` passed.
`cargo build --release --workspace --locked --target x86_64-pc-windows-msvc`
built all six launchers; `Assert-NomadArtifact` passed for each actual output.
This is PE metadata inspection, not execution or fresh Windows startup testing.
No new live-upstream browser compatibility or native recovery phase ran.

Five new Rust regressions use [independently generated public ZIP bytes](../core/tests/fixtures/zip-compat/README.md),
not archives generated by the upgraded Rust library. They cover flat/wrapped
payloads, nonseekable-stream descriptors, Stored/Deflate/Bzip2/LZMA, UTF-8 paths,
a forced ZIP64 local header, CRC corruption, truncation, extension budgets and
XPI layout boundaries. Initial strict-UTF8 refusal assertions were incorrect:
reviewed ZIP source retains CP437 fallback. Those assumptions were removed,
without adding a new filename restriction or hiding a production failure.
CRC/truncation tests and the existing unsafe-path/budget/rollback tests pass.
Logs and six artifact hashes: `target/zip-refresh-4cc6bb695d184c9a850f7355bfcc47ce/`.

This closes only the new dependency-gate blocker. The VM package stays pinned to
its original clean source and no native isolation result is claimed. CRLSet,
independent-Windows and other documented coverage limits remain. Rating 3/5 and
release hold remain. No push, tag, remote CI pass, signing or release occurred.

## Owner CRLSet acceptance and VM-test deferral (2026-10-16)

**User decision:** "Retain Ungoogled Chromium and explicitly accept the disclosed
CRLSet limitation for v1.0.9". Recorded in [release readiness](RELEASE-READINESS.md#release-specific-residual-risk-decision-2026-10-16)
and linked from the component limitation/feasibility records. This resolves only
the owner disposition for the known v1.0.9 gap. Technical refresh/loading remains
unresolved; existing flags, endpoints, trust checks and public/runtime disclosures
are unchanged. No acceptance for future releases or provider/browser changes,
revocation pass, broader residual risk or release publication was inferred.

The user separately deferred independent-VM setup/testing. The prepared package
and failed second-Sandbox observation remain within their original scopes; none
of the four independent-VM native phases ran. Deferral is not evidence of
isolation and is not release acceptance of that unverified claim. Hyper-V was
enabled through the separately approved no-restart host script; its receipt
reported restart required, with no automatic restart requested. No guest VM or
ISO download was created/performed by the assistant. No further host setup is
part of this deferral checkpoint.

**Read-only verification:** current official Windows release metadata still names
155.0.8059.39-1.1. Nomad's existing standing notice, warning log and disclosure
regression assertions were reread; no browser/component traffic or new CRLSet
runtime test ran. Documentation links, UTF-8/LF and whitespace passed. The latest
code validation is `f560926`: full canonical gate, 558 passed / 18 ignored,
Rust 1.92, six release PE guards. No redundant gate or remote CI is claimed for
this text-only change. Rating 3/5 and overall release hold remain for other
outstanding scope/acceptance decisions. No push, tag, signing or release occurred.
