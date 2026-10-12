# Audit status

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
| F1/F2: broad host-directory cleanup | Fixed. Shared profiles, registration maps, temporary files, raw dumps and compound Jump Lists are preserved. Deletion requires instance attribution. | [`cleanup.rs`](../core/src/cleanup.rs), `ffbd1e0`. |
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
