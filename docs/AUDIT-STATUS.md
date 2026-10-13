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
