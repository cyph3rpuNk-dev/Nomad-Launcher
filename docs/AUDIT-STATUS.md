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

Still unrun: four ignored HKCU tests, real browser smoke tests, and GitHub CI
for this work. The signing-key check does not replace them.
Test counts measure examples exercised, not code coverage; no coverage percentage
has been measured.

Code fixes and documentation cleanup are local commits; the live-check results
are committed as `a83ef02`; isolated smoke-test preparation is uncommitted.
This work has not been pushed, merged,
published or copied into the user's portable installations. At the baseline review,
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

## Remaining maintenance work

| Priority | Item | Severity / certainty | Location and next action |
|---|---|---|---|
| 1 | Large orchestration modules | **Low, confirmed maintainability concern; defect impact is a hypothesis.** `lib.rs` is 3,856 lines including tests, combining CLI, UI pipeline, launch, registry integration and cleanup watcher handling. `browsers/mod.rs` is 1,267 lines including tests, mixing the family contract with Gecko provisioning. | Extract cohesive internal modules after behavior fixes, preserving the public contract and failure-path tests. Line counts alone do not establish poor coverage or a bug. |

Do not reopen a closed finding merely because the old handoff still lists it.
Likewise, a green local gate does not close unrun end-to-end validation.

## Validation and delivery still pending

| Work | Evidence needed / scope |
|---|---|
| Windows registration and URL handoff | Use an isolated Windows account for the four ignored HKCU tests, then verify real same-profile URL/file handoff. Mock registry tests do not prove Windows picker integration. |
| Portable browser smoke tests | Fresh install, update, offline launch, rollback/retry, hardening toggle and extension acceptance in disposable portable folders. Do not use the user's real profiles as fixtures. |
| Historical Helium cross-machine sign-in report | Still needs reproduction. The handoff references issue #54, but current GitHub status and root cause were not checked here. Portability flags alone do not prove cookie portability. Use a disposable account/profile and a controlled move between machines. |
| Historical local artifacts | The handoff reports a nested Mullvad browser tree, stale associations and a stray LibreWolf host profile. These were not re-inspected or removed; they are historical reports, not current verified state. Cleanup needs a separate inventory and user approval. |
| Review, CI and release | Obtain approval for push/PR creation, run GitHub CI, review/merge within authorized scope, build and verify release artifacts, and obtain approval for publishing/deployment. None follows automatically from a local commit. |

Prepared [the isolated Windows smoke-test runbook](SMOKE-TESTS.md), including
exact native-registry test filters and disposable-instance build/setup steps.
The runbook and its commands have not been executed. On 2026-10-07, both
PowerShell examples were parsed without execution and the four exact registry
test names were verified with `--list`. The canonical local gate passed with
489 tests, formatting, Clippy, safeguard fixtures and dependency audit using
the documented RSA exception. These are prior-run results, not a fresh run on
2026-10-11; the temporary gate log is no longer present.

On 2026-10-11, the user confirmed that no isolated Windows test account or
disposable VM is ready and requested runbook preparation only. Browser smoke
and native HKCU tests are deferred; none ran during this follow-up.

Recommended next step: execute that runbook in the isolated environment for
startup, profile persistence and URL handoff validation. Keep the four HKCU
tests confined to that account. Review and CI remain separate delivery work;
defer the optional module split until validation.
