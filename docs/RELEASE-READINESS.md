# v1.0.9 release readiness

## Current decision (2026-10-16)

**On hold.** The scoped privacy/security rating remains **3/5**. This checklist
reconciles the existing audit records; it is not a new exhaustive audit or
permission to tag, push, sign or publish. Completed checks below should not be
repeated merely because older chronological entries still say pending.

**Owner disposition (2026-10-16):** Retain Ungoogled Chromium in v1.0.9 and
explicitly accept its disclosed CRLSet freshness limitation for that release.
This resolves the owner decision for that item; it does not fix or qualify
revocation refresh. The standing launcher/README/SECURITY disclosures remain.
Independent-VM recovery testing was separately deferred at the user's request,
not passed or accepted as a verified isolation guarantee. No tag, publication,
broader risk acceptance or removal of the overall release hold is authorized by
these decisions.

**Metadata disposition (2026-10-16):** The owner also accepted and deferred the
natural browser-crash and Explorer-navigation metadata coverage gap for v1.0.9.
Those cases remain unverified; this resolves their release-specific disposition,
not their technical qualification. It does not accept the separate independent
recovery-isolation or wider platform/production-path gaps. See the
[recorded decision](#metadata-coverage-disposition-2026-10-16).

**Tested repository state:** main was independently read through GitHub's API at
`4951d05b0b4c3305324daee3696bfa577d5b9ba1` (PR #79 merged). All seven reported
check runs for that exact commit were completed/success: canonical check,
dependency advisories, Rust 1.92, Chromium MSRV, Chromium compatibility, Zizmor
and Scorecard. This is evidence for that commit, not subsequent local commits.
Waterfox evidence and the reconciliation were committed locally as `9fbac51`
and `fcd3c01`. The subsequent Windows metadata correction and evidence are local
changes included in the local `codex/windows-cleanup-metadata` correction
checkpoint `187771c`, based on `fcd3c01`. The subsequent native required-settings
GUI, Mullvad startup/relaunch and protocol-prompt results are included in the
local `codex/browser-release-qualification` documentation checkpoint. The current
source already differs from the old proposed `bc3f889` release target. A subsequent
local `codex/native-swap-recovery` documentation checkpoint records bounded native
promotion/restore evidence against `ddaa365` without a production code change.
The following local `codex/live-protocol-handoff` checkpoint records the scoped
already-running Helium handoff against `9e0188f`, also without a Rust change.
The subsequent local `codex/windows-shell-associations` checkpoint records actual
Windows-selected Helium HTTP/HTML handoff and HTTPS dispatch against `4c94a88`,
with operator selection/closure, host evidence verification and guest discard.

**Tested read-only release inventory:** successful paginated GitHub API queries
on 2026-10-15 found no exact `refs/tags/v1.0.9` and no visible `v1.0.9` release.
The workspace version is already 1.0.9. No tag, draft or publication was created.

## Completed evidence to carry forward

Each result covers its documented build, fixture and platform, not every version
or network. The linked records retain failed and superseded attempts.

| Area | Current disposition | Evidence |
|---|---|---|
| Clean-Windows launcher startup | Static CRT/DX12 startup and Floorp's missing-runtime diagnostic/button recovery exercised; the browser's own runtime dependency remains. | [Audit history](AUDIT-STATUS.md), [build safety](BUILD-SAFETY.md). |
| Browser/profile preservation | Chromium update/download failure/retry and profile checks, Floorp smoke coverage, and Gecko site-fix/relaunch observations are recorded. LibreWolf used an imported verified bundle after a Sandbox download interruption. | [Audit history](AUDIT-STATUS.md), [smoke scope](SMOKE-TESTS.md). |
| Helium components and consent | Reviewed x64 0.19.2.1 started, retained bookmark/uBlock/service choices, and showed CRLSet 10833 after refresh/relaunch. Flat installer exclusion is a source/layout inference supported by snapshots, not a complete updater-history measurement. | [Component evidence](HELIUM-COMPONENT-UPDATES.md). |
| Helium secure DNS | Fresh controlled baseline, Collect-before-Restore outage observation and restoration completed. Earlier restored-before-collection and invalid resolver-setting attempts remain unqualified. | [DNS qualification](BROWSER-DNS-QUALIFICATION.md#fresh-controlled-fixture-completed-2026-10-14). |
| Waterfox DNS correction and runtime | Explicit choices preserved; settings/relaunch passed. Scoped normal OHTTP address responses and mode-2 native/system resolution under a startup HTTPS outage now observed. | [Waterfox evidence](WATERFOX-DNS-DEFAULTS.md#runtime-address-responses-and-startup-outage-fallback-2026-10-15). |
| Cleanup safety and recovery | Single coordinator, retired Prefetch deletion, no Explorer termination, bounded attributed Recent/WER cleanup, native same-context DPAPI fixtures and one Helium interrupted-worker/direct-relaunch observation recorded. Windows 11 Shell Recent/custom queued WER replay now passed after a narrow Recent-flag correction; natural crash/navigation variants remain separate. | [Recent](RECENT-SHORTCUT-SAFETY.md), [WER](WER-CLEANUP-SAFETY.md), [native recovery](CLEANUP-RECOVERY-QUALIFICATION.md), [browser integration](RECOVERY-BROWSER-INTEGRATION.md). |
| Required-settings native UI | Windows 11 Helium direct launch refused malformed Local State, offered Retry/Close without fallback, retried successfully after repair and closed safely in a second refusal. Protected files and final idle state checked; other origins/platforms remain separate. | [GUI qualification](HARDENING-GUI-QUALIFICATION.md). |
| Mullvad startup/relaunch | 15.0.25 signature/hash verification, production extraction and portable startup/normal-close/relaunch passed with active bundled-extension records and sentinel preservation. No profile pre-creation or Nomad user.js. | [Startup evidence](BROWSER-STARTUP-HANDOFF-QUALIFICATION.md). |
| Freshness-prompt native handoff | URL/file Close canceled; Continue opened a public loopback page/local file and saved only the expected acknowledgment. Permissive update config did not alter cache or authored stage/backup sentinels. Scoped already-running and Windows-selected Helium follow-ups are recorded below; other association combinations remain separate. | [Handoff evidence](BROWSER-STARTUP-HANDOFF-QUALIFICATION.md#native-protocol-reminder-and-handoff). |
| Live-browser protocol handoff | Already-running Helium retained its original main process/worker through URL/file Close/Continue; intended targets opened only after Continue. Bookmark/uBlock/protected sentinels and normal final closure passed; duplicate workers exited through the coordinator lock. No Windows association selection was exercised. | [Live handoff evidence](LIVE-PROTOCOL-HANDOFF-QUALIFICATION.md). |
| Windows-selected Shell handoff | User selected the Nomad Helium candidate for HTTP/HTTPS/.html. Real Windows ShellExecute cold HTTP content, live HTML beacon and live HTTPS dispatch passed with the same portable process/worker; two-copy registration/removal scoped checks passed. HTTPS content and retail registration dialogs were not qualified. The disposable guest was discarded after evidence preservation. | [Windows handoff evidence](WINDOWS-SHELL-HANDOFF-QUALIFICATION.md). |
| Native bundle promotion/recovery | Failed promotion restored the old real bundle; blocked restoration preserved backup/stage; the next retail direct launch recovered. Successful promotion and bookmark/uBlock/sentinel preservation passed. Same authenticated version with authored variant tags; no physical crash or post-success health rollback. | [Native swap evidence](NATIVE-SWAP-RECOVERY-QUALIFICATION.md), [rollback boundary](UPDATE-SAFETY.md#promotion-and-rollback-boundary). |
| Ungoogled component investigation / owner disposition | Published-build snapshot and authenticated CRLSet-loading feasibility review completed. The owner explicitly accepted retaining the disclosed gap for v1.0.9 on 2026-10-16. Technical refresh remains unresolved; no refresh pass is claimed. | [Runtime evidence](UNGOOGLED-COMPONENT-UPDATES.md), [feasibility](CRLSET-REFRESH-FEASIBILITY.md). |
| Local validation | Latest code checkpoint `f560926`: full canonical gate passed with 558 Rust tests / 18 ignored, formatting, strict Clippy, safety fixtures and clean structured audit with the existing RSA exception; Rust 1.92 and all six release PE guards passed. No remote CI or native execution of those release outputs is claimed. | [ZIP checkpoint](#zip-dependency-gate-resolved-2026-10-16), [audit policy](../SECURITY.md#dependency-audit-policy); earlier [metadata evidence](WINDOWS-METADATA-QUALIFICATION.md) retains its original scope. |

## Open work and acceptance evidence

These are distinct residual risks and coverage gaps, not repetitions of the
completed campaign. Resolving a technical gap and explicitly accepting a
well-disclosed residual risk are different release decisions; this checklist
does not make that decision for the owner.

| Priority | Open item | Next concrete action / acceptance evidence |
|---|---|---|
| 2 | Recovery isolation across independent Windows contexts (deferred by user, unverified) | User deferred this qualification on 2026-10-16. No acceptance of the unverified isolation claim was given. To resume, use a separately initialized disposable Windows machine and a separately created user. Exchange only the public-payload ciphertext fixture, verify refusal and retained intent, and preserve receipts. The second Sandbox's machine-only sample decrypted; another identical Sandbox rerun cannot qualify independent keys. Never export keys or bypass the current Sandbox-only runner guards to test personal stores. A [separately guarded VM package](INDEPENDENT-WINDOWS-RECOVERY.md) is now prepared, with source/peer/foreign/return phases and strict host verification; preparation is not a native isolation pass. |
| 3 | Natural-crash/navigation metadata coverage (accepted and deferred for v1.0.9; unverified) | The owner explicitly accepted and deferred this coverage gap for v1.0.9; no further test is required to resolve that specific release decision. The [bounded browser capture attempt](BROWSER-METADATA-OBSERVATION.md) produced no matching report or new cleanup replay. Windows 11 Shell/custom-WER passes retain their narrower scope. Future technical qualification must use original bounded bytes and unrelated sentinels in a disposable environment without upload or personal host data. Genuine user-store variants and Windows 10 remain unqualified; the wider platform decision stays in priority 4. [Disposition](#metadata-coverage-disposition-2026-10-16), [scope](WINDOWS-METADATA-QUALIFICATION.md). |
| 4 | Remaining platform and production-path coverage | Windows 10, remaining hardening-error origins/Gecko/staged UI, other browser/platform Windows-association and live-browser combinations, independent-machine sign-in, real version-transition compatibility, physical interruption/media-loss and wider recovery/fault cases retain specific gaps. Bounded native failed-promotion/restore/recovery, Mullvad startup, fresh-browser protocol prompts, already-running Helium handoff and the bounded Windows-selected Helium Shell matrix are completed above. Automatic health-based rollback after successful promotion is not implemented; assess that disclosed structural limit separately from unrun tests. Choose a bounded disposable scenario from its runbook, preserve profile/sentinels and record exact build/OS/results. Historical removed-Firefox coverage is not current six-browser coverage. |
| 5 | Final candidate and delivery | After the hold is resolved, select the full reviewed commit rather than reuse `bc3f889`; recheck its actual CI/compatibility and release notes. Tag/push remain separate authorized actions. The tag workflow must build/attest the six launchers, checksums and licenses; verify exact artifacts/provenance, then the owner signs the checksum manifest offline before publication. A local gate is not release integrity. |

The Windows 11 Shell/custom-WER metadata track now has a scoped pass and
correction. Its natural-crash/navigation extension is accepted and deferred for
v1.0.9 in priority 3, with no technical pass. Windows 10 and wider coverage remain
separate in priority 4. Independent Windows initialization for priority 2 has not
been qualified.
Further preparation must preserve the no-upload boundary; a custom queued WER
report must not be relabelled as a natural browser crash. The CRLSet technical
gap remains open, with explicit owner acceptance for v1.0.9 as recorded above. That acceptance does not turn the investigative
snapshot into a refresh pass.

## Validation and delivery limits

**Verified in code:** [.github/workflows/release.yml](../.github/workflows/release.yml)
triggers on pushed `v*` tags, validates/builds/attests artifacts and invokes the
draft-release publisher. Its comments and [security policy](../SECURITY.md#release-integrity)
reserve the detached checksum signature for the owner. The publisher refuses
populated/published releases and does not silently overwrite assets.

**Tested for this reconciliation:** local document targets/heading anchors,
UTF-8/LF and whitespace checks; read-only main/check-run/tag/release API queries.
The metadata follow-up changes the narrow Recent-link flag policy and adds
regression/guarded replay tests. It changes no browser setting, configuration,
endpoint, dependency or key. The canonical/MSRV results above apply to the final
Rust correction; later evidence-only documentation edits did not trigger another
gate rerun. New local commits have no remote checks until published and checked.
Nothing here clears the existing rating or release hold.

## Independent VM preparation checkpoint (2026-10-16)

The separate VM-only ignored fixture, bounded input packaging, enrolled runner,
phase/matrix verifiers and failure-path regressions are now present. The original
Sandbox-only guard and production launcher behavior are unchanged. This is
preparation, not an independent-context native result. No VM/account was created,
no native binding phase ran and no release isolation claim is cleared.

**Tested:** `pwsh -NoProfile -File scripts/check.ps1` passed its safety fixtures,
formatting, strict Clippy and 553 Rust tests, with 18 ignored, before failing the
unchanged dependency audit on yanked `zip 2.4.2`. The audit reported zero matching
vulnerability advisories with the existing documented RSA exception; that does
not override its yanked warning or constitute a passing full gate. Windows
PowerShell 5.1 VM metadata regressions and `cargo +1.92 check --workspace
--all-targets --locked --target x86_64-pc-windows-msvc` passed. Logs are retained
under `target/vm-recovery-validation-9936920862714a969b6032dba2975841/`.
No remote CI, push, tag or publication was performed at this checkpoint.

## ZIP dependency gate resolved (2026-10-16)

The failed yanked-crate check in the preparation checkpoint above is resolved by
a separate change based on `a779970`. Production/test dependencies now resolve
`zip 9.0.4` in the committed lockfile, with the previous optional format set
explicitly retained. All three ZIP consumers handle the new fallible filename
API by propagating errors. Ownership, traversal, size, verification and promotion
checks are retained. No audit exception was added or gate weakened.

**Tested:** the full `pwsh -NoProfile -File scripts/check.ps1` now passes,
including safety fixtures, formatting, strict Clippy, 558 Rust tests (18 ignored)
and the structured dependency audit with the existing RSA exception. Rust 1.92
workspace/all-targets checking passed. All six unsigned release launchers built
and passed the metadata-only PE import/CRT/mitigation guard; none was executed,
signed or published. Independent Python-authored fixtures cover flat/wrapped
ZIPs, streaming descriptors, Stored/Deflate/Bzip2/LZMA, a small forced-ZIP64 entry,
UTF-8 paths, CRC corruption and truncation across the applicable consumers.
These are bounded archive checks, not fresh live browser/version-transition tests.
Logs and artifact identities are retained under
`target/zip-refresh-4cc6bb695d184c9a850f7355bfcc47ce/`.

The dependency gate is no longer an open item. Independent Windows recovery
qualification, Ungoogled CRLSet disposition and remaining platform/production
coverage retain the scopes listed above. The previously prepared VM package
remains pinned to `a779970`; it is not silently rebuilt or relabelled for this
new dependency graph. No native VM phase, remote CI or release approval follows
from this local pass. Rating 3/5 and release hold remain.

## Release-specific residual-risk decision (2026-10-16)

**User decision, recorded verbatim:** "Retain Ungoogled Chromium and explicitly
accept the disclosed CRLSet limitation for v1.0.9".

The six-browser release scope is retained. No component flag, update endpoint,
CRLSet file, verification rule or default is changed. The existing runtime row,
launch log, README and SECURITY limitation remain. A current browser bundle,
DNS filtering or Certificate Transparency is not evidence of current revocation
data. The [technical follow-up](CRLSET-REFRESH-FEASIBILITY.md) remains open for a
supported authenticated loading/refresh route and effective runtime validation.
This acceptance is specific to v1.0.9 and does not pre-accept future releases or
future browser/provider changes.

**Separate user direction:** skip the independent-VM setup/test and move to the
next item. This defers that test only. All four native phases remain unrun, no
isolation pass is claimed and no release acceptance of that unverified claim
was inferred. Hyper-V enablement is a separate completed host setup action;
its receipt reported restart required with no automatic restart. No guest VM
or ISO was created/downloaded by the assistant in that setup attempt.

**Read-only refresh:** the official Windows release metadata still identified
[155.0.8059.39-1.1](https://github.com/ungoogled-software/ungoogled-chromium-windows/releases/tag/155.0.8059.39-1.1),
the same build covered by the existing source/runtime investigation. No new
whole-source review, browser run, revocation test or component service contact
was performed. The existing disclosures and regression assertions were reread.

**Validation:** documentation-only disposition; UTF-8/LF, local document links
and whitespace checked. The full canonical 558-pass/18-ignored, Rust 1.92 and
six release PE guard results at `f560926` remain the latest code validation;
no new remote CI or full gate is claimed for this text-only checkpoint.
Rating 3/5 and the overall release hold remain pending the other listed scope
and acceptance decisions. No push, signing, tag or publication is authorized or
performed by this disposition.

## Metadata coverage disposition (2026-10-16)

**User decision, recorded verbatim:** "Accept and defer this metadata coverage
gap for v1.0.9". The question identified the offline attempt's missing WER report
and the resulting unverified natural browser-crash and Explorer-navigation
cleanup coverage. This is acceptance and deferral of that specific coverage gap
for v1.0.9, not a successful crash capture, cleanup replay or guarantee of complete
trace removal. It does not pre-accept future releases.

The [bounded observation](BROWSER-METADATA-OBSERVATION.md) and its selected
verification/disposal receipts retain their original inconclusive and unqualified
results. The earlier Windows 11 Shell API Recent/custom queued WER passes remain
valid only for their captured forms. No runtime behavior, cleanup scope, test
result, receipt or public protection claim is changed by this disposition.

The separate CRLSet limitation already has its v1.0.9 acceptance. Independent
Windows recovery isolation remains deferred and unverified without a release
acceptance of that claim. Genuine user-store variants, Windows 10 and other
wider platform/production paths retain their documented qualification limits;
this metadata response is not a blanket acceptance of those separate items.
Rating 3/5 and the overall hold remain pending the other scope/acceptance
decisions and final candidate/delivery checks. No push, tag, signing or publication
is authorized by this decision.

**Validation:** documentation links/anchors, UTF-8/LF and whitespace checked. No
browser, fault, cleanup or full gate was rerun for this text-only disposition.
The code checks at `f560926` remain the latest recorded local validation, not
remote CI for subsequent commits.

## Draft release-note reconciliation (2026-10-16)

**Tested read-only:** main still resolves to
`4951d05b0b4c3305324daee3696bfa577d5b9ba1`, with seven reported check runs all
completed/success. Successful paginated tag and release inventories found no
exact v1.0.9 tag or visible release. The local review began at clean `d856c37`,
12 commits ahead of that main commit; those commits' author, committer and full
messages were inspected. This does not publish them or establish their remote CI.

The diff from `f560926` to that local checkpoint contains documentation only.
All five saved validation-log hashes and eleven non-documentation changed-source/
fixture hashes in its local receipt were rechecked successfully. The existing
558-pass/18-ignored gate, Rust 1.92 and six unsigned PE-guard results are carried
forward as prior local evidence, not a new run or runtime/browser qualification.
The post-main production diff was reread for the Recent-link flag correction
and ZIP consumers; VM/metadata qualification additions remain test-only. This
is a bounded change review, not a second exhaustive security audit.

The [draft release notes](RELEASE-NOTES-v1.0.9.md) now identify the local fixes,
latest validation and both accepted v1.0.9 limitations. The draft remains on hold.
Independent-context recovery isolation is deferred/unverified and still needs a
release-scope decision; wider platform/production coverage has its separate open
scope. Final exact-commit CI, compatibility, artifact/provenance verification and
owner signing/publication remain future delivery steps. No new owner acceptance
was inferred and no push, tag, signing or release mutation occurred.

**Validation:** the three documentation files passed UTF-8/LF, local link/anchor
and whitespace checks. No production code changed and no full gate or browser
test was rerun solely for this release-note update.
