# v1.0.9 release readiness

## Current decision (2026-10-15)

**On hold.** The scoped privacy/security rating remains **3/5**. This checklist
reconciles the existing audit records; it is not a new exhaustive audit or
permission to tag, push, sign or publish. Completed checks below should not be
repeated merely because older chronological entries still say pending.

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
source already differs from the old proposed `bc3f889` release target.

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
| Freshness-prompt native handoff | URL/file Close canceled; Continue opened a public loopback page/local file and saved only the expected acknowledgment. Permissive update config did not alter cache or authored stage/backup sentinels. Association resolution/already-running combinations remain separate. | [Handoff evidence](BROWSER-STARTUP-HANDOFF-QUALIFICATION.md#native-protocol-reminder-and-handoff). |
| Ungoogled component investigation | Published-build snapshot and authenticated CRLSet-loading feasibility review completed. Investigation completion does not close the revocation-data gap. | [Runtime evidence](UNGOOGLED-COMPONENT-UPDATES.md), [feasibility](CRLSET-REFRESH-FEASIBILITY.md). |
| Local validation | Final Windows metadata correction: 551 Rust tests passed, 17 ignored, formatting, strict Clippy, safety fixtures and clean structured audit with the existing RSA exception; Rust 1.92 passed. | [Metadata evidence](WINDOWS-METADATA-QUALIFICATION.md), `target/windows-metadata-final-check.log`; [audit policy](../SECURITY.md#dependency-audit-policy). |

## Open work and acceptance evidence

These are distinct residual risks and coverage gaps, not repetitions of the
completed campaign. Resolving a technical gap and explicitly accepting a
well-disclosed residual risk are different release decisions; this checklist
does not make that decision for the owner.

| Priority | Open item | Next concrete action / acceptance evidence |
|---|---|---|
| 1 | Ungoogled Chromium revocation-data freshness | A supported signed CRLSet-only loading/refresh capability needs separate design and runtime validation, including effective rejection of a controlled revoked certificate. No supported narrow route was identified in the reviewed interfaces. Do not remove a flag, change an endpoint or copy an unverified list as a claimed fix. Any release retaining the disclosed gap needs an explicit owner disposition. |
| 2 | Recovery isolation across independent Windows contexts | Use a separately initialized disposable Windows machine and a separately created user. Exchange only the public-payload ciphertext fixture, verify refusal and retained intent, and preserve receipts. The second Sandbox's machine-only sample decrypted; another identical Sandbox rerun cannot qualify independent keys. Never export keys or bypass the current Sandbox-only runner guards to test personal stores. |
| 3 | Remaining natural-crash/navigation metadata variants | Windows 11 Shell API Recent links and custom queued WER metadata now passed unmodified-byte replay; the Recent flag defect was reproduced and corrected. Actual Explorer/browser navigation, natural browser-crash reports, genuine user-store variants and Windows 10 remain separate qualification targets. Continue only in disposable environments without report upload or personal host data, preserving encodings and unrelated sentinels. [Scope](WINDOWS-METADATA-QUALIFICATION.md). |
| 4 | Remaining platform and production-path coverage | Windows 10, remaining hardening-error origins/Gecko/staged UI, already-running browser/Windows-association combinations, post-replacement rollback, independent-machine sign-in, and wider recovery/fault cases retain specific gaps. Mullvad startup and the bounded native protocol-prompt cases are completed above. Choose a bounded disposable scenario from its runbook, preserve profile/sentinels and record exact build/OS/results. Historical removed-Firefox coverage is not current six-browser coverage. |
| 5 | Final candidate and delivery | After the hold is resolved, select the full reviewed commit rather than reuse `bc3f889`; recheck its actual CI/compatibility and release notes. Tag/push remain separate authorized actions. The tag workflow must build/attest the six launchers, checksums and licenses; verify exact artifacts/provenance, then the owner signs the checksum manifest offline before publication. A local gate is not release integrity. |

The Windows 11 Shell/custom-WER metadata track now has a scoped pass and
correction; its natural-crash/navigation/Windows 10 extensions remain in priority
3. Independent Windows initialization for priority 2 has not been qualified.
Further preparation must preserve the no-upload boundary; a custom queued WER
report must not be relabelled as a natural browser crash. The CRLSet design decision remains separate
and cannot be resolved by declaring the investigative snapshot a pass.

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
