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
The Waterfox evidence documentation is committed locally as `9fbac51` on
`codex/waterfox-dns-traffic`; this reconciliation is a subsequent documentation
change. The current source already differs from the old proposed `bc3f889`
release target.

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
| Cleanup safety and recovery | Single coordinator, retired Prefetch deletion, no Explorer termination, bounded attributed Recent/WER cleanup, native same-context DPAPI fixtures and one Helium interrupted-worker/direct-relaunch observation recorded. | [Recent](RECENT-SHORTCUT-SAFETY.md), [WER](WER-CLEANUP-SAFETY.md), [native recovery](CLEANUP-RECOVERY-QUALIFICATION.md), [browser integration](RECOVERY-BROWSER-INTEGRATION.md). |
| Ungoogled component investigation | Published-build snapshot and authenticated CRLSet-loading feasibility review completed. Investigation completion does not close the revocation-data gap. | [Runtime evidence](UNGOOGLED-COMPONENT-UPDATES.md), [feasibility](CRLSET-REFRESH-FEASIBILITY.md). |
| Local validation | Canonical gate before `9fbac51`: 550 Rust tests passed, 16 ignored, formatting, strict Clippy, safety fixtures and clean structured audit with the existing RSA exception. | `target/waterfox-dns-evidence-check.log`; [audit policy](../SECURITY.md#dependency-audit-policy). |

## Open work and acceptance evidence

These are distinct residual risks and coverage gaps, not repetitions of the
completed campaign. Resolving a technical gap and explicitly accepting a
well-disclosed residual risk are different release decisions; this checklist
does not make that decision for the owner.

| Priority | Open item | Next concrete action / acceptance evidence |
|---|---|---|
| 1 | Ungoogled Chromium revocation-data freshness | A supported signed CRLSet-only loading/refresh capability needs separate design and runtime validation, including effective rejection of a controlled revoked certificate. No supported narrow route was identified in the reviewed interfaces. Do not remove a flag, change an endpoint or copy an unverified list as a claimed fix. Any release retaining the disclosed gap needs an explicit owner disposition. |
| 2 | Recovery isolation across independent Windows contexts | Use a separately initialized disposable Windows machine and a separately created user. Exchange only the public-payload ciphertext fixture, verify refusal and retained intent, and preserve receipts. The second Sandbox's machine-only sample decrypted; another identical Sandbox rerun cannot qualify independent keys. Never export keys or bypass the current Sandbox-only runner guards to test personal stores. |
| 3 | Genuine Windows Recent/WER metadata | In a disposable environment, capture inert Windows-created Recent links and real Report.wer metadata with original encodings. Replay under owned fake-host roots with unrelated-target sentinels before any live cleanup qualification. Clearly label redaction/path rebinding. Current WER cases are authored report-shaped fixtures; native Shell Link tests use WScript.Shell, not captured Explorer Recent records. No personal host report or memory dump is needed. |
| 4 | Remaining platform and production-path coverage | Windows 10, Mullvad live startup, required-hardening failure UI, new protocol freshness-prompt handoff, post-replacement rollback, independent-machine sign-in, and wider recovery/fault cases retain specific gaps. Choose a bounded disposable scenario from its runbook, preserve profile/sentinels and record exact build/OS/results. Historical removed-Firefox coverage is not current six-browser coverage. |
| 5 | Final candidate and delivery | After the hold is resolved, select the full reviewed commit rather than reuse `bc3f889`; recheck its actual CI/compatibility and release notes. Tag/push remain separate authorized actions. The tag workflow must build/attest the six launchers, checksums and licenses; verify exact artifacts/provenance, then the owner signs the checksum manifest offline before publication. A local gate is not release integrity. |

The next available runtime-qualification track is genuine Windows metadata
(priority 3); independent Windows initialization for priority 2 has not been
qualified. Preparation should first establish how to obtain metadata without
sending crash reports. Generating or uploading a browser crash is not part of
this documentation reconciliation. The CRLSet design decision remains separate
and cannot be resolved by declaring the investigative snapshot a pass.

## Validation and delivery limits

**Verified in code:** [.github/workflows/release.yml](../.github/workflows/release.yml)
triggers on pushed `v*` tags, validates/builds/attests artifacts and invokes the
draft-release publisher. Its comments and [security policy](../SECURITY.md#release-integrity)
reserve the detached checksum signature for the owner. The publisher refuses
populated/published releases and does not silently overwrite assets.

**Tested for this reconciliation:** local document targets/heading anchors,
UTF-8/LF and whitespace checks; read-only main/check-run/tag/release API queries.
No production code/configuration, upstream endpoint, browser setting, dependency
or key changed. The canonical result above applies to unchanged production code
and the preceding documentation checkpoint; it was not rerun solely for this
second documentation pass. New local commits have no remote checks until
published and checked. Nothing here clears the existing rating or release hold.
