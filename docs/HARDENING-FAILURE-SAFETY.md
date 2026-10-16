# Required-settings failure safety

## Scope and launch contract

**Verified in code:** `core/src/lib.rs:1187` applies required managed settings;
`prepare_browser_for_launch` (`lib.rs:1532`) also requires adapter preparation
before best-effort self-registration repair. Normal launch (`lib.rs:1131`),
fallback (`lib.rs:1435`) and existing-browser protocol launches use this path.
Preparation errors carry their failing step (`browsers/mod.rs:406`). The GUI
shows Retry/Close; a stale Launch anyway action is refused. Ordinary update
errors can still offer fallback, but that fallback must pass the same checks.
No new browser process, cleanup watcher or success signal occurs on these
preparation failures. This cannot stop a browser already running or someone
invoking its executable directly.

**Verified in code:** Required surfaces are Chromium Local State/Preferences,
adapter first-run/portability preparation, declared Gecko user.js/policies,
and complete declared autoconfig pairs. Turning off hardening requires removal
of the managed Gecko fence and any Nomad-declared autoconfig pair. An empty
vendor-managed user.js payload requires removal of a stale Nomad fence too.
Vendor autoconfig is preserved. Existing policies are retained when disabled;
they are not restored to vendor originals or refreshed in a replacement bundle.
Chromium preferences already saved by the browser are not unmerged.

**Verified in code:** Staged enabled-hardening Gecko preparation
(`core/src/updater.rs:317`) validates pair completeness and policy shape, then
requires overlay writes before the success marker and swap. A rejected staged
overlay leaves the active binary/profile/marker unchanged. Active-profile
preparation follows promotion: a failure there blocks launch but does not undo
a successful browser update.

## Validation and preservation

**Verified in code:** `core/src/hardening.rs:331` distinguishes missing files
from empty, unreadable, malformed and nonobject existing Chromium JSON. Invalid
files are preserved and cause an error. Nonobject containers that block known
enforced scalar paths cannot silently skip that enforcement (`hardening.rs:302`).
Initial-preferences payload construction requires JSON objects (`hardening.rs:257`).
Policy roots and their policies member must be objects; extension-policy injection
also validates ExtensionSettings and uses a percent-encoded absolute file URL
(`hardening.rs:431`, `hardening.rs:454`). A linked, directory-shaped or unreadable
cached XPI path is refused; a missing optional XPI remains optional. This does not
rehash the cached extension or prove it is enabled.

**Verified in code:** Unreadable/non-UTF-8 user.js cannot be treated as missing
during withdrawal (`hardening.rs:80`). Matching managed text/binary file contents
are accepted without replacement (`hardening.rs:22`); Chromium compares the
merged parsed JSON so matching pretty-printed files retain their bytes.
These writer no-ops allow matching read-only files; adapter-specific preparation
may have additional writes. Changed contents that cannot be replaced fail.

**Documented limits:** Writes are atomic per file, not across the preparation
sequence. An earlier successful change can remain after a later failure, including
one half of an autoconfig pair. Removal can also succeed for one file and fail for
the next. There is no whole-profile rollback. Ownership/reparse checks are not a
hostile concurrent-writer defense. Fence preservation assumes well-formed Nomad
markers; existing healing behavior for an unterminated fence can replace its
remaining contents.

**Documented upstream contract:** Mozilla describes the pointer file plus the
root config file, including its first comment line, in its
[AutoConfig documentation](https://support.mozilla.org/en-US/kb/customizing-firefox-using-autoconfig).
Nomad checks the declared pair and filesystem/JSON structure, not full JavaScript
syntax, every policy's semantics or runtime effectiveness. Browser versions may
ignore settings; user content/extra arguments and previously running processes
can affect results. A successful local write is not proof of DNS behavior, malware
protection or extension activation. Optional extension-download failures still
retain the existing copy and may remain warnings; this patch does not make
extension provisioning mandatory. Safe Browsing trade-offs remain as disclosed
in README; DNS filtering is not equivalent browser phishing/malware protection.

## Tested scope and remaining checks

**Tested:** On Windows 11 build 26200, inert owned fixtures cover malformed and
nonobject JSON, blocked enforced paths, policy/seed shape validation, unreadable
withdrawal, missing profile locations, incomplete autoconfig, directory-shaped
required paths, encoded extension URLs and matching read-only managed files.
Normal/fallback/protocol-style failures never reach the fixture's command builder;
GUI-state tests check Retry/Close and rejection of stale fallback clicks.
Staged overlay failures preserve active binary, profile sentinel and marker.
No browser, watcher or real host cleanup/registry configuration was invoked by
these new regressions.

**Tested:** `pwsh -NoProfile -File scripts/check.ps1` passed formatting, strict
Clippy, 499 core tests, 12 integration tests and two metadata regressions (513
total), safety fixtures and the clean dependency audit. Four native registry
tests and eight live-upstream/download tests remain ignored.
`cargo +1.92 check --workspace --all-targets --locked --target
x86_64-pc-windows-msvc --target-dir target/msrv-1.92` passed compilation.
Logs: `target/required-hardening-failures.log`,
`target/required-hardening-check.log`, `target/required-hardening-msrv-check.log`.

**Not tested in the initial regression campaign:** Visible Windows GUI interaction
for these new errors, effective
browser preferences/first-run behavior after this patch, Windows 10 execution,
read-denied ACLs and exhaustive concurrent-writer scenarios. Existing-readonly
checks exercise actual Windows filesystem permissions; JSON/directory fixtures
exercise other local errors. A separate disposable Windows 10/11 check should
observe a required-file error, confirm only Retry/Close, then repair the fixture
and retry; compare the active browser marker/profile before and after staged
failure and inspect actual browser settings after a successful launch. Such live
checks were not substituted with host provisioning or real personal-profile
mutations.

Delivery at initial collection was local and uncommitted on
`codex/privacy-security-followup`,
base `ca4633d676ddac433eff4248950de8242d90405a`. Prior Recent/WER working-tree
changes are included in the full validation; no remote CI/release is claimed.

## Native GUI follow-up (2026-10-15)

**Tested:** Windows 11 Sandbox exercised the production Helium direct-launch
required-JSON error: visible Retry/Close with no Launch anyway, a repeated
refusal while malformed bytes remained, successful Retry after repair, and
Close without launch in a second case. Exact browser/profile arguments, one
native watcher after successful launch, protected-file preservation and final
idle state were checked. A DPI-aware image confirmed button visibility.
The [qualification record](HARDENING-GUI-QUALIFICATION.md) preserves exact build
hashes, failed controller attempts and host verification limits. This closes
that bounded native GUI gap; the other origins, Gecko, staged native UI,
effective preferences, Windows 10 and ACL/concurrency cases remain unqualified.
No production change was needed; this new evidence is local documentation on
`codex/hardening-error-gui`, based on committed `187771c`.
