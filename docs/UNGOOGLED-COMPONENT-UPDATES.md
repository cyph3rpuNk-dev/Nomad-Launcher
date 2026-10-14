# Ungoogled Chromium component-update limitation

## Disposition

**Verified in Nomad code:** Default hardening passes
`--disable-component-update` and `--disable-background-networking`
(`core/src/browsers/ungoogled.rs:80`). Turning hardening off omits those flags;
Nomad does not provide a separate component/CRLSet updater in either mode.
The standing runtime-details row says **Security data: CRLSet refresh not
assured**, supplied by the adapter (`ungoogled.rs:309`) through the initial view
(`core/src/lib.rs:605`) to the details card (`core/src/ui/mod.rs:420`). Required
preparation logs the limitation (`ungoogled.rs:313`), including fallback and
protocol launches that reach that preparation. The row appears only in phases
that show runtime details; maintenance reminders hide that card. It is a
disclosure, not a measured component version or successful refresh result.

**Inference from pinned upstream code:** Removing one Nomad switch does not
restore the normal service path. Component registration remains in Chromium,
but the Windows build applies domain rewriting to the normal updater URL file.
The runtime security gap is still open. This follow-up preserves existing
flags, browser/profile settings, downloaded component state and verification.
It adds no endpoint, service consent, automatic update, downloader, component
installation or blocking acknowledgment prompt.

## Pinned source review

**Documented upstream / source verified by public HTTPS reads:** Windows
release **155.0.8059.39-1.1** points to packaging commit
`989b4382364baaddb8b3180e1eb1030ca96a7273`, whose core submodule is
`ffeb45a2bb88bc56a1dfed31410aeb10e9efcd5a`. The core version file is
155.0.8059.39, revision 1. This is a source/packaging linkage, not independent
proof that published binaries were reproducibly built from those inputs.
See the [packaging commit](https://github.com/ungoogled-software/ungoogled-chromium-windows/commit/989b4382364baaddb8b3180e1eb1030ca96a7273)
and [core source tree](https://github.com/ungoogled-software/ungoogled-chromium/tree/ffeb45a2bb88bc56a1dfed31410aeb10e9efcd5a).

**Verified in upstream source:** Chromium 155's startup condition gates component
registration on the component-disable switch (`chrome_browser_main.cc:1968`).
CRLSet registration is still in `registration.cc:179`; the reviewed core and
Windows patches did not remove that registration. The component installer
identifies the CRLSet publisher key and uses a profile component directory
(`crl_set_component_installer.cc:34`, `:137`). These facts do not prove loading
or authenticity of any data in a user's current profile. See
[pinned startup source](https://github.com/chromium/chromium/blob/155.0.8059.39/chrome/browser/chrome_browser_main.cc#L1968),
[registration](https://github.com/chromium/chromium/blob/155.0.8059.39/chrome/browser/component_updater/registration.cc#L179)
and [installer policy](https://github.com/chromium/chromium/blob/155.0.8059.39/chrome/browser/component_updater/crl_set_component_installer.cc#L34).

**Verified in upstream source:** Stock service URLs live in
`components/component_updater/component_updater_url_constants.cc:17`.
The Windows domain-substitution list includes that file (line 3147), and its
build applies core/Windows patches before domain substitution (`build.py:222`,
`:236`). The release workflow's stage action calls build.py without the tarball
option (`index.js:33`); this selects the Windows path list. Applying the pinned
core regex rules to the pinned URL text produces
`https://update.9oo91eapis.qjz9zk/service/update2/json` and its HTTP fallback.
These are neutralized placeholder hosts, not a restored service. See
[pinned URLs](https://github.com/chromium/chromium/blob/155.0.8059.39/components/component_updater/component_updater_url_constants.cc),
[Windows path list](https://github.com/ungoogled-software/ungoogled-chromium-windows/blob/989b4382364baaddb8b3180e1eb1030ca96a7273/domain_substitution.list#L3147),
[build transformation](https://github.com/ungoogled-software/ungoogled-chromium-windows/blob/989b4382364baaddb8b3180e1eb1030ca96a7273/build.py#L222),
[stage action](https://github.com/ungoogled-software/ungoogled-chromium-windows/blob/989b4382364baaddb8b3180e1eb1030ca96a7273/.github/actions/stage/index.js#L33)
and [domain rules](https://github.com/ungoogled-software/ungoogled-chromium/blob/ffeb45a2bb88bc56a1dfed31410aeb10e9efcd5a/domain_regex.list).
A scan of 27 Windows patches found one updater-related private-token patch;
reading it did not reveal a replacement CRLSet service or restored registration.
This is a scoped code search/review, not a complete analysis of every component.

**Documented upstream:** Chromium describes CRLSets as rapid emergency
revocation data with only a subset of other revocations, not complete revocation
coverage. Its documentation also says ordinary online OCSP/CRL checks generally
are not performed by Chrome. See [Chromium CRLSets](https://www.chromium.org/Home/chromium-security/crlsets/).
A missing/stale CRLSet does not itself switch off certificate-chain, hostname or
expiry checks; DNS filtering, HTTPS-only mode and Certificate Transparency are
separate controls and do not establish fresh revocation data. Exact behavior
of a particular binary/profile remains a runtime check.

## What would restore refresh

**Recommendation:** A supported refresh solution needs a reviewed upstream
service/binary path or a separately designed signed CRLSet-only mechanism.
It must preserve publisher verification, authenticate metadata, reject rollback,
disclose the endpoint/data sent, separate browser-installer/code-bearing
components, preserve user choices and enforce the launch-only protocol boundary.
Nomad does not implement that mechanism here. A debug `--component-updater`
URL override would change routing and privacy assumptions and can affect more
than CRLSet; it is not a reviewed Nomad recovery procedure. Do not infer fresh
data from a removed flag, an enabled toggle, browser release metadata, an
unauthenticated raw list or a copied profile file.

Helium differs because it has its own consented component service and a reviewed
installer-layout guard. The separate [Helium evidence](HELIUM-COMPONENT-UPDATES.md)
includes a user-observed CRLSet refresh on x64 0.19.2.1; it does not certify
Ungoogled Chromium or future Helium builds.

## Validation, preserved evidence and gaps

**Tested:** Bounded public-source downloads were saved with URL/size/SHA-256
records under `target/ungoogled-components-source-review-2026-10-14/`.
`SOURCE-MANIFEST.json` records core/Windows source archive digests, the scoped
Windows patch scan and the domain-list hash. Selected source text was read
from archives in memory; upstream code was never executed. The 1,146,251-byte
Windows path list exceeded an initial 1 MiB cap; it was subsequently scanned
under a 16 MiB cap for updater paths. Other path-list entries were not reviewed.

**Tested:** `python target/ungoogled-components-source-review-2026-10-14/reproduce-endpoints.py`
verified 24 saved snapshot hashes and reproduced both rewritten service hosts
using only text. `endpoint-review.log` records the result. There was no contact
with Google/placeholder component services, component/browser binary download,
profile mutation or browser execution. Public source retrieval is distinct from
application runtime traffic.

**Tested:** Two new inert regressions check the disclosure's view wiring, existing
hardening-on/off flags, absence of a new updater URL and fixed-window action
bounds with the added row. `pwsh -NoProfile -File scripts/check.ps1` passed
formatting, strict Clippy, 510 core + 12 integration + two metadata tests (524
total), safety fixtures and clean dependency audit. Four native registry and
eight live-upstream/download tests remain ignored. Rust 1.92 workspace/all-target
locked compilation passed. The local static UI preview example was updated for
the new view field and compiled, not run. Logs:
`target/ungoogled-components-targeted.log`, `target/ungoogled-components-check.log`,
`target/ungoogled-components-msrv-check.log`.

**Not tested:** Published-binary endpoint strings, signed component request/
response handling, loaded CRLSet version, preservation/loading of a pre-existing
CRLSet with registration blocked, update success, other component installers,
real Windows 10/11 GUI rendering and network captures. The flag guard could also
prevent discovery/loading through the registration path; existing profile data
is not deleted by this follow-up, but usability is not verified. The disclosure
is not a runtime diagnostic or an assertion that every version/custom route can
never update.

A disposable Windows check should inspect chrome://version and chrome://components,
record the installed/profile paths and current CRLSet version, and capture updater
behavior with the default flags. Testing flag removal must use a separate inert/
disposable profile and explicit endpoint/traffic observation; do not treat a
changed command line as successful refresh. Avoid personal-host profile changes.

The launcher-side disclosure is complete locally; restoration of fresh component
data is unresolved. Source/documentation mismatch is corrected, not the security
gap itself. Work is uncommitted/unpushed on `codex/privacy-security-followup`,
base `ca4633d676ddac433eff4248950de8242d90405a`; prior Recent, WER, hardening and
protocol-reminder patches remain in scope. No remote CI or release is claimed;
v1.0.9 stays on hold and the rating stays 3/5.
