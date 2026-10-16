# Ungoogled Chromium component-update limitation

## Disposition

**Owner decision for v1.0.9 (2026-10-16):** Retain Ungoogled Chromium and accept
this disclosed CRLSet freshness limitation for that release. This is a
release-specific risk acceptance, not a refresh fix, effective-revocation test,
or approval for future releases. [Recorded scope and remaining hold](RELEASE-READINESS.md#release-specific-residual-risk-decision-2026-10-16).

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

**Tested guest snapshot / verified selected export:** The reviewed Windows 11
fresh profile now has runtime evidence: the component-disable switch is present,
the user-visible components page has no entries, the loaded module is reported
to contain the neutralized updater-host literal, and no CertificateRevocation
directory was found. Host checks verify copied records/provenance and the supplied
screenshot, not live module access, updater traffic or loading of any pre-existing
CRLSet. [The runtime record and limits](#windows-11-default-runtime-snapshot-2026-10-14)
retain the security gap as unresolved.

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

**Subsequent feasibility review:** The [signed-refresh and loading review](CRLSET-REFRESH-FEASIBILITY.md)
found no production-supported CRLSet-only route in the inspected interfaces.
Native CRX publisher verification is separate from cached-data loading; the
referenced fetch/dump utility is not a substitute verifier. A narrow upstream
capability is proposed without enabling general components or new provider
contacts. This is a scoped review/proposal, not an implemented refresh fix.

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

**Not tested at the original source-review checkpoint:** Published-binary endpoint
strings, signed component request/
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
gap itself. The original source/disclosure follow-up was subsequently committed
in `920a829`; the DNS follow-up is committed in `a59035c`. The new runtime record
below was collected on `codex/privacy-security-followup`. Branch publication
does not establish remote CI or release qualification; v1.0.9 stays on hold and
the rating stays 3/5.


## Windows 11 default runtime snapshot (2026-10-14)

**Preparation tested:** A fresh fixture at
`target/ungoogled-components-runtime-19caeed196d54b2193de4af35e904d65` compiled
and checked a local unsigned launcher from clean commit
`a59035c9bd1dcfd8f2c29858017efa1578d8869e`. Its manifest froze 189 source files
and four input files; source SHA256:
`07482925255F59D7426AE24A1AB5D8BA55CE65B398843E4C76BA6891F68E4BDB`;
launcher SHA256:
`7170FEA156C58BF8E7EA2462D402155C65A99D4C58158A7419510BA8D36BC87D`.
The reviewed x64 release ZIP digest was rechecked against public GitHub metadata:
`7ab1bac653c531ea06cd4f08a59120e129d53f73f2cf7a00ae52a43276849f11`.
Nomad performs its normal download verification in the guest; no browser/profile
was imported from the personal host. Generated inspection helpers remain in the
ignored fixture and are input-hashed separately from committed production source.

PowerShell 5.1/7 syntax, host-entry refusal and inert binary-marker tests passed,
including ASCII chunk boundaries, UTF-16, empty files and size-limit refusals.
Status does not change flags, profile/configuration, network settings or component
files; it exports only bounded selected metadata. Marker scans have a 512 MiB
file bound and a 30-second scan deadline. Presence is a literal-data observation,
not proof of execution or routing. No real host browser/network configuration
operation ran during preparation or these offline tests.

**User-observed guest:** Initial package download failed with a generic
response-body error. The message does not establish timeout, routing or Sandbox
cause. One visible Retry succeeded far enough to open Chromium at
chrome://components. The screenshot says **No components are installed**.
The prior launcher screenshot also shows the standing CRLSet limitation row;
that row discloses a known limitation rather than measuring component freshness.

**Verified selected export:** The live Status helper reported the expected flat
loaded chrome.dll and command switches: component-disable/background-networking
present, component-URL override absent. Its bounded module scan found
`update.9oo91eapis.qjz9zk` and did not find `update.googleapis.com` under that
scanner's ASCII/UTF-16 rules. The fresh profile has no CertificateRevocation
directory and an empty directory inventory. Neither a loaded CRLSet version nor
refresh success is asserted.

Guest-recorded browser identities, not an independent upstream-extracted match:

- chrome.exe SHA256: `CC434A783B1F72051126000804029FD6DB73C4FF6895BBA0E86E9F9C0D9042BC`.
- chrome.dll SHA256: `169CE39172EAC6488E24E3505ED7FAFA85A3C156E22C4688A880CECFD1886955`.

The host checked the four frozen inputs, manifest/preparation linkage, exact
receipt/output allowlist, declared observation bytes/hash, typed scope fields,
fixture/version/commit identities and absence of broadened success claims.
Receipt SHA256:
`967FEDCE5A454A2801009623DF932D99157848AAD6BC6290BB8492CD8D9ED2B0`.
OBSERVATION.json is 1,546 bytes with SHA256:
`A14CE4EDBAF26C8BAB03AADAD66F584B7B20CD1AE525BB635C74C73229AC28A6`.
An unmapped VerifiedEvidence status snapshot preserves nine unchanged selected/
provenance/screenshot files plus scoped HOST-VERIFICATION.json. The original
components screenshot was available locally, inspected and copied unchanged;
its SHA256 is `83C88F7CDA2F117148981A29EFEA7C2C7CA7E8A546152A5BF741D07CC7BD4C3F`.
No full profile, raw network log or browser binary was transferred in this export.
The preserved host record is outside the Sandbox mappings; the guest may close.

**Inference and unresolved controls:** These observations corroborate the default
registration block and reviewed binary's neutralized-host data. They do not prove
which URL was executed, a complete network history, reproducible source-to-binary
provenance, authentication/loading of a pre-existing CRLSet, or the effect of
removing the switch. No custom route, unverified list or copied component was
introduced. Restoration requires the supported authenticated refresh design
already described above; the security gap remains open. This observation does
not imply ordinary certificate-chain/hostname/expiry checks are disabled.

Only evidence documentation changed in tracked source. Whitespace/UTF-8/LF and
preserved-copy checks passed. The `a59035c` canonical gate (546 passed, 16 ignored,
strict Clippy, formatting and clean dependency audit) remains historical and was
not rerun for this evidence-only record. This checkpoint establishes no remote
CI, refresh fix or release qualification; subsequent commit/push delivery does
not change those limits.
