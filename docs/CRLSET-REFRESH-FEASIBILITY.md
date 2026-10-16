# Ungoogled Chromium CRLSet refresh feasibility

## Decision and scope

**Subsequent owner disposition (2026-10-16):** Retain Ungoogled Chromium in
v1.0.9 with explicit acceptance of the disclosed CRLSet limitation. The technical
finding below remains unresolved; acceptance does not establish a loading/refresh
capability. See the [release-specific decision](RELEASE-READINESS.md#release-specific-residual-risk-decision-2026-10-16).

**Source review / inference:** No production-supported, CRLSet-only update and
loading route was identified in the reviewed Chromium 155.0.8059.39 source paths
and Ungoogled Windows 155.0.8059.39-1.1 packaging. This is a scoped finding, not
proof that no custom build or unreviewed mechanism could provide one. Nomad's
current flags, endpoints, profiles and verification remain unchanged. The known
revocation-data gap is still unresolved.

The [default Windows runtime snapshot](UNGOOGLED-COMPONENT-UPDATES.md#windows-11-default-runtime-snapshot-2026-10-14)
corroborates component registration being blocked, a neutralized-host literal in
the browser module and absence of a fresh-profile CRLSet directory. That snapshot
does not measure the effect of a changed flag or prove any list was loaded.

Downloading authenticated data and making the browser use it are separate
requirements. A successful download, syntactically valid list or visible component
version alone does not establish effective revoked-certificate rejection.

## Evidence and candidate paths

**Verified in pinned upstream source:** The native update path pins CRLSet's
signing-key SPKI SHA256 to
`75daf8cb77684033654c97e5c51bcd817b1eeb112ce1a4338cf5725eedb84397`.
Its derived component ID is `hfnkpimlhhgieaddgfemjhofmfblmnib`.
[`CRLSetPolicy::GetHash`](https://github.com/chromium/chromium/blob/155.0.8059.39/chrome/browser/component_updater/crl_set_component_installer.cc#L34)
supplies the required key hash to component registration. The
[unpacker](https://github.com/chromium/chromium/blob/155.0.8059.39/components/update_client/unpacker.cc#L82)
calls the [CRX verifier](https://github.com/chromium/chromium/blob/155.0.8059.39/components/crx_file/crx_verifier.cc#L117)
before unzipping. CRX3 proofs cover signed-header bytes and the archive, not merely
a filename or a checksum obtained from the same untrusted response. This trace
is source evidence; no new cryptographic verifier was executed or implemented.

| Candidate | Source evidence | Disposition |
|---|---|---|
| Remove the component-disable flag | Startup calls shared RegisterComponentsForUpdate, whose list includes CRLSet and other data/code components, with conditional recovery/Widevine registration. Normal upstream service addresses remain neutralized in the reviewed build. | Does not establish refresh; not a CRLSet-only capability. No flag change made. |
| Override the component service URL | The reviewed command-line policy labels these overrides as debug options and applies routing through the shared configurator. | Not a production-supported isolated fix; no override or service contact added. |
| Run the referenced crlset-tools fetcher | The reviewed fetch function reads the CRX header, skips its proof bytes, opens the ZIP and outputs crl-set without a CRX signature-verification step. | A research fetch/dump utility is not Nomad's integrity boundary. Not executed or adopted. |
| Independently verify a CRX, then stage a component directory | Native startup selects manifest/version directories and invokes CRLSet ComponentReady, but that loading path depends on component registration. | Conditional research candidate only. No verified narrow-loading or effective-revocation result; no profile file was staged. |
| A browser-side CRLSet-only capability | Would separate required signature verification and effective loading from general component services. | Preferred upstream design direction; not present or implemented in this review. |

**Verified in pinned upstream source:** The general
[registration list](https://github.com/chromium/chromium/blob/155.0.8059.39/chrome/browser/component_updater/registration.cc#L153)
is reached through the component-disable
[startup guard](https://github.com/chromium/chromium/blob/155.0.8059.39/chrome/browser/chrome_browser_main.cc#L1968).
The [URL override parser](https://github.com/chromium/chromium/blob/155.0.8059.39/components/component_updater/component_updater_command_line_config_policy.cc#L22)
explicitly treats its values as debug controls. Removing a flag or changing a
URL therefore cannot be represented as a reviewed data-only refresh solution.
Not every listed component is built/enabled in this Ungoogled binary; the source
list establishes shared scope, not actual installation of each component.

**Verified in pinned upstream source:** CRLSet
[ComponentReady](https://github.com/chromium/chromium/blob/155.0.8059.39/chrome/browser/component_updater/crl_set_component_installer.cc#L125)
passes cached data to the certificate-verifier factory. Startup directory selection
uses [manifest and installation checks](https://github.com/chromium/chromium/blob/155.0.8059.39/components/component_updater/component_installer.cc#L345);
CRLSet's installation check requires the crl-set file to exist. These are not a
fresh verification of the original CRX signature on every cached-file load. An
external Nomad installer would need its own authenticated retained-package/cache
policy, ownership protection and safe staging. This is consistent with the
existing compromised-host/drive-writer exclusions, not evidence of a new remote
signature bypass in the native download path.

**Verified in pinned upstream source:** The
[verifier factory](https://github.com/chromium/chromium/blob/155.0.8059.39/services/cert_verifier/cert_verifier_service_factory.cc#L358)
refuses an update whose sequence is no higher than the currently loaded sequence.
That per-factory comparison is not by itself proof of a durable Nomad rollback
floor across restarts, drive movement or cache restoration. The
[CRLSet parser](https://github.com/chromium/chromium/blob/155.0.8059.39/net/cert/crl_set.cc#L214)
also permits an absent NotAfter value. A signed list is not automatically proof
that it is the newest list; outage/freshness handling must be separately disclosed.

**Verified in pinned utility source:** The
[fetcher at b7a5ed8](https://github.com/agl/crlset-tools/blob/b7a5ed8d598c736634aa8f6d4beda95bca4a1439/crlset.go#L87)
uses clients2.google.com metadata and a response-supplied download URL. Its
fetch/extract path does not enforce Nomad's publisher-verification, bounded-body,
redirect and controlled-extraction requirements. It was read as source only.
No Google component service was contacted by this review.

## Proposed browser-side capability

This is a concrete proposal for upstream review, not a shipped API or a posted
issue. A CRLSet-only capability should:

1. Accept a signed data package through a documented, versioned interface and
   require the fixed CRLSet publisher key/ID before extraction or loading.
2. Admit only bounded CRLSet data and required manifest fields; exclude executable
   content, extension installation, installer actions and general component updates.
3. Load the authenticated list even while general component updates remain
   disabled; report the effective loaded sequence and data age/expiry limitations.
4. Refuse malformed, wrong-key and older data, preserve a known-good list on failure
   and reinitialize the verifier correctly after relevant service/browser restarts.
5. Keep other updater routes, component registrations and user settings intact.
   Registering unrelated components must not be required to consume the list.
6. Permit explicit, disclosed provider consent if networking is offered. An offline
   signed-package interface could let a separately reviewed Nomad fetcher handle
   network policy without the browser adding background traffic.

An eventual Nomad integration must also preserve the existing direct-launch-only
update boundary, instance locks, reparse/ownership checks, transactional staging
and rollback/freshness disclosure. It should be capability/version gated and must
not silently replace unsupported browser bundles or send new provider requests.
Candidate network providers would observe at least an IP address and request
metadata; a privacy relay changes the trust/data inventory and needs its own
review. No new provider or consent default is selected here.

Acceptance requires offline wrong-key/tampered/truncated/oversized/rollback tests,
plus a disposable runtime test proving the loaded sequence and rejection of a
controlled revoked-certificate fixture. Also test restart, failed replacement,
retained user data and absence of unrelated updater/installer activity. An entry
on chrome://components alone is not the acceptance test.

## Validation, unavailable sources and delivery

**Tested offline:** Twenty saved source files were read and hash-verified in
`target/crlset-loading-review-e381e04dbe214160b5bda3ceaa0543a8`.
SOURCE-MANIFEST.json records pinned URLs, sizes and SHA256 values. The independent
`check-source-evidence.py` rechecked all snapshots, derived the CRLSet ID from
Chromium's pinned public-key hash and matched the utility's component ID. Its
saved-text checks corroborate verify-before-unzip and shared registration calls;
they do not execute Chromium, CRX crypto or the fetch tool.

No CRLSet-specific entry was found in the three reviewed switch-definition files.
This limited search does not prove the absence of every hidden/native interface.
The requested chrome/common/chrome_switches.cc path returned 404; its header was
reviewed instead. The mistaken chrome/browser/component_updater/component_installer.cc
path was unavailable; the correct components/component_updater/component_installer.cc
was retrieved and reviewed. Whole Chromium source/builds and every patch/call site
were not examined. Some pinned links were unavailable through web browsing;
bounded direct public-HTTPS source retrieval supplied the saved pinned files.

Tracked changes are documentation only. The prior canonical gate on `a59035c`
(546 tests passed, 16 ignored, formatting, strict Clippy and clean dependency audit)
is historical and was not rerun merely for this feasibility record. Whitespace
and local document-link checks apply to the new documentation. No production
behavior, dependency, trust key, update endpoint or browser setting changed.
The proposal has not been posted upstream; branch publication does not submit
it upstream or establish release qualification.
The refresh gap, rating 3/5 and release hold remain.
