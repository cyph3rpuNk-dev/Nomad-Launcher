# Nomad Launcher v1.0.9 (draft; delivery checks pending)

This candidate fixes portable update, profile handoff, clean-Windows startup and
privacy-control problems. It includes the implementation merged through PR #79
and local follow-ups for Windows Recent links and the ZIP dependency. Unsigned
local build checks are recorded below; the final release commit and tagged
artifacts have not been selected or built.
See the [current release-readiness checklist](RELEASE-READINESS.md) for completed
evidence, open risks and delivery steps. These notes do not authorize publication.

## Fixes

- Windows launchers use static CRT linkage and Direct3D 12 with the system shader
  compiler. The launcher needs no separately installed Visual C++ runtime or
  OpenGL driver; individual browsers can still have their own dependencies.
- Updates verify packages and staged layouts before replacement, serialize work
  per portable folder, preserve recovery backups, reject downgrades and reapply
  required overlays. Required privacy/portability preparation failures prevent
  normal, fallback and protocol browser creation.
- Windows URL and HTML handlers route through the owning launcher and profile.
  Protocol launches cannot install or update a browser. Local freshness reminders
  advise when a direct launch is needed; Continue does not perform an update.
- Default-browser registration is scoped to each launcher folder and reversible.
  Automatic handler repairs keep write-ahead records and preserve later edits
  during undo. Existing historical state cannot always be reconstructed.
- One cleanup coordinator handles an owned session. Attributed Recent shortcuts
  and current-user/ProgramData WER reports are cleaned conservatively; ambiguous
  records, shared state and standalone dumps are preserved. Windows Shell Recent
  links using DisableKnownFolderTracking are now supported when every stored
  target agrees; ignored folder-translation combinations stay preserved. Prefetch deletion is
  retired. Optional thumbnail/icon-cache clearing never terminates Explorer and
  leaves files in use alone.
- Default-on missed-cleanup recovery records bounded DPAPI-protected retry intent
  for attributed Recent/WER cleanup. It needs the original decryptable context,
  owned paths and an idle instance; it does not guarantee removal after a crash
  or encrypt the browser profile. The second-Sandbox isolation test did not
  qualify independently keyed machines; see the limits below.
- The reviewed flat x64 Helium 0.19.2.1 bundle can refresh native security
  components subject to user service consent and existing update preferences.
  The reviewed upstream layout guard rejects browser-installer updates for that
  layout. Unreviewed versions/targets retain the conservative update block;
  component refresh is not assured there. Nomad does not accept consent for users.
- Waterfox no longer inherits a shared autoconfig default that disabled encrypted
  DNS. Explicit user choices remain intact. Reviewed 6.7.6 defaults use OHTTP and
  mode 2, which permits native/system DNS fallback; this is not Quad9 filtering
  or a requirement to encrypt every lookup.
- Floorp, LibreWolf and Waterfox managed profiles enable ETP's major and minor
  site fixes while keeping Strict protection. Exceptions may permit tracking
  elements; uBlock Origin's rules are unchanged.
- Verification dependencies, bundled extraction tools, build validation and
  release-upload safeguards have been refreshed. The yanked ZIP dependency was
  replaced with 9.0.4 while retaining the previous optional decoder set; browser,
  extension and XPI paths propagate filename-decoding errors. Independent inert
  archive fixtures cover supported layouts and corruption refusal.
- Early browser loader failures are reported as errors. Retry, Launch anyway
  and Close remain visible for long diagnostics. Window titles use
  `Nomad Launcher - <Browser Name>`.

## Upgrading

Firefox, Firefox ESR and Bitwarden launchers have been removed. Chromium,
Helium, Floorp, Waterfox, LibreWolf and Mullvad remain supported; the release
build contains six launchers. Removed-browser installations, profiles, vaults
and Windows registrations are not deleted or migrated. Retain their old launcher
for any needed unregistration; do not reuse an owned folder for another brand.

Close the browser and launcher, back up the portable folder, and replace only
the matching launcher executable. Keep Browser, Data and Nomad state together.
Use the documented registration command and folder-labelled Windows Default
apps entry for URL handoff. Floorp needs Microsoft's Visual C++ Redistributable
(x64) on the PC; installing it is separate from Nomad's launcher requirements.

Waterfox users who explicitly saved mode 5 or a custom DNS provider keep those
choices. Existing Helium profiles whose component preference was previously
forced off need an explicit user choice in Helium services to permit refresh.
Store sensitive profiles on an encrypted volume: Chromium profile encryption
is disabled for portability, independently of the hardening toggle.

## Validation and limits

**Tested locally:** the latest code checkpoint `f560926` passed the full canonical
gate: 558 Rust tests (18 ignored), formatting, strict Clippy, safety fixtures and
a clean structured dependency audit with the existing RSA advisory exception.
Rust 1.92 workspace/all-target checking and all six unsigned release PE metadata
guards passed. These build checks did not execute the six outputs or qualify
new browser versions. Earlier 550/551-test results retain their historical scope;
they are not the current total. See the [ZIP checkpoint](RELEASE-READINESS.md#zip-dependency-gate-resolved-2026-10-16)
and the [native GUI scope](HARDENING-GUI-QUALIFICATION.md).

**Tested read-only on 2026-10-16:** current main still names `4951d05`; all seven
reported check runs are completed/success. Current tracked build/test source is
unchanged from `f560926`; five saved validation-log hashes and eleven changed
source/fixture hashes match the prior receipt. The subsequent local commits are
not covered by main's CI. Paginated tag/release inventories found no exact
v1.0.9 tag or visible release. No tagged build or new CI result is claimed.

**Owner decisions for v1.0.9:** retain Ungoogled Chromium with the disclosed CRLSet
freshness limitation, and accept/defer the unverified natural browser-crash and
Explorer-navigation metadata coverage gap. These are release-specific decisions,
not technical passes or future-release acceptances. The owner also accepted and
deferred independent-user/machine recovery testing, with recovery enabled and
isolation labelled unverified, and accepted the listed remaining platform/
production coverage limits and lack of post-promotion health rollback. The listed
scope decisions are resolved; exact-candidate CI and delivery checks remain.
[Recorded decisions and limits](RELEASE-READINESS.md#remaining-scope-acceptance-2026-10-16).

| Browser | Exercised Windows 11 scope |
|---|---|
| Ungoogled Chromium | Portable profile/uBlock, hardening, offline launch, languages, registration/URL/HTML handoff; authentic 154-to-155 update, interrupted-download preservation, fallback and retry. Component snapshot found no installed entries or CRLSet directory; refresh remains unresolved. |
| Floorp | 12.20.1 smoke tests, profile/extension preservation, hardening, offline launch, registration/handoff, missing-runtime error and retry after installing the verified runtime in Sandbox. |
| LibreWolf | Corrected site-fix settings and user-confirmed relaunch/bookmark/uBlock preservation. A verified browser bundle was imported after a Sandbox download interruption; this does not establish uninterrupted download reliability. |
| Waterfox | Corrected settings/relaunch and profile preservation; 6.7.6 normal OHTTP address-response observation and native/system resolution under a controlled startup HTTPS outage, in different disposable profiles. No OS packet capture. |
| Helium | Reviewed 0.19.2.1 startup, built-in uBlock/bookmark/service preservation, CRLSet 10833 refresh/relaunch; scoped secure-DNS baseline/outage/restoration and one interrupted-cleanup-worker/direct-relaunch scenario. Native direct-launch required-JSON error/blocked Retry/repaired Retry/Close also exercised, with protected-file preservation. Installer exclusion is source/layout inference plus snapshots, not exhaustive updater-history proof. |
| Mullvad | 15.0.25 signed/hash-verified import and production extraction, initially absent portable profile startup, normal close/relaunch, active bundled-extension records and public sentinel preservation passed. Online updater delivery, bookmark/account migration and effective extension blocking remain unqualified. |

The [current checklist](RELEASE-READINESS.md) links the individual evidence records
and preserves the limits of each build/run. In particular:

- Ungoogled Chromium has no assured authenticated CRLSet refresh path. Its
  launcher discloses this security-data gap. Certificate-chain/hostname/expiry
  checks are distinct; neither DNS filtering nor a newer bundle proves fresh
  revocation data. Removing one flag is not a reviewed fix. The owner accepted
  this disclosed limitation for v1.0.9; technical refresh remains unresolved.
- Recovery has same-context native and authored-file browser-integration
  evidence. Different-user/independently keyed-machine isolation, physical
  interruption and genuine Windows crash-report forms remain unqualified. The
  owner accepted deferring the independent-context test for v1.0.9 with recovery
  still enabled; this is not an isolation guarantee.
- Windows 11 Shell API Recent links and custom queued WER metadata passed
  fake-root replay after the narrow Recent flag correction. Natural crash forms,
  actual Explorer/browser navigation, Windows 10 execution, other native failure
  origins, other browser/platform Windows-association and live-browser combinations, and
  cross-machine sign-in retain gaps. The natural-crash/Explorer-navigation gap
  is accepted and deferred for v1.0.9 while remaining unverified. The listed
  wider coverage gaps now have their separate v1.0.9 acceptance. Already-running
  Helium URL/file Close/Continue
  now has a [scoped native pass](LIVE-PROTOCOL-HANDOFF-QUALIFICATION.md), including
  original browser/worker identity and bookmark preservation. Windows-selected
  Helium HTTP/HTML handoff and HTTPS dispatch also have a [bounded pass](WINDOWS-SHELL-HANDOFF-QUALIFICATION.md);
  HTTPS content was not qualified. Native failed-promotion rollback, blocked
  restoration and subsequent direct recovery now have a [scoped Windows 11 pass](NATIVE-SWAP-RECOVERY-QUALIFICATION.md).
  Successful promotion removes the old backup before browser startup; later
  profile/startup failure has no automatic health-based rollback. Real version
  transitions, physical interruption and media-loss cases remain unqualified;
  those coverage limits and the lack of health rollback were explicitly accepted
  for v1.0.9. Back up the portable folder before updating.
- Safe Browsing is disabled by Nomad hardening in Chromium/managed Gecko.
  DNS filtering does not replace browser-level phishing/malware protection.
  Host forensics, compromised computers and read/write access to an unencrypted
  portable drive remain outside the protective claims.

The [subsequent startup/handoff qualification](BROWSER-STARTUP-HANDOFF-QUALIFICATION.md)
adds Mullvad runtime and four native protocol-prompt cases; no Rust change or new
remote CI result follows from this evidence.

The broader audit rating stays 3/5. The listed release-scope decisions are now
resolved through explicit v1.0.9 acceptance; candidate CI and delivery remain
pending. Final commit selection, push/PR/merge/tag, tagged build/compatibility
checks, six-artifact/checksum/
license/provenance verification, the owner's offline checksum signature and
publication remain separate delivery actions. Follow README.md's release
verification instructions before trusting downloaded artifacts.
