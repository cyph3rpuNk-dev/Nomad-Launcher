# Security policy

## Reporting a vulnerability

Report vulnerabilities privately via [GitHub's vulnerability reporting](https://github.com/cyph3rpuNk-dev/Nomad-Launcher/security/advisories/new) for this repository. Please do not open a public issue for anything exploitable. This is a solo-maintained project; expect an initial response within a week.

## Supported versions

Only the latest release receives fixes. There are no backports.

## Release integrity

Releases ship a `SHA256SUMS` manifest with a detached signature (`SHA256SUMS.asc`) made by the Nomad release key:

```
4F90 CF11 723D C3A2 E719 8331 FEF9 81E9 09EF 44ED   (ed25519, expires 2029-07-11)
```

The public key is distributed in this repository (`nomad-release-signing-key.asc`) and, independently of it, on public keyservers ([keys.openpgp.org](https://keys.openpgp.org/vks/v1/by-fingerprint/4F90CF11723DC3A2E7198331FEF981E909EF44ED) and keyserver.ubuntu.com). Cross-check the repository copy against a keyserver before trusting a release.

The launcher binaries are intentionally not Authenticode-signed; the GPG-signed manifest is the integrity anchor. Key rotation history: access to the pre-v1.0.2 key (`4D92 5DAD 1DB4 405C 99EA 1FD3 9984 5DA3 20CD 1F37`) was lost in July 2026. It is not believed compromised, and releases up to v1.0.1 remain verifiable against it; see the [v1.0.2 release notes](https://github.com/cyph3rpuNk-dev/Nomad-Launcher/releases/tag/v1.0.2).

## Release rerun safety

`scripts/publish-draft-release.ps1` refuses published releases, populated drafts,
failed lookups, and invalid metadata. Release creation requires a successful
paginated lookup and uses `--draft --verify-tag`. Required local artifacts are
checked first; draft status and release identity are rechecked before upload.
Uploads omit `--clobber` ([GitHub CLI upload documentation](https://cli.github.com/manual/gh_release_upload)),
preventing deletion/replacement of existing assets even
if publication races the check. The workflow serializes runs for the same tag.
Do not publish while a workflow is still uploading; draft checks and uploads are
separate API operations. Partial drafts require explicit review before a retry.

The canonical gate runs `scripts/test-release-publish.ps1` with a mocked GitHub
CLI and owned temporary artifacts. It never creates or changes a real release.

## Threat model

### What Nomad defends against

- **Tampered browser downloads.** Every package is hash-verified (SHA-256, or SHA-512 for Waterfox). Where the upstream signs, the signature is verified against an embedded key: Mullvad via GPG, uBlock Origin's Chromium build via a GPG-verified release tag plus a required GitHub SHA-256 asset digest and an asset-timeline tamper check (the tag signature does not cover ZIP bytes). An adapter with an embedded package-signing key requires its detached signature: missing, unreadable, invalid or failed-to-download signatures cannot fall back to a matching hash. A package with no verifiable integrity material is refused. A failed verification aborts before extraction and leaves the existing install untouched.
- **Gecko extension download integrity.** Nomad resolves uBlock Origin's version, file URL, and required SHA-256 digest together from AMO metadata, checks the add-on identity and public file status, and verifies bounded XPI bytes before staging. Invalid metadata or mismatched bytes cannot replace the cached extension. The digest trusts AMO over HTTPS; Nomad's signature-file check is only a layout sanity check. The browser performs cryptographic Mozilla signature validation at installation. Already-current cached files are not rehashed.
- **Unintended browser downgrades.** Update decisions reject older or unorderable browser release versions before download, including target changes and legacy marker migration. Obsolete cached metadata is refreshed; rejected fresh metadata cannot replace the cache. This compares release metadata, not executable contents, and does not defeat a compromised host or drive writer. See [downgrade protection](docs/UPDATE-SAFETY.md#downgrade-protection).
- **Casual inspection of the host after use.** Post-exit cleanup removes only individually attributed Recent shortcuts and WER reports after validating portable-folder ownership and the browser image path. Shared browser state, temp files, raw dumps, and compound Jump Lists are preserved because they cannot be attributed by name alone. Optional thumbnail/icon-cache and Prefetch clearing remains explicit opt-in. One owned cleanup coordinator handles each session; thumbnail clearing never stops Explorer and preserves files in use. Host traces can remain; see the cleanup limits in README.md.
- **Pre-existing filesystem aliases.** Portable-state writes and update roots reject symlinks and Windows reparse points before following them. Download basenames are fixed, staging is created exclusively, and temporary cleanup requires creation by the current operation. These metadata checks do not protect against a hostile writer replacing paths between checks and operations; drive write access and compromised hosts remain outside the threat model.
- **Helium component/installer separation.** The reviewed x64 0.19.2.1 flat bundle permits upstream component updates subject to existing update preferences and service consent. Its native installer eligibility guard rejects the flat layout; unreviewed versions/targets keep the old update block. Source review and inert fixtures do not replace live Windows validation. See [Helium component-update safety](docs/HELIUM-COMPONENT-UPDATES.md).
- **Malicious archives and stalled endpoints.** Extraction rejects path traversal and drive-absolute entries. ZIP output and streamed downloads are size-capped; metadata and extension responses are bounded before buffering. HTTP clients have connect, read and total deadlines. Bundled 7-Zip extraction has a deadline and observed output/entry limits before promotion. Its output may overshoot between scans; these are not OS disk, CPU or memory quotas. See [network and extraction budgets](docs/UPDATE-SAFETY.md#network-and-extraction-budgets).

Automatic HKCU handler repairs save bounded, validated write-ahead records before
mutation. Undo compares raw value type and bytes, preserves subsequent edits,
and disables automatic repair before restoring commands. The per-folder lock
serializes Nomad operations; a third-party registry writer can still race the
last comparison and write. Existing repairs without snapshots cannot be undone.
Explicit default-browser registration persists a validated cleanup plan before
its first HKCU write and retains it on failure for retry/removal. This is
recoverable partial state, not atomic multi-key rollback. New picker names are
scoped to the launcher location, and deletion requires a matching version-2 owner
record. Migration preserves historical shared entries and archives their records. See [registry repair safety](docs/REGISTRY-SAFETY.md).

### What Nomad does not defend against

- **Forensic examination of the host.** Windows keeps execution records Nomad cannot remove: Amcache and ShimCache, SRUM, the USN journal, event logs, and the pagefile. Prefetch scrubbing exists but requires a UAC elevation. If the host may be forensically examined, do not use it.
- **A compromised host.** Malware on the machine sees everything the browser does, regardless of hardening.
- **Read access to an unencrypted portable drive.** Profiles can retain history, account data and session cookies/tokens. Chromium OS-bound encryption is disabled for portability; use an encrypted volume for sensitive profiles.
- **Write access to the portable drive.** The launcher, browser, and profile are not integrity-protected at rest, and Chromium profile encryption (DPAPI) is disabled for portability. Anyone who can write to the drive can compromise it; keep it on an encrypted volume.
- **Network-level anonymity.** The hardening reduces fingerprinting and tracking. It does not hide your IP address or your traffic from the network operator. Use a VPN or Tor Browser for anonymity.
- **Unsigned upstreams.** LibreWolf, Floorp, Waterfox, Ungoogled Chromium, and Helium publish no usable signing key, so their integrity chain is TLS to the distribution host plus the hash that host publishes. There is no publisher key to pin because none exists.

## Build and CI safeguards

Distribution builds use the committed lockfile and the explicit Windows x64
target. Required inputs and the exact launcher set must be present; requested
signing and verification failures stop packaging. Metadata-only artifact checks reject external CRT/unreviewed direct or delayed DLL imports and missing CFG/System32-only import flags before completion. The Windows UI uses DX12/system FXC; graphics behavior and dynamic loads need separate validation. Signers work on an owned stage.
Final copied bytes are checked before the completion manifest is promoted.
Build failures remove completion manifests rather than leaving stale signatures
beside incomplete artifacts. File promotion is not a multi-file transaction;
partial output files may remain, but the workflow must stop on the error.

`NOMAD_SIGN_PASS` is rejected before child processes start. Certificate-store
thumbprints avoid putting PFX passwords in process arguments or inherited
environments. The script never imports certificates. Unsigned review/CI builds
remain supported; public release signing remains a separate owner action.

Hardening Sync defaults to no token permissions. Only its existing baseline-PR
jobs request contents/pull-request writes; verification jobs remain read-only.
CI checkouts used only for validation do not persist credentials. See
[Build and CI safeguards](docs/BUILD-SAFETY.md) for exact behavior and limits.

## Dependency audit policy

The canonical gate runs `cargo audit --json --deny warnings`, including
yanked-crate checks. Unmaintained, unsound, and yanked dependency findings fail
validation. The gate requires a clean structured report and captures stderr:
registry-check errors fail even if cargo-audit exits zero. Missing, malformed
or unsafe reports cannot establish completed validation.
`scripts/test-audit-gate.ps1` exercises these clean and failure cases with
mocked Cargo calls, so it requires no network or provisioning.

The only advisory exception is `RUSTSEC-2023-0071` (`rsa`, the Marvin private-key
timing attack). Nomad's production OpenPGP path verifies detached signatures
with public keys; it does not decrypt or perform RSA private-key operations.
Upstream has no patched release. Re-evaluate this exception if cryptographic
usage changes or a fixed release becomes available. Signature verification is
retained. The previous `quick-xml` exceptions were removed after upgrading its
dependency paths to patched releases.

## Vendored verification dependencies

The embedded 7-Zip extractor and browser public keys are outside Cargo audit.
See [vendored dependency maintenance](docs/VENDORED-DEPENDENCIES.md) for reviewed
extractor provenance, the offline file-integrity gate, and signing-key refresh
evidence and limitations.
