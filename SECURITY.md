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

- **Tampered browser downloads.** Every package is hash-verified (SHA-256, or SHA-512 for Waterfox). Where the upstream signs, the signature is verified against an embedded key: Firefox and Mullvad via GPG, uBlock Origin's Chromium build via a GPG-verified release tag plus an asset-timeline tamper check, Bitwarden additionally via Authenticode signer pinning. An adapter with an embedded package-signing key requires its detached signature: missing, unreadable, invalid or failed-to-download signatures cannot fall back to a matching hash. Firefox instead verifies the signed checksum manifest during release resolution. A package with no verifiable integrity material is refused. A failed verification aborts before extraction and leaves the existing install untouched.
- **Unintended browser downgrades.** Update decisions reject older or unorderable browser release versions before download, including target changes and legacy marker migration. Obsolete cached metadata is refreshed; rejected fresh metadata cannot replace the cache. This compares release metadata, not executable contents, and does not defeat a compromised host or drive writer. See [downgrade protection](docs/UPDATE-SAFETY.md#downgrade-protection).
- **Casual inspection of the host after use.** Post-exit cleanup removes only individually attributed Recent shortcuts and WER reports after validating portable-folder ownership and the browser image path. Shared browser state, temp files, raw dumps, and compound Jump Lists are preserved because they cannot be attributed by name alone. Optional thumbnail/icon-cache and Prefetch clearing remains explicit opt-in. Host traces can remain; see the cleanup limits in README.md.
- **Pre-existing filesystem aliases.** Portable-state writes and update roots reject symlinks and Windows reparse points before following them. Download basenames are fixed, staging is created exclusively, and temporary cleanup requires creation by the current operation. These metadata checks do not protect against a hostile writer replacing paths between checks and operations; drive write access and compromised hosts remain outside the threat model.
- **Malicious archives and stalled endpoints.** Extraction rejects path traversal and drive-absolute entries. ZIP output and streamed downloads are size-capped; metadata and extension responses are bounded before buffering. HTTP clients have connect, read and total deadlines. Bundled 7-Zip extraction has a deadline and observed output/entry limits before promotion. Its output may overshoot between scans; these are not OS disk, CPU or memory quotas. See [network and extraction budgets](docs/UPDATE-SAFETY.md#network-and-extraction-budgets).

### What Nomad does not defend against

- **Forensic examination of the host.** Windows keeps execution records Nomad cannot remove: Amcache and ShimCache, SRUM, the USN journal, event logs, and the pagefile. Prefetch scrubbing exists but requires a UAC elevation. If the host may be forensically examined, do not use it.
- **A compromised host.** Malware on the machine sees everything the browser does, regardless of hardening.
- **Write access to the portable drive.** The launcher, browser, and profile are not integrity-protected at rest, and Chromium profile encryption (DPAPI) is disabled for portability. Anyone who can write to the drive can compromise it; keep it on an encrypted volume.
- **Network-level anonymity.** The hardening reduces fingerprinting and tracking. It does not hide your IP address or your traffic from the network operator. Use a VPN or Tor Browser for anonymity.
- **Unsigned upstreams.** LibreWolf, Floorp, Waterfox, Ungoogled Chromium, and Helium publish no usable signing key, so their integrity chain is TLS to the distribution host plus the hash that host publishes. There is no publisher key to pin because none exists.

## Dependency audit policy

The canonical gate runs `cargo audit --deny warnings`, including yanked-crate
checks. Unmaintained, unsound, and yanked dependency findings fail validation.
`scripts/test-audit-gate.ps1` exercises clean and failure cases with mocked
Cargo calls, so it requires no network or provisioning.

The only advisory exception is `RUSTSEC-2023-0071` (`rsa`, the Marvin private-key
timing attack). Nomad's production OpenPGP path verifies detached signatures
with public keys; it does not decrypt or perform RSA private-key operations.
Upstream has no patched release. Re-evaluate this exception if cryptographic
usage changes or a fixed release becomes available. Signature verification is
retained. The previous `quick-xml` exceptions were removed after upgrading its
dependency paths to patched releases.
