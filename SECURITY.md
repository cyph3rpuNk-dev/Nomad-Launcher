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

## Threat model

### What Nomad defends against

- **Tampered browser downloads.** Every package is hash-verified (SHA-256, or SHA-512 for Waterfox). Where the upstream signs, the signature is verified against an embedded key: Firefox and Mullvad via GPG, uBlock Origin's Chromium build via a GPG-verified release tag plus an asset-timeline tamper check, Bitwarden additionally via Authenticode signer pinning. A package with no verifiable integrity material is refused. A failed verification aborts before extraction and leaves the existing install untouched.
- **Casual inspection of the host after use.** The post-exit scrub removes browser temp files, Recent shortcuts pointing at the portable drive, Jump List entries, WER crash dumps, and browser runtime directories from `%LOCALAPPDATA%`/`%PROGRAMDATA%`.
- **Malicious archives.** Extraction rejects path traversal and drive-absolute entries and enforces decompressed-size budgets against zip bombs. Downloads are size-capped.

### What Nomad does not defend against

- **Forensic examination of the host.** Windows keeps execution records Nomad cannot remove: Amcache and ShimCache, SRUM, the USN journal, event logs, and the pagefile. Prefetch scrubbing exists but requires a UAC elevation. If the host may be forensically examined, do not use it.
- **A compromised host.** Malware on the machine sees everything the browser does, regardless of hardening.
- **Write access to the portable drive.** The launcher, browser, and profile are not integrity-protected at rest, and Chromium profile encryption (DPAPI) is disabled for portability. Anyone who can write to the drive can compromise it; keep it on an encrypted volume.
- **Network-level anonymity.** The hardening reduces fingerprinting and tracking. It does not hide your IP address or your traffic from the network operator. Use a VPN or Tor Browser for anonymity.
- **Unsigned upstreams.** LibreWolf, Floorp, Waterfox, Ungoogled Chromium, and Helium publish no usable signing key, so their integrity chain is TLS to the distribution host plus the hash that host publishes. There is no publisher key to pin because none exists.
