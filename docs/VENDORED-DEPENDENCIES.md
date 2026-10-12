# Vendored dependency maintenance

Cargo audit does not inspect the embedded 7-Zip executable/DLL or public signing
keys. These require separate source review and freshness checks.

## Bundled extractor

Nomad embeds the x64 `7z.exe` and `7z.dll` from 7-Zip 26.04. The versioned
[source package](https://github.com/ip7z/7zip/releases/tag/26.04), package SHA-256,
and individual vendored-file SHA-256 hashes are recorded in
[`manifest.json`](../core/payloads/7zip/manifest.json). The package digest was
compared with the official `ip7z/7zip` GitHub release asset metadata before the
package was extracted as an archive; its installer was never executed.
Only the two extractor files and the license text were copied. The license text
uses LF line endings; the executable and DLL are byte-for-byte upstream files.

The canonical Rust test gate checks all three vendored hashes and the binaries'
x64 PE machine type. The existing extraction test executes the
bundled extractor against an inert ZIP in an owned temporary directory. It does
not install a browser or prove compatibility with every current NSIS package.

The [upstream history](https://www.7-zip.org/history.txt) lists security fixes
between the previous 24.09 snapshot and 26.04. Check that history and the
[official download page](https://www.7-zip.org/download.html) during maintenance;
the offline hash test detects unreviewed file drift, not future upstream
releases or vulnerabilities. A deliberate refresh must update the package
provenance, both binaries, license, hashes and README together, and pass the
canonical gate. A hash from GitHub release metadata depends on GitHub's integrity;
it is not an independent publisher signature.

## Browser signing keys

On 2026-10-07, `scripts/check-signing-keys.sh` found the embedded Firefox key
covered Firefox 157.0.1 and ESR 140.17.0esr, and the gorhill key covered uBlock
1.75.0. Mullvad 15.0.24 used signing subkey
`022DA248432D2A0E0F54E65E316C1FACD62D07D9`, absent from the old snapshot.

The Mullvad public key was refreshed from the
[Tor Project WKD endpoint](https://openpgpkey.torproject.org/.well-known/openpgpkey/torproject.org/hu/kounek7zrdx745qydx6p59t9mqjpuhdf)
linked by [Mullvad's verification guide](https://mullvad.net/en/help/verifying-mullvad-browser-signature).
The primary fingerprint remains
`EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`, matching both the previous embedded
key and the published fingerprint. No new primary trust anchor was introduced.
The refreshed key was merged with the previous snapshot in a disposable keyring, retaining every historical subkey
for verification of older releases. GPG `export-clean` removes unusable
third-party certifications while retaining all nine primary/subkey IDs; trust
remains based on the pinned primary and its binding signatures.
The refreshed armored file's SHA-256 is
`171fc26632b5fa7ce065befd07b37e9b534e0b4a5668c772cab79b2d44141926`.

The small offline fixtures `core/tests/fixtures/mullvad-15.0.24-sha256sums.txt`
and its `.asc` are the exact `sha256sums-signed-build.txt` and signature from
[the upstream release](https://github.com/mullvad/mullvad-browser/releases/tag/15.0.24).
They are release metadata, not executable browser fixtures. Their signature
failed with the old embedded key and was checked with GPG in a disposable keyring
before replacement. Tests now verify that signature through Nomad's Rust
verification path, the primary fingerprint, and the key/subkey binding signatures.
The final live coverage check passed for Firefox, Firefox ESR, Mullvad and
uBlock after the refresh. Never normalize bytes covered by a detached signature.

The weekly Hardening Sync workflow already runs the public signing-key coverage
script. Run it with a disposable `GNUPGHOME` when checking locally; Git Bash
needs an MSYS-style path such as `/c/...`, not a Windows backslash path. The
script fetches metadata and signatures only and checks issuer-key membership.
It does not verify the browser package, key expiry/revocation policy, or full
upstream compatibility. Transport/tool failures must be investigated before
concluding that a key is stale. Refresh subkeys only after verifying their
binding to the existing primary; a primary-key rotation requires a separate
trust review. Never import public keys into the user's personal keyring for
repository validation, retrieve private keys, or configure ownertrust.
