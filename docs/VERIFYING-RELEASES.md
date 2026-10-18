# Verify a release

[Back to the overview](../README.md) · [Release integrity policy](../SECURITY.md#release-integrity)

Download the launcher, `SHA256SUMS`, and `SHA256SUMS.asc` from the same
[release](https://github.com/cyph3rpuNk-dev/Nomad-Launcher/releases/latest).
Obtain [the public signing key](../nomad-release-signing-key.asc) and cross-check
its fingerprint independently as described below. Run the commands in the
folder containing those files. Continue only if the signature is valid and the
launcher's hash matches. Use Git Bash or WSL for the `sha256sum` command, or the
PowerShell alternative below.

## Signature and checksum

```bash
# Import the Nomad release key and confirm the fingerprint:
# 4F90 CF11 723D C3A2 E719 8331 FEF9 81E9 09EF 44ED
gpg --import nomad-release-signing-key.asc
gpg --fingerprint 4F90CF11723DC3A2E7198331FEF981E909EF44ED

# The key is also published on keyservers independent of this repository,
# so you can cross-check that the copy here hasn't been swapped:
gpg --keyserver hkps://keys.openpgp.org --recv-keys 4F90CF11723DC3A2E7198331FEF981E909EF44ED

# Verify the manifest, then check your binary against it
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

> **Key rotation (v1.0.2):** access to the previous signing key
> (`4D92 5DAD 1DB4 405C 99EA 1FD3 9984 5DA3 20CD 1F37`) was lost; it is not
> believed compromised. Releases up to and including v1.0.1 remain verifiable
> against that key ([announcement](https://github.com/cyph3rpuNk-dev/Nomad-Launcher/releases/tag/v1.0.2)).

On Windows PowerShell: `(Get-FileHash .\Nomad-Floorp.exe -Algorithm SHA256).Hash.ToLower()` and compare against the `SHA256SUMS` line.

## Build provenance

Releases after v1.0.2 are also built from source by a GitHub Actions workflow ([release.yml](../.github/workflows/release.yml)) that records signed build provenance. With the [GitHub CLI](https://cli.github.com/) installed, you can check that a binary was produced by that workflow from this repository's code rather than on someone's machine:

```bash
gh attestation verify Nomad-Floorp.exe --repo cyph3rpuNk-dev/Nomad-Launcher
```

The same command works for any of the launchers and for the `SHA256SUMS` file itself. Attestation is independent of the GPG key above, so the two checks back each other up.

## Publishing and reruns

The release workflow accepts only a new release or an empty draft. It checks
eligibility before building and rechecks draft status before uploading. Published
releases and drafts that already contain assets stop the run; assets are never
automatically deleted or replaced. Runs for the same tag are serialized.

If an upload fails partway through, inspect the draft and explicitly review/reset
it before rerunning, or use a new release tag. After a successful build, attach and
verify `SHA256SUMS.asc`, then publish only after the workflow has finished. GitHub
status checks and upload are separate operations; omitting `--clobber` also protects
existing assets if publication or another upload races the final check.
