# Build and CI safeguards

The canonical gate runs locked Clippy/tests plus offline distribution and CI
regressions. CI also checks all workspace targets at Rust 1.92. Cargo's
[`--locked`](https://doc.rust-lang.org/cargo/commands/cargo-build.html#manifest-options)
rejects missing or changed dependency resolution; intentional dependency updates
must update and review `Cargo.lock` separately.

## Windows runtime and renderer

`.cargo/config.toml` adds static CRT linkage for Windows MSVC targets while
retaining CFG and `/DEPENDENTLOADFLAG:0x800`. Windows gate, CI, MSRV and manual
commands use explicit `--target x86_64-pc-windows-msvc`: Cargo then applies target
flags only to target crates, not host proc macros/build scripts
([Cargo rustflags](https://doc.rust-lang.org/cargo/reference/config.html#buildrustflags),
[Rust CRT linkage](https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes)).
Environment/compiler overrides can still change flags; artifact inspection must
pass before distribution completion, so an unsafe override cannot silently pass.

Windows UI builds enable only wgpu's DX12 backend. The setup explicitly uses
system FXC, disables external Agility SDK/debug-layer requests and clamps backend
selection instead of accepting unrelated WGPU backend/compiler environment
requests. Non-Windows tooling retains glow. A usable DX12 adapter is required;
Windows offers [WARP software rendering](https://learn.microsoft.com/en-us/windows/win32/direct3darticles/directx-warp).
Host tests construct configuration only and do not enumerate/probe adapters.
Live Windows/guest checks remain separate from build checks.

`scripts/artifact-guard.ps1` parses bounded PE metadata without loading/executing
binaries or requiring Visual Studio's dumpbin. `dist.ps1` checks built, staged
(after optional signing) and promoted launchers. It requires x64 PE32+ GUI images,
CFG flag/function-table metadata, dependent-load flag exactly `0x800`, and direct
and delayed DLL imports limited to the reviewed stock Windows allowlist/API-set
names. External VCRUNTIME/MSVCP/MSVCR imports and unreviewed DLL names fail.
Malformed, truncated and unsupported import layouts fail closed. Import checks
do not inspect every dynamic `LoadLibrary` request, prove CFG coverage of every
instruction, authenticate binaries, or establish graphics behavior on every OS.
Explicit system-shader-compiler selection and live smoke tests provide complementary evidence.

The canonical gate runs inert positive/negative PE fixtures, including external
CRT delay imports, bad RVA bounds, malformed descriptors and missing hardening.
Distribution fixtures check unsafe artifacts stop before signers/manifests and
preserve failure cleanup. These tests create no real browser or registry state.

## Distribution outputs

`dist.ps1` runs from its own checkout, builds `x86_64-pc-windows-msvc` with
an explicit `target` directory, and reads binaries from
`target/x86_64-pc-windows-msvc/release`. Validated outputs retain their public
location, `target/release`. Optional `-ArtifactDirectory` must stay beneath
this checkout's `target`; links, reparse points, parent/drive-relative paths
and wrong artifact types are refused.

The exact nine launcher names must match the workspace binary declarations.
Missing/empty or extra launcher outputs fail rather than silently shipping a
partial or stale set. The artifact guard, Cargo configuration, four license texts and `TRADEMARKS.md` must be nonempty
ordinary files before building. The notices and license destinations remain
self-contained beside the final binaries.

An OS file lock at `target/.nomad-dist.lock` serializes distribution invocations
in this checkout. The persistent lock file is not deleted to avoid lock races.
It does not serialize separate manual Cargo commands or arbitrary file writers.

After preflight, old checksum/signature completion artifacts are invalidated.
Binaries are copied into an exclusively created `target/.nomad-dist-<guid>`
stage; requested signing, license staging and checksum generation happen there.
Every promoted launcher is hashed again against the stage manifest. Only then
are `SHA256SUMS` and an optional `SHA256SUMS.asc` promoted.

Requested signing/build/copy/hash failures stop dependent work and leave no
completion manifest for the failed distribution. Previous/partially promoted
binary files can remain: promotion is not an atomic directory or multi-file
transaction. Do not publish or reuse those outputs after an error. Owned stage
cleanup verifies its path and refuses aliases. Host/drive writers and compromised
build/signing tools remain outside these metadata checks.

## Signing configuration

- `NOMAD_SIGN_CERT`: a public SHA-1 certificate-store thumbprint, or an
  existing password-free PFX path. Every requested Authenticode signature must
  pass [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
  verification with `verify /pa /all` before checksums are computed.
- `NOMAD_SIGN_PASS`: rejected before any child process starts. Password-bearing
  PFX support is retired; select a certificate already available in the store.
  Importing/setting up that certificate is a separate user action, never a test
  or automatic step here.
- `NOMAD_SIGNTOOL`: optional existing tool path. Invalid overrides fail instead
  of silently selecting another tool. `NOMAD_SIGN_TS` overrides the existing
  timestamp URL; it must be an absolute HTTP(S) URL without user-info credentials.
- `NOMAD_SIGNING_KEY`: requests detached GPG manifest signing. The public selector
  stays a literal argument; failure, missing output or failed verification aborts.
  `NOMAD_GPG` optionally supplies an existing tool path.

Unset signing selectors intentionally produce review/CI artifacts without
requesting signing. The draft-release workflow still requires the owner to sign
the downloaded manifest offline and attach its signature before publishing.
No certificate, token or real signing key is retrieved/imported by validation.

## Workflow permissions and validation limits

[Job-scoped permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
grant Hardening Sync writes only to the two existing baseline-PR jobs. Their
checkout credentials remain necessary for their existing branch pushes.
Verification jobs request only contents-read and disable credential persistence.
The general CI check/audit/MSRV checkouts also disable persistence. Source builds,
tests and upstream compatibility checks consistently use the committed lockfile.

`scripts/test-build-safeguards.ps1` runs copied scripts against inert temporary
artifacts and mocked Cargo/SignTool/GPG. It exercises required-input, signing,
promotion, checksum, lock and path failures and intentional unsigned/signed
successes. It runs on PowerShell 7 and Windows PowerShell 5.1.
`scripts/test-ci-safeguards.ps1` mocks the local gate and checks workflow wiring,
permission scopes and binary declarations, including deliberately unsafe fixtures.
It is not a full YAML/action linter. GitHub workflow analysis and real CI runs
remain separate checks.

These fixtures build/sign/publish nothing real, run no browsers or registry
operations, and change no certificate stores or persistent user configuration.
