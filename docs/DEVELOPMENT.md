# Development

[Back to the overview](../README.md) · [Project charter](../PROJECT-CHARTER.md) · [Engineering policy](../AGENTS.md) · [Specification](../SPEC.md)

## Building from source

Requires Rust 1.92+ on Windows 10/11.

```powershell
pwsh -NoProfile -File scripts/check.ps1  # canonical local/CI validation gate
cargo build --workspace --locked --target x86_64-pc-windows-msvc # debug build
.\dist.ps1                       # release build → target/release/Nomad-<browser>.exe
cargo test --workspace --locked --target x86_64-pc-windows-msvc # test suite
cargo clippy --workspace --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings
```

The repository uses rolling stable for development and separately checks the
declared Rust 1.92 minimum supported version in CI. The dependency gate treats
all audit warnings, including yanked crates, as failures. Its sole documented
advisory exception is the verification-only RSA timing finding; see
[Dependency audit policy](../SECURITY.md#dependency-audit-policy).

The repository Windows MSVC flags statically link the C runtime and retain CFG
and System32-only import search. Use the explicit `--target` on Windows so
Cargo keeps host-side proc macros/build scripts separate from those flags.
The canonical gate does this automatically; non-Windows tooling keeps its native
OpenGL renderer and target. See [build and artifact checks](BUILD-SAFETY.md).

`dist.ps1` builds the explicit Windows x64 target with locked dependencies,
requires all six launchers and license inputs, and stages signing and packaging
before promoting the distribution into `target/release`. Requested signing
must succeed and verify. Unrequested signing remains optional for review/CI
builds; release publication still requires the owner's offline manifest signature.

Password-bearing PFX signing via `NOMAD_SIGN_PASS` is rejected before any
build or signer starts. Use a certificate already in your certificate store,
selected by its public thumbprint in `NOMAD_SIGN_CERT`. The script does not
import certificates or retrieve secrets. See [Build and CI safeguards](BUILD-SAFETY.md)
for signing options, output paths, failure behavior and offline checks.
