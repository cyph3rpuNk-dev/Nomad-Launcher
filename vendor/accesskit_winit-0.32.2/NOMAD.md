# Nomad accessibility dependency patch

This is the published `accesskit_winit` 0.32.2 crate, with its Rust source
unchanged. The downloaded crate's SHA-256 was checked against the original
`Cargo.lock` checksum before extraction. `provenance.json` records the package,
upstream revision and hashes of the retained files, including the patched
manifest. The upstream package lockfile is omitted; the workspace lockfile is
authoritative. `LICENSE-APACHE` comes from the same upstream revision.
The final blank line in `Cargo.toml.orig` is trimmed for repository whitespace
checks; its dependency declarations are unchanged.

The sole manifest change removes `accesskit_unix` and `async-io` from default
features. Windows accessibility still uses upstream `accesskit_windows` 0.32.1.
The raw-window-handle and window-system features are unchanged. Non-Windows
tooling uses the upstream null accessibility adapter on Unix; Unix screen-reader
integration is intentionally unavailable. Nomad ships Windows launchers only.

The egui-winit versions compatible with Nomad's Rust 1.92 MSRV enable these
defaults without an opt-out. The unused Unix adapter brings in `zbus_names`,
`zvariant` and `zvariant_derive`, declared unmaintained in RUSTSEC-2026-0370,
RUSTSEC-2026-0371 and RUSTSEC-2026-0372 after their merger into zbus 6.
Even accesskit_unix 0.24.0 still requires zbus 5. This patch removes the unused
dependency path without suppressing audit warnings or changing Windows code.

To refresh, verify the new crate archive against its registry checksum, compare
the upstream source and feature declarations, retain its license, regenerate
the file hashes and run the canonical gate plus the separate Rust 1.92 check.
Remove this patch and the workspace exclusion when an MSRV-compatible egui-winit
allows disabling Unix accessibility defaults, or its Unix stack uses maintained
dependencies. Recheck the audit and Windows accessibility dependency tree.

`scripts/test-accesskit-vendor.ps1` checks the pinned snapshot and rejects source
drift, manifest drift, missing files and missing hash entries. Compilation and
these checks do not establish live screen-reader behavior.
