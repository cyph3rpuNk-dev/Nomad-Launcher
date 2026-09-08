# Nomad Launcher engineering policy

Nomad Launcher builds portable Windows browser launchers. Start with
`PROJECT-CHARTER.md`, then read `README.md`, `SPEC.md`, and `SECURITY.md` before
changing update, launch, cleanup, registry, or verification behavior.

## Canonical validation

Run `pwsh -NoProfile -File scripts/check.ps1`. The script is the local and CI
gate: formatting, Clippy with warnings denied, workspace tests, and dependency
advisories. Use `-SkipAudit` only when `cargo-audit` is unavailable and report
the skipped check honestly. Do not claim CI passed before it runs.

## Safety invariants

- Verify every downloaded executable/archive before extraction or execution.
  Fail closed if no supported signature or digest can be verified.
- Stage and validate a complete update before swapping it into place. A failed
  update must leave the current browser and profile launchable.
- Treat one launcher directory as one owned browser instance. Never allow a
  differently branded launcher to silently reuse or replace its `Browser/`,
  `Data/`, `Nomad/`, staging, or backup paths.
- A URL/file protocol invocation may launch an existing portable browser, but
  must never provision or update software. Installation and updates require a
  direct, visible launcher invocation.
- Browser updates replace upstream-owned files. Reapply overlays to the staged
  version and verify every required overlay before recording success.
- Keep profiles and user configuration outside replaceable browser bundles.
  Never delete or rewrite data outside paths demonstrably owned by this
  launcher instance.
- Registry writes must be explicit registration/repair operations, limited to
  HKCU, tracked in owned state, and reversible.
- Keep check, doctor, and test paths free of real provisioning, browser launch,
  hardware probes, and persistent user/system configuration changes.
- Treat URLs and tokens as data. Do not interpolate them into executable source,
  print credentials, or leave temporary process credentials behind.

## Compatibility

- Preserve Windows 10/11 and the `x86_64-pc-windows-msvc` release target.
- Keep the workspace MSRV (`rust-version`) tested separately from rolling stable.
- Preserve LF endings and keep `Cargo.lock` committed.
- Add a regression test for every safety or failure-path change.
- Do not weaken verification, compatibility gates, or ownership checks merely
  to make a newly changed upstream release install.
