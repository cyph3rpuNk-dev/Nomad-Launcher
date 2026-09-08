# Project Charter

## Identity

- Name: Nomad Launcher
- Status: ACTIVE
- Visibility: Public
- License: MIT OR Apache-2.0

## Purpose

Nomad Launcher provides auditable, single-file Windows launchers that keep a
browser, its profile, and launcher state portable. It solves the gap between a
normal machine-bound browser installation and a user-controlled browser tree
that can be moved without silently installing software elsewhere on the host.

## Users and outcomes

- Portable-browser users: launch the intended browser and profile from one
  self-contained directory.
- Privacy-conscious users: receive verified upstream packages and transparent,
  reversible hardening.
- Maintainers: detect upstream incompatibility before it overwrites a working
  installation or causes custom overlays to disappear.

## Current milestone

Build an update-safe architecture that permanently addresses four observed
failure classes:

1. prevent one launcher (for example Helium) from claiming another launcher's
   browser/profile state;
2. keep default-browser URL handoff in the existing portable browser instance
   without allowing the protocol path to install or update software;
3. continuously exercise Floorp metadata, checksum, extraction, and executable
   discovery against upstream releases;
4. make update overlays fail closed and retryable so Chromium resource-ID drift
   cannot be recorded as a successful branding operation.

## Technical baseline

- Language: Rust 2021
- Toolchains: rolling stable for development; Rust 1.88 MSRV compatibility gate
- Primary target: `x86_64-pc-windows-msvc`
- Dependency strategy: Cargo with committed `Cargo.lock`
- UI: eframe/egui with the glow renderer
- CI/local gate: `pwsh -NoProfile -File scripts/check.ps1`

## Trust boundaries and invariants

- Upstream release APIs, archives, signatures, hashes, and browser package
  layouts are untrusted inputs.
- The active browser and user profile are durable state; staging and backup
  directories are launcher-owned transactional state.
- The updater may replace only the owned browser bundle after verification and
  preparation have completed.
- The launcher must not silently provision software from an OS protocol launch.
- A successful marker means every required overlay was found, applied, and
  verified for the installed build.
- Release promotion is blocked when upstream metadata, verification material,
  extraction layout, launch target, or required overlays are incompatible.

## Definition of done

A change is ready when the canonical gate passes, new failure paths have
regression coverage, documentation matches behavior, and any live-upstream
compatibility check has been run or explicitly reported as unavailable.

## Open decisions

- Whether launcher self-update belongs in this repository or a separate signed
  distribution tool.
- Whether future releases should be Authenticode-signed in addition to current
  checksum, GPG, and GitHub provenance verification.
