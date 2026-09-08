# Update and instance safety

This document records the architecture behind Nomad's update safeguards. It is
normative for code that changes installation, update, branding, protocol
handoff, or portable-folder layout.

## Why changes used to reappear

A Nomad browser update is a bundle replacement, not an in-place browser patch.
The new upstream archive is extracted to a staging directory and then replaces
the active `Browser/` directory. Any manual change made inside `Browser/` is
therefore upstream-owned state and is expected to disappear at the next swap.

Nomad reapplies declared overlays after an update. The Chromium help-page logo
is one such overlay: it replaces grit-numbered resources in
`chrome_100_percent.pak` and `chrome_200_percent.pak`. Those numeric IDs can
change between Chromium majors. Older code safely skipped a missing or
wrong-sized resource, but incorrectly treated the rebuilt PAK as successful and
could write `.branding-patched`. That marker suppressed future retries, making
the reverted icon appear permanent.

The rebuild changes the contract: every required resource must be found and
match its expected dimensions, and every target must be written, before the
branding marker can exist. A newly downloaded browser is branded while it is
still staged. If any required overlay is incompatible, the atomic swap is
aborted and the currently working browser remains in place.

## Update transaction

```text
resolve release
      |
      v
compatibility gate ---- incompatible ---> keep current install, report error
      |
      v
download -> authenticate -> extract to staging
                              |
                              v
                  apply and verify overlays
                              |
                     failure  |  success
                       |      v
                       |   write version marker
                       |      |
                       |      v
                       +-> no swap   atomic swap -> launch
```

Authentication and compatibility answer different questions. A valid digest or
signature proves that a package matches what upstream published. The
compatibility gate proves that this launcher understands that package's layout
and required overlays. Both must pass.

Ungoogled Chromium is certified by major version because its required branding
uses version-sensitive PAK resources. The weekly upstream workflow deliberately
fails when a newer major appears. Maintainers then inspect the official portable
archive, update and verify the overlay manifest, exercise extraction, and raise
the certified major in the same reviewed change.

Floorp's weekly check goes beyond metadata parsing: it downloads the current
release, verifies its published SHA-256, extracts it to a temporary directory,
checks the configured executable exists, and checks that the version marker
survives the swap. It never launches the browser or writes user configuration.

## One folder, one browser family

All launchers historically used the same relative names (`Browser/`, `Data/`,
and `Nomad/`). Placing Nomad-Chromium and Nomad-Helium in one folder therefore
let either executable interpret and replace the other's state. This is the most
credible code-level explanation for Helium appearing after a Chromium update.

`Nomad/instance.toml` now records the stable browser ID that owns the portable
folder. The first launcher to use an unclaimed folder writes it atomically.
Every later run must match it. A mismatch or corrupt marker fails closed before
the updater can touch `Browser/` or `Data/`.

For an existing portable folder without a marker, launch the browser that
already owns that folder once after upgrading Nomad. It will claim the folder.
Move any other Nomad launcher executables into their own empty directories.
Never edit `instance.toml` to convert a folder between browser families; move or
back up the profile and create a fresh instance instead.

## Direct launch versus protocol launch

The registry command uses `"Nomad-<browser>.exe" -- "%1"`. Arguments after
`--` identify an OS URL/file-protocol invocation. That path is launch-only:

- it requires an existing version marker and browser installation;
- it disables browser update checks and automatic downloads;
- it disables extension provisioning that is coupled to update checks;
- it forwards the URL to the same executable and portable profile used by a
  direct launch, allowing Chromium's normal single-instance handoff to open a
  tab in the existing window.

A direct launcher invocation remains the only path that may install or update
software. This keeps ordinary link clicks from becoming hidden provisioning
events and makes unexpected installs attributable and reproducible.

## Success markers

Markers are assertions, not hints. Code may write a success marker only after
the corresponding postcondition has been verified. Missing targets, skipped
resources, partial writes, or incompatible layouts leave the marker absent so
the operation is retried after the launcher is updated. Tests must cover both
the success path and every fail-closed condition.
