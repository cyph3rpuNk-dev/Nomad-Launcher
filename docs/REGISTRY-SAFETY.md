# Registry repair safety

Nomad's automatic repair redirects recognized browser self-registrations through
the launcher so URL opens use the portable profile. It inspects HKCU ProgID,
Applications and StartMenuInternet open commands. It never changes UserChoice.

## Journal and undo

`core/src/registry/repair_journal.rs` implements the write-ahead journal and an
in-memory-testable registry interface. `core/src/registry.rs` supplies the HKCU
adapter and enumeration. Launch, live watcher and exit sweeps all use this path;
`core/src/lib.rs` routes `--unregister-default` through conditional undo.

Before a repair, Nomad atomically saves the original raw bytes and registry type
(REG_SZ or REG_EXPAND_SZ), the exact replacement and the key path in
`Nomad/nomad.registry-repairs.json`. The journal is separate from the existing
`nomad.reg-state.json` picker-registration record. Repeated repairs do not replace
an original snapshot with Nomad's own command. A later browser self-registration
updates the snapshot to that newly observed browser command.

A persistent `Nomad/registry-repair.lock` serializes Nomad repairs, registration
and CLI unregistration in one folder. A busy lock skips an automatic sweep;
explicit operations report failure and can be retried. Never delete the lock file.

Unregister first persists `enabled: false`, then restores only values whose raw
bytes and type still equal the recorded replacement. Missing or changed values
are preserved. A failed restore retains the journal and the disabled state for
retry; a successful restore clears entries but retains the disabled journal.
Thus an active helper cannot immediately repair the restored browser commands.
Successful `--register-default` reenables repair. Unregister also works when only
automatic repairs exist and no Nomad picker registration was created.

## Validation and recovery

The schema rejects unknown fields, duplicate keys and mismatched launcher or
installation paths. Its limits are 4 MiB serialized state, 4,096 entries and
64 KiB per original command. Supported keys have an exact command-path shape.
Original commands must point inside the validated sibling browser installation,
without parent traversal, Windows path aliases or filesystem reparse points.
Only recognized browser flags and one URL placeholder are accepted; customized
arguments are preserved rather than logged or copied into the journal.

Journal read, validation or persistence failure prevents the associated repair.
A crash after journaling but before writing is safe to retry: undo compares the
current value before restoring anything. Journal errors do not prevent ordinary
browser launching. Explicit register/unregister errors are reported to the user.

Run `--unregister-default` before moving the folder, renaming the launcher or
changing the installation directory. Then register again from the new location.
Outstanding records refuse relocation rather than rewriting their historical
paths. If already moved, return the folder/launcher to its original location and
unregister there before moving again. Preserve unreadable or mismatched journals
for review; deleting one discards the repair history and disabled state.

## Explicit registration failure recovery

`core/src/registry/registration.rs` builds the 16 explicit registration values
and their cleanup plan. Before any HKCU mutation, it atomically saves the plan
in `Nomad/nomad.reg-state.json`, using a version-2 format bound to the current
launcher location. Existing records must match the supported schema, browser ID and exact planned key/value
lists; inputs over 64 KiB, unknown fields and malformed records are refused.
A record for another browser is preserved and prevents registration writes.

A failed sidecar save makes no registration writes and preserves the prior
record. A registry write failure stops further writes and keeps the complete
plan. Retry `--register-default` to finish the same plan, or use
`--unregister-default` to remove partial entries. RegisteredApplications is
written last. Reenabling automatic repair can also fail after registry writes;
that failure reports an incomplete registration with the same recovery options.

Unregister validates the record before removing picker entries. Missing keys or
values from an interrupted registration are harmless. Removal failures retain
the record for retry; a failure deleting the record itself is reported too.
Do not treat the mere presence of the file as a successful registration marker.
This provides recoverability, not a multi-key registry transaction or automatic
rollback of prior values after a failed refresh.

## Separate portable copies and migration

New names derive from SHA-256 over the browser ID, a NUL separator and the
canonical launcher-parent path plus executable filename, folded to ASCII
lowercase. The ProgID is `NomadPortable.` plus 24 digest hex characters (38
characters total); capability roots and RegisteredApplications use the full
digest. This follows Microsoft's [ProgID length and character guidance](https://learn.microsoft.com/en-us/windows/win32/com/-progid--key).
The Windows picker label includes the folder so copies can be distinguished.

Version-2 state binds the generated key/value names to that launcher path.
Unregistration validates the current location before any picker deletion or
CLI automatic-repair undo. Copied records, modified paths and legacy version-1
records cannot authorize removal. A per-folder lock serializes CLI operations;
separate copies address different registry names.

On explicit registration, a valid same-browser record from another location or
an old version-1 record is preserved under `Nomad/registration-history/` in a
file named by the record's SHA-256. An existing matching archive is reused; a
conflicting, unreadable or redirected archive stops the attempt. The archive
must be saved before replacing the active plan or performing registry writes.
A failure replacing the active plan leaves the prior plan available for retry.

Migration creates a new entry and leaves all historical registry entries alone.
Select the new folder-labelled entry in Windows Default apps. Old shared entries
may still appear and need manual review; the archive is a record, not automatic
permission to delete them. An unregister attempt against an old/shared or copied
record gives guidance to register this location first. Automatic repair journals
with outstanding snapshots still require undo at the original location before
moving, as described above.

## Limits

- Older versions did not save originals. Already-repaired commands without a
  snapshot remain unchanged; Nomad cannot safely guess their previous arguments.
- The compare and registry write are separate operations. A browser or another
  registry writer can race between them; the lock coordinates Nomad processes
  in one folder only. Close the browser before explicit registration changes.
- Raw REG_EXPAND_SZ bytes are preserved, but environment-variable executable
  paths are not expanded or repaired.
- Older launcher versions still use shared names. Migration leaves those entries
  intact; old executables can still change their shared entries. Removing stale
  historical registrations remains a manual review operation.
- Identity is location-based, not a globally unique installation ID. Replacing a
  launcher at the same path reuses that location's names. Case-sensitive Windows
  directories and deliberately engineered digest collisions are not supported.
- Filesystem checks reject existing redirects, but cannot defeat a hostile writer
  swapping paths concurrently. Portable-drive write access is outside the threat
  model. Journal durability also depends on the filesystem and storage device.

## Validation

The canonical gate exercises this logic using an in-memory registry and owned
temporary directories. Tests cover write-ahead ordering, exact type/byte restore,
write failures, retries, user edits/deletions, concurrent edits, disabled watchers,
relocation, malformed and oversized state, locking, and filesystem aliases.
Native HKCU tests remain explicitly ignored and require a separate isolated
Windows test account. A passing local gate does not establish a live Windows
Default-apps or multi-process browser smoke-test result.

Explicit registration tests use injected writes, covering failures before and
after each of the 16 writes (32 interruption cases), retry, write-ahead ordering,
sidecar persistence failure, rejected old records and failed record deletion.
They do not create or modify real HKCU entries.

Ownership tests cover two copies in one fake registry, deletion of one while
preserving the other, copied-state rejection, stable/distinct identities,
legacy migration without shared-key writes, archive failures and retries, and
tampered scoped paths. No live HKCU entries are changed by these tests.
