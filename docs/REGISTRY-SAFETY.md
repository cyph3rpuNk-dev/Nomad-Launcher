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

## Limits

- Older versions did not save originals. Already-repaired commands without a
  snapshot remain unchanged; Nomad cannot safely guess their previous arguments.
- The compare and registry write are separate operations. A browser or another
  registry writer can race between them; the lock coordinates Nomad processes
  in one folder only. Close the browser before explicit registration changes.
- Raw REG_EXPAND_SZ bytes are preserved, but environment-variable executable
  paths are not expanded or repaired.
- The journal covers automatic command repairs. Existing explicit registration
  still uses browser-wide Nomad ProgID names and its separate removal sidecar;
  cross-instance picker ownership and registration failure atomicity remain
  separate work.
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
