# Independently initialized Windows recovery qualification

## Status and acceptance boundary

**Prepared only.** This package adds a separate ignored lib-test fixture and
bounded runner/verifiers for public-payload binding checks on two independently
initialized disposable Windows x64 VMs. The native matrix has not run merely
because it compiled, its metadata regressions passed, or a package exists.
The release isolation claim remains unverified until all four phases and the
host matrix verifier pass with reviewed VM provenance.

The [original Sandbox suite](CLEANUP-RECOVERY-QUALIFICATION.md) is unchanged.
Its same-context pass and second-Sandbox machine-only decryption observation
remain valid within their original scopes. Never spoof WDAGUtilityAccount or
relax that suite's guards. Another Sandbox is not this qualification.

**Verified in code:** `core/src/cleanup_recovery/vm_binding_tests.rs` is included
only by Windows lib tests. Its native function is explicitly ignored. It calls
the production `NativeBinding`, `dpapi`, journal arm/decode/replay/retirement and
instance-lock code. It never calls a host trace scanner, runs a browser, launches
a child executable from the fixture, writes a registry key, provisions software
or creates a user/VM. The inert image is a text marker that is never executed.
ReturnOrigin retires its own journal through an inert successful callback; this
is not a Recent/WER cleanup effectiveness test.

## Required environments

Use two disposable x64 Windows installations initialized separately from trusted
installation media, with no personal files, credentials, accounts or browser
profiles. Do not clone a Windows installation after its accounts/key stores were
initialized, copy a user profile or transfer Windows cryptographic stores.
Creating the VMs/accounts and signing in are operator actions, outside this tool.
The preparer does not install a hypervisor, retrieve an OS image or configure the
personal host. Keep both VMs offline for all native phases.

| Machine | Exact fresh local account | Phase | Expected public-payload result |
|---|---|---|---|
| VM A, origin | NomadRecoverySource | Origin | User, machine and nested samples round-trip; original inert journal remains. |
| Same VM A | NomadRecoveryPeer | PeerUser | Machine sample opens; user, nested sample and journal ciphertext are refused; copied intent bytes remain. |
| Independently initialized VM B | NomadRecoveryForeign | ForeignMachine | User, machine, nested sample and journal ciphertext are refused; copied intent remains. |
| Return to VM A | NomadRecoverySource | ReturnOrigin | All three samples open; original journal still matches the exported bytes and retires through one inert completed callback. |

Use nonroaming local accounts with exact `C:\Users\<name>` profiles; redirected
profiles, domain accounts, other account names, Sandbox and nonnative-x64 shells
are refused. The runner must reside at `C:\NomadVmRecoveryInput` and requires
`-AcknowledgeDisposableVm`. A manually reviewed `DISPOSABLE-VM.json` enrollment
must name this campaign/role and affirm independent initialization/no personal
data. The examples deliberately start with both affirmations false; edit them
only after the conditions are true in the disposable VM.

**Operational guards, not attestation:** names, paths, enrollment and fingerprints
cannot establish that a hostile administrator actually supplied a disposable VM.
The native guard independently checks the current Windows token SID and public
MachineGuid as campaign-salted hashes. Different identifiers alone do not prove
different DPAPI keys. Reviewed initialization provenance and the actual machine-
only refusal are both required; no fingerprint or changed machine name substitutes
for the cryptographic observations.

Microsoft's [DPAPI contract](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
describes ordinary user protection, machine-scope sharing with other users on the
same computer and roaming exceptions. [Unprotect](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
also documents integrity/error limits. The matrix requires actual unprotect errors
for refusal, not merely successfully opened bytes that differ from the public
payload; it does not depend on one specific Windows error code. These source/API
facts do not constitute a native pass on the intended VMs.

## Build and pin the package on the development host

```powershell
pwsh -NoProfile -File scripts/prepare-recovery-isolation.ps1
```

The preparer uses a locked explicit x64 MSVC lib-test `--no-run` build, selects
exactly one actual Cargo test artifact and compares source inventories before/
after compilation. It writes a new `target/recovery-isolation-<campaign>` package:

- `Input/`: the unsigned test executable, runner, definitions-only common/verifier,
  exact-child deadline helper and BUILD-MANIFEST.json with source/toolchain hashes.
- `ENROLLMENT-origin.example.json` and `ENROLLMENT-foreign.example.json`: manual
  enrollment examples with false affirmations.
- `RUNBOOK.md` and `PREPARATION.json`: instructions and an explicit preparation-
  only result with zero native phases run.

Record/check the printed build-manifest SHA256 through the trusted host copy.
Use only dedicated input/evidence transfer media or folders; do not share the
personal host's home/profile directories. Place the five verified input files
and build manifest at `C:\NomadVmRecoveryInput` in each VM. Add the appropriately
reviewed enrollment there as `DISPOSABLE-VM.json`, then keep the input read-only.
The manifest pins all executable/script inputs; enrollment is the separate
operator declaration. A local hash manifest is not a publisher signature or
compromised-guest attestation. Do not disable Windows security controls to run it;
record a blocked environment instead.

## Run and verify one phase at a time

In the named local account of the appropriate offline VM, use Windows PowerShell:

```powershell
powershell -NoProfile -File C:\NomadVmRecoveryInput\Run-VmRecovery.ps1 -Phase Origin -AcknowledgeDisposableVm
```

The runner creates only a fresh owned phase folder under that test account's
`AppData/Local/NomadVmRecoveryQualification/<campaign>/<phase>`. It never overwrites
a prior phase; retain failures. The ignored native test runs alone, with a
180-second deadline and captured numeric exit/stdout/stderr. Only that exact
retained child handle can be killed on timeout. Environment changes are process-
local and restored. The ordinary local/CI gate never selects this native function.

Copy only RECEIPT.json and its allowlisted selected files to an owned host evidence
folder whose final component is the exact phase name. Origin also exports its
`Transfer/` index and five public fixture files. On the host, verify against the
original package input, not an untrusted copy returned by the VM:

```powershell
. .\scripts\vm-recovery\Verify-VmRecovery.ps1
Test-VmRecoveryPhaseEvidence -InputDirectory '<package>\Input' -OutputDirectory '<evidence>\Origin'
```

Before the next phase, preserve an unmapped verified host copy. Retain the trusted
Origin `Transfer/BUNDLE-INDEX.json` SHA256; use the same bytes/hash for all later
phases. Copy just that index and its five allowlisted public files into
`C:\NomadVmRecoveryOrigin` in the target VM/account, keeping them read-only.
Never exchange DPAPI keys, live journal records, browser data or VM images.

Run PeerUser on VM A, then ForeignMachine on VM B, verifying each before proceeding:

```powershell
powershell -NoProfile -File C:\NomadVmRecoveryInput\Run-VmRecovery.ps1 -Phase PeerUser -AcknowledgeDisposableVm -OriginBundleSha256 '<verified uppercase SHA256>'
powershell -NoProfile -File C:\NomadVmRecoveryInput\Run-VmRecovery.ps1 -Phase ForeignMachine -AcknowledgeDisposableVm -OriginBundleSha256 '<same SHA256>'
```

Sign back into the original source account on VM A, retaining its original fixture.
Keep the same public bundle at the fixed origin-input path and run:

```powershell
powershell -NoProfile -File C:\NomadVmRecoveryInput\Run-VmRecovery.ps1 -Phase ReturnOrigin -AcknowledgeDisposableVm -OriginBundleSha256 '<same SHA256>'
```

Then verify the four preserved phase directories together on the host:

```powershell
Test-VmRecoveryMatrix -InputDirectory '<package>\Input' -OriginDirectory '<evidence>\Origin' -PeerUserDirectory '<evidence>\PeerUser' -ForeignMachineDirectory '<evidence>\ForeignMachine' -ReturnOriginDirectory '<evidence>\ReturnOrigin'
```

The verifier requires typed successful assertions, exact-one-test completion,
empty stderr, matching build/harness/campaign/bundle hashes, appropriate actual
context equality/difference and the expected open/refuse/retire/preserve matrix.
Missing or mixed phases, wrong context/bundle, partial/failing results and altered
bytes are refusals. Preserve observations when an expected refusal fails; do not
change assertions or enroll another identical clone to manufacture a pass.

## Data and limits

Native output includes only encrypted known public payloads, an inert journal
containing the public fixture paths, campaign-salted context fingerprints, OS
version, fixed fixture labels and selected logs/hashes. Raw SID, MachineGuid,
private keys, credentials, live profiles and real crash dumps are not exported.
Fingerprints remain linkable within one campaign; hashes are not identity/key
attestation. Input binaries/source inventories may reveal build/repository paths.
DPAPI can create/use Windows key state inside the authorized disposable accounts;
this is not a zero-OS-side-effect claim. No network endpoint or telemetry client
is added by the test path.

Copied journal paths differ in peer/foreign profiles. Replay preservation alone
could therefore follow from a scope mismatch; the separate direct unprotect-
refusal assertions are mandatory to establish the binding observation. No browser,
forensic completeness, roaming/domain, compromised administrator, cloned-key
protection, real crash/power loss or storage durability result follows.

After host verification, revert/discard only the explicitly owned disposable
VMs through the operator's VM controls. The runner does not recursively clean
personal data or delete a VM. Prepared tooling and inert metadata tests leave
[rating/release readiness](RELEASE-READINESS.md) unchanged. The CRLSet disposition
remains a separate owner decision.
