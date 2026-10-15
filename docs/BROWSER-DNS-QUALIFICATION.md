# Helium DNS runtime qualification

## Scope and status

**Scoped guest qualification completed:** A fresh Windows 11 Helium 0.19.2.1
fixture recorded normal Quad9 DoH replies, then failed DoH attempts with no
recognized plain attempt for the test hostname during a deliberate transport
block. Collect preceded Restore; the guest checked owned rules in persistent and
active stores before collection and reported their removal afterward. Host checks
verified selected copied records, input hashes and restoration assertions. Raw
NetLog, live firewall state and total packet-leak absence were not independently
replayed or verified. See the [completed fixture](#fresh-controlled-fixture-completed-2026-10-14).

The earlier prelaunch loopback-resolver fixture was **invalid**, because Nomad
re-enforces secure mode/Quad9 before creating the browser process. The earlier
Restore-before-Collect capture remains unqualified as a full fault fixture;
its historical record is retained below. Do not repeat that loopback fixture.

**Verified in code:** `core/payloads/chromium/local_state.json` supplies secure mode
and Quad9. `core/src/hardening.rs` includes both DoH fields in
`LOCKED_SCALAR_PATHS` and reapplies them on every hardened launch. Other merged
scalar choices can be preserved; these two required fields are exceptions.
The helper checks hashes and closed-browser state. Current source refuses the
retired FailClosed phase before state/profile/launch changes. Collection of
existing evidence and restoration remain available. Original mapped scripts,
inputs and receipts are preserved as historical fixtures, not modified in place.
Host/system DNS settings were not changed.

## Prepare and use

Run from the repository:

```powershell
pwsh -NoProfile -File scripts/prepare-helium-dns-sandbox.ps1
```

Preparation compiles a locked debug launcher, checks its artifact, freezes tracked/
nonignored source and four input hashes, and verifies source stability during build.
It creates `target/helium-dns-<token>/Nomad-Helium-DNS.wsb` with readonly Input and
dedicated writable Output mappings. It does not launch/download a browser or run
registration, DPAPI or cleanup on the host.

1. Open the new `.wsb` in a **fresh Sandbox**. The helper runs Fresh automatically;
   do not repeat it. Nomad downloads/verifies Helium inside the guest.
2. Leave Helium services setup untouched. Use only its generated public URL,
   `https://nomad-<token>-baseline.example.com/`. A DNS error page is acceptable:
   a valid NXDOMAIN can still demonstrate the observed DNS transport. Do not sign
   in or browse personal sites during capture.
3. After the probe settles, close **all** Helium windows normally. In guest PowerShell:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File C:\NomadInput\Run-Helium-Dns.ps1 -Phase CollectBaseline
   ```

   Send the output; keep Sandbox open for independent host evidence checking.
4. Do not run the former FailClosed phase. It is retired: editing Local State
   before a hardened Nomad launch cannot inject this fault. A new resolver-outage
   fixture must preserve the required secure/Quad9 settings and cause an observed
   transport outage instead. The later program-scoped transport fixture and post-restore recovery are
   recorded below, including the later completed fresh fixture.
   For the existing guest, use the preserved continuation's read-only `-Phase Status`
   to confirm secure mode/Quad9 after restoration; keep the guest open for review.

On missing/held/oversized capture, schema or ownership failure, preserve the guest
and stop dependent work. Do not change guards, stop guessed processes, force user
choices, copy a personal profile or upload raw NetLog to get a pass. Restore is
available after recorded failure-test intent; unexpected choices remain intact.
Closing Sandbox discards the guest profile and raw captures.

## Observation rules and limits

**Verified in code:** `Analyze-Dns-NetLog.ps1` uses capture event/phase dictionaries.
It links the exact probe transaction to a DoH source and matching HTTPS URL job,
then checks its DNS response and transaction result. A saved secure setting or
unrelated Quad9 connection is insufficient. Valid NXDOMAIN counts as a response;
a failed network transaction does not. Classic TCP/UDP, platform or system
resolver attempts for the probe are flagged. Wrong/redirected endpoints,
unrecognized schemas and incomplete events cannot establish a secure response.

Statuses: `secure_query_response_observed`,
`failed_doh_no_plain_attempt_in_capture`,
`classic_or_system_target_attempt_observed`, or `inconclusive`.
The latter two need investigation; no production fix is automatic. Absence of
recognized plain attempts is limited to this capture. Resolver-host bootstrap
may use OS DNS and differs from plain DNS for the probe. Other processes, missing
events and OS network channels are outside this measurement. OS packet capture
would require separate privacy/completeness qualification. A secure DNS response
does not establish fresh revocation data or browser phishing protection.

**Upstream source / inference:** Current Chromium DoH code associates its URL
request with the attempt's NetLog source. The parser uses that relationship rather
than temporal proximity. This review is not attestation of Helium's binary.
[Chromium DoH attempt source](https://raw.githubusercontent.com/chromium/chromium/main/net/dns/dns_http_attempt.cc).
NetLog events have no backward-compatibility requirement; unknown structures
must remain inconclusive. [Chromium NetLog design](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/docs/net-log.md).

## Data, endpoints and retention

**Verified in code:** Fresh contacts the GitHub API tag metadata endpoint for
`imputnet/helium-windows` 0.19.2.1 and requires its recorded asset URL/digest.
Nomad performs its normal verified GitHub release download, including HTTPS CDN
redirects. Helium contacts Quad9 for a public nonce hostname; an HTTPS connection
to that public `example.com` destination is possible if it resolves. Failure
attempts guest loopback port 9. DNS bootstrap and other browser background
traffic may occur. Untouched Helium setup does not certify silence/no telemetry.

Raw `Baseline.netlog.json`/`Failure.netlog.json` and profile stay under
`C:\NomadDnsQualification\<token>\Instance` in the guest. Default capture strips
sensitive fields best-effort, retains most HTTP headers and omits complete socket
bytes. It can reveal URLs, IP/network and certificate information; do not treat
it as anonymous or safe to publish.
[Chromium capture-mode contract](https://raw.githubusercontent.com/chromium/chromium/main/net/log/net_log_capture_mode.h).
The collector refuses over 32 MiB / 200,000 events. These are collection limits,
not a logging disk quota; use a short test and close the browser normally.

Only `OBSERVATION.json` and `GUEST-RECEIPT.json` enter mapped Output: public probe,
bounded selected source/event IDs, response/error counts, expected resolver
without query data, known HTTPS host names limited to Quad9/Helium services/
loopback, saved-choice assertion, source/launcher identity, OS version and
hash/length references. Parser output excludes raw headers, response buffers,
URL queries, IPs and profile data; selected events are capped at 256. Raw SHA/size
are guest references, not independently verified host raw evidence.

Host checking dot-sources `Recovery-Integration-Helpers.ps1` and
`Analyze-Dns-NetLog.ps1`, then calls `Test-DnsEvidenceExport` with frozen Input and
exact new Output subfolder. It checks input hashes, receipt provenance, selected
file hash and typed consistent results; it refuses total packet-absence claims.
This validates selected copies, not guest attestation or independent raw replay.
Recheck host inputs after guest use. Keep original receipts unchanged and record
later verification separately. Host output remains until explicitly removed.

## Pending broader checks

This covers one Helium build/profile/direct launch. Chromium runtime DNS, Gecko
effective settings/fallback, Mullvad defaults, changed preferences, protocol
launches, other Windows versions, component endpoint/installer history and
independent recovery user/machine isolation remain separate work. Ungoogled
CRLSet restoration is unresolved. The failed second-Sandbox machine-only
isolation comparison is unchanged. See [audit status](AUDIT-STATUS.md); rating
3/5 and the v1.0.9 hold remain.


## Existing-capture diagnostic

If CollectBaseline reports only a generic JSON/schema/correlation failure, preserve
the closed-browser capture and keep Sandbox open. A separately prepared read-only
`C:\NomadInput\DnsDiagnostics\Inspect-Dns-Capture.ps1` can inspect it without a new
browser launch or profile/DNS writes. It prints counts, JSON conversion outcome,
a fixed allowlist of parser refusals, or exception type/line. Arbitrary exception
text and raw fields are suppressed. It exports nothing and records no DNS pass.
The diagnostic is a later mapped addition; original package inputs/manifests remain
unchanged. Send only its console output before any controlled-failure mutation.


## Signed source-ID correction and existing baseline

Chromium's separately initialized source partition can serialize as negative int32
IDs. These are identities, not invalid events. The corrected parser preserves the
exact signed representation and matches dependencies by that same identity;
zero selected IDs, strings, fractional and out-of-range IDs remain refused.
[Chromium partition source](https://raw.githubusercontent.com/chromium/chromium/main/net/log/net_log.cc),
[serialization source](https://raw.githubusercontent.com/chromium/chromium/main/net/log/net_log_entry.cc).

The original collector's refusal did not record a DNS pass. For the existing
uncollected Baseline only, a separately prepared
`C:\NomadInput\DnsCorrection\Recollect-Dns-Baseline.ps1` checks original inputs and
its own correction manifest, reproduces the frozen-parser outcome, counts negative
IDs and reanalyzes the finalized bounded capture. It exports selected observations
with `analysis_correction_sha256` in result/receipt and updates only collection
bookkeeping. It does not relaunch, change DNS/profile, rewrite raw logs or alter
original input manifests. Host verification also checks the correction manifest
and both corrected-analysis input hashes. The original source hash identifies the
browser build/preparation; it must not be represented as the corrected analyzer's
source identity. Actual runtime evidence remains pending until execution and
host checking; keep the guest open and do not start FailClosed on this refusal alone.


## Baseline selected evidence and existing-session continuation

The 2026-10-14 baseline (`e68ca8a1ffab42afa571297eec5b6725`) recorded three
correlated Quad9 DoH replies and saved test DNS choices. Host checks verified the
selected-copy hashes/provenance and reply sequences, not raw event replay or all
traffic. The 74 negative source-ID events reproduced the frozen parser refusal;
corrected analysis succeeded on the existing capture. Original receipts and
analysis provenance are preserved in an unmapped snapshot; see [audit record](AUDIT-STATUS.md#helium-secure-dns-baseline-selected-evidence-verified-2026-10-14).

For this existing guest, a separately prepared Input/DnsContinuation folder
contains a guarded `Run-Helium-Dns.ps1`, corrected analyzer, original launcher
bytes and helpers with its own input manifest. The manifest's source hash/inventory
identifies the original launcher build; `input_files` identify the later workflow.
No fresh build/provisioning is claimed. Original Input and DnsCorrection files
remain unchanged. The continuation has no Fresh phase or metadata/download
provisioning command. Its defaults, resolver checks and restore safeguards match
the tested original workflow; it uses the existing guest instance and consent.

**Historical continuation outcome:** The attempted prelaunch loopback change was
re-enforced to Quad9 by Nomad, so failure collection is inconclusive (three probe
transactions, zero matching loopback attempts, saved test DNS mismatch). The
reported restore confirmed/restored Quad9. The page's ERR_NAME_NOT_RESOLVED alone
was not evidence of an outage or fallback behavior. Preserve the failed attempt;
do not reuse those historical FailClosed instructions. Current source refuses
that phase, while original mapped inputs remain unchanged for evidence integrity.
A replacement fault fixture must test an actual transport outage with Nomad's
required DNS settings intact. Read-only guest Status confirmation is pending.


## Program-scoped guest HTTPS outage (replacement fixture)

**User observation:** Read-only Status after the retired attempt reported zero
browser processes, secure mode and the Quad9 template. This confirms saved
restoration in the user's console, not live DNS traffic or host replay.

**Prepared only / verified in code:** `Run-Dns-Transport-Fault.ps1` uses the
existing restored instance and original unsigned launcher. It refuses execution
outside WDAGUtilityAccount / the exact mapped guest input, verifies input hashes,
and pins the reviewed browser image/module hashes from the prior component
qualification. No browser/package download, consent acceptance, DNS preference
write or production code change is required. Original evidence/inputs are retained.

Start checks closed browsers, saved secure Quad9, firewall services, three enabled
active profiles and no explicit policy disabling local rules. It does not enable
services/profiles or weaken global policy. It records a fresh nonce intent and
owned config backup before creating two exact-name rules. The rules block outbound
TCP and UDP remote port 443 only for the existing Helium executable. DNS port 53
is not blocked by the helper. Matching rule filters are checked in persistent and
active stores before launch/collection. Program/port filters are supported by
[Microsoft's firewall-rule API](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps).

This blocks all matching HTTPS/QUIC traffic for that guest browser, including
services and components during the test, not solely Quad9. Proxies using other
ports, rule-policy exceptions, other processes and OS traffic are not a claimed
outage or leak-absence measurement. A rule snapshot is not proof of every packet
being blocked. The capture must actually contain a correlated failed Quad9 DoH
transaction; successful replies, plain fallback, missing correlation or unavailable
firewall policy cannot be converted into an outage pass.

The helper temporarily changes only the owned Nomad test config to keep hardening
on, prevent launch-time updates/downloads, capture a new `Fault-<token>.netlog.json`
and query a fresh public hostname. Secure Quad9 remains enforced by Nomad. The
new token is separate from the earlier instance token. NetLog collection retains
the same 32 MiB / 200,000 event and 256 selected-event limits. Raw capture, the
intent and config backup remain guest-only. Selected export adds browser hashes
and typed firewall-rule/profile assertions; no IP lists or raw firewall/profile/
NetLog contents are transferred. It is guest-observed selected evidence, not an
independent host firewall/packet replay.

A separately hashed Input/DnsFault package supplies the existing launcher,
updated analyzer, guest helper and common bounded-file utilities. Its manifest's
source inventory identifies the original launcher build; input hashes identify
the new workflow. Original Input/DnsContinuation and DnsCorrection remain frozen.
Host `Test-DnsEvidenceExport` must use Input/DnsFault for this result. It additionally
refuses inconsistent/false/untyped fixture assertions and a changed expected
resolver. Actual browser/firewall qualification remains pending.

In the **same Sandbox**, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\NomadInput\DnsFault\Run-Helium-Dns.ps1 -Phase Start
```

Wait for the error page, close all Helium windows normally, then run the same path
with `-Phase Collect`, followed by `-Phase Restore` even if collection is inconclusive
or fails. Do not browse personal sites. Send outputs and keep the guest open.
`-Phase Status` is read-only after fault intent creation. Failed setup attempts
owned restoration; a failed restore prints instructions to close the browser and
run Restore explicitly. Existing fault intents are never overwritten by Start.

Restore validates every retained owned rule's name, description, direction/action,
profile, program, protocol, port and address scope before deleting any of them.
It permits a missing rule after partial setup, but refuses changed/foreign rules.
It removes only retained owned objects, checks both stores for absence, restores
only recognized original/fault config bytes from its hashed backup, confirms
secure Quad9 and exports a separate bounded RESTORE.json/receipt. It does not
restart the browser. Rule removal/config restoration needs separate host evidence
review; the next browser's ability to connect is not established by these checks.

**Tested offline:** PowerShell 5.1/7 authored rule/filter mocks cover changed
program, foreign description, inbound direction, wrong ports, all-rules validation
before any deletion, closed-browser refusal, user-changed config preservation,
exact owned removal and repeated restore. JSON fixtures cover the expected Quad9
failed transport and visible plain fallback; host metadata checks reject invalid
fixture flags. Ordinary regression tests invoke no real firewall commands. Guest
execution is still required, and the retired resolver-mutation attempt remains
inconclusive.


## Restore-before-Collect recovery

The guest ran Restore before Collect for fault token
`8e215f4c4aa4489b8ff15b554f7d560f`. Ordinary Collect refused because rules/config
had already been restored. The unchanged restoration receipt and selected fields
were checked on the host: zero owned rules, matching original/restored config hash,
saved secure Quad9. This is typed guest evidence plus copy/provenance validation,
not independent host firewall replay. An unmapped snapshot preserves the receipt,
RESTORE.json and original fault workflow inputs. No outage pass is established.

A separately hashed Input/DnsFaultRecovery workflow can read the existing finalized
raw capture without restarting/reblocking anything. It requires started/restored/
uncollected intent, closed browsers, current owned-rule absence in both stores,
restored config/hash and secure Quad9, reviewed browser/module identities and
unchanged original fault inputs. It exports only bounded selected observations
and a new receipt, leaving original state/profile/config/capture unchanged.

It explicitly labels `collection_after_restore = true`,
`rules_during_capture_rechecked = false`, `qualified_fault_fixture = false`.
Original startup checks are historical. Recovered DNS events can support a
capture-scoped transport observation, but cannot retroactively certify the full
active-rule-at-collection fixture. Host verification rejects changed/false/untyped
restoration fields or any recovered claim of full/active fault qualification.
Even an observed failed DoH/no-plain-attempt status remains limited to those
captured events. No total packet-leak absence is claimed.

In the same closed-browser Sandbox, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\NomadInput\DnsFaultRecovery\Run-Helium-Dns.ps1
```

Send output and keep the guest open. Do not repeat Start/Restore or reopen Helium
to manufacture evidence for the earlier interval. The recovery path invokes no
rule mutation, browser launch, DNS/profile/config write or state rewrite; raw logs
stay guest-only. It creates only a new selected-evidence Output subfolder. The
completed selected-evidence review is recorded below.


## Recovered capture result (2026-10-14)

**Tested in the guest / verified selected export on the host:** The recovery
helper reported `failed_doh_no_plain_attempt_in_capture` for four target
transactions and four correlated Quad9 attempts. The host ran
`Test-DnsEvidenceExport` against Input/DnsFaultRecovery and rechecked the original
fault inputs and restoration receipt with `Test-DnsRestoreExport`. Both passed.
All four selected sequences have an exact probe transaction, a Quad9 HTTPS attempt
and a later negative transaction end; the selected sequence sources are 26, 28,
80 and 82. This validates copied selected records and their internal ordering,
not an independent replay of the guest-only raw capture.

The recovery receipt SHA256 is
`C4AEDA6FF61ABDD979BE4B504730F2FCF48BBE49577619C5CB56A83BEBBA1713`.
An unmapped `VerifiedEvidence/failure-8e215f4c4aa4489b8ff15b554f7d560f-5042b01d5f7444a0b34960f63b09b6e3`
snapshot retains 13 unchanged evidence/provenance/verifier files plus a scoped
HOST-VERIFICATION.json. The launcher and guest raw capture are hash-only
references; neither raw NetLog nor the browser profile was transferred.

**Limits:** Collection happened after Restore. The verified selected fields retain
`collection_after_restore = true`, `rules_during_capture_rechecked = false` and
`qualified_fault_fixture = false`. The guest reports current owned-rule absence,
restored original config and saved secure Quad9. The host verified those typed
records and hashes; it did not independently inspect live guest firewall state.
No recognized plain target attempt was reported in this capture. This is not
proof of total packet-leak absence, continuously effective firewall blocking or
all-browser DNS behavior. The full fault qualification remains pending.

After host preservation, this guest may be closed. A full fault qualification
would require a fresh owned capture, normal browser closure, Collect while the
owned rules still exist, then Restore and separate evidence review. Do not rerun
Start against the preserved intent or silently re-enable the earlier rules.
Work remains local/uncommitted; the prior canonical gate result is historical,
and no new CI, publication or release qualification is claimed.


## Fresh controlled fixture completed (2026-10-14)

**Tested guest / verified selected exports:** A new package at
`target/helium-dns-6265146b95374fe3ad7f881cfd5950d0` froze 189 source files,
compiled a local unsigned x64 launcher and checked its artifact and input/mapping
hashes. Base commit: `920a8294afde63b4a9629433025a7f69a8eb6075`;
source SHA256: `04F93821D9466F2C4A033D2358DD0643545F8FA05A34B805CC2F1F6F87BE2A42`;
launcher SHA256: `D878000B40C578EAA48927A9C22CBD1F39B5862B1A1AB59265781B6EBCAC272B`.
The input manifest records uncommitted changes in the build scope. This is a
local test artifact, not a signed release or CI artifact.

Fresh session `5aaec5e79bce4cbdb7a3960f09833ffd` recorded three correlated
Quad9 replies with matching saved secure DNS settings. Host selected-record
verification passed; receipt SHA256:
`489814C6E54FABD8F8179BCC3D0687BE5B9A31293A759C417FC6204DFD5171EF`.
These replies establish observed encrypted DNS transport for the test hostname,
not successful webpage loading.

The user then ran Start, closed all Helium windows normally, ran Collect, and
only afterward ran Restore. Fault token: `eb40d791ba494fd78dc2d2b04fe3b70e`.
The collection record asserts owned-rule verification in both stores and enabled
firewall profiles, preserves secure Quad9 and matches the reviewed browser/module
hashes. Four selected exact-hostname Quad9 attempts ended negatively: sources
26, 28 and 59 returned -356; source 57 returned -3. Chromium's matching
[155.0.8059.39 error definitions](https://raw.githubusercontent.com/chromium/chromium/155.0.8059.39/net/base/net_error_list.h)
identify these as QUIC protocol errors and an aborted operation, respectively.
The aborted sequence is recorded separately; it is not counted as an additional
completed transport failure. No recognized classic/system attempt for the probe
was reported in this bounded capture.

Host `Test-DnsEvidenceExport` and `Test-DnsRestoreExport` passed. The host also
checked selected sequence ordering, source/dependency IDs, exact Quad9 endpoint,
three non-abort errors, baseline/fault/restore session linkage and original-input
hashes. Failure receipt SHA256:
`79E0238858E985BF6C40F27EF23A86795CA2D9C539B414C4DDB4B20E5648BF43`.
Restoration receipt SHA256:
`80DA05360A98560CCE882D9A38EA70C581EE4F50BD276375E999C0ADFD44421F`.
The restoration record reports zero owned rules, restored original config with
identical hashes and saved secure Quad9. Browser was not restarted afterward.

Separate unmapped VerifiedEvidence baseline/failure/restore snapshots each retain
eight unchanged selected/provenance/verifier files and a scoped host record.
Launcher/raw capture references are hash-only. Original inputs and older results
remain intact. The guest can now close after these host copies are preserved.

**Conclusion and limits:** This completes the exercised guest fixture and supports
fail-closed behavior for this hostname during the recorded interval. Active-rule
and restoration facts are typed guest assertions whose copied bytes/provenance
were verified; the host did not independently inspect live guest rules or replay
raw NetLog. There was no OS packet capture. This is not total DNS-leak absence,
coverage of delayed fallback beyond browser closure, resolver bootstrap traffic,
other browser versions/families, Windows 10, VPN/proxy paths or every network.
The earlier invalid/unqualified records retain their original verdicts.
No production behavior changed. Documentation whitespace checks passed; the prior
canonical workflow gate remains historical and was not rerun for evidence-only
recording. Work remains local/uncommitted; broader audit and release holds remain.
