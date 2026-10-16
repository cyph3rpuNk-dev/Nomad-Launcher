# Waterfox DNS defaults

## Confirmed defect and local correction

**Verified in code:** Waterfox previously included the shared
`firefox/nomad.cfg`, including `defaultPref("network.trr.mode", 5)`.
Its `user.js` omitted DNS choices while claiming to preserve upstream oblivious
DNS. Those comments did not describe the complete hardening stack.

**Tested by user in Windows 11 Sandbox:** a fresh x64 Waterfox 6.7.6 launched
with the unchanged local unsigned launcher showed these effective values in
`about:config`, before any settings edits:

| Preference | Observed value |
|---|---|
| `network.trr.mode` | `5` |
| `network.trr.use_ohttp` | `true` |
| `network.trr.ohttp.uri` | `https://dooh.cloudflare-dns.com/dns-query` |
| `network.trr.ohttp.relay_uri` | `https://dooh.waterfox.com/` |
| `network.trr.ohttp.config_uri` | `https://dooh.cloudflare-dns.com/.well-known/doohconfig` |

Screenshots `Screenshot 2026-10-15 011006.png`, `011829.png` and `012231.png`
record those values. The OHTTP preferences alone do not enable resolution while
mode 5 disables TRR. This is an effective-settings observation, not a packet
capture or evidence of successful/failed relay traffic.

**Verified in code, correction:** the shared autoconfig now
contains only the common non-DNS settings. Floorp appends the extracted
`firefox/dns.cfg` unchanged; Waterfox omits it. Waterfox's managed `user.js` and
policies also leave transport/provider choices alone. Existing direct/protocol
launch preparation and staged-update preparation write the selected adapter's
complete autoconfig through the required-settings path. They replace the old
managed default without editing saved user DNS preferences. Explicit choices,
including mode 5 and custom resolvers, are preserved. This does not assert that
an old disabled value saved by a user should be automatically reset.

## Upstream behavior and trade-offs

**Documented in pinned upstream source:** Waterfox 6.7.6 source commit
`1de140d004d3fd63a2b63564b2ed4ea26f0adc97`,
[`04-dns.js`](https://github.com/BrowserWorks/waterfox/blob/1de140d004d3fd63a2b63564b2ed4ea26f0adc97/waterfox/browser/app/profile/04-dns.js),
defaults mode 2 and OHTTP true with the relay/config/query URLs above.
[`TRRServiceBase.cpp`](https://github.com/BrowserWorks/waterfox/blob/1de140d004d3fd63a2b63564b2ed4ea26f0adc97/netwerk/dns/TRRServiceBase.cpp)
selects a nonzero explicit mode before rollout mode, and selects the OHTTP URI
when that feature is enabled.

**Documented in Mozilla:** [TRR modes and exceptions](https://firefox-source-docs.mozilla.org/networking/dns/dns-over-https-trr.html)
define mode 2 as TRR-first with native DNS fallback; mode 5 explicitly disables
TRR. Restoring Waterfox defaults therefore does not establish fail-closed DNS,
Quad9 filtering, every lookup encrypted, or successful oblivious transport.
The relay/Cloudflare service dependency and fallback are deliberate trade-offs.
Safe Browsing remains disabled by Nomad's other hardening; this change does not
supply a replacement phishing/malware protection service.

## Evidence provenance and limits

**Tested:** `Run-Waterfox-Dns.ps1 -Phase Status`, after normal browser closure,
exported selected saved fields and guest hash-only inventory. All seven selected
user preferences were absent from `prefs.js`, consistent with the screenshots
showing defaults; absence alone cannot prove their effective values.
The guest reported the old shared autoconfig SHA256
`9C0B571C032C0C3FE146E915C30A52534A7F7C513AD6409D9A5B7710A11D4FF3`,
matching the frozen source payload.

**Tested on host:** bounded selected JSON, schema/session/build linkage, sizes
and SHA256 hashes, four frozen inputs, and ten retained selected/provenance/
screenshot files were checked. Receipt SHA256:
`444153D9D09A78F9C1DDA3D2542FDB8B111457CF397FF2D158554A91A00940F0`.
Unmapped evidence snapshot is under the original package's
`VerifiedEvidence/settings-0ef32f7ccc2847fda93899440709074e-a1a762452488410a86be73a9d6b8bcfb`.
No full profile or raw network log was exported. Original guest browser/profile
hashes remain guest assertions, not independent host reads of those files.

Baseline commit: `a59035c9bd1dcfd8f2c29858017efa1578d8869e`.
Working source SHA256:
`1DA9A525EF171207991B568E22AD6268FC7DEF9D35565602297C49F3647C24BE`.
Launcher SHA256:
`E6ACF00294AD1CBDFBC1D605E874E4DB8B07893BC601710EF4C20897D56A3529`.
The build also contained the then-uncommitted CRLSet documentation work; the DNS
defect did not depend on those documentation edits. The browser installer was
SHA512-verified and unpacked, never executed. Host source research preserved
21 bounded metadata/source snapshots; it executed no upstream source.

**Tested locally:** `pwsh -NoProfile -File scripts/check.ps1` passed: 549 Rust
tests, 16 ignored, formatting, strict Clippy, offline safety fixtures and the
structured dependency audit with its existing documented RSA exception. Three
new tests cover payload separation, existing-profile/idempotent replacement and
non-file write refusal. An initial test incorrectly expected RFP in a locked
autoconfig setting; it was corrected to inspect Waterfox's actual user.js layer.
No product RFP behavior changed. These tests use inert files, not live browsers.
The separate `cargo +1.92 check --workspace --all-targets --locked --target
x86_64-pc-windows-msvc` compatibility check also passed before publication.
The broader audit/release hold remains; this validation is not release qualification.

## Corrected-build settings and relaunch check (2026-10-15)

**Tested by user in the same Windows 11 Sandbox:**
`Run-Waterfox-Dns-Correction.ps1 -Phase Apply` replaced only the local unsigned
launcher in the existing owned test instance, after backing up the launcher,
config and selected managed/profile files inside the guest. Browser bundle
updates were temporarily disabled for this test; no browser installer ran.
The user reported effective `network.trr.mode = 2` without editing the pref.
After creating `about:blank` as **Nomad DNS test**, closing Waterfox normally
and running `-Phase Relaunch`, the user confirmed mode 2, `use_ohttp = true`,
the bookmark and enabled uBlock Origin remained. This is text confirmation;
no corrected-build screenshot was supplied or independently inspected.

**Tested guest collection:** after another normal closure, `-Phase Status`
reported the original test config restored and the installed marker unchanged.
The selected export records one helper relaunch, the expected corrected cfg
hash, and all seven saved DNS user fields absent. These facts remain typed
guest assertions; the host verified exported bytes rather than reading the
original live guest files. Absence of saved user prefs is consistent with the
user's report of defaults, but cannot independently establish effective values.

**Tested host verification:** exact two-file export membership, bounded JSON,
schema/session/build linkage, observation size/hash, both corrected inputs,
four original inputs and preparation provenance all passed. Eight unchanged
selected/provenance/helper files are retained in the unmapped host snapshot
`VerifiedEvidence/correction-0ef32f7ccc2847fda93899440709074e-498613c6892848dfa9fcfdab83d04a84`.
Receipt SHA256: `85E0AC589BA86A6FD04BFC3881252546B70500569F711A3F073B6E0962062139`.
Corrected source SHA256:
`9E24C1AF101464C75BE1A1FB5FFEC37511CBA89542B6E3B5BA7942842F662F30`.
Corrected launcher SHA256:
`4452B84AF5A660E7567A51EB8D9704738969DA5659C2E086739BEF1D7E6480FC`.
The frozen build includes the uncommitted Waterfox correction and prior CRLSet
documentation. Original baseline inputs/evidence remain unchanged.

**Conclusion and limits:** the exercised settings conflict and restart/preservation
check passed for this x64 Waterfox 6.7.6 instance. At this settings-only
checkpoint, actual traffic and fallback were unverified. The scoped runtime
observations below supersede that status for their two specific runs. Other
browser versions, Windows 10, broader profiles and explicit custom choices in
a live browser remain unverified.
Offline tests cover preserved explicit choices; they do not replace live traffic
qualification. No raw network log or full profile was transferred. It is safe
to close this Sandbox after host preservation; the corrected launcher remains
only in the disposable test instance. The canonical gate above was not rerun
for this evidence-only documentation update. Subsequent commit/push delivery
does not extend that validation scope; the broader audit, CRLSet gap and release
hold remain.

## Runtime address responses and startup-outage fallback (2026-10-15)

**Tested in Windows 11 Sandbox / selected exports verified on the host:** The
corrected local unsigned x64 launcher was built from clean merged-main
`4951d05b0b4c3305324daee3696bfa577d5b9ba1`. Both runs used pinned Waterfox 6.7.6,
the same launcher and corrected managed autoconfig. The outage used a fresh
disposable guest/profile because the baseline guest was no longer running.
No production behavior was changed to obtain these observations.

| Case | Observed browser-log evidence | Disposition |
|---|---|---|
| Normal conditions, `example.org` | Four A/AAAA starts and two completed OHTTP/TRR address-response sequences (AAAA), status 0 and TRR resolver type 1; request mode 2. Zero recognized native probe events. | Encrypted address-response sequences observed for this probe/run. Zero recognized native events is not a packet-level absence-of-leaks result. |
| Outage present at startup, `example.net` | Nineteen readiness NS starts, sixteen failed confirmation records, ten native probe events and four successful native completion records (resolver type 0); three request-mode-2 records. Zero qualified OHTTP address-response sequences or recognized cached probe records. | Native/system resolution observed during the controlled HTTPS outage. Completion records are not a count of unique queries. |

**Verified in pinned source:**
[`DNS.h:162`](https://github.com/BrowserWorks/waterfox/blob/1de140d004d3fd63a2b63564b2ed4ea26f0adc97/netwerk/dns/DNS.h#L162)
defines `DNSResolverType::Native = 0` and TRR as 1. The masked public-format
records identify successful `CompleteLookup` status 0 and the resolver value.
**Inference:** The observed native path is consistent with mode 2's documented
fallback/failed-confirmation behavior. It does not identify whether Windows
itself encrypted the DNS exchange. Do not describe this setting as requiring
encrypted DNS for every lookup or as fail-closed.

**Tested fault and restoration:** Only the exact owned guest Waterfox executable
was blocked outbound on TCP/UDP port 443 by two temporary local firewall rules.
No DNS preference was overridden; native DNS and host networking were unchanged.
Rule identity, executable, direction, action, port/address scope, enabled firewall
profiles, and both PersistentStore/ActiveStore were checked. Rules remained
present at normal browser closure and collection. Collection restored the exact
original test launch configuration and removed both owned rules. A separate
nonce-bound guest inspection then reported zero Waterfox processes, zero owned
rules in either store, unchanged selected saved DNS fields, and the original
launcher/marker/autoconfig inventory. This verifies the copied guest assertions,
not continuous independent observation of every packet or live guest file.

The normal and outage launches used owned local test pages and per-process
`MOZ_LOG` captures. The agent ran the outage via Windows Sandbox CLI as the
disposable logged-in user and closed only the exact owned browser window with
`CloseMainWindow`; no forced browser termination was used. Commands exercised:

- Normal baseline: `Run-Waterfox-Address-Probe.ps1 -Phase Start`, normal closure,
  then the collection-only `AddressCollect` copy with `-Phase CollectAndRestore`.
- Outage: `OutageProbe/Run-Waterfox-Address-Probe.ps1 -Phase Start`, normal closure,
  then `-Phase CollectAndRestore`; `Inspect-Outage-Restoration.ps1` checked the
  final guest state independently of collection.
- Host: `Test-OutageProbe.ps1` passed in PowerShell 5.1 and 7.6.6 with inert
  config/parser fixtures and mocked firewall calls; frozen helpers passed 5.1.
  `Verify-Outage-Evidence.py` passed exact bounded export membership, digest and
  typed-field checks, native-event/public-format line correspondence, numeric
  result counts, restoration snapshots and all 192 frozen source-file hashes.

**Preserved provenance:** Fixture package
`target/waterfox-traffic-3437c1277ad946e1b5a152e51a9f2ff6` retains unmapped
`VerifiedEvidence` snapshots. Raw logs and profiles were not transferred.

| Identity | SHA256 |
|---|---|
| Frozen source aggregate | `6364A7805CF83832ACC0C84503D921D494A4C8B2ABFFFFC8ED2EF6B64BDC7DFC` |
| Launcher | `36AC534C987E77565780151B6432A48A2B28C3CFEB346A3CAB91850CDA43C215` |
| Reviewed `xul.dll` (guest-recorded inventory) | `9BA45B29907CDA4F2373E5AC07DABCC8D2FDEEF61E9143539095C760B68D3F5E` |
| Normal selected observation | `74CA04890715D6A20DD1B47DBBB957E6D8B822AB47FD5F7D7843BD4FB2743188` |
| Normal receipt | `D6E7BA7AC26856C69803B9CE26EB60DEFE93FB836BE0A0D8FE6121E64AECABAC` |
| Outage selected observation | `D33A0C747C280F98B2F4A625C07CCA43C7F8A32BD1F16E2EEABC889A3DAB78DC` |
| Outage receipt | `9DFAC2630D9B624E84874EBC67541EB3D2D031D53F4B426FDEF814FA586235EB` |

The normal export ends `f22f7d72f2114ad99e1a50875f17c7ab`; the outage export ends
`384860889b5249fdb884cc892702aaaf`. Each has its own `HOST-VERIFICATION.json`.
Host verification preserves byte-identical selected evidence outside the guest's
writable mapping. It does not replay guest-only raw logs or independently attest
the original guest DLL or profile. Public log-format matches mask string/pointer
arguments and retain only scoped identifiers and typed numeric fields.

**Earlier attempts remain unqualified:** The original `example.com` probe
collided with the browser's built-in `confirmationNS`; its four type-2 starts
were readiness checks, not A/AAAA evidence. The first corrected helper failed
before launch because PowerShell 5.1 treated a null `File.Replace` backup as an
empty path. Its replacement uses an explicit unique backup and passed real
inert atomic-replacement/hash-refusal tests. Pretty JSON later exceeded the
existing 1 MiB export budget; compact collection reprocessed the same closed
capture under that unchanged budget. None of these attempts was rewritten as a
pass or used to infer a browser defect.

**Limits:** This is a startup-outage test blocking all HTTPS for one owned
browser, not a resolver-only block or a warmed mid-session outage. The page also
cannot load over HTTPS, so its error is not DNS evidence. Capture rotation and
browser closure bound the interval; other lookups, OS traffic, bootstrap,
VPN/proxy paths, explicit custom choices, Windows 10 and other releases remain
outside this qualification. The earlier normal baseline used a different guest
and profile. No all-browser guarantee, rating increase or release clearance is
established. The broader audit and release hold remain.
