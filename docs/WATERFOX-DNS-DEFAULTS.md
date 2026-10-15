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
check passed for this x64 Waterfox 6.7.6 instance. Actual DNS/OHTTP traffic,
relay reachability, fallback conditions, other browser versions, Windows 10,
other profiles and explicit custom choices in a live browser remain unverified.
Offline tests cover preserved explicit choices; they do not replace live traffic
qualification. No raw network log or full profile was transferred. It is safe
to close this Sandbox after host preservation; the corrected launcher remains
only in the disposable test instance. The canonical gate above was not rerun
for this evidence-only documentation update. Subsequent commit/push delivery
does not extend that validation scope; the broader audit, CRLSet gap and release
hold remain.
