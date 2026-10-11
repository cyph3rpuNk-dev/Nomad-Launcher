# Windows Sandbox validation results: 2026-10-11

Detailed evidence for [the audit status](AUDIT-STATUS.md). Guest commands were
executed by the user; results distinguish screenshots, user reports and prepared
but unrun work. Host-side builds and inert checks are explicitly identified.

This dated record covers the experimental builds. Subsequent production source
changes, completed gates and staged supported-build artifacts are recorded in
[AUDIT-STATUS.md](AUDIT-STATUS.md). Supported-build Firefox and Chromium startup/verification
have since been observed; broader supported-build checks remain pending.

## Windows Sandbox validation (2026-10-11)

Windows Sandbox was enabled with user approval and the required host restart
completed. Only the test input folder is mapped, read-only; host clipboard,
audio/video input and printer sharing are disabled. GPU sharing was initially disabled. Test files were copied
into guest-local `C:\NomadSmoke`. Network access is enabled for browser downloads.

The initial development-profile test executable returned `-1073741515`
(`0xC0000135`, DLL-not-found) before printing a test summary. Dependency inspection
confirmed that it and both locally built release launchers imported
`VCRUNTIME140.dll`. The exact missing guest DLL was not independently queried;
the user entered the DLL path as a command rather than running `Test-Path`.

An isolated rebuild of source `6f51fe5` added `-C target-feature=+crt-static`
while retaining CFG and `/DEPENDENTLOADFLAG:0x800`. All three rebuilt executables
have no VCRUNTIME/MSVCP/MSVCR imports. The release-profile test binary passed
475 normal unit tests on the host with the four HKCU tests still ignored there.
This is a build override for the test bundle, not a committed production fix.

The user then ran all four exact native HKCU tests serially inside Sandbox.
Screenshots `Screenshot 2026-10-11 093321.png` and
`Screenshot 2026-10-11 093711.png` show each test passing with exit code 0:

- `registry::tests::repair_command_key_rewrites_only_commands_inside_install_dir`
- `registry::tests::repair_rewrites_progids_that_are_not_the_userchoice_selection`
- `registry::tests::register_writes_sidecar_and_unregister_removes_it`
- `selfreg_watch::tests::live_repair_reroutes_a_self_registration_written_mid_session`

Test executable SHA-256:
`E1927CBAF45495F243970C7769B5489FB7CC78255E1ACD5A8DF44E2A44F0508B`.
These are observed user-executed guest results; they do not establish real
browser startup, Windows Default-apps picker behavior, or URL/file handoff.
No browser had been launched at this checkpoint. Results await commit approval.

The subsequent Firefox launcher attempt reached its error dialog but could not
create the status window: `egui_glow requires opengl 2.0+`, shown in user screenshot
`Screenshot 2026-10-11 094419.png`. Browser startup remains unverified. The original
Sandbox configuration disabled vGPU; insufficient guest graphics support blocks
this UI check. A separate GPU-enabled Sandbox configuration and startup script
were prepared to copy the same hash-verified static-runtime artifacts. Script
syntax, configuration XML and artifact hashes were checked. With explicit user
approval, the original guest was closed and the GPU-enabled configuration was
launched on 2026-10-11. User screenshot `Screenshot 2026-10-11 100035.png` shows
the same OpenGL error in the replacement guest: enabling vGPU did not resolve
status-window creation. The original guest's files were discarded on restart.

An isolated source snapshot of `6f51fe5` was used to build the existing static
`ui_preview` example with eframe's wgpu renderer and only its DX12 backend.
The trial changed no tracked runtime source or production lockfile. The preview
has no browser pipeline: it cannot provision or start a browser. Its release
build and formatting check passed; imported-DLL inspection found no external
VCRUNTIME/MSVCP/MSVCR dependency. Dynamic graphics loading and actual window
creation were not tested on the host. CFG and `/DEPENDENTLOADFLAG:0x800` were
retained alongside the static-CRT build override. A hash-validating guest script
was prepared and parsed without execution on the host; it preserves the existing
Firefox folder. User screenshot `Screenshot 2026-10-11 102103.png` confirms the
preview rendered inside the GPU-enabled Sandbox. Its version and update-status
text are static example content, not evidence of browser installation or update.
The preview's exit code and selected hardware/software adapter were not observed.

Preview SHA-256:
`704C6199D973A05CB7C3211E3E547A82814FBBA7622CD3E9D84383A6B0F261EF`.

A real Firefox launcher was then built from the same isolated renderer trial
using the updated trial lockfile and static-CRT override. The build passed;
imported-DLL inspection found no external VCRUNTIME/MSVCP/MSVCR dependency and
PE inspection confirmed CFG and dependent-load flag `0x800`. A hash-validating
Sandbox script was prepared and parsed to copy it into a fresh guest-local
`C:\NomadSmoke\Direct3D\Firefox` folder and invoke it directly. The user subsequently
reported that the launcher downloaded Firefox, and screenshot
`Screenshot 2026-10-11 103003.png` shows Firefox running inside Sandbox. This
establishes an observed browser-startup result for the renderer experiment.
User screenshot `Screenshot 2026-10-11 103948.png` of `about:addons` shows
uBlock Origin in the Enabled section with its switch on and no visible load
error on that page. Its blocking behavior has not been checked. Version metadata and preservation
across relaunch and a hardening off/on cycle are recorded below. User screenshot `Screenshot 2026-10-11 103710.png`
of `about:support` subsequently confirms Firefox `157.0.1`, build ID
`20261005135250`, application binary
`C:\NomadSmoke\Direct3D\Firefox\Browser\firefox.exe`, and profile folder
`C:\NomadSmoke\Direct3D\Firefox\Data`. The running browser uses the expected
portable instance; profile persistence after relaunch is reported below.
The page also lists an update folder beneath guest `C:\ProgramData\Mozilla-...`;
this is browser-reported location evidence, not an inspection of its contents
or evidence that Nomad stores the profile there. Enterprise Policies is shown
as Active, but individual policy behavior has not been checked.
Launch exit codes for the replacement guest are recorded below; verification
logs remain to be collected. Successful
startup alone does not independently establish every verification/overlay step.
No launcher or browser ran on the host. No production runtime source or lockfile
was changed for this experiment. Offline fallback, updates, rollback/retry,
hardening toggles and Windows handoff remain separate checks.

A guest-only relaunch helper was prepared and syntax-checked without execution.
It verifies the existing trial launcher hash and browser/profile presence,
refuses to proceed while any Firefox process remains, reports available uBlock
metadata, and directly invokes the same launcher without changing configuration
or killing processes. A disposable bookmark and post-relaunch extension check
remain user-executed validation steps; preparing the helper does not pass them.

User screenshot `Screenshot 2026-10-11 104923.png` shows the relaunch helper
refusing to run while 12 Firefox processes remained; their displayed executable
paths all point into the disposable `Direct3D\Firefox\Browser` folder. No full
exit/relaunch or bookmark-persistence result was obtained. The user subsequently
reported accidentally closing Sandbox and requested reopening. Host inspection
found no Sandbox client or guest-memory process, and the prepared GPU-enabled
configuration was launched again. Guest preparation and retained/new state have
not been inspected through this connection. Earlier screenshot results remain
recorded; profile persistence is still pending and must be checked within one
continuous guest session.

After reopening Sandbox, the user reported reinstalling/starting Firefox and
repeating the disposable-bookmark/full-exit/relaunch procedure in the new session.
The user confirmed that the `Nomad smoke test` bookmark remained and uBlock Origin
was still enabled in `about:addons`. Record these as user-reported persistence
passes, not direct agent observation of the guest or a collected exit-code/log
record. The guard in the prepared relaunch helper refuses running Firefox
processes; the successful check's console output was not supplied.

A guest-only hardening-toggle helper was prepared for the same hash-verified
trial launcher. It requires Firefox to be stopped, rejects linked fixture paths,
retains the original configuration before the off phase, changes only the
`enabled` boolean inside the single `[hardening]` section, verifies the written
text, then starts the existing disposable instance. The on phase requires the
retained backup. Script syntax and pure text fixtures passed for section scoping,
restoration and missing/duplicate settings or sections. These fixtures do not
change a real browser configuration or launch software on the host. The user then
reported completing the off phase and confirmed that the disposable bookmark
remained and uBlock Origin was still enabled. This is a user-reported preservation
pass with hardening disabled; the console output and effective preference/policy
state were not collected. The user subsequently reported completing the on phase
and again confirmed that the bookmark remained and uBlock Origin was still
enabled. Preservation across the off/on cycle is a user-reported pass; the
user screenshot `Screenshot 2026-10-11 113004.png` subsequently shows the off
helper reporting `hardening.enabled = false`, the on helper reporting `true`,
and each launcher exit code as 0. The helper verifies the written text before
launch; effective individual preference/policy behavior was not inspected. Disabling this setting does not prove every previously applied Firefox
preference has reverted to upstream defaults.

A guest-only offline-launch helper was prepared and syntax-checked without
execution. It validates the trial hash and existing browser/profile, requires
Firefox to be stopped and the guest PowerShell to be elevated, and refuses
ambiguous adapter selection. It records the one connected guest adapter before
disabling it, confirms disconnection, then directly launches the existing trial.
A three-minute wait bounds the helper's observation; it re-enables the selected
adapter in `finally` and checks it is no longer disabled, preserving the recovery
record. It changes neither launcher configuration nor metadata caches. The
adapter commands follow Microsoft's [Disable-NetAdapter](https://learn.microsoft.com/en-us/powershell/module/netadapter/disable-netadapter)
and [Enable-NetAdapter](https://learn.microsoft.com/en-us/powershell/module/netadapter/enable-netadapter)
interfaces. No adapter was queried or changed on the host. User screenshot
`Screenshot 2026-10-11 113004.png` shows guest `Ethernet` disabled, the existing
launcher invoked while disconnected, launcher exit code 0, and the adapter
re-enabled. Firefox is visible with uBlock Origin in its Enabled section. This
confirms an observed offline-launch pass for the experimental instance and
successful adapter re-enable; Internet reachability after re-enable was not
independently checked. The bookmark after this specific offline launch remains
unconfirmed. A fresh metadata cache may avoid a network request; this test alone
does not establish timeout or every rollback/retry path.

A guest-only registration helper was prepared and parsed without execution. It
checks the trial launcher hash and installed browser/profile, invokes the explicit
`--register-default` path, checks exit code and the version-2 Firefox ownership
sidecar, then opens Windows Default apps. Selection of the folder-labelled Nomad
candidate remains manual; the helper does not set UserChoice. User screenshot
`Screenshot 2026-10-11 113730.png` shows registration exit code 0, followed by an
ownership-check error in the temporary helper, before it could open Settings.
The helper compared the sidecar owner with an ordinary path literally. Source
`core/src/registry/registration.rs::canonical_launcher` canonicalizes the parent
and lowercases the path; on Windows this can include a verbatim `\\?\` prefix.
The original helper therefore incorrectly rejects that equivalent owner path.
At that checkpoint the raw guest sidecar had not been supplied, so its exact
contents still needed checking; the screenshot does not establish a production ownership defect.

A separate guest-only check was prepared to inspect the existing record without
repeating registration. It accepts the expected absolute path in ordinary or
verbatim drive-path form, preserving exact location comparison, validates the
location-derived key/value plan, and reads the actual HKCU open command and
HTTP/HTTPS capabilities before opening Default apps. The original registration
helper was backed up and corrected to use this check after registration. Both
scripts parse; three valid and five wrong/malformed path fixtures passed without
registry access. User screenshot `Screenshot 2026-10-11 114354.png` shows the
corrected check executing successfully: recorded version 2, browser `firefox`,
owner `\\?\c:\nomadsmoke\direct3d\firefox\nomad-firefox.exe`, and matching owner
path, location-scoped plan and actual HKCU command/capabilities. This confirms
the original helper's error came from the equivalent verbatim-path form. The
check made no registration or UserChoice writes. Windows Default apps visibly
lists `Firefox (Nomad Launcher: C:\NomadSmoke\Direct3D\Firefox)`. Candidate
registration and picker visibility therefore pass for this experimental copy.
The user clicked Set default; screenshot `Screenshot 2026-10-11 114838.png`
shows the same Nomad entry selected for `.htm`, `.html`, FTP, HTTP and HTTPS.
`.shtml` and `.xhtml` remain unassigned in the displayed page and are not part
of the current handoff check. Windows default selection passes for the tested
HTTP/HTTPS/HTML scope; subsequent URL/file routing results are recorded below. No registry or
Windows settings operation was run on the host.

A guest-only handoff helper was prepared and parsed without execution. It reuses
the registration inspection without opening Settings, confirms that Windows
HTTP/HTTPS and `.html` UserChoice ProgIDs match the inspected Nomad instance,
and checks the expected running/closed browser state. It creates an inert local
HTML fixture exclusively (or checks an identical existing fixture), then opens
an example.com HTTPS URL and that file through Windows shell associations.
It records original/retained window PIDs and before/after installed-marker and
browser-executable hashes. These observations supplement, but do not replace,
checking the resulting tabs, portable profile/bookmark and absence of a visible
provisioning/update flow. The user ran open-browser mode and confirmed both pages
reached the existing Firefox window. Screenshot `Screenshot 2026-10-11 115527.png`
shows the Example Domain and local-test tabs in that window, the fixture's
expected local file path, successful owner/default checks, and original window
PID `8216` retained. The helper reports the installed-version marker and Firefox
executable unchanged (`True` for both hash comparisons). Open-window HTTPS and
local HTML routing therefore pass for this experimental instance. Bookmark
presence and absence of a transient update/provisioning window during this
specific handoff were not explicitly confirmed at that checkpoint.

User screenshot `Screenshot 2026-10-11 120508.png` shows the first closed-mode
attempt correctly refusing while Firefox processes remained, then a successful
retry with no Firefox window PIDs before dispatch. Both requested pages are
visible after launch, and installed-marker/executable hash comparisons again
report `True`. The user confirmed that both pages opened, the bookmark remained,
uBlock Origin was enabled, and no download/update window appeared. Closed-browser
HTTPS/local HTML handoff therefore passes for the existing experimental install,
with profile preservation confirmed by the user. These checks do not establish
all package-verification or rollback behavior. No browser, handoff or real
registry access ran on the host.

A guest-only empty-instance protocol test was prepared and parsed without
execution. It copies the hash-verified trial launcher into an exclusively created
`C:\NomadSmoke\Direct3D\EmptyFirefox` folder and invokes it with `--` followed by
a harmless HTTPS URL. It requires exit code 1 and the exact unclaimed-folder
refusal in the retained log, then checks that no browser/profile, ownership
marker, launcher configuration or extension cache was created. The expected
error dialog must be acknowledged by the user. Logging may create `Nomad/` and
`nomad.log`; that is not browser provisioning. The helper does not register the
empty copy or change the installed instance/defaults. User screenshot
`Screenshot 2026-10-11 121632.png` shows the expected unclaimed-folder refusal
dialog, and `Screenshot 2026-10-11 121920.png` shows exit code 1 and the helper's
PASS after finding the expected log message and no provisioned browser/profile,
marker, config or extension cache. Unclaimed-instance protocol refusal therefore
passes for this trial. The log is retained under `EmptyFirefox\Nomad\nomad.log`.
The script was not run on the host. This does not separately test an already
claimed instance whose browser is missing.

A guest-only second-copy registration/removal helper was prepared and parsed.
Registration mode exclusively creates `C:\NomadSmoke\Direct3D\SecondFirefox`,
copies the hash-verified launcher, snapshots the primary sidecar hash, open
command, application name, registered capabilities and HTTP/HTTPS/HTML selected
ProgIDs, then explicitly registers the second launcher. It requires disjoint
registration keys/value names, correct second-owner/command/capabilities, and an
unchanged primary snapshot before opening Default apps for a two-entry visual
check. No second browser/profile is provisioned by this registration-only test.
Removal mode backs up the second sidecar and invokes its explicit unregister
path, then checks its keys/value/sidecar are absent and the inspected primary
registration/defaults remain unchanged. It retains fixture folders and logs.
The user executed registration mode. Screenshot
`Screenshot 2026-10-11 122507.png` shows the second-folder registration dialog;
`Screenshot 2026-10-11 122526.png` shows registration exit code 0, the helper's
PASS for disjoint registrations and unchanged inspected primary/default values,
and both `Firefox` and `SecondFirefox` folder-labelled Nomad entries in Windows
Default apps. Screenshot `Screenshot 2026-10-11 122601.png` shows the second
candidate's page while `.htm`, `.html`, HTTP and HTTPS still select the primary
`Direct3D\Firefox` entry. Second-copy candidate registration, separate picker
visibility and preservation of the inspected primary registration/HTTP/HTTPS/HTML
defaults therefore pass. No second browser was installed or launched. The user
subsequently reported completing removal mode, but its console result/exit code
was not supplied, so removal preservation is not yet marked passed. A guest-only
read-only results helper was prepared and parsed to check that the second
sidecar, planned registry keys and registered-app value are absent and the
primary snapshot still matches. It also prints the retained installed-version
marker and selected verification/protocol-launch log lines for evidence review.
User screenshot `Screenshot 2026-10-11 123311.png` subsequently confirms second
unregistration exit code 0 and both the removal helper and read-only results
helper passing: second sidecar, planned keys and registered-app value absent;
primary ownership record, inspected registration values and HTTP/HTTPS/HTML
selected defaults matching the saved snapshot. Second-copy removal preservation
therefore passes. The retained primary marker reports target `x64`, browser and
engine version `157.0.1`, also corroborating the replacement guest's version.
At that checkpoint both fixture folders and logs were retained and the primary
registration had not yet been removed; its later removal result is recorded below. No registry or launcher operation ran on the host.

The displayed primary log contains the generic updater warning
`no GPG signature published; relying on hash only` for Firefox, and no matching
successful verification/launch lines at its default warning log level. Static
inspection confirms this warning concerns the per-package stage:
`core/src/updater.rs::verify_package` uses a SHA-256 digest after Firefox's
`fetch_latest_version` authenticates `SHA256SUMS` and its detached signature in
`core/src/browsers/firefox.rs`. The production constructor has `skip_gpg = false`
and the embedded key file is nonempty. Successful signature/hash checks use debug
logging, while `core/src/lib.rs::init_tracing` defaults to warn. This warning is
not evidence of a missing-signature fallback in Firefox's manifest verification.
The screenshot does not independently capture the earlier debug authentication
steps; no new signing-material or verification bypass was introduced.

A guest-only primary unregister helper was prepared and parsed without execution.
It requires all Firefox processes to exit, checks the existing registration,
backs up its ownership sidecar, and snapshots the Firefox executable, installed
marker and `Data/places.sqlite` hashes before invoking `--unregister-default`.
It checks exit code and removal of the planned keys/value/sidecar, then verifies
those retained-file hashes and writes a result record. It does not delete fixture
folders or browser/profile files. The selected candidate will be removed; any
further guest default selection remains a separate Windows action. User screenshot
`Screenshot 2026-10-11 124153.png` confirms primary unregistration exit code 0,
planned registration keys/value and ownership sidecar absent, and unchanged
Firefox executable, installed-version marker and `places.sqlite` hashes. Primary
unregistration/preservation therefore passes. Browser/profile folders, sidecar
backups, result records and logs remain in the guest; no fixture folder was
removed. The helper was not run on the host. This completes the exercised Firefox
startup/profile/registration/handoff baseline for the experimental build; it does
not complete all-browser, update/rollback, Windows 10 or production-build validation.

Screenshot `Screenshot 2026-10-11 113730.png` supplies earlier console evidence from this replacement
guest: initial Firefox launch exited 0, the relaunch helper confirmed no Firefox
processes remained before starting the browser and exited 0, and cached extension
metadata reported uBlock Origin `1.75.0`, `active=True`, `userDisabled=False`.
This supplements the user's bookmark/extension persistence reports; metadata
version is not an independent blocking-behavior test. The screenshot also shows
both hardening-toggle launches and the offline launch exiting 0.

Firefox renderer-trial SHA-256:
`82031D654C5EA76CE2BAE8D4EB00B55E72FAE556A5422652B39A1C3AD8ADAA9A`.


## Supported-build Firefox: subsequent checkpoint

The production configuration was built through the ordinary unsigned distribution
path with no experimental Rust flag override. Firefox artifact SHA-256:
`79E64AD13B338F80719A0D38B8B68356AE845B0371698B994A3D65B455AE0C6B`.
The guest helper verifies that source/copy hash and enables `NOMAD_LOG=debug` only
for its launcher child. User screenshot `Screenshot 2026-10-11 141934.png` shows:

- `production.ps1 Firefox`, fresh instance `C:\NomadSmoke\Production\Firefox`,
  and production launcher exit code 0.
- DX12 request/selection result: AMD Radeon 780M, IntegratedGpu. Available-adapter
  enumeration includes Microsoft Basic Render Driver (Cpu) and NVIDIA adapters;
  software/other-adapter rendering was not selected or validated in this run.
- Firefox `SHA256SUMS GPG signature verified`, followed by package `SHA-256 hash
  verified` and `browser launched`, PID `4932`, executable
  `C:\NomadSmoke\Production\Firefox\Browser\firefox.exe`.

The debug evidence closes the earlier warning-only log limitation for this new
Firefox provision. Browser process spawn is observed in the log; a visible
Firefox window and its actual profile path are not supplied by this console
screenshot. Persistence/registration/handoff checks above remain experimental-build
results until repeated with these artifacts. At this Firefox checkpoint Chromium was unrun; its subsequent result appears
below. Windows 10 and selected software-adapter behavior remain unrun. No host browser or registry operation ran
for this guest checkpoint. Changes/results remain local and uncommitted.

## Supported-build Chromium: subsequent checkpoint

User screenshot `Screenshot 2026-10-11 143056.png` shows `production.ps1 Chromium`
using a fresh `C:\NomadSmoke\Production\Chromium` instance and launcher exit code 0.
The browser visibly displays its Ungoogled Chromium first-run page. Debug output
confirms the AMD Radeon 780M DX12 adapter selected, package SHA-256 verified for
`ungoogled-chromium`, and browser launch from that instance's `Browser\chrome.exe`.
The copy/hash-validating helper uses the supported artifact SHA-256
`4935165932B7721EFDDF84BD1937106F2D8B9547F1A2DD712C0A3CA176353D9C`.
This closes Chromium startup for these bytes in the guest, not its version/profile
inspection, extension acceptance, persistence, language behavior, Windows handoff
or authentic update/failure tests. No supported Firefox profile confirmation was
supplied with this screenshot. Hardware was selected; available CPU/software
adapter enumeration is not a software-rendering pass. No host browser or registry
operation ran for this guest checkpoint. Changes/results remain uncommitted.

User screenshot `Screenshot 2026-10-11 144613.png` of Chromium `chrome://version`
then confirms version `155.0.8059.39`, 64-bit Ungoogled Chromium, Windows 11 24H2
build `26100.9445`, executable
`C:\NomadSmoke\Production\Chromium\Browser\chrome.exe`, and profile
`C:\NomadSmoke\Production\Chromium\Data\Default`. The command line targets the
same `Data` user-data directory and includes `--lang=en-US` and
`--load-extension` pointing beneath `Browser\nomad-extensions\uBlock0`. Portable
profile and command-line targeting pass for these observed bytes. The page does
not establish that all supplied privacy switches take effect, that the extension
is accepted/enabled, or that cookies are portable between machines. Extension UI,
profile persistence and alternate-language/production integration checks remain
pending. No new source or browser operation ran on the host for this observation.

User screenshot `Screenshot 2026-10-11 145202.png` of supported Chromium
`chrome://extensions` shows uBlock Origin `1.75.0` with its enable switch on,
Developer mode on, and no visible Errors button or warning on the card. Initial
extension acceptance/enabled state passes. This does not prove filtering behavior
or persistence across later hardening/update changes. A new supported-build
relaunch helper is prepared and syntax-checked: it validates the manifest/hash,
requires the selected browser's processes to be stopped, preserves the existing
instance, and reports exit code and before/after installed-marker equality.
The user's disposable bookmark and post-relaunch extension observations are still
pending; the helper was not executed on the host or yet observed in the guest.

User screenshot `Screenshot 2026-10-11 150310.png` confirms that
`production-relaunch.ps1 Chromium` required and observed no Chrome processes
remaining, then relaunched the same supported instance with exit code 0 and
unchanged installed marker. The user also explicitly confirmed the disposable
bookmark remained and uBlock Origin stayed enabled. Full-exit relaunch and
bookmark/extension preservation pass for the supported Chromium build. A supported
hardening off/on helper was prepared, parsed and checked with a pure text
preservation fixture; it changes only the existing instance's hardening boolean,
retains the original config and enables debug logging only in the launcher child.
Neither guest phase has run at this checkpoint. No browser, configuration or
registry operation occurred on the host during these preparations.

User screenshot `Screenshot 2026-10-11 151815.png` then shows
`production-hardening.ps1 off Chromium`, `hardening.enabled = false`, the original
configuration backup retained under the supported instance's `Nomad/` directory,
and phase launcher exit code 0. Chromium is open on a New Tab page. The
`Nomad production smoke test` bookmark and uBlock enabled state are not shown,
and were not explicitly confirmed with this screenshot. Off-phase launch passes;
off-phase preservation and on-phase restoration remain pending. A New Tab shortcut
to Example Domain does not independently establish the named bookmark's presence.

User screenshot `Screenshot 2026-10-11 152905.png` confirms supported Chromium
hardening on mode reporting true and exit code 0; off mode false/exit 0 is also
visible. The user explicitly confirmed the bookmark and uBlock Origin remained
intact in response to the requested off/on observations. The off/on preservation
cycle passes for the supported Chromium build, with preservation based on the
user's report and settings/exit codes based on the screenshot. Actual individual
privacy-switch effectiveness was not tested. A supported-artifact offline helper
was prepared and parsed; it retains the earlier guest-only single-adapter guards,
three-minute observation limit and `finally` re-enable check, adding supported
manifest/hash validation and child-only debug logging. Guest execution and offline
profile/extension observations remain pending; no host adapter/browser operation
was performed during preparation.

User screenshot `Screenshot 2026-10-11 153442.png` confirms supported Chromium
launch with guest Ethernet disabled, exit code 0, and Ethernet re-enabled. The
user explicitly confirms bookmark and uBlock Origin preservation. Debug log lines
show `gorhill uBO update check skipped (offline)` after a request error and then
browser launch from the supported instance. Offline startup/preservation passes;
extension-update failure was tolerated. Browser-update interruption/rollback and
Internet reachability after re-enable were not tested by this result.

A guest-only Chromium language helper was then prepared and parsed. It preserves
an original config backup and requires the current config to match its last
recorded hash before later phases/restoration, preventing unrelated edits from
being overwritten. It requires a stopped browser and matching supported-artifact
hash. Only launch language/extra_args are changed for French, a German explicit
argument overriding French, and omitted language with no argument; restoration
returns the original configuration. Three pure text scoping/preservation and two
ambiguous/missing-input rejection fixtures passed on the host without touching
real configuration or launching a browser. Guest language phases remain unrun.

User screenshot `Screenshot 2026-10-11 154600.png` confirms `language.ps1 fr`,
phase exit code 0, actual `--lang=fr` in `chrome://version`, and French labels
including the About Version tab. The user explicitly confirms the UI appeared
in French. The same supported executable and `Data\Default` profile paths remain
visible. Config-driven French locale selection passes for Chromium 155.0.8059.39;
this is not proof that every locale exists in every upstream package. Bookmark
and extension state during this phase was not separately confirmed. German
explicit-argument override, omitted-key behavior and restoration remain pending.

The user subsequently confirmed that the explicit German override phase displayed
German UI and that the bookmark and uBlock Origin remained intact. Record this as
a user-reported override/preservation pass. No screenshot, actual command-line
capture or launcher exit code was supplied for this phase. Omitted-key behavior
and restoration of the original configuration remain pending.

Screenshot `Screenshot 2026-10-11 162820.png` subsequently shows both override and
default language phases with launcher exit code 0. Chromium is visible with
English New Tab and All Bookmarks labels after the default phase. This confirms
successful launch and visible English UI for the omitted-language configuration.
The screenshot does not show `chrome://version`, so absence of a generated
`--lang` argument is not yet observed. Bookmark and uBlock Origin preservation
for this phase and restoration of the original configuration remain pending.

Screenshot `Screenshot 2026-10-11 163353.png` closes the default-phase evidence
gap: `chrome://version` shows no `--lang` argument, English labels, Chromium
155.0.8059.39 and the same Production\Chromium executable and Data\Default
profile paths. The user explicitly confirms the bookmark remains and uBlock
Origin is enabled. Omitted-language launch and profile preservation pass for
this package. Original-configuration restoration remains pending.

Screenshot `Screenshot 2026-10-11 164109.png` confirms `language.ps1 restore`
completed with launcher exit code 0. The user confirms Chromium reopened in
English with the bookmark and uBlock Origin intact. The helper restores the
saved original configuration with backup/current-config hash guards. The
supported Chromium language sequence and restoration are complete; no separate
restored command-line screenshot was supplied. Next is supported Firefox profile
and extension confirmation, followed by remaining production integration checks.

The user requested moving on from Firefox retesting to supported Chromium Windows
integration. Prepared `production-register.ps1` and `production-check-reg.ps1`
in the read-only Sandbox input bundle. Both require the Sandbox user/input path
and validate the supported Chromium artifact against the production manifest.
Registration refuses a pre-existing ownership sidecar and invokes only the
launcher's explicit registration option. The checker validates canonical owner,
browser ID, location-derived registry plan, open command, registered application,
and HTTP/HTTPS/HTML capabilities. Windows default selection remains manual.
Both scripts passed Windows PowerShell syntax parsing; neither was executed on
the host. Guest registration and handoff results remain pending. Supported
Firefox's separate profile-path evidence remains pending rather than inferred
from the earlier experimental run.

Screenshot `Screenshot 2026-10-11 165906.png` confirms supported Chromium
registration exit code 0. The checker reports version 2, browser ID
`ungoogled-chromium`, the canonical Production\Chromium launcher owner, and
matching location-scoped registry plan/open command/capabilities. Windows
Default apps visibly lists Ungoogled Chromium with the Production\Chromium
folder label. Candidate registration passes. Default selection, URL/HTML
handoff and removal remain pending; the inspection itself made no UserChoice
writes.

Screenshot `Screenshot 2026-10-11 170159.png` confirms the Windows default-browser
checkmark and HTTP, HTTPS, .htm and .html associations selecting the supported
Production\Chromium Nomad instance. FTP also displays this candidate; .shtml and
.xhtml remain unselected. No protocol dispatch result is inferred from Settings.
Prepared `production-handoff.ps1` with open/closed modes, reusing the registration
checker and verifying selected HTTP/HTTPS/.html ProgIds before dispatch. It checks
browser process paths, records retained window PIDs and browser/marker hashes,
and opens an HTTPS test URL plus an owned local HTML fixture via Windows shell
associations. Syntax parsing passed; no host dispatch occurred. Guest handoff
results and eventual registration cleanup remain pending.

Screenshot `Screenshot 2026-10-11 170611.png` confirms supported Chromium open-mode
handoff: the Example Domain and local HTML fixture tabs appear in the existing
window, the original window PID 3012 is retained, and both the installed marker
and browser executable hashes are unchanged. Registration/default checks passed
before dispatch. The user confirms everything is intact in response to the
bookmark, enabled uBlock Origin and no installation/update-window checks.
Open-window HTTPS/HTML handoff passes. Closed-browser handoff and registration
cleanup remain pending.

Screenshot `Screenshot 2026-10-11 170947.png` shows `production-handoff.ps1 closed`
returned to the prompt without errors. Registration/default checks and the
stopped-browser precondition passed; no original window PIDs were present.
Browser executable and installed marker remained unchanged. The helper's final
process checks did not report a failure. The screenshot contains only console
output, so both resulting pages, bookmark/uBlock Origin preservation and absence
of an installation/update window still require user confirmation. Registration
cleanup remains pending.

The user subsequently confirms both pages reopened with the bookmark and enabled
uBlock Origin intact, without an installation/update window. This completes the
supported Chromium closed-browser handoff pass. Prepared `production-finish.ps1`
to require stopped Chromium, verify the production registration/artifact using
the existing checker, retain the ownership sidecar as a removal backup, and call
the launcher's explicit unregister option. It verifies planned keys/value and
sidecar removal and unchanged browser executable, installed marker, Bookmarks
and Preferences hashes. Syntax parsing passed; no host registration changes
were performed. Guest unregistration remains pending.

Screenshot `Screenshot 2026-10-11 171701.png` confirms `production-finish.ps1`
completed with unregistration exit code 0. Planned registration keys/value and
the active ownership sidecar are absent. Chromium executable, installed-version
marker, Data\Default\Bookmarks and Data\Default\Preferences hashes are unchanged.
Browser/profile folders, registration backups and guest logs remain; no fixture
folder was deleted. Supported Chromium registration, manual default selection,
open/closed HTTPS/HTML handoff and unregistration are complete. This does not
establish that Windows selected a replacement default after removal, nor that
guest logs have been exported. The Sandbox session should be retained for now.
