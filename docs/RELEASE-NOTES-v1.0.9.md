# Nomad Launcher v1.0.9

This release fixes portable update, profile handoff, and clean-Windows startup
problems. It includes the changes merged in PR #68 and a workspace version update.

## Fixes

- Windows launchers use static CRT linkage and Direct3D 12 with the system shader
  compiler, removing the external Visual C++ runtime and OpenGL startup requirements.
- Updates verify packages and staged layouts before replacement, serialize work
  per portable folder, preserve recovery backups, and reapply required overlays.
- Windows URL and HTML handlers route through the owning launcher and portable
  profile. Protocol launches cannot install or update a browser.
- Default-browser registration is scoped to each launcher folder and reversible.
  Cleanup preserves unrelated profiles, associations, and ambiguous host traces.
- Chromium language settings support an explicit override and the default-language
  case. Helium's built-in updater is disabled to keep updates in the portable folder.
- Verification dependencies, bundled extraction tools, build validation, and
  release-upload safeguards have been refreshed.
- Floorp, LibreWolf, and Waterfox managed profiles enable ETP's major and minor
  site fixes for compatibility while keeping Strict protection. These exceptions
  may allow some tracking elements; uBlock Origin's rules are unchanged. The
  profile records the opt-in before Gecko's first-use migration can reset it.
- A browser that Windows cannot load at start-up, for example because a system
  DLL is missing, is reported as an error instead of a successful launch.

## Upgrading

Firefox, Firefox ESR, and Bitwarden launchers have been removed from the project.
Chromium, Helium, Floorp, Waterfox, LibreWolf, and Mullvad remain supported. This
release builds six launchers. Existing Firefox, Firefox ESR, and Bitwarden
installations, profiles, vaults, and Windows registrations are not
removed or migrated. Keep their old launcher for any needed unregistration;
do not place a different launcher in an existing owned folder.

Floorp needs the Microsoft Visual C++ Redistributable (x64) on the PC; Floorp's
own installer does not include it. Most PCs already have it. See Troubleshooting
in README.md if Floorp does not start.

Close the browser and launcher, back up the portable folder, and replace only the
matching Nomad launcher executable. Keep Browser, Data, and Nomad state together;
do not mix launcher brands in one folder. Use Nomad's documented registration
command and the folder-labelled entry in Windows Default apps for URL handoff.

Windows launchers require a usable Direct3D 12 adapter. Windows 10 and forced
software rendering have not yet been exercised in this validation campaign.
Chromium machine-ID/encryption bypass flags are not supplied by the hardening
profile; cross-machine sign-in persistence is not established by these tests.

## Validation and limits

The merged implementation passed all main-branch CI checks, Rust 1.92 checks,
Actions static analysis, and Chromium archive/layout/overlay verification. CI
built and validated the previous nine-launcher set before these removals.
That earlier local validation passed 492
Rust tests and the artifact, build, and release safeguard fixtures.

Windows Sandbox testing covered Chromium profile/extension persistence,
hardening, offline launch, language selection, default-browser registration,
open/closed URL and HTML handoff, and registration removal. An authentic Chromium
154-to-155 update survived an interrupted download, launched the older version
as fallback, and then updated successfully with the bookmark and enabled uBlock
Origin retained. Firefox verification/startup and experimental Firefox profile
and integration results are recorded separately in the audit documents.

Other browser families, post-replacement rollback, claimed-but-uninstalled
protocol refusal, and the historical Helium cross-machine sign-in report retain
coverage gaps. Download-failure recovery does not prove post-replacement rollback.

The version-only release preparation also passed the local canonical gate and
Rust 1.92 checks. The launcher-removal changes also passed the local canonical
gate (466 Rust tests, including retained updater safety coverage), 36 build
safeguard cases, and Rust 1.92 workspace/all-target checking. PR #70 merged after
its checks passed; the subsequent main Chromium Compatibility run exposed a
socket-fixture race, corrected in PR #71; all main checks then passed.

A Floorp 12.20.1 smoke test in Windows Sandbox then passed install verification,
portable profile, relaunch, hardening, cached offline launch, registration,
URL/HTML handoff and unregistration once the Visual C++ runtime was installed in
the guest. It also showed that Floorp cannot start without that runtime and that
the launcher reported the failed start as a launch. The start-up watch added
afterwards was checked in a second Sandbox session: it reported the failure when
the launcher was started from PowerShell and raised no false error once the
runtime was installed, but a launcher started from Explorer still let Windows
show its own missing-DLL dialog and reported a launch. A follow-up sets the
Windows error mode so that case is reported too, and keeps the error buttons
inside the window. It passed the local canonical gate (475 Rust tests) and Rust
1.92 checks. A fresh Sandbox check of the follow-up build then confirmed the
Explorer-started missing-runtime error, visible buttons, and normal Floorp launch
after installing Microsoft's verified runtime in the guest. The combined change
with current main still requires refreshed CI.

Corrected local builds of Floorp, LibreWolf, and Waterfox showed Strict and both
ETP site-fix options selected on first start; the owner confirmed the settings,
bookmark and enabled uBlock survived restart. LibreWolf used an imported browser
bundle after a Sandbox download interruption, which the owner accepted as
non-blocking. Its extension state is user-confirmed rather than independently
corroborated by exported metadata. The actual merged-main Floorp window title
`Nomad Launcher - Floorp` was also checked in Sandbox.

Mullvad and Helium still lack a live startup campaign; command-line inspection
does not establish that coverage. The remaining platform/recovery gaps above
remain open. The tagged release build remains pending.
Downloaded release artifacts must be verified against the signed
SHA256SUMS manifest and GitHub build provenance as described in README.md.
