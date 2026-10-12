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

## Upgrading

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
built and validated all nine launcher artifacts. Local validation passed 492
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
Rust 1.92 checks. Release-branch CI and the tagged release build remain pending.
Downloaded release artifacts must be verified against the signed
SHA256SUMS manifest and GitHub build provenance as described in README.md.
