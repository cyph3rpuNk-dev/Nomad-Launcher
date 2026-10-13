# Isolated Windows smoke tests

Prepared against `a83ef02` on `rebuild/foundation`. An experimental Firefox
baseline was later exercised in Windows Sandbox;
see [the dated results](SANDBOX-VALIDATION-2026-10-11.md). Supported artifacts must
be tested separately after the runtime/renderer production changes.
Passing metadata/extraction tests does not establish these results.
Record outcomes in [AUDIT-STATUS.md](AUDIT-STATUS.md).

## Environment and evidence

Use a disposable Windows 10/11 x64 VM or a separate Windows test account with
no personal browser profiles or accounts. The four native registry tests write
HKCU; some use fixed test key names. Browser startup can also register handlers
and create host data even when its profile is portable. A temporary folder alone
is not account isolation. Take a VM snapshot when available. Do not use the
user's existing portable installations, personal credentials, or default apps.

Run commands in that environment from the Nomad checkout. Record Windows
version, `git rev-parse HEAD`, `rustc --version`, command exit codes, launcher
SHA-256 hashes, resolved browser versions, and each observation. Preserve logs
and registry state files when a check fails; stop dependent steps. Creating or
switching accounts and choosing defaults are user actions, not automated here.

## Native registry tests

Run serially so registry fixtures cannot interfere. These exact filters run
only the four intentionally ignored HKCU tests, not package downloads:

```powershell
$registryTests = @(
    'registry::tests::repair_command_key_rewrites_only_commands_inside_install_dir',
    'registry::tests::repair_rewrites_progids_that_are_not_the_userchoice_selection',
    'registry::tests::register_writes_sidecar_and_unregister_removes_it',
    'selfreg_watch::tests::live_repair_reroutes_a_self_registration_written_mid_session'
)
foreach ($testName in $registryTests) {
    cargo test -p nomad-core --lib --locked --target x86_64-pc-windows-msvc $testName -- --exact --ignored --nocapture --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw "Native registry check failed: $testName" }
    # Read the result: exactly one test must have run and passed, not zero.
}
```

These tests do not prove Windows Default-apps picker integration or real browser
handoff. Do not rerun them in the normal user account to diagnose a failure.

## Build and create disposable instances

Start with Floorp and Ungoogled Chromium to exercise Gecko and Chromium. This
is representative coverage, not coverage of all six launchers. Builds below
are unsigned local test artifacts, not published release packages.

```powershell
cargo build --release --locked --target x86_64-pc-windows-msvc -p nomad-floorp -p nomad-ungoogled-chromium
if ($LASTEXITCODE -ne 0) { throw 'Smoke-test build failed' }
$artifactRoot = Join-Path $PWD 'target/x86_64-pc-windows-msvc/release'
$smokeRoot = Join-Path $env:TEMP ('Nomad-Smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $smokeRoot -ErrorAction Stop | Out-Null
foreach ($family in @('Floorp', 'Chromium')) {
    $instancePath = Join-Path $smokeRoot $family
    New-Item -ItemType Directory -Path $instancePath -ErrorAction Stop | Out-Null
    $sourcePath = Join-Path $artifactRoot ("Nomad-$family.exe")
    Copy-Item -LiteralPath $sourcePath -Destination $instancePath -ErrorAction Stop
    Get-FileHash -LiteralPath (Join-Path $instancePath ("Nomad-$family.exe")) -Algorithm SHA256
}
Write-Output "Disposable instances: $smokeRoot"
```

Use a default Cargo target directory for this command; if `CARGO_TARGET_DIR` is
set, resolve the actual build output before copying. Do not copy stale binaries.
Keep exactly one launcher family in each instance folder. Launch interactively
from Explorer in the isolated session; capture errors instead of dismissing them.

## Browser checks

For each instance, record pass/fail/not run and evidence for every row:

| Check | Action and expected observation |
|---|---|
| Fresh install | Run the launcher directly while online. It resolves, verifies and installs the browser, then opens it. Record version and launch errors. |
| Portable profile | Inspect `about:support` (Gecko) or `chrome://version` (Chromium). The profile must be under the disposable instance's `Data/`, not a host profile. Add a disposable bookmark as a sentinel. |
| Relaunch | Close the browser fully, relaunch, and confirm the same profile and bookmark. A remaining background process can invalidate this check. |
| Hardening toggle | Close fully; set `hardening.enabled = false` in `Nomad/nomad.toml`, relaunch, then repeat with `true`. The bookmark and installed extension state must persist. |
| Language | On Chromium, set `launch.language = "fr"`, fully restart, and record the command line and UI locale. Repeat with `extra_args = ["--lang=de"]`, then with the language key omitted and no override. Locale availability/fallback is a browser result, not guaranteed by argument tests. Gecko should receive no generated `--lang` flag. |
| Extension acceptance | Inspect the browser's extension UI for uBlock Origin, its enabled state and any signature/load errors. Repeat after relaunch and the hardening toggle. Record version and launcher logs; file presence alone is insufficient. |
| ETP site compatibility | On Floorp, LibreWolf, and Waterfox with Nomad hardening enabled, inspect Privacy & Security: Strict stays selected, and both "Fix major site issues" and "Fix minor site issues" are checked. Confirm both `privacy.trackingprotection.allow_list.*.enabled` values in `about:config`, then fully close and relaunch to confirm persistence. Record absent controls or locked upstream preferences as a browser-specific limitation. |
| Offline launch | In a disposable VM, disconnect its virtual network, then launch the existing install and observe timeout/fallback behavior. Restore networking afterward. Setting `check_on_launch = false` separately tests configuration bypass, not network failure. Do not disable host networking for this test. |
| Update/preservation | Requires an authentic older browser package and a newer supported release. Keep both within a separate disposable instance and use the normal verified updater. Confirm the bookmark, extension state and version marker afterward. If no suitable older fixture is available, mark not run. Never falsify an installed-version marker to claim update coverage. |
| Failure/retry | In a VM, interrupt networking during a disposable update download. The working installation/profile must remain usable; restore networking and retry. This exercises download failure, not every rollback path. Never bypass verification or corrupt the user's installation. |

Extend coverage to Waterfox, LibreWolf, Mullvad, and Helium
before claiming all-launcher validation. Mullvad uses `Data/Profile`; verify its
profile preservation separately. Use no real sign-in credentials. Helium's historical
cross-machine cookie report requires a separate controlled two-machine test.

## Default-browser picker and URL/file handoff

Only in the isolated account, after startup/profile checks pass:

1. Run the instance's launcher with `--register-default`. Check its exit status
   and retain `Nomad/nomad.reg-state.json` and repair-journal files.
2. In Windows Default apps, select the folder-labelled Nomad entry for the
   desired URL protocols/file type. Record the selection; Nomad does not set
   UserChoice itself.
3. Leave the browser open with the disposable bookmark visible. Open a harmless
   URL through Windows and a local HTML fixture. Both must reach the same
   portable profile, without a new empty profile or provisioning/update flow.
4. Close the browser and repeat handoff: the existing installation should open
   without downloading or provisioning. Test an empty disposable instance
   separately and confirm protocol invocation cannot install a browser.
5. Test a second disposable copy of the same browser in a different folder.
   Confirm distinct picker entries; unregistering one must preserve the other.
6. Close the browser and run that instance's launcher with
   `--unregister-default`. Check its exit status. Failures require investigation
   with state retained, not manual registry deletion. Automatic repair stays
   disabled until a later successful explicit registration.

See [registry ownership and recovery limits](REGISTRY-SAFETY.md). Unknown
historical registry originals cannot be restored by these tests.

## Completion and cleanup

Report actual commands, observations, failures, skips and retained artifacts.
Do not call a prepared runbook a passed test. Unregister registered instances
before removing folders; retain failed recovery records. Any cleanup must first
verify the absolute target is the exact owned smoke root, with all test browser
processes stopped. No recursive cleanup command is provided here. Reverting the
disposable VM snapshot is preferable when validating host-state behavior.
