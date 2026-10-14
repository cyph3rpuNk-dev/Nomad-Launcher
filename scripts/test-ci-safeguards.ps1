# Fresh process. Gate tools are mocks; workflow checks are offline wiring checks.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repoRoot=Split-Path -Parent $PSScriptRoot
$global:GateCalls=[Collections.Generic.List[object]]::new()
$global:GateCase=''
function global:pwsh {
    $global:GateCalls.Add(@('pwsh')+@($args)); $global:LASTEXITCODE=0
    if ($global:GateCase -eq 'artifact-failure' -and ($args -join ' ') -match 'test-artifact-guard.ps1') {$global:LASTEXITCODE=1}
    if ($global:GateCase -eq 'recovery-failure' -and ($args -join ' ') -match 'test-cleanup-recovery-sandbox.ps1') {$global:LASTEXITCODE=1}
    if ($global:GateCase -eq 'integration-failure' -and ($args -join ' ') -match 'test-recovery-integration.ps1') {$global:LASTEXITCODE=1}
}
function global:cargo {
    $global:GateCalls.Add(@('cargo')+@($args)); $global:LASTEXITCODE=0
    if ($args[0] -in @('clippy','test') -and [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and (-not ($args -contains '--target') -or -not ($args -contains 'x86_64-pc-windows-msvc'))) {throw 'Windows gate must separate target and host crates.'}
    if ($args[0] -in @('clippy','test') -and -not ($args -contains '--locked')) {throw 'Unlocked gate command.'}
    if (($global:GateCase -eq 'clippy-failure' -and $args[0] -eq 'clippy') -or ($global:GateCase -eq 'test-failure' -and $args[0] -eq 'test')) {$global:LASTEXITCODE=1}
}
foreach ($case in @('clean','artifact-failure','recovery-failure','integration-failure','clippy-failure','test-failure')) {
    $global:GateCase=$case; $global:GateCalls.Clear(); $failed=$false
    try {& (Join-Path $PSScriptRoot 'check.ps1') -SkipAudit 6>$null} catch {$failed=$true}
    if ($failed -ne ($case -ne 'clean')) {throw 'Gate ignored or invented a native failure.'}
    $tests=@($global:GateCalls | Where-Object {$_[0] -eq 'cargo' -and $_[1] -eq 'test'})
    if ($case -eq 'clippy-failure' -and $tests.Count -ne 0) {throw 'Dependent tests ran after failed Clippy.'}
    $expectedFixtures=if ($case -eq 'artifact-failure') {1} elseif ($case -eq 'recovery-failure') {6} else {7}
    if ($case -in @('artifact-failure','recovery-failure','integration-failure') -and @($global:GateCalls | Where-Object {$_[0] -eq 'cargo'}).Count -ne 0) {throw 'Cargo ran after failed safety fixtures.'}
    if (@($global:GateCalls | Where-Object {$_[0] -eq 'pwsh'}).Count -ne $expectedFixtures) {throw 'Required fixture gates are not wired.'}
}
function Assert-WorkflowWiring([string]$Text,[string]$Name) {
    foreach ($line in ($Text -split '\r?\n')) {
        if ($line -match '^\s*(?:run:\s*)?cargo\s+(?:\+[^\s]+\s+)?(?:build|test|check|clippy)\s+' -and $line -notmatch '(?:^|\s)--locked(?:\s|$)') {throw "Unlocked workspace command in $Name"}
    }
    foreach ($line in ($Text -split '\r?\n')) {
        if ($line -match '^\s*(?:run:\s*)?cargo\s+(?:\+[^\s]+\s+)?(?:build|test|check|clippy)\s+' -and $line -notmatch '--target x86_64-pc-windows-msvc') {throw "Windows workspace command must use an explicit target in $Name"}
    }
    if ($Name -eq 'hardening-sync.yml') {
        if ($Text -notmatch '(?m)^permissions: \{\}\s*$') {throw 'Hardening Sync must default-deny.'}
        $jobs=@([regex]::Matches($Text.Substring($Text.IndexOf('jobs:')),'(?ms)^  ([a-z][a-z0-9-]+):\r?\n(.*?)(?=^  [a-z][a-z0-9-]+:|\z)'))
        if ($jobs.Count -ne 4) {throw 'Unexpected Hardening Sync job set.'}
        foreach ($job in $jobs) {
            $name=$job.Groups[1].Value; $body=$job.Groups[2].Value
            if ($name -in @('chromium-flags','arkenfox')) {
                if ($body -notmatch 'contents: write' -or $body -notmatch 'pull-requests: write') {throw 'PR writer lacks explicit scopes.'}
            } elseif ($body -match ': write' -or $body -notmatch 'contents: read' -or $body -notmatch 'persist-credentials: false') {throw 'Verification job has excessive scopes or persisted credentials.'}
        }
    }
    if ($Name -eq 'ci.yml' -and @([regex]::Matches($Text,'persist-credentials: false')).Count -ne 3) {throw 'CI checkouts must not persist credentials.'}
}
foreach ($path in @(Get-ChildItem -LiteralPath (Join-Path $repoRoot '.github/workflows') -Filter '*.yml')) {
    Assert-WorkflowWiring ([IO.File]::ReadAllText($path.FullName)) $path.Name
}
$sync=[IO.File]::ReadAllText((Join-Path $repoRoot '.github/workflows/hardening-sync.yml'))
foreach ($mutant in @(
    $sync.Replace('permissions: {}',"permissions: { contents: write }"),
    $sync.Replace('contents: read','contents: write'),
    $sync.Replace('cargo test --locked','cargo test'),
    $sync.Replace('--target x86_64-pc-windows-msvc','')
)) {
    $failed=$false; try {Assert-WorkflowWiring $mutant 'hardening-sync.yml'} catch {$failed=$true}
    if (-not $failed) {throw 'Workflow regression fixture was accepted.'}
}
foreach ($path in @((Join-Path $repoRoot 'dist.ps1'),$PSCommandPath,(Join-Path $PSScriptRoot 'test-build-safeguards.ps1'))) {
    $tokens=$null; $errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if ($errors.Count -ne 0) {throw 'PowerShell syntax error.'}
}
# Keep the exact distribution set synchronized with the declared binaries.
$dist=[IO.File]::ReadAllText((Join-Path $repoRoot 'dist.ps1'))
$declaredNames=[Collections.Generic.List[string]]::new()
foreach ($manifest in @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'launchers') -Filter Cargo.toml -Recurse)) {
    $text=[IO.File]::ReadAllText($manifest.FullName)
    $bin=[regex]::Match($text,'(?s)\[\[bin\]\]\s*\r?\nname\s*=\s*"([^"]+)"')
    if (-not $bin.Success -or -not $dist.Contains("'"+$bin.Groups[1].Value+".exe'")) {throw 'Distribution set differs from workspace binaries.'}
    $declaredNames.Add($bin.Groups[1].Value+'.exe')
}
$distributionNames=@([regex]::Matches($dist,"'(Nomad-[A-Za-z0-9-]+\.exe)'") | ForEach-Object {$_.Groups[1].Value})
if ((@($distributionNames | Sort-Object) -join ',') -cne (@($declaredNames | Sort-Object) -join ',')) {throw 'Distribution binary set must exactly match the workspace.'}
Write-Host 'CI safeguard fixtures passed (9 failure/wiring cases plus workflow and binary-set checks).'
$global:LASTEXITCODE=0
