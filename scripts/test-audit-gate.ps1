# Run in a fresh PowerShell process. All Cargo calls are mocked; no network,
# browser, registry, package installation, or persistent settings are touched.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function global:cargo-audit {}
function global:cargo {
    if ($args.Count -eq 0 -or $args[0] -ne 'audit') {
        throw 'The audit-only fixture must not invoke build or provisioning commands.'
    }
    $global:MockAuditArguments = @($args)
    $global:MockAuditCalls++
    $denyWarnings = $false
    for ($i = 0; $i -lt $args.Count - 1; $i++) {
        if ($args[$i] -eq '--deny' -and $args[$i + 1] -eq 'warnings') {
            $denyWarnings = $true
        }
    }
    $global:LASTEXITCODE = 0
    if ($global:MockAuditCase -eq 'vulnerability' -or
        ($global:MockAuditCase -ne 'clean' -and $denyWarnings)) {
        $global:LASTEXITCODE = 1
    }
}

foreach ($case in @('clean', 'unmaintained', 'unsound', 'yanked', 'vulnerability')) {
    $global:MockAuditCase = $case
    $global:MockAuditCalls = 0
    $global:MockAuditArguments = @()
    $failed = $false
    try {
        & (Join-Path $PSScriptRoot 'check.ps1') -AuditOnly
    }
    catch {
        $failed = $true
    }
    if ($global:MockAuditCalls -ne 1) { throw "Audit was not invoked exactly once for $case." }
    if ($case -eq 'clean' -and $failed) { throw 'A clean audit must pass.' }
    if ($case -ne 'clean' -and -not $failed) { throw "The gate accepted the $case fixture." }
    if ($global:MockAuditArguments -contains '--no-yanked') { throw 'Yanked checks must remain enabled.' }
}
Write-Host 'Audit gate regression fixtures passed.'
