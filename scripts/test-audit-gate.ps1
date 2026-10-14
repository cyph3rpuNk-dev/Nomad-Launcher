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
    if ($global:MockAuditCase -in @('vulnerability', 'unmaintained', 'unsound', 'yanked') -and $denyWarnings) {
        $global:LASTEXITCODE = 1
    }
    if ($global:MockAuditCase -eq 'registry-timeout') {
        # The real failure observed in review: stderr error, process exit zero.
        Write-Error -Message "couldn't check if the package is yanked: registry timeout" -ErrorAction Continue
    }
    if ($global:MockAuditCase -eq 'invalid-json') { return '{broken' }
    if ($global:MockAuditCase -eq 'missing-report') { return '{}' }
    if ($global:MockAuditCase -eq 'empty-output') { return }
    if ($global:MockAuditCase -eq 'warning-zero-exit') {
        return '{"vulnerabilities":{"found":false},"warnings":{"yanked":[{"name":"fixture"}]}}'
    }
    if ($global:MockAuditCase -eq 'unsafe-report') {
        return '{"vulnerabilities":{"found":true},"warnings":{}}'
    }
    return '{"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}'
}

foreach ($case in @('clean', 'unmaintained', 'unsound', 'yanked', 'vulnerability', 'registry-timeout', 'invalid-json', 'missing-report', 'empty-output', 'unsafe-report', 'warning-zero-exit')) {
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
    if ($global:MockAuditArguments -notcontains '--json') { throw 'Audit must prove structured completion.' }
    if ($global:MockAuditArguments -contains '--no-yanked') { throw 'Yanked checks must remain enabled.' }
}
Write-Host 'Audit gate regression fixtures passed.'
