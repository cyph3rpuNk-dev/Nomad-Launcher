[CmdletBinding()]
param(
    [switch]$SkipAudit,
    [switch]$AuditOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repoRoot
try {
    function Invoke-GateStep {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Name,
            [Parameter(Mandatory = $true)]
            [scriptblock]$Action
        )

        Write-Host "==> $Name"
        & $Action
        if ($LASTEXITCODE -ne 0) {
            throw "$Name failed with exit code $LASTEXITCODE"
        }
    }

    if (-not $AuditOnly) {
        Invoke-GateStep 'Formatting' {
            cargo fmt --all -- --check
        }
        Invoke-GateStep 'Clippy' {
            cargo clippy --workspace --all-targets -- -D warnings
        }
        Invoke-GateStep 'Tests' {
            cargo test --workspace
        }
    }

    if (-not $SkipAudit) {
        $audit = Get-Command cargo-audit -ErrorAction SilentlyContinue
        if ($null -eq $audit) {
            throw 'cargo-audit is required. Install it with: cargo install cargo-audit --locked'
        }
        Invoke-GateStep 'Dependency advisories' {
            cargo audit `
                --ignore RUSTSEC-2023-0071 `
                --ignore RUSTSEC-2026-0194 `
                --ignore RUSTSEC-2026-0195
        }
    }

    Write-Host 'Nomad validation passed.'
}
finally {
    Pop-Location
}
