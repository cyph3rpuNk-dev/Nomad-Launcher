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

    # --target separates Windows static-CRT target crates from host proc macros.
    $targetArgs = @()
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { $targetArgs = @('--target', 'x86_64-pc-windows-msvc') }
    if (-not $AuditOnly) {
        Invoke-GateStep 'Artifact guard regression fixtures' {
            pwsh -NoProfile -File (Join-Path $PSScriptRoot 'test-artifact-guard.ps1')
        }
        Invoke-GateStep 'Audit gate regression fixtures' {
            pwsh -NoProfile -File (Join-Path $PSScriptRoot 'test-audit-gate.ps1')
        }
        Invoke-GateStep 'Release publishing regression fixtures' {
            pwsh -NoProfile -File (Join-Path $PSScriptRoot 'test-release-publish.ps1')
        }
        Invoke-GateStep 'Build safeguard regression fixtures' {
            pwsh -NoProfile -File (Join-Path $PSScriptRoot 'test-build-safeguards.ps1')
        }
        Invoke-GateStep 'CI safeguard regression fixtures' {
            pwsh -NoProfile -File (Join-Path $PSScriptRoot 'test-ci-safeguards.ps1')
        }
        Invoke-GateStep 'Formatting' {
            cargo fmt --all -- --check
        }
        Invoke-GateStep 'Clippy' {
            cargo clippy --workspace --all-targets --locked @targetArgs -- -D warnings
        }
        Invoke-GateStep 'Tests' {
            cargo test --workspace --locked @targetArgs
        }
    }

    if (-not $SkipAudit) {
        $audit = Get-Command cargo-audit -ErrorAction SilentlyContinue
        if ($null -eq $audit) {
            throw 'cargo-audit is required. Install it with: cargo install cargo-audit --locked'
        }
        Invoke-GateStep 'Dependency advisories' {
            # RSA is used only for public-key signature verification. The
            # unfixed private-key timing advisory is documented in SECURITY.md.
            # cargo-audit can print registry failures yet exit zero. Capture
            # stderr too: any non-JSON diagnostic makes completion unprovable.
            $auditOutput = @(& cargo audit --json --deny warnings --ignore RUSTSEC-2023-0071 2>&1)
            $auditExitCode = $LASTEXITCODE
            $auditText = ($auditOutput | ForEach-Object { $_.ToString() }) -join "`n"
            if ($auditExitCode -ne 0) {
                throw "Dependency audit failed with exit code $auditExitCode. $auditText"
            }
            try {
                $report = ConvertFrom-Json -InputObject $auditText -ErrorAction Stop
                if ($null -eq $report -or $report -is [array] -or
                    $null -eq $report.PSObject.Properties['vulnerabilities'] -or
                    $null -eq $report.PSObject.Properties['warnings'] -or
                    $null -eq $report.vulnerabilities.PSObject.Properties['found'] -or
                    $report.vulnerabilities.found -isnot [bool] -or
                    $report.vulnerabilities.found -or
                    $report.warnings -isnot [pscustomobject] -or
                    @($report.warnings.PSObject.Properties).Count -ne 0) {
                    throw 'Missing or unsafe dependency audit report.'
                }
            }
            catch {
                throw "Dependency audit did not complete with a valid clean JSON report; registry checks may have failed. $auditText"
            }
            Write-Host 'Dependency audit completed without registry-check diagnostics.'
        }
    }

    Write-Host 'Nomad validation passed.'
}
finally {
    Pop-Location
}
