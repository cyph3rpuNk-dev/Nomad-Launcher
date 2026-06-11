#Requires -Version 5.1
<#
.SYNOPSIS
    On-demand local check for upstream drift in Nomad's vendored hardening baselines.

.DESCRIPTION
    Mirrors the *detection* half of .github/workflows/hardening-sync.yml so you can
    check for drift without GitHub Actions (e.g. on a local-only checkout).

    READ-ONLY: never modifies the baselines or the shipped payloads. It fetches
    upstream, compares against the pinned baselines, and reports.

    Sources checked:
      1. ungoogled-chromium docs/flags.md   vs  core/baselines/ungoogled-flags.md
      2. arkenfox user.js (latest release)  vs  core/baselines/arkenfox-user.js
                                                + core/baselines/arkenfox-version.txt

    When drift is found, curate it by hand into the SHIPPED payloads, keeping only
    the safe, non-site-breaking subset (SPEC section 5):
      - arkenfox  ->  core/payloads/firefox/user.js  (+ waterfox/user.js for ESR 115,
                      + librewolf/user.js — minimal, only LibreWolf's genuine gaps)
      - flags.md  ->  HARDENING_FLAGS in core/src/browsers/{ungoogled,helium}.rs

    Exit code: 0 = no drift, 1 = drift detected (or a source could not be checked).

.PARAMETER ShowDiff
    Also print the line-level differences, not just the summary.

.EXAMPLE
    ./check-hardening-drift.ps1
.EXAMPLE
    ./check-hardening-drift.ps1 -ShowDiff
#>
[CmdletBinding()]
param([switch]$ShowDiff)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root = $PSScriptRoot
$driftFound = $false
$ua = @{ 'User-Agent' = 'nomad-hardening-drift' }

function Write-Head($t)  { Write-Host ""; Write-Host "== $t ==" -ForegroundColor Cyan }
function Write-Ok($t)    { Write-Host "  [OK]    $t" -ForegroundColor Green }
function Write-Drift($t) { Write-Host "  [DRIFT] $t" -ForegroundColor Yellow }
function Write-Warn2($t) { Write-Host "  [WARN]  $t" -ForegroundColor Yellow }
function Write-Err2($t)  { Write-Host "  [ERR]   $t" -ForegroundColor Red }

function Get-Body($url) {
    (Invoke-WebRequest -Uri $url -Headers $ua -UseBasicParsing).Content
}

function Format-Lf($s) { ($s -replace "`r`n", "`n").TrimEnd("`n") }

# --- 1. ungoogled-chromium docs/flags.md --------------------------------------
Write-Head "Ungoogled-Chromium docs/flags.md"
$flagsBaseline = Join-Path $root 'core/baselines/ungoogled-flags.md'
try {
    $upstreamFlags = Get-Body 'https://raw.githubusercontent.com/ungoogled-software/ungoogled-chromium/master/docs/flags.md'
    if (-not (Test-Path $flagsBaseline)) {
        Write-Warn2 "no baseline at core/baselines/ungoogled-flags.md (first sync?)"
        $driftFound = $true
    }
    else {
        $a = Format-Lf (Get-Content $flagsBaseline -Raw)
        $b = Format-Lf $upstreamFlags
        if ($a -ceq $b) {
            Write-Ok "flags.md matches the pinned baseline"
        }
        else {
            Write-Drift "upstream flags.md differs from the baseline"
            $driftFound = $true
            if ($ShowDiff) {
                Compare-Object ($a -split "`n") ($b -split "`n") | ForEach-Object {
                    $tag = if ($_.SideIndicator -eq '=>') { '+ upstream' } else { '- baseline' }
                    Write-Host ("    {0}: {1}" -f $tag, $_.InputObject)
                }
            }
        }

        # Heuristic: which Nomad Chromium flags no longer appear (by name) upstream.
        $rsFiles = @(
            (Join-Path $root 'core/src/browsers/ungoogled.rs'),
            (Join-Path $root 'core/src/browsers/helium.rs')
        )
        $flags = @()
        foreach ($f in $rsFiles) {
            if (Test-Path $f) {
                $flags += [regex]::Matches((Get-Content $f -Raw), '"(--[A-Za-z0-9=_:.-]+)"') |
                    ForEach-Object { $_.Groups[1].Value }
            }
        }
        # Drop format!-string prefixes like "--user-data-dir=" / "--load-extension="
        # (captured up to '=' because the value is a {} placeholder, not a literal).
        $flags = @($flags | Where-Object { $_ -notmatch '=$' } | Sort-Object -Unique)
        $missing = @()
        foreach ($fl in $flags) {
            $bare = ($fl -replace '=.*$', '') -replace '^--', ''   # name only, no value
            if ($upstreamFlags -notmatch [regex]::Escape($bare)) { $missing += $fl }
        }
        if ($missing.Count -gt 0) {
            Write-Warn2 "Nomad flags not found by name in upstream flags.md - verify each (note: stock-Chromium switches like --disable-sync are not listed in ungoogled's doc, so most of these are false positives):"
            $missing | ForEach-Object { Write-Host "          $_" }
        }
        else {
            Write-Ok "every Nomad Chromium flag name still appears in upstream flags.md"
        }
    }
}
catch {
    Write-Err2 "could not check flags.md: $($_.Exception.Message)"
    $driftFound = $true
}

# --- 2. arkenfox user.js ------------------------------------------------------
Write-Head "Arkenfox user.js"
$ajBaseline = Join-Path $root 'core/baselines/arkenfox-user.js'
$ajVersion  = Join-Path $root 'core/baselines/arkenfox-version.txt'
try {
    $latest = (Invoke-RestMethod -Uri 'https://api.github.com/repos/arkenfox/user.js/releases/latest' -Headers $ua).tag_name
    $pinned = if (Test-Path $ajVersion) { (Get-Content $ajVersion -Raw).Trim() } else { '' }
    $pinnedShow = if ($pinned) { $pinned } else { '(none)' }
    Write-Host ("    pinned: {0}    latest: {1}" -f $pinnedShow, $latest)
    if ($latest -eq $pinned) {
        Write-Ok "arkenfox is at the latest release ($pinned)"
    }
    else {
        Write-Drift "new arkenfox release available: $pinnedShow -> $latest"
        $driftFound = $true
        if (Test-Path $ajBaseline) {
            $newUserJs = Get-Body "https://raw.githubusercontent.com/arkenfox/user.js/$latest/user.js"
            $a = Format-Lf (Get-Content $ajBaseline -Raw)
            $b = Format-Lf $newUserJs
            $cmp = Compare-Object ($a -split "`n") ($b -split "`n")
            $added   = @($cmp | Where-Object { $_.SideIndicator -eq '=>' }).Count
            $removed = @($cmp | Where-Object { $_.SideIndicator -eq '<=' }).Count
            Write-Host ("    user.js delta vs baseline: +{0} / -{1} lines" -f $added, $removed)
            if ($ShowDiff) {
                $cmp | ForEach-Object {
                    $tag = if ($_.SideIndicator -eq '=>') { '+ new' } else { '- baseline' }
                    Write-Host ("    {0}: {1}" -f $tag, $_.InputObject)
                }
            }
        }
    }
}
catch {
    Write-Err2 "could not check arkenfox: $($_.Exception.Message)"
    $driftFound = $true
}

# --- Summary ------------------------------------------------------------------
Write-Host ""
if ($driftFound) {
    Write-Host "Drift detected (or a source was unreachable) - review above; curate upstream changes into the shipped payloads by hand (SPEC section 5)." -ForegroundColor Yellow
    exit 1
}
else {
    Write-Host "No drift - baselines are current." -ForegroundColor Green
    exit 0
}
