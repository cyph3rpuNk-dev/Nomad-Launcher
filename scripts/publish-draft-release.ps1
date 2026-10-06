#requires -Version 7.0
# Called by release.yml. Tests replace gh in a fresh process; do not run this
# publisher locally unless creating/uploading a GitHub draft is authorized.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Tag,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$')]
    [string]$Repository,
    [string]$ArtifactDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'target/release'),
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent $PSScriptRoot
$remoteRepo = "github.com/$Repository"

function Read-GitHubJson {
    param([string[]]$Arguments)
    $output = @(& gh @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw "GitHub release lookup failed (exit $LASTEXITCODE); no upload attempted."
    }
    try {
        $parsed = ConvertFrom-Json -InputObject ($output -join "`n") -NoEnumerate -Depth 100
        return ,$parsed
    }
    catch { throw 'GitHub returned invalid release JSON; no upload attempted.' }
}

function Assert-ReleaseRecord {
    param($Record)
    if ($null -eq $Record -or $Record -is [array] -or
        $null -eq $Record.PSObject.Properties['id'] -or
        ($Record.id -isnot [long] -and $Record.id -isnot [int]) -or $Record.id -le 0 -or
        $null -eq $Record.PSObject.Properties['tag_name'] -or $Record.tag_name -isnot [string] -or
        $null -eq $Record.PSObject.Properties['draft'] -or $Record.draft -isnot [bool] -or
        $null -eq $Record.PSObject.Properties['assets'] -or $Record.assets -isnot [array]) {
        throw 'GitHub returned incomplete or invalid release metadata; no upload attempted.'
    }
}

function Find-Release {
    # A successful, paginated list distinguishes an absent release from an
    # authentication/network error. A failed lookup must never mean "create".
    $pages = Read-GitHubJson @('api', '--hostname', 'github.com', '--method', 'GET',
        '--paginate', '--slurp', "repos/$Repository/releases?per_page=100")
    if ($pages -isnot [array] -or $pages.Count -eq 0) { throw 'Invalid paginated release metadata.' }
    $found = $null
    foreach ($page in $pages) {
        if ($page -isnot [array]) { throw 'Invalid release page.' }
        foreach ($record in $page) {
            Assert-ReleaseRecord $record
            if ($record.tag_name -ceq $Tag) {
                if ($null -ne $found) { throw 'More than one release matched the requested tag.' }
                $found = $record
            }
        }
    }
    return $found
}

function Assert-EmptyDraft {
    param($Release)
    Assert-ReleaseRecord $Release
    if ($Release.tag_name -cne $Tag) { throw 'Release tag changed; refusing to upload.' }
    if (-not $Release.draft) { throw 'The release is already published; refusing to modify it.' }
    if ($Release.assets.Count -ne 0) {
        throw 'The draft already contains assets. Review/reset the draft explicitly or use a new tag; existing assets will not be replaced.'
    }
}

$release = Find-Release
if ($null -ne $release) { Assert-EmptyDraft $release }
if ($CheckOnly) {
    Write-Host 'Release target is eligible for a new or empty draft; no changes made.'
    return
}

# Check every artifact before creating a draft. CLI upload interprets # as a
# label separator, so reject such paths rather than upload a different file.
$artifactRoot = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
$launchers = @(Get-ChildItem -LiteralPath $artifactRoot -Filter 'Nomad-*.exe' -File | Sort-Object Name)
if ($launchers.Count -eq 0) { throw 'No launcher artifacts found; refusing to create/upload a release.' }
$files = @($launchers | ForEach-Object FullName)
$files += @((Join-Path $artifactRoot 'SHA256SUMS'), (Join-Path $artifactRoot 'licenses.zip'),
    (Join-Path $repoRoot 'nomad-release-signing-key.asc'))
foreach ($file in $files) {
    if ($file.Contains('#')) { throw 'Artifact paths containing # cannot be passed safely to gh release upload.' }
    $item = Get-Item -LiteralPath $file
    if ($item -isnot [IO.FileInfo] -or $item.Length -eq 0) { throw 'A required release artifact is missing, empty, or not a file.' }
}

if ($null -eq $release) {
    $notes = "Draft created by the release workflow.`n`nBefore publishing: download SHA256SUMS from this draft, create the detached signature locally (gpg --armor --detach-sign SHA256SUMS), attach SHA256SUMS.asc, then publish."
    $create = @('release', 'create', '--repo', $remoteRepo, '--draft', '--verify-tag',
        '--title', $Tag, '--notes', $notes, '--', $Tag)
    & gh @create >$null 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Draft creation failed (exit $LASTEXITCODE); no upload attempted." }
    $release = Find-Release
    if ($null -eq $release) { throw 'Created draft could not be confirmed; no upload attempted.' }
}

# Re-read this release ID immediately before upload. Never use --clobber:
# a publication/upload race must not delete or replace any existing asset.
$fresh = Read-GitHubJson @('api', '--hostname', 'github.com', '--method', 'GET',
    "repos/$Repository/releases/$($release.id)")
Assert-EmptyDraft $fresh
if ($fresh.id -ne $release.id) { throw 'Release identity changed; refusing to upload.' }
$upload = @('release', 'upload', '--repo', $remoteRepo, '--', $Tag) + $files
& gh @upload >$null 2>$null
if ($LASTEXITCODE -ne 0) { throw "Draft upload failed (exit $LASTEXITCODE); existing assets were not replaced. Inspect the draft before retrying." }
Write-Host 'Artifacts uploaded to the draft. Sign and verify SHA256SUMS before publishing.'
