# Run in a fresh PowerShell process: all gh calls are mocked before loading
# publisher code. No network, authentication, release changes or browser runs.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$publisher = Join-Path $PSScriptRoot 'publish-draft-release.ps1'
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('nomad-release-test-' + [Guid]::NewGuid().ToString('N'))
$global:ReleaseCalls = [Collections.Generic.List[object]]::new()
$global:ReleaseCase = ''
$global:CreatedDraft = $false
$global:FixtureTag = 'v9.0.0'
$fixtureCount = 0

function global:gh {
    $global:ReleaseCalls.Add(@($args))
    $global:LASTEXITCODE = 0
    if ($args[0] -eq 'api') {
        if (-not ($args -contains 'GET') -or -not ($args -contains '--hostname') -or
            -not ($args -contains 'github.com')) { throw 'Unexpected API scope/method in fixture.' }
        if ($global:ReleaseCase -eq 'lookup-failure' -or
            ($global:ReleaseCase -eq 'lookup-after-create-failure' -and $global:CreatedDraft)) {
            $global:LASTEXITCODE = 1; return
        }
        if ($global:ReleaseCase -eq 'invalid-json') { return '{invalid' }
        if ($global:ReleaseCase -eq 'null-json') { return 'null' }
        $listing = $args -contains '--slurp'
        if ($listing -and -not ($args -contains '--paginate')) { throw 'Release lookup must cover all pages.' }
        if ($listing -and $global:ReleaseCase -in @('absent', 'create-failure', 'lookup-after-create-failure') -and -not $global:CreatedDraft) {
            return '[[]]'
        }
        $record = @{ id = 42; tag_name = $global:FixtureTag; draft = $true; assets = @() }
        if ($global:ReleaseCase -eq 'published' -or ($global:ReleaseCase -eq 'published-before-upload' -and -not $listing)) {
            $record.draft = $false
        }
        if ($global:ReleaseCase -eq 'missing-draft-field') { [void]$record.Remove('draft') }
        if ($global:ReleaseCase -eq 'string-draft') { $record.draft = 'true' }
        if ($global:ReleaseCase -eq 'missing-assets') { [void]$record.Remove('assets') }
        if ($global:ReleaseCase -eq 'populated-draft' -or ($global:ReleaseCase -eq 'assets-before-upload' -and -not $listing)) {
            $record.assets = @(@{ name = 'SHA256SUMS.asc' })
        }
        if (-not $listing -and $global:ReleaseCase -eq 'wrong-release-id') { $record.id = 99 }
        if (-not $listing -and $global:ReleaseCase -eq 'wrong-release-tag') { $record.tag_name = 'v-other' }
        if ($listing) {
            if ($global:ReleaseCase -eq 'invalid-pages') { return '[{}]' }
            if ($global:ReleaseCase -eq 'empty-pages') { return '[]' }
            $json = ConvertTo-Json -InputObject $record -Depth 8 -Compress
            if ($global:ReleaseCase -eq 'multiple-pages') {
                $other = @{ id = 7; tag_name = 'v-old'; draft = $false; assets = @(@{ name = 'old.exe' }) }
                $oldJson = ConvertTo-Json -InputObject $other -Depth 8 -Compress
                return ('[[' + $oldJson + '],[' + $json + ']]')
            }
            if ($global:ReleaseCase -eq 'duplicate-tags') { return ('[[' + $json + ',' + $json + ']]') }
            return ('[[' + $json + ']]')
        }
        return (ConvertTo-Json -InputObject $record -Depth 8 -Compress)
    }
    if ($args[0] -eq 'release' -and $args[1] -eq 'create') {
        if ($global:ReleaseCase -eq 'create-failure') { $global:LASTEXITCODE = 1; return }
        $global:CreatedDraft = $true; return
    }
    if ($args[0] -eq 'release' -and $args[1] -eq 'upload') {
        if ($global:ReleaseCase -eq 'upload-failure') { $global:LASTEXITCODE = 1 }
        return
    }
    throw 'Unexpected GitHub CLI operation in fixture.'
}

function Reset-Fixture([string]$Case) {
    $global:ReleaseCase = $Case
    $global:ReleaseCalls.Clear()
    $global:CreatedDraft = $false
    $global:FixtureTag = 'v9.0.0'
}

function Assert-PublishingCalls([int]$Creates, [int]$Uploads) {
    $actualCreates = @($global:ReleaseCalls | Where-Object { $_[0] -eq 'release' -and $_[1] -eq 'create' })
    $actualUploads = @($global:ReleaseCalls | Where-Object { $_[0] -eq 'release' -and $_[1] -eq 'upload' })
    if ($actualCreates.Count -ne $Creates -or $actualUploads.Count -ne $Uploads) {
        throw "Unexpected mutations for $global:ReleaseCase (create=$($actualCreates.Count), upload=$($actualUploads.Count))."
    }
    foreach ($call in $global:ReleaseCalls) {
        if ($call -contains '--clobber' -or $call -contains 'delete' -or $call -contains 'delete-asset') {
            throw 'The publisher must never delete or replace existing assets.'
        }
        if ($call[0] -eq 'release') {
            if (-not ($call -contains '--repo') -or -not ($call -contains 'github.com/fixture/nomad')) {
                throw 'Publishing must specify the intended repository.'
            }
            $separator = [Array]::IndexOf($call, '--')
            if ($separator -lt 0 -or $call[$separator + 1] -cne $global:FixtureTag) {
                throw 'Tag must remain a literal positional argument.'
            }
            if ($call[1] -eq 'create' -and (-not ($call -contains '--draft') -or -not ($call -contains '--verify-tag'))) {
                throw 'Creation must require an existing tag and remain a draft.'
            }
        }
    }
}

function Invoke-Fixture([switch]$CheckOnly) {
    & $publisher -Tag $global:FixtureTag -Repository 'fixture/nomad' -ArtifactDirectory $fixtureRoot -CheckOnly:$CheckOnly 6>$null
}

try {
    # Parse the scripts before running them. Workflow wiring checks ensure the
    # actual release job calls this tested helper before building and for upload.
    foreach ($path in @($publisher, $PSCommandPath)) {
        $tokens = $null; $errors = $null
        [void][Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        if ($errors.Count -ne 0) { throw "PowerShell syntax errors in $path" }
    }
    $workflow = [IO.File]::ReadAllText((Join-Path $repoRoot '.github/workflows/release.yml'))
    $runs = @($workflow -split "`r?`n" | Where-Object { $_ -match '^\s*run:.*publish-draft-release\.ps1' })
    if ($runs.Count -ne 2 -or $runs[0] -notmatch '-CheckOnly' -or $runs[1] -match '-CheckOnly' -or
        $workflow -match '--clobber' -or
        $workflow.IndexOf($runs[0].Trim()) -gt $workflow.IndexOf('      - name: Install Rust toolchain') -or
        $workflow -notmatch 'group: release-\$\{\{ github\.ref \}\}' -or
        $workflow -notmatch 'cancel-in-progress: false') {
        throw 'Release workflow must use the guarded publisher and serialize same-tag runs.'
    }

    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    foreach ($file in @('Nomad-Fixture.exe', 'SHA256SUMS', 'licenses.zip')) {
        [IO.File]::WriteAllText((Join-Path $fixtureRoot $file), 'inert fixture')
    }

    $failures = @(
        @{ Case = 'published'; Reason = 'already published'; Creates = 0; Uploads = 0 },
        @{ Case = 'lookup-failure'; Reason = 'lookup failed'; Creates = 0; Uploads = 0 },
        @{ Case = 'invalid-json'; Reason = 'invalid release JSON'; Creates = 0; Uploads = 0 },
        @{ Case = 'null-json'; Reason = 'Invalid paginated'; Creates = 0; Uploads = 0 },
        @{ Case = 'missing-draft-field'; Reason = 'invalid release metadata'; Creates = 0; Uploads = 0 },
        @{ Case = 'string-draft'; Reason = 'invalid release metadata'; Creates = 0; Uploads = 0 },
        @{ Case = 'missing-assets'; Reason = 'invalid release metadata'; Creates = 0; Uploads = 0 },
        @{ Case = 'populated-draft'; Reason = 'already contains assets'; Creates = 0; Uploads = 0 },
        @{ Case = 'published-before-upload'; Reason = 'already published'; Creates = 0; Uploads = 0 },
        @{ Case = 'assets-before-upload'; Reason = 'already contains assets'; Creates = 0; Uploads = 0 },
        @{ Case = 'wrong-release-id'; Reason = 'identity changed'; Creates = 0; Uploads = 0 },
        @{ Case = 'wrong-release-tag'; Reason = 'tag changed'; Creates = 0; Uploads = 0 },
        @{ Case = 'invalid-pages'; Reason = 'Invalid release page'; Creates = 0; Uploads = 0 },
        @{ Case = 'empty-pages'; Reason = 'Invalid paginated'; Creates = 0; Uploads = 0 },
        @{ Case = 'duplicate-tags'; Reason = 'More than one'; Creates = 0; Uploads = 0 },
        @{ Case = 'create-failure'; Reason = 'Draft creation failed'; Creates = 1; Uploads = 0 },
        @{ Case = 'lookup-after-create-failure'; Reason = 'lookup failed'; Creates = 1; Uploads = 0 },
        @{ Case = 'upload-failure'; Reason = 'Draft upload failed'; Creates = 0; Uploads = 1 }
    )
    foreach ($scenario in $failures) {
        Reset-Fixture $scenario.Case
        $failure = $null
        try { Invoke-Fixture } catch { $failure = $_.Exception.Message }
        if ($null -eq $failure -or -not $failure.Contains($scenario.Reason)) {
            throw "Wrong failure for $($scenario.Case): $failure"
        }
        Assert-PublishingCalls $scenario.Creates $scenario.Uploads
        $fixtureCount++
    }

    foreach ($case in @('absent', 'empty-draft', 'multiple-pages')) {
        Reset-Fixture $case
        Invoke-Fixture
        $creates = 0; if ($case -eq 'absent') { $creates = 1 }
        Assert-PublishingCalls $creates 1
        $fixtureCount++
    }
    foreach ($case in @('absent', 'empty-draft')) {
        Reset-Fixture $case
        Invoke-Fixture -CheckOnly
        Assert-PublishingCalls 0 0
        $fixtureCount++
    }

    Reset-Fixture 'published'
    $failure = $null
    try { Invoke-Fixture -CheckOnly } catch { $failure = $_.Exception.Message }
    if ($null -eq $failure -or -not $failure.Contains('already published')) { throw 'Early preflight accepted a published release.' }
    Assert-PublishingCalls 0 0
    $fixtureCount++

    # All local-artifact failures must occur before creating a GitHub draft.
    $sums = Join-Path $fixtureRoot 'SHA256SUMS'
    foreach ($fault in @('missing', 'empty', 'directory')) {
        Reset-Fixture 'absent'
        Remove-Item -LiteralPath $sums -Force
        if ($fault -eq 'empty') { [IO.File]::WriteAllText($sums, '') }
        if ($fault -eq 'directory') { New-Item -ItemType Directory -Path $sums | Out-Null }
        $failed = $false
        try { Invoke-Fixture } catch { $failed = $true }
        if (-not $failed) { throw "Publisher accepted $fault artifact." }
        Assert-PublishingCalls 0 0
        if ($fault -eq 'directory') { Remove-Item -LiteralPath $sums }
        [IO.File]::WriteAllText($sums, 'inert fixture')
        $fixtureCount++
    }

    Reset-Fixture 'absent'
    $launcher = Join-Path $fixtureRoot 'Nomad-Fixture.exe'
    Remove-Item -LiteralPath $launcher
    $failure = $null
    try { Invoke-Fixture } catch { $failure = $_.Exception.Message }
    if ($null -eq $failure -or -not $failure.Contains('No launcher artifacts')) { throw 'Empty launcher set was not rejected.' }
    Assert-PublishingCalls 0 0
    [IO.File]::WriteAllText($launcher, 'inert fixture')
    $fixtureCount++

    Reset-Fixture 'absent'
    $labeledRoot = Join-Path $fixtureRoot 'hash#label'
    New-Item -ItemType Directory -Path $labeledRoot | Out-Null
    foreach ($file in @('Nomad-Fixture.exe', 'SHA256SUMS', 'licenses.zip')) {
        Copy-Item -LiteralPath (Join-Path $fixtureRoot $file) -Destination (Join-Path $labeledRoot $file)
    }
    $failure = $null
    try { & $publisher -Tag $global:FixtureTag -Repository 'fixture/nomad' -ArtifactDirectory $labeledRoot 6>$null }
    catch { $failure = $_.Exception.Message }
    if ($null -eq $failure -or -not $failure.Contains('paths containing #')) { throw 'CLI label syntax in artifact paths was not rejected.' }
    Assert-PublishingCalls 0 0
    $fixtureCount++

    Reset-Fixture 'empty-draft'
    $global:FixtureTag = 'v9.0.0;$(Write-Error nope)'
    Invoke-Fixture
    Assert-PublishingCalls 0 1
    $fixtureCount++
    Write-Host "Release publishing regression fixtures passed ($fixtureCount cases)."
}
finally {
    $resolved = [IO.Path]::GetFullPath($fixtureRoot)
    $tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ((Split-Path -Parent $resolved) -cne $tempParent -or (Split-Path -Leaf $resolved) -notmatch '^nomad-release-test-[0-9a-f]{32}$') {
        throw 'Refusing cleanup outside the owned fixture directory.'
    }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
