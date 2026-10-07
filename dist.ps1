#requires -Version 5.1
[CmdletBinding()]
param([string]$ArtifactDirectory = (Join-Path $PSScriptRoot 'target/release'))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$targetRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'target'))
$sourceDir=Join-Path $targetRoot 'x86_64-pc-windows-msvc/release'
if ($ArtifactDirectory -match '(^|[\\/])\.\.([\\/]|$)' -or $ArtifactDirectory -match '^[A-Za-z]:[^\\/]') {throw 'ArtifactDirectory must not use parent or drive-relative paths.'}
if (-not [IO.Path]::IsPathRooted($ArtifactDirectory)) {$ArtifactDirectory=Join-Path $PSScriptRoot $ArtifactDirectory}
$artifactDir=[IO.Path]::GetFullPath($ArtifactDirectory)
$programFilesX86=[Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
$expectedNames=@('Nomad-Bitwarden.exe','Nomad-Chromium.exe','Nomad-Firefox.exe','Nomad-Firefox-ESR.exe','Nomad-Floorp.exe','Nomad-Helium.exe','Nomad-LibreWolf.exe','Nomad-Mullvad.exe','Nomad-Waterfox.exe')
function Assert-OrdinaryPath([string]$Path) {
    $cursor=[IO.Path]::GetFullPath($Path)
    while ($cursor) {
        try {
            $attributes=[IO.File]::GetAttributes($cursor)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'Distribution paths must not contain links or reparse points.'}
        } catch [IO.FileNotFoundException] {} catch [IO.DirectoryNotFoundException] {}
        $parent=[IO.Path]::GetDirectoryName($cursor); if ($parent -eq $cursor) {break}; $cursor=$parent
    }
}
function Assert-File([string]$Path) {
    Assert-OrdinaryPath $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Get-Item -LiteralPath $Path).Length -eq 0) {throw "Required nonempty distribution input/artifact missing: $Path"}
}
function Resolve-Tool([string]$Override,[string]$Name,[string[]]$Fallbacks) {
    if ($Override) {Assert-File $Override; return Get-Command -Name $Override -ErrorAction Stop}
    $command=Get-Command -Name $Name -ErrorAction SilentlyContinue
    if ($command) {return $command}
    foreach ($candidate in $Fallbacks) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {Assert-File $candidate; return Get-Command -Name $candidate -ErrorAction Stop}
    }
    throw "Requested signing tool unavailable: $Name"
}
function Clear-Manifests([string]$Directory) {
    foreach ($name in @('SHA256SUMS','SHA256SUMS.asc')) {
        $path=Join-Path $Directory $name; Assert-OrdinaryPath $path
        if (Test-Path -LiteralPath $path) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {throw 'Distribution manifest path is not a file.'}
            Remove-Item -LiteralPath $path -Force
        }
    }
}
function Assert-LauncherSet([string]$Directory) {
    Assert-OrdinaryPath $Directory
    foreach ($name in $expectedNames) {Assert-File (Join-Path $Directory $name)}
    foreach ($file in @(Get-ChildItem -LiteralPath $Directory -Filter 'Nomad-*.exe')) {
        if ($expectedNames -cnotcontains $file.Name) {throw 'Unexpected launcher artifact; review stale build outputs.'}
    }
}
# Validate every prerequisite before building, signing or invalidating manifests.
if (-not $artifactDir.StartsWith($targetRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'ArtifactDirectory must be inside this checkout target directory.'}
foreach ($path in @($targetRoot,$sourceDir,$artifactDir)) {Assert-OrdinaryPath $path}
foreach ($directory in @($sourceDir,$artifactDir)) {
    foreach ($name in $expectedNames) {
        $output=Join-Path $directory $name; Assert-OrdinaryPath $output
        if (Test-Path -LiteralPath $output -PathType Container) {throw 'Launcher output path is not a file.'}
    }
}
Assert-File (Join-Path $PSScriptRoot 'Cargo.lock')
$licenses=@(
    @{Source='LICENSE-MIT'; Destination='Nomad-LICENSE-MIT.txt'},
    @{Source='core/payloads/fonts/OFL.txt'; Destination='AtkinsonHyperlegible-OFL.txt'},
    @{Source='core/payloads/7zip/LICENSE.txt'; Destination='7-Zip-LICENSE.txt'},
    @{Source='core/payloads/chromium/logos/LICENSE'; Destination='Chromium-logo-LICENSE.txt'}
)
foreach ($entry in $licenses) {Assert-File (Join-Path $PSScriptRoot $entry.Source)}
Assert-File (Join-Path $PSScriptRoot 'TRADEMARKS.md')
if ($env:NOMAD_SIGN_PASS) {throw 'NOMAD_SIGN_PASS is unsupported: use certificate-store signing by thumbprint; passwords must not enter child processes.'}
$cert=$env:NOMAD_SIGN_CERT; $key=$env:NOMAD_SIGNING_KEY
$signtool=$null; $gpg=$null; $certArgs=@(); $timestamp='http://timestamp.digicert.com'
if ($cert) {
    if ($cert -match '^[0-9a-fA-F]{40}$') {$certArgs=@('/sha1',$cert)}
    else {Assert-File $cert; $certArgs=@('/f',[IO.Path]::GetFullPath($cert))}
    $candidates=@()
    if (-not $env:NOMAD_SIGNTOOL -and -not (Get-Command signtool -ErrorAction SilentlyContinue) -and $programFilesX86) {
        $sdk=Join-Path $programFilesX86 'Windows Kits/10/bin'
        if (Test-Path -LiteralPath $sdk) {$candidates=@(Get-ChildItem -LiteralPath $sdk -Recurse -Filter signtool.exe | Where-Object {$_.FullName -match '\\x64\\'} | Sort-Object FullName -Descending | ForEach-Object {$_.FullName})}
    }
    $signtool=Resolve-Tool $env:NOMAD_SIGNTOOL 'signtool' $candidates
    if ($env:NOMAD_SIGN_TS) {$timestamp=$env:NOMAD_SIGN_TS}
    $uri=$null
    if (-not [Uri]::TryCreate($timestamp,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -notin @('http','https') -or $uri.UserInfo) {throw 'Invalid signing timestamp URL.'}
}
if ($key) {$gpg=Resolve-Tool $env:NOMAD_GPG 'gpg' @("$env:ProgramFiles/GnuPG/bin/gpg.exe","$programFilesX86/GnuPG/bin/gpg.exe","$env:ProgramFiles/Git/usr/bin/gpg.exe")}
$stage=$null; $ownedStage=$false; $success=$false; $buildStarted=$false; $buildLock=$null
Push-Location -LiteralPath $PSScriptRoot
try {
    New-Item -ItemType Directory -Path $targetRoot -Force | Out-Null
    $lockPath=Join-Path $targetRoot '.nomad-dist.lock'; Assert-OrdinaryPath $lockPath
    $buildLock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
    Clear-Manifests $artifactDir
    if ($sourceDir -ne $artifactDir) {Clear-Manifests $sourceDir}
    $buildStarted=$true
    Write-Host 'Building locked Windows x64 release binaries...'
    cargo build --release --workspace --locked --target x86_64-pc-windows-msvc --target-dir $targetRoot
    if ($LASTEXITCODE -ne 0) {throw 'Release build failed; distribution incomplete.'}
    Assert-LauncherSet $sourceDir
    $stage=Join-Path $targetRoot ('.nomad-dist-'+[Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage | Out-Null; $ownedStage=$true
    foreach ($name in $expectedNames) {Copy-Item -LiteralPath (Join-Path $sourceDir $name) -Destination (Join-Path $stage $name)}
    if ($cert) {
        foreach ($name in $expectedNames) {
            $file=Join-Path $stage $name
            & $signtool sign @certArgs /fd SHA256 /tr $timestamp /td SHA256 /d 'Nomad Launcher' $file
            if ($LASTEXITCODE -ne 0) {throw 'Requested Authenticode signing failed.'}
            & $signtool verify /pa /all $file
            if ($LASTEXITCODE -ne 0) {throw 'Requested Authenticode signature verification failed.'}
        }
    } else {Write-Warning 'Authenticode signing not requested.'}
    $licenseDir=Join-Path $stage 'licenses'; New-Item -ItemType Directory -Path $licenseDir | Out-Null
    foreach ($entry in $licenses) {
        $source=Join-Path $PSScriptRoot $entry.Source; Assert-File $source
        Copy-Item -LiteralPath $source -Destination (Join-Path $licenseDir $entry.Destination)
    }
$notices = @'
Nomad Launcher - Third-Party Notices
====================================

Nomad Launcher itself is licensed under the MIT License
(licenses/Nomad-LICENSE-MIT.txt).

Components bundled INSIDE the Nomad launcher binaries
-----------------------------------------------------
* Atkinson Hyperlegible font - SIL Open Font License 1.1
  -> licenses/AtkinsonHyperlegible-OFL.txt
* 7-Zip 24.09 (7z.exe + 7z.dll, distributed unmodified) - GNU LGPL-2.1
  -> licenses/7-Zip-LICENSE.txt    Source: https://www.7-zip.org/
* Chromium reference logos (used for compatibility checks) - BSD-3-Clause
  -> licenses/Chromium-logo-LICENSE.txt    Source: https://chromium.googlesource.com/chromium/src/

Software Nomad downloads at RUNTIME (NOT bundled in these binaries)
------------------------------------------------------------------
The browsers and apps Nomad launches (Firefox, Firefox ESR,
Mullvad Browser, Ungoogled Chromium, Helium, Floorp, Waterfox, LibreWolf,
Bitwarden) are fetched from their official sources at launch and remain under
their own licenses and trademarks. Nomad is an independent project and is not
affiliated with, endorsed by, or sponsored by any of them. See TRADEMARKS.md.
'@
    [IO.File]::WriteAllText((Join-Path $stage 'THIRD-PARTY-NOTICES.txt'),$notices,[Text.Encoding]::ASCII)
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'TRADEMARKS.md') -Destination (Join-Path $stage 'TRADEMARKS.md')
    $sums=Join-Path $stage 'SHA256SUMS'
    $lines=foreach ($name in $expectedNames) {
        $hash=(Get-FileHash -LiteralPath (Join-Path $stage $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    [IO.File]::WriteAllText($sums,($lines -join [char]10)+[char]10,[Text.Encoding]::ASCII)
    $signature="$sums.asc"
    if ($key) {
        & $gpg --batch --yes "--local-user=$key" --armor --detach-sign --output $signature -- $sums
        if ($LASTEXITCODE -ne 0) {throw 'Requested manifest signing failed.'}
        Assert-File $signature
        & $gpg --batch --verify $signature $sums
        if ($LASTEXITCODE -ne 0) {throw 'Requested manifest signature verification failed.'}
    } else {Write-Warning 'Manifest signing not requested; this is not a published signed release.'}
    # Promote only validated files; manifests are final completion artifacts.
    foreach ($name in $expectedNames) {
        $dest=Join-Path $artifactDir $name; Assert-OrdinaryPath $dest
        if (Test-Path -LiteralPath $dest -PathType Container) {throw 'Launcher destination is a directory.'}
        Copy-Item -LiteralPath (Join-Path $stage $name) -Destination $dest -Force
    }
    $finalLicenses=Join-Path $artifactDir 'licenses'; Assert-OrdinaryPath $finalLicenses
    New-Item -ItemType Directory -Path $finalLicenses -Force | Out-Null
    foreach ($entry in $licenses) {
        $dest=Join-Path $finalLicenses $entry.Destination; Assert-OrdinaryPath $dest
        Copy-Item -LiteralPath (Join-Path $licenseDir $entry.Destination) -Destination $dest -Force
    }
    foreach ($name in @('THIRD-PARTY-NOTICES.txt','TRADEMARKS.md')) {
        $dest=Join-Path $artifactDir $name; Assert-OrdinaryPath $dest
        Copy-Item -LiteralPath (Join-Path $stage $name) -Destination $dest -Force
    }
    Assert-LauncherSet $artifactDir
    foreach ($line in $lines) {
        $expectedHash,$name=$line -split '  ',2
        if ((Get-FileHash -LiteralPath (Join-Path $artifactDir $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash) {throw 'Promoted launcher bytes do not match the staged manifest.'}
    }
    Move-Item -LiteralPath $sums -Destination (Join-Path $artifactDir 'SHA256SUMS')
    if ($key) {Move-Item -LiteralPath $signature -Destination (Join-Path $artifactDir 'SHA256SUMS.asc')}
    $success=$true
    Write-Host "Distribution complete: $($expectedNames.Count) launchers in $artifactDir"
}
finally {
    try {
        if ($buildStarted -and -not $success) {Clear-Manifests $artifactDir}
        if ($ownedStage) {
            $resolved=[IO.Path]::GetFullPath($stage)
            if ((Split-Path -Parent $resolved) -cne $targetRoot -or (Split-Path -Leaf $resolved) -notmatch '^\.nomad-dist-[0-9a-f]{32}$') {throw 'Refusing unowned stage cleanup.'}
            Assert-OrdinaryPath $resolved
            Get-ChildItem -LiteralPath $resolved -Recurse -Force | ForEach-Object {Assert-OrdinaryPath $_.FullName}
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    } finally {if ($buildLock) {$buildLock.Dispose()}; Pop-Location}
}
