[CmdletBinding()]
param([switch]$Baseline)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repoRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'artifact-fixtures.ps1')
$fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('nomad-dist-test-'+[Guid]::NewGuid().ToString('N'))
$global:BuildCalls=[Collections.Generic.List[object]]::new()
$names=@('Nomad-Chromium.exe','Nomad-Floorp.exe','Nomad-Helium.exe','Nomad-LibreWolf.exe','Nomad-Mullvad.exe','Nomad-Waterfox.exe')
$global:FixtureLock=$null
$global:FixtureLink=$null
$inputs=@('LICENSE-MIT','core/payloads/fonts/OFL.txt','core/payloads/7zip/LICENSE.txt','core/payloads/chromium/logos/LICENSE','TRADEMARKS.md')
function global:cargo {
    $global:BuildCalls.Add(@('cargo')+@($args)); $global:LASTEXITCODE=0
    if ($global:BuildCase -eq 'cargo-failure') {$global:LASTEXITCODE=1; return}
    foreach ($dir in @('target/release','target/x86_64-pc-windows-msvc/release')) {
        $output=Join-Path $global:BuildRoot $dir; New-Item -ItemType Directory -Path $output -Force | Out-Null
        foreach ($name in $global:BuildNames) {
            if ($global:BuildCase -eq 'missing-launcher' -and $name -eq 'Nomad-Waterfox.exe') {continue}
                        $bytes=New-LauncherPEFixture
            if ($name -eq 'Nomad-Floorp.exe') {
                if ($global:BuildCase -eq 'external-runtime') {$bytes=New-LauncherPEFixture 'VCRUNTIME140.dll'}
                if ($global:BuildCase -eq 'missing-cfg') {Set-FixtureU16 $bytes 0xde 0}
                if ($global:BuildCase -eq 'unsafe-dll-search') {Set-FixtureU16 $bytes 0x74e 0x1000}
                if ($global:BuildCase -eq 'malformed-pe') {$bytes=New-Object byte[] 512}
            }
            [IO.File]::WriteAllBytes((Join-Path $output $name),$bytes)
        }
        if ($global:BuildCase -eq 'extra-launcher') {[IO.File]::WriteAllText((Join-Path $output 'Nomad-Stale.exe'),'stale')}
        if ($global:BuildCase -eq 'retired-firefox') {[IO.File]::WriteAllBytes((Join-Path $output 'Nomad-Firefox.exe'),(New-LauncherPEFixture))}
        if ($global:BuildCase -eq 'retired-firefox-esr') {[IO.File]::WriteAllBytes((Join-Path $output 'Nomad-Firefox-ESR.exe'),(New-LauncherPEFixture))}
        if ($global:BuildCase -eq 'retired-bitwarden') {[IO.File]::WriteAllBytes((Join-Path $output 'Nomad-Bitwarden.exe'),(New-LauncherPEFixture))}
        if ($global:BuildCase -eq 'empty-launcher') {[IO.File]::WriteAllText((Join-Path $output 'Nomad-Waterfox.exe'),'')}
    }
}
function global:Copy-Item {
    [CmdletBinding()]
    param([string]$LiteralPath,[string]$Destination,[switch]$Force)
    $promotion=$LiteralPath -match '[\\/]\.nomad-dist-[^\\/]+[\\/]Nomad-.*\.exe$' -and $Destination.StartsWith((Join-Path $global:BuildRoot 'target/release'))
    if ($promotion -and $global:BuildCase -eq 'promotion-failure') {throw 'Mocked promotion failure.'}
    Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination -Force:$Force
    if ($promotion -and $global:BuildCase -eq 'promotion-corruption') {[IO.File]::WriteAllText($Destination,'corrupted')}
}
function global:signtool {
    $global:BuildCalls.Add(@('signtool')+@($args)); $global:LASTEXITCODE=0
    if ($args -contains '/p' -or $args -contains 'fixture-password') {throw 'Password reached a command.'}
    if (($global:BuildCase -eq 'auth-failure' -and $args[0] -eq 'sign') -or ($global:BuildCase -eq 'auth-verify-failure' -and $args[0] -eq 'verify')) {$global:LASTEXITCODE=1; return}
    if ($args[0] -eq 'sign') {[IO.File]::AppendAllText($args[-1],'-signed')}
}
function global:gpg {
    $global:BuildCalls.Add(@('gpg')+@($args)); $global:LASTEXITCODE=0
    if ($global:BuildCase -eq 'gpg-failure' -or ($global:BuildCase -eq 'gpg-verify-failure' -and $args -contains '--verify')) {$global:LASTEXITCODE=1; return}
    if ($args -contains '--detach-sign' -and $global:BuildCase -ne 'gpg-no-output') {
        $index=[Array]::IndexOf(@($args),'--output'); [IO.File]::WriteAllText($args[$index+1],'inert signature')
    }
}
function New-Fixture([string]$Case) {
    $global:BuildCase=$Case; $global:BuildRoot=Join-Path $fixtureRoot $Case; $global:BuildCalls.Clear(); $global:BuildNames=$names
    foreach ($name in @('NOMAD_SIGN_CERT','NOMAD_SIGN_PASS','NOMAD_SIGNTOOL','NOMAD_SIGN_TS','NOMAD_SIGNING_KEY','NOMAD_GPG')) {[Environment]::SetEnvironmentVariable($name,$null,'Process')}
    New-Item -ItemType Directory -Path $global:BuildRoot | Out-Null
    Copy-Item -LiteralPath (Join-Path $repoRoot 'dist.ps1') -Destination (Join-Path $global:BuildRoot 'dist.ps1')
    foreach ($relativePath in @($inputs)+@('Cargo.lock')) {
        $path=Join-Path $global:BuildRoot $relativePath; New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
        [IO.File]::WriteAllText($path,'inert required input')
    }
    $guardPath=Join-Path $global:BuildRoot 'scripts/artifact-guard.ps1'
    New-Item -ItemType Directory -Path (Split-Path -Parent $guardPath) -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'artifact-guard.ps1') -Destination $guardPath
    $configPath=Join-Path $global:BuildRoot '.cargo/config.toml'
    New-Item -ItemType Directory -Path (Split-Path -Parent $configPath) -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $repoRoot '.cargo/config.toml') -Destination $configPath
    if ($Case -eq 'missing-guard') {Remove-Item -LiteralPath $guardPath}
    if ($Case -eq 'missing-config') {Remove-Item -LiteralPath $configPath}
    if ($Case -eq 'missing-license') {Remove-Item -LiteralPath (Join-Path $global:BuildRoot $inputs[0])}
    if ($Case -eq 'empty-license') {[IO.File]::WriteAllText((Join-Path $global:BuildRoot $inputs[0]),'')}
    if ($Case -eq 'directory-license') {Remove-Item -LiteralPath (Join-Path $global:BuildRoot $inputs[0]); New-Item -ItemType Directory -Path (Join-Path $global:BuildRoot $inputs[0]) | Out-Null}
    if ($Case -eq 'missing-lock') {Remove-Item -LiteralPath (Join-Path $global:BuildRoot 'Cargo.lock')}
    if ($Case -like 'auth-*') {$env:NOMAD_SIGN_CERT='a'*40}
    if ($Case -eq 'auth-missing-tool') {$env:NOMAD_SIGNTOOL=Join-Path $global:BuildRoot 'absent-tool.exe'}
    if ($Case -like 'gpg-*') {$env:NOMAD_SIGNING_KEY='b'*40}
    if ($Case -eq 'gpg-missing-tool') {$env:NOMAD_GPG=Join-Path $global:BuildRoot 'absent-gpg.exe'}
    if ($Case -eq 'auth-bad-timestamp') {$env:NOMAD_SIGN_TS='file:///fixture'}
    if ($Case -eq 'auth-bad-certificate') {$env:NOMAD_SIGN_CERT=Join-Path $global:BuildRoot 'absent.pfx'}
    if ($Case -eq 'password') {$env:NOMAD_SIGN_CERT='fixture.pfx'; $env:NOMAD_SIGN_PASS='fixture-password'}
    if ($Case -eq 'signed-success') {$env:NOMAD_SIGN_CERT='a'*40; $env:NOMAD_SIGNING_KEY='b'*40}
    $output=Join-Path $global:BuildRoot 'target/release'; New-Item -ItemType Directory -Path $output -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $output 'SHA256SUMS'),'old manifest'); [IO.File]::WriteAllText((Join-Path $output 'SHA256SUMS.asc'),'old signature')
    if ($Case -eq 'build-busy') {$global:FixtureLock=[IO.File]::Open((Join-Path $global:BuildRoot 'target/.nomad-dist.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
    if ($Case -eq 'directory-output') {New-Item -ItemType Directory -Path (Join-Path $output 'Nomad-Waterfox.exe') | Out-Null}
    if ($Case -in @('linked-output','linked-launcher')) {
        $foreign=Join-Path $global:BuildRoot 'foreign'; New-Item -ItemType Directory -Path $foreign | Out-Null
        [IO.File]::WriteAllText((Join-Path $foreign 'sentinel'),'foreign fixture')
        if (-not $output.StartsWith($global:BuildRoot+[IO.Path]::DirectorySeparatorChar)) {throw 'Unsafe link fixture path.'}
        $link=$output
        if ($Case -eq 'linked-output') {Remove-Item -LiteralPath $output -Recurse -Force}
        else {$link=Join-Path $output 'Nomad-Waterfox.exe'}
        $global:FixtureLink=$link
        if (($link+$foreign) -notmatch '^[A-Za-z0-9\\/:. _~-]+$') {throw 'Unsafe link fixture characters.'}
        $proc=Start-Process -FilePath $env:ComSpec -ArgumentList ('/d /c mklink /J "'+$link+'" "'+$foreign+'"') -Wait -PassThru -WindowStyle Hidden
        if ($proc.ExitCode -ne 0) {throw 'Fixture junction creation failed.'}
    }
    return $output
}
$cases=@('missing-guard','missing-config','missing-license','empty-license','directory-license','missing-lock','missing-launcher','empty-launcher','extra-launcher','external-runtime','missing-cfg','unsafe-dll-search','malformed-pe','cargo-failure','auth-missing-tool','auth-failure','auth-verify-failure','gpg-missing-tool','gpg-failure','gpg-no-output','gpg-verify-failure','password','auth-bad-timestamp','auth-bad-certificate','promotion-failure','promotion-corruption','build-busy','linked-output','outside-output','directory-output','linked-launcher')
$cases+=@('retired-firefox','retired-firefox-esr','retired-bitwarden')
if ($Baseline) {$cases=@('missing-license')}
try {
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    foreach ($case in $cases) {
        $output=New-Fixture $case; $failure=$null
        try {
            if ($case -eq 'outside-output') {& (Join-Path $global:BuildRoot 'dist.ps1') -ArtifactDirectory (Join-Path $global:BuildRoot 'outside') 6>$null 3>$null}
            else {& (Join-Path $global:BuildRoot 'dist.ps1') 6>$null 3>$null}
        } catch {$failure=$_.Exception.Message}
        finally {if ($global:FixtureLock) {$global:FixtureLock.Dispose(); $global:FixtureLock=$null}}
        if ($null -eq $failure) {throw "Accepted unsafe distribution case: $case"}
        if ($failure.Contains('fixture-password')) {throw 'Password printed in error.'}
        $preflight=$case -in @('missing-guard','missing-config','missing-license','empty-license','directory-license','missing-lock','auth-missing-tool','gpg-missing-tool','password','auth-bad-timestamp','auth-bad-certificate','build-busy','linked-output','outside-output','directory-output','linked-launcher')
        if ($preflight -and $global:BuildCalls.Count -ne 0) {throw "Prerequisite failure started dependent work: $case"}
        if (-not $preflight -and (Test-Path -LiteralPath (Join-Path $output 'SHA256SUMS'))) {throw "Failed build retained a publishable manifest: $case"}
        if ($case -in @('external-runtime','missing-cfg','unsafe-dll-search','malformed-pe') -and @($global:BuildCalls | Where-Object {$_[0] -in @('signtool','gpg')}).Count -ne 0) {throw 'Unsafe PE reached a signer.'}
        if ($case -in @('linked-output','linked-launcher')) {
            $sentinel=Join-Path $global:BuildRoot 'foreign/sentinel'
            if ([IO.File]::ReadAllText($sentinel) -cne 'foreign fixture') {throw 'Linked target was changed.'}
            if (([IO.File]::GetAttributes($global:FixtureLink) -band [IO.FileAttributes]::ReparsePoint) -eq 0) {throw 'Expected owned fixture junction.'}
            [IO.Directory]::Delete($global:FixtureLink)
        }
        if (@(Get-ChildItem -LiteralPath (Join-Path $global:BuildRoot 'target') -Directory -Filter '.nomad-dist-*').Count -ne 0) {throw 'Owned staging leaked.'}
    }
    foreach ($case in @('unsigned-success','signed-success')) {
        $output=New-Fixture $case; & (Join-Path $global:BuildRoot 'dist.ps1') 6>$null 3>$null
        $cargoCalls=@($global:BuildCalls | Where-Object {$_[0] -eq 'cargo'})
        if ($cargoCalls.Count -ne 1 -or -not ($cargoCalls[0] -contains '--locked')) {throw 'Build must use locked dependencies.'}
        $sums=[IO.File]::ReadAllText((Join-Path $output 'SHA256SUMS'))
        if ($sums.Contains([char]13) -or @($sums.TrimEnd([char]10).Split([char]10)).Count -ne $names.Count) {throw 'Wrong manifest format/set.'}
        foreach ($line in $sums.TrimEnd([char]10).Split([char]10)) {
            $hash,$name=$line -split '  ',2
            if ($names -cnotcontains $name -or (Get-FileHash -LiteralPath (Join-Path $output $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash) {throw 'Manifest misses final bytes.'}
        }
        foreach ($file in @('licenses/Nomad-LICENSE-MIT.txt','licenses/AtkinsonHyperlegible-OFL.txt','licenses/7-Zip-LICENSE.txt','licenses/Chromium-logo-LICENSE.txt','THIRD-PARTY-NOTICES.txt','TRADEMARKS.md')) {
            if (-not (Test-Path -LiteralPath (Join-Path $output $file) -PathType Leaf)) {throw 'License bundle incomplete.'}
        }
        if ((Test-Path -LiteralPath (Join-Path $output 'SHA256SUMS.asc')) -ne ($case -eq 'signed-success')) {throw 'Wrong signature state.'}
        if ($case -eq 'signed-success') {
            if (@($global:BuildCalls | Where-Object {$_[0] -eq 'signtool' -and $_[1] -eq 'sign'}).Count -ne $names.Count -or @($global:BuildCalls | Where-Object {$_[0] -eq 'signtool' -and $_[1] -eq 'verify'}).Count -ne $names.Count) {throw 'All requested signatures must be verified.'}
            if (@($global:BuildCalls | Where-Object {$_[0] -eq 'gpg' -and $_ -contains '--verify'}).Count -ne 1) {throw 'Manifest signature must be verified.'}
        }
    }
    Write-Host "Build safeguard fixtures passed ($($cases.Count+2) cases)."; $global:LASTEXITCODE=0
}
finally {
    $resolved=[IO.Path]::GetFullPath($fixtureRoot); $parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ((Split-Path -Parent $resolved) -cne $parent -or (Split-Path -Leaf $resolved) -notmatch '^nomad-dist-test-[0-9a-f]{32}$') {throw 'Refusing unowned cleanup.'}
    if (Test-Path -LiteralPath $resolved) {Remove-Item -LiteralPath $resolved -Recurse -Force}
}
