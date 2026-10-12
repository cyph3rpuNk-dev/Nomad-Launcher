# Fresh process; inert metadata only. No installers, browsers or registry writes.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'artifact-guard.ps1')
. (Join-Path $PSScriptRoot 'artifact-fixtures.ps1')
$root=Join-Path ([IO.Path]::GetTempPath()) ('nomad-pe-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $path=Join-Path $root 'inert.bin'
    foreach ($bytes in @((New-LauncherPEFixture), (New-LauncherPEFixture 'opengl32.dll'), (New-LauncherPEFixture 'api-ms-win-core-synch-l1-2-0.dll' 'user32.dll'))) {
        [IO.File]::WriteAllBytes($path,$bytes); Assert-NomadArtifact $path
    }
    $mutations=@(
        { New-LauncherPEFixture 'VCRUNTIME140.dll' },
        { New-LauncherPEFixture 'kernel32.dll' 'VCRUNTIME140_1.dll' },
        { New-LauncherPEFixture 'dxcompiler.dll' },
        { New-LauncherPEFixture '../kernel32.dll' },
        { $b=New-LauncherPEFixture; Set-FixtureU32 $b 0x3c ([uint32]::MaxValue); return ,$b },
        { $b=New-LauncherPEFixture; Set-FixtureU16 $b 0x84 0x14c; return ,$b },
        { $b=New-LauncherPEFixture; Set-FixtureU16 $b 0xdc 3; return ,$b },
        { $b=New-LauncherPEFixture; Set-FixtureU16 $b 0xde 0; return ,$b },
        { $b=New-LauncherPEFixture; Set-FixtureU16 $b 0x74e 0x1000; return ,$b },
        { $b=New-LauncherPEFixture; Set-FixtureU32 $b 0x790 0x100; return ,$b },
        { $b=New-LauncherPEFixture; Set-FixtureU32 $b 0x700 64; return ,$b },
        { $b=New-LauncherPEFixture; Set-FixtureU32 $b 0x110 0x3000; return ,$b },
        { $b=New-LauncherPEFixture; Set-FixtureU32 $b 0x320 1; return ,$b },
        { $b=New-LauncherPEFixture; for($i=0x500;$i -lt 0x604;$i++) {$b[$i]=65}; return ,$b },
        { $b=New-LauncherPEFixture 'kernel32.dll' 'user32.dll'; Set-FixtureU32 $b 0x600 0; return ,$b },
        { $b=New-LauncherPEFixture; Set-FixtureU64 $b 0x780 0; return ,$b },
        { $b=New-LauncherPEFixture; Set-FixtureU16 $b 0x94 96; return ,$b },
        { return ,(New-Object byte[] 128) }
    )
    foreach($mutation in $mutations) {
        [IO.File]::WriteAllBytes($path,(& $mutation)); $failed=$false
        try { Assert-NomadArtifact $path } catch {$failed=$true}
        if(-not $failed) {throw 'Accepted unsafe/malformed PE fixture.'}
    }
    [IO.File]::WriteAllBytes($path,(New-LauncherPEFixture))
    [IO.File]::AppendAllText($path,'inert signature overlay')
    Assert-NomadArtifact $path
    Write-Host "Artifact guard fixtures passed (4 accepted, $($mutations.Count) rejected)."
} finally {
    $resolved=[IO.Path]::GetFullPath($root)
    $parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if((Split-Path -Parent $resolved) -cne $parent -or (Split-Path -Leaf $resolved) -notmatch '^nomad-pe-test-[0-9a-f]{32}$') {throw 'Refusing unowned fixture cleanup.'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
