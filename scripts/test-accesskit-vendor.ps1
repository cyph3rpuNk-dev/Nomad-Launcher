[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'accesskit-vendor.ps1')
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'vendor/accesskit_winit-0.32.2'
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('nomad-accesskit-test-' + [Guid]::NewGuid().ToString('N'))
$utf8 = [Text.UTF8Encoding]::new($false)
try {
    Assert-AccessKitVendorSnapshot -Root $source
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    $cases = @('source-drift', 'manifest-drift', 'license-drift', 'missing-file', 'missing-hash', 'extra-file', 'traversal')
    foreach ($case in $cases) {
        $fixture = Join-Path $fixtureRoot $case
        Copy-Item -LiteralPath $source -Destination $fixture -Recurse -Force
        $provenancePath = Join-Path $fixture 'provenance.json'
        switch ($case) {
            'source-drift' { [IO.File]::AppendAllText((Join-Path $fixture 'src/lib.rs'), "`n// unexpected change`n", $utf8) }
            'manifest-drift' { [IO.File]::AppendAllText((Join-Path $fixture 'Cargo.toml'), "`n# unexpected feature change`n", $utf8) }
            'license-drift' { [IO.File]::WriteAllText((Join-Path $fixture 'LICENSE-APACHE'), 'changed', $utf8) }
            'missing-file' { Remove-Item -LiteralPath (Join-Path $fixture 'src/platform_impl/windows.rs') }
            'missing-hash' {
                $provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
                $provenance.files.PSObject.Properties.Remove('src/platform_impl/windows.rs')
                [IO.File]::WriteAllText($provenancePath, ($provenance | ConvertTo-Json -Depth 5), $utf8)
            }
            'extra-file' { [IO.File]::WriteAllText((Join-Path $fixture 'src/extra.rs'), '// unexpected source', $utf8) }
            'traversal' {
                $provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
                $provenance.files | Add-Member -NotePropertyName '../outside' -NotePropertyValue ('0' * 64)
                [IO.File]::WriteAllText($provenancePath, ($provenance | ConvertTo-Json -Depth 5), $utf8)
            }
        }
        $rejected = $false
        try { Assert-AccessKitVendorSnapshot -Root $fixture } catch { $rejected = $true }
        if (-not $rejected) { throw "AccessKit snapshot unexpectedly accepted $case." }
    }
    Write-Host 'AccessKit snapshot checks passed (original accepted, 7 changed/incomplete snapshots rejected).'
}
finally {
    $resolved = [IO.Path]::GetFullPath($fixtureRoot)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolved) -notmatch '^nomad-accesskit-test-[a-f0-9]{32}$') {
        throw 'Unsafe AccessKit fixture cleanup target.'
    }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
