# Snapshot checks only. No package downloads, application launch or user settings.
function Assert-AccessKitVendorSnapshot {
    param([Parameter(Mandatory = $true)][string]$Root)

    $manifest = Get-Content -LiteralPath (Join-Path $Root 'provenance.json') -Raw | ConvertFrom-Json
    if ($manifest.version -cne '0.32.2' -or
        $manifest.archive_sha256 -cne '1fe9a94394896352cc4660ca2288bd4ef883d83238853c038b44070c8f134313') {
        throw 'Unexpected AccessKit upstream snapshot.'
    }
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $actual = @(Get-ChildItem -LiteralPath $rootPath -Recurse -File -Force | ForEach-Object {
        $_.FullName.Substring($rootPath.Length + 1).Replace('\', '/')
    } | Where-Object { $_ -cne 'provenance.json' -and $_ -cne 'NOMAD.md' } | Sort-Object)
    $recorded = @($manifest.files.PSObject.Properties.Name | Sort-Object)
    if ($actual.Count -eq 0 -or (Compare-Object $actual $recorded -CaseSensitive)) {
        throw 'Incomplete or unexpected AccessKit snapshot files.'
    }
    foreach ($entry in $manifest.files.PSObject.Properties) {
        if ($entry.Name -notmatch '^[A-Za-z0-9_./-]+$' -or
            $entry.Name -match '(^|/)\.\.(/|$)' -or $entry.Name.StartsWith('/') -or
            $entry.Value -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Invalid AccessKit snapshot hash entry.'
        }
        $path = Join-Path $rootPath $entry.Name
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -cne $entry.Value) { throw "AccessKit snapshot hash mismatch: $($entry.Name)" }
    }
}
