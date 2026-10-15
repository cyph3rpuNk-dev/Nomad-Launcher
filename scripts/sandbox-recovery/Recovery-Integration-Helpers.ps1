# Functions only. Host regressions use authored metadata; no browser is started.
Set-StrictMode -Version Latest
function Assert-RIPlain([string]$Path) {
    $cursor=[IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Linked integration path refused.'}
        $parent=Split-Path -Parent $cursor
        if ($parent -eq $cursor) {break}
        $cursor=$parent
    }
}
function Read-RIBytesSnapshot([string]$Path,[long]$Limit=524288) {
    Assert-RIPlain $Path
    if ($Limit -lt 0 -or $Limit -gt 1048576) {throw 'Invalid snapshot limit.'}
    $stream=$null
    try {
        # Keep the writer open. Capture a bounded prefix through this one retained read handle.
        $share=[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
        $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
        $length=$stream.Length
        if ($length -gt $Limit) {throw 'Oversized snapshot preserved in place.'}
        $bytes=New-Object byte[] ([int]$length)
        $offset=0
        while ($offset -lt $bytes.Length) {
            $count=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if ($count -le 0) {throw 'Snapshot truncated while reading.'}
            $offset+=$count
        }
        if ($stream.Length -lt $length) {throw 'Snapshot source shrank.'}
        Assert-RIPlain $Path
        return ,$bytes
    } finally {if($null -ne $stream){$stream.Dispose()}}
}
function Get-RILogText([string]$Path) {
    $bytes=Read-RIBytesSnapshot $Path
    $encoding=New-Object Text.UTF8Encoding($false,$true)
    return $encoding.GetString($bytes)
}
function Copy-RIBoundedSnapshot([string]$Source,[string]$Destination) {
    $bytes=Read-RIBytesSnapshot $Source
    Assert-RIPlain $Destination
    $output=$null
    try {
        $output=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $output.Write($bytes,0,$bytes.Length);$output.Flush()
    } finally {if($null -ne $output){$output.Dispose()}}
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try {$hash=[BitConverter]::ToString($algorithm.ComputeHash($bytes)).Replace('-','')}finally{$algorithm.Dispose()}
    if ((Get-Item -LiteralPath $Destination).Length -ne $bytes.Length -or (Get-FileHash -LiteralPath $Destination).Hash -cne $hash) {throw 'Captured snapshot copy changed.'}
    return @{bytes=$bytes.Length;sha256=$hash;capture='bounded source prefix; not atomic/stable live-file history'}
}
function Read-RIJson([string]$Path,[long]$Limit=524288) {
    Assert-RIPlain $Path
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt $Limit) {throw 'Oversized/non-file integration JSON.'}
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}
function Assert-RIGuest([string]$InputRoot) {
    if ($env:USERNAME -cne 'WDAGUtilityAccount' -or $env:USERPROFILE -cne 'C:\Users\WDAGUtilityAccount' -or $InputRoot -cne 'C:\NomadInput') {throw 'Disposable Sandbox only; do not run on the host or spoof this guard.'}
}
function Start-RILauncher([string]$Launcher,[string]$InputRoot) {
    Assert-RIGuest $InputRoot
    if ($Launcher -cnotmatch '^C:\\NomadRecoveryIntegration\\[a-f0-9]{32}\\Instance\\Nomad-Helium\.exe$') {throw 'Unexpected guest launcher path.'}
    $previous=$env:NOMAD_LOG
    try {
        $env:NOMAD_LOG='info'
        Start-Process -FilePath $Launcher | Out-Null
    } finally {
        if ($null -eq $previous) {Remove-Item Env:\NOMAD_LOG -ErrorAction SilentlyContinue}
        else {$env:NOMAD_LOG=$previous}
    }
}
function Get-RIWatcherPid([string]$Text) {
    $events=[regex]::Matches($Text,'cleanup watcher spawned watcher_pid=([0-9]+)')
    if ($events.Count -ne 1) {throw "Expected exactly one INFO watcher spawn; observed $($events.Count). Export diagnostics; do not stop a guessed process."}
    $value=0
    if (-not [int]::TryParse($events[0].Groups[1].Value,[ref]$value) -or $value -le 0) {throw 'Invalid watcher PID in log.'}
    return $value
}
function Assert-RIWatcher($Metadata,[int]$ExpectedPid,[string]$Launcher,[string]$Image,[datetime]$StartTime) {
    if ($ExpectedPid -le 0 -or $Metadata.ProcessId -ne $ExpectedPid -or -not [string]::Equals($Metadata.ExecutablePath,$Launcher,[StringComparison]::OrdinalIgnoreCase)) {throw 'Watcher process/image mismatch.'}
    $pattern='^"?'+[regex]::Escape($Launcher)+'"?\s+--nomad-cleanup-pid\s+[1-9][0-9]*\s+--nomad-cleanup-exe\s+"?'+[regex]::Escape($Image)+'"?\s+--nomad-recover-cleanup\s*$'
    if ($Metadata.CommandLine -notmatch $pattern) {throw 'Unexpected watcher command; no process stopped.'}
    if ($null -eq $Metadata.CreationDate -or [Math]::Abs(($Metadata.CreationDate.ToUniversalTime()-$StartTime.ToUniversalTime()).TotalMilliseconds) -gt 50) {throw 'Watcher identity/start time changed.'}
}
function Get-RIBookmark([string]$Path) {
    $json=Read-RIJson $Path 1048576
    $queue=New-Object 'Collections.Generic.Queue[object]'
    foreach ($property in $json.roots.PSObject.Properties) {$queue.Enqueue($property.Value)}
    $found=@();$count=0
    while ($queue.Count -gt 0) {
        $node=$queue.Dequeue();$count++
        if ($count -gt 4096) {throw 'Bookmark traversal budget exceeded.'}
        if ($node.PSObject.Properties['type'] -and $node.type -ceq 'url' -and $node.PSObject.Properties['name'] -and $node.name -ceq 'Nomad recovery test') {
            if ($node.url -cnotin @('about:blank','https://example.com/')) {throw 'Use only the public test bookmark URL.'}
            $found+=@{name=$node.name;url=$node.url}
        }
        if ($node.PSObject.Properties['children']) {foreach ($child in $node.children) {$queue.Enqueue($child)}}
    }
    if ($found.Count -ne 1) {throw 'Create exactly one bookmark named Nomad recovery test.'}
    return $found[0].url
}
function Test-RIExport([string]$InputDirectory,[string]$OutputDirectory) {
    $build=Read-RIJson (Join-Path $InputDirectory 'BUILD-MANIFEST.json')
    $receipt=Read-RIJson (Join-Path $OutputDirectory 'GUEST-RECEIPT.json') 65536
    if ($receipt.schema -ne 1 -or $receipt.token -cnotmatch '^[a-f0-9]{32}$' -or $receipt.export_token -cnotmatch '^[a-f0-9]{32}$' -or (Split-Path -Leaf $OutputDirectory) -cne ('integration-'+$receipt.token+'-'+$receipt.export_token)) {throw 'Invalid integration export scope.'}
    if ($build.schema -ne 1 -or $build.target -cne 'x86_64-pc-windows-msvc' -or $build.base_commit -cnotmatch '^[a-f0-9]{40}$' -or $build.source_tree_sha256 -cnotmatch '^[A-F0-9]{64}$' -or $build.launcher_sha256 -cnotmatch '^[A-F0-9]{64}$') {throw 'Invalid integration build provenance.'}
    foreach ($key in @('base_commit','source_tree_sha256','launcher_sha256')) {if ($receipt.$key -cne $build.$key) {throw 'Integration provenance mismatch.'}}
    if ((Get-FileHash -LiteralPath (Join-Path $InputDirectory 'Nomad-Helium.exe')).Hash -cne $build.launcher_sha256) {throw 'Input launcher changed.'}
    $allowed=@('STATE.json','INTERRUPTED.json','CLOSED.json','RELAUNCH.json','nomad.log')
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    if (@($receipt.files).Count -ne 5) {throw 'Incomplete integration evidence.'}
    foreach ($entry in $receipt.files) {
        if ($entry.name -cnotin $allowed -or -not $seen.Add($entry.name) -or $entry.bytes -lt 0 -or $entry.bytes -gt 524288 -or $entry.sha256 -cnotmatch '^[A-F0-9]{64}$') {throw 'Invalid/duplicate evidence entry.'}
        $path=Join-Path $OutputDirectory $entry.name;Assert-RIPlain $path
        $item=Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or $item.Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.sha256) {throw 'Integration evidence hash mismatch.'}
    }
    $result=Read-RIJson (Join-Path $OutputDirectory 'RELAUNCH.json')
    foreach ($key in @('old_journals_retired','owned_shortcut_removed','owned_report_removed','foreign_fixtures_preserved','configuration_unchanged','installed_marker_unchanged','bookmark_preserved','browser_running','recovery_logged')) {
        if ($result.$key -isnot [bool] -or -not $result.$key) {throw "Integration assertion missing/false: $key"}
    }
    $interrupted=Read-RIJson (Join-Path $OutputDirectory 'INTERRUPTED.json')
    $closed=Read-RIJson (Join-Path $OutputDirectory 'CLOSED.json')
    if ($interrupted.watcher_stopped -isnot [bool] -or -not $interrupted.watcher_stopped -or $closed.browser_stopped -isnot [bool] -or -not $closed.browser_stopped -or $closed.intent_and_fixtures_preserved -isnot [bool] -or -not $closed.intent_and_fixtures_preserved) {throw 'Interrupted/closed stage not corroborated.'}
    $log=Get-Content -LiteralPath (Join-Path $OutputDirectory 'nomad.log') -Raw -Encoding UTF8
    if ($log -notmatch 'retired completed owned cleanup recovery records' -or $log -notmatch 'browser launched') {throw 'Production recovery log absent.'}
    [pscustomobject]@{hashes_verified=$true;files_verified=5;guest_reported_integration_pass=$true;scope='Mapped bytes and guest assertions; built-in uBlock needs user confirmation; no independent key/power-loss qualification'}
}
