[CmdletBinding()]
param([ValidateSet('Fresh','Interrupt','Relaunch','Status','Export')][string]$Phase='Fresh')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:USERNAME -cne 'WDAGUtilityAccount' -or $env:USERPROFILE -cne 'C:\Users\WDAGUtilityAccount' -or $PSScriptRoot -cne 'C:\NomadInput') {throw 'Run only inside this disposable Sandbox. No host actions.'}
. (Join-Path $PSScriptRoot 'Recovery-Integration-Helpers.ps1')
Assert-RIGuest $PSScriptRoot
$utf8=New-Object Text.UTF8Encoding($false)
$manifest=Read-RIJson (Join-Path $PSScriptRoot 'BUILD-MANIFEST.json')
$seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach ($entry in $manifest.input_files) {
    if ($entry.name -cnotin @('Nomad-Helium.exe','Run-Recovery-Integration.ps1','Recovery-Integration-Helpers.ps1') -or -not $seen.Add($entry.name)) {throw 'Unexpected/duplicate input.'}
    $path=Join-Path $PSScriptRoot $entry.name;Assert-RIPlain $path
    if ((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.sha256) {throw 'Input bytes changed.'}
}
if ($seen.Count -ne 3 -or $manifest.schema -ne 1 -or $manifest.target -cne 'x86_64-pc-windows-msvc') {throw 'Incomplete input manifest.'}
$homeRoot='C:\NomadRecoveryIntegration';$statePath=Join-Path $homeRoot 'STATE.json'
Assert-RIPlain $homeRoot
function Save-RI([string]$Path,$Value,[switch]$New) {
    Assert-RIPlain $Path
    if ($New -and (Test-Path -LiteralPath $Path)) {throw 'Existing stage preserved; do not repeat this mutation.'}
    [IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 10),$utf8)
}
function Get-RIBrowsers {
    $matches=@()
    foreach ($process in @(Get-Process -Name chrome -ErrorAction SilentlyContinue)) {
        try {$path=$process.Path} catch {throw 'Cannot establish browser identity; preserve everything.'}
        if (-not $path) {throw 'Browser identity unavailable.'}
        if (-not [string]::Equals($path,$image,[StringComparison]::OrdinalIgnoreCase)) {throw 'Another chrome.exe context is present; preserve everything.'}
        $matches+=$process.Id
    }
    return $matches
}
function Get-RIJournals {
    $dir=Join-Path $instance 'Nomad\cleanup-pending';Assert-RIPlain $dir
    $records=@()
    if (-not (Test-Path -LiteralPath $dir)) {return $records}
    foreach ($item in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)) {
        Assert-RIPlain $item.FullName
        if ($item.PSIsContainer -or $item.Name -cnotmatch '^pending-[a-f0-9]{16}\.bin$' -or $item.Length -gt 65536) {throw 'Unexpected journal entry.'}
        $records+=@{name=$item.Name;sha256=(Get-FileHash -LiteralPath $item.FullName).Hash}
    }
    if ($records.Count -gt 32) {throw 'Journal bound exceeded.'}
    return $records
}
function Assert-RIPreserved {
    foreach ($entry in $state.foreign) {
        $path=Join-Path $foreignRoot $entry.name
        if ((Get-FileHash -LiteralPath $path -ErrorAction Stop).Hash -cne $entry.sha256) {throw 'Foreign fixture changed.'}
    }
    foreach ($entry in @(@{path=$foreignLink;hash=$state.foreign_link_sha256},@{path=$rawDump;hash=$state.raw_dump_sha256})) {
        Assert-RIPlain $entry.path
        if ((Get-FileHash -LiteralPath $entry.path -ErrorAction Stop).Hash -cne $entry.hash) {throw 'Unrelated sentinel changed.'}
    }
}
function Assert-RIPending {
    foreach ($record in $state.old_journals) {
        $path=Join-Path $instance ('Nomad\cleanup-pending\'+$record.name);Assert-RIPlain $path
        if ((Get-FileHash -LiteralPath $path -ErrorAction Stop).Hash -cne $record.sha256) {throw 'Pending intent changed unexpectedly.'}
    }
    if (-not (Test-Path -LiteralPath $ownedLink) -or -not (Test-Path -LiteralPath (Join-Path $ownedReport 'Report.wer')) -or -not (Test-Path -LiteralPath (Join-Path $ownedReport 'inert.dmp'))) {throw 'Owned fixtures disappeared before recovery.'}
    Assert-RIPreserved
}
function New-RILink([string]$Target,[string]$Link) {
    Assert-RIPlain $Target;Assert-RIPlain $Link
    if (Test-Path -LiteralPath $Link) {throw 'Existing shortcut preserved.'}
    $shell=$null;$shortcut=$null
    try {$shell=New-Object -ComObject WScript.Shell;$shortcut=$shell.CreateShortcut($Link);$shortcut.TargetPath=$Target;$shortcut.Save()}
    finally {if($shortcut){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut)};if($shell){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}}
}
function Export-RI {
    Assert-RIPlain 'C:\NomadRecoveryOutput'
    if (-not (Test-Path -LiteralPath 'C:\NomadRecoveryOutput' -PathType Container)) {throw 'Dedicated output mapping absent.'}
    $exportToken=[Guid]::NewGuid().ToString('N')
    $out=Join-Path 'C:\NomadRecoveryOutput' ('integration-'+$state.token+'-'+$exportToken)
    if (Test-Path -LiteralPath $out) {throw 'Existing export preserved.'}
    $null=New-Item -ItemType Directory -Path $out
    $files=@()
    foreach ($name in @('STATE.json','INTERRUPTED.json','CLOSED.json','RELAUNCH.json','nomad.log')) {
        $path=Join-Path $instance $name
        if ($name -eq 'STATE.json') {$path=$statePath}
        if ($name -eq 'nomad.log') {$path=$log}
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {continue}
        Assert-RIPlain $path
        $dest=Join-Path $out $name
        $captured=Copy-RIBoundedSnapshot $path $dest
        $files+=@{name=$name;bytes=$captured.bytes;sha256=$captured.sha256;capture=$captured.capture}
    }
    Save-RI (Join-Path $out 'GUEST-RECEIPT.json') @{schema=1;token=$state.token;export_token=$exportToken;base_commit=$manifest.base_commit;source_tree_sha256=$manifest.source_tree_sha256;launcher_sha256=$manifest.launcher_sha256;files=$files;scope='Disposable production launcher/browser and authored host artifacts; profile not exported';os_version=[Environment]::OSVersion.Version.ToString()} -New
    Write-Host "EVIDENCE EXPORTED: $out; files: $($files.Count). Keep Sandbox open for host verification."
}
if ($Phase -eq 'Fresh') {
    if (Test-Path -LiteralPath $statePath) {throw 'Existing test preserved. Use Status; do not repeat Fresh.'}
    $null=New-Item -ItemType Directory -Path $homeRoot -Force
    $token=[Guid]::NewGuid().ToString('N');$instance=Join-Path $homeRoot ($token+'\Instance')
    $null=New-Item -ItemType Directory -Path (Join-Path $instance 'Nomad')
    $launcher=Join-Path $instance 'Nomad-Helium.exe';Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Nomad-Helium.exe') -Destination $launcher
    $headers=@{'User-Agent'='Nomad-Recovery-Sandbox-Qualification'}
    [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
    $release=Invoke-RestMethod -Uri 'https://api.github.com/repos/imputnet/helium-windows/releases/tags/0.19.2.1' -Headers $headers
    $assets=@($release.assets | Where-Object {$_.name -ceq 'helium_0.19.2.1_x64-windows.zip'})
    $url='https://github.com/imputnet/helium-windows/releases/download/0.19.2.1/helium_0.19.2.1_x64-windows.zip'
    $digest='8623c04201a0a45a97920c7acdaa3a9f022260c66d6dfe78e7dcb323d4d2d89c'
    if ($release.tag_name -cne '0.19.2.1' -or $assets.Count -ne 1 -or $assets[0].digest -cne ('sha256:'+$digest) -or $assets[0].browser_download_url -cne $url) {throw 'Reviewed release changed; no browser launched.'}
    $fetched=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $cache="fetched_at = $fetched`ntarget = `"x64`"`nbrowser_version = `"0.19.2.1`"`nengine_version = `"0.19.2.1`"`ndownload_url = `"$url`"`nsha256 = `"$digest`"`n"
    [IO.File]::WriteAllText((Join-Path $instance 'Nomad\nomad-version-cache.toml'),$cache,$utf8)
    $config="[browser]`ninstall_dir = `"Browser`"`narch = `"x64`"`n[update]`ncheck_on_launch = true`nauto_download = true`nremind_on_protocol = false`n[launch]`nlanguage = `"en-US`"`nextra_args = [`"about:blank`"]`nincognito = false`n[hardening]`nenabled = true`nrecover_missed_cleanup = true`nscrub_thumbnail_cache = false`nclear_data_on_exit = false`n"
    [IO.File]::WriteAllText((Join-Path $instance 'Nomad\nomad.toml'),$config,$utf8)
    Save-RI $statePath @{schema=1;token=$token;initial_config_sha256=(Get-FileHash -LiteralPath (Join-Path $instance 'Nomad\nomad.toml')).Hash} -New
    Start-RILauncher $launcher $PSScriptRoot
    Write-Host 'LOCAL UNSIGNED BUILD. Nomad downloads and verifies pinned Helium 0.19.2.1 inside this guest.'
    Write-Host 'Leave Helium services setup untouched. Do not make it the default browser or enter personal data.'
    Write-Host 'Bookmark about:blank as Nomad recovery test; confirm built-in uBlock. Leave Helium OPEN.'
    Write-Host 'Then run: powershell -NoProfile -ExecutionPolicy Bypass -File C:\NomadInput\Run-Recovery-Integration.ps1 -Phase Interrupt'
    exit
}
$state=Read-RIJson $statePath 65536
if ($state.schema -ne 1 -or $state.token -cnotmatch '^[a-f0-9]{32}$') {throw 'Invalid owned test token.'}
$instance=Join-Path $homeRoot ($state.token+'\Instance');Assert-RIPlain $instance
$launcher=Join-Path $instance 'Nomad-Helium.exe';$image=Join-Path $instance 'Browser\chrome.exe'
$configPath=Join-Path $instance 'Nomad\nomad.toml';$marker=Join-Path $instance 'Browser\.nomad-version';$log=Join-Path $instance 'Nomad\nomad.log'
if ((Get-FileHash -LiteralPath $launcher).Hash -cne $manifest.launcher_sha256) {throw 'Copied launcher changed.'}
$recent=Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
$queue=Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportQueue'
$ownedReport=Join-Path $queue ('NomadRecovery-Owned-'+$state.token)
$foreignRoot=Join-Path $queue ('NomadRecovery-Foreign-'+$state.token)
$ownedLink=Join-Path $recent ('NomadRecovery-Owned-'+$state.token+'.lnk')
$foreignLink=Join-Path $recent ('NomadRecovery-Foreign-'+$state.token+'.lnk')
$rawDump=Join-Path $queue ('NomadRecovery-Standalone-'+$state.token+'.dmp')
$bookmarks=Join-Path $instance 'Data\Default\Bookmarks'
if ($Phase -eq 'Status') {
    Write-Host ('Browser process count: '+@(Get-RIBrowsers).Count)
    Write-Host ('Pending journals: '+@(Get-RIJournals).Count)
    Write-Host "Instance: $instance"
    foreach($stage in @('INTERRUPTED.json','CLOSED.json','RELAUNCH.json')){Write-Host ($stage+': '+(Test-Path -LiteralPath (Join-Path $instance $stage)))}
    Write-Host 'Read-only status. Keep Sandbox open.';exit
}
if ($Phase -eq 'Export') {Export-RI;exit}
if ($Phase -eq 'Relaunch') {
    if (@($state.old_journals).Count -lt 1 -or @($state.old_journals).Count -gt 32) {throw 'Invalid saved journal count.'}
    foreach($record in $state.old_journals){if($record.name -cnotmatch '^pending-[a-f0-9]{16}\.bin$' -or $record.sha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'Invalid saved journal path/hash.'}}
    if (@($state.foreign).Count -ne 2) {throw 'Invalid foreign fixture inventory.'}
    $names=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach($entry in $state.foreign){if($entry.name -cnotin @('Report.wer','inert.dmp') -or -not $names.Add($entry.name) -or $entry.sha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'Invalid saved foreign path/hash.'}}
}
if ($Phase -eq 'Interrupt') {
    if (Test-Path -LiteralPath (Join-Path $instance 'INTERRUPTED.json')) {throw 'Interruption already recorded; preserve it.'}
    if (@(Get-RIBrowsers).Count -eq 0) {throw 'Helium must remain open before interrupting its watcher.'}
    $bookmarkUrl=Get-RIBookmark $bookmarks
    $text=Get-Content -LiteralPath $marker -Raw
    if ($text -notmatch 'browser_version\s*=\s*"0\.19\.2\.1"' -or $text -notmatch 'target\s*=\s*"x64"') {throw 'Wrong installed browser/target.'}
    if ((Get-FileHash -LiteralPath $configPath).Hash -cne $state.initial_config_sha256) {throw 'Initial test config changed.'}
    $records=@(Get-RIJournals);if($records.Count -eq 0){throw 'No protected recovery record was armed.'}
    if ((Get-Item -LiteralPath $log).Length -gt 524288) {throw 'Oversized log preserved.'}
    $logText=Get-RILogText $log
    $watcherId=Get-RIWatcherPid $logText
    $worker=[Diagnostics.Process]::GetProcessById($watcherId)
    try {
        $null=$worker.Handle # retain the exact process object/handle before any validation
        $started=$worker.StartTime
        $metadata=Get-CimInstance Win32_Process -Filter ("ProcessId = "+$watcherId)
        Assert-RIWatcher $metadata $watcherId $launcher $image $started
        if ($worker.HasExited -or @(Get-RIBrowsers).Count -eq 0) {throw 'Session ended; no worker stopped.'}
        # Only this retained and corroborated watcher handle is stopped. Never kill by name or browser PID.
        $worker.Kill();if(-not $worker.WaitForExit(5000)){throw 'Owned watcher did not stop.'};$worker.WaitForExit();$workerExit=$worker.ExitCode
    } finally {$worker.Dispose()}
    foreach($path in @($recent,$queue,$ownedReport,$foreignRoot)){Assert-RIPlain $path}
    foreach($path in @($ownedReport,$foreignRoot,$ownedLink,$foreignLink,$rawDump)){if(Test-Path -LiteralPath $path){throw 'Existing sentinel preserved; export diagnostics.'}}
    $null=New-Item -ItemType Directory -Path $recent -Force
    $null=New-Item -ItemType Directory -Path $ownedReport -Force
    $null=New-Item -ItemType Directory -Path $foreignRoot
    $foreignImage=Join-Path $homeRoot ($state.token+'\Foreign\inert.exe')
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $foreignImage)
    [IO.File]::WriteAllText($foreignImage,'INERT authored marker; never executable',$utf8)
    foreach($pair in @(@{dir=$ownedReport;app=$image},@{dir=$foreignRoot;app=$foreignImage})) {
        [IO.File]::WriteAllText((Join-Path $pair.dir 'Report.wer'),("AppPath="+$pair.app+"`r`n"),$utf8)
        [IO.File]::WriteAllText((Join-Path $pair.dir 'inert.dmp'),'INERT public recovery sentinel',$utf8)
    }
    New-RILink $image $ownedLink;New-RILink $foreignImage $foreignLink
    [IO.File]::WriteAllText($rawDump,'INERT standalone public sentinel',$utf8)
    # Freeze updates for subsequent launches; only the exact helper-created config is changed.
    $config=[IO.File]::ReadAllText($configPath).Replace('check_on_launch = true','check_on_launch = false')
    [IO.File]::WriteAllText($configPath,$config,$utf8)
    $state | Add-Member config_sha256 (Get-FileHash -LiteralPath $configPath).Hash
    $state | Add-Member marker_sha256 (Get-FileHash -LiteralPath $marker).Hash
    $state | Add-Member bookmark_url $bookmarkUrl
    $state | Add-Member old_journals $records
    $state | Add-Member foreign @(@('Report.wer','inert.dmp') | ForEach-Object {@{name=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $foreignRoot $_)).Hash}})
    $state | Add-Member foreign_link_sha256 (Get-FileHash -LiteralPath $foreignLink).Hash
    $state | Add-Member raw_dump_sha256 (Get-FileHash -LiteralPath $rawDump).Hash
    Save-RI $statePath $state
    Assert-RIPending
    Save-RI (Join-Path $instance 'INTERRUPTED.json') @{watcher_stopped=$true;watcher_pid=$watcherId;watcher_exit_code=$workerExit;journals=$records;browser_running=(@(Get-RIBrowsers).Count -gt 0)} -New
    Write-Host "Owned cleanup watcher interrupted: $watcherId. Protected intent and authored guest fixtures remain."
    Write-Host 'Now close Helium normally, including all windows. No browser process is terminated by the helper.'
    Write-Host 'Then run: powershell -NoProfile -ExecutionPolicy Bypass -File C:\NomadInput\Run-Recovery-Integration.ps1 -Phase Relaunch'
    exit
}
if (Test-Path -LiteralPath (Join-Path $instance 'RELAUNCH.json')) {throw 'Completed relaunch preserved; use Status or Export.'}
if (@(Get-RIBrowsers).Count -ne 0) {throw 'Close Helium normally before Relaunch. Nothing is terminated.'}
Assert-RIPending
if ((Get-FileHash -LiteralPath $configPath).Hash -cne $state.config_sha256 -or (Get-FileHash -LiteralPath $marker).Hash -cne $state.marker_sha256) {throw 'Frozen configuration or installed marker changed.'}
if (Test-Path -LiteralPath (Join-Path $instance 'CLOSED.json')) {throw 'Prior relaunch attempt preserved; export diagnostics instead of repeating.'}
Save-RI (Join-Path $instance 'CLOSED.json') @{browser_stopped=$true;intent_and_fixtures_preserved=$true;journals=$state.old_journals} -New
$before=Get-RILogText $log;$offset=$before.Length
Start-RILauncher $launcher $PSScriptRoot
$deadline=[DateTime]::UtcNow.AddSeconds(60)
$ready=$false
while ([DateTime]::UtcNow -lt $deadline) {
    if ((Get-Item -LiteralPath $log).Length -gt 524288) {throw 'Oversized log; preserve diagnostics.'}
    $after=Get-RILogText $log
    if ($after.Length -lt $offset) {throw 'Log rotated; preserve diagnostics.'}
    $tail=$after.Substring($offset)
    $recovered=$tail.IndexOf('retired completed owned cleanup recovery records',[StringComparison]::Ordinal)
    $launched=$tail.IndexOf('browser launched',[StringComparison]::Ordinal)
    if (@(Get-RIBrowsers).Count -gt 0 -and $recovered -ge 0 -and $launched -gt $recovered) {$ready=$true;break}
    Start-Sleep -Milliseconds 250
}
if (-not $ready) {throw 'Reopen/replay ordering not corroborated; keep Sandbox and use Export.'}
foreach($record in $state.old_journals){if(Test-Path -LiteralPath (Join-Path $instance ('Nomad\cleanup-pending\'+$record.name))){throw 'Old journal not retired.'}}
if ((Test-Path -LiteralPath $ownedLink) -or (Test-Path -LiteralPath $ownedReport)) {throw 'Owned traces remain; export diagnostics.'}
Assert-RIPreserved
if ((Get-FileHash -LiteralPath $configPath).Hash -cne $state.config_sha256 -or (Get-FileHash -LiteralPath $marker).Hash -cne $state.marker_sha256 -or (Get-RIBookmark $bookmarks) -cne $state.bookmark_url) {throw 'Configuration/marker/bookmark preservation failed.'}
$result=@{old_journals_retired=$true;owned_shortcut_removed=$true;owned_report_removed=$true;foreign_fixtures_preserved=$true;configuration_unchanged=$true;installed_marker_unchanged=$true;bookmark_preserved=$true;browser_running=$true;recovery_logged=$true;ubo_confirmation='pending user visual confirmation';scope='Real Helium/production launcher-watcher; synthetic WER and Windows-created shortcut; no physical interruption or key isolation claim'}
Save-RI (Join-Path $instance 'RELAUNCH.json') $result -New
Export-RI
Write-Host 'GUEST INTEGRATION ASSERTIONS PASSED. Confirm bookmark and built-in uBlock visually; send output. Keep Sandbox open.'
