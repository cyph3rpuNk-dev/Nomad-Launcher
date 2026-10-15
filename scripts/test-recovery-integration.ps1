# Offline authored metadata only. No browser, DPAPI, registry, download or process termination.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'sandbox-recovery/Recovery-Integration-Helpers.ps1')
function Reject([scriptblock]$Action){$failed=$false;try{& $Action | Out-Null}catch{$failed=$true};if(-not $failed){throw 'Unsafe fixture accepted.'}}
$root=Join-Path ([IO.Path]::GetTempPath()) ('nomad-ri-metadata-'+[Guid]::NewGuid().ToString('N'))
$utf8=New-Object Text.UTF8Encoding($false)
function Json([string]$Path,$Value){[IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 12),$utf8)}
try {
    $launcher='C:\NomadRecoveryIntegration\test\Instance\Nomad-Helium.exe';$image='C:\NomadRecoveryIntegration\test\Instance\Browser\chrome.exe'
    $started=[datetime]::UtcNow
    $metadata=[pscustomobject]@{ProcessId=123;ExecutablePath=$launcher;CommandLine=('"'+$launcher+'" --nomad-cleanup-pid 456 --nomad-cleanup-exe "'+$image+'" --nomad-recover-cleanup');CreationDate=$started}
    Assert-RIWatcher $metadata 123 $launcher $image $started
    foreach($change in @(@{ExecutablePath='C:\other.exe'},@{CommandLine='chrome.exe'},@{CommandLine=($metadata.CommandLine+' --nomad-scrub-thumbcache')},@{CreationDate=$started.AddSeconds(1)},@{ProcessId=124})){
        $copy=$metadata.PSObject.Copy();foreach($key in $change.Keys){$copy.$key=$change[$key]};Reject {Assert-RIWatcher $copy 123 $launcher $image $started}
    }
    Reject {Assert-RIGuest 'C:\NotNomadInput'}
    $info='2026-10-14T14:00:00Z INFO nomad_core: cleanup watcher spawned watcher_pid=123 browser_pid=456 exe="C:\test\chrome.exe" scrub_thumbnail_cache=false'
    if((Get-RIWatcherPid $info) -ne 123){throw 'Valid tracing event was not recognized.'}
    foreach($badLog in @('WARN safe browsing disabled',($info+"`n"+$info),$info.Replace('watcher_pid=123','watcher_pid=0'),$info.Replace('watcher_pid=123','watcher_pid=999999999999999'))){Reject {Get-RIWatcherPid $badLog}}
    # Scoped mocks test inherited logging and restoration without provisioning or starting any process.
    & {
        $previous=$env:NOMAD_LOG
        $script:startCount=0;$script:failStart=$false
        function Assert-RIGuest([string]$InputRoot){if($InputRoot -cne 'C:\NomadInput'){throw 'Mock input scope refused.'}}
        function Start-Process([string]$FilePath){
            if($env:NOMAD_LOG -cne 'info'){throw 'Child did not inherit info logging.'}
            $script:startCount++
            if($script:failStart){throw 'Authored startup failure'}
        }
        try {
            $path='C:\NomadRecoveryIntegration\'+('a'*32)+'\Instance\Nomad-Helium.exe'
            foreach($prior in @($null,'warn','debug')){
                if($null -eq $prior){Remove-Item Env:\NOMAD_LOG -ErrorAction SilentlyContinue}else{$env:NOMAD_LOG=$prior}
                Start-RILauncher $path 'C:\NomadInput'
                if($env:NOMAD_LOG -cne $prior){throw 'Logging environment not restored.'}
                $script:failStart=$true;Reject {Start-RILauncher $path 'C:\NomadInput'};$script:failStart=$false
                if($env:NOMAD_LOG -cne $prior){throw 'Failed startup did not restore environment.'}
            }
            $count=$script:startCount
            Reject {Start-RILauncher 'C:\other.exe' 'C:\NomadInput'}
            Reject {Start-RILauncher $path 'C:\other'}
            if($script:startCount -ne $count){throw 'Refused scope reached mocked startup.'}
        } finally {if($null -eq $previous){Remove-Item Env:\NOMAD_LOG -ErrorAction SilentlyContinue}else{$env:NOMAD_LOG=$previous}}
    }

    $null=New-Item -ItemType Directory -Path $root
    # Real ordinary temporary file with a held writer, not a personal log/browser.
    $live=Join-Path $root 'live.log';$writer=$null
    try {
        $writer=[IO.File]::Open($live,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
        $data=[Text.Encoding]::UTF8.GetBytes($info)
        $writer.Write($data,0,$data.Length);$writer.Flush()
        $dest=Join-Path $root 'captured.log'
        $captured=Copy-RIBoundedSnapshot $live $dest
        if($captured.bytes -ne $data.Length -or (Get-RIWatcherPid (Get-RILogText $live)) -ne 123){throw 'Held-writer snapshot failed.'}
        $more=[Text.Encoding]::UTF8.GetBytes("`npublic later append")
        $writer.Write($more,0,$more.Length);$writer.Flush()
        if((Get-FileHash -LiteralPath $dest).Hash -cne $captured.sha256){throw 'Later append changed earlier snapshot.'}
        $next=Read-RIBytesSnapshot $live
        if($next.Length -ne $data.Length+$more.Length){throw 'Shared snapshot missed authored append.'}
        Reject {Read-RIBytesSnapshot $live 1}
        Reject {Copy-RIBoundedSnapshot $live $dest}
    } finally {if($writer){$writer.Dispose()}}
    $exclusive=$null
    try {$exclusive=[IO.File]::Open($live,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);Reject {Read-RIBytesSnapshot $live}} finally {if($exclusive){$exclusive.Dispose()}}
    $empty=Join-Path $root 'empty.log';[IO.File]::WriteAllBytes($empty,(New-Object byte[] 0))
    $emptyBytes=Read-RIBytesSnapshot $empty
    if($emptyBytes -isnot [byte[]] -or $emptyBytes.Length -ne 0){throw 'Empty bounded snapshot mishandled.'}
    $bookmark=Join-Path $root 'Bookmarks'
    Json $bookmark @{roots=@{bookmark_bar=@{type='folder';children=@(@{type='url';name='Nomad recovery test';url='about:blank'})}}}
    if((Get-RIBookmark $bookmark) -cne 'about:blank'){throw 'Expected public bookmark.'}
    Json $bookmark @{roots=@{bookmark_bar=@{type='folder';children=@(@{type='url';name='Nomad recovery test';url='https://private.invalid/'})}}}
    Reject {Get-RIBookmark $bookmark}
    foreach($script in @('prepare-recovery-integration-sandbox.ps1','sandbox-recovery/Run-Recovery-Integration.ps1','sandbox-recovery/Recovery-Integration-Helpers.ps1')){
        $tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $script),[ref]$tokens,[ref]$errors)
        if($errors.Count){throw ($errors | Out-String)}
    }
    $inputRoot=Join-Path $root 'input';$token='a'*32;$exportToken='b'*32;$out=Join-Path $root ('integration-'+$token+'-'+$exportToken)
    $null=New-Item -ItemType Directory -Path $inputRoot;$null=New-Item -ItemType Directory -Path $out
    [IO.File]::WriteAllText((Join-Path $inputRoot 'Nomad-Helium.exe'),'INERT fixture; never executed',$utf8)
    $build=@{schema=1;target='x86_64-pc-windows-msvc';base_commit=('a'*40);source_tree_sha256=('B'*64);launcher_sha256=(Get-FileHash -LiteralPath (Join-Path $inputRoot 'Nomad-Helium.exe')).Hash}
    Json (Join-Path $inputRoot 'BUILD-MANIFEST.json') $build
    $result=@{};foreach($key in @('old_journals_retired','owned_shortcut_removed','owned_report_removed','foreign_fixtures_preserved','configuration_unchanged','installed_marker_unchanged','bookmark_preserved','browser_running','recovery_logged')){$result[$key]=$true}
    Json (Join-Path $out 'RELAUNCH.json') $result
    Json (Join-Path $out 'INTERRUPTED.json') @{watcher_stopped=$true}
    Json (Join-Path $out 'CLOSED.json') @{browser_stopped=$true;intent_and_fixtures_preserved=$true}
    Json (Join-Path $out 'STATE.json') @{schema=1}
    [IO.File]::WriteAllText((Join-Path $out 'nomad.log'),'Authored fixture: retired completed owned cleanup recovery records; browser launched',$utf8)
    $files=@(Get-ChildItem -LiteralPath $out -File | ForEach-Object {@{name=$_.Name;bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
    $receipt=@{schema=1;token=$token;export_token=$exportToken;base_commit=$build.base_commit;source_tree_sha256=$build.source_tree_sha256;launcher_sha256=$build.launcher_sha256;files=$files}
    Json (Join-Path $out 'GUEST-RECEIPT.json') $receipt
    $checked=Test-RIExport $inputRoot $out;if(-not $checked.hashes_verified){throw 'Expected valid authored receipt.'}
    $originalName=$receipt.files[0].name
    $receipt.files[0].name='../escape';Json (Join-Path $out 'GUEST-RECEIPT.json') $receipt;Reject {Test-RIExport $inputRoot $out}
    $receipt.files[0].name=$originalName
    foreach($bad in @($false,'true')) {
        $result.bookmark_preserved=$bad;Json (Join-Path $out 'RELAUNCH.json') $result
        foreach($file in $receipt.files){if($file.name -ceq 'RELAUNCH.json'){$file.bytes=(Get-Item -LiteralPath (Join-Path $out 'RELAUNCH.json')).Length;$file.sha256=(Get-FileHash -LiteralPath (Join-Path $out 'RELAUNCH.json')).Hash}}
        Json (Join-Path $out 'GUEST-RECEIPT.json') $receipt;Reject {Test-RIExport $inputRoot $out}
    }
    $result.bookmark_preserved=$true;Json (Join-Path $out 'RELAUNCH.json') $result
    foreach($file in $receipt.files){if($file.name -ceq 'RELAUNCH.json'){$file.bytes=(Get-Item -LiteralPath (Join-Path $out 'RELAUNCH.json')).Length;$file.sha256=(Get-FileHash -LiteralPath (Join-Path $out 'RELAUNCH.json')).Hash}}
    Json (Join-Path $out 'GUEST-RECEIPT.json') $receipt
    $null=Test-RIExport $inputRoot $out
    [IO.File]::AppendAllText((Join-Path $out 'nomad.log'),'tampered',$utf8);Reject {Test-RIExport $inputRoot $out}
    $receipt.files=@($files | Select-Object -Skip 1);Json (Join-Path $out 'GUEST-RECEIPT.json') $receipt;Reject {Test-RIExport $inputRoot $out}
    Write-Host 'Integration safety metadata fixtures passed; guest/browser integration NOT RUN.'
} finally {
    $resolved=[IO.Path]::GetFullPath($root)
    if(-not $resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)-or (Split-Path -Leaf $resolved) -notmatch '^nomad-ri-metadata-[a-f0-9]{32}$'){throw 'Unsafe fixture cleanup target.'}
    Assert-RIPlain $resolved
    if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
$global:LASTEXITCODE=0
