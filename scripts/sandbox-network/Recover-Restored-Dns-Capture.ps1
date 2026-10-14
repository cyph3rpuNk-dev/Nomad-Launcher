# Post-restore capture recovery only. No launch, rules/config/profile changes or state rewrites.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($env:USERNAME -cne 'WDAGUtilityAccount' -or $env:USERPROFILE -cne 'C:\Users\WDAGUtilityAccount' -or $PSScriptRoot -cne 'C:\NomadInput\DnsFaultRecovery'){throw 'Disposable post-restore capture recovery only.'}
. (Join-Path $PSScriptRoot 'Recovery-Integration-Helpers.ps1')
. (Join-Path $PSScriptRoot 'Analyze-Dns-NetLog.ps1')
$manifest=Read-RIJson (Join-Path $PSScriptRoot 'BUILD-MANIFEST.json')
function Assert-RecoveryInputs([string]$Root,$Build){
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach($entry in $Build.input_files){
        if($entry.name -cnotin @('Nomad-Helium.exe','Run-Helium-Dns.ps1','Analyze-Dns-NetLog.ps1','Recovery-Integration-Helpers.ps1') -or -not $seen.Add($entry.name)){throw 'Unexpected recovery input inventory.'}
        $path=Join-Path $Root $entry.name;Assert-RIPlain $path
        if((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.sha256){throw 'Frozen input changed.'}
    }
    if($seen.Count -ne 4 -or $Build.schema -ne 1 -or $Build.target -cne 'x86_64-pc-windows-msvc'){throw 'Incomplete recovery inputs.'}
}
Assert-RecoveryInputs $PSScriptRoot $manifest
$originalRoot='C:\NomadInput\DnsFault';$originalPath=Join-Path $originalRoot 'BUILD-MANIFEST.json';Assert-RIPlain $originalPath
if((Get-FileHash -LiteralPath $originalPath).Hash -cne $manifest.original_fault_manifest_sha256){throw 'Original fault manifest changed.'}
$original=Read-RIJson $originalPath;Assert-RecoveryInputs $originalRoot $original
foreach($key in @('base_commit','source_tree_sha256','launcher_sha256')){if($original.$key -cne $manifest.$key){throw 'Original/recovery provenance differs.'}}
$root='C:\NomadDnsQualification';$state=Read-RIJson (Join-Path $root 'DnsFault\STATE.json') 65536;$parent=Read-RIJson (Join-Path $root 'STATE.json') 65536
if($state.schema -ne 1 -or $state.token -cnotmatch '^[a-f0-9]{32}$' -or $state.session_token -cnotmatch '^[a-f0-9]{32}$' -or $state.session_token -cne $parent.token -or $state.started -isnot [bool] -or -not $state.started -or $state.restored -isnot [bool] -or -not $state.restored -or $state.collected -isnot [bool] -or $state.collected){throw 'Only a started, restored, previously uncollected fault can be recovered.'}
if(@(Get-Process -Name chrome -ErrorAction SilentlyContinue).Count){throw 'Close all Helium windows normally before finalized-capture recovery.'}
foreach($store in @('PersistentStore','ActiveStore')){
    $rules=@(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop)
    foreach($protocol in @('TCP','UDP')){if(@($rules|Where-Object Name -CEQ ('NomadDnsFault-'+$state.token+'-'+$protocol)).Count){throw 'An owned rule still exists; preserve it and report this refusal.'}}
}
$instance=Join-Path $root ($state.session_token+'\Instance');$configPath=Join-Path $instance 'Nomad\nomad.toml';$launcher=Join-Path $instance 'Nomad-Helium.exe'
foreach($path in @($instance,$configPath,$launcher)){Assert-RIPlain $path}
if($state.original_config_sha256 -cnotmatch '^[A-F0-9]{64}$' -or (Get-FileHash -LiteralPath $configPath).Hash -cne $state.original_config_sha256 -or (Get-FileHash -LiteralPath $launcher).Hash -cne $manifest.launcher_sha256){throw 'Restored configuration/launcher differs.'}
$local=Read-RIJson (Join-Path $instance 'Data\Local State') 1048576;$dns=Get-DnsField $local 'dns_over_https'
if((Get-DnsField $dns 'mode') -cne 'secure' -or (Get-DnsField $dns 'templates') -cne 'https://dns.quad9.net/dns-query'){throw 'Restored saved DNS setting differs; preserve it.'}
$image=Join-Path $instance 'Browser\chrome.exe';$module=Join-Path $instance 'Browser\chrome.dll';Assert-RIPlain $image;Assert-RIPlain $module
$browserHash=(Get-FileHash -LiteralPath $image).Hash;$moduleHash=(Get-FileHash -LiteralPath $module).Hash
if($browserHash -cne 'A7EFCB9F8C830AD2C6BD059DA38774B2E83411196E696602D08D4B6A4E4BE00D' -or $moduleHash -cne '36B703C1B1B563558181F3AA42BDE16D21EC6A0B5E0E658989D59D77B2627B7D'){throw 'Reviewed browser identity differs.'}
$raw=Join-Path $instance ('Fault-'+$state.token+'.netlog.json');Assert-RIPlain $raw;$stream=$null
try{
    $stream=[IO.File]::Open($raw,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    if($stream.Length -gt 33554432){throw 'Finalized capture exceeds 32 MiB.'}
    $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
    while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($count -le 0){throw 'Incomplete finalized capture.'};$offset+=$count}
    $text=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes).TrimStart([char]0xFEFF)
}finally{if($stream){$stream.Dispose()}}
$probe='nomad-'+$state.token+'-failure.example.com'
try{$log=ConvertFrom-Json -InputObject $text;$observation=Get-DnsObservation $log $probe Failure Quad9Blocked}catch{throw 'Recovered capture correlation could not be parsed; no result fabricated; raw remains guest-only.'}
foreach($key in @('base_commit','source_tree_sha256','launcher_sha256')){$observation|Add-Member -NotePropertyName $key -NotePropertyValue $manifest.$key}
$algorithm=[Security.Cryptography.SHA256]::Create();try{$rawHash=[BitConverter]::ToString($algorithm.ComputeHash($bytes)).Replace('-','')}finally{$algorithm.Dispose()}
foreach($pair in @(@('saved_test_dns_matches',$true),@('transport_fixture','restored-before-collection'),@('collection_after_restore',$true),@('current_rules_absent',$true),@('historical_start_checks_recorded',$true),@('qualified_fault_fixture',$false),@('rules_during_capture_rechecked',$false),@('original_fault_manifest_sha256',$manifest.original_fault_manifest_sha256),@('browser_image_sha256',$browserHash),@('browser_module_sha256',$moduleHash),@('raw_capture_sha256',$rawHash),@('raw_capture_bytes',$bytes.Length))){$observation|Add-Member -NotePropertyName $pair[0] -NotePropertyValue $pair[1]}
$outRoot='C:\NomadDnsOutput';Assert-RIPlain $outRoot
if(-not(Test-Path -LiteralPath $outRoot -PathType Container)){throw 'Dedicated output mapping absent.'}
$exportToken=[Guid]::NewGuid().ToString('N');$out=Join-Path $outRoot ('failure-'+$state.token+'-'+$exportToken)
if(Test-Path -LiteralPath $out){throw 'Existing recovered output preserved.'}
$null=New-Item -ItemType Directory -Path $out;$utf8=New-Object Text.UTF8Encoding($false);$path=Join-Path $out 'OBSERVATION.json'
[IO.File]::WriteAllText($path,($observation|ConvertTo-Json -Depth 64),$utf8)
$receipt=@{schema=1;case='Failure';token=$state.token;session_token=$state.session_token;export_token=$exportToken;base_commit=$manifest.base_commit;source_tree_sha256=$manifest.source_tree_sha256;launcher_sha256=$manifest.launcher_sha256;files=@(@{name='OBSERVATION.json';bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path).Hash});scope='Post-restore selected capture recovery; no live fault qualification or raw/profile transfer';os_version=[Environment]::OSVersion.Version.ToString()}
[IO.File]::WriteAllText((Join-Path $out 'GUEST-RECEIPT.json'),($receipt|ConvertTo-Json -Depth 10),$utf8)
Write-Host ('RECOVERED DNS OBSERVATION: '+$observation.status+'; target transactions '+$observation.target_transactions+'; correlated Quad9 attempts '+$observation.correlated_doh_attempts)
Write-Host 'Collected AFTER restore: no active-rule check during capture close is claimed; full fault fixture remains unqualified.'
Write-Host ('EVIDENCE EXPORTED: '+$out)
Write-Host 'No browser/firewall/config/profile/state change. Send output; keep Sandbox open for host selected-evidence review.'
