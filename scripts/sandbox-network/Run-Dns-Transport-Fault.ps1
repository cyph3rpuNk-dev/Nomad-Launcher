# Existing disposable guest only. Program-scoped transport fault, no DNS/profile preference changes.
[CmdletBinding()]
param([ValidateSet('Start','Collect','Restore','Status')][string]$Phase='Status')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($env:USERNAME -cne 'WDAGUtilityAccount' -or $env:USERPROFILE -cne 'C:\Users\WDAGUtilityAccount' -or $PSScriptRoot -cne 'C:\NomadInput\DnsFault'){throw 'Disposable DNS-fault Sandbox only; no host firewall or profile actions.'}
. (Join-Path $PSScriptRoot 'Recovery-Integration-Helpers.ps1')
. (Join-Path $PSScriptRoot 'Analyze-Dns-NetLog.ps1')
$manifest=Read-RIJson (Join-Path $PSScriptRoot 'BUILD-MANIFEST.json')
$seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach($entry in $manifest.input_files){
    if($entry.name -cnotin @('Nomad-Helium.exe','Run-Helium-Dns.ps1','Analyze-Dns-NetLog.ps1','Recovery-Integration-Helpers.ps1') -or -not $seen.Add($entry.name)){throw 'Unexpected fault input inventory.'}
    $path=Join-Path $PSScriptRoot $entry.name;Assert-RIPlain $path
    if((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.sha256){throw 'Fault input hash mismatch.'}
}
if($seen.Count -ne 4 -or $manifest.schema -ne 1 -or $manifest.target -cne 'x86_64-pc-windows-msvc'){throw 'Incomplete fault manifest.'}
$root='C:\NomadDnsQualification';$faultRoot=Join-Path $root 'DnsFault';$statePath=Join-Path $faultRoot 'STATE.json';$backupPath=Join-Path $faultRoot 'config-before.toml';$utf8=New-Object Text.UTF8Encoding($false)
Assert-RIPlain $faultRoot
function Save-FaultJson([string]$Path,$Value){Assert-RIPlain $Path;[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 64),$utf8)}
function Assert-FaultClosed {if(@(Get-Process -Name chrome -ErrorAction SilentlyContinue).Count){throw 'Close all Helium windows normally first; no process is stopped.'}}
function Assert-FaultDns {
    $local=Read-RIJson (Join-Path $instance 'Data\Local State') 1048576
    $dns=Get-DnsField $local 'dns_over_https'
    if((Get-DnsField $dns 'mode') -cne 'secure' -or (Get-DnsField $dns 'templates') -cne 'https://dns.quad9.net/dns-query'){throw 'Required secure Quad9 setting differs; preserve it.'}
}
function Assert-FaultFirewall {
    foreach($service in @('BFE','MpsSvc')){if((Get-Service -Name $service -ErrorAction Stop).Status -ne 'Running'){throw 'Guest firewall services are unavailable; no global settings are enabled or changed.'}}
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if($profiles.Count -ne 3){throw 'Guest firewall profile inventory is incomplete.'}
    foreach($profile in $profiles){if([string]$profile.Enabled -cne 'True' -or [string]$profile.AllowLocalFirewallRules -ceq 'False'){throw 'Guest firewall/local-rule policy cannot establish this fault; no global setting is changed.'}}
}
function Assert-FaultRule($Rule,$Application,$Port,$Address,[string]$Name,[string]$Program,[string]$Protocol,[string]$Token){
    if($Token -cnotmatch '^[a-f0-9]{32}$' -or $Name -cne ('NomadDnsFault-'+$Token+'-'+$Protocol) -or $Program -cnotmatch '^C:\\NomadDnsQualification\\[a-f0-9]{32}\\Instance\\Browser\\chrome\.exe$'){throw 'Invalid fault rule identity.'}
    if($Rule.Name -cne $Name -or $Rule.Description -cne ('Nomad disposable DNS fault '+$Token) -or [string]$Rule.Direction -cne 'Outbound' -or [string]$Rule.Action -cne 'Block' -or [string]$Rule.Enabled -cne 'True' -or [string]$Rule.Profile -cne 'Any'){throw 'Owned rule metadata changed; no rule removed.'}
    if(-not [string]::Equals([string]$Application.Program,$Program,[StringComparison]::OrdinalIgnoreCase)){throw 'Rule program differs; no rule removed.'}
    $number=if($Protocol -ceq 'TCP'){'6'}elseif($Protocol -ceq 'UDP'){'17'}else{throw 'Unknown fault protocol.'}
    if([string]$Port.Protocol -cnotin @($Protocol,$number) -or @($Port.RemotePort).Count -ne 1 -or [string]$Port.RemotePort -cne '443' -or @($Port.LocalPort).Count -ne 1 -or [string]$Port.LocalPort -cne 'Any' -or @($Address.RemoteAddress).Count -ne 1 -or [string]$Address.RemoteAddress -cne 'Any' -or @($Address.LocalAddress).Count -ne 1 -or [string]$Address.LocalAddress -cne 'Any'){throw 'Rule transport/address scope changed; no rule removed.'}
}
function Get-FaultRules([switch]$AllowMissing,[string]$Store='PersistentStore'){
    $rules=@()
    foreach($protocol in @('TCP','UDP')){
        $name='NomadDnsFault-'+$state.token+'-'+$protocol
        $found=@(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop | Where-Object Name -CEQ $name)
        if($found.Count -eq 0 -and $AllowMissing){continue}
        if($found.Count -ne 1){throw 'Owned rule is missing/duplicated; preserve state.'}
        $app=@($found[0]|Get-NetFirewallApplicationFilter -ErrorAction Stop);$port=@($found[0]|Get-NetFirewallPortFilter -ErrorAction Stop);$address=@($found[0]|Get-NetFirewallAddressFilter -ErrorAction Stop)
        if($app.Count -ne 1 -or $port.Count -ne 1 -or $address.Count -ne 1){throw 'Owned rule filter inventory differs.'}
        Assert-FaultRule $found[0] $app[0] $port[0] $address[0] $name $image $protocol $state.token
        $rules+=$found[0]
    }
    return $rules
}
function Restore-Fault {
    Assert-FaultClosed
    $rules=@(Get-FaultRules -AllowMissing) # validate ALL retained rules before any deletion
    $current=(Get-FileHash -LiteralPath $configPath).Hash
    if($current -cne $state.original_config_sha256 -and $current -cne $state.fault_config_sha256){throw 'Config differs from owned original/fault bytes; preserve it.'}
    if((Get-FileHash -LiteralPath $backupPath).Hash -cne $state.original_config_sha256){throw 'Owned config backup changed.'}
    foreach($rule in $rules){$rule|Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop}
    if(@(Get-FaultRules -AllowMissing).Count -or @(Get-FaultRules -AllowMissing -Store ActiveStore).Count){throw 'Owned firewall removal incomplete.'}
    if($current -cne $state.original_config_sha256){$original=Read-RIBytesSnapshot $backupPath;Assert-RIPlain $configPath;[IO.File]::WriteAllBytes($configPath,$original)}
    if((Get-FileHash -LiteralPath $configPath).Hash -cne $state.original_config_sha256){throw 'Owned config restoration failed.'}
    Assert-FaultDns
    $state.restored=$true;Save-FaultJson $statePath $state
}
function Export-Fault($Value,[string]$Kind){
    $outRoot='C:\NomadDnsOutput';Assert-RIPlain $outRoot
    if(-not(Test-Path -LiteralPath $outRoot -PathType Container)){throw 'Dedicated output mapping absent.'}
    $exportToken=[Guid]::NewGuid().ToString('N');$out=Join-Path $outRoot ($Kind+'-'+$state.token+'-'+$exportToken)
    if(Test-Path -LiteralPath $out){throw 'Existing fault evidence preserved.'}
    $null=New-Item -ItemType Directory -Path $out
    $name=if($Kind -ceq 'failure'){'OBSERVATION.json'}else{'RESTORE.json'};$path=Join-Path $out $name
    Save-FaultJson $path $Value
    $receipt=@{schema=1;case=if($Kind -ceq 'failure'){'Failure'}else{'Restore'};token=$state.token;session_token=$state.session_token;export_token=$exportToken;base_commit=$manifest.base_commit;source_tree_sha256=$manifest.source_tree_sha256;launcher_sha256=$manifest.launcher_sha256;files=@(@{name=$name;bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path).Hash});scope='Selected program-scoped guest firewall/DNS observations; no raw log/profile transfer';os_version=[Environment]::OSVersion.Version.ToString()}
    Save-FaultJson (Join-Path $out 'GUEST-RECEIPT.json') $receipt
    Write-Host ('EVIDENCE EXPORTED: '+$out)
}
foreach($command in @('Get-NetFirewallRule','New-NetFirewallRule','Remove-NetFirewallRule','Get-NetFirewallApplicationFilter','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter','Get-NetFirewallProfile')){if(-not(Get-Command $command -ErrorAction SilentlyContinue)){throw 'Required guest firewall cmdlet unavailable; no mutation.'}}
$parent=Read-RIJson (Join-Path $root 'STATE.json') 65536
if($parent.schema -ne 1 -or $parent.token -cnotmatch '^[a-f0-9]{32}$' -or $parent.baseline_collected -isnot [bool] -or -not $parent.baseline_collected -or $parent.failure_started -isnot [bool] -or ($parent.failure_started -and -not $parent.restored)){throw 'Verified baseline and prior test restoration required.'}
$instance=Join-Path $root ($parent.token+'\Instance');$launcher=Join-Path $instance 'Nomad-Helium.exe';$image=Join-Path $instance 'Browser\chrome.exe';$module=Join-Path $instance 'Browser\chrome.dll';$configPath=Join-Path $instance 'Nomad\nomad.toml'
foreach($path in @($instance,$image,$module,$launcher,$configPath)){Assert-RIPlain $path}
if((Get-FileHash -LiteralPath $launcher).Hash -cne $manifest.launcher_sha256){throw 'Original launcher identity changed.'}
# Reviewed 0.19.2.1 x64 image identities from the earlier component qualification.
$browserHash=(Get-FileHash -LiteralPath $image).Hash;$moduleHash=(Get-FileHash -LiteralPath $module).Hash
if($browserHash -cne 'A7EFCB9F8C830AD2C6BD059DA38774B2E83411196E696602D08D4B6A4E4BE00D' -or $moduleHash -cne '36B703C1B1B563558181F3AA42BDE16D21EC6A0B5E0E658989D59D77B2627B7D'){throw 'Reviewed browser/module identity differs; preserve guest.'}
if($Phase -ceq 'Start'){
    if(Test-Path -LiteralPath $statePath){throw 'A fault intent already exists; use Status/Collect/Restore and preserve it.'}
    Assert-FaultClosed;Assert-FaultDns;Assert-FaultFirewall
    if((Get-FileHash -LiteralPath $configPath).Hash -cne $parent.config_sha256){throw 'Prior helper-owned configuration changed.'}
    $token=[Guid]::NewGuid().ToString('N')
    foreach($protocol in @('TCP','UDP')){if(@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop|Where-Object Name -CEQ ('NomadDnsFault-'+$token+'-'+$protocol)).Count){throw 'Rule collision; no mutation.'}}
    $null=New-Item -ItemType Directory -Path $faultRoot
    $copy=Copy-RIBoundedSnapshot $configPath $backupPath
    $capture=Join-Path $instance ('Fault-'+$token+'.netlog.json');$probe='nomad-'+$token+'-failure.example.com'
    if(Test-Path -LiteralPath $capture){throw 'Existing fault capture preserved.'}
    $arguments=@(('--log-net-log='+$capture),'--net-log-capture-mode=Default',('https://'+$probe+'/'))
    $argumentText=ConvertTo-Json -InputObject $arguments -Compress
    $config="[browser]`ninstall_dir = `"Browser`"`narch = `"x64`"`n[update]`ncheck_on_launch = false`nauto_download = false`nremind_on_protocol = false`n[launch]`nlanguage = `"en-US`"`nextra_args = $argumentText`nincognito = false`n[hardening]`nenabled = true`nrecover_missed_cleanup = true`nscrub_thumbnail_cache = false`nclear_data_on_exit = false`n"
    $algorithm=[Security.Cryptography.SHA256]::Create();try{$configHash=[BitConverter]::ToString($algorithm.ComputeHash($utf8.GetBytes($config))).Replace('-','')}finally{$algorithm.Dispose()}
    $state=[pscustomobject]@{schema=1;session_token=$parent.token;token=$token;original_config_sha256=$copy.sha256;fault_config_sha256=$configHash;started=$false;collected=$false;restored=$false}
    Save-FaultJson $statePath $state # intent and original backup exist before rule/config changes
    try{
        foreach($protocol in @('TCP','UDP')){New-NetFirewallRule -PolicyStore PersistentStore -Name ('NomadDnsFault-'+$token+'-'+$protocol) -DisplayName ('Nomad DNS fault '+$protocol) -Description ('Nomad disposable DNS fault '+$token) -Direction Outbound -Action Block -Enabled True -Profile Any -Program $image -Protocol $protocol -RemotePort 443 -LocalPort Any -RemoteAddress Any -LocalAddress Any -ErrorAction Stop|Out-Null}
        $null=Get-FaultRules;$null=Get-FaultRules -Store ActiveStore;Assert-FaultFirewall
        Assert-RIPlain $configPath;[IO.File]::WriteAllText($configPath,$config,$utf8)
        if((Get-FileHash -LiteralPath $configPath).Hash -cne $configHash){throw 'Fault config write differs.'}
        $previous=$env:NOMAD_LOG
        try{$env:NOMAD_LOG='info';Start-Process -FilePath $launcher|Out-Null}finally{if($null -eq $previous){Remove-Item Env:\NOMAD_LOG -ErrorAction SilentlyContinue}else{$env:NOMAD_LOG=$previous}}
        $state.started=$true;Save-FaultJson $statePath $state
    }catch{
        try{Restore-Fault}catch{Write-Host 'Owned restore could not finish. Close all Helium windows and run this helper with -Phase Restore.'}
        throw 'Fault setup did not complete; original evidence preserved. Report this message and keep Sandbox open.'
    }
    Write-Host 'GUEST ONLY: exact Helium executable blocked on outbound TCP/UDP 443. DNS port 53 and host networking unchanged.'
    Write-Host 'Nomad hardening remains enabled; secure Quad9 choices are not changed. A new nonce query is captured.'
    Write-Host 'After the error page settles, close ALL Helium windows normally; run -Phase Collect, then -Phase Restore.'
    exit
}
$state=Read-RIJson $statePath 65536
if($state.schema -ne 1 -or $state.token -cnotmatch '^[a-f0-9]{32}$' -or $state.session_token -cne $parent.token -or $state.original_config_sha256 -cnotmatch '^[A-F0-9]{64}$' -or $state.fault_config_sha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'Invalid retained fault intent.'}
if($Phase -ceq 'Restore'){
    Restore-Fault
    $restoration=@{schema=1;token=$state.token;session_token=$state.session_token;owned_rules_remaining=0;config_restored=$true;original_config_sha256=$state.original_config_sha256;observed_config_sha256=(Get-FileHash -LiteralPath $configPath).Hash;saved_secure_quad9=$true;base_commit=$manifest.base_commit;source_tree_sha256=$manifest.source_tree_sha256;launcher_sha256=$manifest.launcher_sha256;scope='Exact owned guest rules removed and test config restored; browser not relaunched; host unchanged'}
    Export-Fault $restoration 'restore'
    Write-Host 'RESTORED: owned rules absent; original test config restored; secure Quad9 confirmed. Keep Sandbox open for host verification.';exit
}
if($Phase -ceq 'Status'){
    Assert-FaultDns
    Write-Host ('Read-only fault status: restored '+$state.restored+'; owned rules '+@(Get-FaultRules -AllowMissing).Count+'; browser count '+@(Get-Process -Name chrome -ErrorAction SilentlyContinue).Count)
    Write-Host 'Saved secure Quad9 is confirmed; this does not establish actual network behavior.';exit
}
if(-not $state.started -or $state.restored -or $state.collected){throw 'Collect requires one started, uncollected, unrestored fault.'}
Assert-FaultClosed;Assert-FaultDns;Assert-FaultFirewall
$null=Get-FaultRules;$null=Get-FaultRules -Store ActiveStore
if((Get-FileHash -LiteralPath $configPath).Hash -cne $state.fault_config_sha256){throw 'Fault config changed.'}
$raw=Join-Path $instance ('Fault-'+$state.token+'.netlog.json');Assert-RIPlain $raw;$stream=$null
try{
    $stream=[IO.File]::Open($raw,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    if($stream.Length -gt 33554432){throw 'Capture exceeds 32 MiB bound.'}
    $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
    while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($count -le 0){throw 'Capture incomplete.'};$offset+=$count}
    $text=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes).TrimStart([char]0xFEFF)
}finally{if($stream){$stream.Dispose()}}
$probe='nomad-'+$state.token+'-failure.example.com'
try{$log=ConvertFrom-Json -InputObject $text;$observation=Get-DnsObservation $log $probe Failure Quad9Blocked}catch{throw 'Capture/schema/correlation failed; no outage pass claimed. Run Restore; keep raw capture in guest.'}
foreach($key in @('base_commit','source_tree_sha256','launcher_sha256')){$observation|Add-Member -NotePropertyName $key -NotePropertyValue $manifest.$key}
$algorithm=[Security.Cryptography.SHA256]::Create();try{$hash=[BitConverter]::ToString($algorithm.ComputeHash($bytes)).Replace('-','')}finally{$algorithm.Dispose()}
foreach($pair in @(@('saved_test_dns_matches',$true),@('firewall_rules_verified',$true),@('firewall_profiles_enabled',$true),@('transport_fixture','owned-browser-https-block'),@('browser_image_sha256',$browserHash),@('browser_module_sha256',$moduleHash),@('raw_capture_sha256',$hash),@('raw_capture_bytes',$bytes.Length))){$observation|Add-Member -NotePropertyName $pair[0] -NotePropertyValue $pair[1]}
Export-Fault $observation 'failure'
$state.collected=$true;Save-FaultJson $statePath $state
Write-Host ('DNS OBSERVATION: '+$observation.status+'; correlated Quad9 attempts '+$observation.correlated_doh_attempts+'; plain target attempt '+$observation.plain_target_attempt_observed)
Write-Host 'Run -Phase Restore now, including after an inconclusive result. Keep Sandbox open for host evidence checking.'
