[CmdletBinding()]
param([ValidateSet('Fresh','Status','CollectBaseline','FailClosed','CollectFailure','Restore')][string]$Phase='Fresh')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($env:USERNAME -cne 'WDAGUtilityAccount' -or $env:USERPROFILE -cne 'C:\Users\WDAGUtilityAccount' -or $PSScriptRoot -cne 'C:\NomadInput'){throw 'Disposable Sandbox only; no host DNS/profile changes.'}
. (Join-Path $PSScriptRoot 'Recovery-Integration-Helpers.ps1')
. (Join-Path $PSScriptRoot 'Analyze-Dns-NetLog.ps1')
$manifest=Read-RIJson (Join-Path $PSScriptRoot 'BUILD-MANIFEST.json')
$seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach($entry in $manifest.input_files){
    if($entry.name -cnotin @('Nomad-Helium.exe','Run-Helium-Dns.ps1','Analyze-Dns-NetLog.ps1','Recovery-Integration-Helpers.ps1') -or -not $seen.Add($entry.name)){throw 'Unexpected input filename.'}
    $path=Join-Path $PSScriptRoot $entry.name;Assert-RIPlain $path
    if((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.sha256){throw 'Input mismatch.'}
}
if($seen.Count -ne 4 -or $manifest.schema -ne 1 -or $manifest.target -cne 'x86_64-pc-windows-msvc'){throw 'Incomplete input manifest.'}
$utf8=New-Object Text.UTF8Encoding($false)
$root='C:\NomadDnsQualification';$statePath=Join-Path $root 'STATE.json';Assert-RIPlain $root
function Save-DnsJson([string]$Path,$Value,[switch]$New){Assert-RIPlain $Path;if($New -and (Test-Path -LiteralPath $Path)){throw 'Existing state/evidence preserved.'};[IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 64),$utf8)}
function Start-DnsLauncher {
    $previous=$env:NOMAD_LOG
    try{$env:NOMAD_LOG='info';Start-Process -FilePath $launcher | Out-Null}finally{if($null -eq $previous){Remove-Item Env:\NOMAD_LOG -ErrorAction SilentlyContinue}else{$env:NOMAD_LOG=$previous}}
}
function Get-DnsBrowsers {
    $ids=@()
    foreach($process in @(Get-Process -Name chrome -ErrorAction SilentlyContinue)){
        try{$path=$process.Path}catch{throw 'Browser identity unavailable; preserve state.'}
        if(-not [string]::Equals($path,$image,[StringComparison]::OrdinalIgnoreCase)){throw 'Other/unqueryable chrome context; preserve state.'}
        $ids+=$process.Id
    }
    return $ids
}
function Write-DnsConfig([string]$Case,[bool]$CheckUpdates){
    $capture=Join-Path $instance ($Case+'.netlog.json')
    if(Test-Path -LiteralPath $capture){throw 'Existing raw capture preserved.'}
    $probe='nomad-'+$state.token+'-'+$Case.ToLowerInvariant()+'.example.com'
    $arguments=@(('--log-net-log='+$capture),'--net-log-capture-mode=Default',('https://'+$probe+'/'))
    # These controlled strings are JSON/TOML data, never executable source.
    $argumentText=ConvertTo-Json -InputObject $arguments -Compress
    $check=if($CheckUpdates){'true'}else{'false'}
    $config="[browser]`ninstall_dir = `"Browser`"`narch = `"x64`"`n[update]`ncheck_on_launch = $check`nauto_download = true`nremind_on_protocol = false`n[launch]`nlanguage = `"en-US`"`nextra_args = $argumentText`nincognito = false`n[hardening]`nenabled = true`nrecover_missed_cleanup = true`nscrub_thumbnail_cache = false`nclear_data_on_exit = false`n"
    Assert-RIPlain $configPath
    [IO.File]::WriteAllText($configPath,$config,$utf8)
    $state.config_sha256=(Get-FileHash -LiteralPath $configPath).Hash
    $state.case=$Case
    Save-DnsJson $statePath $state
}
function Get-DnsLocal {
    $local=Read-RIJson $localPath 1048576
    $dns=Get-DnsField $local 'dns_over_https'
    if($null -eq $dns -or (Get-DnsField $dns 'mode') -isnot [string] -or (Get-DnsField $dns 'templates') -isnot [string]){throw 'DNS fields absent/unrecognized; preserve profile.'}
    return $local
}
function Set-TestDns([string]$Expected,[string]$Replacement){
    if(@(Get-DnsBrowsers).Count){throw 'Close Helium normally before any test DNS modification.'}
    $local=Get-DnsLocal
    if($local.dns_over_https.mode -cne 'secure' -or $local.dns_over_https.templates -cne $Expected){throw 'DNS choice differs from this helper-owned case; preserve it.'}
    $local.dns_over_https.templates=$Replacement
    Save-DnsJson $localPath $local
}
if($Phase -ceq 'Fresh'){
    if(Test-Path -LiteralPath $statePath){throw 'Fresh already started; preserve this instance.'}
    $null=New-Item -ItemType Directory -Path $root -Force
    $state=[pscustomobject]@{schema=1;token=[Guid]::NewGuid().ToString('N');case='Baseline';config_sha256='';baseline_collected=$false;failure_started=$false;failure_collected=$false;restored=$false}
    $instance=Join-Path $root ($state.token+'\Instance');$null=New-Item -ItemType Directory -Path (Join-Path $instance 'Nomad')
    $launcher=Join-Path $instance 'Nomad-Helium.exe';$configPath=Join-Path $instance 'Nomad\nomad.toml'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Nomad-Helium.exe') -Destination $launcher
    [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
    $release=Invoke-RestMethod -Uri 'https://api.github.com/repos/imputnet/helium-windows/releases/tags/0.19.2.1' -Headers @{'User-Agent'='Nomad-Sandbox-DNS-Qualification'}
    $asset=@($release.assets | Where-Object name -CEQ 'helium_0.19.2.1_x64-windows.zip')
    $url='https://github.com/imputnet/helium-windows/releases/download/0.19.2.1/helium_0.19.2.1_x64-windows.zip';$hash='8623c04201a0a45a97920c7acdaa3a9f022260c66d6dfe78e7dcb323d4d2d89c'
    if($release.tag_name -cne '0.19.2.1' -or $asset.Count -ne 1 -or $asset[0].browser_download_url -cne $url -or $asset[0].digest -cne ('sha256:'+$hash)){throw 'Reviewed upstream metadata changed; no browser launched.'}
    $time=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    [IO.File]::WriteAllText((Join-Path $instance 'Nomad\nomad-version-cache.toml'),"fetched_at = $time`ntarget = `"x64`"`nbrowser_version = `"0.19.2.1`"`nengine_version = `"0.19.2.1`"`ndownload_url = `"$url`"`nsha256 = `"$hash`"`n",$utf8)
    Write-DnsConfig Baseline $true
    Start-DnsLauncher
    Write-Host 'LOCAL UNSIGNED DNS TEST. Nomad downloads/verifies reviewed Helium inside this guest.'
    Write-Host ('Public probe URL: https://nomad-'+$state.token+'-baseline.example.com/')
    Write-Host 'A DNS error page is acceptable: the probe tests the DNS transport, not a working website.'
    Write-Host 'Leave Helium services setup untouched; do not sign in or browse personal sites. Raw NetLog stays in the guest.'
    Write-Host 'After the probe settles, close ALL Helium windows normally, then run this helper with -Phase CollectBaseline.'
    exit
}
$state=Read-RIJson $statePath 65536
if($state.schema -ne 1 -or $state.token -cnotmatch '^[a-f0-9]{32}$' -or $state.case -cnotin @('Baseline','Failure')){throw 'Invalid owned DNS test state.'}
$instance=Join-Path $root ($state.token+'\Instance');Assert-RIPlain $instance
$launcher=Join-Path $instance 'Nomad-Helium.exe';$image=Join-Path $instance 'Browser\chrome.exe';$configPath=Join-Path $instance 'Nomad\nomad.toml';$localPath=Join-Path $instance 'Data\Local State'
if((Get-FileHash -LiteralPath $launcher).Hash -cne $manifest.launcher_sha256 -or (Get-FileHash -LiteralPath $configPath).Hash -cne $state.config_sha256){throw 'Launcher/helper-owned config changed.'}
if($Phase -ceq 'Status'){
    Write-Host ('Read-only: browser process count '+@(Get-DnsBrowsers).Count+'; case '+$state.case)
    $local=Get-DnsLocal;Write-Host ('Saved DNS mode: '+$local.dns_over_https.mode)
    if($local.dns_over_https.templates -cin @('https://dns.quad9.net/dns-query','https://127.0.0.1:9/dns-query')){Write-Host ('Saved test resolver: '+$local.dns_over_https.templates)}else{Write-Host 'Saved resolver differs; it is not printed.'}
    Write-Host 'Saved values do not prove actual DNS traffic.';exit
}
if($Phase -ceq 'FailClosed'){
    throw 'Prelaunch resolver mutation is not a valid outage test: Nomad re-enforces Quad9. Existing captures and restore remain available; do not repeat this fixture.'
}
if($Phase -ceq 'Restore'){
    if(-not $state.failure_started -or $state.restored){throw 'No pending helper-owned resolver override to restore.'}
    if(@(Get-DnsBrowsers).Count){throw 'Close Helium normally before restoring the test choice.'}
    $local=Get-DnsLocal
    # An earlier refusal may have recorded intent without applying the override.
    if($local.dns_over_https.mode -cne 'secure' -or $local.dns_over_https.templates -cne 'https://dns.quad9.net/dns-query'){
        Set-TestDns 'https://127.0.0.1:9/dns-query' 'https://dns.quad9.net/dns-query'
    }
    $state.restored=$true;Save-DnsJson $statePath $state
    Write-Host 'Restored/confirmed the original Quad9 test choice in the closed disposable profile. No browser restarted.';exit
}
$case=if($Phase -ceq 'CollectBaseline'){'Baseline'}else{'Failure'}
if($state.case -cne $case -or ($case -ceq 'Failure' -and -not $state.failure_started)){throw 'Wrong collection phase.'}
if(@(Get-DnsBrowsers).Count){throw 'Close all Helium windows before collecting the finalized NetLog.'}
$raw=Join-Path $instance ($case+'.netlog.json');Assert-RIPlain $raw
$stream=$null
try{
    # Deny concurrent writers while reading the finalized capture; never hash a live file.
    $stream=[IO.File]::Open($raw,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    if($stream.Length -gt 33554432){throw 'Raw NetLog exceeds 32 MiB; preserved in guest.'}
    $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
    while($offset -lt $bytes.Length){$read=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($read -le 0){throw 'Truncated raw capture.'};$offset+=$read}
    $text=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes).TrimStart([char]0xFEFF)
}catch{throw 'NetLog is missing, still held, oversized or incomplete; preserve the guest and send this message.'}finally{if($stream){$stream.Dispose()}}
$probe='nomad-'+$state.token+'-'+$case.ToLowerInvariant()+'.example.com'
try{$netlog=$text | ConvertFrom-Json -ErrorAction Stop;$observation=Get-DnsObservation $netlog $probe $case}catch{throw 'Finalized NetLog schema/event correlation could not be parsed; no DNS success claimed. Raw capture remains in guest.'}
$local=Get-DnsLocal
$expected=if($case -ceq 'Baseline'){'https://dns.quad9.net/dns-query'}else{'https://127.0.0.1:9/dns-query'}
$observation | Add-Member -NotePropertyName saved_test_dns_matches -NotePropertyValue ($local.dns_over_https.mode -ceq 'secure' -and $local.dns_over_https.templates -ceq $expected)
$algorithm=[Security.Cryptography.SHA256]::Create()
try{$rawHash=[BitConverter]::ToString($algorithm.ComputeHash($bytes)).Replace('-','')}finally{$algorithm.Dispose()}
$observation | Add-Member -NotePropertyName raw_capture_sha256 -NotePropertyValue $rawHash
$observation | Add-Member -NotePropertyName raw_capture_bytes -NotePropertyValue $bytes.Length
$observation | Add-Member -NotePropertyName base_commit -NotePropertyValue $manifest.base_commit
$observation | Add-Member -NotePropertyName source_tree_sha256 -NotePropertyValue $manifest.source_tree_sha256
$observation | Add-Member -NotePropertyName launcher_sha256 -NotePropertyValue $manifest.launcher_sha256
Assert-RIPlain 'C:\NomadDnsOutput'
$exportToken=[Guid]::NewGuid().ToString('N');$out=Join-Path 'C:\NomadDnsOutput' ($case.ToLowerInvariant()+'-'+$state.token+'-'+$exportToken)
if(-not(Test-Path -LiteralPath 'C:\NomadDnsOutput' -PathType Container)-or(Test-Path -LiteralPath $out)){throw 'Dedicated fresh output mapping required.'}
$null=New-Item -ItemType Directory -Path $out
Save-DnsJson (Join-Path $out 'OBSERVATION.json') $observation -New
$receipt=@{schema=1;case=$case;token=$state.token;export_token=$exportToken;base_commit=$manifest.base_commit;source_tree_sha256=$manifest.source_tree_sha256;launcher_sha256=$manifest.launcher_sha256;files=@(@{name='OBSERVATION.json';bytes=(Get-Item -LiteralPath (Join-Path $out 'OBSERVATION.json')).Length;sha256=(Get-FileHash -LiteralPath (Join-Path $out 'OBSERVATION.json')).Hash});scope='Selected DNS observations only; raw log/profile not exported';os_version=[Environment]::OSVersion.Version.ToString()}
Save-DnsJson (Join-Path $out 'GUEST-RECEIPT.json') $receipt -New
if($case -ceq 'Baseline'){$state.baseline_collected=$true}else{$state.failure_collected=$true}
Save-DnsJson $statePath $state
Write-Host ('DNS OBSERVATION: '+$observation.status)
Write-Host ('Target transactions: '+$observation.target_transactions+'; correlated DoH attempts: '+$observation.correlated_doh_attempts+'; saved test DNS matches: '+$observation.saved_test_dns_matches)
Write-Host "EVIDENCE EXPORTED: $out. Raw NetLog remains in guest; keep Sandbox open for host verification."
if($case -ceq 'Failure'){Write-Host 'Restore the guest test choice next with -Phase Restore. Do not close Sandbox until host evidence verification.'}else{Write-Host 'Send this output before changing DNS or closing Sandbox.'}
