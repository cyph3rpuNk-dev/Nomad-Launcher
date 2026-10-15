# Existing guest capture only. Separate corrected analyzer provenance; original inputs stay frozen.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($env:USERNAME -cne 'WDAGUtilityAccount' -or $env:USERPROFILE -cne 'C:\Users\WDAGUtilityAccount' -or $PSScriptRoot -cne 'C:\NomadInput\DnsCorrection'){throw 'Existing disposable Sandbox only.'}
$inputRoot='C:\NomadInput'
. (Join-Path $inputRoot 'Recovery-Integration-Helpers.ps1')
$build=Read-RIJson (Join-Path $inputRoot 'BUILD-MANIFEST.json')
$correctionPath=Join-Path $PSScriptRoot 'CORRECTION-MANIFEST.json'
$correction=Read-RIJson $correctionPath 16384
if($build.schema -ne 1 -or $correction.schema -ne 1 -or $correction.original_source_tree_sha256 -cne $build.source_tree_sha256){throw 'Correction/original provenance mismatch.'}
$seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach($entry in $build.input_files){
    if($entry.name -cnotin @('Nomad-Helium.exe','Run-Helium-Dns.ps1','Analyze-Dns-NetLog.ps1','Recovery-Integration-Helpers.ps1') -or -not $seen.Add($entry.name)){throw 'Unexpected original inputs.'}
    $path=Join-Path $inputRoot $entry.name;Assert-RIPlain $path
    if((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.sha256){throw 'Original frozen input changed.'}
}
if($seen.Count -ne 4){throw 'Incomplete original input inventory.'}
$seen.Clear()
foreach($entry in $correction.files){
    if($entry.name -cnotin @('Analyze-Dns-NetLog.ps1','Recollect-Dns-Baseline.ps1') -or -not $seen.Add($entry.name)){throw 'Unexpected correction inputs.'}
    $path=Join-Path $PSScriptRoot $entry.name;Assert-RIPlain $path
    if((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.sha256){throw 'Correction input changed.'}
}
if($seen.Count -ne 2){throw 'Incomplete correction inputs.'}
$root='C:\NomadDnsQualification';$statePath=Join-Path $root 'STATE.json'
$state=Read-RIJson $statePath 65536
if($state.schema -ne 1 -or $state.token -cnotmatch '^[a-f0-9]{32}$' -or $state.case -cne 'Baseline' -or $state.failure_started -isnot [bool] -or $state.failure_started -or $state.baseline_collected -isnot [bool] -or $state.baseline_collected){throw 'Only the uncollected original baseline is accepted.'}
if(@(Get-Process -Name chrome -ErrorAction SilentlyContinue).Count){throw 'Close all Helium windows normally; no process is stopped.'}
$instance=Join-Path $root ($state.token+'\Instance');$launcher=Join-Path $instance 'Nomad-Helium.exe';$configPath=Join-Path $instance 'Nomad\nomad.toml'
foreach($path in @($instance,$launcher,$configPath)){Assert-RIPlain $path}
if((Get-FileHash -LiteralPath $launcher).Hash -cne $build.launcher_sha256 -or (Get-FileHash -LiteralPath $configPath).Hash -cne $state.config_sha256){throw 'Owned launcher/config changed.'}
$raw=Join-Path $instance 'Baseline.netlog.json';Assert-RIPlain $raw;$stream=$null
try{
    $stream=[IO.File]::Open($raw,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    if($stream.Length -gt 33554432){throw 'Capture exceeds bound; preserved.'}
    $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
    while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($count -le 0){throw 'Incomplete capture; preserved.'};$offset+=$count}
    $text=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes).TrimStart([char]0xFEFF)
}finally{if($stream){$stream.Dispose()}}
try{$log=ConvertFrom-Json -InputObject $text -ErrorAction Stop}catch{throw 'Capture JSON conversion failed; raw exception suppressed; preserved.'}
$probe='nomad-'+$state.token+'-baseline.example.com'
. (Join-Path $inputRoot 'Analyze-Dns-NetLog.ps1')
$negativeCount=0
foreach($event in (Get-DnsField $log 'events')){$id=Get-DnsField (Get-DnsField $event 'source') 'id';if((Test-DnsInteger $id) -and $id -lt 0){$negativeCount++}}
$originalIdentityRefusal=$false
try{$null=Get-DnsObservation $log $probe Baseline}catch{$originalIdentityRefusal=$_.Exception.Message -ceq 'Invalid event identity or phase.'}
. (Join-Path $PSScriptRoot 'Analyze-Dns-NetLog.ps1')
Write-Host ('Existing capture: negative source-ID events '+$negativeCount+'; original identity refusal '+$originalIdentityRefusal)
try{$result=Get-DnsObservation $log $probe Baseline}catch{
    $safe=@('Only the public test probe is accepted.','Case/probe mismatch.','Missing NetLog symbol dictionaries.','Invalid/duplicate event symbol.','Invalid phase symbols.','Missing/oversized event inventory.','Invalid event identity or phase.','Selected DNS/request event has no source identity.','Selected observation budget exceeded.')
    if($_.Exception.Message -cin $safe){Write-Host ('Corrected parser refusal: '+$_.Exception.Message)}else{Write-Host ('Corrected parser error type: '+$_.Exception.GetType().FullName+'; line: '+$_.InvocationInfo.ScriptLineNumber)}
    throw 'No corrected observation recorded; keep guest/raw capture intact.'
}
$local=Read-RIJson (Join-Path $instance 'Data\Local State') 1048576
$dns=Get-DnsField $local 'dns_over_https'
$result|Add-Member -NotePropertyName saved_test_dns_matches -NotePropertyValue ((Get-DnsField $dns 'mode') -ceq 'secure' -and (Get-DnsField $dns 'templates') -ceq 'https://dns.quad9.net/dns-query')
$algorithm=[Security.Cryptography.SHA256]::Create()
try{$rawHash=[BitConverter]::ToString($algorithm.ComputeHash($bytes)).Replace('-','')}finally{$algorithm.Dispose()}
foreach($key in @('base_commit','source_tree_sha256','launcher_sha256')){$result|Add-Member -NotePropertyName $key -NotePropertyValue $build.$key}
$result|Add-Member -NotePropertyName raw_capture_sha256 -NotePropertyValue $rawHash
$result|Add-Member -NotePropertyName raw_capture_bytes -NotePropertyValue $bytes.Length
$correctionHash=(Get-FileHash -LiteralPath $correctionPath).Hash
$result|Add-Member -NotePropertyName analysis_correction_sha256 -NotePropertyValue $correctionHash
$result|Add-Member -NotePropertyName negative_source_events -NotePropertyValue $negativeCount
$result|Add-Member -NotePropertyName original_identity_refusal -NotePropertyValue $originalIdentityRefusal
$outRoot='C:\NomadDnsOutput';Assert-RIPlain $outRoot
if(-not(Test-Path -LiteralPath $outRoot -PathType Container)){throw 'Dedicated output mapping absent.'}
$exportToken=[Guid]::NewGuid().ToString('N');$out=Join-Path $outRoot ('baseline-'+$state.token+'-'+$exportToken)
if(Test-Path -LiteralPath $out){throw 'Existing output preserved.'}
$null=New-Item -ItemType Directory -Path $out;$utf8=New-Object Text.UTF8Encoding($false)
$observationPath=Join-Path $out 'OBSERVATION.json'
[IO.File]::WriteAllText($observationPath,($result|ConvertTo-Json -Depth 64),$utf8)
$receipt=@{schema=1;case='Baseline';token=$state.token;export_token=$exportToken;base_commit=$build.base_commit;source_tree_sha256=$build.source_tree_sha256;launcher_sha256=$build.launcher_sha256;analysis_correction_sha256=$correctionHash;files=@(@{name='OBSERVATION.json';bytes=(Get-Item -LiteralPath $observationPath).Length;sha256=(Get-FileHash -LiteralPath $observationPath).Hash});scope='Original browser capture, separately hashed corrected analysis; raw/profile not exported';os_version=[Environment]::OSVersion.Version.ToString()}
[IO.File]::WriteAllText((Join-Path $out 'GUEST-RECEIPT.json'),($receipt|ConvertTo-Json -Depth 10),$utf8)
# Only collection bookkeeping changes. No DNS/profile/browser/cleanup action.
$state.baseline_collected=$true;Assert-RIPlain $statePath
[IO.File]::WriteAllText($statePath,($state|ConvertTo-Json -Depth 10),$utf8)
Write-Host ('DNS OBSERVATION: '+$result.status)
Write-Host ('Target transactions: '+$result.target_transactions+'; correlated DoH attempts: '+$result.correlated_doh_attempts+'; saved test DNS matches: '+$result.saved_test_dns_matches)
Write-Host ('EVIDENCE EXPORTED: '+$out)
Write-Host 'Send console output. Keep Sandbox open for host verification; do not run FailClosed yet. Raw capture/profile unchanged.'
