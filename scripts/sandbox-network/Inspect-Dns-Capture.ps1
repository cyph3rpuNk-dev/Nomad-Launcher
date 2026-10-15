# Read-only diagnostic. No raw values, URLs, messages or profile data are printed.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($env:USERNAME -cne 'WDAGUtilityAccount' -or $env:USERPROFILE -cne 'C:\Users\WDAGUtilityAccount' -or $PSScriptRoot -cne 'C:\NomadInput\DnsDiagnostics'){throw 'Disposable guest diagnostic only.'}
. 'C:\NomadInput\Recovery-Integration-Helpers.ps1'
. 'C:\NomadInput\Analyze-Dns-NetLog.ps1'
$build=Read-RIJson 'C:\NomadInput\BUILD-MANIFEST.json'
foreach($entry in $build.input_files){
    if($entry.name -cnotin @('Nomad-Helium.exe','Run-Helium-Dns.ps1','Analyze-Dns-NetLog.ps1','Recovery-Integration-Helpers.ps1')){throw 'Unexpected input inventory.'}
    $path=Join-Path 'C:\NomadInput' $entry.name;Assert-RIPlain $path
    if((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $path).Hash -cne $entry.sha256){throw 'Frozen input changed.'}
}
$state=Read-RIJson 'C:\NomadDnsQualification\STATE.json' 65536
if($state.token -cnotmatch '^[a-f0-9]{32}$' -or $state.case -cnotin @('Baseline','Failure')){throw 'Invalid public test state.'}
$instance='C:\NomadDnsQualification\'+$state.token+'\Instance'
$image=Join-Path $instance 'Browser\chrome.exe'
if(@(Get-Process -Name chrome -ErrorAction SilentlyContinue).Count){throw 'Close all Helium windows normally before inspecting the finalized capture.'}
$raw=Join-Path $instance ($state.case+'.netlog.json');Assert-RIPlain $raw
$stream=$null
try{
    $stream=[IO.File]::Open($raw,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    if($stream.Length -gt 33554432){throw 'Capture exceeds diagnostic bound; preserved.'}
    $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
    while($offset -lt $bytes.Length){$read=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($read -le 0){throw 'Incomplete capture; preserved.'};$offset+=$read}
    $text=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes).TrimStart([char]0xFEFF)
}finally{if($stream){$stream.Dispose()}}
Write-Host 'READ-ONLY DNS DIAGNOSTIC: no launch, DNS/profile write, cleanup or raw export.'
Write-Host ('PowerShell: '+$PSVersionTable.PSVersion.ToString()+'; capture bytes: '+$bytes.Length+'; case: '+$state.case)
try{$log=ConvertFrom-Json -InputObject $text -ErrorAction Stop}catch{
    Write-Host 'JSON conversion: FAILED. Raw exception text suppressed.'
    Write-Host ('Exception type: '+$_.Exception.GetType().FullName);exit
}
Write-Host 'JSON conversion: PASSED'
$types=Get-DnsField (Get-DnsField $log 'constants') 'logEventTypes'
$phases=Get-DnsField (Get-DnsField $log 'constants') 'logEventPhase'
$events=Get-DnsField $log 'events'
Write-Host ('Event dictionary present: '+($null -ne $types)+'; phase dictionary present: '+($null -ne $phases)+'; event count: '+@($events).Count)
$probe='nomad-'+$state.token+'-'+$state.case.ToLowerInvariant()+'.example.com'
try{
    $null=Get-DnsObservation $log $probe $state.case
    Write-Host 'Frozen parser: COMPLETED. No DNS pass is recorded by this diagnostic.'
}catch{
    $safe=@('Only the public test probe is accepted.','Case/probe mismatch.','Missing NetLog symbol dictionaries.','Invalid/duplicate event symbol.','Invalid phase symbols.','Missing/oversized event inventory.','Invalid event identity or phase.','Selected DNS/request event has no source identity.','Selected observation budget exceeded.')
    if($_.Exception.Message -cin $safe){Write-Host ('Frozen parser refusal: '+$_.Exception.Message)}else{
        Write-Host 'Frozen parser runtime error; raw exception text suppressed.'
        Write-Host ('Exception type: '+$_.Exception.GetType().FullName+'; parser line: '+$_.InvocationInfo.ScriptLineNumber)
    }
}
Write-Host 'Send only this console output. Raw capture remains in guest; keep Sandbox open.'
