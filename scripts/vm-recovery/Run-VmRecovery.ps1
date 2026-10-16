[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Origin','PeerUser','ForeignMachine','ReturnOrigin')][string]$Phase,
      [switch]$AcknowledgeDisposableVm,[string]$OriginBundleSha256='')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
# Refuse before reading identity, creating fixtures, invoking DPAPI or starting a child.
if(-not $AcknowledgeDisposableVm -or $PSScriptRoot -cne 'C:\NomadVmRecoveryInput' -or $env:USERNAME -cnotin @('NomadRecoverySource','NomadRecoveryPeer','NomadRecoveryForeign')){throw 'Explicit independently initialized disposable VM only; never run on the personal host or fake Sandbox identity.'}
if($env:PROCESSOR_ARCHITECTURE -cne 'AMD64'){throw 'Use native x64 Windows PowerShell in the disposable x64 VM.'}
. (Join-Path $PSScriptRoot 'VmRecovery.Common.ps1')
$enrollment=Read-VmJson (Join-Path $PSScriptRoot 'DISPOSABLE-VM.json') 4096
Assert-VmEnrollment $enrollment $Phase $env:USERNAME $env:USERDOMAIN $env:COMPUTERNAME $env:USERPROFILE
$up=@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|Where-Object {$_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -notin @('Loopback','Tunnel')})
$routes=@(Get-NetRoute -ErrorAction Stop|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')});if($up.Count -or $routes.Count){throw 'Disconnect disposable VM network adapters before qualification.'}
$build=Test-VmBuild $PSScriptRoot;if($build.campaign -cne $enrollment.campaign){throw 'Enrollment does not match this prepared campaign.'}
$harness=Join-Path $PSScriptRoot 'NativeVmRecoveryTests.exe';$harnessHash=Get-VmHash $harness
$bundle=$null;if($Phase -cne 'Origin'){$bundle=Test-VmOriginBundle 'C:\NomadVmRecoveryOrigin' $OriginBundleSha256 $build.campaign $harnessHash}
$root=Join-Path $env:USERPROFILE ('AppData\Local\NomadVmRecoveryQualification\'+$build.campaign+'\'+$Phase);Assert-VmPlainPath $root;if(Test-Path -LiteralPath $root){throw 'Existing native result preserved; do not overwrite or rerun in this campaign.'}
$null=New-Item -ItemType Directory -Path $root;Write-VmNew (Join-Path $root 'OWNER.txt') ("Nomad independent VM binding fixture v1`n"+$build.campaign+"`n"+$Phase+"`n")
. (Join-Path $PSScriptRoot 'Invoke-RecoveryProcess.ps1')
$oldPhase=[Environment]::GetEnvironmentVariable('NOMAD_VM_RECOVERY_PHASE','Process');$oldBundle=[Environment]::GetEnvironmentVariable('NOMAD_VM_RECOVERY_BUNDLE_SHA256','Process')
$exitCode=$null;$failure=$null
try{
    $env:NOMAD_VM_RECOVERY_PHASE=$Phase;$env:NOMAD_VM_RECOVERY_BUNDLE_SHA256=$OriginBundleSha256
    $exitCode=Invoke-RecoveryFixtureProcess -FilePath $harness -Arguments '--exact cleanup_recovery::vm_binding_tests::qualify_enrolled_vm_binding --ignored --nocapture --test-threads=1' -StdoutPath (Join-Path $root 'native-stdout.txt') -StderrPath (Join-Path $root 'native-stderr.txt') -TimeoutSeconds 180
}catch{$failure=$_.Exception.Message}finally{
    [Environment]::SetEnvironmentVariable('NOMAD_VM_RECOVERY_PHASE',$oldPhase,'Process');[Environment]::SetEnvironmentVariable('NOMAD_VM_RECOVERY_BUNDLE_SHA256',$oldBundle,'Process')
}
if($Phase -cne 'Origin'){$null=Test-VmOriginBundle 'C:\NomadVmRecoveryOrigin' $OriginBundleSha256 $build.campaign $harnessHash}
$files=@();$names=@('RESULT.json','native-stdout.txt','native-stderr.txt');if($Phase -ceq 'Origin'){$names+=@('Transfer/BUNDLE-INDEX.json','Transfer/journal.bin','Transfer/machine.bin','Transfer/nested.bin','Transfer/origin.json','Transfer/user.bin')}
foreach($name in $names){$path=Join-Path $root $name;if(Test-Path -LiteralPath $path){Assert-VmPlainPath $path;$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer -or $item.Length -gt 65536){throw 'Oversized native evidence preserved; no pass claimed.'};$files+=@{name=$name;bytes=$item.Length;sha256=(Get-VmHash $path)}}}
$indexHash=if($Phase -ceq 'Origin' -and (Test-Path -LiteralPath (Join-Path $root 'Transfer/BUNDLE-INDEX.json'))){Get-VmHash (Join-Path $root 'Transfer/BUNDLE-INDEX.json')}else{$OriginBundleSha256}
$receipt=@{schema=1;phase=$Phase;campaign=$build.campaign;base_commit=$build.base_commit;source_tree_sha256=$build.source_tree_sha256;build_manifest_sha256=(Get-VmHash (Join-Path $PSScriptRoot 'BUILD-MANIFEST.json'));harness_sha256=$harnessHash;bundle_index_sha256=$indexHash;enrollment=$enrollment;os_version=[Environment]::OSVersion.Version.ToString();nonloopback_interfaces=$up.Count;default_routes=$routes.Count;exit_code=$exitCode;failure=$failure;files=$files}
Write-VmNew (Join-Path $root 'RECEIPT.json') ($receipt|ConvertTo-Json -Depth 10)
. (Join-Path $PSScriptRoot 'Verify-VmRecovery.ps1')
$verified=Test-VmRecoveryPhaseEvidence -InputDirectory $PSScriptRoot -OutputDirectory $root
Write-Host "SCOPED VM PHASE PASSED: $Phase; receipt: $root\RECEIPT.json"
Write-Host "Origin bundle index SHA256: $indexHash"
Write-Host 'Copy only the allowlisted selected evidence; independent host verification is still required. No browser, host trace cleanup or key export occurred.'
