# Authored metadata only; never calls DPAPI, creates users/VMs, or runs the native harness.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'vm-recovery/Verify-VmRecovery.ps1')
$root=Join-Path ([IO.Path]::GetTempPath()) ('nomad-vm-recovery-metadata-'+[Guid]::NewGuid().ToString('N'));$utf8=New-Object Text.UTF8Encoding($false)
function Save([string]$Path,$Value){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 14),$utf8)}
function Reject([scriptblock]$Code){$failed=$false;try{$null=& $Code}catch{$failed=$true};if(-not $failed){throw 'Unsafe VM metadata or enrollment accepted.'}}
function Clone($Value){$Value|ConvertTo-Json -Depth 14|ConvertFrom-Json}
function Rehash([string]$Directory,$Receipt){foreach($file in $Receipt.files){$p=Join-Path $Directory $file.name;$file.bytes=(Get-Item -LiteralPath $p).Length;$file.sha256=Get-VmHash $p};Save (Join-Path $Directory 'RECEIPT.json') $Receipt}
try{
    $fixtureInput=Join-Path $root 'Input';$null=New-Item -ItemType Directory -Path $fixtureInput
    foreach($name in @('NativeVmRecoveryTests.exe','Run-VmRecovery.ps1','VmRecovery.Common.ps1','Verify-VmRecovery.ps1','Invoke-RecoveryProcess.ps1')){[IO.File]::WriteAllText((Join-Path $fixtureInput $name),('INERT metadata only '+$name),$utf8)}
    $files=@();foreach($item in @(Get-ChildItem -LiteralPath $fixtureInput -File)){$files+=@{name=$item.Name;bytes=$item.Length;sha256=(Get-VmHash $item.FullName)}}
    $build=[pscustomobject]@{schema=1;campaign=('a'*32);base_commit=('b'*40);source_tree_sha256=('C'*64);target='x86_64-pc-windows-msvc';input_files=$files};Save (Join-Path $fixtureInput 'BUILD-MANIFEST.json') $build
    $harness=Get-VmHash (Join-Path $fixtureInput 'NativeVmRecoveryTests.exe');$bundle=Join-Path $root 'Origin/Transfer';$null=New-Item -ItemType Directory -Path $bundle
    $originContext=[pscustomobject]@{machine=('a'*64);user=('b'*64)}
    foreach($name in @('journal.bin','machine.bin','nested.bin','user.bin')){[IO.File]::WriteAllText((Join-Path $bundle $name),('INERT public metadata '+$name),$utf8)}
    Save (Join-Path $bundle 'origin.json') ([pscustomobject]@{schema=1;campaign=$build.campaign;context=$originContext})
    $entries=@();foreach($name in @('journal.bin','machine.bin','nested.bin','origin.json','user.bin')){$p=Join-Path $bundle $name;$entries+=@{name=$name;bytes=(Get-Item -LiteralPath $p).Length;sha256=(Get-VmHash $p).ToLowerInvariant()}}
    $index=[pscustomobject]@{schema=1;campaign=$build.campaign;harness_sha256=$harness.ToLowerInvariant();files=$entries};$indexPath=Join-Path $bundle 'BUNDLE-INDEX.json';Save $indexPath $index;$indexHash=Get-VmHash $indexPath
    $enrollment=[pscustomobject]@{schema=1;campaign=$build.campaign;environment='independently_initialized_disposable_windows_vm';machine_role='origin';independently_initialized=$true;no_personal_data=$true}
    Assert-VmEnrollment $enrollment 'Origin' 'NomadRecoverySource' 'vm' 'vm' 'C:\Users\NomadRecoverySource'
    foreach($user in @('WDAGUtilityAccount','PersonalUser','Administrator')){Reject {Assert-VmEnrollment $enrollment 'Origin' $user 'vm' 'vm' ('C:\Users\'+$user)}}
    Reject {Assert-VmEnrollment $enrollment 'Origin' 'NomadRecoverySource' 'domain' 'vm' 'C:\Users\NomadRecoverySource'}
    Reject {Assert-VmEnrollment $enrollment 'Origin' 'NomadRecoverySource' 'vm' 'vm' 'C:\Users\SomeoneElse'}
    foreach($key in @('independently_initialized','no_personal_data')){foreach($value in @($false,'true')){$bad=Clone $enrollment;$bad.$key=$value;Reject {Assert-VmEnrollment $bad 'Origin' 'NomadRecoverySource' 'vm' 'vm' 'C:\Users\NomadRecoverySource'}}}
    foreach($token in @('../escape',('a'*31),('A'*32))){$bad=Clone $enrollment;$bad.campaign=$token;Reject {Assert-VmEnrollment $bad 'Origin' 'NomadRecoverySource' 'vm' 'vm' 'C:\Users\NomadRecoverySource'}}
    Reject {Assert-VmEnrollment $enrollment 'ForeignMachine' 'NomadRecoverySource' 'vm' 'vm' 'C:\Users\NomadRecoverySource'}
    $null=Test-VmOriginBundle $bundle $indexHash $build.campaign $harness
    Reject {Test-VmOriginBundle $bundle ('0'*64) $build.campaign $harness};Reject {Test-VmOriginBundle $bundle $indexHash ('c'*32) $harness};Reject {Test-VmOriginBundle $bundle $indexHash $build.campaign ('D'*64)}
    foreach($unsafe in @('../outside','NUL','machine.bin')){$bad=Clone $index;$bad.files[0].name=$unsafe;Save $indexPath $bad;Reject {Test-VmOriginBundle $bundle (Get-VmHash $indexPath) $build.campaign $harness}}
    Save $indexPath $index
    $alias=Join-Path $root 'linked-bundle';$null=New-Item -ItemType Junction -Path $alias -Target $bundle
    try{Reject {Test-VmOriginBundle $alias $indexHash $build.campaign $harness};if(-not(Test-Path -LiteralPath (Join-Path $bundle 'journal.bin'))){throw 'Linked fixture target changed.'}}finally{if(-not ((Get-Item -LiteralPath $alias -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Expected owned fixture junction.'};[IO.Directory]::Delete($alias)}
    $phaseDirectories=@{}
    foreach($phase in @('Origin','PeerUser','ForeignMachine','ReturnOrigin')){
        $directory=Join-Path $root $phase;$phaseDirectories[$phase]=$directory;if(-not(Test-Path -LiteralPath $directory)){$null=New-Item -ItemType Directory -Path $directory}
        $context=switch($phase){'Origin'{$originContext};'PeerUser'{[pscustomobject]@{machine=('a'*64);user=('c'*64)}};'ForeignMachine'{[pscustomobject]@{machine=('d'*64);user=('e'*64)}};'ReturnOrigin'{$originContext}}
        $returning=$phase -ceq 'ReturnOrigin';$peer=$phase -ceq 'PeerUser'
        $result=[ordered]@{schema=1;campaign=$build.campaign;phase=$phase;context=$context;scope='public payload and inert journal only; no host trace scanner invoked';qualified=$true}
        if($phase -ceq 'Origin'){$result.roundtrip=$true;$result.intent_retained=$true}else{
            $result.origin_context=$originContext;$result.same_machine=($returning -or $peer);$result.same_user=$returning
            foreach($key in @('nested_payload_opened','user_payload_opened')){$result[$key]=$returning}
            foreach($key in @('nested_payload_refused','user_payload_refused','journal_ciphertext_refused')){$result[$key]=(-not $returning)}
            $result.machine_payload_opened=($returning -or $peer);$result.machine_payload_refused=(-not ($returning -or $peer));$result.retired=if($returning){1}else{0};$result.retained=if($returning){0}else{1};if(-not $returning){$result.intent_bytes_unchanged=$true}
        }
        Save (Join-Path $directory 'RESULT.json') $result;[IO.File]::WriteAllText((Join-Path $directory 'native-stdout.txt'),'AUTHORED METADATA, NOT NATIVE. test result: ok. 1 passed; 0 failed;',$utf8);[IO.File]::WriteAllText((Join-Path $directory 'native-stderr.txt'),'',$utf8)
        $names=@('RESULT.json','native-stdout.txt','native-stderr.txt');if($phase -ceq 'Origin'){$names+=@('Transfer/BUNDLE-INDEX.json','Transfer/journal.bin','Transfer/machine.bin','Transfer/nested.bin','Transfer/origin.json','Transfer/user.bin')}
        $inventory=@();foreach($name in $names){$p=Join-Path $directory $name;$inventory+=@{name=$name;bytes=(Get-Item -LiteralPath $p).Length;sha256=(Get-VmHash $p)}}
        $e=Clone $enrollment;if($phase -ceq 'ForeignMachine'){$e.machine_role='foreign'}
        $receipt=[pscustomobject]@{schema=1;phase=$phase;campaign=$build.campaign;base_commit=$build.base_commit;source_tree_sha256=$build.source_tree_sha256;build_manifest_sha256=(Get-VmHash (Join-Path $fixtureInput 'BUILD-MANIFEST.json'));harness_sha256=$harness;bundle_index_sha256=$indexHash;enrollment=$e;os_version='10.0.26100.0';nonloopback_interfaces=0;default_routes=0;exit_code=0;failure=$null;files=$inventory};Save (Join-Path $directory 'RECEIPT.json') $receipt
        $null=Test-VmRecoveryPhaseEvidence $fixtureInput $directory
    }
    $matrix=Test-VmRecoveryMatrix $fixtureInput $phaseDirectories.Origin $phaseDirectories.PeerUser $phaseDirectories.ForeignMachine $phaseDirectories.ReturnOrigin
    if(-not $matrix.scoped_binding_matrix_verified -or $matrix.phases.Count -ne 4){throw 'Valid authored matrix refused.'}
    $peerDir=$phaseDirectories.PeerUser;$original=Read-VmJson (Join-Path $peerDir 'RECEIPT.json');$resultOriginal=Read-VmJson (Join-Path $peerDir 'RESULT.json')
    foreach($badExit in @($null,$false,101)){$bad=Clone $original;$bad.exit_code=$badExit;Save (Join-Path $peerDir 'RECEIPT.json') $bad;Reject {Test-VmRecoveryPhaseEvidence $fixtureInput $peerDir}}
    Save (Join-Path $peerDir 'RECEIPT.json') $original
    foreach($key in @('qualified','intent_bytes_unchanged','nested_payload_refused')){$bad=Clone $resultOriginal;$bad.$key='true';Save (Join-Path $peerDir 'RESULT.json') $bad;$receipt=Clone $original;Rehash $peerDir $receipt;Reject {Test-VmRecoveryPhaseEvidence $fixtureInput $peerDir}}
    foreach($key in @('nested_payload_opened','machine_payload_refused')){$bad=Clone $resultOriginal;$bad.$key=$true;Save (Join-Path $peerDir 'RESULT.json') $bad;$receipt=Clone $original;Rehash $peerDir $receipt;Reject {Test-VmRecoveryPhaseEvidence $fixtureInput $peerDir}}
    $bad=Clone $resultOriginal;$bad.context.machine=('f'*64);Save (Join-Path $peerDir 'RESULT.json') $bad;$receipt=Clone $original;Rehash $peerDir $receipt;Reject {Test-VmRecoveryPhaseEvidence $fixtureInput $peerDir}
    Save (Join-Path $peerDir 'RESULT.json') $resultOriginal;Save (Join-Path $peerDir 'RECEIPT.json') $original
    foreach($unsafe in @('../outside','RESULT.json.','native-stdout.txt')){$bad=Clone $original;$bad.files[0].name=$unsafe;Save (Join-Path $peerDir 'RECEIPT.json') $bad;Reject {Test-VmRecoveryPhaseEvidence $fixtureInput $peerDir}}
    $bad=Clone $original;$bad.bundle_index_sha256=('F'*64);Save (Join-Path $peerDir 'RECEIPT.json') $bad;Reject {Test-VmRecoveryMatrix $fixtureInput $phaseDirectories.Origin $peerDir $phaseDirectories.ForeignMachine $phaseDirectories.ReturnOrigin};Save (Join-Path $peerDir 'RECEIPT.json') $original
    Reject {Test-VmRecoveryMatrix $fixtureInput $phaseDirectories.Origin $peerDir $peerDir $phaseDirectories.ReturnOrigin}
    [IO.File]::AppendAllText((Join-Path $bundle 'journal.bin'),'changed');Reject {Test-VmOriginBundle $bundle $indexHash $build.campaign $harness}
    # Real runner must refuse the ordinary host before any native child/key operation.
    Reject {& (Join-Path $PSScriptRoot 'vm-recovery/Run-VmRecovery.ps1') -Phase Origin -AcknowledgeDisposableVm}
    foreach($name in @('vm-recovery/Run-VmRecovery.ps1','vm-recovery/VmRecovery.Common.ps1','vm-recovery/Verify-VmRecovery.ps1','prepare-recovery-isolation.ps1')){$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$errors);if(@($errors).Count){throw ('VM script syntax failed: '+$name)}}
    Write-Host 'Independent VM preparation safety fixtures passed: authored metadata only; native DPAPI/VM qualification NOT run.'
}finally{
    $resolved=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    if(-not $resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolved) -cnotmatch '^nomad-vm-recovery-metadata-[a-f0-9]{32}$'){throw 'Owned metadata cleanup boundary failed.'}
    if(Test-Path -LiteralPath $resolved){Assert-VmPlainPath $resolved;Remove-Item -LiteralPath $resolved -Recurse -Force}
}
