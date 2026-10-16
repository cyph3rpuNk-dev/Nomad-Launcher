# Definitions only. No DPAPI, process, registry, network, or configuration action on import.
Set-StrictMode -Version Latest
function Assert-VmPlainPath([string]$Path) {
    $q=[IO.Path]::GetFullPath($Path)
    while($q){if(Test-Path -LiteralPath $q){if((Get-Item -LiteralPath $q -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked VM input/evidence refused.'}};$parent=[IO.Path]::GetDirectoryName($q);if($parent -eq $q){break};$q=$parent}
}
function Read-VmJson([string]$Path,[long]$Limit=65536) {
    Assert-VmPlainPath $Path;$item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($item.PSIsContainer -or $item.Length -gt $Limit){throw 'Invalid bounded VM JSON.'}
    Get-Content -LiteralPath $Path -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
}
function Write-VmNew([string]$Path,[string]$Text) {
    Assert-VmPlainPath $Path;$bytes=([Text.UTF8Encoding]::new($false)).GetBytes($Text)
    $f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
function Get-VmHash([string]$Path){Assert-VmPlainPath $Path;(Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash}
function Assert-VmShape($Value,[string[]]$Names) {
    if($Value -isnot [pscustomobject] -or (($Value.PSObject.Properties.Name|Sort-Object)-join '|') -cne (($Names|Sort-Object)-join '|')){throw 'Unexpected VM object shape.'}
}
function Assert-VmBool($Value,[bool]$Expected) {if($Value -isnot [bool] -or $Value -ne $Expected){throw 'Missing, mistyped or unexpected VM assertion.'}}
function Assert-VmInteger($Value,[long]$Expected) {if(($Value -isnot [int] -and $Value -isnot [long]) -or $Value -ne $Expected){throw 'Missing, mistyped or unexpected VM count.'}}
function Assert-VmEnrollment($Enrollment,[string]$Phase,[string]$User,[string]$Domain,[string]$Computer,[string]$Profile) {
    Assert-VmShape $Enrollment @('schema','campaign','environment','machine_role','independently_initialized','no_personal_data')
    Assert-VmInteger $Enrollment.schema 1
    if($Enrollment.campaign -cnotmatch '^[a-f0-9]{32}$' -or $Enrollment.environment -cne 'independently_initialized_disposable_windows_vm'){throw 'VM enrollment/campaign refused.'}
    Assert-VmBool $Enrollment.independently_initialized $true;Assert-VmBool $Enrollment.no_personal_data $true
    $expectedUser=switch($Phase){'Origin'{'NomadRecoverySource'};'PeerUser'{'NomadRecoveryPeer'};'ForeignMachine'{'NomadRecoveryForeign'};'ReturnOrigin'{'NomadRecoverySource'};default{throw 'Unknown VM phase.'}}
    $expectedRole=if($Phase -ceq 'ForeignMachine'){'foreign'}else{'origin'}
    if($User -cne $expectedUser -or $Domain -cne $Computer -or $Profile -cne ('C:\Users\'+$expectedUser) -or $Enrollment.machine_role -cne $expectedRole){throw 'Fresh local disposable VM account/role required; never impersonate Sandbox or personal accounts.'}
}
function Test-VmBuild([string]$InputDirectory) {
    $build=Read-VmJson (Join-Path $InputDirectory 'BUILD-MANIFEST.json') 1048576
    Assert-VmInteger $build.schema 1
    if($build.campaign -cnotmatch '^[a-f0-9]{32}$' -or $build.base_commit -cnotmatch '^[a-f0-9]{40}$' -or $build.source_tree_sha256 -cnotmatch '^[A-F0-9]{64}$' -or $build.target -cne 'x86_64-pc-windows-msvc'){throw 'VM build provenance refused.'}
    $names=@('NativeVmRecoveryTests.exe','Run-VmRecovery.ps1','VmRecovery.Common.ps1','Verify-VmRecovery.ps1','Invoke-RecoveryProcess.ps1')
    if(@($build.input_files).Count -ne $names.Count){throw 'Incomplete VM input set.'}
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach($entry in $build.input_files){if($entry.name -cnotin $names -or -not $seen.Add($entry.name) -or ($entry.bytes -isnot [int] -and $entry.bytes -isnot [long]) -or $entry.bytes -le 0 -or $entry.bytes -gt 268435456 -or $entry.sha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'Unsafe VM input entry.'};$p=Join-Path $InputDirectory $entry.name;Assert-VmPlainPath $p;$item=Get-Item -LiteralPath $p -Force;if($item.PSIsContainer -or $item.Length -ne $entry.bytes -or (Get-VmHash $p) -cne $entry.sha256){throw 'VM input bytes changed.'}}
    $build
}
function Test-VmOriginBundle([string]$Directory,[string]$ExpectedIndexSha256,[string]$Campaign,[string]$HarnessSha256) {
    if($ExpectedIndexSha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'Independently verified origin bundle hash required.'}
    $indexPath=Join-Path $Directory 'BUNDLE-INDEX.json';if((Get-VmHash $indexPath) -cne $ExpectedIndexSha256){throw 'Origin bundle index hash mismatch.'}
    $index=Read-VmJson $indexPath
    Assert-VmShape $index @('schema','campaign','harness_sha256','files');Assert-VmInteger $index.schema 1
    if($index.campaign -cne $Campaign -or $index.harness_sha256.ToUpperInvariant() -cne $HarnessSha256){throw 'Origin campaign/harness mismatch.'}
    $names=@('journal.bin','machine.bin','nested.bin','origin.json','user.bin');$seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if(@($index.files).Count -ne 5){throw 'Incomplete public-payload transfer.'}
    foreach($file in $index.files){Assert-VmShape $file @('name','bytes','sha256');if($file.name -cnotin $names -or -not $seen.Add($file.name) -or ($file.bytes -isnot [int] -and $file.bytes -isnot [long]) -or $file.bytes -le 0 -or $file.bytes -gt 65536 -or $file.sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Unsafe transfer entry.'};$p=Join-Path $Directory $file.name;Assert-VmPlainPath $p;$item=Get-Item -LiteralPath $p -Force;if($item.PSIsContainer -or $item.Length -ne $file.bytes -or (Get-VmHash $p) -cne $file.sha256.ToUpperInvariant()){throw 'Public-payload transfer changed.'}}
    $origin=Read-VmJson (Join-Path $Directory 'origin.json');Assert-VmShape $origin @('schema','campaign','context');Assert-VmInteger $origin.schema 1;Assert-VmShape $origin.context @('machine','user')
    if($origin.campaign -cne $Campaign -or $origin.context.machine -cnotmatch '^[a-f0-9]{64}$' -or $origin.context.user -cnotmatch '^[a-f0-9]{64}$'){throw 'Origin context metadata refused.'}
    [pscustomobject]@{index_sha256=$ExpectedIndexSha256;context=$origin.context}
}
