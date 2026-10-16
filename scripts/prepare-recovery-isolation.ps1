[CmdletBinding()]
param()
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot 'vm-recovery/VmRecovery.Common.ps1')
Assert-VmPlainPath $repo;Assert-VmPlainPath (Join-Path $repo 'target')
function Get-SourceSnapshot {
    $names=@(& git -C $repo ls-files --cached --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) {throw 'Source inventory failed.'}
    $entries=@()
    foreach ($name in @($names | Sort-Object -Unique)) {
        $path=[IO.Path]::GetFullPath((Join-Path $repo $name))
        if (-not $path.StartsWith($repo+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Source path escaped repository.'}
        Assert-VmPlainPath $path
        $item=Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Source inventory refuses linked/non-file entries.'}
        $entries+=[ordered]@{path=$name.Replace('\','/');bytes=$item.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
    }
    $json=ConvertTo-Json -InputObject @($entries) -Depth 5 -Compress
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try {$hash=[BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))).Replace('-','')} finally {$algorithm.Dispose()}
    return @{entries=$entries;hash=$hash}
}

Push-Location -LiteralPath $repo
try {
    $before=Get-SourceSnapshot;$head=(& git rev-parse HEAD).Trim();if($LASTEXITCODE -ne 0 -or $head -cnotmatch '^[a-f0-9]{40}$'){throw 'Commit identity unavailable.'}
    $status=@(& git status --porcelain=v1);if($LASTEXITCODE -ne 0){throw 'Working-tree status unavailable.'}
    $campaign=[Guid]::NewGuid().ToString('N');$package=Join-Path $repo ('target\recovery-isolation-'+$campaign);if(Test-Path -LiteralPath $package){throw 'Existing package preserved.'}
    $packageInput=Join-Path $package 'Input';$null=New-Item -ItemType Directory -Path $packageInput
    $buildJson=Join-Path $package 'cargo-artifacts.jsonl'
    & cargo test -p nomad-core --lib --no-run --locked --target x86_64-pc-windows-msvc --target-dir (Join-Path $repo 'target') --message-format=json 1> $buildJson 2> (Join-Path $package 'cargo-build.log')
    if($LASTEXITCODE -ne 0){throw 'Locked VM harness build failed; incomplete package preserved.'}
    $artifacts=@(Get-Content -LiteralPath $buildJson|ForEach-Object {$_|ConvertFrom-Json}|Where-Object {$_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'nomad_core' -and $_.profile.test -and $_.executable})
    if($artifacts.Count -ne 1){throw 'Exactly one actual lib-test artifact required.'}
    $binary=[IO.Path]::GetFullPath($artifacts[0].executable);$target=[IO.Path]::GetFullPath((Join-Path $repo 'target\x86_64-pc-windows-msvc\debug'))+'\'
    if(-not $binary.StartsWith($target,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected test artifact path.'};Assert-VmPlainPath $binary
    $after=Get-SourceSnapshot;if($after.hash -cne $before.hash){throw 'Source changed during compilation; package not qualified.'}
    Copy-Item -LiteralPath $binary -Destination (Join-Path $packageInput 'NativeVmRecoveryTests.exe')
    foreach($name in @('Run-VmRecovery.ps1','VmRecovery.Common.ps1','Verify-VmRecovery.ps1')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot ('vm-recovery/'+$name)) -Destination (Join-Path $packageInput $name)}
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'sandbox-recovery/Invoke-RecoveryProcess.ps1') -Destination (Join-Path $packageInput 'Invoke-RecoveryProcess.ps1')
    $files=@();foreach($item in @(Get-ChildItem -LiteralPath $packageInput -File)){$files+=@{name=$item.Name;bytes=$item.Length;sha256=(Get-VmHash $item.FullName)}}
    $rustcVersion=(& rustc --version);if($LASTEXITCODE -ne 0){throw 'Rust compiler version unavailable.'}
    $cargoVersion=(& cargo --version);if($LASTEXITCODE -ne 0){throw 'Cargo version unavailable.'}
    $build=@{schema=1;campaign=$campaign;base_commit=$head;working_tree_status=$status;source_tree_sha256=$before.hash;source_files=$before.entries;target='x86_64-pc-windows-msvc';rustc_version=$rustcVersion;cargo_version=$cargoVersion;input_files=$files;scope='Prepared unsigned VM-only test harness. Native binding matrix NOT run. No VM/user creation or personal-host configuration.'}
    Write-VmNew (Join-Path $packageInput 'BUILD-MANIFEST.json') ($build|ConvertTo-Json -Depth 8)
    foreach($role in @('origin','foreign')){$enrollment=[ordered]@{schema=1;campaign=$campaign;environment='independently_initialized_disposable_windows_vm';machine_role=$role;independently_initialized=$false;no_personal_data=$false};Write-VmNew (Join-Path $package ('ENROLLMENT-'+$role+'.example.json')) ($enrollment|ConvertTo-Json)}
    Copy-Item -LiteralPath (Join-Path $repo 'docs/INDEPENDENT-WINDOWS-RECOVERY.md') -Destination (Join-Path $package 'RUNBOOK.md')
    $verified=Test-VmBuild $packageInput
    Write-VmNew (Join-Path $package 'PREPARATION.json') (@{schema=1;status='PREPARED_ONLY_NATIVE_MATRIX_NOT_RUN';campaign=$campaign;build_manifest_sha256=(Get-VmHash (Join-Path $packageInput 'BUILD-MANIFEST.json'));input_files_verified=@($verified.input_files).Count;native_phases_run=0;source_tree_sha256=$before.hash}|ConvertTo-Json)
    Write-Host "PREPARED ONLY: $package"
    Write-Host "Campaign: $campaign; build manifest SHA256: $(Get-VmHash (Join-Path $packageInput 'BUILD-MANIFEST.json'))"
    Write-Host 'Use RUNBOOK.md on two independently initialized disposable Windows VMs with fresh local accounts. Do not substitute another Sandbox or alter old guards.'
    Write-Host 'No VM was created. No native DPAPI phase ran. The release isolation claim remains unverified.'
} finally {Pop-Location}
