[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$utf8=New-Object Text.UTF8Encoding($false)
. (Join-Path $PSScriptRoot 'sandbox-recovery/Verify-Cleanup-Recovery-Evidence.ps1')
Assert-RecoveryPlainPath $repo
Assert-RecoveryPlainPath (Join-Path $repo 'target')
function Get-SourceSnapshot {
    $names=@(& git -C $repo ls-files --cached --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) {throw 'Source inventory failed.'}
    $entries=@()
    foreach ($name in @($names | Sort-Object -Unique)) {
        $path=[IO.Path]::GetFullPath((Join-Path $repo $name))
        if (-not $path.StartsWith($repo+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Source path escaped repository.'}
        Assert-RecoveryPlainPath $path
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
    $before=Get-SourceSnapshot
    $head=(& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -cnotmatch '^[a-f0-9]{40}$') {throw 'Commit identity unavailable.'}
    $status=@(& git status --porcelain=v1)
    if ($LASTEXITCODE -ne 0) {throw 'Working-tree status unavailable.'}
    $package=Join-Path $repo ('target\cleanup-recovery-native-'+[Guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $package) {throw 'Refuse existing package.'}
    $null=New-Item -ItemType Directory -Path (Join-Path $package 'Input')
    $null=New-Item -ItemType Directory -Path (Join-Path $package 'Output')
    $null=New-Item -ItemType Directory -Path (Join-Path $package 'ForeignOutput')
    $buildJson=Join-Path $package 'cargo-artifacts.jsonl'
    & cargo test -p nomad-core --lib --no-run --locked --target x86_64-pc-windows-msvc --target-dir (Join-Path $repo 'target') --message-format=json 1> $buildJson 2> (Join-Path $package 'cargo-build.log')
    if ($LASTEXITCODE -ne 0) {throw 'Locked qualification harness build failed; package incomplete.'}
    $artifacts=@(Get-Content -LiteralPath $buildJson | ForEach-Object {$_ | ConvertFrom-Json} | Where-Object {$_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'nomad_core' -and $_.profile.test -and $_.executable})
    if ($artifacts.Count -ne 1) {throw 'Exactly one lib-test executable is required.'}
    $binary=[IO.Path]::GetFullPath($artifacts[0].executable)
    $targetRoot=[IO.Path]::GetFullPath((Join-Path $repo 'target\x86_64-pc-windows-msvc\debug'))+'\'
    if (-not $binary.StartsWith($targetRoot,[StringComparison]::OrdinalIgnoreCase)) {throw 'Unexpected qualification artifact location.'}
    $after=Get-SourceSnapshot
    if ($after.hash -cne $before.hash) {throw 'Source changed during compilation; incomplete package retained for review.'}
    $input=Join-Path $package 'Input'
    Copy-Item -LiteralPath $binary -Destination (Join-Path $input 'NativeRecoveryTests.exe')
    foreach ($name in @('Run-Cleanup-Recovery-Qualification.ps1','Verify-Cleanup-Recovery-Evidence.ps1','Invoke-RecoveryProcess.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot ('sandbox-recovery/'+$name)) -Destination (Join-Path $input $name)
    }
    $files=@()
    foreach ($item in @(Get-ChildItem -LiteralPath $input -File)) {$files+=@{name=$item.Name;bytes=$item.Length;sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash}}
    $manifest=@{schema=1;base_commit=$head;working_tree_status=$status;source_tree_sha256=$before.hash;source_files=$before.entries;target='x86_64-pc-windows-msvc';rustc_version=(& rustc --version);cargo_version=(& cargo --version);input_files=$files;scope='local unsigned lib-test harness; native tests pending; not a release or production launcher';command='cargo test -p nomad-core --lib --no-run --locked --target x86_64-pc-windows-msvc'}
    [IO.File]::WriteAllText((Join-Path $input 'BUILD-MANIFEST.json'),($manifest | ConvertTo-Json -Depth 8),$utf8)
    $hostInput=[Security.SecurityElement]::Escape($input)
    $hostOutput=[Security.SecurityElement]::Escape((Join-Path $package 'Output'))
    $wsb=@"
<Configuration>
  <vGPU>Disable</vGPU><Networking>Disable</Networking>
  <AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection><ClipboardRedirection>Disable</ClipboardRedirection>
  <MappedFolders>
    <MappedFolder><HostFolder>$hostInput</HostFolder><SandboxFolder>C:\NomadInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$hostOutput</HostFolder><SandboxFolder>C:\NomadRecoveryOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>powershell.exe -NoProfile -NoExit -ExecutionPolicy Bypass -File C:\NomadInput\Run-Cleanup-Recovery-Qualification.ps1</Command></LogonCommand>
</Configuration>
"@
    [IO.File]::WriteAllText((Join-Path $package 'Nomad-Recovery-Native.wsb'),$wsb,$utf8)
    [IO.File]::WriteAllText((Join-Path $package 'NEXT-STEPS.txt'),"Open Nomad-Recovery-Native.wsb in a fresh Sandbox. The inert tests run automatically.`nTo run manually in that fresh guest:`npowershell -NoProfile -ExecutionPolicy Bypass -File C:\NomadInput\Run-Cleanup-Recovery-Qualification.ps1`nKeep the Sandbox open and send the console output. Output/ contains a dedicated hashed receipt for independent host validation. Native checks have not run merely because this package exists.`n",$utf8)
    Write-Host "PREPARED ONLY: $package"
    Write-Host "Source SHA256: $($before.hash)"
    Write-Host 'Native Sandbox qualification has NOT run. No host browser/profile/configuration was changed.'
} finally {Pop-Location}
