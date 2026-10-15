[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$utf8=New-Object Text.UTF8Encoding($false)
. (Join-Path $PSScriptRoot 'sandbox-recovery/Verify-Cleanup-Recovery-Evidence.ps1')
. (Join-Path $PSScriptRoot 'artifact-guard.ps1')
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
    $head=(& git rev-parse HEAD).Trim();if($LASTEXITCODE -ne 0){throw 'Commit unavailable.'}
    $status=@(& git status --porcelain=v1);if($LASTEXITCODE -ne 0){throw 'Status unavailable.'}
    $package=Join-Path $repo ('target\helium-dns-'+[Guid]::NewGuid().ToString('N'))
    if(Test-Path -LiteralPath $package){throw 'Existing package refused.'}
    $inputRoot=Join-Path $package 'Input';$outputRoot=Join-Path $package 'Output'
    $null=New-Item -ItemType Directory -Path $inputRoot
    $null=New-Item -ItemType Directory -Path $outputRoot
    & cargo build -p nomad-helium --bin Nomad-Helium --locked --target x86_64-pc-windows-msvc --target-dir (Join-Path $repo 'target') --message-format=json 1> (Join-Path $package 'cargo-artifacts.jsonl') 2> (Join-Path $package 'cargo-build.log')
    if($LASTEXITCODE -ne 0){throw 'Launcher compilation failed; package incomplete.'}
    $artifacts=@(Get-Content -LiteralPath (Join-Path $package 'cargo-artifacts.jsonl') | ForEach-Object {$_ | ConvertFrom-Json} | Where-Object {$_.reason -eq 'compiler-artifact' -and $_.target.name -ceq 'Nomad-Helium' -and $_.executable})
    if($artifacts.Count -ne 1){throw 'Expected exactly one launcher artifact.'}
    $binary=[IO.Path]::GetFullPath($artifacts[0].executable)
    if(-not $binary.StartsWith((Join-Path $repo 'target\x86_64-pc-windows-msvc\debug\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected build artifact path.'}
    Assert-RecoveryPlainPath $binary
    Assert-NomadArtifact -LiteralPath $binary
    $after=Get-SourceSnapshot
    if($before.hash -cne $after.hash){throw 'Source changed during build; package incomplete.'}
    Copy-Item -LiteralPath $binary -Destination (Join-Path $inputRoot 'Nomad-Helium.exe')
    foreach($name in @('Run-Helium-Dns.ps1','Analyze-Dns-NetLog.ps1')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot ('sandbox-network/'+$name)) -Destination (Join-Path $inputRoot $name)}
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'sandbox-recovery/Recovery-Integration-Helpers.ps1') -Destination (Join-Path $inputRoot 'Recovery-Integration-Helpers.ps1')
    $files=@(Get-ChildItem -LiteralPath $inputRoot -File | ForEach-Object {@{name=$_.Name;bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
    $manifest=@{schema=1;base_commit=$head;working_tree_status=$status;source_tree_sha256=$before.hash;source_files=$before.entries;target='x86_64-pc-windows-msvc';input_files=$files;launcher_sha256=(Get-FileHash -LiteralPath (Join-Path $inputRoot 'Nomad-Helium.exe')).Hash;scope='Local unsigned launcher; guest DNS qualification NOT RUN; not release/CI';command='cargo build -p nomad-helium --bin Nomad-Helium --locked --target x86_64-pc-windows-msvc';rustc_version=(& rustc --version)}
    [IO.File]::WriteAllText((Join-Path $inputRoot 'BUILD-MANIFEST.json'),($manifest | ConvertTo-Json -Depth 8),$utf8)
    $mappedInput=[Security.SecurityElement]::Escape($inputRoot)
    $mappedOutput=[Security.SecurityElement]::Escape($outputRoot)
    $wsb=@"
<Configuration>
  <Networking>Enable</Networking><vGPU>Disable</vGPU>
  <AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput><PrinterRedirection>Disable</PrinterRedirection><ClipboardRedirection>Disable</ClipboardRedirection>
  <MappedFolders>
    <MappedFolder><HostFolder>$mappedInput</HostFolder><SandboxFolder>C:\NomadInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$mappedOutput</HostFolder><SandboxFolder>C:\NomadDnsOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>powershell.exe -NoProfile -NoExit -ExecutionPolicy Bypass -File C:\NomadInput\Run-Helium-Dns.ps1 -Phase Fresh</Command></LogonCommand>
</Configuration>
"@
    [IO.File]::WriteAllText((Join-Path $package 'Nomad-Helium-DNS.wsb'),$wsb,$utf8)
    Write-Host "PREPARED ONLY: $package"
    Write-Host "Source SHA256: $($before.hash)"
    Write-Host "Launcher SHA256: $($manifest.launcher_sha256)"
    Write-Host 'No browser/download, watcher termination, registration or cleanup ran on the host. Guest DNS observations remain pending.'
} finally {Pop-Location}
