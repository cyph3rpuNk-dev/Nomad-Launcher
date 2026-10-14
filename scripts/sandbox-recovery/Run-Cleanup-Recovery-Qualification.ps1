[CmdletBinding()]
param([ValidateSet('Primary','Foreign')][string]$Phase='Primary')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:USERNAME -cne 'WDAGUtilityAccount' -or $env:USERPROFILE -cne 'C:\Users\WDAGUtilityAccount' -or $PSScriptRoot -cnotin @('C:\NomadInput','C:\NomadInput\ExitCaptureFollowup')) {
    throw 'Explicit disposable Sandbox qualification only. Do not run this on the host.'
}
function Assert-PlainPath([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Fixture path contains a reparse point.'}
        }
        $parent=Split-Path -Parent $current
        if ($parent -eq $current) {break}
        $current=$parent
    }
}
$manifestPath=Join-Path $PSScriptRoot 'BUILD-MANIFEST.json'
if ((Get-Item -LiteralPath $manifestPath).Length -gt 524288) {throw 'Oversized input manifest.'}
$manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne 1 -or $manifest.target -cne 'x86_64-pc-windows-msvc') {throw 'Unexpected local build manifest.'}
$seenInput=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($file in $manifest.input_files) {
    if (-not $seenInput.Add($file.name)) {throw 'Duplicate input filename.'}
    if ($file.name -cnotin @('NativeRecoveryTests.exe','Run-Cleanup-Recovery-Qualification.ps1','Verify-Cleanup-Recovery-Evidence.ps1','Invoke-RecoveryProcess.ps1')) {throw 'Unexpected input filename.'}
    $path=Join-Path $PSScriptRoot $file.name
    if ((Get-Item -LiteralPath $path).Length -ne $file.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $file.sha256) {throw "Input verification failed: $($file.name)"}
}
if (@($manifest.input_files).Count -ne 4) {throw 'Incomplete input set.'}
. (Join-Path $PSScriptRoot 'Invoke-RecoveryProcess.ps1')
$testInput=Join-Path $PSScriptRoot 'NativeRecoveryTests.exe'
$harnessHash=(Get-FileHash -LiteralPath $testInput -Algorithm SHA256).Hash
$token=[Guid]::NewGuid().ToString('N')
$root=Join-Path 'C:\NomadRecoveryQualification' $token
Assert-PlainPath $root
if (Test-Path -LiteralPath $root) {throw 'Never overwrite a previous qualification fixture.'}
$null=New-Item -ItemType Directory -Path (Join-Path $root 'tools')
[IO.File]::WriteAllText((Join-Path $root 'SESSION-OWNER.txt'),"Nomad disposable recovery qualification v1`n$token`n",(New-Object Text.UTF8Encoding($false)))
$harness=Join-Path $root 'tools\NativeRecoveryTests.exe'
Copy-Item -LiteralPath $testInput -Destination $harness
if ((Get-FileHash -LiteralPath $harness -Algorithm SHA256).Hash -cne $harnessHash) {throw 'Copied harness mismatch.'}
if ($Phase -eq 'Foreign') {
    foreach ($name in @('native-protected.bin','machine-protected.bin')) {
        $blob=Join-Path 'C:\NomadForeignInput' $name
        if (-not (Test-Path -LiteralPath $blob -PathType Leaf) -or (Get-Item -LiteralPath $blob).Length -gt 65536) {throw 'Bounded primary public-payload evidence is required for the foreign phase.'}
    }
}
$env:NOMAD_RECOVERY_FIXTURE_TOKEN=$token
$stdout=Join-Path $root 'native-stdout.txt'
$stderr=Join-Path $root 'native-stderr.txt'
$selector='cleanup_recovery::sandbox_tests::qualify_native_recovery'
if ($Phase -eq 'Foreign') {$selector='cleanup_recovery::sandbox_tests::qualify_foreign_context'}
Write-Host 'LOCAL UNSIGNED TEST HARNESS; no browser, updater, registration or personal host cleanup.'
Write-Host "Base: $($manifest.base_commit)"
Write-Host "Working source SHA256: $($manifest.source_tree_sha256)"
Write-Host "Harness SHA256: $harnessHash"
Write-Host "Phase: $Phase; fixture: $root"
Write-Host 'Only inert fixtures and exact child handles are used. Native DPAPI writes stay in the disposable guest.'
$exitCode=-1
$failure=$null
try {
    $exitCode=Invoke-RecoveryFixtureProcess -FilePath $harness -Arguments "--exact $selector --ignored --nocapture --test-threads=1" -StdoutPath $stdout -StderrPath $stderr -TimeoutSeconds 180
} catch {$failure=$_.Exception.Message}
finally {Remove-Item Env:\NOMAD_RECOVERY_FIXTURE_TOKEN -ErrorAction SilentlyContinue}
if (Test-Path -LiteralPath $stdout) {Get-Content -LiteralPath $stdout | Write-Host}
if (Test-Path -LiteralPath $stderr) {Get-Content -LiteralPath $stderr | Write-Host}
$output=Join-Path 'C:\NomadRecoveryOutput' ($Phase.ToLowerInvariant()+'-'+$token)
if (-not (Test-Path -LiteralPath 'C:\NomadRecoveryOutput' -PathType Container) -or (Test-Path -LiteralPath $output)) {throw 'Fresh dedicated output mapping required; guest fixture preserved.'}
$null=New-Item -ItemType Directory -Path (Join-Path $output 'files')
$files=@()
$hashOnly=@()
$queue=New-Object 'Collections.Generic.Queue[string]'
$queue.Enqueue($root)
$entries=0
while ($queue.Count -gt 0) {
    $dir=$queue.Dequeue()
    Assert-PlainPath $dir
    foreach ($item in @(Get-ChildItem -LiteralPath $dir -Force)) {
        $entries++
        if ($entries -gt 256 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Evidence traversal budget/link refusal; guest fixture preserved.'}
        if ($item.PSIsContainer) {$queue.Enqueue($item.FullName); continue}
        $relative=$item.FullName.Substring($root.Length+1).Replace('\','/')
        $hash=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        if ($item.Extension -ieq '.exe') {
            $hashOnly+=@{relative_path=$relative;bytes=$item.Length;sha256=$hash}
            continue
        }
        if ($item.Extension -cnotin @('.txt','.json','.bin','.toml','.wer','.dmp','.lock')) {continue}
        if ($item.Length -gt 65536) {throw 'Oversized qualification evidence preserved in guest.'}
        if ($item.Extension -ieq '.dmp') {
            $bytes=[IO.File]::ReadAllBytes($item.FullName)
            if ($bytes.Length -lt 5 -or [Text.Encoding]::ASCII.GetString($bytes,0,5) -cne 'INERT') {throw 'Only authored inert dump fixtures may be exported.'}
        }
        $relativeOutput='files/'+$relative
        $destination=Join-Path $output $relativeOutput
        $null=New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force
        Copy-Item -LiteralPath $item.FullName -Destination $destination
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -cne $hash) {throw 'Copied evidence hash mismatch.'}
        $files+=@{relative_path=$relativeOutput;bytes=$item.Length;sha256=$hash}
    }
}
$receipt=@{schema=1;phase=$Phase;run_token=$token;base_commit=$manifest.base_commit;source_tree_sha256=$manifest.source_tree_sha256;harness_sha256=$harnessHash;exit_code=$exitCode;failure=$failure;os_version=[Environment]::OSVersion.Version.ToString();files=$files;hash_only=$hashOnly;scope='inert native guest qualification; host verification pending'}
[IO.File]::WriteAllText((Join-Path $output 'GUEST-RECEIPT.json'),($receipt | ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
Write-Host "NATIVE EXIT CODE: $exitCode"
Write-Host "EVIDENCE EXPORTED: $output; files: $($files.Count); hash-only: $($hashOnly.Count)"
Write-Host 'Host independently validates this dedicated mapped output next. Keep Sandbox open.'
if ($failure -or $exitCode -ne 0) {throw "Qualification did not pass. Evidence retained. $failure"}
