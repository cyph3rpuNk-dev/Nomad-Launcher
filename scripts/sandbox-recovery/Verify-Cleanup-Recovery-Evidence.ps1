# Read-only host verifier; functions only until explicitly called.
Set-StrictMode -Version Latest
function Assert-RecoveryPlainPath([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Evidence path has a reparse point.'}
        }
        $parent=Split-Path -Parent $current
        if ($parent -eq $current) {break}
        $current=$parent
    }
}
function Read-RecoveryJson([string]$Path,[long]$Limit) {
    Assert-RecoveryPlainPath $Path
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt $Limit) {throw 'Invalid bounded JSON evidence.'}
    return (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
}
function Test-CleanupRecoveryEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$InputDirectory,[Parameter(Mandatory=$true)][string]$OutputDirectory)
    $inputRoot=[IO.Path]::GetFullPath($InputDirectory)
    $outputRoot=[IO.Path]::GetFullPath($OutputDirectory)
    Assert-RecoveryPlainPath $inputRoot
    Assert-RecoveryPlainPath $outputRoot
    $build=Read-RecoveryJson (Join-Path $inputRoot 'BUILD-MANIFEST.json') 524288
    $receipt=Read-RecoveryJson (Join-Path $outputRoot 'GUEST-RECEIPT.json') 131072
    if ($build.schema -ne 1 -or $receipt.schema -ne 1 -or $build.target -cne 'x86_64-pc-windows-msvc' -or $receipt.phase -cnotin @('Primary','Foreign') -or $receipt.run_token -cnotmatch '^[a-f0-9]{32}$') {throw 'Invalid build/receipt schema or scope.'}
    $expectedLeaf=$receipt.phase.ToLowerInvariant()+'-'+$receipt.run_token
    if ((Split-Path -Leaf $outputRoot) -cne $expectedLeaf) {throw 'Output folder does not match recorded run.'}
    foreach ($key in @('base_commit','source_tree_sha256')) {
        if ($receipt.$key -cne $build.$key) {throw 'Build/receipt provenance mismatch.'}
    }
    $harness=Join-Path $inputRoot 'NativeRecoveryTests.exe'
    Assert-RecoveryPlainPath $harness
    $harnessHash=(Get-FileHash -LiteralPath $harness -Algorithm SHA256 -ErrorAction Stop).Hash
    $expected=@($build.input_files | Where-Object {$_.name -ceq 'NativeRecoveryTests.exe'})
    if ($expected.Count -ne 1 -or $expected[0].sha256 -cne $harnessHash -or $receipt.harness_sha256 -cne $harnessHash) {throw 'Harness provenance mismatch.'}
    if (@($receipt.files).Count -eq 0 -or @($receipt.files).Count -gt 256 -or @($receipt.hash_only).Count -gt 32) {throw 'Evidence entry budget exceeded/incomplete.'}
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $receipt.files) {
        $relative=$file.relative_path
        if ($relative -cnotmatch '^files/[A-Za-z0-9._/-]+$' -or @($relative.Split('/') | Where-Object {$_ -eq '.' -or $_ -eq '..' -or $_ -eq '' -or $_.EndsWith('.') -or $_ -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)'}).Count -ne 0 -or -not $seen.Add($relative)) {throw 'Unsafe or duplicate evidence path.'}
        if ($file.sha256 -cnotmatch '^[A-F0-9]{64}$' -or $file.bytes -lt 0 -or $file.bytes -gt 65536) {throw 'Invalid evidence hash/size.'}
        $path=[IO.Path]::GetFullPath((Join-Path $outputRoot $relative))
        if (-not $path.StartsWith($outputRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'Evidence path escapes scope.'}
        Assert-RecoveryPlainPath $path
        $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Length -ne $file.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $file.sha256) {throw 'Evidence byte/hash mismatch.'}
    }
    $resultName='files/native-results.json'
    $checks=@('native_round_trip','native_tamper_refused','malformed_blob_refused','running_image_preserved','same_name_foreign_image_unknown','cross_process_record_recovered','terminated_worker_lock_released','unavailable_image_preserved','moved_scope_preserved','attributed_fixture_reports_removed','foreign_report_and_shared_dump_preserved')
    if ($receipt.phase -ceq 'Foreign') {$resultName='files/foreign-results.json';$checks=@('nested_blob_refused','machine_blob_refused')}
    if (-not $seen.Contains($resultName)) {throw 'Native result is not hash-inventoried.'}
    $result=Read-RecoveryJson (Join-Path $outputRoot $resultName) 65536
    if ($result.schema -ne 1 -or ($receipt.exit_code -isnot [int] -and $receipt.exit_code -isnot [long]) -or $receipt.exit_code -ne 0 -or $receipt.failure) {throw 'Native run did not report successful completion.'}
    foreach ($key in $checks) {if ($result.$key -isnot [bool] -or -not $result.$key) {throw "Native assertion missing/false: $key"}}
    foreach ($name in @('files/native-stdout.txt','files/native-stderr.txt')) {if (-not $seen.Contains($name)) {throw 'Native logs not inventoried.'}}
    $stdout=Get-Content -LiteralPath (Join-Path $outputRoot 'files/native-stdout.txt') -Raw
    if ($stdout -notmatch 'test result: ok\. 1 passed; 0 failed;') {throw 'Native exact-test completion not corroborated by log.'}
    [pscustomobject]@{schema=1;phase=$receipt.phase;run_token=$receipt.run_token;hashes_verified=$true;files_verified=@($receipt.files).Count;harness_sha256=$harnessHash;base_commit=$build.base_commit;source_tree_sha256=$build.source_tree_sha256;guest_reported_checks=$checks;os_version=$receipt.os_version;scope='Verified mapped bytes and guest assertions; no full production watcher/browser or physical power-loss qualification claimed'}
}
