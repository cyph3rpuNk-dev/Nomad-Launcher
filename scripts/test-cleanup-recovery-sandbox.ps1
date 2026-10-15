[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'sandbox-recovery/Verify-Cleanup-Recovery-Evidence.ps1')
. (Join-Path $PSScriptRoot 'sandbox-recovery/Invoke-RecoveryProcess.ps1')
$root=Join-Path ([IO.Path]::GetTempPath()) ('nomad-recovery-export-test-'+[Guid]::NewGuid().ToString('N'))
$token='0123456789abcdef0123456789abcdef'
$inputDir=Join-Path $root 'input'
$outputDir=Join-Path $root ('primary-'+$token)
$utf8=New-Object Text.UTF8Encoding($false)
function Save-Json($Path,$Value) {[IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 10),$utf8)}
function Expect-Failure([scriptblock]$Action) {
    $failed=$false
    try {& $Action | Out-Null} catch {$failed=$true}
    if (-not $failed) {throw 'Unsafe metadata unexpectedly accepted.'}
}
try {
    $null=New-Item -ItemType Directory -Path $inputDir
    $null=New-Item -ItemType Directory -Path (Join-Path $outputDir 'files')
    $harness=Join-Path $inputDir 'NativeRecoveryTests.exe'
    [IO.File]::WriteAllText($harness,'inert metadata fixture; never executable',$utf8)
    $hash=(Get-FileHash -LiteralPath $harness -Algorithm SHA256).Hash
    $build=@{schema=1;target='x86_64-pc-windows-msvc';base_commit=('a'*40);source_tree_sha256=('B'*64);input_files=@(@{name='NativeRecoveryTests.exe';sha256=$hash})}
    Save-Json (Join-Path $inputDir 'BUILD-MANIFEST.json') $build
    $result=@{schema=1;scope='authored metadata fixture, NOT a native test'}
    foreach ($key in @('native_round_trip','native_tamper_refused','malformed_blob_refused','running_image_preserved','same_name_foreign_image_unknown','cross_process_record_recovered','terminated_worker_lock_released','unavailable_image_preserved','moved_scope_preserved','attributed_fixture_reports_removed','foreign_report_and_shared_dump_preserved')) {$result[$key]=$true}
    Save-Json (Join-Path $outputDir 'files/native-results.json') $result
    [IO.File]::WriteAllText((Join-Path $outputDir 'files/native-stdout.txt'),'Authored metadata test log. test result: ok. 1 passed; 0 failed;',$utf8)
    [IO.File]::WriteAllText((Join-Path $outputDir 'files/native-stderr.txt'),'',$utf8)
    $files=@()
    foreach ($name in @('native-results.json','native-stdout.txt','native-stderr.txt')) {
        $path=Join-Path $outputDir ('files/'+$name)
        $files+=@{relative_path=('files/'+$name);bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
    }
    $receipt=@{schema=1;phase='Primary';run_token=$token;base_commit=$build.base_commit;source_tree_sha256=$build.source_tree_sha256;harness_sha256=$hash;exit_code=0;failure=$null;os_version='synthetic';files=$files;hash_only=@()}
    $receiptPath=Join-Path $outputDir 'GUEST-RECEIPT.json'
    Save-Json $receiptPath $receipt
    $verified=Test-CleanupRecoveryEvidence -InputDirectory $inputDir -OutputDirectory $outputDir
    if (-not $verified.hashes_verified -or $verified.files_verified -ne 3) {throw 'Valid inert fixture rejected.'}
    foreach ($unsafe in @('files/../outside.json','files/C:/outside.json','/absolute.json','files//empty.json','files/./same.json','files/NUL','files/COM1.txt','files/PRN.bin','files/native-results.json.')) {
        $receipt.files[0].relative_path=$unsafe
        Save-Json $receiptPath $receipt
        Expect-Failure {Test-CleanupRecoveryEvidence -InputDirectory $inputDir -OutputDirectory $outputDir}
    }
    $receipt.files[0].relative_path='files/native-results.json'
    $result['native_round_trip']='true' # A string must not pass as a native assertion.
    Save-Json (Join-Path $outputDir 'files/native-results.json') $result
    $receipt.files[0].bytes=(Get-Item -LiteralPath (Join-Path $outputDir 'files/native-results.json')).Length
    $receipt.files[0].sha256=(Get-FileHash -LiteralPath (Join-Path $outputDir 'files/native-results.json') -Algorithm SHA256).Hash
    Save-Json $receiptPath $receipt
    Expect-Failure {Test-CleanupRecoveryEvidence -InputDirectory $inputDir -OutputDirectory $outputDir}
    $result['native_round_trip']=$true
    Save-Json (Join-Path $outputDir 'files/native-results.json') $result
    $receipt.files[0].bytes=(Get-Item -LiteralPath (Join-Path $outputDir 'files/native-results.json')).Length
    $receipt.files[0].sha256=(Get-FileHash -LiteralPath (Join-Path $outputDir 'files/native-results.json') -Algorithm SHA256).Hash
    $receipt.files+=@($receipt.files[0])
    Save-Json $receiptPath $receipt
    Expect-Failure {Test-CleanupRecoveryEvidence -InputDirectory $inputDir -OutputDirectory $outputDir}
    $receipt.files=@($receipt.files | Select-Object -First 3)
    $receipt.exit_code=$null
    Save-Json $receiptPath $receipt
    Expect-Failure {Test-CleanupRecoveryEvidence -InputDirectory $inputDir -OutputDirectory $outputDir}
    $receipt.exit_code=1
    Save-Json $receiptPath $receipt
    Expect-Failure {Test-CleanupRecoveryEvidence -InputDirectory $inputDir -OutputDirectory $outputDir}
    $receipt.exit_code=0
    $receipt.harness_sha256=('0'*64)
    Save-Json $receiptPath $receipt
    Expect-Failure {Test-CleanupRecoveryEvidence -InputDirectory $inputDir -OutputDirectory $outputDir}
    $receipt.harness_sha256=$hash
    $receipt.files[0].bytes=65537
    Save-Json $receiptPath $receipt
    Expect-Failure {Test-CleanupRecoveryEvidence -InputDirectory $inputDir -OutputDirectory $outputDir}
    $receipt.files[0].bytes=(Get-Item -LiteralPath (Join-Path $outputDir 'files/native-results.json')).Length
    Save-Json $receiptPath $receipt
    [IO.File]::AppendAllText((Join-Path $outputDir 'files/native-results.json'),'tampered',$utf8)
    Expect-Failure {Test-CleanupRecoveryEvidence -InputDirectory $inputDir -OutputDirectory $outputDir}
    # Linked evidence must be rejected before following an otherwise valid path.
    $linkedTarget=Join-Path $root 'linked-target'
    $null=New-Item -ItemType Directory -Path $linkedTarget
    Save-Json (Join-Path $linkedTarget 'native-results.json') $result
    $link=Join-Path $outputDir 'files/alias'
    $null=New-Item -ItemType Junction -Path $link -Target $linkedTarget
    try {
        $receipt.files[0].relative_path='files/alias/native-results.json'
        $receipt.files[0].bytes=(Get-Item -LiteralPath (Join-Path $linkedTarget 'native-results.json')).Length
        $receipt.files[0].sha256=(Get-FileHash -LiteralPath (Join-Path $linkedTarget 'native-results.json') -Algorithm SHA256).Hash
        Save-Json $receiptPath $receipt
        Expect-Failure {Test-CleanupRecoveryEvidence -InputDirectory $inputDir -OutputDirectory $outputDir}
        if (-not (Test-Path -LiteralPath (Join-Path $linkedTarget 'native-results.json'))) {throw 'Linked target was changed.'}
    } finally {
        if (-not ((Get-Item -LiteralPath $link -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Expected owned junction before unlink.'}
        [IO.Directory]::Delete($link) # Nonrecursive unlink only; PowerShell 5.1 Remove-Item has a junction bug.
    }
    # Only inert no-profile PowerShell children; no browser, DPAPI, network or configuration calls.
    $shell=Join-Path $PSHOME 'powershell.exe'
    if (Test-Path -LiteralPath (Join-Path $PSHOME 'pwsh.exe')) {$shell=Join-Path $PSHOME 'pwsh.exe'}
    foreach ($expected in @(0,7)) {
        $code=Invoke-RecoveryFixtureProcess -FilePath $shell -Arguments ('-NoProfile -NonInteractive -Command "exit '+$expected+'"') -StdoutPath (Join-Path $root 'child-out.txt') -StderrPath (Join-Path $root 'child-err.txt') -TimeoutSeconds 10
        if ($code -isnot [int] -or $code -ne $expected) {throw 'Real inert-child exit code not retained.'}
    }
    Expect-Failure {Invoke-RecoveryFixtureProcess -FilePath $shell -Arguments '-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 5"' -StdoutPath (Join-Path $root 'child-out.txt') -StderrPath (Join-Path $root 'child-err.txt') -TimeoutSeconds 1}
    foreach ($name in @('sandbox-recovery/Run-Cleanup-Recovery-Qualification.ps1','sandbox-recovery/Verify-Cleanup-Recovery-Evidence.ps1','sandbox-recovery/Invoke-RecoveryProcess.ps1','prepare-cleanup-recovery-sandbox.ps1')) {
        $tokens=$null; $errors=$null
        $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$errors)
        if (@($errors).Count) {throw "Preparation/runner syntax error: $name"}
    }
    Write-Host 'Recovery evidence regressions passed: authored metadata, scope, traversal, duplicate, size, source, failed-run and hash checks; native guest tests not executed.'
} finally {
    $resolved=[IO.Path]::GetFullPath($root)
    $tempBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($tempBase,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolved) -notmatch '^nomad-recovery-export-test-[a-f0-9]{32}$') {throw 'Owned fixture cleanup boundary failed.'}
    if (Test-Path -LiteralPath $resolved) {Assert-RecoveryPlainPath $resolved; Remove-Item -LiteralPath $resolved -Recurse -Force}
}
