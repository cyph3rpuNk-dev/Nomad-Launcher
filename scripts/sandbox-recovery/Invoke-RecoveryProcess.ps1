# Definitions only. Starts only the exact executable supplied by the authorized caller.
function Invoke-RecoveryFixtureProcess {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$FilePath,
          [Parameter(Mandatory=$true)][string]$Arguments,
          [Parameter(Mandatory=$true)][string]$StdoutPath,
          [Parameter(Mandatory=$true)][string]$StderrPath,
          [ValidateRange(1,180)][int]$TimeoutSeconds=180)
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$FilePath
    $info.Arguments=$Arguments
    $info.UseShellExecute=$false
    $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true
    $info.RedirectStandardError=$true
    $process=New-Object Diagnostics.Process
    $process.StartInfo=$info
    $outTask=$null; $errTask=$null; $started=$false
    try {
        if (-not $process.Start()) {throw 'Inert process did not start.'}
        $started=$true
        $null=$process.Handle # Retain the actual OS handle before waiting, including fast exits.
        $outTask=$process.StandardOutput.ReadToEndAsync()
        $errTask=$process.StandardError.ReadToEndAsync()
        $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        while (-not $process.WaitForExit(250)) {
            if ([DateTime]::UtcNow -ge $deadline) {throw 'Inert qualification process exceeded its deadline.'}
        }
        $process.WaitForExit() # Drain asynchronous redirects before taking the code.
        $observed=$process.ExitCode
        if ($null -eq $observed -or ($observed -isnot [int] -and $observed -isnot [long])) {throw 'A numeric process exit code could not be captured.'}
        return [int]$observed
    } finally {
        try {
            if ($started -and -not $process.HasExited) {$process.Kill();$process.WaitForExit()}
            $utf8=New-Object Text.UTF8Encoding($false)
            if ($null -ne $outTask) {[IO.File]::WriteAllText($StdoutPath,$outTask.GetAwaiter().GetResult(),$utf8)}
            if ($null -ne $errTask) {[IO.File]::WriteAllText($StderrPath,$errTask.GetAwaiter().GetResult(),$utf8)}
        } finally {$process.Dispose()}
    }
}
