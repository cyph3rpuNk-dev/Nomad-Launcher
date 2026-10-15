[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][string]$Target,[Parameter(Mandatory=$true)][string]$Link)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$fixtureRoot=[IO.Path]::GetFullPath($Root)
$marker=Join-Path $fixtureRoot '.nomad-shortcut-fixture'
if ([IO.File]::ReadAllText($marker) -cne 'Nomad inert shortcut fixture') { throw 'Not an owned shortcut fixture.' }
foreach ($path in @($Target,$Link)) {
    $full=[IO.Path]::GetFullPath($path)
    if (-not $full.StartsWith($fixtureRoot+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Shortcut path outside owned fixture.' }
    $cursor=Split-Path -Parent $full
    while ($cursor.Length -ge $fixtureRoot.Length) {
        $item=Get-Item -LiteralPath $cursor
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked fixture parent refused.' }
        if ($cursor -eq $fixtureRoot) { break }
        $cursor=Split-Path -Parent $cursor
    }
}
if (-not (Test-Path -LiteralPath $Target -PathType Leaf) -or (Test-Path -LiteralPath $Link)) { throw 'Target missing or shortcut already exists.' }
$shell=$null;$shortcut=$null
try {
    $shell=New-Object -ComObject WScript.Shell
    $shortcut=$shell.CreateShortcut($Link)
    $shortcut.TargetPath=$Target
    $shortcut.Save()
} finally {
    if ($null -ne $shortcut) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) }
    if ($null -ne $shell) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
}
# No shortcut/target is opened, executed or resolved. Only its owned .lnk is saved.
