# Minimal inert PE metadata fixtures. They contain no runnable launcher code.
function Set-FixtureU16([byte[]]$Bytes,[int]$Offset,[uint16]$Value) { [Array]::Copy([BitConverter]::GetBytes($Value),0,$Bytes,$Offset,2) }
function Set-FixtureU32([byte[]]$Bytes,[int]$Offset,[uint32]$Value) { [Array]::Copy([BitConverter]::GetBytes($Value),0,$Bytes,$Offset,4) }
function Set-FixtureU64([byte[]]$Bytes,[int]$Offset,[uint64]$Value) { [Array]::Copy([BitConverter]::GetBytes($Value),0,$Bytes,$Offset,8) }
function New-LauncherPEFixture([string]$Import='kernel32.dll',[string]$DelayImport='') {
    $bytes=New-Object byte[] 4096
    Set-FixtureU16 $bytes 0 0x5a4d; Set-FixtureU32 $bytes 0x3c 0x80
    Set-FixtureU32 $bytes 0x80 0x4550; Set-FixtureU16 $bytes 0x84 0x8664
    Set-FixtureU16 $bytes 0x86 1; Set-FixtureU16 $bytes 0x94 240
    Set-FixtureU16 $bytes 0x98 0x20b; Set-FixtureU64 $bytes 0xb0 0x140000000
    Set-FixtureU32 $bytes 0xd4 512; Set-FixtureU16 $bytes 0xdc 2
    Set-FixtureU16 $bytes 0xde 0x4000; Set-FixtureU32 $bytes 0x104 16
    Set-FixtureU32 $bytes 0x110 0x1100; Set-FixtureU32 $bytes 0x114 40
    Set-FixtureU32 $bytes 0x158 0x1500; Set-FixtureU32 $bytes 0x15c 148
    Set-FixtureU32 $bytes 0x190 0xe00; Set-FixtureU32 $bytes 0x194 0x1000
    Set-FixtureU32 $bytes 0x198 0xe00; Set-FixtureU32 $bytes 0x19c 0x200
    Set-FixtureU32 $bytes 0x30c 0x1300
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes($Import),0,$bytes,0x500,$Import.Length)
    Set-FixtureU32 $bytes 0x700 148; Set-FixtureU16 $bytes 0x74e 0x800
    Set-FixtureU64 $bytes 0x770 0x140001610
    Set-FixtureU64 $bytes 0x780 0x140001600; Set-FixtureU64 $bytes 0x788 1
    Set-FixtureU32 $bytes 0x790 0x500; Set-FixtureU32 $bytes 0x800 0x1000
    if ($DelayImport) {
        Set-FixtureU32 $bytes 0x170 0x1400; Set-FixtureU32 $bytes 0x174 64
        Set-FixtureU32 $bytes 0x600 1; Set-FixtureU32 $bytes 0x604 0x1450
        [Array]::Copy([Text.Encoding]::ASCII.GetBytes($DelayImport),0,$bytes,0x650,$DelayImport.Length)
    }
    return ,$bytes
}
