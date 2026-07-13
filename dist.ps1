Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

Write-Host "Building release binaries..."
cargo build --release --workspace
if ($LASTEXITCODE -ne 0) { exit 1 }

$relDir = Join-Path $PSScriptRoot "target\release"
$exes = Get-ChildItem $relDir -Filter "Nomad-*.exe" | Sort-Object Name
Write-Host "Done. $($exes.Count) launcher(s) in target\release\"

# --- Authenticode: sign every launcher (set NOMAD_SIGN_CERT to enable) ---
# Drop-in config (Phase 3): set NOMAD_SIGN_CERT to either
#   * a .pfx file path   -> also set NOMAD_SIGN_PASS to its password, or
#   * a 40-hex SHA-1 thumbprint of a cert already in your certificate store.
# Optional overrides: NOMAD_SIGNTOOL (path to signtool.exe), NOMAD_SIGN_TS
# (RFC3161 timestamp URL; default below). Signing runs BEFORE SHA256SUMS so the
# checksums — and the GPG signature over them — cover the signed bytes.
$cert = $env:NOMAD_SIGN_CERT
if ($cert) {
    # Resolve signtool.exe: NOMAD_SIGNTOOL override -> PATH -> newest x64 under
    # the Windows 10 Kit (signtool is rarely on PATH even when installed).
    $signtool = $null
    if ($env:NOMAD_SIGNTOOL -and (Test-Path $env:NOMAD_SIGNTOOL)) { $signtool = $env:NOMAD_SIGNTOOL }
    if (-not $signtool) { $c = Get-Command signtool.exe -ErrorAction SilentlyContinue; if ($c) { $signtool = $c.Source } }
    if (-not $signtool) {
        $kit = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
        if (Test-Path $kit) {
            $signtool = Get-ChildItem $kit -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\x64\\' } |
                Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
        }
    }
    if (-not $signtool) {
        Write-Warning "signtool.exe not found (install the Windows SDK or set NOMAD_SIGNTOOL); launchers are left UNSIGNED"
    } else {
        $ts = if ($env:NOMAD_SIGN_TS) { $env:NOMAD_SIGN_TS } else { "http://timestamp.digicert.com" }
        # Thumbprint (40 hex) -> select from store with /sha1; otherwise treat as a .pfx path.
        if ($cert -match '^[0-9A-Fa-f]{40}$') {
            $certArgs = @("/sha1", $cert)
        } else {
            $certArgs = @("/f", $cert)
            if ($env:NOMAD_SIGN_PASS) { $certArgs += @("/p", $env:NOMAD_SIGN_PASS) }
        }
        $signed = 0
        foreach ($e in $exes) {
            & $signtool sign @certArgs /fd SHA256 /tr $ts /td SHA256 /d "Nomad Launcher" $e.FullName
            if ($LASTEXITCODE -eq 0) { $signed++ }
            else { Write-Warning "signtool failed on $($e.Name) (exit $LASTEXITCODE)" }
        }
        Write-Host "Authenticode-signed $signed/$($exes.Count) launcher(s)"
    }
} else {
    Write-Warning "NOMAD_SIGN_CERT not set; skipping Authenticode signing (launchers are UNSIGNED)"
}

# --- License bundling: third-party notices must ship beside the binaries ---
# The OFL (font) and LGPL (7-Zip) require their license text to travel with the
# distributed artifact; stage them plus Nomad's own licenses into licenses\.
$licDir = Join-Path $relDir "licenses"
New-Item -ItemType Directory -Force -Path $licDir | Out-Null
$licenseFiles = @(
    @{ Src = "LICENSE-MIT";                    Dst = "Nomad-LICENSE-MIT.txt" },
    @{ Src = "LICENSE-APACHE";                 Dst = "Nomad-LICENSE-APACHE.txt" },
    @{ Src = "core\payloads\fonts\OFL.txt";    Dst = "AtkinsonHyperlegible-OFL.txt" },
    @{ Src = "core\payloads\7zip\LICENSE.txt"; Dst = "7-Zip-LICENSE.txt" }
)
foreach ($f in $licenseFiles) {
    $src = Join-Path $PSScriptRoot $f.Src
    if (Test-Path $src) { Copy-Item $src (Join-Path $licDir $f.Dst) -Force }
    else { Write-Warning "license file missing: $($f.Src)" }
}
$notices = @'
Nomad Launcher - Third-Party Notices
====================================

Nomad Launcher itself is dual-licensed MIT OR Apache-2.0
(licenses/Nomad-LICENSE-MIT.txt, licenses/Nomad-LICENSE-APACHE.txt).

Components bundled INSIDE the Nomad launcher binaries
-----------------------------------------------------
* Atkinson Hyperlegible font - SIL Open Font License 1.1
  -> licenses/AtkinsonHyperlegible-OFL.txt
* 7-Zip 24.09 (7z.exe + 7z.dll, distributed unmodified) - GNU LGPL-2.1
  -> licenses/7-Zip-LICENSE.txt    Source: https://www.7-zip.org/

Software Nomad downloads at RUNTIME (NOT bundled in these binaries)
------------------------------------------------------------------
The browsers and apps Nomad launches (Firefox, Firefox ESR,
Mullvad Browser, Ungoogled Chromium, Helium, Floorp, Waterfox, LibreWolf,
Bitwarden) are fetched from their official sources at launch and remain under
their own licenses and trademarks. Nomad is an independent project and is not
affiliated with, endorsed by, or sponsored by any of them. See TRADEMARKS.md.
'@
Set-Content -Path (Join-Path $relDir "THIRD-PARTY-NOTICES.txt") -Value $notices -Encoding ascii
# THIRD-PARTY-NOTICES points readers at TRADEMARKS.md — ship it beside the binaries.
Copy-Item (Join-Path $PSScriptRoot "TRADEMARKS.md") (Join-Path $relDir "TRADEMARKS.md") -Force
Write-Host "Staged license bundle (licenses\ + THIRD-PARTY-NOTICES.txt + TRADEMARKS.md)"

# --- Integrity: SHA256SUMS over the launcher binaries (sha256sum -c format) ---
$sumsPath = Join-Path $relDir "SHA256SUMS"
$lines = foreach ($e in $exes) {
    $h = (Get-FileHash $e.FullName -Algorithm SHA256).Hash.ToLower()
    "$h  $($e.Name)"
}
# ASCII, no BOM, LF line endings. Set-Content would write CRLF, and GNU
# sha256sum treats the \r as part of the filename ("no file was verified" —
# the v1.0.2 manifest shipped with this bug).
[IO.File]::WriteAllText($sumsPath, (($lines -join "`n") + "`n"), [Text.Encoding]::ASCII)
Write-Host "Wrote SHA256SUMS ($($exes.Count) entries)"

# --- Authenticity: detached GPG signature of SHA256SUMS ---
# Set NOMAD_SIGNING_KEY to the Nomad release key's fingerprint (or uid/email)
# to sign. Users verify with: gpg --verify SHA256SUMS.asc SHA256SUMS
$key = $env:NOMAD_SIGNING_KEY
if ($key) {
    # Resolve gpg: $env:NOMAD_GPG override -> PATH -> common install locations
    # (Gpg4win / GnuPG / Git's bundled gpg). gpg is often not on the PowerShell
    # PATH even when installed, so probe explicitly rather than fail silently.
    $gpg = $null
    if ($env:NOMAD_GPG -and (Test-Path $env:NOMAD_GPG)) { $gpg = $env:NOMAD_GPG }
    if (-not $gpg) { $c = Get-Command gpg -ErrorAction SilentlyContinue; if ($c) { $gpg = $c.Source } }
    if (-not $gpg) {
        foreach ($p in @(
                "$env:ProgramFiles\GnuPG\bin\gpg.exe",
                "${env:ProgramFiles(x86)}\GnuPG\bin\gpg.exe",
                "$env:ProgramFiles\Git\usr\bin\gpg.exe")) {
            if (Test-Path $p) { $gpg = $p; break }
        }
    }
    if (-not $gpg) {
        Write-Warning "gpg not found (set NOMAD_GPG to gpg.exe's path); SHA256SUMS is left UNSIGNED"
    } else {
        $sig = "$sumsPath.asc"
        if (Test-Path $sig) { Remove-Item $sig -Force }
        & $gpg --batch --yes --local-user $key --armor --detach-sign --output $sig $sumsPath
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Signed SHA256SUMS -> SHA256SUMS.asc (key: $key)"
        } else {
            Write-Warning "GPG signing failed (exit $LASTEXITCODE); SHA256SUMS is left UNSIGNED"
        }
    }
} else {
    Write-Warning "NOMAD_SIGNING_KEY not set; skipping GPG signature (SHA256SUMS is UNSIGNED)"
}
