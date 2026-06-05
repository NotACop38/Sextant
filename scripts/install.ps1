<#
.SYNOPSIS
    Sextant installer for Windows.

.DESCRIPTION
    Downloads the prebuilt `sextant` binary for Windows from the GitHub Releases
    page, verifies its SHA-256 checksum, and installs it into a bin directory.
    It does not require Rust or a compiler.

.EXAMPLE
    irm https://raw.githubusercontent.com/NotACop38/Sextant/main/scripts/install.ps1 | iex

.NOTES
    Environment overrides:
      SEXTANT_VERSION   Version to install, for example 0.1.0 (default: latest).
      SEXTANT_BIN_DIR   Install directory (default: %LOCALAPPDATA%\Sextant\bin).
      SEXTANT_REPO      GitHub owner/repo (default: NotACop38/Sextant).

    To build from source instead, use `cargo install sextant-re`.
#>

$ErrorActionPreference = "Stop"

$repo = if ($env:SEXTANT_REPO) { $env:SEXTANT_REPO } else { "NotACop38/Sextant" }
$binName = "sextant"
$binDir = if ($env:SEXTANT_BIN_DIR) { $env:SEXTANT_BIN_DIR } else { Join-Path $env:LOCALAPPDATA "Sextant\bin" }
$target = "x86_64-pc-windows-msvc"

# Resolve the version: explicit override, or the latest published release.
$version = $env:SEXTANT_VERSION
if (-not $version) {
    $api = "https://api.github.com/repos/$repo/releases/latest"
    $release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "sextant-install" }
    $version = $release.tag_name -replace '^v', ''
}
if (-not $version) { throw "could not determine the latest release version" }

$archive = "$binName-v$version-$target.zip"
$base = "https://github.com/$repo/releases/download/v$version"
$url = "$base/$archive"
$sumUrl = "$url.sha256"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $zipPath = Join-Path $tmp $archive
    $sumPath = "$zipPath.sha256"

    Write-Host "Downloading $archive ..."
    Invoke-WebRequest -Uri $url -OutFile $zipPath -Headers @{ "User-Agent" = "sextant-install" }
    Invoke-WebRequest -Uri $sumUrl -OutFile $sumPath -Headers @{ "User-Agent" = "sextant-install" }

    Write-Host "Verifying checksum ..."
    $expected = ((Get-Content $sumPath) -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLower()
    if ($expected -ne $actual) {
        throw "checksum mismatch: expected $expected, got $actual"
    }

    Write-Host "Extracting ..."
    Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
    $exe = Join-Path $tmp "$binName-v$version-$target\$binName.exe"
    if (-not (Test-Path $exe)) { throw "binary not found in archive" }

    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    Copy-Item -Path $exe -Destination (Join-Path $binDir "$binName.exe") -Force

    Write-Host "Installed $binName $version to $binDir\$binName.exe"
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$binDir*") {
        Write-Host "Note: $binDir is not on your PATH. Add it, for example:"
        Write-Host "  setx PATH `"$binDir;`$env:PATH`""
    }
    Write-Host "Run '$binName --help' to get started."
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
