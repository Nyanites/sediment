# Sediment installer for Windows.
#
#   irm https://nyanites.github.io/sediment/install.ps1 | iex
#
# What it does, in order:
#   1. Downloads the latest Sediment release for your CPU (x64 or ARM64), and its
#      SHA256SUMS.txt, from https://github.com/Nyanites/sediment/releases
#   2. Checks the download against the published SHA-256 checksum and stops if it
#      doesn't match.
#   3. Installs sediment.exe to %LOCALAPPDATA%\Programs\Sediment, adds a Start menu
#      shortcut, and adds that folder to your user PATH so `sediment $MFT` works.
#   4. Cleans up its temporary files.
#
# No administrator rights needed; it changes nothing outside your user profile.
#
# Options (environment variables):
#   $env:SEDIMENT_VERSION = "0.1.0"      install a specific release instead of the latest
#   $env:SEDIMENT_INSTALL_DIR = "<dir>"  install somewhere else
#
# Uninstall: delete %LOCALAPPDATA%\Programs\Sediment and the Sediment Start menu
# shortcut, and remove that folder from your user PATH.
#
# Source: https://github.com/Nyanites/sediment/blob/main/docs/install.ps1

# Everything runs inside a function, called on the last line, so a partially
# downloaded script does nothing.
function Install-Sediment {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'  # Invoke-WebRequest is much faster without it
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $repo = 'Nyanites/sediment'
    function Say($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { $asset = 'sediment-windows-x86_64.exe' }
        'ARM64' { $asset = 'sediment-windows-arm64.exe' }
        default { throw "Sediment needs 64-bit Windows (this is $arch)." }
    }

    if ($env:SEDIMENT_VERSION) {
        if ($env:SEDIMENT_VERSION -notmatch '^v?[0-9A-Za-z.\-]+$') {
            throw "invalid SEDIMENT_VERSION: $env:SEDIMENT_VERSION"
        }
        $base = "https://github.com/$repo/releases/download/v$($env:SEDIMENT_VERSION -replace '^v', '')"
    } else {
        $base = "https://github.com/$repo/releases/latest/download"
    }

    $dest = $env:SEDIMENT_INSTALL_DIR
    if (-not $dest) { $dest = Join-Path $env:LOCALAPPDATA 'Programs\Sediment' }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("sediment-install-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Say "Downloading $asset"
        Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS.txt" -OutFile "$tmp\SHA256SUMS.txt"
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile "$tmp\$asset"

        Say 'Verifying checksum'
        $expected = $null
        foreach ($line in Get-Content "$tmp\SHA256SUMS.txt") {
            $parts = $line -split '\s+', 2
            if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $asset) { $expected = $parts[0].ToLower() }
        }
        if (-not $expected) { throw "checksum for $asset not found in SHA256SUMS.txt" }
        $actual = (Get-FileHash -Algorithm SHA256 "$tmp\$asset").Hash.ToLower()
        if ($expected -ne $actual) {
            throw "checksum mismatch for $asset (expected $expected, got $actual); not installing"
        }

        Say "Installing to $dest"
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        $exe = Join-Path $dest 'sediment.exe'
        $running = Get-Process -Name sediment -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -eq $exe }
        if ($running) {
            Say 'Closing the running Sediment'
            $running | Stop-Process -Force
            Start-Sleep -Seconds 1
        }
        Copy-Item -Force "$tmp\$asset" $exe

        $startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
        $shell = New-Object -ComObject WScript.Shell
        $lnk = $shell.CreateShortcut((Join-Path $startMenu 'Sediment.lnk'))
        $lnk.TargetPath = $exe
        $lnk.WorkingDirectory = $dest
        $lnk.Description = 'Windows forensic artifact explorer'
        $lnk.Save()

        # Edit the raw registry value so entries like %USERPROFILE%\bin stay unexpanded.
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
        try {
            $raw = [string]$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
            $entries = @($raw -split ';' | Where-Object { $_ })
            if ($entries -notcontains $dest) {
                $key.SetValue('Path', (($entries + $dest) -join ';'), 'ExpandString')
                # Setting any user variable broadcasts WM_SETTINGCHANGE, so new terminals see PATH.
                [Environment]::SetEnvironmentVariable('SEDIMENT_INSTALL_REFRESH', $null, 'User')
                $env:Path = "$env:Path;$dest"
            }
        } finally {
            $key.Close()
        }

        Say "Sediment is installed: $exe"
        Write-Host '    Start it from the Start menu, or run: sediment'
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

Install-Sediment
