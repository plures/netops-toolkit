[CmdletBinding()]
param(
    [string]$Version,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "netops-toolkit"),
    [string]$SourcePath,
    [switch]$CheckPython
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Get-PythonCandidate {
    param(
        [string]$Path,
        [string[]]$Arguments = @()
    )

    try {
        $versionText = & $Path @Arguments -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>$null
        if ($LASTEXITCODE -ne 0) {
            return $null
        }
        $version = [version]($versionText | Select-Object -First 1)
        if ($version -lt [version]"3.9") {
            return $null
        }
        return [pscustomobject]@{
            Path = $Path
            Arguments = $Arguments
            Version = $version
        }
    } catch {
        return $null
    }
}

function Get-PythonCommand {
    $candidates = @()
    $seen = @{}
    $launcher = Get-Command py -ErrorAction SilentlyContinue

    if ($null -ne $launcher) {
        $registered = & $launcher.Source -0p 2>$null
        foreach ($line in $registered) {
            if ($line -notmatch '^\s*-V:(?<tag>\S+)\s+\*?\s*(?<path>.+)$') {
                continue
            }
            $path = $Matches.path.Trim()
            if (-not $seen.ContainsKey($path)) {
                $seen[$path] = $true
                $candidate = Get-PythonCandidate -Path $path
                if ($null -ne $candidate) {
                    $candidates += $candidate
                }
            }
        }
    }

    foreach ($name in @("python", "python3")) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -eq $command -or $seen.ContainsKey($command.Source)) {
            continue
        }
        $seen[$command.Source] = $true
        $candidate = Get-PythonCandidate -Path $command.Source
        if ($null -ne $candidate) {
            $candidates += $candidate
        }
    }

    if ($null -ne $launcher) {
        $candidate = Get-PythonCandidate -Path $launcher.Source -Arguments @("-3")
        if ($null -ne $candidate) {
            $candidates += $candidate
        }
    }

    $selected = $candidates |
        Sort-Object -Property @{ Expression = { $_.Version }; Descending = $true }, Path |
        Select-Object -First 1
    if ($null -ne $selected) {
        return @{ Path = $selected.Path; Arguments = @($selected.Arguments); Version = $selected.Version }
    }

    throw "Python 3.9 or newer is required. Install it for the current user from https://www.python.org/downloads/windows/ and run this installer again."
}

function Get-ReleaseSource([string]$RequestedVersion) {
    $tag = if ($RequestedVersion -and -not $RequestedVersion.StartsWith("v")) {
        "v$RequestedVersion"
    } else {
        $RequestedVersion
    }
    $releaseEndpoint = if ($tag) {
        "https://api.github.com/repos/plures/netops-toolkit/releases/tags/$tag"
    } else {
        "https://api.github.com/repos/plures/netops-toolkit/releases/latest"
    }
    $release = Invoke-RestMethod -Uri $releaseEndpoint -Headers @{ Accept = "application/vnd.github+json" }
    $asset = @($release.assets | Where-Object { $_.name -match '^netops-toolkit-.+\.zip$' }) | Select-Object -First 1
    if ($null -eq $asset) {
        throw "The selected release has no Windows ZIP asset. Download the release ZIP manually from https://github.com/plures/netops-toolkit/releases."
    }

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("netops-toolkit-" + [guid]::NewGuid().ToString("N"))
    $archivePath = Join-Path $temporaryRoot $asset.name
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archivePath -UseBasicParsing
    Expand-Archive -LiteralPath $archivePath -DestinationPath $temporaryRoot -Force

    $source = Get-ChildItem -LiteralPath $temporaryRoot -Directory |
        Where-Object { Test-Path (Join-Path $_.FullName "pyproject.toml") } |
        Select-Object -First 1
    if ($null -eq $source) {
        throw "Downloaded release ZIP did not contain a netops-toolkit package."
    }

    return @{ Path = $source.FullName; TemporaryRoot = $temporaryRoot }
}

$temporaryRoot = $null
try {
    $pythonCommand = Get-PythonCommand
    $python = $pythonCommand.Path
    $pythonArguments = $pythonCommand.Arguments
    if ($CheckPython) {
        Write-Host "Selected Python $($pythonCommand.Version): $python $($pythonArguments -join ' ')"
        exit 0
    }
    if (-not $SourcePath -and $PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "pyproject.toml"))) {
        $SourcePath = $PSScriptRoot
    }
    if (-not $SourcePath) {
        $releaseSource = Get-ReleaseSource $Version
        $SourcePath = $releaseSource.Path
        $temporaryRoot = $releaseSource.TemporaryRoot
    }
    if (-not (Test-Path (Join-Path $SourcePath "pyproject.toml"))) {
        throw "No netops-toolkit source was found at $SourcePath."
    }

    $venv = Join-Path $InstallRoot "venv"
    $venvPython = Join-Path $venv "Scripts\\python.exe"
    $cliExecutable = Join-Path $venv "Scripts\\netops.exe"
    $tuiExecutable = Join-Path $venv "Scripts\\netops-tui.exe"
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null

    Write-Host "Creating a user-local virtual environment at $venv"
    & $python @pythonArguments -m venv $venv --clear
    if ($LASTEXITCODE -ne 0) { throw "Failed to create the virtual environment." }
    & $venvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw "Failed to upgrade pip in the virtual environment." }
    & $venvPython -m pip install "$SourcePath[tui,snmp,report]"
    if ($LASTEXITCODE -ne 0) { throw "Failed to install netops-toolkit and its TUI dependencies." }
    if (-not (Test-Path $cliExecutable) -or -not (Test-Path $tuiExecutable)) {
        throw "Installation completed without both netops.exe and netops-tui.exe."
    }

    try {
        $startMenu = Join-Path $env:APPDATA "Microsoft\\Windows\\Start Menu\\Programs"
        New-Item -ItemType Directory -Path $startMenu -Force | Out-Null
        $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $startMenu "netops-tui.lnk"))
        $shortcut.TargetPath = $tuiExecutable
        $shortcut.WorkingDirectory = $InstallRoot
        $shortcut.Description = "netops-toolkit terminal interface"
        $shortcut.Save()
    } catch {
        Write-Warning "Installed netops-tui, but could not create the Start menu shortcut: $($_.Exception.Message)"
    }

    Write-Host ""
    Write-Host "netops-toolkit installed for the current user."
    Write-Host "Command line: $cliExecutable"
    Write-Host "Start it from the Start menu, or run: $tuiExecutable"
} finally {
    if ($temporaryRoot -and (Test-Path $temporaryRoot)) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
