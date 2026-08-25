[CmdletBinding()]
param(
    [string]$Version,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "netops-toolkit"),
    [string]$SourcePath
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Get-PythonCommand {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $python) {
        $python = Get-Command py -ErrorAction SilentlyContinue
        if ($null -eq $python) {
            throw "Python 3.9 or newer is required. Install it for the current user from https://www.python.org/downloads/windows/ and run this installer again."
        }
        $arguments = @("-3")
    } else {
        $arguments = @()
    }

    & $python.Source @arguments -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)"
    if ($LASTEXITCODE -ne 0) {
        throw "Python 3.9 or newer is required. Found: $(& $python.Source @arguments --version)"
    }

    return @{ Path = $python.Source; Arguments = $arguments }
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
    $tuiExecutable = Join-Path $venv "Scripts\\netops-tui.exe"
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null

    Write-Host "Creating a user-local virtual environment at $venv"
    & $python @pythonArguments -m venv $venv --clear
    & $venvPython -m pip install --upgrade pip
    & $venvPython -m pip install "$SourcePath[tui,snmp,report]"
    if (-not (Test-Path $tuiExecutable)) {
        throw "Installation completed without netops-tui.exe."
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
    Write-Host "Start it from the Start menu, or run: $tuiExecutable"
} finally {
    if ($temporaryRoot -and (Test-Path $temporaryRoot)) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
