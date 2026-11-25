[CmdletBinding()]
param(
    [ValidateSet("plan", "install", "update", "resume", "verify", "restore", "uninstall")]
    [string]$Action = "install",
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "netops-toolkit"),
    [string]$SourcePath = $PSScriptRoot,
    [string]$PlanFile,
    [string]$Checkpoint,
    [string[]]$Capability = @(),
    [string[]]$Companion = @(),
    [string]$GenerationId,
    [string]$InstallationId,
    [string]$Python,
    [switch]$Enhanced,
    [switch]$CheckPython,
    [switch]$DocsOnly,
    [string]$DocsDirectory = $env:NETOPS_DOCS_DIR
)

$ErrorActionPreference = "Stop"

# No acquisition, global environment, shortcut, shell settings or ACL repair.
# The Python entry point owns exact plan review and private one-use consent.
if (-not $Python) {
    $candidate = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $candidate) {
        Write-Error "An existing compatible Python is required to review setup. No runtime was acquired."
        exit 3
    }
    $Python = $candidate.Source
}
$identity = & $Python -I -B -c "import sys; print(sys.executable); sys.exit(0 if sys.version_info >= (3,9) else 3)"
if ($LASTEXITCODE -ne 0) { exit 3 }
if ($CheckPython) {
    Write-Host "Selected existing Python: $identity"
    exit 0
}
if (-not (Test-Path -LiteralPath (Join-Path $SourcePath "netops/setup.py") -PathType Leaf)) {
    Write-Error "Select a reviewed local source containing netops/setup.py."
    exit 3
}
# Preserve the [tui,snmp,report,docs] installation contract through the registry,
# not global pip. The owned bridge executes Python -m mkdocs build --strict
# --config-file <reviewed-source>/mkdocs.yml --site-dir <owned-output>/site.
if (-not $DocsDirectory) { $DocsDirectory = Join-Path $env:LOCALAPPDATA "netops-docs" }
if ($DocsOnly) {
    & $Python -I -B -c "import sys,site; sys.path.insert(0,sys.argv.pop(1)); p=site.getusersitepackages(); sys.path.extend([p] if isinstance(p,str) else p); from netops.dependencies._documentation import _main; raise SystemExit(_main())" $SourcePath --source $SourcePath --output $DocsDirectory
    exit $LASTEXITCODE
}
$arguments = @($Action, "--root", $InstallRoot)
if ($PlanFile) { $arguments += @("--plan-file", $PlanFile) }
if ($Checkpoint) { $arguments += @("--checkpoint", $Checkpoint) }
foreach ($item in $Capability) { $arguments += @("--capability", $item) }
foreach ($item in $Companion) { $arguments += @("--companion", $item) }
if ($Enhanced) { $arguments += "--enhanced" }
if ($GenerationId) { $arguments += @("--generation-id", $GenerationId) }
if ($InstallationId) { $arguments += @("--installation-id", $InstallationId) }
# Isolated import of this explicitly selected reviewed source only; no
# PYTHONPATH/editable install. The child may create only the consented root.
& $Python -I -B -c "import sys; sys.path.insert(0,sys.argv.pop(1)); from netops.setup import main; raise SystemExit(main())" $SourcePath @arguments
$setupExit = $LASTEXITCODE
if ($setupExit -ne 0) { exit $setupExit }
if ($Action -in @("install", "update")) {
    & $Python -I -B -c "import sys,site; sys.path.insert(0,sys.argv.pop(1)); p=site.getusersitepackages(); sys.path.extend([p] if isinstance(p,str) else p); from netops.dependencies._documentation import _main; raise SystemExit(_main())" $SourcePath --source $SourcePath --output $DocsDirectory
    exit $LASTEXITCODE
}
exit $setupExit
