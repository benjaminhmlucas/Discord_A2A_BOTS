$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
& py -3.11 (Join-Path $repoRoot 'scripts/manage.py') setup
exit $LASTEXITCODE
