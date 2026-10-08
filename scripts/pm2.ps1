$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
& (Join-Path $repoRoot '.venv/Scripts/python.exe') (Join-Path $repoRoot 'scripts/manage.py') pm2 @args
exit $LASTEXITCODE
