$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$env:PM2_HOME = Join-Path $repoRoot '.pm2'
& (Join-Path $repoRoot '.venv/Scripts/python.exe') (Join-Path $repoRoot 'scripts/manage.py') start
exit $LASTEXITCODE
