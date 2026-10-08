param([Parameter(Mandatory=$true)][string]$NodePath, [string]$TaskName = 'BotBridge-Recovery')
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$nodeExe = (Resolve-Path -LiteralPath $NodePath).Path
$entry = Join-Path $PSScriptRoot 'recover_pm2.cjs'
$homePath = Join-Path $repoRoot '.pm2'
New-Item -ItemType Directory -Path $homePath -Force | Out-Null
$launcher = Join-Path $homePath 'recovery_launcher.vbs'
$launchCommand = '"' + $nodeExe + '" "' + $entry + '"'
$vbs = 'Set shell = CreateObject("WScript.Shell")' + "`r`n" + 'result = shell.Run("' + $launchCommand.Replace('"','""') + '", 0, True)' + "`r`n" + 'WScript.Quit result' + "`r`n"
[IO.File]::WriteAllText($launcher, $vbs, [Text.Encoding]::Unicode)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\wscript.exe') -Argument ('"' + $launcher + '"') -WorkingDirectory $repoRoot
$logon = New-ScheduledTaskTrigger -AtLogOn -User $identity
$repeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 2)
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
$task = New-ScheduledTask -Action $action -Trigger @($logon, $repeat) -Principal $principal -Settings $settings -Description 'Hidden BotBridge daemon recovery. Restores missing saved services without restarting deliberately stopped processes.'
Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName,State,Principal,Actions,Triggers
