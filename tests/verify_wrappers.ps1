param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$Receipt,
    [string[]]$TargetArguments = @(),
    [switch]$StubPythonLauncher,
    [int]$StubExitCode = 0
)
$ErrorActionPreference = 'Stop'
$parseTokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Target, [ref]$parseTokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Wrapper syntax is invalid' }
$branchNodes = $ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.IfStatementAst] -or
    $node -is [System.Management.Automation.Language.LoopStatementAst] -or
    $node -is [System.Management.Automation.Language.SwitchStatementAst] -or
    $node -is [System.Management.Automation.Language.TryStatementAst] -or
    $node -is [System.Management.Automation.Language.TernaryExpressionAst]
}, $true)
if ($branchNodes.Count -ne 0) { throw 'Setup decisions must remain in the branch-tested Python orchestrator' }
$points = @()
$breakpoints = @()
foreach ($statement in $ast.EndBlock.Statements) {
    $point = [pscustomobject]@{ line = $statement.Extent.StartLineNumber; hit = $false }
    $points += $point
    $action = { $point.hit = $true }.GetNewClosure()
    $breakpoints += Set-PSBreakpoint -Script $Target -Line $point.line -Action $action
}
if ($StubPythonLauncher) {
    function global:py { $global:LASTEXITCODE = $StubExitCode }
}
$resultCode = 0
try {
    & $Target @TargetArguments
    $resultCode = $LASTEXITCODE
} finally {
    $breakpoints | Remove-PSBreakpoint
    $result = [pscustomobject]@{ wrapper = [IO.Path]::GetFileName($Target); branches = 0; statements = $points; exit_code = $resultCode }
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Receipt
}
if (@($points | Where-Object { -not $_.hit }).Count) { throw 'An executable wrapper statement was not observed' }
exit $resultCode
