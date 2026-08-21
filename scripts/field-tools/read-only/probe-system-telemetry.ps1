$ErrorActionPreference = 'Continue'

$cli = 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe'
$resultPath = 'C:\Temp\LtoBackupManager\system-telemetry-probe.json'
$output = @(& $cli --json telemetry --device TAPE0 2>&1 | ForEach-Object { $_.ToString() })
$exitCode = $LASTEXITCODE
[ordered]@{
    observed_at = (Get-Date).ToString('o')
    exit_code = $exitCode
    output = $output
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding UTF8
