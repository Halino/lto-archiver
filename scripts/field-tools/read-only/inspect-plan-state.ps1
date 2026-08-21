$ErrorActionPreference = 'Stop'

$stateDirectory = 'C:\ProgramData\LtoBackupManager'
$cli = 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe'
$resultDirectory = 'C:\Temp\LtoBackupManager'
$exportPath = Join-Path $resultDirectory 'plan-state-catalog.json'
$resultPath = Join-Path $resultDirectory 'plan-state-result.json'

try {
    New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
    $config = Get-Content -LiteralPath (Join-Path $stateDirectory 'config.json') -Raw |
        ConvertFrom-Json
    $processes = @(Get-Process -Name 'LtoBackupManager' -ErrorAction SilentlyContinue)
    $exportOutput = @(& $cli --state-dir $stateDirectory --json catalog export --output $exportPath 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Catalog export failed: $LASTEXITCODE - $($exportOutput -join ' ')"
    }
    $catalog = Get-Content -LiteralPath $exportPath -Raw | ConvertFrom-Json
    $jobRows = @($catalog.automatic_jobs | Sort-Object created_at -Descending)
    $latest = if ($jobRows.Count) { $jobRows[0] } else { $null }
    $latestCassettes = if ($latest) {
        @($catalog.automatic_cassettes | Where-Object { $_.job_id -eq $latest.id })
    } else { @() }
    $latestLibraries = if ($latest) {
        @($catalog.automatic_job_libraries | Where-Object { $_.job_id -eq $latest.id })
    } else { @() }
    [ordered]@{
        observed_at = (Get-Date).ToString('o')
        gui_process_count = $processes.Count
        reserve_bytes = [int64]$config.reserve_bytes
        tape_capacity_bytes = [int64]$config.tape_capacity_bytes
        job_count = $jobRows.Count
        active_job_count = @($jobRows | Where-Object {
            $_.status -notin @('completed', 'failed', 'paused', 'planned')
        }).Count
        latest_plan = if ($latest) {
            [ordered]@{
                media_key = $latest.media_key
                status = $latest.status
                library_count = $latestLibraries.Count
                cassette_count = $latestCassettes.Count
                planned_files = [int64](($latestCassettes | Measure-Object planned_files -Sum).Sum)
                planned_bytes = [int64](($latestCassettes | Measure-Object planned_bytes -Sum).Sum)
                planned_bytes_per_cassette = @($latestCassettes | Sort-Object sequence |
                    ForEach-Object { [int64]$_.planned_bytes })
            }
        } else { $null }
    } | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
catch {
    [ordered]@{
        observed_at = (Get-Date).ToString('o')
        diagnostic_error = $_.Exception.Message
    } | ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
finally {
    Remove-Item -LiteralPath $exportPath -Force -ErrorAction SilentlyContinue
}
