$ErrorActionPreference = 'Stop'

$stateDirectory = 'C:\ProgramData\LtoBackupManager'
$cli = 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe'
$resultDirectory = 'C:\Temp\LtoBackupManager'
$exportPath = Join-Path $resultDirectory 'live-job-catalog.json'
$resultPath = Join-Path $resultDirectory 'live-job-diagnostic.json'
try {
New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null

$exportOutput = @(& $cli --state-dir $stateDirectory --json catalog export --output $exportPath 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "Esportazione diagnostica del catalogo fallita: $LASTEXITCODE - $($exportOutput -join ' ')"
}
$catalog = Get-Content -LiteralPath $exportPath -Raw | ConvertFrom-Json
$job = @($catalog.automatic_jobs | Sort-Object created_at -Descending | Select-Object -First 1)
$job = if ($job.Count) { $job[0] } else { $null }
$cassette = $null
if ($job) {
    $cassette = @(
        $catalog.automatic_cassettes |
            Where-Object {
                $_.job_id -eq $job.id -and
                [int]$_.sequence -eq [int]$job.current_sequence
            } |
            Select-Object -First 1
    )
    $cassette = if ($cassette.Count) { $cassette[0] } else { $null }
}

$service = Get-CimInstance Win32_Service -Filter "Name='FUSE4WinSvc'" -ErrorAction SilentlyContinue
$processNames = @('LtoBackupManager.exe', 'LtoBackupManagerCli.exe', 'ltfs.exe', 'FUSE4WinSvc.exe')
function Get-IoSnapshot {
    $rows = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -in $processNames })
    [ordered]@{
        ReadBytes = [uint64](($rows | Measure-Object ReadTransferCount -Sum).Sum)
        WriteBytes = [uint64](($rows | Measure-Object WriteTransferCount -Sum).Sum)
        Processes = @($rows | Select-Object Name, ProcessId)
    }
}

$before = Get-IoSnapshot
Start-Sleep -Seconds 5
$after = Get-IoSnapshot
$ltfsVolumes = @(
    Get-CimInstance Win32_LogicalDisk |
        Where-Object { $_.FileSystem -eq 'LTFS' } |
        Select-Object DeviceID, FileSystem, Size, FreeSpace
)

[ordered]@{
    ObservedAt = (Get-Date).ToString('o')
    Job = if ($job) {
        [ordered]@{
            DisplayName = $job.display_name
            Status = $job.status
            CurrentSequence = [int]$job.current_sequence
            LastError = $job.last_error
        }
    } else { $null }
    Cassette = if ($cassette) {
        [ordered]@{
            Sequence = [int]$cassette.sequence
            Label = $cassette.physical_label
            Status = $cassette.status
            CopiedFiles = [int]$cassette.copied_files
            PlannedFiles = [int]$cassette.planned_files
            CopiedBytes = [int64]$cassette.copied_bytes
            PlannedBytes = [int64]$cassette.planned_bytes
            Error = $cassette.error
        }
    } else { $null }
    StoreOpenService = if ($service) {
        [ordered]@{ State = $service.State; ProcessId = [int]$service.ProcessId }
    } else { $null }
    LtfsVolumes = $ltfsVolumes
    ProcessCount = @($after.Processes).Count
    ReadBytesIn5Seconds = [math]::Max(0, [int64]$after.ReadBytes - [int64]$before.ReadBytes)
    WriteBytesIn5Seconds = [math]::Max(0, [int64]$after.WriteBytes - [int64]$before.WriteBytes)
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding UTF8

Remove-Item -LiteralPath $exportPath -Force -ErrorAction SilentlyContinue
}
catch {
    [ordered]@{
        ObservedAt = (Get-Date).ToString('o')
        DiagnosticError = $_.Exception.Message
    } | ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
