$ErrorActionPreference = 'Stop'

$resultPath = 'C:\Temp\LtoBackupManager\live-io-diagnostic.json'
$processNames = @('LtoBackupManager.exe', 'ltfs.exe', 'FUSE4WinSvc.exe')
$jobLockPath = 'C:\ProgramData\LtoBackupManager\automatic-job.lock'

function Get-IoSnapshot {
    $rows = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -in $processNames })
    [ordered]@{
        ReadBytes = [uint64](($rows | Measure-Object ReadTransferCount -Sum).Sum)
        WriteBytes = [uint64](($rows | Measure-Object WriteTransferCount -Sum).Sum)
        Count = $rows.Count
    }
}

$serviceBefore = Get-CimInstance Win32_Service -Filter "Name='FUSE4WinSvc'" -ErrorAction SilentlyContinue
$before = Get-IoSnapshot
Start-Sleep -Seconds 10
$after = Get-IoSnapshot
$serviceAfter = Get-CimInstance Win32_Service -Filter "Name='FUSE4WinSvc'" -ErrorAction SilentlyContinue
$ltfsVolumes = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.FileSystem -eq 'LTFS' })
$tapeDrives = @(Get-CimInstance Win32_TapeDrive)
$processRows = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -in $processNames })
$jobLockHeld = $false
if (Test-Path -LiteralPath $jobLockPath) {
    $lockStream = $null
    try {
        $lockStream = [System.IO.File]::Open(
            $jobLockPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::ReadWrite
        )
        $lockStream.Lock(0, 1)
        $lockStream.Unlock(0, 1)
    }
    catch [System.IO.IOException] {
        $jobLockHeld = $true
    }
    finally {
        if ($lockStream) { $lockStream.Dispose() }
    }
}

[ordered]@{
    ObservedAt = (Get-Date).ToString('o')
    StoreOpenStateBefore = if ($serviceBefore) { $serviceBefore.State } else { 'missing' }
    StoreOpenStateAfter = if ($serviceAfter) { $serviceAfter.State } else { 'missing' }
    LtfsVolumeCount = $ltfsVolumes.Count
    RelevantProcessCount = $after.Count
    ApplicationProcessCount = @($processRows | Where-Object { $_.Name -eq 'LtoBackupManager.exe' }).Count
    LtfsProcessCount = @($processRows | Where-Object { $_.Name -eq 'ltfs.exe' }).Count
    AutomaticJobLockHeld = $jobLockHeld
    TapeDriveCount = $tapeDrives.Count
    TapeDriveStatuses = @($tapeDrives | ForEach-Object { $_.Status })
    ReadBytesIn10Seconds = [math]::Max(0, [int64]$after.ReadBytes - [int64]$before.ReadBytes)
    WriteBytesIn10Seconds = [math]::Max(0, [int64]$after.WriteBytes - [int64]$before.WriteBytes)
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding UTF8
