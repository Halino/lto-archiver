$ErrorActionPreference = 'Stop'

$resultPath = 'C:\Temp\LtoBackupManager\live-io-detailed.json'
$processNames = @('LtoBackupManager.exe', 'ltfs.exe', 'FUSE4WinSvc.exe')

function Get-Snapshot {
    $rows = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -in $processNames })
    $result = @{}
    foreach ($group in @($rows | Group-Object Name)) {
        $result[$group.Name] = [ordered]@{
            count = $group.Count
            read_bytes = [uint64](($group.Group | Measure-Object ReadTransferCount -Sum).Sum)
            write_bytes = [uint64](($group.Group | Measure-Object WriteTransferCount -Sum).Sum)
            kernel_ms = [uint64](($group.Group | Measure-Object KernelModeTime -Sum).Sum / 10000)
            user_ms = [uint64](($group.Group | Measure-Object UserModeTime -Sum).Sum / 10000)
        }
    }
    return $result
}

$before = Get-Snapshot
Start-Sleep -Seconds 10
$after = Get-Snapshot
$names = @($before.Keys + $after.Keys | Sort-Object -Unique)
$deltas = @()
foreach ($name in $names) {
    $left = $before[$name]
    $right = $after[$name]
    $deltas += [ordered]@{
        process_class = $name
        count = if ($right) { $right.count } else { 0 }
        read_bytes = if ($left -and $right) {
            [math]::Max(0, [int64]$right.read_bytes - [int64]$left.read_bytes)
        } else { 0 }
        write_bytes = if ($left -and $right) {
            [math]::Max(0, [int64]$right.write_bytes - [int64]$left.write_bytes)
        } else { 0 }
        cpu_ms = if ($left -and $right) {
            [math]::Max(0, [int64]($right.kernel_ms + $right.user_ms) - [int64]($left.kernel_ms + $left.user_ms))
        } else { 0 }
    }
}

[ordered]@{
    observed_at = (Get-Date).ToString('o')
    interval_seconds = 10
    process_deltas = $deltas
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding UTF8
