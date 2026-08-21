$ErrorActionPreference = 'Stop'

$resultPath = 'C:\Temp\LtoBackupManager\run-lock-status.json'
$lockPath = 'C:\ProgramData\LtoBackupManager\run.lock'

try {
    $service = Get-CimInstance Win32_Service -Filter "Name='FUSE4WinSvc'" -ErrorAction SilentlyContinue
    $volumes = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.FileSystem -eq 'LTFS' })
    $guiProcesses = @(Get-Process -Name 'LtoBackupManager' -ErrorAction SilentlyContinue)
    $acl = if (Test-Path -LiteralPath $lockPath) { Get-Acl -LiteralPath $lockPath } else { $null }
    $canOpen = $false
    $openError = $null
    if (Test-Path -LiteralPath $lockPath) {
        try {
            $stream = [System.IO.File]::Open(
                $lockPath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
            )
            $stream.Dispose()
            $canOpen = $true
        }
        catch { $openError = $_.Exception.GetType().Name }
    }
    [ordered]@{
        observed_at = (Get-Date).ToString('o')
        gui_process_count = $guiProcesses.Count
        storeopen_service_state = if ($service) { $service.State } else { 'missing' }
        ltfs_volume_count = $volumes.Count
        run_lock_exists = Test-Path -LiteralPath $lockPath
        system_can_open_run_lock = $canOpen
        open_error_class = $openError
        owner = if ($acl) { $acl.Owner } else { $null }
        access_rules = if ($acl) {
            @($acl.Access | ForEach-Object {
                [ordered]@{
                    identity = $_.IdentityReference.Value
                    rights = $_.FileSystemRights.ToString()
                    type = $_.AccessControlType.ToString()
                    inherited = [bool]$_.IsInherited
                }
            })
        } else { @() }
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
catch {
    [ordered]@{ diagnostic_error = $_.Exception.Message } | ConvertTo-Json |
        Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
