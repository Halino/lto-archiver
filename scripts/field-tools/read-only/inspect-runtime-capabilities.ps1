$ErrorActionPreference = 'Stop'

$stateDirectory = 'C:\ProgramData\LtoBackupManager'
$cli = 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe'
$temporaryExport = 'C:\Temp\LtoBackupManager\runtime-capabilities-catalog.json'
$resultPath = 'C:\Temp\LtoBackupManager\runtime-capabilities.json'
$storeOpen = 'C:\Program Files\HPE\LTFS'

try {
    $catalogOutput = @(& $cli --state-dir $stateDirectory --json catalog export --output $temporaryExport 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Esportazione interna del catalogo fallita con codice $LASTEXITCODE"
    }
    $catalog = Get-Content -LiteralPath $temporaryExport -Raw | ConvertFrom-Json
    $jobs = @($catalog.automatic_jobs)
    $activeStates = @('waiting_media', 'formatting', 'mounting', 'writing', 'unmounting')
    $service = Get-CimInstance Win32_Service -Filter "Name='FUSE4WinSvc'" -ErrorAction SilentlyContinue
    $volumes = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.FileSystem -eq 'LTFS' })
    $tapeClass = Get-CimClass -ClassName Win32_TapeDrive

    $attributes = @()
    $attributeTool = Join-Path $storeOpen 'ltfsattr.exe'
    foreach ($volume in $volumes) {
        if (-not (Test-Path -LiteralPath $attributeTool)) { break }
        $output = @(& $attributeTool -l ($volume.DeviceID + '\') 2>&1 | ForEach-Object { $_.ToString() })
        $attributes += @($output | ForEach-Object {
            if ($_ -match '^\s*([^:=\s]+)') { $Matches[1] }
        } | Where-Object { $_ } | Sort-Object -Unique)
    }

    [ordered]@{
        observed_at = (Get-Date).ToString('o')
        job_count = $jobs.Count
        active_job_count = @($jobs | Where-Object { $_.status -in $activeStates }).Count
        job_statuses = @($jobs.status | Group-Object | ForEach-Object {
            [ordered]@{ status = $_.Name; count = $_.Count }
        })
        storeopen_service_state = if ($service) { $service.State } else { 'missing' }
        ltfs_volume_count = $volumes.Count
        ltfs_volume_total_bytes = [uint64](($volumes | Measure-Object Size -Sum).Sum)
        ltfs_volume_free_bytes = [uint64](($volumes | Measure-Object FreeSpace -Sum).Sum)
        tape_cim_methods = @($tapeClass.CimClassMethods.Keys | Sort-Object)
        ltfs_attribute_names = @($attributes | Sort-Object -Unique)
        storeopen_files = @(Get-ChildItem -LiteralPath $storeOpen -File -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Name | Sort-Object)
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
catch {
    [ordered]@{ diagnostic_error = $_.Exception.Message } | ConvertTo-Json |
        Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
finally {
    Remove-Item -LiteralPath $temporaryExport -Force -ErrorAction SilentlyContinue
}
