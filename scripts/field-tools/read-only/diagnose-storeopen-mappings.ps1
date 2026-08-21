$ErrorActionPreference = 'Stop'

$resultPath = 'C:\Temp\LtoBackupManager\storeopen-mapping-diagnostic.json'
$mappingRoot = 'HKLM:\SOFTWARE\HPE\LTFS\Mappings'
$mappings = @()
if (Test-Path -LiteralPath $mappingRoot) {
    $mappings = @(Get-ChildItem -LiteralPath $mappingRoot | ForEach-Object {
        $properties = Get-ItemProperty -LiteralPath $_.PSPath
        $letter = $_.PSChildName.ToUpperInvariant()
        $logical = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$letter`:'" -ErrorAction SilentlyContinue
        [ordered]@{
            Letter = $letter
            DeviceName = [string]$properties.DeviceName
            HasLogicalDrive = ($null -ne $logical)
            FileSystem = if ($logical) { [string]$logical.FileSystem } else { $null }
        }
    })
}
$service = Get-Service -Name 'FUSE4WinSvc' -ErrorAction SilentlyContinue
$processes = @(Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match '^(LtoBackupManager|ltfs|mkltfs|unltfs|ltfsck|fuse4win)\.exe$'
} | Select-Object Name, ProcessId)

[ordered]@{
    CapturedAt = (Get-Date).ToString('o')
    MappingCount = $mappings.Count
    Mappings = $mappings
    ServiceExists = ($null -ne $service)
    ServiceStatus = if ($service) { [string]$service.Status } else { $null }
    Processes = $processes
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding UTF8
