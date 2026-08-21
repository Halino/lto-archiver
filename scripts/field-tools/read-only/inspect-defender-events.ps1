$ErrorActionPreference = 'Stop'

$resultPath = 'C:\Temp\LtoBackupManager\defender-events-detail.json'
$log = 'Microsoft-Windows-Windows Defender/Operational'
$since = (Get-Date).AddHours(-8)

function Get-EventData($Event) {
    $values = @{}
    $xml = [xml]$Event.ToXml()
    foreach ($item in @($xml.Event.EventData.Data)) {
        $values[[string]$item.Name] = [string]$item.'#text'
    }
    return $values
}

function Get-ProcessClass([string]$Value) {
    if ($Value -match '(?i)\\Program Files\\LtoBackupManager\\LtoBackupManager\.exe$') {
        return 'installed-gui'
    }
    if ($Value -match '(?i)\\Program Files\\LtoBackupManager\\LtoBackupManagerCli\.exe$') {
        return 'installed-cli'
    }
    if ($Value -match '(?i)\\Temp\\LtoBackupManager\\') {
        return 'deployment-staging'
    }
    if (-not $Value) { return 'unknown' }
    return [IO.Path]::GetFileName($Value)
}

function Get-TargetClass([string]$Value) {
    if ($Value -match '(?i)^\\Device\\Tape') { return 'tape-device' }
    if ($Value -match '(?i)^\\Device\\HarddiskVolumeShadowCopy') { return 'volume-shadow-copy' }
    if ($Value -match '(?i)^\\Device\\Harddisk') { return 'disk-device' }
    if ($Value -match '(?i)LtoBackupManager|LTO-Archiver') { return 'lto-path' }
    if (-not $Value) { return 'unknown' }
    return 'other'
}

try {
    $blocked = @()
    foreach ($event in @(Get-WinEvent -FilterHashtable @{LogName=$log; Id=1127; StartTime=$since} `
        -ErrorAction SilentlyContinue)) {
        $data = Get-EventData $event
        $processValue = @($data.GetEnumerator() | Where-Object {
            $_.Key -match '(?i)Process'
        } | Select-Object -First 1).Value
        $pathValue = @($data.GetEnumerator() | Where-Object {
            $_.Key -match '(?i)^Path$|Device'
        } | Select-Object -First 1).Value
        $blocked += [ordered]@{
            time = $event.TimeCreated
            process_class = Get-ProcessClass $processValue
            target_class = Get-TargetClass $pathValue
        }
    }

    $failures = @()
    foreach ($event in @(Get-WinEvent -FilterHashtable @{LogName=$log; Id=3002; StartTime=$since} `
        -ErrorAction SilentlyContinue)) {
        $data = Get-EventData $event
        $failures += [ordered]@{
            time = $event.TimeCreated
            feature = $data.Feature_Name
            error_code = $data.Error_Code
            error_description = $data.Error_Description
            reason = $data.Reason
        }
    }
    $recoveries = @(Get-WinEvent -FilterHashtable @{LogName=$log; Id=3007; StartTime=$since} `
        -ErrorAction SilentlyContinue | ForEach-Object { $_.TimeCreated })

    [ordered]@{
        observed_at = (Get-Date).ToString('o')
        controlled_folder_blocks = $blocked
        realtime_failures = $failures
        realtime_recoveries = $recoveries
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
catch {
    [ordered]@{ diagnostic_error = $_.Exception.Message } | ConvertTo-Json |
        Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
