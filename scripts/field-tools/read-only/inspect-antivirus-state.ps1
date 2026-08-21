$ErrorActionPreference = 'Stop'

$resultDirectory = 'C:\Temp\LtoBackupManager'
$resultPath = Join-Path $resultDirectory 'antivirus-state.json'
$since = (Get-Date).AddHours(-8)

function Get-ResourceClass([string]$Resource) {
    if ($Resource -match '(?i)\\Program Files\\LtoBackupManager\\LtoBackupManager\.exe') {
        return 'installed-gui'
    }
    if ($Resource -match '(?i)\\Program Files\\LtoBackupManager\\LtoBackupManagerCli\.exe') {
        return 'installed-cli'
    }
    if ($Resource -match '(?i)\\Temp\\LtoBackupManager\\') {
        return 'deployment-staging'
    }
    if ($Resource -match '(?i)LtoBackupManager|LTO-Archiver') {
        return 'other-lto-resource'
    }
    return 'unrelated'
}

try {
    New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
    $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct `
        -ErrorAction SilentlyContinue | Select-Object displayName, productState)
    $services = @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '(?i)WinDefend|CSFalcon|CrowdStrike|McAfee|mfemms|masvc'
    } | Select-Object Name, Status, StartType)

    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $detections = @()
    foreach ($detection in @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object {
        $_.InitialDetectionTime -ge $since -or $_.LastThreatStatusChangeTime -ge $since
    })) {
        $classes = @($detection.Resources | ForEach-Object { Get-ResourceClass $_ } |
            Where-Object { $_ -ne 'unrelated' } | Sort-Object -Unique)
        if ($classes.Count) {
            $detections += [ordered]@{
                initial_detection_time = $detection.InitialDetectionTime
                last_status_change = $detection.LastThreatStatusChangeTime
                threat_id = [int64]$detection.ThreatID
                threat_status_id = [int]$detection.ThreatStatusID
                action_success = [bool]$detection.ActionSuccess
                resource_classes = $classes
            }
        }
    }

    $eventSummaries = @()
    $logs = @(
        'Microsoft-Windows-Windows Defender/Operational',
        'CrowdStrike-Falcon Sensor-CSFalconService/Operational',
        'Microsoft-Windows-CodeIntegrity/Operational'
    )
    foreach ($log in $logs) {
        if (Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue) {
            $events = @(Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$since} `
                -ErrorAction SilentlyContinue | Where-Object {
                    $_.Level -in @(2, 3) -or $_.Id -in @(1116, 1117, 1121, 1122)
                })
            $eventSummaries += [ordered]@{
                log = $log
                warning_or_detection_count = $events.Count
                recent = @($events | Select-Object -First 20 | ForEach-Object {
                    [ordered]@{ time = $_.TimeCreated; id = $_.Id; level = $_.LevelDisplayName }
                })
            }
        }
    }

    $gui = 'C:\Program Files\LtoBackupManager\LtoBackupManager.exe'
    $cli = 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe'
    [ordered]@{
        observed_at = (Get-Date).ToString('o')
        antivirus_products = $products
        antivirus_services = $services
        defender = if ($defenderStatus) {
            [ordered]@{
                antivirus_enabled = $defenderStatus.AntivirusEnabled
                realtime_enabled = $defenderStatus.RealTimeProtectionEnabled
                signature_updated = $defenderStatus.AntivirusSignatureLastUpdated
            }
        } else { $null }
        relevant_defender_detections = $detections
        security_event_summaries = $eventSummaries
        installed_gui = [ordered]@{
            exists = Test-Path -LiteralPath $gui
            sha256 = if (Test-Path -LiteralPath $gui) {
                (Get-FileHash -Algorithm SHA256 -LiteralPath $gui).Hash
            } else { $null }
        }
        installed_cli = [ordered]@{
            exists = Test-Path -LiteralPath $cli
            sha256 = if (Test-Path -LiteralPath $cli) {
                (Get-FileHash -Algorithm SHA256 -LiteralPath $cli).Hash
            } else { $null }
        }
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
catch {
    [ordered]@{
        observed_at = (Get-Date).ToString('o')
        diagnostic_error = $_.Exception.Message
    } | ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
