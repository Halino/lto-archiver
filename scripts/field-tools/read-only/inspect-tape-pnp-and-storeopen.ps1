$ErrorActionPreference = 'Stop'

$resultPath = 'C:\Temp\LtoBackupManager\tape-pnp-storeopen.json'
$mappingRoot = 'HKLM:\SOFTWARE\HPE\LTFS\Mappings'
$logRoots = @(
    'C:\ProgramData\Hewlett-Packard\LTFS',
    'C:\ProgramData\HPE\LTFS'
)

function Get-ValueHash([object]$Value) {
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $bytes = [Text.Encoding]::UTF8.GetBytes($text.Trim())
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '') }
    finally { $sha.Dispose() }
}

try {
    $mappingSerialHashes = @()
    if (Test-Path -LiteralPath $mappingRoot) {
        foreach ($mapping in Get-ChildItem -LiteralPath $mappingRoot -ErrorAction SilentlyContinue) {
            $serial = (Get-ItemProperty -LiteralPath $mapping.PSPath -ErrorAction SilentlyContinue).SerialNumber
            $hash = Get-ValueHash $serial
            if ($hash) { $mappingSerialHashes += $hash }
        }
    }

    $drives = @()
    foreach ($drive in @(Get-CimInstance Win32_TapeDrive)) {
        $properties = @()
        if ($drive.PNPDeviceID) {
            foreach ($property in @(Get-PnpDeviceProperty -InstanceId $drive.PNPDeviceID -ErrorAction SilentlyContinue)) {
                if ($null -eq $property.Data -or [string]::IsNullOrWhiteSpace([string]$property.Data)) {
                    continue
                }
                $hash = Get-ValueHash $property.Data
                $properties += [ordered]@{
                    key_name = $property.KeyName
                    type = [string]$property.Type
                    value_length = ([string]$property.Data).Length
                    matches_storeopen_serial = [bool]($hash -and $mappingSerialHashes -contains $hash)
                }
            }
        }
        $drives += [ordered]@{
            name = $drive.Name
            device_id = $drive.DeviceID
            status = $drive.Status
            availability = $drive.Availability
            needs_cleaning = $drive.NeedsCleaning
            media_type = $drive.MediaType
            pnp_properties = $properties
        }
    }

    $logEvidence = @()
    foreach ($root in $logRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -le 50MB } | Select-Object -First 200)) {
            $matches = @(Select-String -LiteralPath $file.FullName -Pattern @(
                'TapeAlert', 'READ POSITION', 'buffered', 'logical object', 'cartridge', 'medium'
            ) -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 20)
            if ($matches.Count -gt 0) {
                $logEvidence += [ordered]@{
                    relative_path = $file.FullName.Substring($root.Length).TrimStart('\')
                    matching_lines = $matches.Count
                    patterns = @($matches.Pattern | Sort-Object -Unique)
                }
            }
        }
    }

    [ordered]@{
        observed_at = (Get-Date).ToString('o')
        drives = $drives
        storeopen_mapping_serial_count = $mappingSerialHashes.Count
        log_evidence = $logEvidence
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
catch {
    [ordered]@{ diagnostic_error = $_.Exception.Message } | ConvertTo-Json |
        Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
