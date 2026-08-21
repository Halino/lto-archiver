$ErrorActionPreference = 'Stop'

$resultPath = 'C:\Temp\LtoBackupManager\storeopen-installation.json'
$roots = @(
    'C:\Program Files\HPE',
    'C:\Program Files\Hewlett-Packard',
    'C:\Program Files\Quantum'
)

try {
    $executables = @()
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter '*.exe' -File -Recurse -ErrorAction SilentlyContinue)) {
            $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
            $executables += [ordered]@{
                relative_path = $file.FullName.Substring($root.Length).TrimStart('\')
                vendor_root = $root
                signature_status = $signature.Status.ToString()
                signer_subject = if ($signature.SignerCertificate) {
                    $signature.SignerCertificate.Subject
                } else { $null }
            }
        }
    }

    $products = @()
    foreach ($uninstallRoot in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )) {
        $products += @(Get-ItemProperty $uninstallRoot -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match '(?i)(LTFS|StoreOpen)' } |
            ForEach-Object {
                [ordered]@{
                    display_name = $_.DisplayName
                    display_version = $_.DisplayVersion
                    install_location = $_.InstallLocation
                    publisher = $_.Publisher
                }
            })
    }

    $consoleFiles = @()
    foreach ($path in @(
        'C:\Program Files\HPE\LTFS\LTFSConsole.bat',
        'C:\Program Files\HPE\LTFS\README.windows'
    )) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $consoleFiles += [ordered]@{
            name = Split-Path -Leaf $path
            lines = @(Get-Content -LiteralPath $path -ErrorAction SilentlyContinue |
                Where-Object { $_ -match '(?i)(ltfs|mkltfs|unltfs|ltfsck|bin_)' } |
                Select-Object -First 100)
        }
    }

    [ordered]@{
        observed_at = (Get-Date).ToString('o')
        executables = @($executables | Sort-Object vendor_root, relative_path)
        products = $products
        console_references = $consoleFiles
    } | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
catch {
    [ordered]@{ diagnostic_error = $_.Exception.Message } | ConvertTo-Json |
        Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
