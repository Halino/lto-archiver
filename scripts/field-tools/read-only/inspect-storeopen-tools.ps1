$ErrorActionPreference = 'Continue'

$folder = 'C:\Program Files\HPE\LTFS'
$resultPath = 'C:\Temp\LtoBackupManager\storeopen-tools.json'

function Invoke-Help([string]$Name, [string[]]$Arguments) {
    $path = Join-Path $folder $Name
    if (-not (Test-Path -LiteralPath $path)) {
        return [ordered]@{ name = $Name; exists = $false; output = @() }
    }
    $output = @(& $path @Arguments 2>&1 | ForEach-Object { $_.ToString() })
    return [ordered]@{
        name = $Name
        exists = $true
        exit_code = $LASTEXITCODE
        output = @($output | Select-Object -First 200)
    }
}

try {
    $executables = @(Get-ChildItem -LiteralPath $folder -Filter '*.exe' -File |
        Sort-Object Name | ForEach-Object {
            $signature = Get-AuthenticodeSignature -LiteralPath $_.FullName
            [ordered]@{
                name = $_.Name
                company = $_.VersionInfo.CompanyName
                signature_status = $signature.Status.ToString()
                signer = if ($signature.SignerCertificate) {
                    $signature.SignerCertificate.Subject
                } else { $null }
            }
        })
    [ordered]@{
        observed_at = (Get-Date).ToString('o')
        executables = $executables
        help = @(
            (Invoke-Help 'ltfs.exe' @('-h'))
            (Invoke-Help 'unltfs.exe' @('-h'))
            (Invoke-Help 'ltfslibutil.exe' @('-h'))
            (Invoke-Help 'latte.exe' @('-h'))
            (Invoke-Help 'ltfsattr.exe' @('-h'))
        )
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
catch {
    [ordered]@{ diagnostic_error = $_.Exception.Message } | ConvertTo-Json |
        Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
