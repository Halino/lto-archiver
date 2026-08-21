$ErrorActionPreference = 'Stop'

$resultPath = 'C:\Temp\LtoBackupManager\cfa-policy.json'
$gui = 'C:\Program Files\LtoBackupManager\LtoBackupManager.exe'
$cli = 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe'

try {
    $preference = Get-MpPreference
    $allowed = @($preference.ControlledFolderAccessAllowedApplications)
    [ordered]@{
        observed_at = (Get-Date).ToString('o')
        controlled_folder_access_mode = [int]$preference.EnableControlledFolderAccess
        gui_explicitly_allowed = [bool]($allowed -contains $gui)
        cli_explicitly_allowed = [bool]($allowed -contains $cli)
    } | ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
catch {
    [ordered]@{ diagnostic_error = $_.Exception.Message } | ConvertTo-Json |
        Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
