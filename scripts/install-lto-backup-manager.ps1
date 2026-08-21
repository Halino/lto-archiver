param(
    [Parameter(Mandatory = $true)]
    [string]$SourceDirectory,
    [string]$InstallDirectory = 'C:\Program Files\LtoBackupManager',
    [string]$StateDirectory = 'C:\ProgramData\LtoBackupManager',
    [switch]$SkipControlledFolderAccess
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Eseguire questo script da una console PowerShell amministrativa.'
}

$running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.ProcessName -like 'LtoBackupManager*'
})
if ($running.Count -gt 0) {
    throw 'Chiudere LTO Archiver prima di eseguire l''aggiornamento.'
}

$artifacts = @(
    @{ Name = 'LtoBackupManager.exe'; Hash = 'LtoBackupManager.exe.sha256' },
    @{ Name = 'LtoBackupManagerCli.exe'; Hash = 'LtoBackupManagerCli.exe.sha256' }
)
foreach ($artifact in $artifacts) {
    $sourceExe = Join-Path $SourceDirectory $artifact.Name
    $sourceHash = Join-Path $SourceDirectory $artifact.Hash
    if (-not (Test-Path -LiteralPath $sourceExe) -or -not (Test-Path -LiteralPath $sourceHash)) {
        throw "Artefatto o file SHA-256 mancante: $($artifact.Name)"
    }
    $expected = ((Get-Content -LiteralPath $sourceHash -Raw).Trim() -split '\s+')[0].ToUpperInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceExe).Hash
    if ($actual -ne $expected) {
        throw "SHA-256 non valido per $($artifact.Name). Atteso $expected, ottenuto $actual"
    }
}

New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
& takeown.exe /F $StateDirectory /A /R | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Impossibile recuperare la proprieta di $StateDirectory"
}
& icacls.exe $StateDirectory /setowner '*S-1-5-32-544' /T /C /Q | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Impossibile assumere la proprieta delle ACL di $StateDirectory"
}
$aclDirectories = @(
    Get-Item -LiteralPath $StateDirectory
    Get-ChildItem -LiteralPath $StateDirectory -Force -Recurse -Directory
)
foreach ($aclDirectory in $aclDirectories) {
    & icacls.exe $aclDirectory.FullName /inheritance:r `
        /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Impossibile proteggere le ACL di $($aclDirectory.FullName)"
    }
}
$aclProbeFiles = @(Get-ChildItem -LiteralPath $StateDirectory -Force -Recurse -File)
foreach ($aclProbeFile in $aclProbeFiles) {
    & icacls.exe $aclProbeFile.FullName /inheritance:r `
        /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Impossibile proteggere le ACL di $($aclProbeFile.FullName)"
    }
    try {
        $probe = [System.IO.File]::Open(
            $aclProbeFile.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        )
        $probe.Dispose()
    }
    catch {
        throw "ACL non ripristinata per $($aclProbeFile.FullName): $($_.Exception.Message)"
    }
}
$catalogPath = Join-Path $StateDirectory 'catalog.db'
if (Test-Path -LiteralPath $catalogPath) {
    $backupDirectory = Join-Path $StateDirectory ('backups\pre-update-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
    foreach ($stateFile in @('catalog.db', 'catalog.db-wal', 'catalog.db-shm', 'config.json')) {
        $sourceStateFile = Join-Path $StateDirectory $stateFile
        if (Test-Path -LiteralPath $sourceStateFile) {
            Copy-Item -LiteralPath $sourceStateFile -Destination (Join-Path $backupDirectory $stateFile) -Force
        }
    }
}
foreach ($artifact in $artifacts) {
    Copy-Item -LiteralPath (Join-Path $SourceDirectory $artifact.Name) -Destination (Join-Path $InstallDirectory $artifact.Name) -Force
    Copy-Item -LiteralPath (Join-Path $SourceDirectory $artifact.Hash) -Destination (Join-Path $InstallDirectory $artifact.Hash) -Force
    $installedExpected = ((Get-Content -LiteralPath (Join-Path $InstallDirectory $artifact.Hash) -Raw).Trim() -split '\s+')[0].ToUpperInvariant()
    $installedActual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $InstallDirectory $artifact.Name)).Hash
    if ($installedActual -ne $installedExpected) {
        throw "Verifica post-installazione fallita per $($artifact.Name)"
    }
}

$installedExe = Join-Path $InstallDirectory 'LtoBackupManager.exe'
$installedCli = Join-Path $InstallDirectory 'LtoBackupManagerCli.exe'
$cfaConfigurator = Join-Path $SourceDirectory 'configure-controlled-folder-access.ps1'
if (-not (Test-Path -LiteralPath $cfaConfigurator)) {
    throw "Configuratore Controlled Folder Access mancante: $cfaConfigurator"
}
$cfaResult = & $cfaConfigurator `
    -ApplicationPaths @($installedExe, $installedCli) `
    -Skip:$SkipControlledFolderAccess
if (-not (Test-Path -LiteralPath (Join-Path $StateDirectory 'config.json'))) {
    & $installedCli --state-dir $StateDirectory init
    if ($LASTEXITCODE -ne 0) {
        throw "Inizializzazione fallita con codice $LASTEXITCODE"
    }
}

& $installedCli --state-dir $StateDirectory catalog check
if ($LASTEXITCODE -ne 0) {
    throw "Verifica catalogo fallita con codice $LASTEXITCODE"
}

$publicDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
$shell = New-Object -ComObject WScript.Shell
$legacyShortcut = Join-Path $publicDesktop 'LTO Backup Manager.lnk'
if (Test-Path -LiteralPath $legacyShortcut) {
    Remove-Item -LiteralPath $legacyShortcut -Force
}
$shortcut = $shell.CreateShortcut((Join-Path $publicDesktop 'LTO Archiver.lnk'))
$shortcut.TargetPath = $installedExe
$shortcut.Arguments = '--state-dir "' + $StateDirectory + '"'
$shortcut.WorkingDirectory = $InstallDirectory
$shortcut.Description = 'LTO Archiver - archiviazione librerie SMB su nastri LTFS'
$shortcut.IconLocation = "$installedExe,0"
$shortcut.Save()

Write-Host "Installazione completata in $InstallDirectory" -ForegroundColor Green
Write-Host "Stato e catalogo in $StateDirectory" -ForegroundColor Green
Write-Host "Interfaccia grafica disponibile sul Desktop pubblico" -ForegroundColor Green
Write-Host "Controlled Folder Access: $($cfaResult.Status)" -ForegroundColor Green
if ($backupDirectory) {
    Write-Host "Backup pre-aggiornamento in $backupDirectory" -ForegroundColor Green
}
