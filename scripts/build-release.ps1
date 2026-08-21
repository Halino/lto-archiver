param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [string]$Python = '.build-venv\Scripts\python.exe',
    [switch]$SkipTests,
    [string]$SignTool,
    [string]$CertificateSha1
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$pythonPath = if ([IO.Path]::IsPathRooted($Python)) { $Python } else { Join-Path $projectRoot $Python }
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw "Runtime Python non trovato: $pythonPath"
}

$declaredVersion = & $pythonPath -c "import sys; sys.path.insert(0, 'src'); import ltobackup; print(ltobackup.__version__)"
if ($LASTEXITCODE -ne 0 -or $declaredVersion.Trim() -ne $Version) {
    throw "Versione richiesta $Version diversa dal sorgente $declaredVersion"
}

if (-not $SkipTests) {
    $env:PYTHONPATH = 'src'
    & $pythonPath -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Test automatici falliti' }
}

$tag = $Version.Replace('.', '')
$buildDirectory = Join-Path $projectRoot "build-$tag"
$distDirectory = Join-Path $projectRoot "dist-$tag"
$stagingDirectory = Join-Path $projectRoot "staging\$Version"
$documentationDirectory = Join-Path $stagingDirectory 'docs'
$releaseDirectory = Join-Path $projectRoot 'release'
$archive = Join-Path $releaseDirectory "LTO-Archiver-$Version.zip"
foreach ($target in @($buildDirectory, $distDirectory, $stagingDirectory)) {
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
New-Item -ItemType Directory -Path `
    $stagingDirectory, $documentationDirectory, $releaseDirectory -Force | Out-Null

& $pythonPath -m PyInstaller --noconfirm --clean `
    --workpath $buildDirectory --distpath $distDirectory `
    (Join-Path $projectRoot 'LtoBackupManager.spec')
if ($LASTEXITCODE -ne 0) { throw 'Build PyInstaller fallita' }

$binaries = @('LtoBackupManager.exe', 'LtoBackupManagerCli.exe')
if ($SignTool -or $CertificateSha1) {
    if (-not $SignTool -or -not $CertificateSha1) {
        throw 'Per firmare servono sia -SignTool sia -CertificateSha1'
    }
    foreach ($binary in $binaries) {
        & $SignTool sign /sha1 $CertificateSha1 /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
            (Join-Path $distDirectory $binary)
        if ($LASTEXITCODE -ne 0) { throw "Firma fallita per $binary" }
    }
}

foreach ($binary in $binaries) {
    $source = Join-Path $distDirectory $binary
    $destination = Join-Path $stagingDirectory $binary
    Copy-Item -LiteralPath $source -Destination $destination -Force
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash
    "$hash  $binary" | Set-Content -LiteralPath "$destination.sha256" -Encoding ascii
}
$publicScripts = @(
    'scripts\install-lto-backup-manager.ps1',
    'scripts\configure-controlled-folder-access.ps1'
)
foreach ($relativePath in $publicScripts) {
    $source = Join-Path $projectRoot $relativePath
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "File pubblico obbligatorio non trovato: $relativePath"
    }
    Copy-Item -LiteralPath $source -Destination $stagingDirectory -Force
}

$publicRootFiles = @(
    'LICENSE',
    'NOTICE',
    'THIRD_PARTY_NOTICES.md',
    'README.md',
    'README.it.md',
    'CHANGELOG.md'
)
foreach ($relativePath in $publicRootFiles) {
    $source = Join-Path $projectRoot $relativePath
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "File pubblico obbligatorio non trovato: $relativePath"
    }
    Copy-Item -LiteralPath $source -Destination $stagingDirectory -Force
}

$publicDocumentationDirectories = @('docs\en', 'docs\it')
foreach ($relativePath in $publicDocumentationDirectories) {
    $source = Join-Path $projectRoot $relativePath
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw "Manuale pubblico obbligatorio non trovato: $relativePath"
    }
    Copy-Item -LiteralPath $source -Destination $documentationDirectory -Recurse -Force
}

if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
Compress-Archive -Path (Join-Path $stagingDirectory '*') -DestinationPath $archive -CompressionLevel Optimal
$archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash
"$archiveHash  $(Split-Path -Leaf $archive)" | Set-Content -LiteralPath "$archive.sha256" -Encoding ascii
Write-Output $archive
