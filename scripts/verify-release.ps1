[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$ReleaseDirectory = (Join-Path $PSScriptRoot '..\release')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-Sha256File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedFileName
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "SHA-256 file not found: $Path"
    }
    $record = Get-Content -LiteralPath $Path -Raw
    $pattern = '\A(?<hash>[0-9A-Fa-f]{64})  ' + `
        [Regex]::Escape($ExpectedFileName) + '(?:\r\n|\n)?\z'
    if ($record -cnotmatch $pattern) {
        throw "Invalid SHA-256 file format: $Path"
    }
    return $Matches['hash'].ToUpperInvariant()
}

function Get-ReleaseRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $prefix = $Root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Extracted path escaped the temporary directory: $Path"
    }
    return $Path.Substring($prefix.Length).Replace('/', '\')
}

function Assert-SafeArchiveEntries {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$ExtractionRoot
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archiveHandle = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    $seenFiles = @{}
    $extractionPrefix = $ExtractionRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    try {
        foreach ($entry in $archiveHandle.Entries) {
            $entryPath = $entry.FullName.Replace('/', '\')
            $trimmedEntryPath = $entryPath.TrimEnd('\')
            $segments = @($trimmedEntryPath.Split('\'))
            $target = [IO.Path]::GetFullPath((Join-Path $ExtractionRoot $trimmedEntryPath))
            $isUnsafe = (
                [String]::IsNullOrWhiteSpace($trimmedEntryPath) -or
                [IO.Path]::IsPathRooted($entryPath) -or
                $entryPath.Contains(':') -or
                $segments -contains '.' -or
                $segments -contains '..' -or
                $segments -contains '' -or
                -not $target.StartsWith($extractionPrefix, [StringComparison]::OrdinalIgnoreCase)
            )
            if ($isUnsafe) {
                throw "Unsafe archive entry: $($entry.FullName)"
            }

            $unixFileType = ($entry.ExternalAttributes -shr 16) -band 0xF000
            $hasWindowsReparseAttribute = ($entry.ExternalAttributes -band 0x400) -ne 0
            if ($unixFileType -eq 0xA000 -or $hasWindowsReparseAttribute) {
                throw "Unsafe archive entry: link $($entry.FullName)"
            }

            if (-not $entryPath.EndsWith('\')) {
                if ($seenFiles.ContainsKey($entryPath)) {
                    throw "Unsafe archive entry: duplicate $($entry.FullName)"
                }
                $seenFiles[$entryPath] = $true
            }
        }
    }
    finally {
        $archiveHandle.Dispose()
    }
}

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Invalid release version: $Version"
}
if (-not (Test-Path -LiteralPath $ReleaseDirectory -PathType Container)) {
    throw "Release directory not found: $ReleaseDirectory"
}

$releaseRoot = (Resolve-Path -LiteralPath $ReleaseDirectory).Path
$archiveName = "LTO-Archiver-$Version.zip"
$archive = Join-Path $releaseRoot $archiveName
$archiveHashFile = Join-Path $releaseRoot "LTO-Archiver-$Version.zip.sha256"
if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
    throw "Release archive not found: $archive"
}

$expectedArchiveHash = Read-Sha256File -Path $archiveHashFile -ExpectedFileName $archiveName
$actualArchiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToUpperInvariant()
if ($actualArchiveHash -ne $expectedArchiveHash) {
    throw "Archive SHA-256 mismatch for $archiveName"
}

$requiredFiles = @(
    'CHANGELOG.md',
    'LICENSE',
    'LtoBackupManager.exe',
    'LtoBackupManager.exe.sha256',
    'LtoBackupManagerCli.exe',
    'LtoBackupManagerCli.exe.sha256',
    'NOTICE',
    'README.it.md',
    'README.md',
    'THIRD_PARTY_NOTICES.md',
    'configure-controlled-folder-access.ps1',
    'install-lto-backup-manager.ps1',
    'docs\en\administration.md',
    'docs\en\cli-reference.md',
    'docs\en\development.md',
    'docs\en\faq.md',
    'docs\en\index.md',
    'docs\en\installation.md',
    'docs\en\ltfs-operations.md',
    'docs\en\release-process.md',
    'docs\en\security.md',
    'docs\en\troubleshooting.md',
    'docs\en\user-guide.md',
    'docs\it\administration.md',
    'docs\it\cli-reference.md',
    'docs\it\development.md',
    'docs\it\faq.md',
    'docs\it\index.md',
    'docs\it\installation.md',
    'docs\it\ltfs-operations.md',
    'docs\it\release-process.md',
    'docs\it\security.md',
    'docs\it\troubleshooting.md',
    'docs\it\user-guide.md'
)
$expectedExecutableVersions = @{
    'LtoBackupManager.exe' = "LTO Archiver $Version"
    'LtoBackupManagerCli.exe' = "lto-backup $Version"
}
$allowedExecutables = @($expectedExecutableVersions.Keys)
$forbiddenNamePatterns = @(
    '*.db', '*.db-wal', '*.db-shm', '*.sqlite', '*.sqlite3',
    '*.log', '*.etl', '*.evtx', '.env', '.env*',
    '*.pem', '*.key', '*.pfx', '*.p12', '*.ppk',
    '*.lzt', '*.ltt', '*.cab'
)

$temporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$temporaryLeaf = 'LTO-Archiver-verify-' + [Guid]::NewGuid().ToString('N')
$temporaryDirectory = [IO.Path]::GetFullPath((Join-Path $temporaryParent $temporaryLeaf))
$temporaryDirectoryIsOwned = $false

try {
    if ($temporaryLeaf -notmatch '^LTO-Archiver-verify-[0-9a-f]{32}$') {
        throw 'Unsafe temporary directory name'
    }
    if ((Split-Path -Parent $temporaryDirectory).TrimEnd('\', '/') -ne $temporaryParent) {
        throw 'Unsafe temporary directory parent'
    }
    if (Test-Path -LiteralPath $temporaryDirectory) {
        throw "Temporary extraction directory already exists: $temporaryDirectory"
    }
    Assert-SafeArchiveEntries -ArchivePath $archive -ExtractionRoot $temporaryDirectory
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    $temporaryDirectoryIsOwned = $true

    Expand-Archive -LiteralPath $archive -DestinationPath $temporaryDirectory
    $extractedFiles = @(Get-ChildItem -LiteralPath $temporaryDirectory -File -Recurse)
    $actualFiles = @(
        $extractedFiles |
            ForEach-Object { Get-ReleaseRelativePath -Root $temporaryDirectory -Path $_.FullName } |
            Sort-Object
    )

    foreach ($file in $extractedFiles) {
        $relativePath = Get-ReleaseRelativePath -Root $temporaryDirectory -Path $file.FullName
        $leafName = $file.Name
        foreach ($pattern in $forbiddenNamePatterns) {
            if ($leafName -like $pattern) {
                throw "Forbidden release content: $relativePath"
            }
        }
        if ($file.Extension -ieq '.exe' -and $allowedExecutables -notcontains $relativePath) {
            throw "Forbidden release content: unexpected executable $relativePath"
        }
        if ($file.Extension -ine '.exe') {
            $text = [IO.File]::ReadAllText($file.FullName)
            if ($text -match '-----BEGIN [^-\r\n]*PRIVATE KEY-----') {
                throw "Forbidden release content: private key in $relativePath"
            }
        }
    }

    $differences = @(Compare-Object -ReferenceObject ($requiredFiles | Sort-Object) `
        -DifferenceObject $actualFiles -CaseSensitive)
    if ($differences.Count -ne 0) {
        $details = ($differences | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }) -join '; '
        throw "Release content mismatch: $details"
    }

    foreach ($binary in @('LtoBackupManager.exe', 'LtoBackupManagerCli.exe')) {
        $binaryPath = Join-Path $temporaryDirectory $binary
        $expectedBinaryHash = Read-Sha256File `
            -Path "$binaryPath.sha256" -ExpectedFileName $binary
        $actualBinaryHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $binaryPath).Hash.ToUpperInvariant()
        if ($actualBinaryHash -ne $expectedBinaryHash) {
            throw "Executable SHA-256 mismatch for $binary"
        }

        $versionLines = @(& $binaryPath '--version' 2>&1)
        $versionExitCode = $LASTEXITCODE
        $versionOutput = (($versionLines | Out-String).Trim())
        if ($versionExitCode -ne 0 -or $versionOutput -cne $expectedExecutableVersions[$binary]) {
            throw "Executable version mismatch for $binary: exit=$versionExitCode output='$versionOutput'"
        }
    }

    Write-Output "Verified $archiveName ($actualArchiveHash)"
}
finally {
    if ($temporaryDirectoryIsOwned) {
        $parentStillValid = (Split-Path -Parent $temporaryDirectory).TrimEnd('\', '/') -eq $temporaryParent
        $leafStillValid = (Split-Path -Leaf $temporaryDirectory) -match '^LTO-Archiver-verify-[0-9a-f]{32}$'
        if ($parentStillValid -and $leafStillValid -and (Test-Path -LiteralPath $temporaryDirectory)) {
            Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
        }
    }
}
