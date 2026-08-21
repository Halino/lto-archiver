param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ApplicationPaths,
    [switch]$Skip
)

$ErrorActionPreference = 'Stop'

if ($Skip) {
    return [pscustomobject]@{
        Status = 'skipped'
        ControlledFolderAccessMode = $null
        AddedApplications = @()
    }
}

$getPreference = Get-Command -Name 'Get-MpPreference' -ErrorAction SilentlyContinue
$addPreference = Get-Command -Name 'Add-MpPreference' -ErrorAction SilentlyContinue
if (-not $getPreference -or -not $addPreference) {
    return [pscustomobject]@{
        Status = 'defender_unavailable'
        ControlledFolderAccessMode = $null
        AddedApplications = @()
    }
}

function Test-ApplicationAllowed([string]$Path, [object[]]$Allowed) {
    foreach ($candidate in @($Allowed)) {
        if ([string]::Equals(
            [string]$candidate,
            $Path,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            return $true
        }
    }
    return $false
}

$preference = Get-MpPreference
$mode = [int]$preference.EnableControlledFolderAccess
if ($mode -ne 1) {
    return [pscustomobject]@{
        Status = 'inactive'
        ControlledFolderAccessMode = $mode
        AddedApplications = @()
    }
}

$allowed = @($preference.ControlledFolderAccessAllowedApplications)
$missing = @($ApplicationPaths | Where-Object {
    -not (Test-ApplicationAllowed -Path $_ -Allowed $allowed)
})
if ($missing.Count -eq 0) {
    return [pscustomobject]@{
        Status = 'already_configured'
        ControlledFolderAccessMode = $mode
        AddedApplications = @()
    }
}

Add-MpPreference -ControlledFolderAccessAllowedApplications $missing
$verified = Get-MpPreference
$notApplied = @($missing | Where-Object {
    -not (Test-ApplicationAllowed `
        -Path $_ `
        -Allowed @($verified.ControlledFolderAccessAllowedApplications))
})
if ($notApplied.Count -gt 0) {
    throw 'Defender non ha confermato tutte le autorizzazioni Controlled Folder Access richieste.'
}

[pscustomobject]@{
    Status = 'configured'
    ControlledFolderAccessMode = [int]$verified.EnableControlledFolderAccess
    AddedApplications = @($missing)
}
