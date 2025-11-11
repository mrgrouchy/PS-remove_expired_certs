<# 
.SYNOPSIS
  Lists expired certificates on App Registrations (and optionally Service Principals) and logs progress.

.REQUIREMENTS
  - Microsoft Graph PowerShell SDK (Install-Module Microsoft.Graph -Scope AllUsers)
  - Directory read permission (Application.Read.All). You’ll be prompted to consent.

.EXAMPLES
  .\Get-ExpiredGraphAppCerts.ps1
  .\Get-ExpiredGraphAppCerts.ps1 -IncludeServicePrincipals
  .\Get-ExpiredGraphAppCerts.ps1 -ExportCsv .\expired-certs.csv -LogPath .\logs\expired.log
#>

[CmdletBinding()]
param(
    [switch] $IncludeServicePrincipals,
    [string] $ExportCsv,
    [string] $LogPath = (Join-Path -Path $PSScriptRoot -ChildPath "Get-ExpiredGraphAppCerts.log")
)

# region Logging ---------------------------------------------------------------

# Use user's Write-Log signature (relies on $logpath variable)
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp][$Level] $Message"
    Add-Content -Path $logpath -Value $entry
}

# Prepare log path variable & folder
$script:logpath = $LogPath
try {
    $logDir = Split-Path -Path $script:logpath -Parent
    if ($logDir -and -not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    # Start banner
    Write-Log -Message "----- Run started: $(Get-Date -Format o) -----"
    Write-Log -Message "Parameters: IncludeServicePrincipals=$IncludeServicePrincipals; ExportCsv='$ExportCsv'; LogPath='$LogPath'"
}
catch {
    Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
}

# endregion Logging ------------------------------------------------------------

function Connect-GraphIfNeeded {
    if (-not (Get-MgContext)) {
        $scopes = @('Application.Read.All')
        Write-Log -Message "Connecting to Microsoft Graph with scopes: $($scopes -join ', ')"
        Connect-MgGraph -Scopes $scopes | Out-Null
        Select-MgProfile -Name "v1.0"
        Write-Log -Message "Connected to Microsoft Graph; profile set to v1.0"
    }
    else {
        Write-Log -Message "Microsoft Graph context already present; reusing existing connection"
    }
}

function Convert-Thumbprint {
    param([byte[]] $Bytes)
    if (-not $Bytes) { return $null }
    ($Bytes | ForEach-Object { $_.ToString('X2') }) -join ''
}

function Get-ExpiredFrom-KeyCredentials {
    param(
        [Parameter(Mandatory)]
        [array] $Items,
        [Parameter(Mandatory)]
        [ValidateSet('Application', 'ServicePrincipal')]
        [string] $EntityType
    )
    $now = [DateTime]::UtcNow
    $expiredLocal = @()

    foreach ($item in $Items) {
        if (-not $item.KeyCredentials) { continue }

        foreach ($kc in $item.KeyCredentials) {
            if ($kc.Type -ne 'AsymmetricX509Cert') { continue }

            $end = [DateTime]$kc.EndDateTime
            if ($end -lt $now) {
                $thumb = Convert-Thumbprint -Bytes $kc.CustomKeyIdentifier
                $obj = [pscustomobject]@{
                    EntityType     = $EntityType
                    DisplayName    = $item.DisplayName
                    ObjectId       = $item.Id
                    AppId          = if ($EntityType -eq 'Application') { $item.AppId } else { $null }
                    KeyDisplayName = $kc.DisplayName
                    KeyId          = $kc.KeyId
                    Thumbprint     = $thumb
                    StartDateUtc   = [DateTime]$kc.StartDateTime
                    EndDateUtc     = $end
                }
                $expiredLocal += $obj

                # Log each expired certificate as WARN
                Write-Log -Message ("Expired {0} cert found: DisplayName='{1}', AppId='{2}', Thumbprint='{3}', EndDateUtc='{4:O}', KeyId='{5}'" -f `
                        $EntityType, $item.DisplayName, ($obj.AppId ?? ''), $thumb, $end, $kc.KeyId) -Level "WARN"
            }
        }
    }

    return $expiredLocal
}

function Get-AllApplications {
    $props = 'id,displayName,appId,keyCredentials'
    Write-Log -Message "Fetching Applications with properties: $props"
    $result = Get-MgApplication -All -Property $props
    $count = ($result | Measure-Object).Count
    Write-Log -Message "Fetched $count application(s)"
    return $result
}

function Get-AllServicePrincipals {
    $props = 'id,displayName,appId,keyCredentials'
    Write-Log -Message "Fetching Service Principals with properties: $props"
    $result = Get-MgServicePrincipal -All -Property $props
    $count = ($result | Measure-Object).Count
    Write-Log -Message "Fetched $count service principal(s)"
    return $result
}

# --- main ---
try {
    Write-Log -Message "Starting expired certificate scan"
    Connect-GraphIfNeeded

    $apps = Get-AllApplications
    Write-Log -Message "Scanning Applications for expired certificates"
    $expired = Get-ExpiredFrom-KeyCredentials -Items $apps -EntityType 'Application'

    if ($IncludeServicePrincipals) {
        $sps = Get-AllServicePrincipals
        Write-Log -Message "Scanning Service Principals for expired certificates"
        $expired += Get-ExpiredFrom-KeyCredentials -Items $sps -EntityType 'ServicePrincipal'
    }

    # Sort newest-expired first for convenience
    $expired = $expired | Sort-Object EndDateUtc -Descending

    $expiredCount = ($expired | Measure-Object).Count
    Write-Log -Message "Total expired certificates found: $expiredCount" -Level ($expiredCount -gt 0 ? "WARN" : "INFO")

    if ($ExportCsv) {
        try {
            $csvDir = Split-Path -Path $ExportCsv -Parent
            if ($csvDir -and -not (Test-Path -Path $csvDir)) {
                New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
            }
            $expired | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
            Write-Log -Message "Exported expired certificate list to '$ExportCsv'"
            Write-Host "Exported expired certificate list to: $ExportCsv"
        }
        catch {
            Write-Log -Message "Failed to export CSV: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }

    if (-not $expired) {
        Write-Host "No expired certificates were found." -ForegroundColor Green
        Write-Log -Message "No expired certificates found"
    }
    else {
        $expired | Format-Table EntityType, DisplayName, AppId, Thumbprint, KeyDisplayName, EndDateUtc, StartDateUtc, KeyId -AutoSize
        Write-Log -Message "Printed expired certificates to console"
    }
}
catch {
    Write-Log -Message ("Unhandled error: {0}" -f $_.Exception.Message) -Level "ERROR"
    Write-Error $_
}
finally {
    Write-Log -Message "----- Run finished: $(Get-Date -Format o) -----"
}
