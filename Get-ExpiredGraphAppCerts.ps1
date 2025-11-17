<# 
.SYNOPSIS
  Lists expired certificates on App Registrations (and optionally Service Principals) and logs progress.

.REQUIREMENTS
  - Microsoft Graph PowerShell SDK (Install-Module Microsoft.Graph -Scope AllUsers)
  - Directory read permission (Application.Read.All)

.EXAMPLES
  .\Get-ExpiredGraphAppCerts.ps1
  .\Get-ExpiredGraphAppCerts.ps1 -IncludeServicePrincipals
  .\Get-ExpiredGraphAppCerts.ps1 -ExportCsv .\expired-certs.csv
#>

[CmdletBinding()]
param(
    [switch] $IncludeServicePrincipals,

    # Default: per-run CSV file with date/time in the name
    [string] $ExportCsv = (Join-Path -Path $PSScriptRoot -ChildPath ("expired-certs_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))),

    # Default: per-run log file with date/time in the name
    [string] $LogPath = (Join-Path -Path $PSScriptRoot -ChildPath ("Get-ExpiredGraphAppCerts_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)))
)

# --- Logging (uses your signature) -------------------------------------------
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp][$Level] $Message"
    Add-Content -Path $logpath -Value $entry
}

$script:logpath = $LogPath
try {
    $logDir = Split-Path -Path $script:logpath -Parent
    if ($logDir -and -not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        Write-Log -Message "Created log directory '$logDir'" -Level "SUCCESS"
    }
    Write-Log -Message "----- Run started: $(Get-Date -Format o) -----" -Level "INFO"
    Write-Log -Message "Parameters: IncludeServicePrincipals=$IncludeServicePrincipals; ExportCsv='$ExportCsv'; LogPath='$LogPath'" -Level "INFO"
}
catch {
    Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
}

function Connect-GraphIfNeeded {
    if (-not (Get-MgContext)) {
        $scopes = @('Application.Read.All')
        Write-Log -Message "Connecting to Microsoft Graph with scopes: $($scopes -join ', ')" -Level "INFO"
        Connect-MgGraph -Scopes $scopes | Out-Null
        #Select-MgProfile -Name "v1.0"
        Write-Log -Message "Connected to Microsoft Graph; profile set to v1.0" -Level "SUCCESS"
    }
    else {
        Write-Log -Message "Microsoft Graph context already present; reusing existing connection" -Level "INFO"
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
                $appIdStr = if ($EntityType -eq 'Application') { [string]$item.AppId } else { '' }
                $expiredDays = [int][math]::Floor(($now - $end).TotalDays)

                # AppName added explicitly for CSV
                $obj = [pscustomobject]@{
                    EntityType     = $EntityType
                    DisplayName    = $item.DisplayName
                    AppName        = $item.DisplayName
                    ObjectId       = $item.Id
                    AppId          = if ($EntityType -eq 'Application') { $item.AppId } else { $null }
                    KeyDisplayName = $kc.DisplayName
                    KeyId          = $kc.KeyId
                    Thumbprint     = $thumb
                    StartDateUtc   = [DateTime]$kc.StartDateTime
                    EndDateUtc     = $end
                }
                $expiredLocal += $obj

                # Explicitly log the expiry date (UTC) and how long ago it expired
                Write-Log -Message ("Expired {0} cert | DisplayName='{1}' | AppId='{2}' | Thumbprint='{3}' | ExpiryDateUtc='{4:O}' | ExpiredDays={5} | KeyId='{6}'" -f `
                        $EntityType, $item.DisplayName, $appIdStr, $thumb, $end, $expiredDays, $kc.KeyId) -Level "WARN"
            }
        }
    }

    return $expiredLocal
}

function Get-AllApplications {
    $props = 'id,displayName,appId,keyCredentials'
    Write-Log -Message "Fetching Applications with properties: $props" -Level "INFO"
    $result = Get-MgApplication -All -Property $props
    $count = ($result | Measure-Object).Count
    Write-Log -Message "Fetched $count application(s)" -Level "SUCCESS"
    return $result
}

function Get-AllServicePrincipals {
    $props = 'id,displayName,appId,keyCredentials'
    Write-Log -Message "Fetching Service Principals with properties: $props" -Level "INFO"
    $result = Get-MgServicePrincipal -All -Property $props
    $count = ($result | Measure-Object).Count
    Write-Log -Message "Fetched $count service principal(s)" -Level "SUCCESS"
    return $result
}

# --- main --------------------------------------------------------------------
try {
    Write-Log -Message "Starting expired certificate scan" -Level "INFO"
    Connect-GraphIfNeeded

    $apps = Get-AllApplications
    Write-Log -Message "Scanning Applications for expired certificates" -Level "INFO"
    $expired = Get-ExpiredFrom-KeyCredentials -Items $apps -EntityType 'Application'

    if ($IncludeServicePrincipals) {
        $sps = Get-AllServicePrincipals
        Write-Log -Message "Scanning Service Principals for expired certificates" -Level "INFO"
        $expired += Get-ExpiredFrom-KeyCredentials -Items $sps -EntityType 'ServicePrincipal'
    }

    $expired = $expired | Sort-Object EndDateUtc -Descending
    $expiredCount = ($expired | Measure-Object).Count

    if ($expiredCount -gt 0) {
        # Summarize oldest/newest expiry for convenience
        $newestExpired = $expired | Select-Object -First 1
        $oldestExpired = $expired | Select-Object -Last 1
        Write-Log -Message "Total expired certificates found: $expiredCount" -Level "WARN"
        Write-Log -Message ("Newest expired cert date (UTC): {0:O} | Oldest expired cert date (UTC): {1:O}" -f $newestExpired.EndDateUtc, $oldestExpired.EndDateUtc) -Level "INFO"
    }
    else {
        Write-Log -Message "No expired certificates found" -Level "SUCCESS"
    }

    # Always export CSV (with default timestamped path, or user override)
    try {
        $csvDir = Split-Path -Path $ExportCsv -Parent
        if ($csvDir -and -not (Test-Path -Path $csvDir)) {
            New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
            Write-Log -Message "Created CSV output directory '$csvDir'" -Level "SUCCESS"
        }
        $expired | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported expired certificate list to '$ExportCsv'" -Level "SUCCESS"
        Write-Host "Exported expired certificate list to: $ExportCsv"
    }
    catch {
        Write-Log -Message "Failed to export CSV: $($_.Exception.Message)" -Level "ERROR"
        throw
    }

    if (-not $expired) {
        Write-Host "No expired certificates were found." -ForegroundColor Green
    }
    else {
        $expired | Format-Table EntityType, DisplayName, AppName, AppId, Thumbprint, KeyDisplayName, EndDateUtc, StartDateUtc, KeyId -AutoSize
        Write-Log -Message "Printed expired certificates to console" -Level "INFO"
    }
}
catch {
    Write-Log -Message ("Unhandled error: {0}" -f $_.Exception.Message) -Level "ERROR"
    Write-Error $_
}
finally {
    Write-Log -Message "----- Run finished: $(Get-Date -Format o) -----" -Level "INFO"
}
