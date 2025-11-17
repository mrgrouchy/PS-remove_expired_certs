<# 
.SYNOPSIS
  Removes expired certificates from App Registrations / Service Principals based on a CSV list.

.DESCRIPTION
  - CSV must contain at least: EntityType (Application|ServicePrincipal), ObjectId, KeyId, EndDateUtc (optional for context).
  - For each row: fetch the latest object, confirm the key still exists AND is expired, then remove it.
  - Dry run supported (no changes; logs intended actions).

.REQUIREMENTS
  - Microsoft Graph PowerShell SDK (Install-Module Microsoft.Graph -Scope AllUsers)
  - Permissions: Application.ReadWrite.All and Directory.ReadWrite.All (delegated)

.EXAMPLES
  .\Remove-ExpiredGraphAppCerts.ps1 -CsvPath .\expired.csv -DryRun
  .\Remove-ExpiredGraphAppCerts.ps1 -CsvPath .\expired.csv -LogPath .\logs\remove-expired.log
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $CsvPath,

    [switch] $DryRun,

    [string] $LogPath = (Join-Path -Path $PSScriptRoot -ChildPath "Remove-ExpiredGraphCerts.log")
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
    Write-Log -Message "Parameters: CsvPath='$CsvPath'; DryRun=$DryRun; LogPath='$LogPath'" -Level "INFO"
}
catch {
    Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
}

# --- Graph connection ---------------------------------------------------------
function Connect-GraphIfNeeded {
    if (-not (Get-MgContext)) {
        $scopes = @('Application.ReadWrite.All', 'Directory.ReadWrite.All')
        Write-Log -Message "Connecting to Microsoft Graph with scopes: $($scopes -join ', ')" -Level "INFO"
        Connect-MgGraph -Scopes $scopes | Out-Null
        Select-MgProfile -Name "v1.0"
        Write-Log -Message "Connected to Microsoft Graph; profile set to v1.0" -Level "SUCCESS"
    }
    else {
        Write-Log -Message "Microsoft Graph context already present; reusing existing connection" -Level "INFO"
    }
}

# --- Helpers ------------------------------------------------------------------
function Get-ObjectWithKeys {
    param(
        [Parameter(Mandatory)][ValidateSet('Application', 'ServicePrincipal')] [string] $EntityType,
        [Parameter(Mandatory)][string] $ObjectId
    )
    $props = 'id,displayName,appId,keyCredentials'
    if ($EntityType -eq 'Application') {
        return Get-MgApplication -ApplicationId $ObjectId -Property $props -ErrorAction Stop
    }
    else {
        return Get-MgServicePrincipal -ServicePrincipalId $ObjectId -Property $props -ErrorAction Stop
    }
}

function Update-ObjectKeys {
    param(
        [Parameter(Mandatory)][ValidateSet('Application', 'ServicePrincipal')] [string] $EntityType,
        [Parameter(Mandatory)][string] $ObjectId,
        [Parameter(Mandatory)][array] $KeyCredentials
    )
    if ($EntityType -eq 'Application') {
        Update-MgApplication -ApplicationId $ObjectId -KeyCredentials $KeyCredentials -ErrorAction Stop | Out-Null
    }
    else {
        Update-MgServicePrincipal -ServicePrincipalId $ObjectId -KeyCredentials $KeyCredentials -ErrorAction Stop | Out-Null
    }
}

function TryParse-Guid {
    param([string]$Text)
    try { [guid]$Text | Out-Null; return $true } catch { return $false }
}

# ===== FIXED: culture-safe date parsing for CSV EndDateUtc (optional) =====
function TryParse-DateTimeFlexible {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    # Ensure the enum type is preserved (Windows PowerShell is strict about this)
    $styles = [System.Globalization.DateTimeStyles](
        [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
    )

    $cultures = @(
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.CultureInfo]::GetCultureInfo('en-GB'),
        [System.Globalization.CultureInfo]::GetCultureInfo('en-US')
    )
    $formats = @(
        'o', 's', 'u',                       # ISO/round-trip/sortable
        'yyyy-MM-dd HH:mm:ss', 'yyyy-MM-dd',
        'yyyy/MM/dd HH:mm:ss', 'yyyy/MM/dd',
        'dd/MM/yyyy HH:mm:ss', 'dd/MM/yyyy',
        'MM/dd/yyyy HH:mm:ss', 'MM/dd/yyyy'
    )

    foreach ($c in $cultures) {
        foreach ($f in $formats) {
            # Predeclare as [datetime] so [ref] binding matches the overload
            [datetime]$dt = [datetime]::MinValue
            if ([System.DateTime]::TryParseExact($Text, $f, $c, $styles, [ref]$dt)) { return $dt }
        }
        [datetime]$dt2 = [datetime]::MinValue
        if ([System.DateTime]::TryParse($Text, $c, $styles, [ref]$dt2)) { return $dt2 }
    }

    return $null
}
# ==========================================================================

# --- Main ---------------------------------------------------------------------
try {
    # Validate CSV path
    if (-not (Test-Path -Path $CsvPath)) {
        Write-Log -Message "CSV not found at '$CsvPath'" -Level "ERROR"
        throw "CSV not found: $CsvPath"
    }

    # Load CSV
    $rows = Import-Csv -Path $CsvPath
    $rowCount = ($rows | Measure-Object).Count
    Write-Log -Message "Loaded $rowCount row(s) from CSV" -Level "INFO"

    if ($rowCount -eq 0) {
        Write-Log -Message "CSV is empty — nothing to do" -Level "WARN"
        return
    }

    Connect-GraphIfNeeded

    $now = [DateTime]::UtcNow
    $removedCount = 0
    $skippedNotFound = 0
    $skippedNotExpired = 0
    $errors = 0

    foreach ($row in $rows) {
        $entityType = [string]$row.EntityType
        $objectId = [string]$row.ObjectId
        $keyIdText = [string]$row.KeyId

        # CSV EndDateUtc is optional context; parse safely if present
        $csvDateRaw = $null
        $csvDateParsed = $null
        if ($row.PSObject.Properties.Name -contains 'EndDateUtc') {
            $csvDateRaw = [string]$row.EndDateUtc
            $csvDateParsed = TryParse-DateTimeFlexible $csvDateRaw
            if ($csvDateRaw -and -not $csvDateParsed) {
                Write-Log -Message ("CSV EndDateUtc '{0}' could not be parsed; continuing (live expiry will be used)" -f $csvDateRaw) -Level "WARN"
            }
        }

        # Validate basic fields
        if ([string]::IsNullOrWhiteSpace($entityType) -or [string]::IsNullOrWhiteSpace($objectId) -or [string]::IsNullOrWhiteSpace($keyIdText)) {
            Write-Log -Message "Row missing required fields (EntityType/ObjectId/KeyId). Row: $($row | ConvertTo-Json -Compress)" -Level "ERROR"
            $errors++
            continue
        }

        if ($entityType -notin @('Application', 'ServicePrincipal')) {
            Write-Log -Message "Invalid EntityType '$entityType' for ObjectId '$objectId' — skipping" -Level "ERROR"
            $errors++
            continue
        }

        if (-not (TryParse-Guid $keyIdText)) {
            Write-Log -Message "KeyId '$keyIdText' is not a valid GUID for ObjectId '$objectId' — skipping" -Level "ERROR"
            $errors++
            continue
        }
        $keyId = [guid]$keyIdText

        try {
            # Get the latest object + keys
            $obj = Get-ObjectWithKeys -EntityType $entityType -ObjectId $objectId
            if (-not $obj) {
                Write-Log -Message "$entityType '$objectId' not found" -Level "ERROR"
                $errors++
                continue
            }

            # Find the key by KeyId
            $key = $obj.KeyCredentials | Where-Object { $_.KeyId -eq $keyId }
            if (-not $key) {
                Write-Log -Message ("KeyId '{0}' not present on {1} '{2}' (DisplayName='{3}')" -f $keyId, $entityType, $objectId, $obj.DisplayName) -Level "WARN"
                $skippedNotFound++
                continue
            }

            # Re-check expiry against live data (authoritative)
            $endLive = [datetime]$key.EndDateTime
            if ($endLive -ge $now) {
                Write-Log -Message ("KeyId '{0}' on {1} '{2}' is NOT expired (LiveExpiryUtc='{3:O}'; CsvEndDate='{4}') — skipping" -f `
                        $keyId, $entityType, $objectId, $endLive, ($csvDateParsed ? $csvDateParsed.ToString("o") : $csvDateRaw)) -Level "WARN"
                $skippedNotExpired++
                continue
            }

            # Build the new key list (remove target)
            $newKeys = @($obj.KeyCredentials | Where-Object { $_.KeyId -ne $keyId })

            # Dry run?
            if ($DryRun) {
                Write-Log -Message ("DRYRUN: Would remove KeyId '{0}' from {1} '{2}' (DisplayName='{3}', AppId='{4}') | LiveExpiryUtc='{5:O}' | CsvEndDate='{6}'" -f `
                        $keyId, $entityType, $objectId, $obj.DisplayName, ($obj.AppId -as [string]), $endLive, ($csvDateParsed ? $csvDateParsed.ToString("o") : $csvDateRaw)) -Level "INFO"
                continue
            }

            # Perform update
            Update-ObjectKeys -EntityType $entityType -ObjectId $objectId -KeyCredentials $newKeys

            Write-Log -Message ("Removed KeyId '{0}' from {1} '{2}' (DisplayName='{3}', AppId='{4}') | LiveExpiryUtc='{5:O}' | CsvEndDate='{6}'" -f `
                    $keyId, $entityType, $objectId, $obj.DisplayName, ($obj.AppId -as [string]), $endLive, ($csvDateParsed ? $csvDateParsed.ToString("o") : $csvDateRaw)) -Level "SUCCESS"
        }
        catch {
            $errors++
            Write-Log -Message ("Failed processing ObjectId '{0}' / KeyId '{1}': {2}" -f $objectId, $keyIdText, $_.Exception.Message) -Level "ERROR"
        }
    }

    if ($DryRun) {
        Write-Log -Message ("DRYRUN complete. To apply removals, rerun without -DryRun. Summary: Rows={0}, NotFound={1}, NotExpired={2}, Errors={3}" -f `
                $rowCount, $skippedNotFound, $skippedNotExpired, $errors) -Level "INFO"
    }
    else {
        $summaryLevel = "SUCCESS"
        if ($errors -gt 0) { $summaryLevel = "WARN" }
        Write-Log -Message ("Completed removals. Summary: Rows={0}, Removed={1}, NotFound={2}, NotExpired={3}, Errors={4}" -f `
                $rowCount, $removedCount, $skippedNotFound, $skippedNotExpired, $errors) -Level $summaryLevel
    }
}
catch {
    Write-Log -Message ("Unhandled error: {0}" -f $_.Exception.Message) -Level "ERROR"
    throw
}
finally {
    Write-Log -Message "----- Run finished: $(Get-Date -Format o) -----" -Level "INFO"
}
