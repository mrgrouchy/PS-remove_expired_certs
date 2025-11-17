<# 
.SYNOPSIS
  Removes expired certificates from App Registrations / Service Principals based on a CSV list.
  Reconfirms each cert is expired right before removal. Supports -DryRun. Logs with Write-Log.

.DESCRIPTION
  - CSV must contain at least: EntityType (Application|ServicePrincipal), ObjectId, KeyId, EndDateUtc (optional for context).
  - For each row: fetch the latest object, confirm the key still exists AND is expired, then remove it.
  - Supports DryRun mode (no changes, logs only).

.REQUIREMENTS
  - Microsoft Graph PowerShell SDK (Install-Module Microsoft.Graph -Scope AllUsers)
  - Permissions: Application.ReadWrite.All and Directory.ReadWrite.All (delegated, admin consented)

.EXAMPLES
  .\Remove-ExpiredGraphAppCerts.ps1 -CsvPath .\expired.csv -DryRun
  .\Remove-ExpiredGraphAppCerts.ps1 -CsvPath .\expired.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $CsvPath,

    [switch] $DryRun,

    # Default: per-run log file with date/time in the name
    [string] $LogPath = (Join-Path -Path $PSScriptRoot -ChildPath ("Remove-ExpiredGraphCerts_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)))
)

# --- Logging (your signature) -------------------------------------------------
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

# --- Graph connection (ensure write scopes) ----------------------------------
function Connect-GraphIfNeeded {
    $requiredScopes = @(
        "Application.ReadWrite.All",
        "Directory.ReadWrite.All"
    )

    $ctx = $null
    try { $ctx = Get-MgContext } catch {}

    $missing = @()
    if ($ctx -and $ctx.Scopes) {
        foreach ($s in $requiredScopes) {
            if ($s -notin $ctx.Scopes) { $missing += $s }
        }
    }
    else {
        $missing = $requiredScopes
    }

    if (-not $ctx -or $missing.Count -gt 0) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue

        Write-Log -Message ("Connecting to Microsoft Graph with scopes: {0}" -f ($requiredScopes -join ", ")) -Level "INFO"
        Connect-MgGraph -Scopes $requiredScopes | Out-Null
        Select-MgProfile -Name "v1.0"
        Write-Log -Message "Connected to Microsoft Graph; profile set to v1.0" -Level "SUCCESS"
    }
    else {
        Write-Log -Message "Microsoft Graph context already present with required scopes; reusing existing connection" -Level "INFO"
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

# Update helper that:
# - Computes remaining keys from the *live* object
# - If none remain, PATCHes keyCredentials to []
# - Otherwise, uses Update-Mg* with the remaining keys
function Update-ObjectKeys {
    param(
        [Parameter(Mandatory)][ValidateSet('Application', 'ServicePrincipal')] [string] $EntityType,
        [Parameter(Mandatory)][string] $ObjectId,
        [Parameter(Mandatory)][guid] $RemoveKeyId,
        [Parameter(Mandatory)] $SourceObject,
        [switch] $DryRun
    )

    # Compute remaining keys from the live object
    $remaining = @($SourceObject.KeyCredentials | Where-Object { $_.KeyId -ne $RemoveKeyId })
    $remainingCount = ($remaining | Measure-Object).Count

    if ($remainingCount -eq 0) {
        if ($DryRun) {
            Write-Log -Message ("DRYRUN: Would PATCH {0} (ObjectId='{1}') keyCredentials to [] (clear all certs)" -f `
                    $SourceObject.DisplayName, $ObjectId) -Level "INFO"
            return
        }

        $uri = if ($EntityType -eq 'Application') {
            "https://graph.microsoft.com/v1.0/applications/$ObjectId"
        }
        else {
            "https://graph.microsoft.com/v1.0/servicePrincipals/$ObjectId"
        }

        $body = @{ keyCredentials = @() } | ConvertTo-Json -Depth 5
        Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
        Write-Log -Message ("Patched '{0}' (ObjectId='{1}') keyCredentials to empty array" -f `
                $SourceObject.DisplayName, $ObjectId) -Level "INFO"
        return
    }

    # Non-empty path — use the SDK to keep types intact
    if ($DryRun) {
        Write-Log -Message ("DRYRUN: Would update '{0}' (ObjectId='{1}') with {2} remaining key(s)" -f `
                $SourceObject.DisplayName, $ObjectId, $remainingCount) -Level "INFO"
        return
    }

    if ($EntityType -eq 'Application') {
        Update-MgApplication -ApplicationId $ObjectId -KeyCredentials $remaining -ErrorAction Stop | Out-Null
    }
    else {
        Update-MgServicePrincipal -ServicePrincipalId $ObjectId -KeyCredentials $remaining -ErrorAction Stop | Out-Null
    }
}

function TryParse-Guid {
    param([string]$Text)
    try {
        [guid]$Text | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

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

        # CSV EndDateUtc is optional context; log it as-is
        $csvDateForLog = $null
        if ($row.PSObject.Properties.Name -contains 'EndDateUtc') {
            $csvDateForLog = [string]$row.EndDateUtc
        }

        # Validate basic fields
        if ([string]::IsNullOrWhiteSpace($entityType) -or
            [string]::IsNullOrWhiteSpace($objectId) -or
            [string]::IsNullOrWhiteSpace($keyIdText)) {
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

        $appName = $null
        $appId = $null

        try {
            # Get the latest object + keys
            $obj = Get-ObjectWithKeys -EntityType $entityType -ObjectId $objectId
            if (-not $obj) {
                Write-Log -Message "$entityType with ObjectId '$objectId' not found" -Level "ERROR"
                $errors++
                continue
            }

            $appName = $obj.DisplayName
            $appId = $obj.AppId

            # Find the key by KeyId
            $key = $obj.KeyCredentials | Where-Object { $_.KeyId -eq $keyId }
            if (-not $key) {
                Write-Log -Message ("KeyId '{0}' not present on {1} (Name='{2}', ObjectId='{3}')" -f `
                        $keyId, $entityType, $appName, $objectId) -Level "WARN"
                $skippedNotFound++
                continue
            }

            # Re-check expiry against live data (authoritative)
            $endLive = [datetime]$key.EndDateTime
            if ($endLive -ge $now) {
                Write-Log -Message ("KeyId '{0}' on {1} (Name='{2}', ObjectId='{3}') is NOT expired (LiveExpiryUtc='{4:O}', CsvEndDate='{5}') — skipping" -f `
                        $keyId, $entityType, $appName, $objectId, $endLive, $csvDateForLog) -Level "WARN"
                $skippedNotExpired++
                continue
            }

            # Apply update (helper will compute remaining keys and handle empty case)
            Update-ObjectKeys -EntityType $entityType -ObjectId $objectId -RemoveKeyId $keyId -SourceObject $obj -DryRun:$DryRun

            if (-not $DryRun) {
                $removedCount++
                Write-Log -Message ("Removed KeyId '{0}' from {1} (Name='{2}', ObjectId='{3}', AppId='{4}') | LiveExpiryUtc='{5:O}' | CsvEndDate='{6}'" -f `
                        $keyId, $entityType, $appName, $objectId, ($appId -as [string]), $endLive, $csvDateForLog) -Level "SUCCESS"
            }
            else {
                Write-Log -Message ("DRYRUN: Would remove KeyId '{0}' from {1} (Name='{2}', ObjectId='{3}', AppId='{4}') | LiveExpiryUtc='{5:O}' | CsvEndDate='{6}'" -f `
                        $keyId, $entityType, $appName, $objectId, ($appId -as [string]), $endLive, $csvDateForLog) -Level "INFO"
            }
        }
        catch {
            $errors++
            if ($appName) {
                Write-Log -Message ("Failed processing '{0}' (ObjectId='{1}') / KeyId '{2}': {3}" -f `
                        $appName, $objectId, $keyIdText, $_.Exception.Message) -Level "ERROR"
            }
            else {
                Write-Log -Message ("Failed processing ObjectId '{0}' / KeyId '{1}': {2}" -f `
                        $objectId, $keyIdText, $_.Exception.Message) -Level "ERROR"
            }
        }
    }

    if ($DryRun) {
        Write-Log -Message ("DRYRUN complete. Summary: Rows={0}, WouldRemove={1}, NotFound={2}, NotExpired={3}, Errors={4}" -f `
                $rowCount, $removedCount, $skippedNotFound, $skippedNotExpired, $errors) -Level "INFO"
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
