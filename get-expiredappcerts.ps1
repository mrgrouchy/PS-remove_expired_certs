<# 
.SYNOPSIS
  Lists expired certificates on App Registrations (and optionally Service Principals).

.REQUIREMENTS
  - Microsoft Graph PowerShell SDK (Install-Module Microsoft.Graph -Scope AllUsers)
  - Directory read permission (Application.Read.All). You’ll be prompted to consent.

.EXAMPLES
  .\Get-ExpiredGraphAppCerts.ps1
  .\Get-ExpiredGraphAppCerts.ps1 -IncludeServicePrincipals
  .\Get-ExpiredGraphAppCerts.ps1 -ExportCsv .\expired-certs.csv
#>

[CmdletBinding()]
param(
  [switch] $IncludeServicePrincipals,
  [string] $ExportCsv
)

function Connect-GraphIfNeeded {
  if (-not (Get-MgContext)) {
    $scopes = @('Application.Read.All')
    Connect-MgGraph -Scopes $scopes | Out-Null
    Select-MgProfile -Name "v1.0"
  }
}

function Convert-Thumbprint {
  param([byte[]] $Bytes)
  if (-not $Bytes) { return $null }
  # Convert byte[] -> hex thumbprint (no spaces, upper-case)
  ($Bytes | ForEach-Object { $_.ToString('X2') }) -join ''
}

function Get-ExpiredFrom-KeyCredentials {
  param(
    [Parameter(Mandatory)]
    [array] $Items,              # Application or ServicePrincipal objects
    [Parameter(Mandatory)]
    [ValidateSet('Application','ServicePrincipal')]
    [string] $EntityType
  )
  $now = [DateTime]::UtcNow

  foreach ($item in $Items) {
    if (-not $item.KeyCredentials) { continue }

    foreach ($kc in $item.KeyCredentials) {
      # Focus on X.509 certificates
      if ($kc.Type -ne 'AsymmetricX509Cert') { continue }

      # Consider expired if endDateTime strictly in the past (UTC)
      $end = [DateTime]$kc.EndDateTime
      if ($end -lt $now) {
        [pscustomobject]@{
          EntityType     = $EntityType
          DisplayName    = $item.DisplayName
          ObjectId       = $item.Id
          AppId          = if ($EntityType -eq 'Application') { $item.AppId } else { $null }
          KeyDisplayName = $kc.DisplayName
          KeyId          = $kc.KeyId
          Thumbprint     = Convert-Thumbprint -Bytes $kc.CustomKeyIdentifier
          StartDateUtc   = [DateTime]$kc.StartDateTime
          EndDateUtc     = $end
        }
      }
    }
  }
}

function Get-AllApplications {
  # Pull only the fields we need to reduce payload
  $props = 'id,displayName,appId,keyCredentials'
  Get-MgApplication -All -Property $props
}

function Get-AllServicePrincipals {
  $props = 'id,displayName,appId,keyCredentials'
  Get-MgServicePrincipal -All -Property $props
}

# --- main ---
try {
  Connect-GraphIfNeeded

  Write-Verbose "Fetching applications..."
  $apps = Get-AllApplications

  $expired = Get-ExpiredFrom-KeyCredentials -Items $apps -EntityType 'Application'

  if ($IncludeServicePrincipals) {
    Write-Verbose "Fetching service principals..."
    $sps = Get-AllServicePrincipals
    $expired += Get-ExpiredFrom-KeyCredentials -Items $sps -EntityType 'ServicePrincipal'
  }

  # Sort newest-expired first for convenience
  $expired = $expired | Sort-Object EndDateUtc -Descending

  if ($ExportCsv) {
    $expired | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Exported expired certificate list to: $ExportCsv"
  }

  if (-not $expired) {
    Write-Host "No expired certificates were found." -ForegroundColor Green
  } else {
    $expired | Format-Table EntityType, DisplayName, AppId, Thumbprint, KeyDisplayName, EndDateUtc, StartDateUtc, KeyId -AutoSize
  }
}
catch {
  Write-Error $_
}
