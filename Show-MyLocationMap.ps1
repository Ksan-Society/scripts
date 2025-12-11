
<# 
.SYNOPSIS
  Ninja-tailored script: Get location → build Azure Maps Static Map → save image → output JSON (+ diagnostics)

.DESCRIPTION
  1) Tries System.Device.Location.GeoCoordinateWatcher using PositionChanged/StatusChanged events (up to 5 minutes).
  2) Falls back to IP-based geolocation (ipapi.co, then ipinfo.io).
  3) Optional manual lat/lon.
  4) Saves static map PNG to a cache folder on the system drive root and prints JSON with redacted URL.
  5) Emits diagnostics: OS type, lfsvc status, consent values (HKCU/HKLM), Wi‑Fi presence/state, run context.
  6) On success, writes a sidecar metadata JSON file next to the PNG.

.NOTES
  - PowerShell 5.1+ compatible.
  - Uses Render v2 Static Map (api-version=2024-04-01) with explicit tilesetId and proper pins grammar (default||lon lat).
  - Redacts subscription key in MapUrl for output.
#>

param(
    [string]$AzureMapsKey = "YOUR_AZURE_MAPS_KEY_HERE",
    [int]$Zoom = 15,
    [int]$Width = 800,
    [int]$Height = 500,
    [int]$TimeoutSeconds = 300,            # default to 5 minutes
    [int]$DesiredAccuracyMeters = 50,
    [double]$Latitude,
    [double]$Longitude,
    [string]$TilesetId = "microsoft.base.road",  # set to 'microsoft.base.aerial' for imagery
    [string]$Language = "en-us",
    [string]$View = "Auto"
)

# Ensure TLS 1.2 for REST calls (PS 5.1 / .NET)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#--------------- Helpers ---------------#
function Redact-SubscriptionKeyInUrl {
    param([Parameter(Mandatory=$true)][string]$Url)
    return ($Url -replace 'subscription-key=[^&]+','subscription-key=REDACTED')
}

function Ensure-RootCacheFolder {
    # Create %SystemDrive%\AzureMapsCache and grant write to SYSTEM + Users
    $rootDrive = $env:SystemDrive
    if ([string]::IsNullOrWhiteSpace($rootDrive)) { $rootDrive = "C:" }
    $cacheDir = Join-Path $rootDrive "AzureMapsCache"

    if (-not (Test-Path $cacheDir)) {
        New-Item -Path $cacheDir -ItemType Directory -Force | Out-Null
        try {
            # Grant modify to SYSTEM and Users (best effort)
            icacls $cacheDir /grant "SYSTEM:(OI)(CI)M" /T | Out-Null
            icacls $cacheDir /grant "Users:(OI)(CI)M"  /T | Out-Null
        } catch {
            # If ACL ops fail due to policy, proceed; TEMP fallback handles write failures later.
        }
    }
    return $cacheDir
}

function Get-CachePath {
    $dir = Ensure-RootCacheFolder
    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $filename = "AzureMap_$stamp.png"
    $path = Join-Path $dir $filename
    return $path
}

function Get-AzureMapsStaticUrl {
    param(
        [Parameter(Mandatory=$true)][double]$Latitude,
        [Parameter(Mandatory=$true)][double]$Longitude,
        [Parameter(Mandatory=$true)][string]$SubscriptionKey,
        [int]$Zoom = 15,
        [int]$Width = 800,
        [int]$Height = 500,
        [string]$TilesetId = "microsoft.base.road",
        [string]$Language = "en-us",
        [string]$View = "Auto"
    )
    # Render v2 Static Map: https://atlas.microsoft.com/map/static?api-version=2024-04-01
    # Use explicit tilesetId and pins grammar "default||lon lat"
    $apiVersion = "2024-04-01"

    $pinsValue      = "default||$Longitude $Latitude"  # double pipes when no style/label segments
    $pinsEncoded    = [System.Uri]::EscapeDataString($pinsValue)

    $centerValue    = "$Longitude,$Latitude"
    $centerEncoded  = [System.Uri]::EscapeDataString($centerValue)

    $keyEncoded     = [System.Uri]::EscapeDataString($SubscriptionKey)
    $tilesetEncoded = [System.Uri]::EscapeDataString($TilesetId)
    $langEncoded    = [System.Uri]::EscapeDataString($Language)
    $viewEncoded    = [System.Uri]::EscapeDataString($View)

    $url = "https://atlas.microsoft.com/map/static" +
           "?api-version=$apiVersion" +
           "&subscription-key=$keyEncoded" +
           "&tilesetId=$tilesetEncoded" +
           "&center=$centerEncoded" +
           "&zoom=$Zoom" +
           "&width=$Width" +
           "&height=$Height" +
           "&language=$langEncoded" +
           "&view=$viewEncoded" +
           "&format=png" +
           "&pins=$pinsEncoded"

    return $url
}

function Get-OSDiagnostics {
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $isServer = ($os.ProductType -ne 1)  # 1=Workstation, 2=DomainController, 3=Server
        return @{
            OSCaption   = $os.Caption
            OSVersion   = $os.Version
            IsServer    = $isServer
            ProductType = $os.ProductType
        }
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}

function Get-LfsvcDiagnostics {
    try {
        $svc = Get-Service -Name lfsvc -ErrorAction Stop
        return @{
            Present   = $true
            Status    = $svc.Status.ToString()
            StartType = $svc.StartType.ToString()
        }
    } catch {
        return @{
            Present = $false
            Error   = $_.Exception.Message
        }
    }
}

function Get-ConsentValueHK {
    param(
        [Parameter(Mandatory=$true)][ValidateSet('HKCU','HKLM')][string]$Hive
    )
    $path = "$Hive`:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    $result = @{
        Hive        = $Hive
        Path        = $path
        Value       = $null
        NonPackaged = $null
        Error       = $null
    }
    try {
        if (Test-Path $path) {
            $prop = Get-ItemProperty -Path $path -ErrorAction Stop
            if ($prop.PSObject.Properties.Name -contains 'Value') { $result.Value = [string]$prop.Value }
            $np = Join-Path $path "NonPackaged"
            $result.NonPackaged = (Test-Path $np)
        } else {
            $result.Error = "Consent path not found."
        }
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Get-WlanDiagnostics {
    $diag = @{ InterfacesPresent = $null; State = $null; Raw = $null; Error = $null }
    try {
        $out = & netsh wlan show interfaces 2>&1
        $diag.Raw = ($out -join "`n")
        if ($out -match 'There is no wireless interface on the system') {
            $diag.InterfacesPresent = $false
        } else {
            $diag.InterfacesPresent = $true
            $stateLine = $out | Where-Object { $_ -match '^\s*State\s*:' }
            if ($stateLine) { $diag.State = ($stateLine -split ':')[1].Trim() }
        }
    } catch {
        $diag.Error = $_.Exception.Message
    }
    return $diag
}

# --- Event-driven watcher (with final status fix) ---
function Get-CurrentLocationWithGeoWatcherEvents {
    <#
    .SYNOPSIS
      Obtain lat/lon via GeoCoordinateWatcher using PositionChanged/StatusChanged events,
      waiting up to a maximum timeout (default 300s).

    .OUTPUTS
      [pscustomobject] with Latitude, Longitude, AccuracyMeters, Status, Source, Timestamp
    #>
    param(
        [int]$TimeoutSeconds = 300,        # max 5 minutes
        [int]$DesiredAccuracyMeters = 50    # used if HorizontalAccuracy <= 0
    )

    try {
        Add-Type -AssemblyName System.Device -ErrorAction Stop | Out-Null
    } catch {
        throw "Failed to load System.Device. Ensure .NET Framework is available."
    }

    # Initialize watcher
    $watcher = New-Object System.Device.Location.GeoCoordinateWatcher
    $watcher.MovementThreshold = 1.0

    # Signal for first valid position
    $posEvent = New-Object System.Threading.AutoResetEvent($false)

    # Captured state
    $script:lastStatus   = "Unknown"
    $script:lastPosition = $null
    $script:posReady     = $false
    $script:statusReady  = $false

    # Status changes
    $statusHandler = Register-ObjectEvent -InputObject $watcher -EventName StatusChanged -Action {
        $script:lastStatus = $EventArgs.Status.ToString()
        if ($EventArgs.Status -eq [System.Device.Location.GeoPositionStatus]::Ready) {
            $script:statusReady = $true
        }
    }

    # Position changes
    $positionHandler = Register-ObjectEvent -InputObject $watcher -EventName PositionChanged -Action {
        $coord = $EventArgs.Position.Location
        if ($coord -and -not $coord.IsUnknown) {
            $script:lastPosition = $EventArgs.Position
            $script:posReady = $true
            [void]$posEvent.Set()
        }
    }

    try {
        # Start() returns void; readiness via events/Position
        $watcher.Start()

        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
            if ($script:posReady) { break }

            # Safety-net poll
            $coord = $watcher.Position.Location
            if ($coord -and -not $coord.IsUnknown) {
                $script:lastPosition = $watcher.Position
                $script:posReady = $true
                break
            }

            # Wait up to 2s for an event each loop
            $remainingMs = [int][Math]::Max(0, (1000 * $TimeoutSeconds - [int]$sw.Elapsed.TotalMilliseconds))
            $waitMs = [Math]::Min(2000, $remainingMs)
            if ($waitMs -le 0) { break }
            [void]$posEvent.WaitOne($waitMs)
        }

        if (-not $script:posReady -or -not $script:lastPosition) {
            $statusMsg = if ($script:lastStatus) { $script:lastStatus } else { "Unknown" }
            throw "Timed out after $TimeoutSeconds s without a valid position (Status=$statusMsg)."
        }

        # Build result
        $coord = $script:lastPosition.Location
        $lat = [double]$coord.Latitude
        $lon = [double]$coord.Longitude
        $acc = [double]$coord.HorizontalAccuracy
        if ($acc -le 0) { $acc = [double]$DesiredAccuracyMeters }

        # Final status fix: fall back to current watcher status when events haven't updated yet
        $finalStatus = $script:lastStatus
        try {
            $curStatus = $watcher.Status.ToString()
            if (-not $finalStatus -or $finalStatus -eq "Unknown") {
                $finalStatus = $curStatus
            }
        } catch { }

        return [pscustomobject]@{
            Latitude       = $lat
            Longitude      = $lon
            AccuracyMeters = $acc
            Status         = $finalStatus
            Source         = "GeoCoordinateWatcher"
            Timestamp      = (Get-Date).ToUniversalTime()
        }

    } finally {
        # Cleanup
        try { $watcher.Stop() } catch { }
        if ($statusHandler)   { Unregister-Event -SourceIdentifier $statusHandler.Name -ErrorAction SilentlyContinue }
        if ($positionHandler) { Unregister-Event -SourceIdentifier $positionHandler.Name -ErrorAction SilentlyContinue }
        Get-Event | Remove-Event -ErrorAction SilentlyContinue
        try { $posEvent.Dispose() } catch { }
    }
}

# Backward compatibility wrapper: route old name to the events function
function Get-CurrentLocationWithGeoWatcher {
    param(
        [int]$TimeoutSeconds = 300,
        [int]$DesiredAccuracyMeters = 50
    )
    return Get-CurrentLocationWithGeoWatcherEvents -TimeoutSeconds $TimeoutSeconds -DesiredAccuracyMeters $DesiredAccuracyMeters
}

function Get-IpGeolocation {
    <#
    .SYNOPSIS
      IP-based geolocation (less accurate; no device permissions needed).
    .OUTPUTS
      [pscustomobject] with Latitude, Longitude, Source, Provider, Timestamp
    #>

    $providers = @(
        @{ Url = "https://ipapi.co/json/";    LatProp = "latitude";  LonProp = "longitude";  Name = "ipapi.co"   },
        @{ Url = "https://ipinfo.io/json";    LatProp = "loc";       LonProp = "loc";        Name = "ipinfo.io"  } # "loc" is "lat,lon"
    )

    foreach ($p in $providers) {
        try {
            $resp = Invoke-RestMethod -Uri $p.Url -Method GET -TimeoutSec 10
            $lat = $null; $lon = $null

            if ($p.Name -eq "ipapi.co") {
                $lat = [double]$resp.$($p.LatProp)
                $lon = [double]$resp.$($p.LonProp)
            } elseif ($p.Name -eq "ipinfo.io") {
                if ($resp.loc -and ($resp.loc -is [string])) {
                    $parts = $resp.loc.Split(",")
                    if ($parts.Count -eq 2) { $lat = [double]$parts[0]; $lon = [double]$parts[1] }
                }
            }

            if ($lat -ne $null -and $lon -ne $null) {
                return [pscustomobject]@{
                    Latitude       = $lat
                    Longitude      = $lon
                    AccuracyMeters = $null      # city-level
                    Status         = "OK"
                    Source         = "IPGeolocation"
                    Provider       = $p.Name
                    Timestamp      = (Get-Date).ToUniversalTime()
                }
            }
        } catch { continue }
    }

    throw "IP-based geolocation failed (providers unreachable or returned invalid data)."
}

#--------------- Main ---------------#
$runAs = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$summary = @{
    Result         = "Failed"
    RunAs          = $runAs
    Source         = $null
    Provider       = $null
    Latitude       = $null
    Longitude      = $null
    AccuracyMeters = $null
    MapImagePath   = $null
    MapUrl         = $null   # redacted
    TimestampUtc   = (Get-Date).ToUniversalTime().ToString("u")
    Diagnostics    = @{}     # structured diagnostics
    Notes          = @()
}

try {
    if ([string]::IsNullOrWhiteSpace($AzureMapsKey) -or $AzureMapsKey -eq "YOUR_AZURE_MAPS_KEY_HERE") {
        $summary.Notes += "Missing AzureMapsKey. Provide a valid key or proxy via backend."
        throw "Azure Maps key not provided."
    }

    # --- Collect diagnostics upfront ---
    $osDiag    = Get-OSDiagnostics
    $lfsvcDiag = Get-LfsvcDiagnostics
    $hkcuDiag  = Get-ConsentValueHK -Hive HKCU
    $hklmDiag  = Get-ConsentValueHK -Hive HKLM
    $wlanDiag  = Get-WlanDiagnostics

    $summary.Diagnostics = @{
        RunAs          = $runAs
        OS             = $osDiag
        GeolocationSvc = $lfsvcDiag
        ConsentHKCU    = $hkcuDiag
        ConsentHKLM    = $hklmDiag
        WLAN           = $wlanDiag
    }

    if ($osDiag.IsServer -eq $true) {
        $summary.Notes += "Windows Server detected: device location stack may be unavailable or restricted."
    }
    if ($lfsvcDiag.Present -eq $false) {
        $summary.Notes += "Geolocation service (lfsvc) not found; device location cannot start."
    } elseif ($lfsvcDiag.Status -ne 'Running') {
        $summary.Notes += "Geolocation service (lfsvc) is not Running (Status=$($lfsvcDiag.Status), StartType=$($lfsvcDiag.StartType))."
    }
    if ($hkcuDiag.Value) {
        $summary.Notes += "HKCU location consent value: $($hkcuDiag.Value)"
    } else {
        $summary.Notes += "HKCU location consent value not present (may require interactive user consent)."
    }
    if ($wlanDiag.InterfacesPresent -eq $false) {
        $summary.Notes += "No Wi‑Fi interface present; device location accuracy may be limited."
    } elseif ($wlanDiag.State) {
        $summary.Notes += "Wi‑Fi state: $($wlanDiag.State)"
    }

    $loc = $null

    # 1) Try device location (GeoCoordinateWatcher via events, up to 5 minutes)
    try {
        $loc = Get-CurrentLocationWithGeoWatcherEvents -TimeoutSeconds $TimeoutSeconds -DesiredAccuracyMeters $DesiredAccuracyMeters
        $summary.Source    = $loc.Source
        $summary.Provider  = "WindowsLocation"
        $summary.Latitude  = $loc.Latitude
        $summary.Longitude = $loc.Longitude
        $summary.AccuracyMeters = $loc.AccuracyMeters
        $summary.Notes += "Device location acquired via GeoCoordinateWatcher (Status=$($loc.Status))."
        Write-Host "Device location: $([math]::Round($loc.Latitude,6)), $([math]::Round($loc.Longitude,6)) (±$([math]::Round($loc.AccuracyMeters,1)) m). Status: $($loc.Status)" -ForegroundColor Green
    } catch {
        $summary.Notes += "GeoCoordinateWatcher (events) failed: $($_.Exception.Message)"
    }

    # 2) Fallback to IP geolocation
    if (-not $loc) {
        try {
            $loc = Get-IpGeolocation
            $summary.Source    = $loc.Source
            $summary.Provider  = $loc.Provider
            $summary.Latitude  = $loc.Latitude
            $summary.Longitude = $loc.Longitude
            $summary.AccuracyMeters = $loc.AccuracyMeters
            $summary.Notes += "IP geolocation used (provider=$($loc.Provider)). Accuracy is approximate (city-level)."
            Write-Host "IP location (provider: $($loc.Provider)): $([math]::Round($loc.Latitude,6)), $([math]::Round($loc.Longitude,6)) (accuracy: city-level). Status: $($loc.Status)" -ForegroundColor Cyan
        } catch {
            $summary.Notes += "IP geolocation failed: $($_.Exception.Message)"
        }
    }

    # 3) Manual lat/lon fallback if supplied
    if (-not $loc -and $PSBoundParameters.ContainsKey("Latitude") -and $PSBoundParameters.ContainsKey("Longitude")) {
        $loc = [pscustomobject]@{
            Latitude       = [double]$Latitude
            Longitude      = [double]$Longitude
            AccuracyMeters = $null
            Status         = "Manual"
            Source         = "Manual"
            Timestamp      = (Get-Date).ToUniversalTime()
        }
        $summary.Source    = $loc.Source
        $summary.Provider  = "Manual"
        $summary.Latitude  = $loc.Latitude
        $summary.Longitude = $loc.Longitude
        $summary.AccuracyMeters = $loc.AccuracyMeters
        $summary.Notes += "Manual coordinates used."
        Write-Host "Using manual coordinates: $([math]::Round($loc.Latitude,6)), $([math]::Round($loc.Longitude,6))" -ForegroundColor Magenta
    }

    if (-not $loc) {
        $summary.Notes += "No location available: Device + IP + Manual all unavailable."
        throw "Location acquisition failed."
    }

    # Validate coordinates
    if ($loc.Latitude -lt -90 -or $loc.Latitude -gt 90 -or $loc.Longitude -lt -180 -or $loc.Longitude -gt 180) {
        $summary.Notes += "Invalid coordinates detected: lat=$($loc.Latitude) lon=$($loc.Longitude)"
        throw "Invalid coordinates."
    }

    # Build static map URL (Render v2 with tilesetId + default pin)
    $mapUrlFull = Get-AzureMapsStaticUrl -Latitude $loc.Latitude -Longitude $loc.Longitude `
        -SubscriptionKey $AzureMapsKey -Zoom $Zoom -Width $Width -Height $Height `
        -TilesetId $TilesetId -Language $Language -View $View

    $summary.MapUrl = Redact-SubscriptionKeyInUrl -Url $mapUrlFull

    # Download image to root cache; fallback to TEMP if root fails
    $outPath = Get-CachePath
    try {
        Invoke-WebRequest -Uri $mapUrlFull -OutFile $outPath -TimeoutSec 30 -ErrorAction Stop
        $summary.MapImagePath = $outPath
        $summary.Result = "Success"
        $summary.Notes += "Static map image saved to root cache."

        # Save sidecar metadata JSON next to PNG
        try {
            $metaPath = [System.IO.Path]::ChangeExtension($outPath, ".json")
            ($summary | ConvertTo-Json -Depth 6) | Out-File -FilePath $metaPath -Encoding UTF8 -ErrorAction Stop
            $summary.Notes += "Metadata JSON saved: $metaPath"
        } catch {
            $summary.Notes += "Failed to save metadata JSON: $($_.Exception.Message)"
        }
    } catch {
        $summary.Notes += "Root cache write or download failed: $($_.Exception.Message)"
        try {
            $stamp2 = (Get-Date).ToString("yyyyMMdd_HHmmss")
            $tempFilename = "AzureMap_$stamp2.png"
            $tempPath = Join-Path $env:TEMP $tempFilename
            Invoke-WebRequest -Uri $mapUrlFull -OutFile $tempPath -TimeoutSec 30 -ErrorAction Stop
            $summary.MapImagePath = $tempPath
            $summary.Result = "Success"
            $summary.Notes += "Static map image saved to TEMP fallback."

            # Save metadata JSON next to TEMP image
            try {
                $metaPath2 = [System.IO.Path]::ChangeExtension($tempPath, ".json")
                ($summary | ConvertTo-Json -Depth 6) | Out-File -FilePath $metaPath2 -Encoding UTF8 -ErrorAction Stop
                $summary.Notes += "Metadata JSON saved: $metaPath2"
            } catch {
                $summary.Notes += "Failed to save metadata JSON (TEMP): $($_.Exception.Message)"
            }
        } catch {
            $summary.Notes += "Failed to download static map: $($_.Exception.Message)"
            throw "Map image download failed."
        }
    }

} catch {
    $summary.Result = "Failed"
    $summary.Notes += "Script error: $($_.Exception.Message)"
} finally {
    # Emit compact JSON for Ninja output capture
    $json = $summary | ConvertTo-Json -Depth 6 -Compress
    Write-Output $json

    if ($summary.Result -eq "Success") { exit 0 } else { exit 1 }
}