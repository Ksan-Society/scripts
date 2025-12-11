
# Run in an elevated PowerShell window (Run as Administrator)

# 1) Geolocation Service (lfsvc) — set to Automatic and start it
Try {
    $svc = Get-Service -Name 'lfsvc' -ErrorAction Stop
    if ($svc.StartType -ne 'Automatic') {
        Set-Service -Name 'lfsvc' -StartupType Automatic
    }
    if ($svc.Status -ne 'Running') {
        Start-Service -Name 'lfsvc'
    }
} Catch {
    Write-Warning "Could not configure/start Geolocation Service (lfsvc): $_"
}

# 2) Clear policy that disables location (HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors)
$policyPath1 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
If (-not (Test-Path $policyPath1)) { New-Item -Path $policyPath1 -Force | Out-Null }
New-ItemProperty -Path $policyPath1 -Name 'DisableLocation' -PropertyType DWord -Value 0 -Force | Out-Null

# (Optional WOW64 policy mirror on some systems)
$policyPath2 = 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors'
If (-not (Test-Path $policyPath2)) { New-Item -Path $policyPath2 -Force | Out-Null }
New-ItemProperty -Path $policyPath2 -Name 'DisableLocation' -PropertyType DWord -Value 0 -Force | Out-Null

# 3) Set the system Location Services flag ON
# HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration\Status = 1
$sysCfgPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
If (-not (Test-Path $sysCfgPath)) { New-Item -Path $sysCfgPath -Force | Out-Null }
New-ItemProperty -Path $sysCfgPath -Name 'Status' -PropertyType DWord -Value 1 -Force | Out-Null

# 4) Allow user-level location capability
# HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\Value = "Allow"
$userConsentPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
If (-not (Test-Path $userConsentPath)) { New-Item -Path $userConsentPath -Force | Out-Null }
New-ItemProperty -Path $userConsentPath -Name 'Value' -PropertyType String -Value 'Allow' -Force | Out-Null

