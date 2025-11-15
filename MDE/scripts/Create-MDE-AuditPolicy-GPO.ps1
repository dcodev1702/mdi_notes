#Requires -Modules GroupPolicy

<#
.SYNOPSIS
    Creates a GPO with comprehensive audit policy settings optimized for Microsoft Defender for Endpoint (MDE).

.DESCRIPTION
    This script creates a new Group Policy Object with audit policy settings that enable
    comprehensive logging for MDE to maximize EDR visibility and detection capabilities.
    The settings are based on MDE requirements and security best practices.

.PARAMETER GPOName [required]
    Name of the GPO to create. Default: "MDE Audit Policy - Workstations"
    Name of the GPO to create. Default: "MDE Audit Policy - Domain Controllers"

.PARAMETER TargetOU [required]
    Distinguished Name of the OU to link the GPO to. If not specified, GPO is created but not linked.

.PARAMETER LinkEnabled
    Whether to enable the GPO link immediately. Default: $true

.EXAMPLE
    .\Create-MDE-AuditPolicy-GPO.ps1 -GPOName "MDE Audit Policy - Domain Controllers" -TargetOU "OU=Domain Controllers,DC=contoso,DC=local"

.EXAMPLE
    .\Create-MDE-AuditPolicy-GPO.ps1 -GPOName "MDE Audit Policy - Workstations" -TargetOU "OU=Workstations,DC=contoso,DC=local"

.NOTES
    Author: DCODEV1702 & Claude Sonnet 4.5
    Date: 12 NOV 2025
    Description: Generated for MDE Audit Policy Configuration
    Requires: Active Directory PowerShell Module, Group Policy Management
    Run as: Domain Administrator or user with GPO creation rights
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$GPOName,
    
    [Parameter(Mandatory=$true)]
    [string]$TargetOU,
    
    [Parameter(Mandatory=$false)]
    [bool]$LinkEnabled = $true
)

# Check for required modules
if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    Write-Error "GroupPolicy module not found. Install RSAT Group Policy Management Tools."
    Write-Error "Run the following command below to install RSAT on Windows 11"
    Write-Error "Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online"
    exit 1
}

Import-Module GroupPolicy

# Audit policy settings optimized for MDE
# Format: SubcategoryName, Success (enable/disable), Failure (enable/disable)
$AuditSettings = @(
    # Account Logon
    @{Category="Account Logon"; Subcategory="Credential Validation"; Success="enable"; Failure="enable"},
    @{Category="Account Logon"; Subcategory="Kerberos Authentication Service"; Success="enable"; Failure="enable"},
    @{Category="Account Logon"; Subcategory="Kerberos Service Ticket Operations"; Success="disable"; Failure="enable"},
    @{Category="Account Logon"; Subcategory="Other Account Logon Events"; Success="enable"; Failure="enable"},
    
    # Account Management
    @{Category="Account Management"; Subcategory="User Account Management"; Success="enable"; Failure="enable"},
    @{Category="Account Management"; Subcategory="Computer Account Management"; Success="enable"; Failure="enable"},
    @{Category="Account Management"; Subcategory="Security Group Management"; Success="enable"; Failure="enable"},
    @{Category="Account Management"; Subcategory="Distribution Group Management"; Success="enable"; Failure="enable"},
    @{Category="Account Management"; Subcategory="Application Group Management"; Success="enable"; Failure="enable"},
    @{Category="Account Management"; Subcategory="Other Account Management Events"; Success="enable"; Failure="enable"},
    
    # Detailed Tracking - CRITICAL for EDR
    @{Category="Detailed Tracking"; Subcategory="Process Creation"; Success="enable"; Failure="enable"},
    @{Category="Detailed Tracking"; Subcategory="Process Termination"; Success="enable"; Failure="disable"},
    @{Category="Detailed Tracking"; Subcategory="DPAPI Activity"; Success="enable"; Failure="enable"},
    @{Category="Detailed Tracking"; Subcategory="Plug and Play Events"; Success="enable"; Failure="disable"},
    @{Category="Detailed Tracking"; Subcategory="Token Right Adjusted Events"; Success="enable"; Failure="disable"},
    
    # Logon/Logoff
    @{Category="Logon/Logoff"; Subcategory="Logon"; Success="enable"; Failure="enable"},
    @{Category="Logon/Logoff"; Subcategory="Logoff"; Success="enable"; Failure="disable"},
    @{Category="Logon/Logoff"; Subcategory="Account Lockout"; Success="enable"; Failure="enable"},
    @{Category="Logon/Logoff"; Subcategory="Special Logon"; Success="enable"; Failure="enable"},
    @{Category="Logon/Logoff"; Subcategory="Other Logon/Logoff Events"; Success="enable"; Failure="enable"},
    @{Category="Logon/Logoff"; Subcategory="Network Policy Server"; Success="enable"; Failure="enable"},
    @{Category="Logon/Logoff"; Subcategory="User / Device Claims"; Success="enable"; Failure="disable"},
    @{Category="Logon/Logoff"; Subcategory="Group Membership"; Success="enable"; Failure="disable"},
    
    # Object Access
    @{Category="Object Access"; Subcategory="File System"; Success="disable"; Failure="enable"},
    @{Category="Object Access"; Subcategory="Registry"; Success="disable"; Failure="enable"},
    @{Category="Object Access"; Subcategory="Kernel Object"; Success="disable"; Failure="enable"},
    @{Category="Object Access"; Subcategory="SAM"; Success="disable"; Failure="enable"},
    @{Category="Object Access"; Subcategory="Certification Services"; Success="enable"; Failure="enable"},
    @{Category="Object Access"; Subcategory="Application Generated"; Success="enable"; Failure="enable"},
    @{Category="Object Access"; Subcategory="Handle Manipulation"; Success="disable"; Failure="disable"},
    @{Category="Object Access"; Subcategory="File Share"; Success="enable"; Failure="enable"},
    @{Category="Object Access"; Subcategory="Filtering Platform Packet Drop"; Success="enable"; Failure="enable"},
    @{Category="Object Access"; Subcategory="Filtering Platform Connection"; Success="enable"; Failure="enable"},
    @{Category="Object Access"; Subcategory="Other Object Access Events"; Success="enable"; Failure="enable"},
    @{Category="Object Access"; Subcategory="Detailed File Share"; Success="enable"; Failure="enable"},
    @{Category="Object Access"; Subcategory="Removable Storage"; Success="enable"; Failure="enable"},
    @{Category="Object Access"; Subcategory="Central Policy Staging"; Success="disable"; Failure="disable"},
    
    # Policy Change
    @{Category="Policy Change"; Subcategory="Audit Policy Change"; Success="enable"; Failure="enable"},
    @{Category="Policy Change"; Subcategory="Authentication Policy Change"; Success="enable"; Failure="enable"},
    @{Category="Policy Change"; Subcategory="Authorization Policy Change"; Success="enable"; Failure="enable"},
    @{Category="Policy Change"; Subcategory="MPSSVC Rule-Level Policy Change"; Success="enable"; Failure="enable"},
    @{Category="Policy Change"; Subcategory="Filtering Platform Policy Change"; Success="enable"; Failure="enable"},
    @{Category="Policy Change"; Subcategory="Other Policy Change Events"; Success="enable"; Failure="enable"},
    
    # Privilege Use
    @{Category="Privilege Use"; Subcategory="Sensitive Privilege Use"; Success="enable"; Failure="enable"},
    @{Category="Privilege Use"; Subcategory="Non Sensitive Privilege Use"; Success="disable"; Failure="disable"},
    @{Category="Privilege Use"; Subcategory="Other Privilege Use Events"; Success="disable"; Failure="disable"},
    
    # System
    @{Category="System"; Subcategory="Security State Change"; Success="enable"; Failure="enable"},
    @{Category="System"; Subcategory="Security System Extension"; Success="enable"; Failure="enable"},
    @{Category="System"; Subcategory="System Integrity"; Success="enable"; Failure="enable"},
    @{Category="System"; Subcategory="IPsec Driver"; Success="enable"; Failure="enable"},
    @{Category="System"; Subcategory="Other System Events"; Success="enable"; Failure="enable"}
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "MDE Audit Policy GPO Configuration" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Create the GPO
Write-Host "[*] Creating GPO: $GPOName" -ForegroundColor Yellow
try {
    $GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if ($GPO) {
        Write-Host "    GPO already exists. Using existing GPO." -ForegroundColor Yellow
    } else {
        $GPO = New-GPO -Name $GPOName -Comment "Audit policy settings optimized for Microsoft Defender for Endpoint (MDE). Enables comprehensive logging for EDR visibility."
        Write-Host "    GPO created successfully." -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to create GPO: $_"
    exit 1
}

# Create temporary audit policy CSV
$TempPath = [System.IO.Path]::GetTempPath()
$AuditCSVPath = Join-Path $TempPath "mde-audit-policy.csv"

Write-Host "`n[*] Generating audit policy configuration..." -ForegroundColor Yellow

# Build CSV content
$CSVContent = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value`r`n"

foreach ($setting in $AuditSettings) {
    # Get subcategory GUID
    $subcatInfo = auditpol /list /subcategory:"$($setting.Subcategory)" /v 2>$null | Where-Object { $_ -match '\{[0-9A-F\-]+\}' }
    
    if ($subcatInfo -match '\{([0-9A-F\-]+)\}') {
        $guid = "{$($matches[1])}"
        
        # Calculate setting value
        # 0 = No Auditing, 1 = Success, 2 = Failure, 3 = Success and Failure
        $settingValue = 0
        if ($setting.Success -eq "enable" -and $setting.Failure -eq "enable") { $settingValue = 3 }
        elseif ($setting.Success -eq "enable") { $settingValue = 1 }
        elseif ($setting.Failure -eq "enable") { $settingValue = 2 }
        
        $CSVContent += ",$($setting.Category),$($setting.Subcategory),$guid,,$settingValue`r`n"
        
        Write-Host "    [+] $($setting.Subcategory): " -NoNewline -ForegroundColor Gray
        switch ($settingValue) {
            0 { Write-Host "No Auditing" -ForegroundColor DarkGray }
            1 { Write-Host "Success" -ForegroundColor Green }
            2 { Write-Host "Failure" -ForegroundColor Yellow }
            3 { Write-Host "Success and Failure" -ForegroundColor Cyan }
        }
    }
}

# Save CSV
$CSVContent | Out-File -FilePath $AuditCSVPath -Encoding ASCII -Force

# Get GPO path
$GPOPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($GPO.Id)}\Machine\Microsoft\Windows NT\Audit"

Write-Host "`n[*] Applying audit policy to GPO..." -ForegroundColor Yellow

# Create audit directory in GPO if it doesn't exist
if (-not (Test-Path $GPOPath)) {
    New-Item -Path $GPOPath -ItemType Directory -Force | Out-Null
}

# Copy audit CSV to GPO
Copy-Item -Path $AuditCSVPath -Destination "$GPOPath\audit.csv" -Force

# Update GPO version to trigger refresh
$GPO = Get-GPO -Name $GPOName
$GPORegistryPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($GPO.Id)}\GPT.INI"

if (Test-Path $GPORegistryPath) {
    $GPTContent = Get-Content $GPORegistryPath
    $versionLine = $GPTContent | Where-Object { $_ -match "Version=" }
    
    if ($versionLine -match "Version=(\d+)") {
        $currentVersion = [int]$matches[1]
        $newVersion = $currentVersion + 65536  # Increment computer version
        $GPTContent = $GPTContent -replace "Version=\d+", "Version=$newVersion"
        $GPTContent | Set-Content $GPORegistryPath -Force
    }
}

Write-Host "    Audit policy applied successfully." -ForegroundColor Green

# Configure additional PowerShell logging for MDE
Write-Host "`n[*] Configuring PowerShell logging..." -ForegroundColor Yellow
try {
    # Enable PowerShell Script Block Logging
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1 | Out-Null
    
    # Enable PowerShell Module Logging
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ValueName "EnableModuleLogging" -Type DWord -Value 1 | Out-Null
    
    Write-Host "    PowerShell logging enabled." -ForegroundColor Green
} catch {
    Write-Warning "Failed to configure PowerShell logging: $_"
}

# Configure Process Creation to include command line
Write-Host "`n[*] Configuring Process Creation command line logging..." -ForegroundColor Yellow
try {
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1 | Out-Null
    Write-Host "    Process command line logging enabled." -ForegroundColor Green
} catch {
    Write-Warning "Failed to configure process command line logging: $_"
}

# Configure Security Event Log settings
Write-Host "`n[*] Configuring Security Event Log settings..." -ForegroundColor Yellow
try {
    # Set Security Event Log maximum size to 1GB
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" -ValueName "MaxSize" -Type DWord -Value 1048576 | Out-Null
    Write-Host "    Security Event Log maximum size set to 1GB" -ForegroundColor Green
    
    # Disable Configure log access
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" -ValueName "ChannelAccess" -Type String -Value "" | Out-Null
    Write-Host "    Configure log access set to Disabled" -ForegroundColor Yellow
    
    # Disable Configure log access (legacy)
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" -ValueName "ChannelAccessLegacy" -Type String -Value "" | Out-Null
    Write-Host "    Configure log access (legacy) set to Disabled" -ForegroundColor Yellow
    
} catch {
    Write-Warning "Failed to configure Security Event Log settings: $_"
}

# Link to OU if specified
if ($TargetOU) {
    Write-Host "`n[*] Linking GPO to OU: $TargetOU" -ForegroundColor Yellow
    try {
        $link = New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled $(if ($LinkEnabled) { "Yes" } else { "No" }) -ErrorAction Stop
        Write-Host "    GPO linked successfully." -ForegroundColor Green
        if (-not $LinkEnabled) {
            Write-Host "    (Link is currently disabled)" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Failed to link GPO: $_"
    }
}

# Clean up temp file
Remove-Item $AuditCSVPath -Force -ErrorAction SilentlyContinue

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Configuration Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nGPO Details:" -ForegroundColor White
Write-Host "  Name: $($GPO.DisplayName)" -ForegroundColor Gray
Write-Host "  GUID: {$($GPO.Id)}" -ForegroundColor Gray
Write-Host "  Created: $($GPO.CreationTime)" -ForegroundColor Gray
Write-Host "  Modified: $($GPO.ModificationTime)" -ForegroundColor Gray

if ($TargetOU) {
    Write-Host "`nGPO Link:" -ForegroundColor White
    Write-Host "  Target OU: $TargetOU" -ForegroundColor Gray
    Write-Host "  Link Enabled: $LinkEnabled" -ForegroundColor Gray
} else {
    Write-Host "`nNote: GPO created but not linked. Link manually to desired OU." -ForegroundColor Yellow
}

Write-Host "`nNext Steps:" -ForegroundColor White
Write-Host "  1. Review the GPO settings in Group Policy Management Console" -ForegroundColor Gray
Write-Host "  2. Run 'gpupdate /force' on target clients to apply immediately" -ForegroundColor Gray
Write-Host "  3. Verify audit settings with: auditpol /get /category:*" -ForegroundColor Gray
Write-Host "  4. Monitor Security event log size and adjust if needed (recommend 1GB+)" -ForegroundColor Gray
Write-Host "`n"

# Optional: Generate report
$ReportPath = Join-Path $PSScriptRoot "GPO-Report-$($GPOName -replace ' ','-').html"
Write-Host "[*] Generating GPO report to: $ReportPath" -ForegroundColor Yellow
try {
    Get-GPOReport -Name $GPOName -ReportType HTML -Path $ReportPath
    Write-Host "    Report generated successfully." -ForegroundColor Green
} catch {
    Write-Warning "Failed to generate report: $_"
}
