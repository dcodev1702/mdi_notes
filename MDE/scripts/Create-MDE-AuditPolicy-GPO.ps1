#Requires -Modules GroupPolicy

<#
.SYNOPSIS
    Creates a GPO with comprehensive audit policy settings optimized for Microsoft Defender for Endpoint (MDE).

.DESCRIPTION
    This script creates and configures a comprehensive Group Policy Object optimized for Microsoft 
    Defender for Endpoint (MDE) with the following components:
    
    AUDIT POLICY CONFIGURATION:
    - Configures 40+ audit subcategories across 7 major categories (Account Logon, Account Management,
      Detailed Tracking, Logon/Logoff, Object Access, Policy Change, Privilege Use, and System)
    - Generates audit policy CSV and deploys it to SYSVOL for GPO enforcement
    - Automatically increments GPO version to trigger policy refresh
    - Creates startup script to clear legacy audit policies that can interfere with Advanced Audit Policy
    - Sets SCENoApplyLegacyAuditPolicy registry key to enforce Advanced Audit Policy
    
    POWERSHELL LOGGING:
    - Enables PowerShell Script Block Logging for detailed script execution visibility
    - Enables PowerShell Module Logging to track module usage
    
    PROCESS MONITORING:
    - Enables command line logging for process creation events (Event ID 4688)
    - Critical for EDR visibility into process execution and parent-child relationships
    
    SECURITY EVENT LOG OPTIMIZATION:
    - Sets Security Event Log maximum size to 1GB (1,048,576 KB)
    - Disables "Configure log access" policy
    - Disables "Configure log access (legacy)" policy
    - Ensures adequate log retention for security monitoring and forensic analysis
    
    GPO DEPLOYMENT:
    - Creates new GPO or updates existing GPO with specified name
    - Links GPO to specified Organizational Unit with configurable enabled/disabled state
    - Generates HTML report of complete GPO configuration
    
    The script enforces security logging best practices aligned with MDE requirements, NIST guidelines,
    and CIS benchmarks to maximize endpoint detection and response capabilities.

.PARAMETER GPOName
    Name of the GPO to create. Default: "MDE Audit Policy - Workstations"

.PARAMETER TargetOU
    Distinguished Name of the OU to link the GPO to. If not specified, GPO is created but not linked.

.PARAMETER LinkEnabled
    Whether to enable the GPO link immediately. Default: $true

.EXAMPLE
    .\Create-MDE-AuditPolicy-GPO.ps1 -GPOName "MDE Audit Policy - Domain Controllers" -TargetOU "OU=Domain Controllers,DC=contoso,DC=local"

.EXAMPLE
    .\Create-MDE-AuditPolicy-GPO.ps1 -GPOName "MDE Audit Policy - Workstations" -TargetOU "OU=Workstations,DC=contoso,DC=local"

.NOTES
    Author: Generated for MDE Audit Policy Configuration
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
    @{Category="Object Access"; Subcategory="Filtering Platform Packet Drop"; Success="enable"; Failure="disable"},
    @{Category="Object Access"; Subcategory="Filtering Platform Connection"; Success="disable"; Failure="enable"},
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

# Get all subcategory GUIDs at once for better performance
Write-Host "[*] Retrieving audit subcategory GUIDs..." -ForegroundColor Yellow
$allSubcats = auditpol /list /subcategory:* /r 2>$null | Select-Object -Skip 1

# Build a hashtable for quick GUID lookup
$guidLookup = @{}
foreach ($line in $allSubcats) {
    if ($line -and $line.Contains(',')) {
        # Split by comma - format is: "  Subcategory Name,{GUID}"
        $parts = $line -split ',', 2
        if ($parts.Count -eq 2) {
            $subcatName = $parts[0].Trim()
            $subcatGuid = $parts[1].Trim()
            
            # Only add subcategories (lines that start with spaces), not category headers
            if ($line -match '^\s{2,}') {
                $guidLookup[$subcatName] = $subcatGuid
            }
        }
    }
}

Write-Host "    Retrieved $($guidLookup.Count) subcategory GUIDs" -ForegroundColor Green

foreach ($setting in $AuditSettings) {
    # Look up GUID from hashtable
    if ($guidLookup.ContainsKey($setting.Subcategory)) {
        $guid = $guidLookup[$setting.Subcategory]
        
        # Calculate setting value
        # 0 = No Auditing, 1 = Success, 2 = Failure, 3 = Success and Failure
        $settingValue = 0
        if ($setting.Success -eq "enable" -and $setting.Failure -eq "enable") { $settingValue = 3 }
        elseif ($setting.Success -eq "enable") { $settingValue = 1 }
        elseif ($setting.Failure -eq "enable") { $settingValue = 2 }
        
        # Generate CSV line with proper format - must have all 7 fields to match header
        # Field 1: Machine Name (empty)
        # Field 2: Policy Target (Category)  
        # Field 3: Subcategory
        # Field 4: Subcategory GUID
        # Field 5: Inclusion Setting (empty)
        # Field 6: Exclusion Setting (empty)
        # Field 7: Setting Value
        $csvLine = @(
            "",                         # Machine Name
            $setting.Category,          # Policy Target
            $setting.Subcategory,       # Subcategory
            $guid,                      # Subcategory GUID
            "",                         # Inclusion Setting
            "",                         # Exclusion Setting
            $settingValue               # Setting Value
        ) -join ','
        $CSVContent += "$csvLine`r`n"
        
        Write-Host "    [+] $($setting.Subcategory): " -NoNewline -ForegroundColor Gray
        switch ($settingValue) {
            0 { Write-Host "No Auditing" -ForegroundColor DarkGray }
            1 { Write-Host "Success" -ForegroundColor Green }
            2 { Write-Host "Failure" -ForegroundColor Yellow }
            3 { Write-Host "Success and Failure" -ForegroundColor Cyan }
        }
    } else {
        Write-Warning "Could not find GUID for subcategory: $($setting.Subcategory)"
        Write-Host "    Available subcategories:" -ForegroundColor Yellow
        $guidLookup.Keys | Sort-Object | ForEach-Object { Write-Host "      - $_" -ForegroundColor Gray }
    }
}

# Save CSV - Write directly to file to ensure proper formatting
[System.IO.File]::WriteAllText($AuditCSVPath, $CSVContent, [System.Text.Encoding]::ASCII)

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

# CRITICAL: Force advanced audit policy to override legacy audit policy
Write-Host "`n[*] Forcing advanced audit policy to override legacy settings..." -ForegroundColor Yellow
try {
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "SCENoApplyLegacyAuditPolicy" -Type DWord -Value 1 | Out-Null
    Write-Host "    Advanced audit policy enforcement enabled." -ForegroundColor Green
} catch {
    Write-Warning "Failed to configure advanced audit policy enforcement: $_"
}

# Create startup script to clear legacy audit policies
Write-Host "`n[*] Creating startup script to clear legacy audit policies..." -ForegroundColor Yellow
try {
    # Create Scripts directory in GPO SYSVOL
    $ScriptsPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($GPO.Id)}\Machine\Scripts\Startup"
    if (-not (Test-Path $ScriptsPath)) {
        New-Item -Path $ScriptsPath -ItemType Directory -Force | Out-Null
    }
    
    # Create the legacy audit policy cleanup script
    $StartupScriptContent = @'
@echo off
REM Clear legacy audit policies that can override Advanced Audit Policy
REM This ensures Advanced Audit Policy from GPO is properly applied

auditpol /clear /y >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    gpupdate /target:computer /force /wait:0 >nul 2>&1
)
exit /b 0
'@
    
    $StartupScriptPath = Join-Path $ScriptsPath "Clear-LegacyAuditPolicy.cmd"
    $StartupScriptContent | Out-File -FilePath $StartupScriptPath -Encoding ASCII -Force
    
    # Configure GPO to run the startup script
    $ScriptsIniPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($GPO.Id)}\Machine\Scripts\scripts.ini"
    
    # Create scripts.ini content
    $ScriptsIniContent = @"
[Startup]
0CmdLine=Clear-LegacyAuditPolicy.cmd
0Parameters=
"@
    
    $ScriptsIniContent | Out-File -FilePath $ScriptsIniPath -Encoding Unicode -Force
    
    # Update psscripts.ini for consistency
    $PsScriptsIniPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($GPO.Id)}\Machine\Scripts\psscripts.ini"
    "[Startup]" | Out-File -FilePath $PsScriptsIniPath -Encoding Unicode -Force
    
    Write-Host "    Startup script created and configured." -ForegroundColor Green
    Write-Host "    Script will clear legacy audit policies on every reboot." -ForegroundColor Gray
} catch {
    Write-Warning "Failed to create startup script: $_"
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
    
    # Disable Configure log access (remove the registry value to disable the policy)
    Remove-GPRegistryValue -Name $GPOName -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" -ValueName "ChannelAccess" -ErrorAction SilentlyContinue | Out-Null
    Write-Host "    Configure log access set to Disabled" -ForegroundColor Yellow
    
    # Disable Configure log access (legacy)
    Remove-GPRegistryValue -Name $GPOName -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" -ValueName "ChannelAccessLegacy" -ErrorAction SilentlyContinue | Out-Null
    Write-Host "    Configure log access (legacy) set to Disabled" -ForegroundColor Yellow
    
} catch {
    Write-Warning "Failed to configure Security Event Log settings: $_"
}

# Link to OU if specified
if ($TargetOU) {
    Write-Host "`n[*] Linking GPO to OU: $TargetOU" -ForegroundColor Yellow
    try {
        # Check if link already exists
        $existingLink = Get-GPInheritance -Target $TargetOU | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $GPOName }
        
        if ($existingLink) {
            Write-Host "    GPO link already exists." -ForegroundColor Yellow
            # Update link properties if needed
            Set-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled $(if ($LinkEnabled) { "Yes" } else { "No" }) -Enforced "Yes" -ErrorAction Stop | Out-Null
            Write-Host "    GPO link updated (Enforced: Yes, Enabled: $LinkEnabled)." -ForegroundColor Green
        } else {
            # Create new link
            $link = New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled $(if ($LinkEnabled) { "Yes" } else { "No" }) -Enforced "Yes" -ErrorAction Stop
            Write-Host "    GPO linked successfully (Enforced: Yes)." -ForegroundColor Green
        }
        
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
Write-Host "  2. For EXISTING machines, manually clear legacy audit policies:" -ForegroundColor Gray
Write-Host "     - Run: auditpol /clear /y" -ForegroundColor DarkGray
Write-Host "     - Run: gpupdate /force" -ForegroundColor DarkGray
Write-Host "  3. NEW machines will automatically clear legacy policies on startup" -ForegroundColor Gray
Write-Host "  4. Verify audit settings with: auditpol /get /category:*" -ForegroundColor Gray
Write-Host "  5. Monitor Security event log size and adjust if needed (recommend 1GB+)" -ForegroundColor Gray
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
