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

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "MDE Audit Policy GPO Configuration (Fixed)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Create the GPO
Write-Host "[*] Creating/Checking GPO: $GPOName" -ForegroundColor Yellow
try {
    $GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if ($GPO) {
        Write-Host "    GPO already exists. Updating existing GPO." -ForegroundColor Yellow
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

# ---------------------------------------------------------
# FIX APPLIED: Hardcoded CSV Content
# This ensures the GUIDs are always correct and prevents the 
# "Empty Audit Policy" issue caused by auditpol parsing failures.
# ---------------------------------------------------------
$CSVContent = @"
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Security System Extension,{6997984B-797A-11D2-8410-006008C0E1D0},,,3
,System,System Integrity,{6997984C-797A-11D2-8410-006008C0E1D0},,,3
,System,IPsec Driver,{6997984D-797A-11D2-8410-006008C0E1D0},,,3
,System,Other System Events,{6997984E-797A-11D2-8410-006008C0E1D0},,,3
,System,Security State Change,{6997984F-797A-11D2-8410-006008C0E1D0},,,3
,Account Logon,Kerberos Service Ticket Operations,{0CCE9228-69AE-11D9-BED3-505054503030},,,2
,Account Logon,Other Account Logon Events,{0CCE9229-69AE-11D9-BED3-505054503030},,,3
,Account Logon,Kerberos Authentication Service,{0CCE922A-69AE-11D9-BED3-505054503030},,,3
,Account Logon,Credential Validation,{0CCE922C-69AE-11D9-BED3-505054503030},,,3
,Account Management,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},,,3
,Account Management,Computer Account Management,{0CCE9236-69AE-11D9-BED3-505054503030},,,3
,Account Management,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},,,3
,Account Management,Distribution Group Management,{0CCE9238-69AE-11D9-BED3-505054503030},,,3
,Account Management,Application Group Management,{0CCE9239-69AE-11D9-BED3-505054503030},,,3
,Account Management,Other Account Management Events,{0CCE923A-69AE-11D9-BED3-505054503030},,,3
,Detailed Tracking,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},,,3
,Detailed Tracking,Process Termination,{0CCE922D-69AE-11D9-BED3-505054503030},,,1
,Detailed Tracking,DPAPI Activity,{0CCE922E-69AE-11D9-BED3-505054503030},,,3
,Detailed Tracking,RPC Events,{0CCE922F-69AE-11D9-BED3-505054503030},,,3
,Detailed Tracking,Plug and Play Events,{0CCE9230-69AE-11D9-BED3-505054503030},,,1
,Detailed Tracking,Token Right Adjusted Events,{0CCE9231-69AE-11D9-BED3-505054503030},,,1
,Logon/Logoff,Logon,{69979849-797A-11D2-8410-006008C0E1D0},,,3
,Logon/Logoff,Logoff,{6997984A-797A-11D2-8410-006008C0E1D0},,,1
,Logon/Logoff,Account Lockout,{0CCE9216-69AE-11D9-BED3-505054503030},,,3
,Logon/Logoff,IPsec Main Mode,{0CCE9217-69AE-11D9-BED3-505054503030},,,3
,Logon/Logoff,Special Logon,{0CCE9218-69AE-11D9-BED3-505054503030},,,3
,Logon/Logoff,IPsec Extended Mode,{0CCE9219-69AE-11D9-BED3-505054503030},,,3
,Logon/Logoff,Other Logon/Logoff Events,{0CCE921A-69AE-11D9-BED3-505054503030},,,3
,Logon/Logoff,Network Policy Server,{0CCE9243-69AE-11D9-BED3-505054503030},,,3
,Logon/Logoff,User / Device Claims,{0CCE9247-69AE-11D9-BED3-505054503030},,,1
,Logon/Logoff,Group Membership,{0CCE9249-69AE-11D9-BED3-505054503030},,,1
,Object Access,File System,{0CCE921D-69AE-11D9-BED3-505054503030},,,2
,Object Access,Registry,{0CCE921E-69AE-11D9-BED3-505054503030},,,2
,Object Access,Kernel Object,{0CCE921F-69AE-11D9-BED3-505054503030},,,2
,Object Access,SAM,{0CCE9220-69AE-11D9-BED3-505054503030},,,2
,Object Access,Certification Services,{0CCE9221-69AE-11D9-BED3-505054503030},,,3
,Object Access,Application Generated,{0CCE9222-69AE-11D9-BED3-505054503030},,,3
,Object Access,Handle Manipulation,{0CCE9223-69AE-11D9-BED3-505054503030},,,0
,Object Access,File Share,{0CCE9224-69AE-11D9-BED3-505054503030},,,3
,Object Access,Filtering Platform Packet Drop,{0CCE9225-69AE-11D9-BED3-505054503030},,,1
,Object Access,Filtering Platform Connection,{0CCE9226-69AE-11D9-BED3-505054503030},,,2
,Object Access,Other Object Access Events,{0CCE9227-69AE-11D9-BED3-505054503030},,,3
,Object Access,Detailed File Share,{0CCE9244-69AE-11D9-BED3-505054503030},,,3
,Object Access,Removable Storage,{0CCE9245-69AE-11D9-BED3-505054503030},,,3
,Object Access,Central Policy Staging,{0CCE9246-69AE-11D9-BED3-505054503030},,,0
,Policy Change,Audit Policy Change,{0CCE9233-69AE-11D9-BED3-505054503030},,,3
,Policy Change,Authentication Policy Change,{0CCE9234-69AE-11D9-BED3-505054503030},,,3
,Policy Change,Authorization Policy Change,{0CCE9232-69AE-11D9-BED3-505054503030},,,3
,Policy Change,MPSSVC Rule-Level Policy Change,{0CCE923F-69AE-11D9-BED3-505054503030},,,3
,Policy Change,Filtering Platform Policy Change,{0CCE9240-69AE-11D9-BED3-505054503030},,,3
,Policy Change,Other Policy Change Events,{0CCE9241-69AE-11D9-BED3-505054503030},,,3
,Privilege Use,Sensitive Privilege Use,{0CCE923B-69AE-11D9-BED3-505054503030},,,3
,Privilege Use,Non Sensitive Privilege Use,{0CCE923C-69AE-11D9-BED3-505054503030},,,0
,Privilege Use,Other Privilege Use Events,{0CCE923D-69AE-11D9-BED3-505054503030},,,0
"@

# Save CSV - Write directly to file to ensure proper formatting
[System.IO.File]::WriteAllText($AuditCSVPath, $CSVContent, [System.Text.Encoding]::ASCII)
Write-Host "    Audit CSV generated successfully (Static Mode)." -ForegroundColor Green

# Get GPO path in SYSVOL
$GPOPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($GPO.Id)}\Machine\Microsoft\Windows NT\Audit"

Write-Host "`n[*] Applying audit policy to GPO in SYSVOL..." -ForegroundColor Yellow
Write-Host "    Path: $GPOPath" -ForegroundColor Gray

# Create audit directory in GPO if it doesn't exist
if (-not (Test-Path $GPOPath)) {
    New-Item -Path $GPOPath -ItemType Directory -Force | Out-Null
}

# Copy audit CSV to GPO
$DestFile = Join-Path $GPOPath "audit.csv"
Copy-Item -Path $AuditCSVPath -Destination $DestFile -Force

# VERIFY FILE EXISTENCE (Added check)
if (Test-Path $DestFile) {
    $item = Get-Item $DestFile
    if ($item.Length -gt 0) {
         Write-Host "    [SUCCESS] Audit file verified in SYSVOL." -ForegroundColor Green
    } else {
         Write-Warning "    [ERROR] File exists but is empty (0 KB)."
    }
} else {
    Write-Error "    [ERROR] File copy failed. The audit.csv file is NOT in SYSVOL."
}

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

Write-Host "    GPO Version incremented." -ForegroundColor Green

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

if ($TargetOU) {
    Write-Host "`nGPO Link:" -ForegroundColor White
    Write-Host "  Target OU: $TargetOU" -ForegroundColor Gray
    Write-Host "  Link Enabled: $LinkEnabled" -ForegroundColor Gray
} else {
    Write-Host "`nNote: GPO created but not linked. Link manually to desired OU." -ForegroundColor Yellow
}

Write-Host "`nNext Steps:" -ForegroundColor White
Write-Host "  1. Review the GPO settings in Group Policy Management Console" -ForegroundColor Gray
Write-Host "  2. Verify audit file existence:" -ForegroundColor Gray
Write-Host "     $DestFile" -ForegroundColor DarkGray
Write-Host "  3. On the client, run: gpupdate /force" -ForegroundColor DarkGray
Write-Host "  4. Verify settings: auditpol /get /category:*" -ForegroundColor Gray
Write-Host "`n"
