<#
    Author: DCODEV1702 & Claude Sonnet 4.5
    Date: 15 Nov 2025
    
    .SYNOPSIS
    Creates and configures a Group Policy Object for Attack Surface Reduction (ASR) rules in Audit mode.
    
    .DESCRIPTION
    This script creates or updates a GPO that enables Microsoft Defender Attack Surface Reduction (ASR) 
    rules in Audit mode for workstations. Audit mode allows you to evaluate the impact of ASR rules 
    without blocking potentially legitimate activity, making it ideal for initial deployment and testing.
    
    The script performs the following actions:
    - Creates a new GPO named "ASR-Audit-Mode-Workstations" or uses existing GPO
    - Links the GPO to the Workstations Organizational Unit
    - Enables the ASR feature itself (ExploitGuard_ASR_Rules)
    - Configures 17 ASR rules in Audit mode (value = 2)
    
    ASR Rules Configured:
    - Block executable content from email client and webmail
    - Block all Office applications from creating child processes
    - Block Office applications from creating executable content
    - Block Office applications from injecting code into other processes
    - Block JavaScript or VBScript from launching downloaded executable content
    - Block execution of potentially obfuscated scripts
    - Block Win32 API calls from Office macros
    - Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    - Use advanced protection against ransomware
    - Block credential stealing from the Windows local security authority subsystem (lsass.exe)
    - Block process creations originating from PSExec and WMI commands
    - Block untrusted and unsigned processes that run from USB
    - Block Office communication application from creating child processes
    - Block Adobe Reader from creating child processes
    - Block persistence through WMI event subscription
    - Block abuse of exploited vulnerable signed drivers
    - Block rebooting machine in Safe Mode (preview)
    
    ASR Rule Values:
    - 0 = Disabled
    - 1 = Block mode (enforcement)
    - 2 = Audit mode (logging only)
    
    .PARAMETER GPOName
    Name of the Group Policy Object to create or update.
    Default: "ASR-Audit-Mode-Workstations"
    
    .PARAMETER OU
    Distinguished Name of the Organizational Unit to link the GPO to.
    Default: "OU=Workstations,DC=contoso,DC=local"
    
    .EXAMPLE
    .\Create-ASR-AuditMode-GPO.ps1
    
    Creates the ASR audit mode GPO with default settings and links it to the Workstations OU.
    
    .EXAMPLE
    .\Create-ASR-AuditMode-GPO.ps1 -GPOName "ASR-Audit-Test" -OU "OU=TestComputers,DC=contoso,DC=local"
    
    Creates a custom-named GPO and links it to a different OU.
    
    .NOTES
    Requirements:
    - RSAT Group Policy Management Tools (GroupPolicy PowerShell module)
    - Domain Administrator or equivalent permissions
    - Run from Domain Controller or system with RSAT installed
    
    After deployment:
    1. Run 'gpupdate /force' on target workstations
    2. Monitor ASR events in Event Viewer:
       - Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational
       - Event IDs: 1121 (Audit), 1122 (Block)
    3. Review audit logs to identify legitimate applications that may be affected
    4. Adjust rules or exclusions as needed before switching to Block mode
    
    To switch to Block mode later:
    - Change all rule values from 2 (Audit) to 1 (Block)
    
    Microsoft Documentation:
    https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$GPOName = "ASR-Audit-Mode-Workstations",
    
    [Parameter(Mandatory=$false)]
    [string]$OU = "OU=Workstations,DC=contoso,DC=local"
)

# Import required module
Import-Module GroupPolicy

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "ASR Audit Mode GPO Configuration" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Create new GPO or use existing
Write-Host "[*] Checking for GPO: $GPOName" -ForegroundColor Yellow
try {
    $GPO = Get-GPO -Name $GPOName -ErrorAction Stop
    Write-Host "    GPO already exists. Using existing GPO." -ForegroundColor Yellow
} catch {
    Write-Host "    GPO does not exist. Creating new GPO..." -ForegroundColor Yellow
    $GPO = New-GPO -Name $GPOName
    Write-Host "    GPO created successfully." -ForegroundColor Green
    
    # Link to OU
    Write-Host "    Linking GPO to OU: $OU" -ForegroundColor Yellow
    New-GPLink -Name $GPOName -Target $OU -LinkEnabled Yes -Enforced Yes
    Write-Host "    GPO linked and enforced successfully." -ForegroundColor Green
}

# Registry path for ASR rules
$RegPath = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"

Write-Host "`n[*] Enabling Attack Surface Reduction feature..." -ForegroundColor Yellow

# CRITICAL: Enable ASR itself first
Set-GPRegistryValue -Name $GPOName -Key $RegPath -ValueName "ExploitGuard_ASR_Rules" -Type DWord -Value 1 | Out-Null
Write-Host "    ASR feature enabled." -ForegroundColor Green

Write-Host "`n[*] Configuring ASR rules in Audit mode (value = 2)..." -ForegroundColor Yellow

# ASR Rules to enable in Audit mode (value = 2)
# Rule GUID = Rule Mode (2 = Audit)
$ASRRules = @{
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 2  # Block executable content from email client and webmail
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 2  # Block all Office applications from creating child processes
    "3B576869-A4EC-4529-8536-B80A7769E899" = 2  # Block Office applications from creating executable content
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 2  # Block Office applications from injecting code into other processes
    "D3E037E1-3EB8-44C8-A917-57927947596D" = 2  # Block JavaScript or VBScript from launching downloaded executable content
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 2  # Block execution of potentially obfuscated scripts
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 2  # Block Win32 API calls from Office macros
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = 2  # Block executable files from running unless they meet prevalence, age, or trusted list criterion
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = 2  # Use advanced protection against ransomware
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 2  # Block credential stealing from lsass.exe
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = 2  # Block process creations originating from PSExec and WMI commands
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 2  # Block untrusted and unsigned processes that run from USB
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = 2  # Block Office communication application from creating child processes
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = 2  # Block Adobe Reader from creating child processes
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = 2  # Block persistence through WMI event subscription
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = 2  # Block abuse of exploited vulnerable signed drivers
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = 2  # Block rebooting machine in Safe Mode (preview)
}

# Set each ASR rule - GUID on left, numeric value (2) on right
$ruleCount = 0
foreach ($RuleID in $ASRRules.Keys) {
    Set-GPRegistryValue -Name $GPOName -Key "$RegPath\Rules" -ValueName $RuleID -Type String -Value $ASRRules[$RuleID] | Out-Null
    $ruleCount++
    Write-Host "    [+] Rule $ruleCount of $($ASRRules.Count) configured: $RuleID" -ForegroundColor Gray
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Configuration Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nGPO Details:" -ForegroundColor White
Write-Host "  Name: $($GPO.DisplayName)" -ForegroundColor Gray
Write-Host "  GUID: {$($GPO.Id)}" -ForegroundColor Gray
Write-Host "  ASR Rules Configured: $($ASRRules.Count)" -ForegroundColor Gray
Write-Host "  Mode: Audit (value = 2)" -ForegroundColor Gray
Write-Host "  Linked to: $OU" -ForegroundColor Gray

Write-Host "`nNext Steps:" -ForegroundColor White
Write-Host "  1. Run 'gpupdate /force' on target workstations" -ForegroundColor Gray
Write-Host "  2. Monitor ASR events in Event Viewer (Event IDs 1121 for Audit, 1122 for Block)" -ForegroundColor Gray
Write-Host "  3. Review audit logs to identify legitimate applications affected" -ForegroundColor Gray
Write-Host "  4. Adjust rules or add exclusions as needed" -ForegroundColor Gray
Write-Host "  5. Switch to Block mode (value = 1) after testing period" -ForegroundColor Gray

Write-Host "`nMonitoring Commands:" -ForegroundColor White
Write-Host "  # View ASR configuration on client:" -ForegroundColor Gray
Write-Host "  Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions" -ForegroundColor Gray
Write-Host "`n  # View ASR events:" -ForegroundColor Gray
Write-Host "  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1121,1122} | Select-Object TimeCreated, Message" -ForegroundColor Gray

Write-Host "`n"
