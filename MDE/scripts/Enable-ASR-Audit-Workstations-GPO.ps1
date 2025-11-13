#Requires -Modules GroupPolicy

<#
.SYNOPSIS
    Configures Attack Surface Reduction (ASR) rules in audit mode via Group Policy.

.DESCRIPTION
    This script creates or updates a GPO with all Microsoft Defender ASR rules configured
    in audit mode (value = 2). Audit mode allows monitoring of ASR rule impacts without
    blocking actions, which is essential for baselining before enforcement.

.PARAMETER GPOName
    Name of the GPO to create or update. Default: "ASR-Audit-Mode-Workstations"

.PARAMETER TargetOU
    Distinguished Name of the OU to link the GPO to.
    Default: "OU=Workstations,DC=contoso,DC=local"

.EXAMPLE
    .\Configure-ASR-AuditMode.ps1

.EXAMPLE
    .\Configure-ASR-AuditMode.ps1 -GPOName "Custom ASR Audit" -TargetOU "OU=Clients,DC=domain,DC=com"

.NOTES
    Author: ASR Configuration Script
    Requires: Group Policy Management PowerShell Module
    Run as: Domain Administrator or user with GPO creation rights
    
    ASR Rule Values:
    0 = Disabled
    1 = Block mode (enforce)
    2 = Audit mode (log only)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$GPOName = "ASR-Audit-Mode-Workstations",
    
    [Parameter(Mandatory=$false)]
    [string]$TargetOU = "OU=Workstations,DC=contoso,DC=local"
)

# Check for required modules
if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    Write-Error "GroupPolicy module not found. Install RSAT Group Policy Management Tools."
    exit 1
}

Import-Module GroupPolicy

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "ASR Audit Mode Configuration" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Create new GPO or get existing
Write-Host "[*] Configuring GPO: $GPOName" -ForegroundColor Yellow
try {
    $GPO = Get-GPO -Name $GPOName -ErrorAction Stop
    Write-Host "    Using existing GPO." -ForegroundColor Yellow
} catch {
    Write-Host "    Creating new GPO..." -ForegroundColor Yellow
    $GPO = New-GPO -Name $GPOName -Comment "ASR rules configured in audit mode for impact assessment and baselining"
    
    # Link to OU
    try {
        New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled Yes | Out-Null
        Write-Host "    GPO created and linked to: $TargetOU" -ForegroundColor Green
    } catch {
        Write-Warning "GPO created but failed to link to OU: $_"
    }
}

# Registry path for ASR rules
$RegPath = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"

# CRITICAL: Enable ASR functionality first
Write-Host "`n[*] Enabling ASR functionality..." -ForegroundColor Yellow
try {
    Set-GPRegistryValue -Name $GPOName -Key $RegPath -ValueName "ExploitGuard_ASR_Rules" -Type DWord -Value 1 | Out-Null
    Write-Host "    ASR enabled successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to enable ASR: $_"
    exit 1
}

# ASR Rules to configure in Audit mode (value = 2)
# Reference: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
$ASRRules = @{
    # Block executable content from email client and webmail
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 2
    
    # Block all Office applications from creating child processes
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 2
    
    # Block Office applications from creating executable content
    "3B576869-A4EC-4529-8536-B80A7769E899" = 2
    
    # Block Office applications from injecting code into other processes
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 2
    
    # Block JavaScript or VBScript from launching downloaded executable content
    "D3E037E1-3EB8-44C8-A917-57927947596D" = 2
    
    # Block execution of potentially obfuscated scripts
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 2
    
    # Block Win32 API calls from Office macros
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 2
    
    # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = 2
    
    # Use advanced protection against ransomware
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = 2
    
    # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 2
    
    # Block process creations originating from PSExec and WMI commands
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = 2
    
    # Block untrusted and unsigned processes that run from USB
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 2
    
    # Block Office communication application from creating child processes
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = 2
    
    # Block Adobe Reader from creating child processes
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = 2
    
    # Block persistence through WMI event subscription
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = 2
    
    # Block abuse of exploited vulnerable signed drivers
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = 2
    
    # Block Webshell creation for Servers
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = 2
}

# Configure each ASR rule
Write-Host "`n[*] Configuring ASR rules in audit mode..." -ForegroundColor Yellow
$successCount = 0
$failCount = 0

foreach ($RuleID in $ASRRules.Keys) {
    try {
        Set-GPRegistryValue -Name $GPOName -Key "$RegPath\Rules" -ValueName $RuleID -Type String -Value $ASRRules[$RuleID] | Out-Null
        $successCount++
        Write-Host "    [+] Configured rule: $RuleID" -ForegroundColor Gray
    } catch {
        $failCount++
        Write-Warning "Failed to configure rule $RuleID : $_"
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Configuration Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nGPO Details:" -ForegroundColor White
Write-Host "  Name: $($GPO.DisplayName)" -ForegroundColor Gray
Write-Host "  GUID: {$($GPO.Id)}" -ForegroundColor Gray
Write-Host "  Linked to: $TargetOU" -ForegroundColor Gray

Write-Host "`nASR Configuration:" -ForegroundColor White
Write-Host "  Total rules: $($ASRRules.Count)" -ForegroundColor Gray
Write-Host "  Successfully configured: $successCount" -ForegroundColor Green
if ($failCount -gt 0) {
    Write-Host "  Failed: $failCount" -ForegroundColor Red
}
Write-Host "  Mode: Audit (value = 2)" -ForegroundColor Gray

Write-Host "`nNext Steps:" -ForegroundColor White
Write-Host "  1. Run 'gpupdate /force' on target workstations" -ForegroundColor Gray
Write-Host "  2. Monitor ASR events in Microsoft Defender for Endpoint portal" -ForegroundColor Gray
Write-Host "  3. Review audit data for 30+ days before enabling block mode" -ForegroundColor Gray
Write-Host "  4. Create exclusions for false positives before enforcement" -ForegroundColor Gray
Write-Host "  5. Change rule values from 2 (audit) to 1 (block) when ready" -ForegroundColor Gray

Write-Host "`nVerification:" -ForegroundColor White
Write-Host "  Check ASR status on client: Get-MpPreference | Select-Object AttackSurfaceReductionRules_*" -ForegroundColor Gray
Write-Host "  View ASR events: Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1121,1122}" -ForegroundColor Gray

Write-Host "`n"
