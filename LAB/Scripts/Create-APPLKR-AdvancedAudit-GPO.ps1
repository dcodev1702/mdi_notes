#Requires -Modules GroupPolicy

<#
.SYNOPSIS
    Creates or updates a fuller advanced audit policy GPO for APPLKR domain controllers.

.DESCRIPTION
    This script is a thin APPLKR-specific wrapper around the existing full audit policy
    bootstrap used in this repository. It applies the richer Advanced Audit Policy
    baseline to the applkr-lab.local Domain Controllers OU and then layers in a few
    additional PowerShell visibility settings that are useful for the lab.

    It is intended to be run from a management workstation with RSAT installed,
    including a workstation that is not domain joined to applkr-lab.local when launched
    with alternate credentials via runas /netonly.

.PARAMETER GPOName
    Name of the advanced audit policy GPO.

.PARAMETER TargetOU
    Distinguished Name of the OU where the GPO should be linked.

.PARAMETER LinkEnabled
    Whether the GPO link should be enabled immediately.

.PARAMETER PowerShellTranscriptPath
    Optional transcript output folder for PowerShell transcription.

.EXAMPLE
    .\Create-APPLKR-AdvancedAudit-GPO.ps1

.EXAMPLE
    .\Create-APPLKR-AdvancedAudit-GPO.ps1 -TargetOU "OU=Domain Controllers,DC=applkr-lab,DC=local"

.NOTES
    Recommended launch method from win11-xdr-lab-1:
    runas /netonly /user:APPLKRLAB\azureadmin powershell.exe
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$GPOName = "APPLKR - DC Advanced Audit Policy",

    [Parameter(Mandatory = $false)]
    [string]$TargetOU = "OU=Domain Controllers,DC=applkr-lab,DC=local",

    [Parameter(Mandatory = $false)]
    [bool]$LinkEnabled = $true,

    [Parameter(Mandatory = $false)]
    [string]$PowerShellTranscriptPath = "C:\PowerShellTranscripts"
)

if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    throw "GroupPolicy module not found. Install RSAT Group Policy Management Tools first."
}

Import-Module GroupPolicy -ErrorAction Stop

$baseScriptPath = Join-Path $PSScriptRoot "..\..\MDE\scripts\Create-MDE-AuditPolicy-GPO.ps1"
$baseScriptPath = [System.IO.Path]::GetFullPath($baseScriptPath)
if (-not (Test-Path $baseScriptPath)) {
    throw "Required script not found: $baseScriptPath"
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "APPLKR Advanced Audit GPO Configuration" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
Write-Host "[*] Applying full advanced audit policy baseline..." -ForegroundColor Yellow

& $baseScriptPath -GPOName $GPOName -TargetOU $TargetOU -LinkEnabled $LinkEnabled
if ($LASTEXITCODE -ne 0) {
    throw "The base audit policy script reported a failure."
}

Write-Host "`n[*] Applying additional APPLKR PowerShell visibility settings..." -ForegroundColor Yellow

Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "EnableTranscripting" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "EnableInvocationHeader" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "OutputDirectory" -Type String -Value $PowerShellTranscriptPath | Out-Null
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Microsoft-Windows-PowerShell/Operational" -ValueName "MaxSize" -Type DWord -Value 131072 | Out-Null

Write-Host "    PowerShell transcription enabled." -ForegroundColor Green
Write-Host "    PowerShell operational log size updated." -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "APPLKR advanced audit policy complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  GPO Name: $GPOName" -ForegroundColor Gray
Write-Host "  Target OU: $TargetOU" -ForegroundColor Gray
Write-Host "  Transcript Path: $PowerShellTranscriptPath" -ForegroundColor Gray
Write-Host "`nNext steps:" -ForegroundColor White
Write-Host "  1. Review the GPO in GPMC." -ForegroundColor Gray
Write-Host "  2. Run gpupdate /force on dc-core." -ForegroundColor Gray
Write-Host "  3. Verify settings with auditpol /get /category:* on dc-core." -ForegroundColor Gray