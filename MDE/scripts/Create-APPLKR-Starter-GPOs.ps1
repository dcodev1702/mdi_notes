#Requires -Modules GroupPolicy, ActiveDirectory

<#!
.SYNOPSIS
    Creates three starter GPOs for the APPLKR lab domain controllers OU.

.DESCRIPTION
    This script creates or updates three starter GPOs for the applkr-lab.local lab:

    1. Audit policy baseline
    2. PowerShell logging baseline
    3. Admin access baseline

    The script is intended to be run from a management host with RSAT installed,
    including a host that is not joined to applkr-lab.local when launched with
    alternate credentials via runas /netonly.

    The script focuses on registry-backed settings that are safe and useful for
    a first-pass domain controller lab baseline.

.PARAMETER GpoPrefix
    Prefix used for the created GPO names.

.PARAMETER TargetOU
    Distinguished Name of the OU where the GPOs should be linked.

.PARAMETER PowerShellTranscriptPath
    Output folder configured for PowerShell transcription.

.PARAMETER Enforced
    Enables enforced links for the created GPOs.

.EXAMPLE
    .\Create-APPLKR-Starter-GPOs.ps1

.EXAMPLE
    .\Create-APPLKR-Starter-GPOs.ps1 -TargetOU "OU=Domain Controllers,DC=applkr-lab,DC=local"

.NOTES
    Run from a PowerShell session launched with APPLKRLAB credentials when using a
    workstation that is not joined to applkr-lab.local.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$GpoPrefix = "APPLKR",

    [Parameter(Mandatory = $false)]
    [string]$TargetOU = "OU=Domain Controllers,DC=applkr-lab,DC=local",

    [Parameter(Mandatory = $false)]
    [string]$PowerShellTranscriptPath = "C:\PowerShellTranscripts",

    [Parameter(Mandatory = $false)]
    [switch]$Enforced
)

function Assert-RequiredModule {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "Required module '$Name' is not available. Install the corresponding RSAT feature first."
    }

    Import-Module $Name -ErrorAction Stop
}

function Initialize-Gpo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Comment,

        [Parameter(Mandatory = $true)]
        [string]$LinkTarget,

        [Parameter(Mandatory = $true)]
        [bool]$LinkEnforced
    )

    $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if (-not $gpo) {
        Write-Host "[+] Creating GPO: $Name" -ForegroundColor Green
        $gpo = New-GPO -Name $Name -Comment $Comment -ErrorAction Stop
    } else {
        Write-Host "[*] Reusing existing GPO: $Name" -ForegroundColor Yellow
    }

    $inheritance = Get-GPInheritance -Target $LinkTarget -ErrorAction Stop
    $existingLink = $inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $Name }
    if (-not $existingLink) {
        Write-Host "    Linking GPO to $LinkTarget" -ForegroundColor Cyan
        New-GPLink -Name $Name -Target $LinkTarget -LinkEnabled Yes -Enforced:([bool]$LinkEnforced) | Out-Null
    } else {
        Write-Host "    GPO link already exists." -ForegroundColor DarkYellow
        Set-GPLink -Name $Name -Target $LinkTarget -LinkEnabled Yes -Enforced:([bool]$LinkEnforced) | Out-Null
    }

    return $gpo
}

function Set-DwordPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GpoName,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [string]$ValueName,

        [Parameter(Mandatory = $true)]
        [int]$Value
    )

    Set-GPRegistryValue -Name $GpoName -Key $Key -ValueName $ValueName -Type DWord -Value $Value | Out-Null
}

function Set-StringPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GpoName,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [string]$ValueName,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    Set-GPRegistryValue -Name $GpoName -Key $Key -ValueName $ValueName -Type String -Value $Value | Out-Null
}

try {
    Assert-RequiredModule -Name GroupPolicy
    Assert-RequiredModule -Name ActiveDirectory

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "APPLKR Starter GPO Configuration" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $domain = Get-ADDomain -ErrorAction Stop
    Write-Host "[*] Connected to domain: $($domain.DNSRoot)" -ForegroundColor Cyan
    Write-Host "[*] Target OU: $TargetOU" -ForegroundColor Cyan

    $auditGpoName = "$GpoPrefix - DC Audit Policy"
    $loggingGpoName = "$GpoPrefix - DC PowerShell Logging"
    $adminGpoName = "$GpoPrefix - DC Admin Access"

    $null = Initialize-Gpo -Name $auditGpoName -Comment "Starter DC audit and event log baseline for the APPLKR lab." -LinkTarget $TargetOU -LinkEnforced $Enforced.IsPresent
    $null = Initialize-Gpo -Name $loggingGpoName -Comment "Starter PowerShell visibility baseline for the APPLKR lab." -LinkTarget $TargetOU -LinkEnforced $Enforced.IsPresent
    $null = Initialize-Gpo -Name $adminGpoName -Comment "Starter admin access baseline for the APPLKR lab." -LinkTarget $TargetOU -LinkEnforced $Enforced.IsPresent

    Write-Host "`n[*] Configuring audit starter settings..." -ForegroundColor Yellow
    Set-DwordPolicy -GpoName $auditGpoName -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "SCENoApplyLegacyAuditPolicy" -Value 1
    Set-DwordPolicy -GpoName $auditGpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Value 1
    Set-DwordPolicy -GpoName $auditGpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName "MaxSize" -Value 1048576
    Set-DwordPolicy -GpoName $auditGpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -ValueName "MaxSize" -Value 262144
    Set-DwordPolicy -GpoName $auditGpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -ValueName "MaxSize" -Value 262144

    Write-Host "[*] Configuring PowerShell logging starter settings..." -ForegroundColor Yellow
    Set-DwordPolicy -GpoName $loggingGpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -Value 1
    Set-DwordPolicy -GpoName $loggingGpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ValueName "EnableModuleLogging" -Value 1
    Set-StringPolicy -GpoName $loggingGpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ValueName "*" -Value "*"
    Set-DwordPolicy -GpoName $loggingGpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "EnableTranscripting" -Value 1
    Set-DwordPolicy -GpoName $loggingGpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "EnableInvocationHeader" -Value 1
    Set-StringPolicy -GpoName $loggingGpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "OutputDirectory" -Value $PowerShellTranscriptPath

    Write-Host "[*] Configuring admin access starter settings..." -ForegroundColor Yellow
    Set-DwordPolicy -GpoName $adminGpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fDenyTSConnections" -Value 0
    Set-DwordPolicy -GpoName $adminGpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableFirstLogonAnimation" -Value 0
    Set-DwordPolicy -GpoName $adminGpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Microsoft-Windows-PowerShell/Operational" -ValueName "MaxSize" -Value 131072

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Starter GPO configuration complete" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  $auditGpoName" -ForegroundColor Gray
    Write-Host "  $loggingGpoName" -ForegroundColor Gray
    Write-Host "  $adminGpoName" -ForegroundColor Gray
    Write-Host "`nNext steps:" -ForegroundColor White
    Write-Host "  1. Review the GPOs in GPMC." -ForegroundColor Gray
    Write-Host "  2. Run gpupdate /force on dc-core." -ForegroundColor Gray
    Write-Host "  3. Add full Advanced Audit Policy subcategories later if you want deeper DC telemetry." -ForegroundColor Gray
}
catch {
    Write-Error $_
    exit 1
}