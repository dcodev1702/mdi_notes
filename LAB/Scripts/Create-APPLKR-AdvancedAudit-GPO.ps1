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

function Update-AuditPolicyCsv {
    param(
        [Parameter(Mandatory = $true)]
        [Guid]$GpoId,

        [Parameter(Mandatory = $true)]
        [array]$RequiredRows
    )

    $auditCsvPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$GpoId}\Machine\Microsoft\Windows NT\Audit\audit.csv"
    if (-not (Test-Path $auditCsvPath)) {
        throw "Expected audit.csv was not found at: $auditCsvPath"
    }

    $existingRows = @(Import-Csv -Path $auditCsvPath)
    foreach ($requiredRow in $RequiredRows) {
        $matchingRows = @($existingRows | Where-Object { $_.Subcategory -eq $requiredRow.Subcategory })
        if ($matchingRows.Count -eq 0) {
            $existingRows += [pscustomobject]@{
                'Machine Name' = ''
                'Policy Target' = $requiredRow.PolicyTarget
                'Subcategory' = $requiredRow.Subcategory
                'Subcategory GUID' = $requiredRow.SubcategoryGuid
                'Inclusion Setting' = ''
                'Exclusion Setting' = ''
                'Setting Value' = $requiredRow.SettingValue
            }
            continue
        }

        foreach ($matchingRow in $matchingRows) {
            $matchingRow.'Machine Name' = ''
            $matchingRow.'Policy Target' = $requiredRow.PolicyTarget
            $matchingRow.'Subcategory' = $requiredRow.Subcategory
            $matchingRow.'Subcategory GUID' = $requiredRow.SubcategoryGuid
            $matchingRow.'Inclusion Setting' = ''
            $matchingRow.'Exclusion Setting' = ''
            $matchingRow.'Setting Value' = $requiredRow.SettingValue
        }
    }

    $existingRows |
        Sort-Object 'Policy Target', 'Subcategory' |
        Export-Csv -Path $auditCsvPath -NoTypeInformation -Encoding Ascii
}

function Increment-GpoComputerVersion {
    param(
        [Parameter(Mandatory = $true)]
        [Guid]$GpoId
    )

    $gptIniPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$GpoId}\GPT.INI"
    if (-not (Test-Path $gptIniPath)) {
        return
    }

    $gptContent = Get-Content -Path $gptIniPath
    $versionLine = $gptContent | Where-Object { $_ -match '^Version=' }
    if ($versionLine -notmatch 'Version=(\d+)') {
        return
    }

    $currentVersion = [int]$matches[1]
    $newVersion = $currentVersion + 65536
    $gptContent = $gptContent -replace 'Version=\d+', "Version=$newVersion"
    Set-Content -Path $gptIniPath -Value $gptContent -Encoding Ascii
}

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

$gpo = Get-GPO -Name $GPOName -ErrorAction Stop

Write-Host "`n[*] Merging Microsoft Defender for Identity audit subcategories..." -ForegroundColor Yellow

$mdiAuditRows = @(
    @{ PolicyTarget = 'Account Logon';      Subcategory = 'Credential Validation';          SubcategoryGuid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; SettingValue = '3' },
    @{ PolicyTarget = 'Account Management'; Subcategory = 'Computer Account Management';    SubcategoryGuid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; SettingValue = '3' },
    @{ PolicyTarget = 'Account Management'; Subcategory = 'Distribution Group Management';  SubcategoryGuid = '{0CCE9238-69AE-11D9-BED3-505054503030}'; SettingValue = '3' },
    @{ PolicyTarget = 'Account Management'; Subcategory = 'Security Group Management';      SubcategoryGuid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; SettingValue = '3' },
    @{ PolicyTarget = 'Account Management'; Subcategory = 'User Account Management';        SubcategoryGuid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; SettingValue = '3' },
    @{ PolicyTarget = 'DS Access';          Subcategory = 'Directory Service Access';       SubcategoryGuid = '{0CCE923B-69AE-11D9-BED3-505054503030}'; SettingValue = '3' },
    @{ PolicyTarget = 'DS Access';          Subcategory = 'Directory Service Changes';      SubcategoryGuid = '{0CCE923C-69AE-11D9-BED3-505054503030}'; SettingValue = '3' },
    @{ PolicyTarget = 'Logon/Logoff';       Subcategory = 'Logoff';                         SubcategoryGuid = '{46354FC9-6F84-4572-8F95-DEA476CBA9FF}'; SettingValue = '1' },
    @{ PolicyTarget = 'System';             Subcategory = 'Security System Extension';      SubcategoryGuid = '{6997984B-797A-11D2-8410-006008C0E1D0}'; SettingValue = '3' }
)

Update-AuditPolicyCsv -GpoId $gpo.Id -RequiredRows $mdiAuditRows
Increment-GpoComputerVersion -GpoId $gpo.Id
Write-Host "    MDI audit.csv entries updated." -ForegroundColor Green

Write-Host "`n[*] Removing obsolete legacy LDAP diagnostic settings (1644 guidance)..." -ForegroundColor Yellow

Remove-GPRegistryValue -Name $GPOName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ValueName '15 Field Engineering' -ErrorAction SilentlyContinue | Out-Null
Remove-GPRegistryValue -Name $GPOName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ValueName 'Expensive Search Results Threshold' -ErrorAction SilentlyContinue | Out-Null
Remove-GPRegistryValue -Name $GPOName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ValueName 'Inefficient Search Results Threshold' -ErrorAction SilentlyContinue | Out-Null
Remove-GPRegistryValue -Name $GPOName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ValueName 'Search Time Threshold (msecs)' -ErrorAction SilentlyContinue | Out-Null

Write-Host "    Legacy 1644-related registry settings removed from the GPO if present." -ForegroundColor Green

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
Write-Host "  MDI audit policies merged: Yes" -ForegroundColor Gray
Write-Host "`nNext steps:" -ForegroundColor White
Write-Host "  1. Review the GPO in GPMC." -ForegroundColor Gray
Write-Host "  2. Configure the MDI domain-object SACL on applkr-lab.local so 4662 events are emitted for user, group, and computer objects." -ForegroundColor Gray
Write-Host "  3. Configure the MDI NTLM auditing security options on domain controllers: Outgoing NTLM traffic to remote servers = Audit all, Audit NTLM authentication in this domain = Enable all, Audit Incoming NTLM Traffic = Enable auditing for all accounts." -ForegroundColor Gray
Write-Host "  4. Run gpupdate /force on dc-core." -ForegroundColor Gray
Write-Host "  5. Verify settings with auditpol /get /category:* on dc-core." -ForegroundColor Gray