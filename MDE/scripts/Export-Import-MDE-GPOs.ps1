<#
    Author: DCODEV1702 & Claude Sonnet 4.5
    Date: 14 Nov 2025
    
    .SYNOPSIS
    MDE GPO Backup and Import Script
    
    .DESCRIPTION
    This script provides two functions to backup and import Microsoft Defender for Endpoint (MDE) 
    related Group Policy Objects in an Active Directory environment.
    
    The script handles four specific GPOs:
    WORKSTATIONS:
    - ASR Audit Policy - Workstations
    - MDE Audit Policy - Workstations
    - MDE Exploit Protections Policy - Workstations

    DOMAIN CONTROLLERS:
    - ASR Audit Policy - Domain Controllers
    - MDE Audit Policy - Domain Controllers
    
    
    Backup-MDE-GPOs:
    - Exports GPOs to a specified backup location
    - Displays GUID to GPO name mapping for reference
    - Sets working directory to backup location
    
    Import-MDE-GPOs:
    - Checks for and creates Workstations OU if it doesn't exist
    - Moves any computers from default Computers container to Workstations OU
    - Imports backed up GPOs
    - Links GPOs to appropriate OUs (Domain Controllers or Workstations)
    - Enforces all GPO links to ensure policies are applied
    - Forces Group Policy update on local machine
    
    .PARAMETER BackupPath
    Path where GPO backups will be stored or retrieved from.
    Default: Current directory with '\MDE-GPO-Backup' appended for backup function
    Default: Current directory for import function
    
    .PARAMETER Domain
    Target domain for GPO import operations.
    Default: contoso.local
    
    .EXAMPLE
    # Backup MDE GPOs to default location
    Backup-MDE-GPOs
    
    .EXAMPLE
    # Backup MDE GPOs to custom location
    Backup-MDE-GPOs -BackupPath "C:\GPOBackups\MDE"
    
    .EXAMPLE
    # Import MDE GPOs from current directory
    Import-MDE-GPOs
    
    .EXAMPLE
    # Import MDE GPOs from custom location and domain
    Import-MDE-GPOs -BackupPath "C:\GPOBackups\MDE" -Domain "contoso.local"
    
    .NOTES
    Requirements:
    - RSAT Group Policy Management Tools (GroupPolicy PowerShell module)
    - Active Directory PowerShell module
    - Domain Administrator or equivalent permissions
    - Run from Domain Controller or system with RSAT installed
    
    Install RSAT (Windows 10/11):
    Add-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
    Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
#>

# Import required modules
Import-Module GroupPolicy
Import-Module ActiveDirectory

function Backup-MDE-GPOs {
    param(
        [Parameter(Mandatory=$false)]
        [string]$BackupPath = "$PWD\MDE-GPO-Backup"
    )
    
    # Create backup directory if it doesn't exist
    if (!(Test-Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath | Out-Null
    }
    
    Write-Host "Backing up MDE GPOs to: $BackupPath" -ForegroundColor Cyan
    
    # Back up each GPO for Workstations and Domain Controllers OU
    Backup-GPO -Name "ASR Audit Policy - Workstations" -Path $BackupPath
    Backup-GPO -Name "MDE Audit Policy - Workstations" -Path $BackupPath
    Backup-GPO -Name "MDE Exploit Protections Policy - Workstations" -Path $BackupPath
    Backup-GPO -Name "ASR Audit Policy - Domain Controllers" -Path $BackupPath
    Backup-GPO -Name "MDE Audit Policy - Domain Controllers" -Path $BackupPath
        
    Write-Host "`nBackup complete! GUID Mapping:" -ForegroundColor Green
    
    # Display GUID mapping for reference
    Get-ChildItem $BackupPath -Directory | ForEach-Object {
        $BkupInfoPath = "$($_.FullName)\bkupInfo.xml"
        $BackupXmlPath = "$($_.FullName)\Backup.xml"
        $GPOName = $null
        
        if (Test-Path $BkupInfoPath) {
            [xml]$BkupInfo = Get-Content $BkupInfoPath
            $GPOName = $BkupInfo.BackupInst.GPODisplayName.'#cdata-section'
        } elseif (Test-Path $BackupXmlPath) {
            [xml]$BackupXml = Get-Content $BackupXmlPath
            $GPOName = $BackupXml.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.'#cdata-section'
        }
        
        if ($GPOName) {
            [PSCustomObject]@{
                BackupID = $_.Name
                GPOName  = $GPOName
            }
        }
    } | Format-Table -AutoSize
    
    # List backed up GPO contents
    Get-ChildItem -Path "$BackupPath" | Format-Table Name, LastWriteTime -AutoSize
    
    if (Test-Path "MDE-GPO-Backup") {
        Compress-Archive -Path "MDE-GPO-Backup" -DestinationPath "MDE-GPO-Backup.zip" -Force
        Write-Host "MDE GPO's backed up & compressed successfully!" -ForegroundColor Green
        Get-ChildItem -Path "$PWD\MDE-GPO-Backup.zip" | Format-Table Name, LastWriteTime -AutoSize
        
        # Delete the backup directory after successful compression
        Remove-Item -Path "MDE-GPO-Backup" -Recurse -Force
        Write-Host "MDE GPO Backup directory removed." -ForegroundColor Gray
    } else {
        Write-Host "The ME GPO Backup directory not found. Backup may have failed or was not performed." -ForegroundColor Yellow
    }
}

function Import-MDE-GPOs {
    param(
        [Parameter(Mandatory=$false)]
        [string]$BackupPath = "$PWD",
        
        [Parameter(Mandatory=$false)]
        [string]$Domain = "contoso.local"
    )
    
    # Build DN paths
    $DomainDN = "DC=" + ($Domain -split '\.' -join ',DC=')
    $DCsOU = "OU=Domain Controllers,$DomainDN"
    $WorkstationsOU = "OU=Workstations,$DomainDN"
    $ComputersContainer = "CN=Computers,$DomainDN"
    
    Write-Host "Checking Workstations OU..." -ForegroundColor Cyan
    
    # Check if Workstations OU exists, create if not
    try {
        Get-ADOrganizationalUnit -Identity $WorkstationsOU -ErrorAction Stop | Out-Null
        Write-Host "  Workstations OU exists." -ForegroundColor Green
    } catch {
        Write-Host "  Workstations OU does not exist. Creating..." -ForegroundColor Yellow
        New-ADOrganizationalUnit -Name "Workstations" -Path $DomainDN
        Write-Host "  Workstations OU created." -ForegroundColor Green
    }
    
    Write-Host "`nChecking for computers in Computers container..." -ForegroundColor Cyan
    
    # Check for computers in Computers container and move them
    $Computers = Get-ADComputer -Filter * -SearchBase $ComputersContainer -SearchScope OneLevel
    
    if ($Computers) {
        Write-Host "  Found $($Computers.Count) computer(s) in Computers container. Moving to Workstations OU..." -ForegroundColor Yellow
        
        foreach ($Computer in $Computers) {
            Move-ADObject -Identity $Computer.DistinguishedName -TargetPath $WorkstationsOU
            Write-Host "    Moved: $($Computer.Name)" -ForegroundColor Green
        }
        
        Write-Host "  All computers moved to Workstations OU." -ForegroundColor Green
    } else {
        Write-Host "  No computers found in Computers container." -ForegroundColor Gray
    }
    
    Write-Host "`nImporting GPOs..." -ForegroundColor Cyan
    
    # Import GPOs
    Get-ChildItem $BackupPath -Directory | ForEach-Object {
        $BkupInfoPath = "$($_.FullName)\bkupInfo.xml"
        $BackupXmlPath = "$($_.FullName)\Backup.xml"
        
        # Regenerate bkupInfo.xml if missing
        if ((-not (Test-Path $BkupInfoPath)) -and (Test-Path $BackupXmlPath)) {
            try {
                Write-Host "  Regenerating missing bkupInfo.xml for $($_.Name)..." -ForegroundColor Yellow
                [xml]$BackupXml = Get-Content $BackupXmlPath
                $GpoId = $BackupXml.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.ID.'#cdata-section'
                $GpoDomain = $BackupXml.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.Domain.'#cdata-section'
                $GpoName = $BackupXml.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.'#cdata-section'
                $BackupTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
                
                $NewBkupInfo = @"
<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest">
  <GPOGuid><![CDATA[$GpoId]]></GPOGuid>
  <GPODomain><![CDATA[$GpoDomain]]></GPODomain>
  <GPODomainGuid><![CDATA[{00000000-0000-0000-0000-000000000000}]]></GPODomainGuid>
  <GPODomainController><![CDATA[DC.$GpoDomain]]></GPODomainController>
  <BackupTime><![CDATA[$BackupTime]]></BackupTime>
  <ID><![CDATA[$($_.Name)]]></ID>
  <Comment><![CDATA[$GpoName]]></Comment>
  <GPODisplayName><![CDATA[$GpoName]]></GPODisplayName>
</BackupInst>
"@
                $NewBkupInfo | Set-Content -Path $BkupInfoPath
            } catch {
                Write-Warning "Failed to regenerate bkupInfo.xml: $_"
            }
        }
        
        $GPOName = $null
        $BackupId = $_.Name
        
        if (Test-Path $BkupInfoPath) {
            [xml]$BkupInfo = Get-Content $BkupInfoPath
            $GPOName  = $BkupInfo.BackupInst.GPODisplayName.'#cdata-section'
        }
        
        if ($GPOName) {
            Write-Host "`nProcessing: $GPOName" -ForegroundColor Yellow
            
            # Determine target OU
            if ($GPOName -like "*Domain Controllers*") {
                $TargetOU = $DCsOU
                Write-Host "  Target OU: Domain Controllers" -ForegroundColor Gray
            } else {
                $TargetOU = $WorkstationsOU
                Write-Host "  Target OU: Workstations" -ForegroundColor Gray
            }
            
            # Import GPO
            Import-GPO -BackupId $BackupId -TargetName $GPOName -Path $BackupPath -CreateIfNeeded
            Write-Host "  GPO imported." -ForegroundColor Green
            
            # Link and enforce GPO with improved error handling
            try {
                $ExistingLink = Get-GPInheritance -Target $TargetOU |
                     Select-Object -ExpandProperty GpoLinks |
                     Where-Object { $_.DisplayName -eq $GPOName }
                
                if ($ExistingLink) {
                    Write-Host "  GPO already linked to $TargetOU" -ForegroundColor Yellow
                } else {
                    New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled Yes -Enforced Yes -ErrorAction Stop
                    Write-Host "  Linked and enforced to $TargetOU" -ForegroundColor Green
                }
            } catch {
                Write-Host "  ERROR: Failed to link GPO to $TargetOU" -ForegroundColor Red
                Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Warning "Skipping folder $($_.Name): Neither bkupInfo.xml nor Backup.xml found."
        }
    }
    
    Write-Host "`nAll GPOs imported!" -ForegroundColor Green
    Write-Host "`nForcing Group Policy update..." -ForegroundColor Cyan
    
    # Force Group Policy update
    try {
        gpupdate /force
        Write-Host "`nGroup Policy update completed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "`nWARNING: gpupdate failed. You may need to run 'gpupdate /force' manually." -ForegroundColor Yellow
    }
}

# Usage Examples:
# Backup-MDE-GPOs
Import-MDE-GPOs -BackupPath "$PWD\MDE-GPO-Backup"
