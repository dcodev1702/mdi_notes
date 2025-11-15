# 🛡️ Microsoft Defender XDR - Workshop Enhancement Guide

## 📋 Workshop Information

**Learning Portal:** https://mslearningcampus.com/User/Login  
**Student Key:** `[Your Key Here]`

---

<details>
<summary><b>📋 Prerequisites and Assumptions</b></summary>

<br>

This workshop assumes you have the following environment and access already configured:

### Microsoft Cloud Environment

**Required Licenses and Access:**
- ✅ **Microsoft Entra ID** (formerly Azure AD) tenant with administrative access
- ✅ **Microsoft Defender XDR** suite with the following workloads enabled:
  - **Microsoft Defender for Endpoint (MDE)** - P2 License
  - **Microsoft Defender for Office 365 (MDO)** - P2 License
  - **Microsoft Defender for Identity (MDI)**
  - **Microsoft Defender for Cloud Apps (MDCA)**
  - **Microsoft Entra ID Protection**
- ✅ **Global Administrator** permissions to the tenant (required for configuration)

**Portal Access:**
- Microsoft Defender XDR Portal: https://security.microsoft.com
- Microsoft Entra Admin Center: https://entra.microsoft.com
- Microsoft Intune Admin Center: https://intune.microsoft.com (optional, for endpoint management)

### Lab Infrastructure

**Minimum Requirements:**

1. **Domain Controller (DC):**
   - Windows Server 2019 or 2022
   - Active Directory Domain Services configured
   - Domain: `contoso.local` (or your preferred domain)
   - Onboarded to Microsoft Defender for Endpoint
   - Network connectivity to the internet and client systems

2. **Windows 11 Client (CLIENT01):**
   - Windows 11 Pro or Enterprise (22H2 or later recommended)
   - Domain-joined to `contoso.local`
   - Microsoft Defender Antivirus platform, engine, and signatures **up to date**
   - Onboarded to Microsoft Defender for Endpoint
   - **Status:** Vanilla state (no prior MDE configurations applied)

3. **Network Configuration:**
   - Domain Controller and Client on the same subnet (or routable)
   - Outbound internet connectivity for cloud services
   - Microsoft Defender for Endpoint connectivity verified
   - DNS resolution for `contoso.local` and internet domains

### Deployment Resources

**Need to Build a Lab Environment?**

If you need to provision your lab infrastructure from scratch, consider using the **Open Threat Research Forge (OTRF) Blacksmith** project:

🔗 **MSFT Sentinel-2-Go:** https://github.com/OTRF/Microsoft-Sentinel2Go

🔗 **OTRF Blacksmith:** https://github.com/OTRF/Blacksmith

Blacksmith provides automated deployment templates for:
- Windows Server Domain Controllers
- Windows 11 clients
- Active Directory environments
- Pre-configured logging and detection scenarios
- Integration with cloud security tools

**Alternative Options:**
- Microsoft Evaluation Center: https://www.microsoft.com/en-us/evalcenter/
- Azure Virtual Machines with pre-configured templates
- Hyper-V or VMware local lab deployments

### Pre-Workshop Validation

Before starting this workshop, verify the following:

```powershell
# On CLIENT01 - Verify MDE onboarding status
Get-MpComputerStatus | Select-Object AMProductVersion, AMRunningMode, RealTimeProtectionEnabled

# Check if device appears in Defender XDR portal
# Navigate to: https://security.microsoft.com → Assets → Devices
```

**Expected State:**
- ✅ Devices appear in Microsoft Defender XDR portal
- ✅ Microsoft Defender Antivirus in **Active Mode** (not Passive or Disabled)
- ✅ **Real-time Protection** is enabled
- ✅ No existing ASR, Exploit Protection, or Network Protection configurations
- ✅ Cloud-delivered protection enabled

**Update Microsoft Defender Antivirus Platform:**

Ensure your MDAV platform is up to date before starting:

```powershell
# Check current platform version
Get-MpComputerStatus | Select-Object AMProductVersion

# Update MDAV platform via Windows Update
Update-MpSignature
```

**Manual Platform Update (if needed):**

If `Update-MpSignature` doesn't update the platform to the target version, use the automated update script:

```powershell
# Download and execute the MDAV Platform update script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dcodev1702/mdi_notes/refs/heads/main/MDE/scripts/Update-MDAV-Platform.ps1" -OutFile "$env:TEMP\Update-MDAV-Platform.ps1"
Unblock-File -Path "$env:TEMP\Update-MDAV-Platform.ps1"
& "$env:TEMP\Update-MDAV-Platform.ps1"
```

> **💡 Alternative:** Manually download from [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/Search.aspx?q=KB4052623)

**Windows 11 (Client) Target Version:** 4.18.25100.9006 or higher
<img width="865" height="473" alt="image" src="https://github.com/user-attachments/assets/dbf5f299-18be-4125-a6e7-4a8b65f58651" />

---

### What This Workshop Will Configure

This guide will take your vanilla MDE environment and configure:
- Attack Surface Reduction (ASR) rules in audit mode
- Exploit Protection settings across common applications
- Network Protection in audit mode
- Enhanced audit logging for security events
- Advanced threat protection features
- Group Policy Objects for centralized management

### Important Notes

> **⚠️ Workshop Environment Only**  
> This workshop is designed for **LAB and TRAINING environments**. Always test configurations in non-production environments before deploying to production systems.

> **💡 Production Deployment Considerations**  
> When moving to production, follow Microsoft's phased deployment approach:
> 1. Enable audit mode for 30+ days
> 2. Analyze telemetry and identify false positives
> 3. Create necessary exclusions
> 4. Pilot with a small user group
> 5. Gradually roll out to production

> **🔐 Administrative Access**  
> You will need Domain Administrator or equivalent permissions to create and link Group Policy Objects throughout this workshop.

</details>

---

## 🎯 Lab Enhancements Overview

This guide covers the comprehensive enhancements made to the Microsoft Defender for Endpoint (MDE) lab environment:

- ✅ Updated MDE Platform on CLIENT01
- ✅ Updated applications (Firefox, PowerShell, Edge) for Threat & Vulnerability Management
- ✅ Installed RSAT tools on Windows 11
- ✅ Configured ASR rules in Audit Mode
- ✅ Configured Exploit Guard in Audit Mode
- ✅ Configured Network Protection in Audit Mode
- ✅ Enhanced audit logging with comprehensive policies (40+ audit subcategories)
- ✅ Increased Security Event Log size from 20MB to 1GB (1,048,576 KB)
- ✅ Restricted Security Event Log access to System and Administrator accounts only
- ✅ Enabled PowerShell Script Block Logging and Module Logging
- ✅ Enabled Process Creation command line logging (Event ID 4688)
- ✅ Enabled advanced protection features (BAF, Cloud Protection, etc.)

---

## 🔧 Initial Setup (Windows 11 - Client VM)


### 1. Install RSAT Tools for Windows 11

Install all Remote Server Administration Tools:

```powershell
# Open a PS Shell as Administrator
# Install all RSAT capabilities
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
```

Verify installation:

```powershell
# Validate RSAT tools are installed
Get-WindowsCapability -Name RSAT* -Online | Where-Object {$_.State -eq "Installed"}
```

Import Active Directory module:

```powershell
# Import required modules
Import-Module GroupPolicy
Import-Module ActiveDirectory
```

---

## 📂 Active Directory Structure

The import script will automatically handle the following AD configuration tasks:

- **Creates Workstations OU** if it doesn't already exist at `OU=Workstations,DC=contoso,DC=local`
- **Moves computers** from the default `CN=Computers` container to the Workstations OU
- **Imports & Links Four MDE GPOs** to appropriate OUs (Domain Controllers or Workstations)
- **Enforces GPO links** to ensure policies are applied correctly

This automated approach ensures consistent AD structure across lab environments and simplifies the deployment process.

---

<details>
<summary><b>🖥️ Domain Controller Preparation (Complete BEFORE Importing GPOs)</b></summary>

<br>

> **⚠️ IMPORTANT:** Complete these steps on your **Domain Controller** BEFORE importing GPOs from the Windows 11 client.

The Exploit Protection GPO requires an XML configuration file that must be accessible via a network share. This section prepares your Domain Controller with the necessary files and share configuration.

---

### Step 1: Download Exploit Protection Configuration

On your **Domain Controller**, download the ExploitProtectionLite.xml file from GitHub:

```powershell
# Download ExploitProtectionLite.xml from GitHub
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dcodev1702/mdi_notes/main/MDE/GPOs/ExploitProtectionLite.xml" -OutFile "$env:USERPROFILE\Downloads\ExploitProtectionLite.xml"
```

**Verify download:**

```powershell
# Check if file was downloaded
Get-Item "$env:USERPROFILE\Downloads\ExploitProtectionLite.xml"
```

---

### Step 2: Remove Mark-of-the-Web

Remove the security zone identifier to prevent execution warnings:

```powershell
# Remove mark-of-the-web
Unblock-File -Path "$env:USERPROFILE\Downloads\ExploitProtectionLite.xml"
```

**Verify unblocking:**

```powershell
# Check if file is unblocked (should show no alternate data streams)
Get-Item "$env:USERPROFILE\Downloads\ExploitProtectionLite.xml" -Stream *
```

---

### Step 3: Create SMB Share for GPO Configuration

Create the shared folder that will be used by the Exploit Protection GPO:

```powershell
# Create GPO-Configs directory
New-Item -Path "C:\GPO-Configs" -ItemType Directory -Force

# Create SMB share with read access for Domain Computers
New-SmbShare -Name "GPO-Configs" -Path "C:\GPO-Configs" -ReadAccess "Domain Computers"

# Copy ExploitProtectionLite.xml to share
Copy-Item "$env:USERPROFILE\Downloads\ExploitProtectionLite.xml" -Destination "C:\GPO-Configs\"
```

---

### Step 4: Verify Share Configuration

```powershell
# Verify SMB share was created
Get-SmbShare -Name "GPO-Configs"

# View share permissions
Get-SmbShareAccess -Name "GPO-Configs"

# Verify file exists in local directory
Get-ChildItem "C:\GPO-Configs"
```

**Expected Output:**

```
Name         ScopeName Path           Description
----         --------- ----           -----------
GPO-Configs  *         C:\GPO-Configs


Name        ScopeName AccountName          AccessControlType AccessRight
----        --------- -----------          ----------------- -----------
GPO-Configs *         CONTOSO\Domain Co... Allow             Read


    Directory: C:\GPO-Configs


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/14/2025   2:30 PM          12345 ExploitProtectionLite.xml
```

---

### Step 5: Verify Configuration

Verify the file was copied successfully and display the UNC path for GPO configuration:

```powershell
# Verify file exists locally
$LocalPath = "C:\GPO-Configs\ExploitProtectionLite.xml"

if (Test-Path $LocalPath) {
    Write-Host "`nFile successfully copied to share location!" -ForegroundColor Green
    Write-Host "Local Path: $LocalPath" -ForegroundColor Cyan
    
    # Display the UNC path for GPO configuration
    $UNCPath = "$env:LOGONSERVER\GPO-Configs\ExploitProtectionLite.xml"
    Write-Host "`nUNC Path for GPO configuration:" -ForegroundColor Cyan
    Write-Host $UNCPath -ForegroundColor Green
    Write-Host "`nNote: Domain-joined computers will be able to access this path." -ForegroundColor Yellow
    Write-Host "User accounts (including Administrator) cannot access this share - this is expected!" -ForegroundColor Yellow
} else {
    Write-Host "`nERROR: File not found at $LocalPath" -ForegroundColor Red
}
```

> **📝 Important Notes:**
> - The share is configured for **Domain Computers only** - user accounts cannot access it
> - Testing the UNC path as Administrator will fail with "Access Denied" - **this is expected and correct**
> - Domain-joined computers will be able to access the file when the GPO applies
> - The actual verification happens when GPO processes and computers retrieve the XML file

**Save this UNC path** - you'll need it when configuring the Exploit Protection GPO settings later.

---

### What's Next?

After completing these Domain Controller preparation steps:

1. ✅ **Proceed to the Windows 11 client** to import the MDE GPOs
2. ✅ **After GPO import**, you'll configure the Exploit Protection GPO to use the UNC path: `\\<DC-HOSTNAME>\GPO-Configs\ExploitProtectionLite.xml`

The GPO configuration will be completed in the **Configure Exploit Protection GPO Settings** section below.

---

</details>

---

## 📥 Import MDE Group Policy Objects

### Prerequisites

Ensure you have:
- ✅ **Completed Domain Controller preparation** (see collapsible section above)
- ✅ RSAT tools installed (from step 1 above)
- ✅ Domain Administrator privileges

### Automated GPO Import

Follow these steps to automatically download, extract, and import all MDE GPOs:

**Step 1:** Create a temporary working directory

```powershell
$TempPath = "$env:TEMP\MDE-GPO-Import"
New-Item -Path $TempPath -ItemType Directory -Force | Out-Null
```

**Step 2:** Download the MDE GPO backup archive from GitHub

```powershell
Invoke-WebRequest -Uri "https://github.com/dcodev1702/mdi_notes/raw/main/MDE/GPOs/MDE-GPO-Backup.zip" -OutFile "$TempPath\MDE-GPO-Backup.zip"
Unblock-File -Path "$TempPath\MDE-GPO-Backup.zip"
```

**Step 3:** Extract the GPO backup archive

```powershell
Expand-Archive -Path "$TempPath\MDE-GPO-Backup.zip" -DestinationPath $TempPath -Force
```

**Step 4:** Download the GPO import script

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dcodev1702/mdi_notes/refs/heads/main/MDE/scripts/Export-Import-MDE-GPOs.ps1" -OutFile "$TempPath\Export-Import-MDE-GPOs.ps1"
Unblock-File -Path "$TempPath\Export-Import-MDE-GPOs.ps1"
```

**Step 5:** Execute the import script with the backup path

```powershell
& "$TempPath\Export-Import-MDE-GPOs.ps1" -BackupPath "$TempPath\MDE-GPO-Backup"
```

### What This Does:

1. **Creates temp directory** - `$env:TEMP\MDE-GPO-Import`
2. **Downloads MDE-GPO-Backup.zip** from GitHub and removes Mark-of-the-Web
3. **Extracts the archive** to the temp directory
4. **Downloads Export-Import-MDE-GPOs.ps1** script and removes Mark-of-the-Web
5. **Executes the script** with the correct `-BackupPath` parameter pointing to the extracted GPOs

The PowerShell script will automatically perform the following tasks:
- ✅ Create the Workstations OU (if needed)
- ✅ Move computers from Computers container to Workstations OU
- ✅ Import all four MDE GPOs
- ✅ Link GPOs to appropriate OUs
- ✅ Enforce all GPO links

### Benefits:

✅ **Step-by-step execution** - Clear progress through each stage  
✅ **Individual copy buttons** - Easy to copy and paste each command  
✅ **No file management** - Everything handled automatically  
✅ **Clean workspace** - Uses temp directory (can be deleted after import)  
✅ **Consistent workflow** - Same pattern as MDAV Platform update

### Verify GPO Import

**Check GPO links:**

```powershell
# List GPOs linked to Workstations OU
Get-GPInheritance -Target "OU=Workstations,DC=contoso,DC=local"

# List GPOs linked to Domain Controllers OU
Get-GPInheritance -Target "OU=Domain Controllers,DC=contoso,DC=local"
```

**Force GPO update on client computers:**

```powershell
gpupdate /force
```

**Verify imported settings:**
<img width="1147" height="803" alt="image" src="https://github.com/user-attachments/assets/cacfc95f-3e92-416f-a33e-a26520164d6f" />

```powershell
# Check audit policy
auditpol /get /category:*

# Check ASR rules
Get-MpPreference | Select-Object AttackSurfaceReductionRules_*

# Check Exploit Protection
Get-ProcessMitigation -RegistryConfigFilePath
```

---

<details>
<summary><b>🔧 MDE Audit Policy Configuration</b></summary>

<br>

The **MDE Audit Policy GPO** (`MDE-Audit-Policy-Workstations` and `MDE-Audit-Policy-Domain-Controllers`) enforces security logging best practices aligned with MDE requirements, NIST guidelines, and CIS benchmarks to maximize endpoint detection and response capabilities.

---

### 📊 Audit Policy Configuration

**Comprehensive Event Coverage:**
- Configures **40+ audit subcategories** across **7 major categories**:
  - **Account Logon** - Credential validation, Kerberos authentication
  - **Account Management** - User, computer, and group management
  - **Detailed Tracking** - Process creation, termination, DPAPI activity, PnP events
  - **Logon/Logoff** - Interactive logons, network logons, special logons
  - **Object Access** - File system, registry, SAM, network shares
  - **Policy Change** - Audit policy, authentication policy, firewall policy
  - **Privilege Use** - Sensitive privilege usage
  - **System** - Security state changes, system integrity events

**Technical Implementation:**
- Generates audit policy CSV and deploys it to SYSVOL for GPO enforcement
- Automatically increments GPO version to trigger policy refresh
- Ensures consistent audit configuration across all domain-joined systems

---

### 📝 PowerShell Logging

**Script Execution Visibility:**
- **PowerShell Script Block Logging** - Captures detailed script execution for malicious script detection
- **PowerShell Module Logging** - Tracks PowerShell module usage across the environment
- **Detection Capability** - Enables identification of obfuscated commands, fileless malware, and living-off-the-land attacks

---

### 🔍 Process Monitoring

**Command Line Auditing:**
- **Enables Event ID 4688** - Process creation events with full command line arguments
- **Parent-Child Relationships** - Tracks process trees for attack chain analysis
- **Critical for EDR** - Provides visibility into process execution patterns and lateral movement
- **Advanced Hunting** - Supports Microsoft Defender XDR queries for threat hunting

---

### 📋 Security Event Log Optimization

The **MDE Audit Policy GPO** implements critical Security Event Log optimizations for comprehensive EDR visibility:

**Security Event Log Size:**
- **Default Windows Configuration:** 20 MB (inadequate for security monitoring)
- **MDE Configuration:** 1,048,576 KB (1 GB)
- **Benefit:** Provides extended log retention for forensic analysis and threat hunting
- **Recommendation:** With comprehensive audit policies enabled, 1GB allows approximately 7-14 days of retention depending on activity levels

**Security Event Log Access Control:**
- **ChannelAccess:** Disabled (restricts log access to System and Administrator accounts only)
- **ChannelAccessLegacy:** Disabled (restricts legacy log access to System and Administrator accounts only)
- **Security Boundary:** Prevents unauthorized users and applications from reading sensitive security events
- **Compliance:** Aligns with CIS benchmarks and NIST guidelines for security log protection

**Why These Settings Matter:**

*Increased Log Size (1GB):*
- Default 20MB logs fill rapidly with comprehensive audit policies
- Inadequate retention leads to critical security events being overwritten
- 1GB provides sufficient buffer for incident response and forensic investigations
- Supports Microsoft Defender for Endpoint's Advanced Hunting queries with historical data

*Restricted Log Access:*
- Security Event Log contains sensitive information (authentication events, privilege use, process creation with command lines)
- Limiting access to System and Administrators prevents information disclosure
- Reduces attack surface by preventing malware from reading security events
- Ensures only privileged accounts can access security telemetry

---

### 🚀 GPO Deployment

**Automated Configuration:**
- Creates new GPO or updates existing GPO with specified name
- Links GPO to specified Organizational Unit (Domain Controllers or Workstations)
- Configurable enabled/disabled state for controlled rollout
- Generates HTML report of complete GPO configuration for documentation

**Deployment Flexibility:**
- Supports both Domain Controllers and Workstations with separate GPOs
- Enforced GPO links ensure policy cannot be overridden
- Automatic GPO refresh triggers immediate application

---

### ✅ Verify Security Event Log Configuration

After GPO application, verify the Security Event Log settings:

```powershell
# Check Security Event Log maximum size (should be 1048576 KB = 1 GB)
$LogConfig = Get-WinEvent -ListLog Security
Write-Host "Security Log Maximum Size: $($LogConfig.MaximumSizeInBytes / 1MB) MB" -ForegroundColor Cyan
```

**Expected Configuration:**
- ✅ Maximum Size: 1024 MB (1 GB)
- ✅ Log Access: System and Administrator only
- ✅ Retention: Overwrite as needed (circular logging)

---

### ⚠️ Important Notes

> **⚠️ Monitor Log Growth**  
> With comprehensive audit policies enabled, Security Event Logs will grow significantly faster than default configurations. The 1GB size provides adequate retention, but high-activity environments may require monitoring.

> **💡 Log Collection Recommendation**  
> For long-term retention and centralized analysis, configure log forwarding to:
> - Microsoft Sentinel (recommended for MDE integration)
> - Windows Event Forwarding (WEF) to a log collector
> - Third-party SIEM solutions

> **🔐 Access Control Impact**  
> After ChannelAccess restrictions are applied:
> - Standard users cannot read Security Event Log
> - Non-administrative applications cannot access security events
> - Only System and Administrator accounts can query the Security log
> - This is **expected behavior** and enhances security posture

</details>

---

<details>
<summary><b>⚙️ Configure Exploit Protection GPO Settings</b></summary>

<br>

After importing the GPOs, you must configure the **Exploit-Protections-Workstations** GPO to point to the XML configuration file on the Domain Controller.

---

### Open Group Policy Management

On your **Domain Controller** or **Windows 11 client** with RSAT installed:

```powershell
# Open Group Policy Management Console
gpmc.msc
```

---

### Navigate to Exploit Protection Settings

**Path in Group Policy Management Editor:**

```
Computer Configuration
  └── Policies
      └── Administrative Templates
          └── Windows Components
              └── Windows Defender Exploit Guard
                  └── Exploit Protection
```

---

### Configure the Policy Setting

1. **Locate the policy:** `Use a common set of exploit protection settings`
2. **Double-click** to open the setting
3. **Select:** `Enabled`
4. **Options:** In the **"Options"** section, enter the UNC path to the XML file:

```
\\DC\GPO-Configs\ExploitProtectionLite.xml
```

**Example:**
```
\\DC\GPO-Configs\ExploitProtectionLite.xml
```

5. **Click:** `Apply` → `OK`

---

### Verify Configuration

**From Group Policy Editor:**

```powershell
# View the configured setting
Get-GPO -Name "Exploit-Protections-Workstations" | Get-GPOReport -ReportType Xml | Select-String -Pattern "ExploitProtectionLite.xml"
```

**Force GPO update on workstation:**

```powershell
# Force immediate GPO refresh
gpupdate /force
```

**Check if Exploit Protection is applied:**

```powershell
# View current exploit protection settings
Get-ProcessMitigation -System

# Check registry for configured file path
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exploit Guard\Exploit Protection" -ErrorAction SilentlyContinue
```

---

### Troubleshooting

**Issue:** GPO not applying to computers
- **Solution:** Ensure computers are in the Workstations OU
- **Command:** `Get-ADComputer -Filter * | Select-Object Name, DistinguishedName`

**Issue:** "Access denied" when testing UNC path as Administrator
- **Solution:** This is **expected behavior** - the share is restricted to Domain Computers only
- **Verification:** Confirm `Get-SmbShareAccess -Name "GPO-Configs"` shows only "Domain Computers"
- **Test:** The actual test happens when GPO applies to domain-joined computers

**Issue:** XML file not found by GPO
- **Solution:** Verify local file exists at `C:\GPO-Configs\ExploitProtectionLite.xml`
- **Command:** `Test-Path "C:\GPO-Configs\ExploitProtectionLite.xml"`
- **Verify UNC syntax:** Ensure GPO uses `$env:LOGONSERVER\GPO-Configs\ExploitProtectionLite.xml`

**Issue:** Exploit Protection not applying
- **Solution:** Check Windows Defender service status
- **Command:** `Get-Service -Name WinDefend`

---

</details>

---

## 🌐 Configure Network Protection

### Prerequisites

Before enabling Network Protection, ensure:

- ✅ Microsoft Defender for Endpoint P2 license
- ✅ Microsoft Defender Antivirus is in **Active Mode**
- ✅ **Cloud-Delivered Protection** is enabled
- ✅ Can be set to `Enabled` (Block) or `AuditMode` (Audit)

### Enable Network Protection in Audit Mode

```powershell
Set-MpPreference -EnableNetworkProtection AuditMode
```

### Verify Network Protection Status

```powershell
Get-MpPreference | Select-Object EnableNetworkProtection
```

**Expected Output:**
- `0` = Disabled
- `1` = Enabled (Block mode)
- `2` = AuditMode

---

## 🔬 Advanced Protection Features

### Check Current Protection Settings (Baseline)

Before making any changes, document your current Microsoft Defender Antivirus settings:

```powershell
# View all current Defender preferences
Get-MpPreference | Format-List

# View specific protection settings
Get-MpPreference | Select-Object `
    MAPSReporting, `
    DisableBehaviorMonitoring, `
    DisableIOAVProtection, `
    DisableScriptScanning, `
    DisableArchiveScanning, `
    DisableEmailScanning, `
    DisablePackedExeScanning, `
    EnableFileHashComputation, `
    CloudBlockLevel, `
    CloudExtendedTimeout, `
    DisableInboundConnectionFiltering, `
    DisableProtocolRecognition, `
    EnableNetworkProtection

# View computer status
Get-MpComputerStatus | Select-Object `
    RealTimeProtectionEnabled, `
    IoavProtectionEnabled, `
    BehaviorMonitorEnabled, `
    AntivirusEnabled, `
    AMProductVersion
```

> **💡 Pro Tip:** Save this baseline output to a file for comparison after configuration:
> ```powershell
> Get-MpPreference | Out-File -FilePath "C:\Temp\MDE-Baseline-Before.txt"
> ```

---

### Enable Behavioral Monitoring and Cloud Protection

The following features should be configured via GPO or locally:

```powershell
# Enable Cloud Protection (MAPS)
Set-MpPreference -MAPSReporting Advanced

# Enable behavior monitoring
Set-MpPreference -DisableBehaviorMonitoring $false

# Scan downloaded files and attachments
Set-MpPreference -DisableIOAVProtection $false

# Enable script scanning
Set-MpPreference -DisableScriptScanning $false

# Enable archive scanning (depth 10)
Set-MpPreference -DisableArchiveScanning $false
Set-MpPreference -ScanArchiveMaxSize 10

# Enable email scanning
Set-MpPreference -DisableEmailScanning $false

# Enable packed executable scanning
Set-MpPreference -DisablePackedExeScanning $false

# Enable file hash computation
Set-MpPreference -EnableFileHashComputation $true

# Configure extended cloud check (50 seconds)
Set-MpPreference -CloudBlockLevel HighPlus
Set-MpPreference -CloudExtendedTimeout 50

# Enable Network Inspection System
Set-MpPreference -DisableInboundConnectionFiltering $false
Set-MpPreference -DisableProtocolRecognition $false
```

### Cloud Protection Levels

| Level | Description |
|-------|-------------|
| `Default` | Default blocking level |
| `Moderate` | Moderate blocking (recommended for lab) |
| `High` | High blocking level |
| `HighPlus` | High+ blocking with extended timeout |
| `ZeroTolerance` | Block all unknown programs |

---

## 🔍 Verification and Monitoring

### Check MDE Platform Version

```powershell
Get-MpComputerStatus | Select-Object AMProductVersion
```

**Target Version:** 4.18.25100.9006 or higher

### View All Defender Preferences

```powershell
Get-MpPreference | Format-List
```

### Check Real-Time Protection Status

```powershell
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IoavProtectionEnabled, BehaviorMonitorEnabled, AntivirusEnabled
```

### Monitor Security Event Log

```powershell
# View recent security events
Get-WinEvent -LogName Security -MaxEvents 50 | Format-Table TimeCreated, Id, Message -Wrap
```

<details>
<summary><b>🧪 Test ASR Rules (Generate 1122 Events)</b></summary>

<br>

> **⚠️ WARNING:** These tests are for LAB ENVIRONMENTS ONLY. Do not run these in production. These commands and scripts are designed to trigger ASR rules and generate Event ID 1122 (audit mode) events.

**WMI-Based Process Creation (Triggers ASR Rules):**

```powershell
# Test 1: WMI to spawn calculator
Get-WmiObject -Class Win32_Process -List | Invoke-WmiMethod -Name Create -ArgumentList "calc.exe"

# Test 2: WMI to spawn notepad
Get-WmiObject -Class Win32_Process -List | Invoke-WmiMethod -Name Create -ArgumentList "notepad.exe"

# Test 3: CIM instance method
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="calc.exe"}
```

**JavaScript Test (test.js):**

Create a file named `test.js` with the following content:

```javascript
// test.js - Triggers ASR rule for JavaScript/VBScript launching executables
var shell = new ActiveXObject("WScript.Shell");
shell.Run("calc.exe");
```

Execute the script:

```powershell
# Run JavaScript test
wscript.exe test.js
```

**VBScript Test (test.vbs):**

Create a file named `test.vbs` with the following content:

```vbscript
' test.vbs - Triggers ASR rule for JavaScript/VBScript launching executables
Set objShell = CreateObject("WScript.Shell")
objShell.Run "calc.exe"
```

Execute the script:

```powershell
# Run VBScript test
wscript.exe test.vbs
```

**Office Macro Test (if Office is installed):**

Create a Word document with a macro that attempts to spawn a process:

```vba
Sub TestASR()
    Shell "calc.exe", vbNormalFocus
End Sub
```

**Expected ASR Rules Triggered:**

These tests should trigger the following ASR rules (in audit mode):
- **Block all Office applications from creating child processes** (GUID: D4F940AB-401B-4EFC-AADC-AD5F3C50688A)
- **Block JavaScript or VBScript from launching downloaded executable content** (GUID: D3E037E1-3EB8-44C8-A917-57927947596D)
- **Block process creations originating from PSExec and WMI commands** (GUID: D1E49AAC-8F56-4280-B9BA-993A6D77406C)

**Verify Test Results:**

```powershell
# Check for ASR events (Event ID 1122 = audit mode)
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 50 | 
    Where-Object {$_.Id -eq 1122} | 
    Format-Table TimeCreated, Message -Wrap

# Check specific ASR rule GUIDs in events
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | 
    Where-Object {$_.Id -eq 1122 -and $_.Message -like "*D1E49AAC-8F56-4280-B9BA-993A6D77406C*"}
```

</details>

---

### Monitor ASR Events

**View ASR events locally:**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Where-Object {$_.Id -eq 1121 -or $_.Id -eq 1122}
```

**View in Microsoft Defender XDR Portal:**
- Navigate to: **Assets → Devices → CLIENT01 → Incidents & Timeline**

> **📝 Note:** Event ID 1121 = ASR rule triggered (would block), Event ID 1122 = ASR rule in audit mode

---

## 📚 Reference Links

### Official Documentation

- **MDE Platform Updates:** https://www.catalog.update.microsoft.com/Search.aspx?q=KB4052623
- **PowerShell Installation:** https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.5#msi
- **ASR Rules Reference:** https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
- **Exploit Protection:** https://learn.microsoft.com/en-us/defender-endpoint/enable-exploit-protection

---

<details>
<summary><b>✅ Lab Enhancement Checklist</b></summary>

<br>

Use this checklist to track your progress:

**Domain Controller Setup:**
- [ ] Downloaded ExploitProtectionLite.xml from GitHub
- [ ] Removed mark-of-the-web from XML file
- [ ] Created C:\GPO-Configs directory
- [ ] Created GPO-Configs SMB share (Domain Computers only)
- [ ] Copied XML file to share
- [ ] Verified share permissions show "Domain Computers"
- [ ] Verified file exists at local path C:\GPO-Configs\ExploitProtectionLite.xml
- [ ] Noted the UNC path for GPO configuration

**Windows 11 Client Setup:**
- [ ] Installed RSAT tools on Windows 11
- [ ] Extracted MDE-GPO-Backup.zip
- [ ] Imported MDE GPOs using Import-MDE-GPOs script
- [ ] Verified Workstations OU creation (automatic)
- [ ] Verified computers moved to Workstations OU (automatic)
- [ ] Verified GPO links to Workstations and Domain Controllers OUs
- [ ] Configured Exploit Protection GPO with UNC path (ExploitProtectionLite.xml)
- [ ] Configured Network Protection in Audit Mode
- [ ] Network Inspection System: Protocol Recognition
- [ ] Network Inspection System: Datagram Processing for Network Protection
- [ ] Captured baseline settings with Get-MpPreference
- [ ] Enabled Cloud Protection (Microsoft Active Protection Service - MAPS: Advanced)
- [ ] Enabled Behavioral Monitoring
- [ ] Enabled Process Scanning
- [ ] Enabled File Hash Computation
- [ ] Enabled File Download & Attachment Scanning
- [ ] Enabled Script Scanning
- [ ] Enabled Archive Scanning
- [ ] Configured Cloud Block Level
- [ ] Forced GPO update on clients (`gpupdate /force`)
- [ ] Verified audit policy (`auditpol /get /category:*`)
- [ ] Checked MDE platform version
- [ ] Monitored ASR events
- [ ] Verified Security Event Log size (1GB)


</details>

---

## 🎓 Next Steps

1. **Monitor for 30+ days** - Collect audit data before enforcing block mode
2. **Review ASR Events** - Check Microsoft Defender XDR portal for triggered rules
3. **Create Exclusions** - Document false positives and create necessary exclusions
4. **Transition to Block Mode** - After baseline period, change audit mode to block mode
5. **Review Threat & Vulnerability Management** - Check updated applications in TVM dashboard

---

## ⚠️ Important Notes

> **🔴 Before Moving to Block Mode:**
> - Review at least 30 days of audit data
> - Document all false positives
> - Create necessary exclusions
> - Test in a pilot group first
> - Communicate changes to users

> **💡 Pro Tip:**
> Use `Get-WinEvent` filters and Microsoft Defender XDR's Advanced Hunting to analyze audit mode data efficiently before enforcement.

---

## 📞 Support

If you encounter issues during the workshop, contact your instructor or refer to the Microsoft Learn documentation.

**Happy Hunting! 🎯**
