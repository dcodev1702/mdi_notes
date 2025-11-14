# 🛡️ Microsoft Defender XDR - Workshop Enhancement Guide

## 📋 Workshop Information

**Learning Portal:** https://mslearningcampus.com/User/Login  
**Student Key:** `[Your Key Here]`

---

## 🎯 Lab Enhancements Overview

This guide covers the comprehensive enhancements made to the Microsoft Defender for Endpoint (MDE) lab environment:

- ✅ Updated MDE Platform on CLIENT01
- ✅ Updated applications (Firefox, PowerShell, Edge) for Threat & Vulnerability Management
- ✅ Installed RSAT tools on Windows 11
- ✅ Configured ASR rules in Audit Mode
- ✅ Configured Exploit Guard in Audit Mode
- ✅ Configured Network Protection in Audit Mode
- ✅ Enhanced audit logging with comprehensive policies
- ✅ Increased Security Event Log size to 1GB
- ✅ Enabled advanced protection features (BAF, Cloud Protection, etc.)

---

## 🔧 Initial Setup

### 1. Install RSAT Tools for Windows 11

Install all Remote Server Administration Tools:

```powershell
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
- **Links GPOs** to appropriate OUs (Domain Controllers or Workstations)
- **Enforces GPO links** to ensure policies are applied correctly

This automated approach ensures consistent AD structure across lab environments and simplifies the deployment process.

---

## 📥 Import MDE Group Policy Objects

### Prerequisites

Ensure you have:
- RSAT tools installed (from step 1 above)
- Domain Administrator privileges
- The MDE GPO backup files ready for import

### Extract GPO Backup

Extract the GPO backup archive:

```powershell
# Navigate to the GPOs directory
cd MDE\GPOs

# Extract the backup archive
Expand-Archive -Path "__MDE-GPO-Backup.zip" -DestinationPath ".\MDE-GPO-Backup" -Force
```

Verify extraction:

```powershell
# List extracted GPOs
Get-ChildItem .\MDE-GPO-Backup
```

You should see the following GPO folders:
- ASR-Audit-Mode-Workstations
- MDE Audit Policy - Workstations
- MDE Audit Policy - Domain Controllers
- Exploit-Protections-Workstations

### Import GPOs Using Script

Navigate to the scripts directory and run the import function:

```powershell
# Navigate to scripts directory
cd ..\scripts

# Import the script
. .\Export-Import-MDE-GPOs.ps1

# Import all MDE GPOs
Import-MDE-GPOs -BackupPath "..\GPOs\MDE-GPO-Backup" -Domain "contoso.local"
```

The script will automatically:
1. ✅ Create the Workstations OU (if needed)
2. ✅ Move computers from Computers container to Workstations OU
3. ✅ Import all four MDE GPOs
4. ✅ Link GPOs to appropriate OUs
5. ✅ Enforce all GPO links

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

```powershell
# Check audit policy
auditpol /get /category:*

# Check ASR rules
Get-MpPreference | Select-Object AttackSurfaceReductionRules_*

# Check Exploit Protection
Get-ProcessMitigation -RegistryConfigFilePath
```

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

### Test ASR Rules (Generate 1122 Events)

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

## ✅ Lab Enhancement Checklist

Use this checklist to track your progress:

- [ ] Installed RSAT tools on Windows 11
- [ ] Extracted MDE-GPO-Backup.zip
- [ ] Imported MDE GPOs using Import-MDE-GPOs script
- [ ] Verified Workstations OU creation (automatic)
- [ ] Verified computers moved to Workstations OU (automatic)
- [ ] Verified GPO links to Workstations and Domain Controllers OUs
- [ ] Configured Network Protection in Audit Mode
- [ ] Enabled Cloud Protection (MAPS - Advanced)
- [ ] Enabled Behavioral Monitoring
- [ ] Enabled Script Scanning
- [ ] Enabled Archive Scanning
- [ ] Configured Cloud Block Level
- [ ] Forced GPO update on clients (`gpupdate /force`)
- [ ] Verified audit policy (`auditpol /get /category:*`)
- [ ] Checked MDE platform version
- [ ] Monitored ASR events
- [ ] Verified Security Event Log size (1GB)

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
