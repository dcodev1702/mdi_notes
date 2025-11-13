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
# Import Active Directory Module
Import-Module ActiveDirectory
```

---

## 📂 Active Directory Structure

### Create Organizational Unit (OU)

Create a dedicated Workstations OU:

```powershell
# Create Workstations OU
New-ADOrganizationalUnit -Name "Workstations" -Path "DC=contoso,DC=local"
```

### Move Computers to Workstations OU

Move all computers from the default Computers container:

```powershell
# Move all computers to Workstations OU
Get-ADComputer -Filter * -SearchBase "CN=Computers,DC=contoso,DC=local" | Move-ADObject -TargetPath "OU=Workstations,DC=contoso,DC=local"
```

---

## 📊 Configure MDE Audit Policy

### Deploy Audit Policy GPOs

**For Workstations:**

```powershell
.\Create-MDE-AuditPolicyGPO.ps1 -GPOName "MDE Audit Policy - Workstations" -TargetOU "OU=Workstations,DC=contoso,DC=local"
```

**For Domain Controllers:**

```powershell
.\Create-MDE-AuditPolicyGPO.ps1 -GPOName "MDE Audit Policy - Domain Controllers" -TargetOU "OU=Domain Controllers,DC=contoso,DC=local"
```

### Configure Security Event Log Size

Increase Security log size to 1GB (1048576 KB):

**Workstations GPO:**

```powershell
Set-GPRegistryValue -Name "MDE Audit Policy - Workstations" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName "MaxSize" -Type DWord -Value 1048576
```

**Domain Controllers GPO:**

```powershell
Set-GPRegistryValue -Name "MDE Audit Policy - Domain Controllers" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName "MaxSize" -Type DWord -Value 1048576
```

### Apply and Verify

**On client computers, force GPO update:**

```powershell
gpupdate /force
```

**Verify audit settings:**

```powershell
auditpol /get /category:*
```

---

## 🛡️ Configure Attack Surface Reduction (ASR)

### Deploy ASR in Audit Mode

Run the ASR configuration script (creates and links GPO automatically):

```powershell
.\Configure-ASR-AuditMode.ps1
```

### Monitor ASR Events

**View ASR events locally:**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Where-Object {$_.Id -eq 1121 -or $_.Id -eq 1122}
```

**View in Microsoft Defender XDR Portal:**
- Navigate to: **Assets → Devices → CLIENT01 → Incidents & Timeline**

> **📝 Note:** Event ID 1121 = ASR rule triggered (would block), Event ID 1122 = ASR rule in audit mode

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

## 🔒 Configure Exploit Guard (Exploit Protection)

### Setup on Domain Controller

**1. Create SMB Share for GPO Configurations:**

```powershell
New-SmbShare -Name "GPO-Configs" -Path "C:\GPO-Configs" -ReadAccess "Domain Computers"
```

**2. Copy Exploit Protection XML:**

Copy your `ExploitGuard-AuditMode.xml` file to the share:

```powershell
Copy-Item -Path ".\ExploitGuard-AuditMode.xml" -Destination "C:\GPO-Configs\"
```

### Deploy via GPO

**Method 1: Via Group Policy Preferences**

1. Open **Group Policy Management Console**
2. Edit your workstation GPO
3. Navigate to: `Computer Configuration → Preferences → Windows Settings → Registry`
4. Create a new registry item pointing to the XML file path

**Method 2: Via PowerShell (Local Testing)**

```powershell
Set-ProcessMitigation -PolicyFilePath "\\DC-1\GPO-Configs\ExploitGuard-AuditMode.xml"
```

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
- [ ] Created Workstations OU structure
- [ ] Moved computers to Workstations OU
- [ ] Deployed MDE Audit Policy GPO (Workstations)
- [ ] Deployed MDE Audit Policy GPO (Domain Controllers)
- [ ] Configured Security Event Log to 1GB
- [ ] Deployed ASR rules in Audit Mode
- [ ] Configured Network Protection in Audit Mode
- [ ] Deployed Exploit Guard in Audit Mode
- [ ] Enabled Cloud Protection (MAPS - Advanced)
- [ ] Enabled Behavioral Monitoring
- [ ] Enabled Script Scanning
- [ ] Enabled Archive Scanning
- [ ] Configured Cloud Block Level
- [ ] Verified all GPOs applied (`gpupdate /force`)
- [ ] Verified audit policy (`auditpol /get /category:*`)
- [ ] Checked MDE platform version
- [ ] Monitored ASR events

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
