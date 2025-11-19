# 🛡️ Microsoft Defender XDR - Workshop Enhancement Guide

## 📋 Workshop Information

**Learning Portal:** https://mslearningcampus.com/User/Login  
**Student Key:** `[Your Key Here]`


### 🛡️ MDE Group Policy Objects (GPOs) Defined!

<details>
<summary><b><span style="font-size: 1.2em;">⚙️ MDE Group Policy Objects (GPOs)</span></b></summary>

<br>

This section details the three Microsoft Defender for Endpoint Group Policy Objects that provide comprehensive security configurations for your domain environment. Each GPO targets specific security capabilities and is designed to be deployed in audit mode initially, allowing you to establish baselines before enforcement.

---

<details>
<summary><b>🔧 MDE Audit Policy Configuration (Workstations & Domain Controllers)</b></summary>

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

> **🔴 CRITICAL: Domain Controller Reboot Required**  
> After applying the audit policy GPO to Domain Controllers, **a reboot is required** for the audit policies to take full effect. The `SCENoApplyLegacyAuditPolicy` registry setting affects the Local Security Authority (LSA) subsystem, which only loads at boot time and does not dynamically reload this configuration change.
> 
> **Steps After GPO Application:**
> 1. Run `gpupdate /force` on the Domain Controller
> 2. Reboot the Domain Controller: `Restart-Computer -Force`
> 3. After reboot, verify audit policies: `auditpol /get /category:*`
> 
> **Expected Behavior:**
> - ✅ Before reboot: Group Policy Management Editor shows correct audit settings, but `auditpol` shows old settings
> - ✅ After reboot: Both GPMC and `auditpol` show matching audit configurations
> 
> **Why This Happens:**
> - The registry key `HKLM\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy` forces Windows to use advanced audit policies instead of legacy audit policies
> - LSA (Local Security Authority) reads this setting only during system initialization
> - Without a reboot, legacy audit policies from other GPOs (like Default Domain Controllers Policy) continue to override the advanced audit.csv settings

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
<summary><b>🛡️ MDE Attack Surface Reduction (ASR) Configuration</b></summary>

<br>

The **ASR Audit Mode GPO** (`ASR-Audit-Mode-Workstations`) enables Microsoft Defender Attack Surface Reduction rules in Audit mode, allowing you to evaluate the impact of ASR rules without blocking potentially legitimate activity. This is essential for initial deployment and establishing a security baseline.

---

### 🎯 Attack Surface Reduction Rules

**Comprehensive Protection:**
- Configures **17 ASR rules** in **Audit mode** (value = 2)
- Protects against common attack vectors and exploitation techniques
- Enables visibility into potentially malicious behavior without disruption
- Provides telemetry for fine-tuning before enforcement

**ASR Rules Configured:**

| Rule Category | Description | GUID |
|---------------|-------------|------|
| **Email Protection** | Block executable content from email client and webmail | `BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550` |
| **Office Child Processes** | Block all Office applications from creating child processes | `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` |
| **Office Executable Content** | Block Office applications from creating executable content | `3B576869-A4EC-4529-8536-B80A7769E899` |
| **Office Code Injection** | Block Office applications from injecting code into other processes | `75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84` |
| **Script-based Execution** | Block JavaScript or VBScript from launching downloaded executable content | `D3E037E1-3EB8-44C8-A917-57927947596D` |
| **Obfuscated Scripts** | Block execution of potentially obfuscated scripts | `5BEB7EFE-FD9A-4556-801D-275E5FFC04CC` |
| **Office Macros** | Block Win32 API calls from Office macros | `92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B` |
| **Executable Reputation** | Block executable files from running unless they meet prevalence, age, or trusted list criterion | `01443614-cd74-433a-b99e-2ecdc07bfc25` |
| **Ransomware Protection** | Use advanced protection against ransomware | `c1db55ab-c21a-4637-bb3f-a12568109d35` |
| **Credential Theft** | Block credential stealing from lsass.exe | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` |
| **PSExec/WMI** | Block process creations originating from PSExec and WMI commands | `d1e49aac-8f56-4280-b9ba-993a6d77406c` |
| **USB Protection** | Block untrusted and unsigned processes that run from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` |
| **Office Communications** | Block Office communication application from creating child processes | `26190899-1602-49e8-8b27-eb1d0a1ce869` |
| **Adobe Reader** | Block Adobe Reader from creating child processes | `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` |
| **WMI Persistence** | Block persistence through WMI event subscription | `e6db77e5-3df2-4cf1-b95a-636979351e5b` |
| **Vulnerable Drivers** | Block abuse of exploited vulnerable signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce5` |
| **Safe Mode** | Block rebooting machine in Safe Mode (preview) | `c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb` |

---

### 📊 ASR Rule Values

**Configuration Modes:**
- **Value 0:** Disabled - Rule is not active
- **Value 1:** Block mode - Rule actively blocks detected behavior (enforcement)
- **Value 2:** Audit mode - Rule logs detected behavior without blocking (recommended for initial deployment)

**Current Configuration:**
- All 17 rules configured with **value = 2 (Audit mode)**
- Enables comprehensive visibility without operational impact
- Generates Event ID 1122 for all triggered rules
- Allows for baseline establishment and exclusion planning

---

### 🔍 Attack Surface Reduction Detection Capabilities

**Malicious Activity Detection:**
- **Living-off-the-Land Attacks** - Detects abuse of legitimate Windows tools (PowerShell, WMI, WScript)
- **Macro-based Attacks** - Identifies suspicious Office macro behavior
- **Script Execution** - Monitors JavaScript and VBScript launching executables
- **Credential Access** - Protects LSASS memory from dumping attempts
- **Ransomware Behavior** - Advanced behavioral analysis for ransomware indicators
- **Lateral Movement** - Tracks PSExec and WMI-based remote process creation
- **Persistence Mechanisms** - Monitors WMI event subscriptions for persistence

---

### 🚀 GPO Deployment

**Automated Configuration:**
- Creates or updates GPO named `ASR-Audit-Mode-Workstations`
- Links GPO to Workstations OU with enforcement enabled
- Configures ASR feature registry key (`ExploitGuard_ASR_Rules = 1`)
- Sets all 17 ASR rule GUIDs to audit mode (value = 2)
- Provides immediate visibility into protected behaviors

**Registry Configuration:**
```
Registry Path: HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR
  ExploitGuard_ASR_Rules = 1 (DWORD) - Enables ASR feature
  
Registry Path: HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules
  [GUID] = 2 (String) - Each ASR rule configured in audit mode
```

---

### ✅ Verify ASR Configuration

After GPO application, verify ASR rules are active:

```powershell
# Check ASR rules configuration
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions

# Expected output: 17 GUIDs with corresponding action values of 2
```

**Verify Event Logging:**

```powershell
# Check for ASR audit events (Event ID 1122)
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 50 | 
    Where-Object {$_.Id -eq 1122} | 
    Format-Table TimeCreated, Message -Wrap
```

---

### 📈 Monitoring and Analysis

**Event IDs for ASR:**
- **Event ID 1121:** ASR rule was triggered and would have blocked (audit mode reports this as "would block")
- **Event ID 1122:** ASR rule audited the activity (logged but not blocked)
- **Event ID 1123:** ASR rule blocked activity (only in Block mode - value 1)
- **Event ID 5007:** ASR configuration changed

**Microsoft Defender XDR Portal:**
- Navigate to: **Reports → Device protection → Attack surface reduction rules**
- View triggered rules across all devices
- Analyze patterns and identify false positives
- Generate exclusion recommendations

**Advanced Hunting Query Example:**

```kusto
DeviceEvents
| where ActionType startswith "Asr"
| where ActionType contains "Audited"
| summarize Count=count() by ActionType, InitiatingProcessFileName, FileName
| order by Count desc
```

---

### ⚠️ Important Notes

> **⚠️ Audit Mode Duration**  
> Microsoft recommends running ASR rules in Audit mode for **30+ days** before transitioning to Block mode. This baseline period allows you to:
> - Identify legitimate applications that trigger rules
> - Create necessary exclusions
> - Validate business process compatibility
> - Build confidence in rule effectiveness

> **💡 Transitioning to Block Mode**  
> After the audit period:
> 1. Review all Event ID 1122 events in Microsoft Defender XDR
> 2. Identify and document false positives
> 3. Create ASR exclusions for legitimate applications
> 4. Change rule values from 2 (Audit) to 1 (Block) in GPO
> 5. Deploy to pilot group before full production rollout

> **🔐 ASR Exclusions**  
> When creating exclusions:
> - Use file paths rather than file names when possible
> - Document business justification for each exclusion
> - Regularly review and validate exclusions
> - Consider per-rule exclusions vs. global exclusions
> - Test exclusions in pilot environment first

> **📊 Performance Considerations**  
> ASR rules in audit mode have minimal performance impact:
> - Logging overhead is negligible
> - No blocking operations occur
> - Memory and CPU impact < 1%
> - Suitable for all workstation types

</details>

---

<details>
<summary><b>🔒 Endpoint Hardening & Exploit Protection</b></summary>

<br>

The **MDE Exploit Protections Policy - Workstations** GPO (`MDE Exploit Protections Policy - Workstations`) provides comprehensive endpoint security by configuring Microsoft Defender's advanced protection features, cloud intelligence integration, and exploit mitigation capabilities. This GPO establishes a robust security baseline for workstations while maintaining audit-friendly configurations for controlled rollout.

---

### 🌩️ Microsoft MAPS & Cloud Protection

**Cloud-Connected Threat Intelligence:**
- **Microsoft MAPS (Advanced):** Maximum telemetry sharing with Microsoft's cloud protection service
- **Block at First Sight (BAFS):** Instantly blocks suspicious files before signature updates are available
- **Automatic Sample Submission:** All suspicious samples automatically sent to Microsoft for analysis
- **Extended Cloud Check:** 10-second timeout allows cloud analysis for unknown files before execution
- **File Hash Computation:** Enables rapid cloud-based reputation lookups
- **Real-time Security Intelligence Updates:** Automatic signature updates based on MAPS telemetry

**What This Provides:**
- Zero-day threat protection through cloud intelligence
- Immediate response to emerging threats before signature distribution
- Reduced time-to-protection for new malware variants
- Enhanced detection through global threat telemetry

---

### 🛡️ Network Protection

**Web Threat Prevention:**
- **Network Protection:** Enabled in **Audit Mode** (logs dangerous website access attempts)
- **SmartScreen Integration:** Prevents access to phishing sites and malicious downloads
- **Protocol Recognition:** Enabled for enhanced network traffic analysis
- **Datagram Processing:** Enabled for comprehensive network-level threat detection
- **Windows Server Support:** Network Protection explicitly enabled for server platforms

**Protection Scope:**
- Malicious websites and domains
- Phishing attempts
- Exploit hosting sites
- Command-and-control (C2) communications
- Drive-by download attacks

**Audit Mode Benefits:**
- Generates telemetry without blocking user access
- Allows identification of false positives before enforcement
- Provides visibility into web-based threats
- Enables baseline establishment for network behavior

---

### 🔐 Controlled Folder Access (Ransomware Protection)

**Ransomware Defense:**
- **Mode:** Audit Mode (logs unauthorized access attempts without blocking)
- **Protected Folders:** System folders and user document directories
- **Monitoring:** Detects unauthorized applications attempting to modify protected files

**What It Monitors:**
- Unauthorized file encryption attempts
- Suspicious file modification patterns
- Processes attempting to access protected folders
- Ransomware-like behavior indicators

---

### 🔍 Real-Time Protection & Scanning

**Comprehensive Malware Detection:**

| Feature | Status | Description |
|---------|--------|-------------|
| **Behavior Monitoring** | Enabled | Analyzes process behavior for malicious patterns |
| **Process Scanning** | Enabled | Scans running processes for threats |
| **Script Scanning** | Enabled | Monitors PowerShell, JavaScript, and VBScript execution |
| **Downloaded Files** | Enabled | Scans all downloads and attachments |
| **Max Download Size** | 20,480 KB (20 MB) | Maximum file size scanned automatically |
| **File Activity Monitoring** | Enabled | Tracks file and program activity across the system |
| **Raw Volume Writes** | Enabled | Detects direct disk write attempts (ransomware indicator) |

**Advanced Detection Capabilities:**
- **Fileless Malware Detection:** Monitors in-memory threats and script-based attacks
- **Living-off-the-Land Detection:** Identifies abuse of legitimate Windows tools
- **Document Exploit Detection:** Scans embedded content in Office files and PDFs
- **Command Line Monitoring:** Analyzes process execution with full command arguments

---

### 📅 Scheduled Scan Configuration

**Automated Threat Scanning:**

| Setting | Value | Purpose |
|---------|-------|---------|
| **Quick Scans Per Day** | 2 | Efficient threat detection without full system scan overhead |
| **Archive Scanning** | Enabled | Detects threats hidden in compressed files |
| **Archive Depth** | 5 levels | Scans nested archives up to 5 layers deep |
| **Packed Executables** | Enabled | Analyzes compressed/obfuscated executables |
| **Removable Drives** | Enabled | Scans USB drives and external media |
| **Email Scanning** | Enabled | Inspects email attachments and embedded content |
| **Heuristics** | Enabled | Detects unknown threats via behavioral analysis |
| **Pre-Scan Updates** | Enabled | Updates signatures before scheduled scans |

**Benefits:**
- Twice-daily quick scans catch threats missed by real-time protection
- Archive scanning prevents malware delivery via compressed files
- Heuristics detect zero-day threats without signatures
- Email scanning protects against phishing attachments

---

### ⚔️ Exploit Protection

**System and Application Hardening:**
- **Configuration Source:** `\\DC\GPO-Configs\ExploitProtectionLite.xml`
- **Scope:** System-wide and per-application exploit mitigations
- **Deployment:** Centralized configuration via network share

**Mitigation Technologies Applied:**

| Mitigation | Description |
|------------|-------------|
| **DEP (Data Execution Prevention)** | Prevents code execution in data-only memory regions |
| **ASLR (Address Space Layout Randomization)** | Randomizes memory addresses to prevent exploit reliability |
| **CFG (Control Flow Guard)** | Validates indirect function calls to prevent ROP attacks |
| **SEHOP (Structured Exception Handler Overwrite Protection)** | Protects exception handler chains |
| **Bottom-up ASLR** | Randomizes memory allocations |
| **High-entropy ASLR** | Increases randomization entropy for 64-bit processes |
| **Validate Exception Chains** | Ensures exception handler integrity |
| **Validate Stack Integrity** | Detects stack buffer overflows |

**Protected Applications (ExploitProtectionLite.xml):**
- Microsoft Edge
- Internet Explorer
- Google Chrome
- Mozilla Firefox
- Microsoft Office applications
- Adobe Reader
- Java runtime
- Common system utilities

---

### 📊 Microsoft Defender Application Guard

**Container-Based Isolation:**
- **Application Guard Auditing:** Enabled
- **Event Collection:** System events from isolated containers logged to host
- **Purpose:** Monitors browsing in hardware-isolated environments

**Security Boundary:**
- Untrusted websites open in Hyper-V isolated container
- Enterprise resources remain accessible from normal browser
- Auditing provides visibility into isolated session activity

---

### 🚀 GPO Deployment Details

**Automated Configuration:**
- **GPO Name:** `Exploit-Protections-Workstations`
- **Linked to:** Workstations OU (`OU=Workstations,DC=contoso,DC=local`)
- **Enforcement:** Link enforced (NoOverride = true)
- **Scope:** Computer Configuration only

**Registry Paths Configured:**
```
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\
  ├── MpEngine (Cloud protection settings)
  ├── Real-Time Protection (Scanning configurations)
  ├── Scan (Scheduled scan parameters)
  ├── Spynet (MAPS membership)
  ├── Windows Defender Exploit Guard
  │   ├── Controlled Folder Access
  │   ├── Network Protection
  │   └── Exploit Protection
  └── Reporting (MAPS reporting settings)
```

---

### ✅ Verify Configuration

After GPO application, verify the protection features are active:

```powershell
# Check overall Defender status
Get-MpComputerStatus | Select-Object `
    RealTimeProtectionEnabled, `
    BehaviorMonitorEnabled, `
    IoavProtectionEnabled, `
    NISEnabled, `
    AntivirusEnabled

# Verify cloud protection (MAPS)
Get-MpPreference | Select-Object `
    MAPSReporting, `
    SubmitSamplesConsent, `
    DisableBlockAtFirstSeen, `
    CloudBlockLevel, `
    CloudExtendedTimeout

# Check Network Protection status
Get-MpPreference | Select-Object EnableNetworkProtection

# Verify Controlled Folder Access
Get-MpPreference | Select-Object EnableControlledFolderAccess
```

```powershell
# Check exploit protection configuration
Get-ProcessMitigation -System
Get-ProcessMitigation -Name "winword.exe"
Get-ProcessMitigation -Name "iexplore.exe"
Get-ProcessMitigation -Name "chrome.exe"
```

**Expected Values:**

| Setting | Expected Value | Meaning |
|---------|----------------|---------|
| `MAPSReporting` | 2 | Advanced MAPS membership |
| `SubmitSamplesConsent` | 3 | Send all samples automatically |
| `DisableBlockAtFirstSeen` | False | BAFS enabled |
| `CloudExtendedTimeout` | 10 | 10-second cloud check timeout |
| `EnableNetworkProtection` | 2 | Audit mode |
| `EnableControlledFolderAccess` | 2 | Audit mode |

---

### 📈 Monitoring and Event IDs

**Key Event Logs:**

| Event ID | Log | Description |
|----------|-----|-------------|
| **1116** | Microsoft-Windows-Windows Defender/Operational | Malware detected |
| **1117** | Microsoft-Windows-Windows Defender/Operational | Malware action taken |
| **1125** | Microsoft-Windows-Windows Defender/Operational | Network Protection audited event |
| **1126** | Microsoft-Windows-Windows Defender/Operational | Network Protection blocked event |
| **5007** | Microsoft-Windows-Windows Defender/Operational | Configuration changed |
| **1123** | Microsoft-Windows-Windows Defender/Operational | Controlled Folder Access audited |
| **1124** | Microsoft-Windows-Windows Defender/Operational | Controlled Folder Access blocked |

**Monitor Network Protection Events:**

```powershell
# View Network Protection audit events
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | 
    Where-Object {$_.Id -eq 1125} | 
    Format-Table TimeCreated, Message -Wrap

# View Controlled Folder Access audit events
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | 
    Where-Object {$_.Id -eq 1123} | 
    Format-Table TimeCreated, Message -Wrap
```

**Microsoft Defender XDR Portal Monitoring:**
- Navigate to: **Reports → Device protection → Web protection**
- View Network Protection blocks and audits
- Navigate to: **Reports → Device protection → Controlled folder access**
- Monitor ransomware protection events

---

### ⚠️ Important Notes

> **⚠️ Audit Mode Strategy**  
> Network Protection and Controlled Folder Access are configured in **Audit Mode** to allow baseline establishment:
> - Run in audit mode for 30+ days minimum
> - Analyze telemetry in Microsoft Defender XDR portal
> - Identify and document false positives
> - Create necessary exclusions before enforcement
> - Test in pilot group before production rollout

> **💡 Cloud Protection Requirements**  
> Advanced MAPS and Block at First Sight require:
> - Active internet connectivity to Microsoft cloud services
> - Outbound access to Microsoft Defender endpoints
> - Windows Defender Antivirus in active mode (not passive/disabled)
> - Sufficient cloud check timeout for analysis (configured: 10 seconds)

> **🔐 Exploit Protection Best Practices**  
> The ExploitProtectionLite.xml configuration:
> - Applies system-wide mitigations for maximum coverage
> - Includes per-application settings for common targets
> - Balances security with application compatibility
> - Should be tested with critical line-of-business applications before production deployment

> **🌐 Network Protection Performance**  
> Network Protection in audit mode has minimal impact:
> - Logging overhead is negligible
> - No blocking operations in audit mode
> - SmartScreen lookups cached for performance
> - Suitable for all workstation types and user profiles

> **📊 MAPS Telemetry Privacy**  
> Advanced MAPS membership shares:
> - File hashes and metadata (not file contents unless explicitly consented)
> - Threat detection information
> - Sample files automatically submitted for analysis
> - Ensure compliance with organizational data policies before deployment

> **🔄 Transitioning to Block Mode**  
> After audit period, transition Network Protection and Controlled Folder Access to block mode:
> ```powershell
> # Network Protection - Block mode (requires GPO update or direct config)
> Set-MpPreference -EnableNetworkProtection Enabled  # Value = 1
> 
> # Controlled Folder Access - Block mode
> Set-MpPreference -EnableControlledFolderAccess Enabled  # Value = 1
> ```
> **Note:** Prefer GPO configuration over local settings for enterprise management

</details>

</details>

---
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

### 🚀 Lab Infrastructure

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

**Update Microsoft Defender Antivirus (MDAV) Platform:**

Ensure your MDAV platform is up to date before starting:

```powershell
# Check current platform version
Get-MpComputerStatus | Select-Object AMProductVersion

# Update MDAV Signature via Windows Update
Update-MpSignature
```

**Manual MDAV Platform Update (if needed via MSFT Catalog: KB4052623):**

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

###⚡ What This Workshop Will Configure

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

## 🛠️ Import MDE Group Policy Objects

### Prerequisites

Ensure you have:
- ✅ **Completed Domain Controller preparation** (see collapsible section above)
- ✅ RSAT tools installed (from step 1 above)
- ✅ Domain Administrator privileges

### Automated MDE GPO Import

Follow these steps to automatically download, extract, and import all four MDE GPOs:

**Step 1:** Create a temporary working directory

```powershell
$TempPath = "$env:TEMP\MDE-GPO-Import"
New-Item -Path $TempPath -ItemType Directory -Force | Out-Null
cd $TempPath
```

**Step 2:** Download the MDE GPO backup archive from GitHub

```powershell
Invoke-WebRequest -Uri "https://github.com/dcodev1702/mdi_notes/raw/main/MDE/GPOs/MDE-GPO-Backup.zip" -OutFile "$TempPath\MDE-GPO-Backup.zip"
Unblock-File -Path "$TempPath\MDE-GPO-Backup.zip"
```

**Step 3:** Extract the GPO backup archive

```powershell
Expand-Archive -Path "$TempPath\MDE-GPO-Backup.zip" -DestinationPath $PWD -Force
```

**Step 4:** Download the GPO import script

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dcodev1702/mdi_notes/refs/heads/main/MDE/scripts/Export-Import-MDE-GPOs.ps1" -OutFile "$TempPath\Export-Import-MDE-GPOs.ps1"
Unblock-File -Path "$TempPath\Export-Import-MDE-GPOs.ps1"
```

**Step 5:** Execute the import script with the backup path

```powershell
& "$TempPath\Export-Import-MDE-GPOs.ps1"
```

**Step 6:** Remove downloaded archive, GPO's, and scripts

```powershell
cd $env:USERPROFILE
Remove-Item -Path "$TempPath" -Recurse -Force
```

**Step 7:** Force GPO Update on Domain Assets

```powershell
gpupdate /force
```

**Step 8:** REBOOT DC AND CLIENT VM's

```powershell
# Switch over to DC and restart the VM
Restart-Computer
```

```powershell
# Switch over to CLIENT01 and restart the VM
Restart-Computer
```

### What This Does:

1. **Creates temp directory** - `$env:TEMP\MDE-GPO-Import`
2. **Downloads MDE-GPO-Backup.zip** from GitHub and removes Mark-of-the-Web
3. **Extracts the archive** to the temp directory
4. **Downloads Export-Import-MDE-GPOs.ps1** script and removes Mark-of-the-Web
5. **Executes the script** with the correct `-BackupPath` parameter pointing to the extracted GPOs
6. **Removes Temp Directory** containing GPO & PS script artifacts 
7. **Performs Group Policy Update on Domain** [contoso.local]

The PowerShell script will automatically perform the following tasks:
- ✅ Create the Workstations OU (if needed)
- ✅ Move computers from Computers container to Workstations OU
- ✅ Import all four MDE GPOs
- ✅ Link GPOs to appropriate OUs
- ✅ Enforce all GPO links


### 📐 Verify GPO Import

**Check GPO links:**

```powershell
# List GPOs linked to Workstations OU
Get-GPInheritance -Target "OU=Workstations,DC=contoso,DC=local"

# List GPOs linked to Domain Controllers OU
Get-GPInheritance -Target "OU=Domain Controllers,DC=contoso,DC=local"
```


**Verify imported settings:**
<img width="1147" height="580" alt="image" src="https://github.com/user-attachments/assets/26861104-a757-4ee7-b092-16ab4fc4ce5f" />


```powershell
# Check audit policy
auditpol /get /category:*

# Check ASR rules
Get-MpPreference | Select-Object AttackSurfaceReductionRules_*

# Check Exploit Protection
Get-ProcessMitigation -System

# Check Exploit Protection for Microsoft Word
Get-ProcessMitigation -Name winword.exe
```


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

###💡Troubleshooting

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

## 🧬 Advanced Protection Features

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

<details>
<summary><b>Behavioral Monitoring and Cloud Protections (Manual)</b></summary>

<br>

The following features should ALREADY be configured via GPO or locally:

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

</details>

---

## 🔍 Verification and Monitoring

### Validate Observability with MDE & GPO settings

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

<details>
<summary><b>🔐 MDE Exploit Protection Configuration & Monitoring</b></summary>

<br>

The **Exploit Protection GPO** (`Exploit Protections Policy - Workstations`) enables comprehensive exploit mitigation techniques in Audit mode, providing visibility into exploitation attempts without disrupting legitimate applications. This configuration protects against memory corruption, code injection, and Return-Oriented Programming (ROP) attacks.

---

### 🎯 What is Exploit Protection?

Exploit Protection is a set of mitigations that help protect your devices from malware that uses exploits to spread and infect. It provides:

- **System-wide mitigations** - Applied to all processes
- **Application-specific mitigations** - Targeted protections for high-risk applications (Office, browsers, Adobe, Java)
- **Hardware-based security** - Leverages CPU features like Control Flow Guard (CFG) and Intel CET

**Key Benefits:**
- Protection against zero-day exploits
- Reduces attack surface for common exploitation techniques
- Audit mode allows evaluation without disruption
- Granular control per application

---

### ✅ What's Now Being Audited (System-Wide)

The Enhanced Exploit Protection configuration enables the following protections in **Audit Mode**:

- ✅ **SEHOP** - Exception handler exploits  
- ✅ **Dynamic Code** - DLL injection, shellcode  
- ✅ **Binary Signature** - Unsigned DLL loading  
- ✅ **Font Disable** - Malicious font loading  
- ✅ **Image Load** - Remote/low-integrity images  
- ✅ **System Call** - Win32k/Fsctl restrictions  
- ✅ **Child Process** - Unauthorized process spawning  
- ✅ **User Shadow Stack** - Hardware CFI (CET)  
- ✅ **Payload (ROP)** - Memory corruption attacks  

**Plus** application-specific protections for: Office, browsers (Chrome, Firefox, Edge, IE), Adobe Reader, PowerShell, Command Prompt, Windows Script Host, and Java.

---

### 🛡️ Exploit Protections Configured (System-Wide Audit Mode)

<details>
<summary><b>1. SEHOP (Structured Exception Handler Overwrite Protection)</b></summary>

**Purpose:** Detects attempts to exploit SEH (Structured Exception Handler) chains

**Attack Vector Blocked:** 
- Exploits that overwrite exception handlers to redirect execution flow
- Common in buffer overflow attacks

**Audit Mode Events:**
- Event Log: `Microsoft-Windows-Security-Mitigations/KernelMode`
- Event ID: 1 (Audit), 2 (Block when enforced)

**Typical Triggers:**
- Memory corruption exploits
- Buffer overflow attempts
- Heap spray attacks

</details>

<details>
<summary><b>2. Dynamic Code (Code Injection Protection)</b></summary>

**Purpose:** Detects unsigned dynamic code execution (DLL injection, shellcode)

**Attack Vector Blocked:**
- Process injection (CreateRemoteThread, QueueUserAPC)
- Reflective DLL injection
- Shellcode execution in memory
- Code caves

**Audit Mode Events:**
- Event Log: `Microsoft-Windows-Security-Mitigations/UserMode`
- Event ID: 12

**Typical Triggers:**
- ✅ **Legitimate:** Debuggers (Visual Studio, WinDbg), Antivirus engines, .NET JIT compilation
- ❌ **Malicious:** Malware injectors, exploit kits, fileless malware

</details>

<details>
<summary><b>3. Binary Signature (Unsigned DLL Loading)</b></summary>

**Purpose:** Detects loading of unsigned or untrusted binaries

**Attack Vector Blocked:**
- Loading unsigned/untrusted DLLs
- DLL hijacking
- Side-loading malicious libraries

**Audit Mode Events:**
- Event Log: `Microsoft-Windows-Security-Mitigations/UserMode`
- Event ID: 8

**Typical Triggers:**
- ✅ **Legitimate:** Third-party software, in-house developed tools, legacy applications
- ❌ **Malicious:** Unsigned malware, trojanized DLLs

</details>

<details>
<summary><b>4. Font Disable (Untrusted Font Loading)</b></summary>

**Purpose:** Detects attempts to load non-system fonts (common attack vector)

**Attack Vector Blocked:**
- Malicious font parsing exploits
- Embedded font exploits in documents
- Font-based code execution

**Audit Mode Events:**
- Event Log: `Microsoft-Windows-Security-Mitigations/UserMode`
- Event ID: 14

**Typical Triggers:**
- ✅ **Legitimate:** Custom fonts in documents (PowerPoint, Word)
- ❌ **Malicious:** Font-based exploits (CVE-2015-2426, CVE-2016-3393)

</details>

<details>
<summary><b>5. Image Load (Remote/Low-Integrity Image Protection)</b></summary>

**Purpose:** Detects loading of remote images or low-integrity images

**Attack Vector Blocked:**
- Loading DLLs from network shares
- Loading DLLs from temp/download folders
- Low-integrity process image loads

**Audit Mode Events:**
- Event Log: `Microsoft-Windows-Security-Mitigations/UserMode`
- Event IDs: 5 (Remote), 6 (Low Label), 7 (PreferSystem32)

**Typical Triggers:**
- ✅ **Legitimate:** Network-mapped drives, shared libraries
- ❌ **Malicious:** SMB-based DLL hijacking, downloaded malware

</details>

<details>
<summary><b>6. System Call (Win32k/Fsctl Restrictions)</b></summary>

**Purpose:** Blocks system calls that bypass security boundaries

**Attack Vector Blocked:**
- Win32k.sys kernel exploitation
- File system control operations abuse
- Kernel-mode escalation attempts

**Audit Mode Events:**
- Event Log: `Microsoft-Windows-Security-Mitigations/UserMode`
- Event IDs: 3 (Win32k), 33 (Fsctl)

**Typical Triggers:**
- ✅ **Legitimate:** Legacy GUI applications
- ❌ **Malicious:** Kernel exploits, privilege escalation attempts

</details>

<details>
<summary><b>7. Child Process (Process Creation Restrictions)</b></summary>

**Purpose:** Detects unauthorized child process creation

**Attack Vector Blocked:**
- Office macros spawning executables
- Script-based process execution
- Living-off-the-land techniques

**Audit Mode Events:**
- Event Log: `Microsoft-Windows-Security-Mitigations/UserMode`
- Event ID: 10

**Typical Triggers:**
- ✅ **Legitimate:** Office macros (legitimate automation), PowerShell scripts, build systems
- ❌ **Malicious:** Macro-based malware, document exploits, lateral movement

</details>

<details>
<summary><b>8. User Shadow Stack (Hardware Control Flow Integrity - CET)</b></summary>

**Purpose:** Hardware-enforced control flow integrity using Intel CET (Control-flow Enforcement Technology)

**Attack Vector Blocked:**
- Return-Oriented Programming (ROP)
- Control flow hijacking
- Return address manipulation

**Audit Mode Events:**
- Event Log: `Microsoft-Windows-Security-Mitigations/UserMode`
- Event ID: 35

**Requirements:**
- Intel 11th gen (Tiger Lake) or newer
- AMD Zen 3 or newer
- Windows 11 or Windows Server 2022+

**Typical Triggers:**
- ❌ **Malicious:** ROP exploits, advanced memory corruption attacks

</details>

<details>
<summary><b>9. Payload Protections (ROP & Memory Exploitation Mitigations)</b></summary>

**Purpose:** Detects Return-Oriented Programming and memory corruption techniques

**Protections Enabled:**
- **Export Address Filter (EAF)** - Blocks ROP gadgets from exported functions
- **Export Address Filter Plus (EAF+)** - Enhanced EAF with additional modules
- **Import Address Filter (IAF)** - Protects Import Address Table (IAT)
- **ROP Stack Pivot** - Detects stack pointer manipulation
- **ROP Caller Check** - Validates return addresses
- **ROP Sim Exec** - Simulates execution to detect ROP chains

**Audit Mode Events:**
- Event Log: `Microsoft-Windows-Security-Mitigations/UserMode`
- Event IDs: 16 (EAF), 17 (EAF+), 18 (IAF), 19 (Stack Pivot), 20 (Caller Check), 21 (Sim Exec)

**Attack Vectors Blocked:**
- Return-Oriented Programming (ROP)
- Jump-Oriented Programming (JOP)
- Counterfeit Object-Oriented Programming (COOP)
- Memory corruption exploits

**Typical Triggers:**
- ❌ **Malicious:** Exploit kits, advanced malware, targeted attacks

</details>

---

### 📊 Monitoring Exploit Protection Events

<details>
<summary><b>PowerShell Monitoring Commands</b></summary>

<br>

**View All Exploit Protection Events (Last 24 Hours):**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Mitigations/UserMode" -MaxEvents 100 | 
    Where-Object {$_.TimeCreated -gt (Get-Date).AddDays(-1)} | 
    Select-Object TimeCreated, Id, Message | 
    Format-Table -AutoSize
```

**View Specific Protection Type:**

```powershell
# Dynamic Code (Event ID 12)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Security-Mitigations/UserMode'
    ID=12
} -MaxEvents 50 | Format-List TimeCreated, Message

# Child Process (Event ID 10)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Security-Mitigations/UserMode'
    ID=10
} -MaxEvents 50 | Format-List TimeCreated, Message

# Binary Signature (Event ID 8)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Security-Mitigations/UserMode'
    ID=8
} -MaxEvents 50 | Format-List TimeCreated, Message
```

**Export Last 7 Days to CSV:**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Mitigations/UserMode" -MaxEvents 10000 |
    Where-Object {$_.TimeCreated -gt (Get-Date).AddDays(-7)} |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Export-Csv -Path "C:\Temp\ExploitProtection-Audit-7days.csv" -NoTypeInformation
```

**Count Events by Type:**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Mitigations/UserMode" -MaxEvents 1000 |
    Where-Object {$_.TimeCreated -gt (Get-Date).AddDays(-7)} |
    Group-Object Id |
    Select-Object Count, Name |
    Sort-Object Count -Descending
```

</details>

<details>
<summary><b>Event Log Configuration</b></summary>

<br>

**View Current Log Configuration:**

```powershell
wevtutil gl Microsoft-Windows-Security-Mitigations/UserMode
```

**Increase Log Size to 100 MB (Optional):**

```powershell
wevtutil sl Microsoft-Windows-Security-Mitigations/UserMode /ms:104857600
```

**Enable the Log:**

```powershell
wevtutil set-log Microsoft-Windows-Security-Mitigations/UserMode /e:true
```

**Why Increase Log Size?**
- Default size may be insufficient for comprehensive audit data
- 100MB provides ~30 days of retention in typical environments
- Prevents event loss during baseline period

</details>

<details>
<summary><b>Verification Commands</b></summary>

<br>

**Check System-Wide Exploit Protection Settings:**

```powershell
Get-ProcessMitigation -System
```

**Check Application-Specific Settings:**

```powershell
# Microsoft Word
Get-ProcessMitigation -Name winword.exe

# PowerShell
Get-ProcessMitigation -Name powershell.exe

# Chrome
Get-ProcessMitigation -Name chrome.exe

# Internet Explorer
Get-ProcessMitigation -Name iexplore.exe
```

**Verify XML File Path in Registry:**

```powershell
Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection" -Name ExploitProtectionSettings
```

**Test XML File Accessibility:**

```powershell
# From Domain Controller (as System)
Test-Path "\\DC\GPO-Configs\ExploitProtectionLite.xml"

# From Client (as SYSTEM - should succeed)
psexec -s cmd /c "dir \\DC\GPO-Configs\ExploitProtectionLite.xml"
```

</details>

---

### 📋 Event ID Reference Guide

| Event ID | Protection Type | Severity | Description |
|----------|----------------|----------|-------------|
| 1 | SEHOP | Medium | Structured exception handler violation |
| 3 | System Call (Win32k) | High | Restricted Win32k system call attempt |
| 5 | Remote Image Load | Medium | DLL loaded from remote location |
| 6 | Low Label Image Load | Medium | DLL loaded from low-integrity location |
| 7 | PreferSystem32 | Low | Non-System32 DLL loaded |
| 8 | Binary Signature | Medium | Unsigned/untrusted binary loaded |
| 10 | Child Process | High | Unauthorized child process creation |
| 12 | Dynamic Code | High | Dynamic code injection detected |
| 14 | Font Disable | Medium | Non-system font loading attempt |
| 16 | Export Address Filter | High | EAF ROP mitigation triggered |
| 17 | EAF Plus | High | EAF+ ROP mitigation triggered |
| 18 | Import Address Filter | High | IAF ROP mitigation triggered |
| 19 | ROP Stack Pivot | **Critical** | Stack pivot attack detected |
| 20 | ROP Caller Check | **Critical** | Invalid return address detected |
| 21 | ROP Sim Exec | **Critical** | ROP chain simulation detected |
| 33 | System Call (Fsctl) | High | Restricted Fsctl system call attempt |
| 35 | User Shadow Stack | **Critical** | Hardware CET violation (ROP attempt) |

---

### 🎯 Protected Applications

The Enhanced Exploit Protection configuration includes audit mode for:

**Browsers:**
- Internet Explorer (iexplore.exe)
- Microsoft Edge Legacy (MicrosoftEdge.exe)
- Microsoft Edge Chromium (msedge.exe)
- Google Chrome (chrome.exe)
- Mozilla Firefox (firefox.exe)

**Microsoft Office:**
- Outlook (outlook.exe)
- Word (winword.exe)
- Excel (excel.exe)
- PowerPoint (powerpnt.exe)

**Adobe Products:**
- Acrobat Reader (AcroRd32.exe, Acrobat.exe)

**Windows Components:**
- WordPad (wordpad.exe)
- Notepad (notepad.exe)
- PowerShell (powershell.exe, pwsh.exe)
- Command Prompt (cmd.exe)
- Windows Script Host (wscript.exe, cscript.exe)
- Runtime Broker (RuntimeBroker.exe)
- Windows Search (SearchIndexer.exe)

**Java:**
- Java Runtime (java.exe, javaw.exe, javaws.exe)

---

### ⚠️ Common False Positives & Troubleshooting

<details>
<summary><b>Dynamic Code (Event ID 12)</b></summary>

**Common Legitimate Triggers:**
- Visual Studio Debugger (devenv.exe)
- WinDbg debugger
- Antivirus engines
- .NET applications using JIT compilation
- Python interpreters

**Resolution:**
- Review audit events to identify legitimate applications
- After 30-day baseline, add application-specific exceptions
- For development machines, consider excluding debuggers

</details>

<details>
<summary><b>Binary Signature (Event ID 8)</b></summary>

**Common Legitimate Triggers:**
- In-house developed applications
- Legacy third-party software
- Portable applications (non-installed)

**Resolution:**
- Document unsigned applications in your environment
- Consider code-signing internal applications
- Create exceptions for validated unsigned tools

</details>

<details>
<summary><b>Child Process (Event ID 10)</b></summary>

**Common Legitimate Triggers:**
- Office macros (legitimate business automation)
- PowerShell scripts launching processes
- Build systems (MSBuild, Maven, Gradle)
- Administrative scripts

**Resolution:**
- Review business processes using Office macros
- Document legitimate automation workflows
- Consider alternatives to macro-based automation

</details>

<details>
<summary><b>Image Load (Event IDs 5, 6, 7)</b></summary>

**Common Legitimate Triggers:**
- Applications on network shares
- DLLs from mapped drives
- Portable applications

**Resolution:**
- Migrate critical applications to local installation
- Document necessary network dependencies
- Use PreferSystem32 to prefer local system DLLs

</details>

---

### 🚀 Transition to Block Mode (After 30+ Day Audit Period)

<details>
<summary><b>Step-by-Step Enforcement Process</b></summary>

<br>

**Phase 1: Low-Risk Protections (Week 1-2)**

Enable the following protections first as they have minimal false positive rate:

1. **SEHOP** - Rarely causes false positives
2. **Font Disable** - Modern applications use system fonts

**XML Changes:**
```xml
<!-- Change from Audit to Enable -->
<SystemConfig>
    <SEHOP Enable="true" />
    <FontDisable Enable="true" />
</SystemConfig>
```

---

**Phase 2: Medium-Risk Protections (Week 3-4)**

Enable protections with moderate false positive potential:

1. **Binary Signature** - After documenting legitimate unsigned apps
2. **Image Load** - After reviewing network dependencies

**XML Changes:**
```xml
<SystemConfig>
    <BinarySignature 
        MicrosoftSignedOnly="true" 
        AllowStoreSignedBinaries="true"
        EnforceModuleDependencySigning="true" 
    />
    <ImageLoad 
        BlockRemoteImageLoads="true" 
        BlockLowLabelImageLoads="true"
    />
</SystemConfig>
```

---

**Phase 3: High-Risk Protections (Week 5-6)**

Enable protections requiring careful validation:

1. **Dynamic Code** - With application-specific exceptions
2. **Child Process** - With documented business process exceptions

**XML Changes:**
```xml
<SystemConfig>
    <DynamicCode Enable="true" />
    <ChildProcess Enable="true" />
</SystemConfig>
```

**Application Exceptions Example:**
```xml
<!-- Allow Visual Studio debugger to use dynamic code -->
<AppConfig Executable="devenv.exe">
    <DynamicCode Enable="false" />
</AppConfig>
```

---

**Phase 4: Payload Protections (Week 7+)**

Enable advanced ROP mitigations:

**XML Changes:**
```xml
<SystemConfig>
    <Payload 
        EnableExportAddressFilter="true"
        EnableExportAddressFilterPlus="true"
        EnableImportAddressFilter="true"
        EnableRopStackPivot="true"
        EnableRopCallerCheck="true"
        EnableRopSimExec="true"
    />
</SystemConfig>
```

---

**Rollback Plan:**

If issues occur after enforcement:

```powershell
# Immediately revert to audit mode
# Option 1: Via GPO - Change XML back to Audit="true"
# Option 2: Via PowerShell (temporary)
Set-ProcessMitigation -System -Disable DynamicCode
Set-ProcessMitigation -System -Disable ChildProcess
```

</details>

---

### 🔗 Integration with SIEM/Sentinel

<details>
<summary><b>Azure Sentinel Configuration</b></summary>

<br>

**Add Data Collection Rule for Exploit Protection Events:**

1. Navigate to **Azure Portal → Log Analytics Workspace**
2. Select **Data Collection Rules**
3. Add Windows Event Logs:
   - `Microsoft-Windows-Security-Mitigations/UserMode`
   - `Microsoft-Windows-Security-Mitigations/KernelMode`

**KQL Query Examples:**

**All Exploit Protection Events (Last 7 Days):**
```kql
Event
| where EventLog == "Microsoft-Windows-Security-Mitigations/UserMode"
| where TimeGenerated > ago(7d)
| summarize count() by EventID, Computer
| order by count_ desc
```

**Critical ROP Protection Events:**
```kql
Event
| where EventLog == "Microsoft-Windows-Security-Mitigations/UserMode"
| where EventID in (19, 20, 21, 35)  // ROP + Shadow Stack
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
```

**Top Applications Triggering Protections:**
```kql
Event
| where EventLog == "Microsoft-Windows-Security-Mitigations/UserMode"
| extend ProcessName = extract(@"Process Name:\s+(.+?)\\r\\n", 1, RenderedDescription)
| where isnotempty(ProcessName)
| summarize count() by ProcessName, EventID
| order by count_ desc
| take 20
```

**Dynamic Code Injection Attempts:**
```kql
Event
| where EventLog == "Microsoft-Windows-Security-Mitigations/UserMode"
| where EventID == 12  // Dynamic Code
| project TimeGenerated, Computer, RenderedDescription
| order by TimeGenerated desc
```

</details>

---

### 📚 Additional Resources

**Microsoft Documentation:**
- [Exploit Protection Overview](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-exploit-protection)
- [Exploit Protection Reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference)
- [Customize Exploit Protection](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/customize-exploit-protection)
- [Import/Export Exploit Protection Configuration](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/import-export-exploit-protection-emet-xml)

**Security Research:**
- [Understanding ROP Attacks](https://blog.talosintelligence.com/2023/05/understanding-return-oriented-programming.html)
- [Intel CET Deep Dive](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html)
- [Exploit Mitigation Techniques](https://docs.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10)

---

### ⚠️ Important Deployment Notes

> **🔴 XML File Format Requirements**  
> - Use plain `<MitigationPolicy>` XML format for GPO deployment
> - Do NOT use Intune/MDM SyncML-wrapped format
> - Verify file is accessible by Domain Computers via UNC path
> - Test XML syntax before deployment using `Get-ProcessMitigation -Name test.exe -File path\to\config.xml`

> **💡 Hardware Requirements for CET (Shadow Stack)**  
> - Intel 11th Gen (Tiger Lake) or newer processors
> - AMD Zen 3 or newer processors
> - Windows 11 or Windows Server 2022+
> - UEFI firmware with CET support enabled

> **⚙️ Service Restart Required**  
> After XML configuration changes:
> ```powershell
> Restart-Service -Name WinDefend -Force
> ```

> **📊 Expected Audit Volume**  
> - Low activity: ~10-50 events/day
> - Medium activity: ~50-200 events/day  
> - High activity (dev environments): ~200-1000+ events/day
> - Increase log size accordingly

---

</details>

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
- [ ] Enabled File Hash Computation Feature
- [ ] Enabled File Download & Attachment Scanning
- [ ] Enabled Script Scanning
- [ ] Enabled Archive Scanning
- [ ] Configured Cloud Block Level
- [ ] Enabled Monitor file and program activity on your computer
- [ ] Configure Extended Cloud Check (10 seconds)
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

### 🖥️ Deployment Resources

**Need to Build a Lab Environment?**

If you need to provision your lab infrastructure from scratch, consider using the **Open Threat Research Forge (OTRF) Blacksmith** project:

🔗 **MSFT Sentinel-2-Go:** https://github.com/OTRF/Microsoft-Sentinel2Go

🔗 **OTRF Blacksmith:** https://github.com/OTRF/Blacksmith

Blacksmith provides automated deployment templates for:
- Windows Server Domain Controllers (2019 & Up)
- Windows 11 clients
- Active Directory environments
- Pre-configured logging and detection scenarios
- Integration with cloud security tools

**✔️ Alternative Options:**
- Microsoft Evaluation Center: https://www.microsoft.com/en-us/evalcenter/
- Azure Virtual Machines with pre-configured templates
- KVM/Linux, Hyper-V or VMware local lab deployments
  - [Proxmox Lab Guide](https://www.youtube.com/watch?v=oPnojnjUxQE)
- Infrastructure as Code (IaC) solutions
  - [Azure Terraformer](https://www.youtube.com/@azure-terraformer)
  - [MSFT Bicep](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/)
  - [Terraform](https://azure.github.io/Azure-Verified-Modules/)
  
---

## 📞 Support

If you encounter issues during the workshop, contact your instructor or refer to the Microsoft Learn documentation.

**Happy Hunting! 🎯🏆**
