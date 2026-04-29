# XDR Lab Environment - Azure Deployment Guide

## Related Templates

- `xdr-lab-deploy-v4.json`: full XDR lab with DC, Windows 11 endpoints, and Linux VM deployed into the existing Zolab-vNet in the Connectivity resource group.
- `xdr-lab-test-dc.json`: smoke-test template that deploys a single DC into Zolab-vNet, promotes AD, verifies internet connectivity via NAT gateway, and can be torn down cleanly.
- `applkr-lab-dc-core.json`: standalone Windows Server 2022 Server Core domain controller that adds a dedicated `10.4.2.0/26` subnet to Zolab-vNet. See `applkr-lab-dc-core-README.md` for deployment examples and login instructions.

This ARM template deploys a complete XDR (Extended Detection and Response) lab environment in Microsoft Azure, featuring a Windows Active Directory domain with domain-joined Windows 11 workstations and an Ubuntu Linux server.

---

## Environment Overview

| VM Name | Operating System | LAN IP | Public IP | Domain Joined |
|---------|------------------|--------|-----------|---------------|
| dc-xdr-lab-1 | Windows Server 2022 Datacenter Azure Edition | 10.4.0.4 | No | Domain Controller |
| win11-xdr-lab-1 | Windows 11 Enterprise 25H2 | 10.4.0.5 | No | Yes |
| win11-xdr-lab-2 | Windows 11 Enterprise 25H2 | 10.4.0.7 | No | Yes |
| linux-xdr-lab-1 | Ubuntu 24.04 LTS | 10.4.0.6 | No | No |

---

## Domain Information

| Property | Value |
|----------|-------|
| Domain Name (FQDN) | `xdr-lab.local` |
| NetBIOS Name | `XDR-LAB` |
| Domain Controller | dc-xdr-lab-1 (10.4.0.4) |
| DNS Server | 10.4.0.4 |

---

## Network Configuration

| Resource | Value |
|----------|-------|
| Virtual Network | Zolab-vNet (in Connectivity RG) |
| Address Space | 10.4.0.0/16 |
| Workload Subnet | default (10.4.0.0/24) |
| NAT Gateway | natgw-zolab (outbound internet) |
| Network Security Group | Zolab-vNet-default-nsg-eastus2 |
| Region | East US 2 |

All VMs are deployed into the existing `default` subnet of `Zolab-vNet` in the `Connectivity` resource group. Outbound internet is provided by the `natgw-zolab` NAT gateway. No Bastion host is deployed; VM access is via AVD with private network connectivity.

---

## Credentials

| Property | Value |
|----------|-------|
| Local Admin Username | `lorenzo` |
| Domain Admin Username | `lorenzo` |
| Windows Password | Set during deployment |
| Linux SSH Key | Public key provided during deployment |

---

## Connecting to Virtual Machines

### AVD with Private Network Access

All VMs are accessed via Azure Virtual Desktop (AVD) that has private network connectivity to the Zolab-vNet. No public IP addresses are assigned to any lab VMs.

#### Windows VMs (Domain-Joined)

1. Connect to your AVD session
2. RDP to the VM private IP:
   - **DC:** `10.4.0.4`
   - **Win11-1:** `10.4.0.5`
   - **Win11-2:** `10.4.0.7`
3. Enter credentials:
   - **Username:** `lorenzo@xdr-lab.local`
   - **Password:** Your deployment password

#### Linux VM (linux-xdr-lab-1)

1. Connect to your AVD session
2. SSH to `10.4.0.6`:
   - **Username:** `lorenzo`
   - **Authentication:** SSH private key matching the public key passed to `linuxSshPublicKey`

---

## Deployment Instructions

### Prerequisites

- Azure subscription with sufficient permissions
- Azure CLI or PowerShell installed
- Default deployment region is `eastus2`
- Default VM size is `Standard_D4ads_v7` (16 GB RAM, 4 vCPU)
- Windows Server 2022 VMs use the `MicrosoftWindowsServer:windowsserver2022` marketplace offer with `version=latest`.
- Windows admin password meeting complexity requirements (12+ characters, mixed case, numbers, symbols)
- SSH public key available for the Linux VM in OpenSSH format
- Existing Connectivity RG with Zolab-vNet, natgw-zolab, and Zolab-vNet-default-nsg-eastus2

Example key generation command:

```bash
ssh-keygen -t ed25519 -C "lorenzo@linux-xdr-lab-1" -f ~/.ssh/linux-xdr-lab-1
```

If Azure reports a live capacity constraint for `Standard_D4ads_v7`, use `Standard_D4as_v7` as the first fallback in the same region.

### Unified PowerShell Wrapper

Use `LAB/Scripts/Deploy-LabFlavor.ps1` to provision the supported lab flavors with a single entrypoint:

```powershell
.\LAB\Scripts\Deploy-LabFlavor.ps1 -Flavor XDR-LAB
.\LAB\Scripts\Deploy-LabFlavor.ps1 -Flavor XDR-TEST
.\LAB\Scripts\Deploy-LabFlavor.ps1 -Flavor SVR-CORE
```

### Deployment Options

All supported command-line switches for `LAB/Scripts/Deploy-LabFlavor.ps1`:

| Switch | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `-Flavor` | `XDR-LAB \| XDR-TEST \| SVR-CORE` | Yes | None | Selects the deployment flavor. |
| `-SubscriptionName` | `string` | No | `zolab` | Azure subscription name. |
| `-Location` | `string` | No | `eastus2` | Azure region for the target resource group. |
| `-VmSize` | `string` | No | `Standard_D4ads_v7` | VM size passed to the template when supported. |
| `-ConnectivityResourceGroup` | `string` | No | `Connectivity` | Shared connectivity resource group. |
| `-ExistingVnetName` | `string` | No | `Zolab-vNet` | Shared VNet name for connectivity checks and `SVR-CORE` overrides. |
| `-XdrLabResourceGroup` | `string` | No | `xdr-lab-rg` | Target resource group for `XDR-LAB`. |
| `-XdrTestResourceGroup` | `string` | No | `xdr-lab-test-rg` | Target resource group for `XDR-TEST`. |
| `-SvrCoreResourceGroup` | `string` | No | `applkr-lab-rg` | Target resource group for `SVR-CORE`. |
| `-SharedDnsServerResourceGroup` | `string` | No | `xdr-lab-rg` | Resource group containing the shared DNS server used by `SVR-CORE`. |
| `-SharedDnsServerVmName` | `string` | No | `dc-xdr-lab-1` | Shared DNS server VM name used by `SVR-CORE`. |
| `-SvrCoreSubnetName` | `string` | No | `applkr-lab-subnet` | Dedicated subnet name for `SVR-CORE` deployment and cleanup. |
| `-SvrCoreParameterFile` | `string` | No | `LAB/applkr-lab-dc-core.parameters.json` | Parameter file path for `SVR-CORE`. |
| `-LinuxSshPublicKeyPath` | `string` | No | `$HOME/.ssh/linux-xdr-lab-1.pub` | Public key path for `XDR-LAB`. |
| `-AdminUsername` | `string` | No | `lorenzo` for `XDR-LAB` and `XDR-TEST`; `azureadmin` for `SVR-CORE` | Override the template admin username. |
| `-AdminPassword` | `securestring` | No | None | SecureString password input for interactive or pre-created secure password usage. |
| `-PasswordPlainText` | `string` | No | None | Plaintext password input for automation scenarios. Do not combine with `-AdminPassword`. |
| `-ValidateOnly` | `switch` | No | `False` | Runs `az deployment group validate` only and stops before deployment. |
| `-WhatIf` | `switch` | No | `False` | Runs `az deployment group what-if` after validation and stops before deployment. |
| `-Delete` | `switch` | No | `False` | Deletes the selected flavor resource group instead of deploying. For `SVR-CORE`, also removes the dedicated subnet from the shared VNet. |
| `-ConfirmDelete` | `switch` | No | `False` | Bypasses the interactive delete confirmation prompt. Without this switch, delete mode requires typing `YES` interactively. |

Automation and cleanup examples:

```powershell
.\LAB\Scripts\Deploy-LabFlavor.ps1 -Flavor XDR-LAB -PasswordPlainText '<ENTER_STRONG_WINDOWS_PASSWORD_HERE>'
.\LAB\Scripts\Deploy-LabFlavor.ps1 -Flavor XDR-LAB -WhatIf
.\LAB\Scripts\Deploy-LabFlavor.ps1 -Flavor XDR-TEST -Delete -ConfirmDelete
.\LAB\Scripts\Deploy-LabFlavor.ps1 -Flavor SVR-CORE -Delete -ConfirmDelete -SvrCoreResourceGroup 'applkr-lab-rg'
```

Behavior:

- Targets the `zolab` subscription by default
- Verifies Azure CLI sign-in and access to the shared Connectivity resources before provisioning
- Creates the target resource group if needed
- Runs `az deployment group validate` before deployment
- For `XDR-LAB`, requires a public key at `$HOME/.ssh/linux-xdr-lab-1.pub` unless you override `-LinuxSshPublicKeyPath`
- Supports `-ValidateOnly` and `-WhatIf` for dry runs
- Supports `-Delete` for one-command cleanup; `SVR-CORE` cleanup also removes the dedicated subnet from the shared VNet
- Prompts for confirmation before deletes unless you pass `-ConfirmDelete`
- Supports `-PasswordPlainText` for automation pipelines while keeping the secure prompt as the default interactive path
- Supports resource group overrides with `-XdrLabResourceGroup`, `-XdrTestResourceGroup`, `-SvrCoreResourceGroup`, and shared dependency overrides for `SVR-CORE`

### Deploy via Azure CLI

```bash
# Create resource group
az group create --name xdr-lab-rg --location eastus2

# Deploy the template
az deployment group create \
  --resource-group "xdr-lab-rg" \
  --template-file "xdr-lab-deploy-v4.json" \
  --parameters windowsAdminPassword="<ENTER_STRONG_WINDOWS_PASSWORD_HERE>" \
               connectivityResourceGroup="Connectivity" \
               linuxSshPublicKey="$(cat ~/.ssh/linux-xdr-lab-1.pub)"
```

### Deploy via PowerShell

```powershell
# Create resource group
New-AzResourceGroup -Name "xdr-lab-rg" -Location "eastus2"

# Deploy the template
New-AzResourceGroupDeployment `
  -ResourceGroupName "xdr-lab-rg" `
  -TemplateFile "xdr-lab-deploy-v4.json" `
  -windowsAdminPassword (ConvertTo-SecureString "<ENTER_STRONG_WINDOWS_PASSWORD_HERE>" -AsPlainText -Force) `
  -connectivityResourceGroup "Connectivity" `
  -linuxSshPublicKey (Get-Content "$HOME/.ssh/linux-xdr-lab-1.pub" -Raw)
```

### Deploy via Azure Portal

1. Go to **Azure Portal** > **Deploy a custom template**
2. Click **Build your own template in the editor**
3. Paste the contents of `xdr-lab-deploy-v4.json`
4. Click **Save**
5. Fill in the parameters:
   - **Subscription:** Select your subscription
   - **Resource Group:** Create new `xdr-lab-rg`
   - **Windows Admin Password:** Enter a secure password for the Windows VMs
   - **Connectivity Resource Group:** `Connectivity` (default)
   - **Linux SSH Public Key:** Paste your Linux public key in OpenSSH format
6. Click **Review + create** > **Create**

### Redeploy Existing Lab

Use these commands when you want to redeploy into the existing lab resource group instead of creating a new one. They assume the current template defaults of `adminUsername=lorenzo`, `location=eastus2`, and Linux SSH key auth.

Azure CLI:

```bash
az deployment group create \
   --name xdr-lab-deploy-v4-eastus2-$(date +%Y%m%d-%H%M%S) \
   --resource-group xdr-lab-rg \
   --template-file LAB/xdr-lab-deploy-v4.json \
   --parameters adminUsername="lorenzo" \
                windowsAdminPassword="<ENTER_STRONG_WINDOWS_PASSWORD_HERE>" \
                connectivityResourceGroup="Connectivity" \
                location="eastus2" \
                vmSize="Standard_D4ads_v7" \
                linuxSshPublicKey="$(cat ~/.ssh/linux-xdr-lab-1.pub)"
```

Azure CLI fallback if `Standard_D4ads_v7` hits live capacity pressure:

```bash
az deployment group create \
   --name xdr-lab-deploy-v4-eastus2-$(date +%Y%m%d-%H%M%S) \
   --resource-group xdr-lab-rg \
   --template-file LAB/xdr-lab-deploy-v4.json \
   --parameters adminUsername="lorenzo" \
                windowsAdminPassword="<ENTER_STRONG_WINDOWS_PASSWORD_HERE>" \
                connectivityResourceGroup="Connectivity" \
                location="eastus2" \
                vmSize="Standard_D4as_v7" \
                linuxSshPublicKey="$(cat ~/.ssh/linux-xdr-lab-1.pub)"
```

PowerShell:

```powershell
New-AzResourceGroupDeployment `
   -Name ("xdr-lab-deploy-v4-eastus2-" + (Get-Date -Format "yyyyMMdd-HHmmss")) `
   -ResourceGroupName "xdr-lab-rg" `
   -TemplateFile "LAB/xdr-lab-deploy-v4.json" `
   -adminUsername "lorenzo" `
   -windowsAdminPassword (ConvertTo-SecureString "<ENTER_STRONG_WINDOWS_PASSWORD_HERE>" -AsPlainText -Force) `
   -connectivityResourceGroup "Connectivity" `
   -location "eastus2" `
   -vmSize "Standard_D4ads_v7" `
   -linuxSshPublicKey (Get-Content "$HOME/.ssh/linux-xdr-lab-1.pub" -Raw)
```

---

## Smoke Test Template

Use `xdr-lab-test-dc.json` to validate the Connectivity RG networking before a full lab deployment. It deploys a single DC (`dc-xdr-test-1` at `10.4.0.10`), promotes AD, and runs connectivity tests (DNS resolution, HTTPS outbound, NAT gateway public IP verification, AD promotion status).

```bash
az group create --name xdr-lab-test-rg --location eastus2

az deployment group create \
  --resource-group xdr-lab-test-rg \
  --template-file LAB/xdr-lab-test-dc.json \
  --parameters windowsAdminPassword="<ENTER_STRONG_WINDOWS_PASSWORD_HERE>"
```

Tear down after validation:

```bash
az group delete --name xdr-lab-test-rg --yes --no-wait
```

---

## Deployment Timeline

| Phase | Duration | Description |
|-------|----------|-------------|
| NAT Gateway Validation | ~1 min | Cross-RG check of natgw-zolab association |
| NICs | ~1-2 min | All network interfaces in parallel |
| Domain Controller VM | ~5 min | Windows Server 2022 deployment |
| AD Forest Creation | ~10-15 min | AD DS installation and forest creation |
| Windows 11 VMs | ~5-7 min | Both workstations deploy after AD is ready |
| Domain Join | ~3-5 min | Both workstations join domain |
| Linux VM | ~3-5 min | Ubuntu deployment (parallel with DC) |
| **Total** | **~15-25 min** | Complete environment ready |

---

## Post-Deployment Verification

### Verify Domain Controller

1. RDP to dc-xdr-lab-1 (10.4.0.4) via AVD
2. Open **Server Manager** > Verify AD DS and DNS roles are installed
3. Open **Active Directory Users and Computers** > Verify domain `xdr-lab.local` exists
4. Check **Computers** OU for domain-joined workstations

### Verify Domain Join (Windows 11 VMs)

1. Connect to win11-xdr-lab-1 or win11-xdr-lab-2 via AVD
2. Open **System Properties** (Win + Pause/Break)
3. Verify "Domain: xdr-lab.local" is displayed
4. Open Command Prompt and run:
   ```cmd
   whoami
   # Should show: xdr-lab\lorenzo

   nltest /dsgetdc:xdr-lab.local
   # Should return DC information
   ```

### Verify Network Connectivity

From any Windows VM, test connectivity:

```cmd
# Ping Domain Controller
ping 10.4.0.4

# Ping other workstations
ping 10.4.0.5
ping 10.4.0.7

# Ping Linux VM
ping 10.4.0.6

# Test DNS resolution
nslookup dc-xdr-lab-1.xdr-lab.local

# Verify outbound internet via NAT gateway
curl https://api.ipify.org
```

---

## Lab Use Cases

This environment is ideal for:

- **XDR/EDR Testing:** Deploy and test endpoint detection and response solutions
- **Active Directory Security:** Practice AD attack and defense techniques
- **Threat Hunting:** Generate and investigate security events
- **SIEM Integration:** Connect to Microsoft Sentinel or other SIEM platforms
- **Malware Analysis:** Isolated environment for malware testing
- **Security Training:** Hands-on cybersecurity exercises

---

## Clean Up

To delete all resources and stop billing:

```bash
az group delete --name xdr-lab-rg --yes --no-wait
```

Or via PowerShell:

```powershell
Remove-AzResourceGroup -Name "xdr-lab-rg" -Force -AsJob
```

---

## Troubleshooting

### Domain Join Failed

- Ensure DC deployment completed successfully before workstations
- Verify DNS is set to 10.4.0.4 on workstation NICs (configured at NIC level)
- Check that the domain `xdr-lab.local` is resolvable

### Cannot Reach Workstations from DC

- Verify VMs are running
- Check Windows Firewall settings on workstations
- Confirm all VMs are on the same subnet (10.4.0.0/24)

### No Outbound Internet

- Verify NAT gateway `natgw-zolab` is associated with the `default` subnet in Zolab-vNet
- Check deployment outputs for `natGatewayAssociated: true`
- Verify `pip-natgw-zolab` public IP is allocated

### Linux VM SSH Issues

- Connect via AVD and SSH to 10.4.0.6
- Username is `lorenzo` (not domain credentials)
- Confirm the public key passed to `linuxSshPublicKey` matches the private key you are using

---

## Files

| File | Description |
|------|-------------|
| `xdr-lab-deploy-v4.json` | Main ARM template (current version) |
| `xdr-lab-test-dc.json` | Smoke-test template for DC + connectivity validation |
| `applkr-lab-dc-core.json` | Standalone APPLKR domain controller template |
| `applkr-lab-dc-core.parameters.json` | APPLKR DC parameter values |
| `applkr-lab-dc-core-README.md` | APPLKR DC deployment guide |
| `README.md` | This documentation |

---

## Support

For issues or questions about this lab environment:

- Review Azure deployment logs in the Portal
- Check VM boot diagnostics
- Verify all extensions completed successfully

---

**Happy Hunting!**