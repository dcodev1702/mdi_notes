# XDR Lab Environment - Azure Deployment Guide

This ARM template deploys a complete XDR (Extended Detection and Response) lab environment in Microsoft Azure, featuring a Windows Active Directory domain with domain-joined Windows 11 workstations and an Ubuntu Linux server.

---

## Environment Overview

| VM Name | Operating System | LAN IP | Public IP | Domain Joined |
|---------|------------------|--------|-----------|---------------|
| dc-xdr-lab-1 | Windows Server 2022 Datacenter Azure Edition | 10.0.0.4 | Yes | Domain Controller |
| win11-xdr-lab-1 | Windows 11 Enterprise 25H2 | 10.0.0.5 | No | Yes |
| win11-xdr-lab-2 | Windows 11 Enterprise 25H2 | 10.0.0.7 | No | Yes |
| linux-xdr-lab-1 | Ubuntu 24.04 LTS | 10.0.0.6 | No | No |

---

## Domain Information

| Property | Value |
|----------|-------|
| Domain Name (FQDN) | `xdr-lab.local` |
| NetBIOS Name | `XDR-LAB` |
| Domain Controller | dc-xdr-lab-1 (10.0.0.4) |
| DNS Server | 10.0.0.4 |

---

## Network Configuration

| Resource | Value |
|----------|-------|
| Virtual Network | xdr-lab-vnet |
| Address Space | 10.0.0.0/16 |
| Subnet | default (10.0.0.0/24) |
| Network Security Group | xdr-lab-nsg |
| Region | East US 2 |

### Open Ports (NSG Rules)

| Port | Protocol | Service | Source |
|------|----------|---------|--------|
| 3389 | TCP | RDP (Remote Desktop) | Configurable (default: *) |
| 22 | TCP | SSH | Configurable (default: *) |

> **Security Note:** The default configuration allows RDP/SSH from any source (`*`). For production or internet-facing labs, restrict `allowedRdpSource` to your specific IP address (e.g., `203.0.113.10/32`).

---

## Credentials

| Property | Value |
|----------|-------|
| Local Admin Username | `azureadmin` |
| Domain Admin Username | `azureadmin` |
| Password | Set during deployment |

---

## Connecting to Virtual Machines

### Option 1: Azure Bastion (Recommended)

Azure Bastion provides secure RDP/SSH access without exposing public IPs on workstations.

#### Windows VMs (Domain-Joined)

1. Navigate to the VM in Azure Portal
2. Click **Connect** > **Bastion**
3. Enter credentials:
   - **Username:** `azureadmin@xdr-lab.local`
   - **Password:** Your deployment password

#### Domain Controller (dc-xdr-lab-1)

1. Navigate to the VM in Azure Portal
2. Click **Connect** > **Bastion**
3. Enter credentials:
   - **Username:** `azureadmin@xdr-lab.local` or `XDR-LAB\azureadmin`
   - **Password:** Your deployment password

#### Linux VM (linux-xdr-lab-1)

1. Navigate to the VM in Azure Portal
2. Click **Connect** > **Bastion**
3. Enter credentials:
   - **Username:** `azureadmin`
   - **Password:** Your deployment password

### Option 2: Direct RDP (Domain Controller Only)

The Domain Controller has a public IP address for direct RDP access.

1. Get the public IP from Azure Portal or deployment outputs
2. Open Remote Desktop Connection
3. Enter the public IP address
4. Login with:
   - **Username:** `azureadmin@xdr-lab.local`
   - **Password:** Your deployment password

### Option 3: RDP via Domain Controller (Jump Box)

For workstations without public IPs:

1. RDP to the Domain Controller (dc-xdr-lab-1) using its public IP
2. From the DC, open Remote Desktop Connection
3. Connect to internal IPs:
   - win11-xdr-lab-1: `10.0.0.5`
   - win11-xdr-lab-2: `10.0.0.7`
   - linux-xdr-lab-1: `10.0.0.6` (SSH)

---

## Deployment Instructions

### Prerequisites

- Azure subscription with sufficient permissions
- Azure CLI or PowerShell installed
- Password meeting complexity requirements (12+ characters, mixed case, numbers, symbols)

### Deploy via Azure CLI

```bash
# Create resource group
az group create --name xdr-lab-rg --location eastus2

# Deploy the template
az deployment group create \
  --subscription "1dd93b0d-9968-4d42-8d5b-510d621c7866" \
  --resource-group "xdr-lab-rg" \
  --template-file "xdr-lab-deploy-v4.json" \
  --parameters adminPassword="YourSecurePassword123!"
```

### Deploy via PowerShell

```powershell
# Create resource group
New-AzResourceGroup -Name "xdr-lab-rg" -Location "eastus2"

# Deploy the template
New-AzResourceGroupDeployment `
  -ResourceGroupName "xdr-lab-rg" `
  -TemplateFile "xdr-lab-deploy-v4.json" `
  -adminPassword (ConvertTo-SecureString "YourSecurePassword123!" -AsPlainText -Force)
```

### Deploy via Azure Portal

1. Go to **Azure Portal** > **Deploy a custom template**
2. Click **Build your own template in the editor**
3. Paste the contents of `xdr-lab-deploy-v4.json`
4. Click **Save**
5. Fill in the parameters:
   - **Subscription:** Select your subscription
   - **Resource Group:** Create new `xdr-lab-rg`
   - **Admin Password:** Enter a secure password
6. Click **Review + create** > **Create**

---

## Deployment Timeline

| Phase | Duration | Description |
|-------|----------|-------------|
| Network Resources | ~2 min | NSG, VNet, Public IP, NICs |
| Domain Controller VM | ~5 min | Windows Server 2022 deployment |
| AD Forest Creation | ~10-15 min | AD DS installation and forest creation |
| VNET DNS Update | ~1 min | Point VNET DNS to DC |
| Windows 11 VMs | ~5-7 min | Both workstations deploy in parallel |
| Domain Join | ~3-5 min | Both workstations join domain |
| Linux VM | ~3-5 min | Ubuntu deployment (parallel) |
| **Total** | **~20-30 min** | Complete environment ready |

---

## Post-Deployment Verification

### Verify Domain Controller

1. RDP to dc-xdr-lab-1
2. Open **Server Manager** > Verify AD DS and DNS roles are installed
3. Open **Active Directory Users and Computers** > Verify domain `xdr-lab.local` exists
4. Check **Computers** OU for domain-joined workstations

### Verify Domain Join (Windows 11 VMs)

1. Connect to win11-xdr-lab-1 or win11-xdr-lab-2
2. Open **System Properties** (Win + Pause/Break)
3. Verify "Domain: xdr-lab.local" is displayed
4. Open Command Prompt and run:
   ```cmd
   whoami
   # Should show: xdr-lab\azureadmin

   nltest /dsgetdc:xdr-lab.local
   # Should return DC information
   ```

### Verify Network Connectivity

From any Windows VM, test connectivity:

```cmd
# Ping Domain Controller
ping 10.0.0.4

# Ping other workstations
ping 10.0.0.5
ping 10.0.0.7

# Ping Linux VM
ping 10.0.0.6

# Test DNS resolution
nslookup dc-xdr-lab-1.xdr-lab.local
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

### Cannot RDP to Domain Controller

- Verify NSG rules allow port 3389 from your IP
- Check that the VM is running in Azure Portal
- Confirm the public IP is assigned

### Domain Join Failed

- Ensure DC deployment completed successfully before workstations
- Verify DNS is set to 10.0.0.4 on workstation NICs
- Check that the domain `xdr-lab.local` is resolvable

### Cannot Reach Workstations from DC

- Verify VMs are running
- Check Windows Firewall settings on workstations
- Confirm all VMs are on the same subnet (10.0.0.0/24)

### Linux VM SSH Issues

- Use Azure Bastion or SSH from within the VNET
- Verify NSG allows port 22
- Username is `azureadmin` (not domain credentials)

---

## Files

| File | Description |
|------|-------------|
| `xdr-lab-deploy-v4.json` | Main ARM template (current version) |
| `xdr-lab-deploy-v3.json` | Previous version (single Windows 11 VM) |
| `README.md` | This documentation |

---

## Support

For issues or questions about this lab environment:

- Review Azure deployment logs in the Portal
- Check VM boot diagnostics
- Verify all extensions completed successfully

---

**Happy Hunting!**
