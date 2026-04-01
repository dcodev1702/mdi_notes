# DES-LAB Environment

## Overview

DES-LAB is an Active Directory lab environment deployed into Azure. It provisions a domain controller, two domain-joined Windows 11 workstations, and a Linux VM, all on a dedicated subnet within the shared Zolab-vNet.

## Lab Layout

| VM Name | OS | Private IP | Role |
|---|---|---|---|
| dc-des-lab-1 | Windows Server 2022 Datacenter | 10.4.100.4 | Domain Controller / DNS |
| win11-des-lab-1 | Windows 11 Enterprise (25H2) | 10.4.100.5 | Workstation (domain-joined) |
| linux-des-lab-1 | Ubuntu 24.04 LTS | 10.4.100.6 | Linux VM (SSH key auth) |
| win11-des-lab-2 | Windows 11 Enterprise (25H2) | 10.4.100.7 | Workstation (domain-joined) |

## Domain

- **FQDN:** des-lab.local
- **NetBIOS:** DES-LAB
- **Admin Username:** destiny

## Networking

| Resource | Name | Resource Group |
|---|---|---|
| Virtual Network | Zolab-vNet | Connectivity |
| Subnet | des-lab-sn (10.4.100.0/24) | Connectivity |
| NAT Gateway | natgw-zolab | Connectivity |
| Lab Resource Group | des-lab-rg | des-lab-rg |

The subnet, vNet, and NAT gateway are shared resources in the **Connectivity** resource group. All VMs are deployed into the **des-lab-rg** resource group.

## SSH Key

The Linux VM uses key-based authentication. The key pair is stored locally in this folder:

- **Private key:** `des-lab-linux-key`
- **Public key:** `des-lab-linux-key.pub`

These files are excluded from git via `.gitignore`.

## Deployment

### Provision

From the `LAB` directory, run:

```powershell
.\Scripts\Deploy-LabFlavor.ps1 -Flavor DES-LAB
```

You will be prompted to enter a password (minimum 12 characters). This password is used for:

- Windows local admin account on all Windows VMs
- Active Directory domain admin account
- AD DS Safe Mode recovery password

To skip the prompt, pass the password directly:

```powershell
.\Scripts\Deploy-LabFlavor.ps1 -Flavor DES-LAB -PasswordPlainText 'YourPassword123!'
```

### Validate Only (no deployment)

```powershell
.\Scripts\Deploy-LabFlavor.ps1 -Flavor DES-LAB -ValidateOnly
```

### What-If Preview

```powershell
.\Scripts\Deploy-LabFlavor.ps1 -Flavor DES-LAB -WhatIf
```

### Delete

```powershell
.\Scripts\Deploy-LabFlavor.ps1 -Flavor DES-LAB -Delete
```

You will be prompted to type `YES` to confirm. To skip the confirmation:

```powershell
.\Scripts\Deploy-LabFlavor.ps1 -Flavor DES-LAB -Delete -ConfirmDelete
```

This deletes the **des-lab-rg** resource group and all resources inside it. Shared Connectivity resources (vNet, subnet, NAT gateway) are not affected.

## RDP Access

Once the lab is provisioned, connect to the Windows VMs via RDP using the NAT gateway's public IP or Azure Bastion.

- **Username:** `DES-LAB\destiny`
- **Password:** *(password set by user during provisioning)*

## SSH Access

```bash
ssh -i des-lab-linux-key destiny@10.4.100.6
```
