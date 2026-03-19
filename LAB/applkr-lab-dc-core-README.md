# APPLKR Lab - Standalone Server Core Domain Controller

This standalone ARM template deploys a single Windows Server 2022 Server Core VM, adds a dedicated subnet to the existing XDR lab virtual network, and promotes the VM into a separate Active Directory forest.

No password is stored in this repository. Pass the administrator password at deployment time.

The template keeps the shared-network defaults generic. The working values used for this lab are provided explicitly in the deployment examples below.

## Design Summary

This deployment intentionally reuses the existing XDR lab Bastion path instead of creating a second Bastion host.

- Resource group: `applkr-lab-rg`
- Region: `eastus2`
- Existing shared VNet: `xdr-lab-vnet` in `zolab-xdr-range-001`
- Existing Bastion host: `xdr-lab-bastion`
- Dedicated subnet: `applkr-lab-subnet` (`10.0.2.0/26`)
- Domain controller VM: `dc-core`
- Static private IP: `10.0.2.4`
- Domain: `applkr-lab.local`
- NetBIOS: `APPLKRLAB`
- Admin username: `azureadmin`

## Important Behavior

- The template adds the subnet to the existing XDR lab VNet so the current Bastion host can reach the VM over its private IP.
- The template does not repoint the shared VNet DHCP DNS settings. That avoids breaking or changing the existing XDR lab.
- The VM is isolated with its own NIC-level NSG. RDP is allowed from the Bastion subnet, and all traffic from `10.0.0.0/24` to `dc-core` is allowed.
- The template configures a conditional forwarder on the shared lab DNS server so hosts in the XDR lab can resolve `applkr-lab.local` automatically.
- No endpoints are domain joined.

## Files

- Template: `LAB/applkr-lab-dc-core.json`
- Parameters: `LAB/applkr-lab-dc-core.parameters.json`

## Deployment

Create the target resource group:

```bash
az group create --name applkr-lab-rg --location eastus2
```

Validate the template:

```bash
az deployment group validate \
  --resource-group applkr-lab-rg \
  --template-file LAB/applkr-lab-dc-core.json \
  --parameters @LAB/applkr-lab-dc-core.parameters.json \
               adminPassword='<ENTER_STRONG_PASSWORD_HERE>'
```

Deploy the template:

```bash
az deployment group create \
  --name applkr-lab-dc-core-$(date +%Y%m%d-%H%M%S) \
  --resource-group applkr-lab-rg \
  --template-file LAB/applkr-lab-dc-core.json \
  --parameters @LAB/applkr-lab-dc-core.parameters.json \
               adminPassword='<ENTER_STRONG_PASSWORD_HERE>'
```

The parameter file intentionally excludes `adminPassword` so no secret is stored in the repository.

## Verification

After the deployment completes, confirm the subnet and VM wiring:

```bash
az network vnet subnet show \
  --resource-group zolab-xdr-range-001 \
  --vnet-name xdr-lab-vnet \
  --name applkr-lab-subnet \
  --query '{name:name,prefix:addressPrefix,id:id}' \
  --output table

az vm show \
  --resource-group applkr-lab-rg \
  --name dc-core \
  --show-details \
  --query '{name:name,privateIps:privateIps,powerState:powerState}' \
  --output table

az vm run-command invoke \
  --resource-group applkr-lab-rg \
  --name dc-core \
  --command-id RunPowerShellScript \
  --scripts 'Get-Service NTDS,DNS | Select-Object Name,Status; Get-ADDomain | Select-Object DNSRoot,NetBIOSName; hostname'

az vm run-command invoke \
  --resource-group zolab-xdr-range-001 \
  --name win11-xdr-lab-1 \
  --command-id RunPowerShellScript \
  --scripts 'Resolve-DnsName dc-core.applkr-lab.local | Select-Object Name,IPAddress'
```

## Login

Connect through the existing Azure Bastion host using the VM resource, private IP `10.0.2.4`, or FQDN `dc-core.applkr-lab.local`.

Azure Portal path:

- Virtual machine: `dc-core`
- Connect: `Connect` -> `Bastion`

Use one of these usernames after promotion:

- `APPLKRLAB\azureadmin`
- `azureadmin@applkr-lab.local`

No password is published in this repository.

## Starter GPOs

You can create three starter GPOs for the `Domain Controllers` OU from a management workstation by using:

- `MDE/scripts/Create-APPLKR-Starter-GPOs.ps1`

Recommended launch flow from a non-domain-joined management host:

```cmd
runas /netonly /user:APPLKRLAB\azureadmin powershell.exe
```

Then run:

```powershell
.\MDE\scripts\Create-APPLKR-Starter-GPOs.ps1
```

The script creates and links these GPOs to `OU=Domain Controllers,DC=applkr-lab,DC=local`:

- `APPLKR - DC Audit Policy`
- `APPLKR - DC PowerShell Logging`
- `APPLKR - DC Admin Access`

## Test Cleanup

Deleting the resource group removes the VM, NIC, and NSG, but the dedicated subnet lives in the shared XDR VNet and must be removed separately.

```bash
az group delete --name applkr-lab-rg --yes --no-wait

az network vnet subnet delete \
  --resource-group zolab-xdr-range-001 \
  --vnet-name xdr-lab-vnet \
  --name applkr-lab-subnet
```