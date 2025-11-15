<#
  THINGS TO ADD TO VBD
    - Add the Sizing tool and run 2 days before VBD
    - Add Proxy Demo and push MDI install through Squid Proxy w/ authentication

  Defender For Identity PS Module: https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/?view=defenderforidentity-latest
  
#>

Import-Module DefenderForIdentity

$Identity = "MDIgMSA"

&"C:\Windows\System32\powercfg.exe"@('/GETACTIVESCHEME')

# Enable Recycle Bin (used to build historical baseline)
Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADDomain).DNSRoot -Confirm:$false

Install-Module -Name DefenderForIdentity
Import-Module -Name DefenderForIdentity

# Enable KDS Root key to 10 hours ago since it takes 10 hours to set in
Add-kdsRootKey -EffectiveTime ((get-date).AddHours(-10))

# Upon creation of gMSA the MDI CmdLet allows RC4 and AES128 be default (bad)
New-MDIDSA -Identity $Identity -GmsaGroupName "MDISvcGroup"
Set-ADServiceAccount -Identity $Identity -DNSHostName (Get-ADDomain).DNSRoot  -KerberosEncryptionType AES256

# Inspect what we expect
Get-ADServiceAccount $Identity -Properties * | fl DNSHostName, SamAccountName, KerberosEncryptionType, ManagedPasswordIntervalInDays, PrincipalsAllowedToRetrieveManagedPassword
Test-ADServiceAccount -Identity $Identity

# Add MDIgMSA to Logon As a Service
# GPO -> Computer Config -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignemnt -> Log on as a Service
  # Values:
    # HAWK-IR\MDIgMSA$
    # NT SERVICE\ALL SERVICES

# SAM-R GPO
# Default Domain Policy -> Computer -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Network Access: Restrict clients allowed to make remote calls to SAM

    # Add Service Account -> MDIgMSA

    # ADD TO INTUNE IF NEED BE!
        # Get Security Descriptor for MDIgMSA and Administrator
        Get-ADServiceAccount -Identity MDIgMSA | Select-Object SID

        #SID: S-1-5-21-2706510929-2189218490-3368825123-1106

        #SAM-R GPO (Add MDIgMSA and Administrators group to GPO and Intune)
        #MDIgMSA: O:BAG:BAD:(A;;RC;;;BA)(A;;RC;;;S-1-5-21-2706510929-2189218490-3368825123-1106)

        #Administrators Group: 0:BAG:BAD:(A;;RC;:;BA)(A;;RC;:S-1-5-32-544)


# Configure MDI to use Squid Proxy
$proxy_url = "http://10.0.2.4:3128"   # Azure Container Instance (ACI) Container IP
$proxy_creds = New-Object System.Management.Automation.PSCredential ("squid", (ConvertTo-SecureString "Passw0rd123" -AsPlainText -Force))
Invoke-WebRequest -Uri http://www.google.com -Proxy $proxy_url -ProxyCredential $proxy_creds -Verbose

Set-MDISensorProxyConfiguration -ProxyUrl $proxy_url -ProxyCredential $proxy_creds
Get-MDISensorProxyConfiguration


# Create & Link MDI GPO's for AD-DS
Set-MDIConfiguration -Mode Domain -Configuration All -GpoNamePrefix "MDI" -Identity $Identity

# Validate MDI Configuration 
Get-MDIConfiguration -Mode Domain -Configuration All -Identity MDIgMSA -GpoNamePrefix "MDI"

New-MDIConfigurationReport -Mode Domain -GpoNamePrefix "MDI" -Path C:\Temp



