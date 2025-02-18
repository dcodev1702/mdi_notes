<#
  THINGS TO ADD TO VBD
    - Add the Sizing tool and run 2 days before VBD
    - Add Proxy Demo and push MDI install through Squid Proxy w/ authentication

#>
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
$proxy_creds = New-Object System.Management.Automation.PSCredential ("lorenzo", (ConvertTo-SecureString "Passw0rd123" -AsPlainText -Force))
Invoke-WebRequest -Uri http://www.google.com -Proxy $proxy_url -ProxyCredential $proxy_creds -Verbose

Set-MDISensorProxyConfiguration -ProxyUrl $proxy_url -ProxyCredential $proxy_creds
Get-MDISensorProxyConfiguration


# INSTALL MDI GPO's for AD-DS
Set-MDIConfiguration -Mode Domain -Configuration All -GpoNamePrefix "MDI" -Identity $Identity

# Validate MDI Configuration 
Get-MDIConfiguration -Mode Domain -Configuration All -Identity MDIgMSA -GpoNamePrefix "MDI"

New-MDIConfigurationReport -Mode Domain -GpoNamePrefix "MDI" -Path C:\Temp


# Run On the Linux Squid Proxy Server
sudo tcpdump -i eth0 tcp port 3128 -v

<#
INSTALL SQUID PROXY
-------------------
https://github.com/thelebster/docker-squid-simple-proxy/tree/master

sudo apt-get install squid apache2-utils
sudo htpasswd -c /etc/squid/passwords [USERNAME]

Test the password store
/usr/lib/squid3/basic_ncsa_auth /etc/squid/passwords

/etc/squid/squid.conf

acl localnet src 0.0.0.1-0.255.255.255  # RFC 1122 "this" network (LAN)
acl localnet src 10.0.0.0/8             # RFC 1918 local private network (LAN)
acl localnet src 100.64.0.0/10          # RFC 6598 shared address space (CGN)
acl localnet src 169.254.0.0/16         # RFC 3927 link-local (directly plugged) machines
acl localnet src 172.16.0.0/12          # RFC 1918 local private network (LAN)
acl localnet src 192.168.0.0/16         # RFC 1918 local private network (LAN)
acl localnet src fc00::/7               # RFC 4193 local private network range
acl localnet src fe80::/10              # RFC 4291 link-local (directly plugged) machines

acl SSL_ports port 443
acl Safe_ports port 80# http
acl Safe_ports port 21# ftp
acl Safe_ports port 443# https
acl Safe_ports port 70# gopher
acl Safe_ports port 210# wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280# http-mgmt
acl Safe_ports port 488# gss-http
acl Safe_ports port 591# filemaker
acl Safe_ports port 777# multiling http

# Deny requests to certain unsafe ports
http_access deny !Safe_ports

# Deny CONNECT to other than secure SSL ports
http_access deny CONNECT !SSL_ports

# Only allow cachemgr access from localhost
http_access allow localhost manager
http_access deny manager


# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS
# include /etc/squid/conf.d/*.conf  # non-containerized install
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords
auth_param basic realm proxy
acl authenticated proxy_auth REQUIRED
auth_param basic credentialsttl 24 hours
auth_param basic realm Squid proxy-caching web server
auth_param basic casesensitive off


# And finally deny all other access to this proxy
http_access allow localhost
http_access allow localnet
http_access allow authenticated
http_access deny all
dns_v4_first on
ipv6 off
forwarded_for delete
via off
http_port 3128

#>

# htpasswd file: /etc/squid/passwords
lorenzo:$apr1$mMw0DgVt$SFeV95RAvvF..Am49Lh4o/


# BUILD & RUN IN DOCKER
docker build -t digitalkali/squid-proxy .
docker push digitalkali/squid-proxy

# RUN IN DOCKER
docker run -d --name squid-container -e TZ=UTC -p 3128:3128 digitalkali/squid-proxy

# RUN IN AZURE CONTAINER INSTANCE
az container create --resource-group MIR --location eastus2 --name squid-proxy-container --image digitalkali/squid-proxy:latest --cpu 1 --memory 2 --vnet ZoADLab-VNET --subnet ContainerNet --ports 3128 --environment-variables http_proxy="http://localhost:3128" https_proxy="http://localhost:3128"
