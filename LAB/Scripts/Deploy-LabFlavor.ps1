[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('XDR-LAB', 'XDR-TEST', 'SVR-CORE', 'DES-LAB')]
    [string]$Flavor,

    [string]$SubscriptionName = 'zolab',
    [string]$Location = 'eastus2',
    [string]$VmSize = 'Standard_D4ads_v7',
    [string]$ConnectivityResourceGroup = 'Connectivity',
    [string]$ExistingVnetName = 'Zolab-vNet',
    [string]$XdrLabResourceGroup = 'xdr-lab-rg',
    [string]$XdrTestResourceGroup = 'xdr-lab-test-rg',
    [string]$SvrCoreResourceGroup = 'applkr-lab-rg',
    [string]$DesLabResourceGroup = 'des-lab-rg',
    [string]$SharedDnsServerResourceGroup = 'xdr-lab-rg',
    [string]$SharedDnsServerVmName = 'dc-xdr-lab-1',
    [string]$SvrCoreSubnetName = 'applkr-lab-subnet',
    [string]$SvrCoreParameterFile,
    [string]$LinuxSshPublicKeyPath,
    [string]$AdminUsername,
    [securestring]$AdminPassword,
    [string]$PasswordPlainText,
    [switch]$ValidateOnly,
    [switch]$WhatIf,
    [switch]$Delete,
    [switch]$ConfirmDelete
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $PSCommandPath
$labDirectory = Split-Path -Parent $scriptDirectory
$plainPassword = $null

if (-not $SvrCoreParameterFile) {
    $SvrCoreParameterFile = Join-Path $labDirectory 'applkr-lab-dc-core.parameters.json'
}

function Write-Step {
    param([string]$Message)

    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Fail {
    param([string]$Message)

    throw $Message
}

function ConvertTo-PlainText {
    param([Parameter(Mandatory)][securestring]$Value)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)

    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Resolve-PlainPassword {
    param(
        [securestring]$SecurePassword,
        [string]$ProvidedPlainPassword,
        [string]$PromptFlavor
    )

    if ($SecurePassword -and $ProvidedPlainPassword) {
        Fail 'Specify either -AdminPassword or -PasswordPlainText, not both.'
    }

    if ($ProvidedPlainPassword) {
        return $ProvidedPlainPassword
    }

    if ($SecurePassword) {
        return (ConvertTo-PlainText -Value $SecurePassword)
    }

    $promptedPassword = Read-Host -Prompt "Enter the administrator password for $PromptFlavor" -AsSecureString
    return (ConvertTo-PlainText -Value $promptedPassword)
}

function Invoke-Az {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$Quiet
    )

    $output = & az @Arguments 2>&1

    if ($LASTEXITCODE -ne 0) {
        $commandText = 'az ' + ($Arguments -join ' ')
        Fail "Azure CLI command failed: $commandText`n$output"
    }

    if (-not $Quiet -and $output) {
        $output
    }

    return $output
}

function Get-AzJson {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $output = Invoke-Az -Arguments $Arguments -Quiet
    if (-not $output) {
        return $null
    }

    return ($output | ConvertFrom-Json)
}

function Ensure-AzCli {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        Fail "Azure CLI ('az') was not found in PATH. Install Azure CLI first."
    }
}

function Ensure-AzureContext {
    param(
        [Parameter(Mandatory)][string]$Subscription,
        [Parameter(Mandatory)][string]$ConnectivityRg,
        [Parameter(Mandatory)][string]$VnetName
    )

    try {
        $null = Get-AzJson -Arguments @('account', 'show', '--output', 'json')
    }
    catch {
        Fail "Azure CLI is not signed in. Run 'az login' and then rerun this script."
    }

    Write-Step "Selecting Azure subscription '$Subscription'."
    Invoke-Az -Arguments @('account', 'set', '--subscription', $Subscription) -Quiet

    $context = Get-AzJson -Arguments @(
        'account', 'show',
        '--query', '{subscription:name,id:id,user:user.name,tenant:tenantId}',
        '--output', 'json'
    )

    Write-Step "Using subscription '$($context.subscription)' ($($context.id)) as $($context.user)."

    try {
        $null = Get-AzJson -Arguments @('group', 'show', '--name', $ConnectivityRg, '--output', 'json')
        $null = Get-AzJson -Arguments @(
            'network', 'vnet', 'subnet', 'show',
            '--resource-group', $ConnectivityRg,
            '--vnet-name', $VnetName,
            '--name', 'default',
            '--query', '{id:id}',
            '--output', 'json'
        )
    }
    catch {
        Fail "Signed in, but unable to access required shared networking in resource group '$ConnectivityRg'. Confirm you are using the '$Subscription' subscription and have access."
    }
}

function Ensure-FileExists {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Fail "$Description not found at '$Path'."
    }
}

function Ensure-XdrLabKey {
    param([Parameter(Mandatory)][string]$PublicKeyPath)

    Ensure-FileExists -Path $PublicKeyPath -Description 'SSH public key'

    $publicKey = (Get-Content -LiteralPath $PublicKeyPath -Raw).Trim()
    if ($publicKey -notmatch '^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp\d+)\s+') {
        Fail "The SSH public key at '$PublicKeyPath' does not look like an OpenSSH public key."
    }

    return $publicKey
}

function Ensure-SvrCorePrerequisites {
    param(
        [Parameter(Mandatory)][string]$DnsServerResourceGroup,
        [Parameter(Mandatory)][string]$DnsServerVmName,
        [Parameter(Mandatory)][string]$ParameterFilePath
    )

    Write-Step 'Checking shared DNS dependency for SVR-CORE.'
    Ensure-FileExists -Path $ParameterFilePath -Description 'SVR-CORE parameter file'

    try {
        $null = Get-AzJson -Arguments @(
            'vm', 'show',
            '--resource-group', $DnsServerResourceGroup,
            '--name', $DnsServerVmName,
            '--query', '{name:name}',
            '--output', 'json'
        )
    }
    catch {
        Fail "SVR-CORE expects the shared DNS server '$DnsServerVmName' in resource group '$DnsServerResourceGroup'. Deploy the shared DNS server first or override -SharedDnsServerResourceGroup and -SharedDnsServerVmName."
    }
}

function Get-FlavorMetadata {
    param([Parameter(Mandatory)][string]$SelectedFlavor)

    switch ($SelectedFlavor) {
        'XDR-LAB' {
            return @{
                ResourceGroup = $XdrLabResourceGroup
                TemplateFile  = (Join-Path $labDirectory 'xdr-lab-deploy-v4.json')
            }
        }
        'XDR-TEST' {
            return @{
                ResourceGroup = $XdrTestResourceGroup
                TemplateFile  = (Join-Path $labDirectory 'xdr-lab-test-dc.json')
            }
        }
        'DES-LAB' {
            return @{
                ResourceGroup = $DesLabResourceGroup
                TemplateFile  = (Join-Path $labDirectory 'des-lab\des-lab-deploy-v1.json')
            }
        }
        'SVR-CORE' {
            return @{
                ResourceGroup              = $SvrCoreResourceGroup
                TemplateFile               = (Join-Path $labDirectory 'applkr-lab-dc-core.json')
                ParameterFile              = $SvrCoreParameterFile
                CleanupSubnetName          = $SvrCoreSubnetName
                CleanupSubnetResourceGroup = $ConnectivityResourceGroup
                CleanupVnetName            = $ExistingVnetName
            }
        }
        default {
            Fail "Unsupported flavor '$SelectedFlavor'."
        }
    }
}

function Get-DeploymentParameters {
    param(
        [Parameter(Mandatory)][hashtable]$FlavorMetadata,
        [Parameter(Mandatory)][string]$SelectedFlavor,
        [Parameter(Mandatory)][string]$SelectedLocation,
        [Parameter(Mandatory)][string]$SelectedVmSize,
        [Parameter(Mandatory)][string]$SelectedConnectivityResourceGroup,
        [Parameter(Mandatory)][string]$SelectedExistingVnetName,
        [Parameter(Mandatory)][string]$SelectedAdminUsername,
        [Parameter(Mandatory)][string]$PlainPassword,
        [Parameter(Mandatory)][string]$SelectedSshPublicKeyPath,
        [Parameter(Mandatory)][string]$SelectedSharedDnsServerResourceGroup,
        [Parameter(Mandatory)][string]$SelectedSharedDnsServerVmName,
        [Parameter(Mandatory)][string]$SelectedSvrCoreSubnetName
    )

    switch ($SelectedFlavor) {
        'XDR-LAB' {
            $sshPublicKey = Ensure-XdrLabKey -PublicKeyPath $SelectedSshPublicKeyPath

            return @(
                "adminUsername=$SelectedAdminUsername"
                "windowsAdminPassword=$PlainPassword"
                "connectivityResourceGroup=$SelectedConnectivityResourceGroup"
                "location=$SelectedLocation"
                "vmSize=$SelectedVmSize"
                "linuxSshPublicKey=$sshPublicKey"
            )
        }
        'DES-LAB' {
            $sshPublicKey = Ensure-XdrLabKey -PublicKeyPath $SelectedSshPublicKeyPath

            return @(
                "adminUsername=$SelectedAdminUsername"
                "windowsAdminPassword=$PlainPassword"
                "connectivityResourceGroup=$SelectedConnectivityResourceGroup"
                "location=$SelectedLocation"
                "vmSize=$SelectedVmSize"
                "linuxSshPublicKey=$sshPublicKey"
            )
        }
        'XDR-TEST' {
            return @(
                "adminUsername=$SelectedAdminUsername"
                "windowsAdminPassword=$PlainPassword"
                "connectivityResourceGroup=$SelectedConnectivityResourceGroup"
                "location=$SelectedLocation"
                "vmSize=$SelectedVmSize"
            )
        }
        'SVR-CORE' {
            Ensure-SvrCorePrerequisites `
                -DnsServerResourceGroup $SelectedSharedDnsServerResourceGroup `
                -DnsServerVmName $SelectedSharedDnsServerVmName `
                -ParameterFilePath $FlavorMetadata.ParameterFile

            return @(
                "@$($FlavorMetadata.ParameterFile)"
                "adminPassword=$PlainPassword"
                "adminUsername=$SelectedAdminUsername"
                "location=$SelectedLocation"
                "vmSize=$SelectedVmSize"
                "existingVnetResourceGroup=$SelectedConnectivityResourceGroup"
                "existingVnetName=$SelectedExistingVnetName"
                "sharedDnsServerResourceGroup=$SelectedSharedDnsServerResourceGroup"
                "sharedDnsServerVmName=$SelectedSharedDnsServerVmName"
                "domainControllerSubnetName=$SelectedSvrCoreSubnetName"
            )
        }
        default {
            Fail "Unsupported flavor '$SelectedFlavor'."
        }
    }
}

function Wait-ForResourceGroupDeletion {
    param([Parameter(Mandatory)][string]$ResourceGroupName)

    $deadline = (Get-Date).AddMinutes(10)

    do {
        Start-Sleep -Seconds 15
        $exists = (Invoke-Az -Arguments @('group', 'exists', '--name', $ResourceGroupName) -Quiet | Select-Object -Last 1).ToString().Trim()
        if ($exists -eq 'false') {
            return
        }
    } while ((Get-Date) -lt $deadline)

    Fail "Timed out waiting for resource group '$ResourceGroupName' to be deleted."
}

function Remove-FlavorResources {
    param([Parameter(Mandatory)][hashtable]$FlavorMetadata)

    $resourceGroupName = $FlavorMetadata.ResourceGroup

    if (-not $ConfirmDelete) {
        $confirmation = Read-Host -Prompt "Delete resources for $Flavor in resource group '$resourceGroupName'? Type YES to continue"
        if ($confirmation -cne 'YES') {
            Fail 'Delete operation cancelled.'
        }
    }

    $exists = (Invoke-Az -Arguments @('group', 'exists', '--name', $resourceGroupName) -Quiet | Select-Object -Last 1).ToString().Trim()

    if ($exists -eq 'true') {
        Write-Step "Deleting resource group '$resourceGroupName'."
        Invoke-Az -Arguments @('group', 'delete', '--name', $resourceGroupName, '--yes', '--no-wait') -Quiet
        Wait-ForResourceGroupDeletion -ResourceGroupName $resourceGroupName
        Write-Step "Resource group '$resourceGroupName' deleted."
    }
    else {
        Write-Step "Resource group '$resourceGroupName' does not exist."
    }

    if ($FlavorMetadata.ContainsKey('CleanupSubnetName')) {
        $subnetName = $FlavorMetadata.CleanupSubnetName
        $subnetResourceGroup = $FlavorMetadata.CleanupSubnetResourceGroup
        $vnetName = $FlavorMetadata.CleanupVnetName

        try {
            $null = Get-AzJson -Arguments @(
                'network', 'vnet', 'subnet', 'show',
                '--resource-group', $subnetResourceGroup,
                '--vnet-name', $vnetName,
                '--name', $subnetName,
                '--query', '{name:name}',
                '--output', 'json'
            )

            Write-Step "Deleting subnet '$subnetName' from virtual network '$vnetName'."
            Invoke-Az -Arguments @(
                'network', 'vnet', 'subnet', 'delete',
                '--resource-group', $subnetResourceGroup,
                '--vnet-name', $vnetName,
                '--name', $subnetName
            ) -Quiet
        }
        catch {
            Write-Step "Subnet '$subnetName' was not found in virtual network '$vnetName'."
        }
    }
}

if ($ValidateOnly -and $WhatIf) {
    Fail 'Use either -ValidateOnly or -WhatIf, not both.'
}

if ($Delete -and ($ValidateOnly -or $WhatIf)) {
    Fail 'Use -Delete by itself. It cannot be combined with -ValidateOnly or -WhatIf.'
}

Ensure-AzCli

try {
    Ensure-AzureContext -Subscription $SubscriptionName -ConnectivityRg $ConnectivityResourceGroup -VnetName $ExistingVnetName

    $flavorMetadata = Get-FlavorMetadata -SelectedFlavor $Flavor

    if ($Delete) {
        Remove-FlavorResources -FlavorMetadata $flavorMetadata
        return
    }

    if (-not $AdminUsername) {
        switch ($Flavor) {
            'SVR-CORE' { $AdminUsername = 'azureadmin' }
            'DES-LAB'  { $AdminUsername = 'destiny' }
            default    { $AdminUsername = 'lorenzo' }
        }
    }

    if (-not $LinuxSshPublicKeyPath) {
        switch ($Flavor) {
            'DES-LAB' { $LinuxSshPublicKeyPath = Join-Path $labDirectory 'des-lab\des-lab-linux-key.pub' }
            default   { $LinuxSshPublicKeyPath = Join-Path $HOME '.ssh\linux-xdr-lab-1.pub' }
        }
    }

    $plainPassword = Resolve-PlainPassword -SecurePassword $AdminPassword -ProvidedPlainPassword $PasswordPlainText -PromptFlavor $Flavor

    $deploymentParameters = Get-DeploymentParameters `
        -FlavorMetadata $flavorMetadata `
        -SelectedFlavor $Flavor `
        -SelectedLocation $Location `
        -SelectedVmSize $VmSize `
        -SelectedConnectivityResourceGroup $ConnectivityResourceGroup `
        -SelectedExistingVnetName $ExistingVnetName `
        -SelectedAdminUsername $AdminUsername `
        -PlainPassword $plainPassword `
        -SelectedSshPublicKeyPath $LinuxSshPublicKeyPath `
        -SelectedSharedDnsServerResourceGroup $SharedDnsServerResourceGroup `
        -SelectedSharedDnsServerVmName $SharedDnsServerVmName `
        -SelectedSvrCoreSubnetName $SvrCoreSubnetName

    Ensure-FileExists -Path $flavorMetadata.TemplateFile -Description 'Deployment template'

    Write-Step "Ensuring resource group '$($flavorMetadata.ResourceGroup)' exists in $Location."
    Invoke-Az -Arguments @(
        'group', 'create',
        '--name', $flavorMetadata.ResourceGroup,
        '--location', $Location,
        '--output', 'none'
    ) -Quiet

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $validateArgs = @(
        'deployment', 'group', 'validate',
        '--name', "$($Flavor.ToLower())-validate-$stamp",
        '--resource-group', $flavorMetadata.ResourceGroup,
        '--template-file', $flavorMetadata.TemplateFile,
        '--output', 'json',
        '--parameters'
    ) + $deploymentParameters

    Write-Step 'Running ARM template validation.'
    $validationResult = Get-AzJson -Arguments $validateArgs
    Write-Step "Validation completed with state '$($validationResult.properties.provisioningState)'."

    if ($ValidateOnly) {
        Write-Step 'Validate-only mode complete. No deployment was started.'
        return
    }

    if ($WhatIf) {
        $whatIfArgs = @(
            'deployment', 'group', 'what-if',
            '--name', "$($Flavor.ToLower())-whatif-$stamp",
            '--resource-group', $flavorMetadata.ResourceGroup,
            '--template-file', $flavorMetadata.TemplateFile,
            '--parameters'
        ) + $deploymentParameters

        Write-Step 'Running what-if preview.'
        Invoke-Az -Arguments $whatIfArgs
        return
    }

    $createArgs = @(
        'deployment', 'group', 'create',
        '--name', "$($Flavor.ToLower())-deploy-$stamp",
        '--resource-group', $flavorMetadata.ResourceGroup,
        '--template-file', $flavorMetadata.TemplateFile,
        '--output', 'json',
        '--parameters'
    ) + $deploymentParameters

    Write-Step "Starting deployment for $Flavor."
    $deploymentResult = Get-AzJson -Arguments $createArgs
    Write-Step "Deployment completed with state '$($deploymentResult.properties.provisioningState)'."

    if ($deploymentResult.properties.outputs) {
        Write-Step 'Deployment outputs:'
        $deploymentResult.properties.outputs.PSObject.Properties | ForEach-Object {
            Write-Host ("    {0}: {1}" -f $_.Name, $_.Value.value)
        }
    }
}
finally {
    $plainPassword = $null
}