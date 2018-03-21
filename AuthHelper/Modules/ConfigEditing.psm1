$CONFIG_PATH = "~\.AuthHelper.json"
$ENV_LOCAL = "Local"
$ENV_STAGING = "Staging"
$ENV_PRODUCTION = "DomainProduction"

class CredentialStore
{
    [CredentialEnvironment[]] $Environments

    AddEnvironment([CredentialEnvironment] $environment) {
        $this.Environments = $this.Environments += $environment
    }

    [CredentialEnvironment] GetEnvironmentByName([string] $name) {
        return $this.Environments | ? Name -eq $name | Select-Object -First 1
    }

    [string] ToString() {
        $envNames = [string]::Join([System.Environment]::NewLine, $this.Environments)
        return $envNames
    }
}

class CredentialEnvironment
{
    [string] $Name
    [Credentials[]] $Credentials

    CredentialEnvironment([string] $name) {
        $this.Name = $name
        $this.Credentials = @()
    }

    AddCredentials([Credentials] $creds) {
        $this.Credentials = $this.Credentials += $creds
    }

    [Credentials] GetCredentialsByClientKey([string] $clientKey) {
        return $this.Credentials | ? ClientKey -eq $clientKey | Select-Object -First 1
    }
}

class Credentials
{
    [string] $ClientKey
    [string] $ClientSecret

    Credentials([string] $clientKey, [string] $clientSecret) {
        $this.ClientKey = $clientKey
        $this.ClientSecret = $clientSecret
    }
}



function Convert-PSCustomObjectToHashtable($obj) {
    $psObj = $obj.psObject
    if (($psObj.TypeNames -contains "System.Management.Automation.PSCustomObject") -eq $false) {
        Throw "$obj is not a PSCustomObject."
    }

    $ht = @{}
    $psObj.properties | Foreach-Object { $ht[$_.Name] = $_.Value }
    Return $ht
}

function Get-AuthHelperCredentials() {
    [CmdletBinding()]
    param()
    $store = Get-AuthHelperStoreFromConfig

    $store.Environments | Foreach-Object {
        Write-Host "# "  $_.Name
        $_.Credentials | Foreach-Object {
            Write-Host $_.ClientKey  $_.ClientSecret
        }
    }
}



function Get-AuthHelperStoreFromConfig() {
    if (!(Test-Path $CONFIG_PATH)) {
        $store = [CredentialStore]::new()
        $store.AddEnvironment($ENV_LOCAL)
        $store.AddEnvironment($ENV_STAGING)
        $store.AddEnvironment($ENV_PRODUCTION)
        $store | ConvertTo-Json -Depth 100 > $CONFIG_PATH
    }

    $store = Import-CredentialsFromJson (Get-Content $CONFIG_PATH)
    return $store
}

function Import-CredentialsFromJson(
    [string] $json)
{
    $ht = Convert-PSCustomObjectToHashtable($json | ConvertFrom-Json)

    $store = [CredentialStore]::new()
    $ht["Environments"] | Foreach-Object {
        $env = [CredentialEnvironment]::new($_.Name)
        # Foreach-Object will iterate once over $null, which is not what we want.
        if ($_.Credentials -ne $null) {
            $_.Credentials | Foreach-Object {
                $env.AddCredentials([Credentials]::new($_.ClientKey, $_.ClientSecret))
            }
        }
        $store.AddEnvironment($env)
    }

    return $store
}

function Add-AuthHelperCredentials() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Environment,
        [Parameter(Mandatory=$true)]
        [string]$ClientKey,
        [Parameter(Mandatory=$true)]
        [string]$ClientSecret
    )

    $store = Get-AuthHelperStoreFromConfig
    $store.Environments | Foreach-Object {
        $env = $_
        if ($Environment -eq $env.Name) {
            # Remove any old values for the same client key
            $env.Credentials = $env.Credentials | ? ClientKey -ne $ClientKey
            $env.AddCredentials([Credentials]::new($ClientKey, $ClientSecret))
        }
    }
    $store | ConvertTo-Json -Depth 100 > $CONFIG_PATH
}

function Remove-AuthHelperCredentials() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Environment,
        [Parameter(Mandatory=$true)]
        [string]$ClientKey
    )
    $store = Get-AuthHelperStoreFromConfig
    $store.Environments | Foreach-Object {
        $env = $_
        if ($Environment -eq $env.Name) {
            # Remove any old values for the same client key
            $env.Credentials = $env.Credentials | ? ClientKey -ne $ClientKey
            if ($env.Credentials -eq $null) {
                $env.Credentials = @()
            }
        }
    }
    $store | ConvertTo-Json -Depth 100 > $CONFIG_PATH
}



Export-ModuleMember -Function Get-AuthHelperStoreFromConfig
Export-ModuleMember -Function Get-AuthHelperCredentials
Export-ModuleMember -Function Add-AuthHelperCredentials
Export-ModuleMember -Function Remove-AuthHelperCredentials
