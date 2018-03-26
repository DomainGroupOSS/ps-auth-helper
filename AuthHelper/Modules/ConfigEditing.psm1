$CONFIG_PATH = "~\.AuthHelper.json"
$ENV_LOCAL = "Local"
$ENV_STAGING = "Staging"
$ENV_PRODUCTION = "DomainProduction"
$AUTH_URI_STAGING = "https://stage-auth.domain.com.au/v1/connect/token"
$AUTH_URI_PRODUCTION = "https://auth.domain.com.au/v1/connect/token"

class CredentialStore
{
    [string] $DefaultEnvironmentName
    [CredentialEnvironment[]] $Environments

    AddEnvironment([CredentialEnvironment] $environment) {
        $this.Environments = $this.Environments += $environment
    }

    RemoveEnvironment([string] $name) {
        $this.Environments = $this.Environments | ? Name -ne $name;
    }

    [CredentialEnvironment] GetEnvironmentByName([string] $name) {
        return $this.Environments | ? Name -eq $name | Select-Object -First 1
    }

    SetDefault([string] $name) {
        if ((($this.Environments | ? Name -eq $name) | Measure-Object).Count -eq 1) {
            $this.DefaultEnvironmentName = $name
        }
        else {
            $envNames = [string]::Join(", ", ($this.Environments | Foreach-Object { $_.Name } ))
            Throw "No environment has been configured with the name: $name. Available environments: $envNames"
        }
    }

    [string] ToString() {
        $envNames = [string]::Join([System.Environment]::NewLine, $this.Environments)
        return $envNames
    }

    WriteToConfig() {
        $this | ConvertTo-Json -Depth 100 > "~\.AuthHelper.json"
    }
}

class CredentialEnvironment
{
    [string] $Name
    [string] $AuthUri
    [Credentials[]] $Credentials

    CredentialEnvironment([string] $name, [string] $authUri) {
        $this.Name = $name
        $this.AuthUri = $authUri
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
        $store.AddEnvironment([CredentialEnvironment]::new($ENV_LOCAL, $AUTH_URI_STAGING))
        $store.AddEnvironment([CredentialEnvironment]::new($ENV_STAGING, $AUTH_URI_STAGING))
        $store.AddEnvironment([CredentialEnvironment]::new($ENV_PRODUCTION, $AUTH_URI_PRODUCTION))
        $store.SetDefault($ENV_STAGING)
        $store.WriteToConfig()
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
        $env = [CredentialEnvironment]::new($_.Name, $_.AuthUri)
        # Foreach-Object will iterate once over $null, which is not what we want.
        if ($_.Credentials -ne $null) {
            $_.Credentials | Foreach-Object {
                $env.AddCredentials([Credentials]::new($_.ClientKey, $_.ClientSecret))
            }
        }
        $store.AddEnvironment($env)
    }
    $store.SetDefault($ht["DefaultEnvironmentName"])

    return $store
}

function Add-AuthHelperEnvironment() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string]$AuthUri
    )
    $store = Get-AuthHelperStoreFromConfig
    $store.AddEnvironment([CredentialEnvironment]::new($Name, $AuthUri))
    $store.WriteToConfig()
}

function Remove-AuthHelperEnvironment() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    $store = Get-AuthHelperStoreFromConfig
    $store.RemoveEnvironment($Name)
    $store.WriteToConfig()
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
    $store.WriteToConfig()
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
    $store.WriteToConfig()
}

function Get-AuthHelperDefaultEnvironment() {
    $store = Get-AuthHelperStoreFromConfig
    return $store.DefaultEnvironmentName
}

function Set-AuthHelperDefaultEnvironment() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$EnvironmentName
    )
    $store = Get-AuthHelperStoreFromConfig
    $store.SetDefault($EnvironmentName)
    $store.WriteToConfig()
}

Export-ModuleMember -Function Get-AuthHelperStoreFromConfig
Export-ModuleMember -Function Add-AuthHelperEnvironment
Export-ModuleMember -Function Remove-AuthHelperEnvironment
Export-ModuleMember -Function Get-AuthHelperCredentials
Export-ModuleMember -Function Add-AuthHelperCredentials
Export-ModuleMember -Function Remove-AuthHelperCredentials
Export-ModuleMember -Function Get-AuthHelperDefaultEnvironment
Export-ModuleMember -Function Set-AuthHelperDefaultEnvironment
