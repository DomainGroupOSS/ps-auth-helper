$CONFIG_PATH = "~\.AuthHelper.json"
$ENV_LOCAL = "Local"
$ENV_STAGING = "Staging"
$ENV_PRODUCTION = "Production"

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
    $store = Get-StoreFromConfig

    $store.Environments | Foreach-Object {
        Write-Host "# "  $_.Name
        $_.Credentials | Foreach-Object {
            Write-Host $_.ClientKey  $_.ClientSecret
        }
    }
}


function Fetch-AuthToken() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Environment,
        [Parameter(Mandatory=$true)]
        [string]$Client,
        [Parameter(Mandatory=$true)]
        [string]$Scope
    )

    switch ($Environment) {
        "Local" {
            $authUri = "https://stage-auth.domain.com.au/v1/connect/token"
        }
        "Staging" {
            $authUri = "https://stage-auth.domain.com.au/v1/connect/token"
        }
        "Production" {
            $authUri = "https://auth.domain.com.au/v1/connect/token"
        }
    }

    $store = Get-StoreFromConfig

    $env = $store.GetEnvironmentByName($Environment)
    $creds = $env.GetCredentialsByClientKey($Client)

    if ($creds -eq $null) {
        Throw "Could now find client: $Client in environment: $Environment"
    }

    $token = Perform-AuthTokenRequest -AuthUri $authUri -ClientKey $Client -ClientSecret $creds.ClientSecret -Scope $Scope
    Return $token
}

function Perform-AuthTokenRequest() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AuthUri,
        [Parameter(Mandatory=$true)]
        [string]$ClientKey,
        [Parameter(Mandatory=$true)]
        [string]$ClientSecret,
        [Parameter(Mandatory=$true)]
        [string]$Scope
    )

    $payloadAsBytes = [System.Text.Encoding]::UTF8.GetBytes($ClientKey + ":" + $ClientSecret)
    $payloadAsBase64 = [Convert]::ToBase64String($payloadAsBytes)
    $authorizationHeaderValue = "Basic $payloadAsBase64"
    Write-Verbose "Requesting access token for client: $ClientKey, secret: $ClientSecret, scope: $Scope"
    Write-Verbose "Authorization: $authorizationHeaderValue"

    $authResponse = ( `
        Invoke-RestMethod `
            -Method Post `
            -Uri $AuthUri `
            -Body "grant_type=client_credentials&scope=$Scope" `
            -Headers @{Authorization=$authorizationHeaderValue})
    $accessToken = $authResponse.access_token
    Write-Verbose $authResponse
    Return $accessToken
}


function Get-AuthTokenWithClientCredentials() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Environment,
        [Parameter(Mandatory=$true)]
        [string]$Client,
        [Parameter(Mandatory=$true)]
        [string]$Scope
    )

    Write-Verbose "Getting auth token. Environment: $Environment, Client: $Client, Scope: $Scope"

    if (!(Test-Path Variable:Global:AuthHelperCache)) {
        Set-Variable -Name AuthHelperCache -Scope Global -Value @{}
    }

    $cacheKey = "${Environment}:${Client}:${Scope}"

    if (!($AuthHelperCache.ContainsKey($cacheKey))) {
        $token = Fetch-AuthToken -Environment $Environment -Client $Client -Scope $Scope
        Write-Verbose "Writing to cache. Key: $cacheKey, Value: $token"
        $AuthHelperCache[$cacheKey] = $token
    }
    else {
        Write-Verbose "$cacheKey already exists. Doing nothing."
    }

    Return $AuthHelperCache[$cacheKey]
}

function Invoke-RestMethodWithClientCredentials() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Environment,
        [Parameter(Mandatory=$true)]
        [string]$AuthClient,
        [Parameter(Mandatory=$true)]
        [string]$AuthScope,
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Default", "Get", "Head", "Post", "Put", "Delete", "Trace", "Options", "Merge", "Patch")]
        [string]$Method,
        [Parameter(Mandatory=$false)]
        [string]$Body,
        [Parameter(Mandatory=$false)]
        [bool]$RequestPayloadIsJson = $true
    )
    $headers = @{}

    if ($Method -eq "Post" -and $RequestPayloadIsJson) {
        $headers = @{"Content-type"="application/json"}
    }

    if ($Environment -eq "") {
        $Environment = Get-AuthHelperDefaultEnvironment
    }

    $accessToken = Get-AuthTokenWithClientCredentials -Environment $Environment -Client $AuthClient -Scope $AuthScope
    $headers["Authorization"] = "Bearer $accessToken"

    Write-Verbose "Calling URI: $Uri"

    #TODO: other cases where body is not required
    if ($Method -eq "Get") {
        Invoke-RestMethod `
            -Headers $headers `
            -Method $Method `
            -Uri $Uri
    }
    else {
        Invoke-RestMethod `
            -Headers $headers `
            -Method $Method `
            -Uri $Uri `
            -Body $Body
    }

}

function Clear-AuthTokenCache() {
    if (Test-Path Variable:Global:AuthHelperCache) {
        Set-Variable -Name AuthHelperCache -Scope Global -Value @{}
    }
}

function Get-AuthHelperDefaultEnvironment() {
    if (!(Test-Path Variable:Global:AuthHelperDefaultEnvironment)) {
        Set-Variable -Name AuthHelperDefaultEnvironment -Scope Global -Value $ENV_STAGING
    }
    Return $AuthHelperDefaultEnvironment
}

function Set-AuthHelperDefaultEnvironment() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Environment
    )
    if (Test-Path Variable:Global:AuthHelperDefaultEnvironment) {
        Set-Variable -Name AuthHelperDefaultEnvironment -Scope Global -Value $Environment
    }
}


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

function Get-StoreFromConfig() {
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
        $_.Credentials | Foreach-Object {
            $env.AddCredentials([Credentials]::new($_.ClientKey, $_.ClientSecret))
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

    $store = Get-StoreFromConfig
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
    $store = Get-StoreFromConfig
    $store.Environments | Foreach-Object {
        $env = $_
        if ($Environment -eq $env.Name) {
            # Remove any old values for the same client key
            $env.Credentials = $env.Credentials | ? ClientKey -ne $ClientKey
        }
    }
    $store | ConvertTo-Json -Depth 100 > $CONFIG_PATH
}


Export-ModuleMember -Function Get-AuthHelperCredentials
Export-ModuleMember -Function Get-AuthTokenWithClientCredentials
Export-ModuleMember -Function Clear-AuthTokenCache
Export-ModuleMember -Function Invoke-RestMethodWithClientCredentials
Export-ModuleMember -Function Get-AuthHelperDefaultEnvironment
Export-ModuleMember -Function Set-AuthHelperDefaultEnvironment
Export-ModuleMember -Function Add-AuthHelperCredentials
Export-ModuleMember -Function Remove-AuthHelperCredentials
