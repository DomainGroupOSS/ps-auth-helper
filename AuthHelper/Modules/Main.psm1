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

    $store = Get-AuthHelperStoreFromConfig

    $env = $store.GetEnvironmentByName($Environment)
    $creds = $env.GetCredentialsByClientKey($Client)

    if ($creds -eq $null) {
        Throw "Could not find client: $Client in environment: $Environment"
    }

    $token = Perform-AuthTokenRequest -AuthUri $env.AuthUri -ClientKey $Client -ClientSecret $creds.ClientSecret -Scope $Scope
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
        [hashtable]$AddHeaders = $null,
        [Parameter(Mandatory=$false)]
        [string]$ContentType = "",
        [Parameter(Mandatory=$false)]
        [bool]$RequestPayloadIsJson = $true
    )
    $headers = @{}

    if (($Method -eq "Post" -and $RequestPayloadIsJson) -or ($ContentType -ne $null)) {
        $ct = if ($ContentType -eq "") {"application/json"} else {$ContentType}
        $headers = @{"Content-type"=$ct}
    }

    if ($AddHeaders -ne $null) {
        $headers = Merge-HashTables $headers $AddHeaders
    }

    if ($Environment -eq "") {
        $Environment = Get-AuthHelperDefaultEnvironment
    }

    $accessToken = Get-AuthTokenWithClientCredentials -Environment $Environment -Client $AuthClient -Scope $AuthScope
    $headers["Authorization"] = "Bearer $accessToken"

    Write-Verbose "Calling URI: $Uri"
    Write-Verbose "Headers: "
    Write-Verbose "$($headers | Out-String)"

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

function Merge-HashTables($htold=$null, $htnew=$null)
{

<#
.SYNOPSIS
Merges two has tables based on their keys.

.LINK
http://stackoverflow.com/questions/8800375/merging-hashtables-in-powershell-how
#>
    $keys = $htold.GetEnumerator() | foreach {$_.key}
    $keys | foreach {
        $key = $_
        if ($htnew.ContainsKey($key))
        {
            $htold.Remove($key)
        }
    }
    $htnew = $htold + $htnew
    return $htnew
}

Export-ModuleMember -Function Get-AuthTokenWithClientCredentials
Export-ModuleMember -Function Clear-AuthTokenCache
Export-ModuleMember -Function Invoke-RestMethodWithClientCredentials
