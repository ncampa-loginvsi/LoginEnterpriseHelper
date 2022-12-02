# Parameters:
# fqdn: fully qualified name of the Login Enterprise appliance (example.com not https://example.com/publicApi)
# token: the token generated from the appliance (requires Configuration level access)
# pathToCsv: the path to the csv file containing user information in the format Username, Password
Param(
    [Parameter(Mandatory=$true)]$fqdn,
    [Parameter(Mandatory=$true)]$token,
    [Parameter(Mandatory=$true)]$pathToCsv,
    [Parameter(Mandatory=$true)]$count
)

$global:fqdn = $fqdn
$global:token = $token 

$code = @"
public class SSLHandler
{public static System.Net.Security.RemoteCertificateValidationCallback GetSSLHandler()
    {return new System.Net.Security.RemoteCertificateValidationCallback((sender, certificate, chain, policyErrors) => { return true; });}
}
"@
Add-Type -TypeDefinition $code

# Query for existing accounts
function Get-LeAccounts {
    Param (
        [string]$orderBy = "username",
        [string]$Direction = "asc",
        [string]$Count = $count,
        [string]$Include = "none"
    )

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

    $Header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $global:token"
    }

    $Body = @{
        orderBy   = $orderBy
        direction = $Direction
        count     = $Count
        include   = $Include 
    } 

    $Parameters = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v5/accounts'
        Headers     = $Header
        Method      = 'GET'
        body        = $Body
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @Parameters
    $Response.items 
}

# Set configuration of account by account Id
function Set-LeAccount {
    Param (
        [string]$accountId,
        [string]$password,
        [string]$username,
        [string]$domain
    )

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

    $Header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $global:token"
    }

    $Body = @{
        password = $password
        username = $username
        domain = $domain
    } | ConvertTo-Json

    $Parameters = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v5/accounts/' + $accountId
        Headers     = $Header
        Method      = 'PUT'
        body        = $Body
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @Parameters
    $Response.items 
}

# Import spreadsheet containing user profile specifications in Username, Password format
$accountlist = (Import-Csv -Path $pathToCsv)
$count = $accountlist.Count
Write-Host "Collected $count accounts to modify. Starting process now."

# For every row in the dataset
Foreach ($row in $accountlist) {
    # Grab their username and password
    $username = $row.Username 
    $password = $row.Password
    $domain = $row.Domain
    Write-Host $username, $password, $domain
    Write-Host "Configuring changes for: $username..."
    # Find the row's username value, and search for that account
    $account = Get-LeAccounts | Where-Object {($_.username -eq $username) -and ($_.domain -eq $domain)}
    # Grab the row's accountId
    $accountId = $account.id
    # Reconfigure the account using password from dataset
    Set-LeAccount -accountId $accountId -password $password -username $username -domain $domain
    Write-Host "Successfully changed account configuration for $username"
}
