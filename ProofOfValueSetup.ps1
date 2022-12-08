Param(
    [string]$Fqdn,
    [string]$Token,
    [string]$FilePath
)

$global:fqdn = $fqdn
$global:token = $token

$SSLHandler = @"
public class SSLHandler
{public static System.Net.Security.RemoteCertificateValidationCallback GetSSLHandler()
    {return new System.Net.Security.RemoteCertificateValidationCallback((sender, certificate, chain, policyErrors) => { return true; });}
}
"@
Add-Type -TypeDefinition $SSLHandler

# Create account given Active Directory account details
function New-LeAccount {
    Param (
        [string]$username,
        [string]$password,
        [string]$domain
    )

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

    $Header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $token"
    }

    $Body = @{
        username = $username
        domain = $domain
        password = $password
    } | ConvertTo-Json

    $Parameters = @{
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/accounts/"
        Headers     = $Header
        Method      = "POST"
        body        = $Body
        ContentType = "application/json"
    }
    
    #Invoke-RestMethod @Parameters
    $Response = Invoke-RestMethod @Parameters
    $Response
}

# Import Accounts from CSV file
function Import-LeAccounts {
    param (
        $FilePath
    )
    # Import the csv
    Write-Host "[FILE] Attempting to import file..."
    $accountData = (Import-Csv -Path $FilePath)
    Write-Host "[FILE] File import completed successfully."
    $ids = @()
    # Grab the value from each column for each row and use it to create an account
    Foreach ($user in $accountData) {
        $username = $user.Username
        $password = $user.Password
        $domain = $user.Domain
        Write-Host "[ACCOUNTS] Adding user $username..."
        $AccountId =  New-LeAccount -Username $username -Password $password -Domain $domain
        $Id = $AccountId."id"
        Write-Host "[ACCOUNTS] $username ID: $Id..."
        # Add new account id to list to return. This is used when adding users to account groups
        $ids += $Id
    }
    $ids
}

# Create Account Group
function New-LeAccountGroup {
    Param (
        [string]$GroupName,
        [string]$Description
    )

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

    $Header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $token"
    }

    $Body = @{
        type = "Filter"
        filter = "dummy*"
        name = $GroupName
        description = $Description
    } | ConvertTo-Json

    $Parameters = @{
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/account-groups"
        Headers     = $Header
        Method      = "POST"
        body        = $Body
        ContentType = "application/json"
    }
    
    Invoke-RestMethod @Parameters
    $Response.items 
}

function New-AccountGroups {

    # Cmon... DRY
    $ids = @()
    Write-Host "[GROUPS] Creating Application Testing Group..."
    $AppGroupId = New-LeAccountGroup -GroupName "Application Testing" -Description "These users will be dedicated to application testing."
    $Id = $AppGroupId."id"
    $ids += $Id
    Write-Host "[DEBUG] Application Testing id: $Id"

    Write-Host "[GROUPS] Creating Continuous Testing Group..."
    $AppGroupId = New-LeAccountGroup -GroupName "Continuous Testing" -Description "These users will be dedicated to continuous testing."
    $Id = $AppGroupId."id"
    $ids += $Id
    Write-Host "[DEBUG] Continuous Testing id: $Id"

    Write-Host "[GROUPS] Creating Load Testing Group..."
    $AppGroupId = New-LeAccountGroup -GroupName "Load Testing" -Description "These users will be dedicated to load testing."
    $Id = $AppGroupId."id"
    $ids += $Id
    Write-Host "[DEBUG] Load Testing id: $Id"

    $ids
}

function Add-LeAccountGroupMember {
    Param (
        [string]$GroupId,
        [string]$AccountId
    )

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

    $Header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $global:token"
    }

    $Body = @(
        $AccountId
    )
    

    $Parameters = @{
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/account-groups" + "/$GroupId" + "/members"
        Headers     = $Header
        Method      = "POST"
        body        = $Body
        ContentType = "application/json"
    }
    
    $Body
    $Parameters
    #$Response = Invoke-RestMethod @Parameters
    #$Response.items 
}

# Query for existing accounts
function Remove-LeAccountGroup {
    Param (
        [string]$AccountGroupId
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
        accountId = $AccountId
    } 

    $Parameters = @{
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/account-groups" + "/$AccountGroupId"
        Headers     = $Header
        Method      = "DELETE"
        body        = $Body
        ContentType = "application/json"
    }
    
    $Response = Invoke-RestMethod @Parameters
    $Response.items 
}

# Query for existing accounts
function Get-LeAccounts {
    Param (
        [string]$orderBy = "username",
        [string]$Direction = "asc",
        [string]$Count = "200",
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
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/accounts"
        Headers     = $Header
        Method      = "GET"
        body        = $Body
        ContentType = "application/json"
    }

    $Response = Invoke-RestMethod @Parameters
    $Response.items 
}

# Query for existing accounts
function Remove-LeAccount {
    Param (
        [string]$AccountId
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
        accountId = $AccountId
    } 

    $Parameters = @{
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/accounts" + "/$AccountId"
        Headers     = $Header
        Method      = "DELETE"
        body        = $Body
        ContentType = "application/json"
    }
    
    
    $Response = Invoke-RestMethod @Parameters
    $Response.items 
}

function Main {
    param (
        $FilePath,
        $Debug = "Y"
    )
  
    Write-Host "[ACCOUNTS] Beginning account import process..."
    $AccountIds = Import-LeAccounts -FilePath $FilePath
    Foreach ($Id in $AccountIds) {
        
    }
    Write-Host "[ACCOUNTS] Account import process completed..."
    
    Write-Host "[GROUPS] Creating account groups..."
    $AccountGroupIds = New-AccountGroups
    Foreach ($Id in $AccountGroupIds) {
        Write-Host "[DEBUG] Account Group id: $Id"
    }
    Write-Host "[GROUPS] Account groups have been created..."

    # Add first username in AccountData to application testing
    Add-LeAccountGroupMember -GroupId $AccountGroupIds[0] -AccountId $AccountIds[0]
    # Add second username in AccountData to continuous testing
    # Add the remaining users in AccountData to load testing
    #Get-LeAccounts




    # Create application test
    # Create continuous test
    # Create load test

    if ($Debug -eq "Y") {
        Foreach ($Id in $AccountIDs) {
            Remove-LeAccount $Id
        }
        Write-Host "[CLEANUP] Accounts removed..."
        Foreach ($Id in $AccountGroupIds) {
            Remove-LeAccountGroup $Id
        }
        Write-Host "[CLEANUP] Account groups removed..."
    } else {
        Write-Host "Script has completed."
    }
}


Main -FilePath ".\Accounts.csv"


# CreateTest("Application Test", type="appTest")
# CreateTest("Capacity Baseline", type="loadTest")
# CreateTest("Hunting for Failure", type="contTest")

# Create Three tests:
# Create an Application Test (PowerPoint, Word, Excel, Notepad, Paint)
# Create a Load Test (PowerPoint, Word, Excel, Notepad, Paint)
# Create a Continuous Test (PowerPoint, Word, Excel, Notepad, Paint)

# Add three locations:
# Create new location 1
# Create new location 2
# Create new location 3


# READD THESE
#chrisMoltisanti,Password2,newark.nj
#paulieWalnuts,Password3,newark.nj