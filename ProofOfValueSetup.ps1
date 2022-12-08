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
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/accounts"
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
    Write-Host "[FILE] Attempting to import file..." -ForegroundColor "Yellow"
    $accountData = (Import-Csv -Path $FilePath)
    Write-Host "[FILE] File import completed successfully." -ForegroundColor "Green"
    $ids = @()
    # Grab the value from each column for each row and use it to create an account
    Foreach ($user in $accountData) {
        $username = $user.Username
        $password = $user.Password
        $domain = $user.Domain
        Write-Host "[ACCOUNTS] Attempting to add user $username..." -ForegroundColor "Yellow"
        $AccountId =  New-LeAccount -Username $username -Password $password -Domain $domain
        Write-Host "[ACCOUNTS] User $username created successfully..." -ForegroundColor "Green"
        $Id = $AccountId."id"
        Write-Host "[ACCOUNTS] User $username accountID: $Id..." -ForegroundColor "Blue"
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

# This is a helper function used in Import-AccountGroups
# Should return the Account Group ID
function New-AccountGroup {
    param (
        $GroupName,
        $Description
    )

    Write-Host "[GROUPS] Attempting to create $GroupName Group..." -ForegroundColor "Yellow"
    $AccountGroupId = New-LeAccountGroup -GroupName $GroupName -Description $Description
    Write-Host "[GROUPS] $GroupName name created successfully..." -ForegroundColor "Green"
    $Id = $AccountGroupId."id"
    Write-Host "[DEBUG] $GroupName Group id: $Id..." -ForegroundColor "Blue"
    $AccountGroupId
}

function Import-AccountGroups {

    # Cmon... DRY
    $ids = @()
    #Write-Host "[GROUPS] Creating Application Testing Group..."
    #$AppGroupId = New-AccountGroup -GroupName "Application Testing" -Description "These users will be dedicated to application testing."
    $AppGroupId = New-AccountGroup -GroupName "Application Testing" -Description "These users will be dedicated to validating applications post-change."
    $Id = $AppGroupId."id"
    $ids += $Id
    
    # $ContGroupId = New-AccountGroup -GroupName "Continuous Testing" -Description "These users will be dedicated to hunting for failure."
    # $Id = $ContGroupId."id"
    # $ids += $Id

    # $LoadGroupId = New-AccountGroup -GroupName "Load Testing" -Description "These users will be dedicated to baseline testing."
    # $Id = $LoadGroupId."id"
    # $ids += $Id

    $ids
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

# Create Account Group
function New-LeLauncherGroup {
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
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/launcher-groups"
        Headers     = $Header
        Method      = "POST"
        body        = $Body
        ContentType = "application/json"
    }
    
    Invoke-RestMethod @Parameters
    $Response.items 
}

# Query for existing accounts
function Remove-LeLauncherGroup {
    Param (
        [string]$LauncherGroupId
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
        accountId = $LauncherGroupId
    } 

    $Parameters = @{
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/launcher-groups" + "/$LauncherGroupId"
        Headers     = $Header
        Method      = "DELETE"
        body        = $Body
        ContentType = "application/json"
    }
    
    $Response = Invoke-RestMethod @Parameters
    $Response.items 
}

# Query for existing accounts
function Get-LeApplications {
    Param (
        [string]$orderBy = "name",
        [string]$Direction = "asc",
        [string]$Count = "100",
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
        Uri         = 'https://' + $global:fqdn + '/publicApi/v5/applications'
        Headers     = $Header
        Method      = 'GET'
        body        = $Body
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @Parameters
    $Response.items 
}

function Zip-Arrays {
    [CmdletBinding()]
    Param(
        $First,
        $Second,
        $ResultSelector = { ,$args }
    )

    [System.Linq.Enumerable]::Zip($First, $Second, [Func[Object, Object, Object[]]]$ResultSelector)
}

function New-LeTest {
    Param (
        [string]$Type,
        [string]$TestName,
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

    $Body = @"
{
    "type": "ApplicationTest",
    "name": "string",
    "description": "string",
    "connector": {
        "type": "string",
        "host": "string",
        "commandLine": "string"
    },
    "accountGroups": [
        "497f6eca-6276-4993-bfeb-53cbbbba6f08"
    ],
    "launcherGroups": [
        "497f6eca-6276-4993-bfeb-53cbbbba6f08"
    ]
        }
"@

    $Parameters = @{
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/tests"
        Headers     = $Header
        Method      = "POST"
        body        = $Body
        ContentType = "application/json"
    }
    
    $Parameters
    #Invoke-RestMethod @Parameters
    #$Response = Invoke-RestMethod @Parameters
    #$Response
}

function Debug-Cleanup {
    Foreach ($Id in $AccountIDs) {
        Remove-LeAccount $Id
    }
    Write-Host "[CLEANUP] Accounts removed..." -ForegroundColor "Red"
    Foreach ($Id in $AccountGroupIds) {
        Remove-LeAccountGroup $Id
    }
    Write-Host "[CLEANUP] Account groups removed..." -ForegroundColor "Red"

    Write-Host "[CLEANUP] Attempting to removed Launcher group..." -ForegroundColor "Red"
    Remove-LeLauncherGroup -LauncherGroupId $LauncherGroupId."id"
    Write-Host "[CLEANUP] Launcher group removed..." -ForegroundColor "Red"
}


function Main {
    param (
        $FilePath,
        $Debug = "Y"
    )
  
    # Import .csv file of accounts into the appliance
    Write-Host "[ACCOUNTS] Start: Beginning account import process..." -ForegroundColor "White"
    $AccountIds = Import-LeAccounts -FilePath $FilePath
    Write-Host "[ACCOUNTS] End: Account import process completed..." -ForegroundColor "White"

    # Create empty account groups to add users to
    Write-Host "[GROUPS] Start: Beginning account groups creation process..." -ForegroundColor "White"
    $AccountGroupIds = Import-AccountGroups
    Write-Host "[GROUPS] End: Account groups have been created..." -ForegroundColor "White"

    # Create empty launcher group to add launchers to
    # In 4.10 this will no longer be needed, should be a default group for new installations
    Write-Host "[GROUPS] Start: Beginning account groups creation process..." -ForegroundColor "White"
    $LauncherGroupId = New-LeLauncherGroup -GroupName "All Launchers" -Description "This is a group containing all launchers."
    Write-Host "[GROUPS] End: Account groups have been created..." -ForegroundColor "White"

    # Create application test
    $Apps = Get-LeApplications
    [System.Collections.ArrayList]$AppsData = Zip-Arrays -First $Apps.name -Second $Apps.id
    $SampleAppNames = @(
        "Microsoft Excel (interaction)",
        "Microsoft PowerPoint (interaction)",
        "Microsoft Word"
    )
    $SampleAppIds = @()
    $AppsData = $AppsData | Where-Object {$SampleAppNames -ccontains $_[0]}
    $SampleAppIds = @()
    Foreach ($AppId in $AppsData) {
        $Id = $AppId[1]
        $SampleAppIds += $Id
    }
    # $SampleAppIds THESE ARE THE APP IDS OF SAMPLE APPLICATIONS OUT OF THE BOX
    # 4.10 WE CAN UPDATE THIS LIST TO USE KNOWLEDGE WORKER
    # THIS IS WHERE YOU LEFT OFF
    # Create Application test
    # Create continuous test
    # Create load test

    if ($Debug -eq "Y") {
        Write-Host "[GROUPS] Start: Beginning cleanup process..." -ForegroundColor "White"
        Debug-Cleanup
        Write-Host "[GROUPS] End: Account groups have been created..." -ForegroundColor "White"
    } 
    
    Write-Host "[DEBUG] Script has completed. Enjoy your proof of concept..." -ForegroundColor "Green"
    
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
