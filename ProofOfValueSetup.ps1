Param(
    [string]$Fqdn,
    [string]$Token,
    [string]$FilePath,
    [string]$ConnectorType,
    [string]$Target # For now this will be either RDP host or Storefront URL
)

$global:Fqdn = $Fqdn
$global:Token = $Token
$global:Target = $Target

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
    
    $ContGroupId = New-AccountGroup -GroupName "Load Testing" -Description "These users will be dedicated to hunting for failure."
    $Id = $ContGroupId."id"
    $ids += $Id

    $LoadGroupId = New-AccountGroup -GroupName "Continuous Testing" -Description "These users will be dedicated to baseline testing."
    $Id = $LoadGroupId."id"
    $ids += $Id

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
    
    $Response = Invoke-RestMethod @Parameters
    $Response."id"
}

function Import-LeLauncherGroup {
    param(
        $LauncherGroupName,
        $Description
    )
    Write-Host "[GROUPS] Attempting to create $LauncherGroupName..." -ForegroundColor "Yellow"
    $Id = New-LeLauncherGroup -GroupName "$LauncherGroupName" -Description "$Description."
    Write-Host "[GROUPS] $LauncherGroupName created successfully..." -ForegroundColor "Green"
    Write-Host "[DEBUG] $LauncherGroupName id: $Id"
    $Id
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
    $Response 
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

function New-LeApplicationTest {
    Param (
        [string]$TestName,
        [string]$Description,
        [string]$AccountGroupId,
        [string]$LauncherGroupId,
        [string]$ConnectorType,
        [string]$TargetRDPHost, # This is either RDP Host or Storefront URL
        [string]$ServerUrl,
        [string]$TargetResource
    )

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

    $Header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $token"
    }

    if ($ConnectorType -eq "RDP"){
        $Body = @"
{
    "type": "ApplicationTest",
    "name": "$TestName",
    "description": "$Description",
    "connector": {
        "type": "Rdp",
        "hostList": [{
            "endpoint": "$TargetRDPHost",
            "enabled": true
        }]
    },
    "accountGroups": [
        "$AccountGroupId"
    ],
    "launcherGroups": [
        "$LauncherGroupId"
    ]
}
"@
    } elseif ($ConnectorType -eq "StoreFront") {
        $Body = @"
{
    "type": "ApplicationTest",
    "name": "$TestName",
    "description": "$Description",
    "connector": {
        "type": "Storefront",
        "serverUrl": "$ServerUrl",
        "resource": "$TargetResource"
    },
    "accountGroups": [
        "$AccountGroupId"
    ],
    "launcherGroups": [
        "$LauncherGroupId"
    ]
}
"@
    }
    

    $Parameters = @{
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/tests"
        Headers     = $Header
        Method      = "POST"
        body        = $Body
        ContentType = "application/json"
    }
    
    
    #Write-Host $Parameters.body
    $Response = Invoke-RestMethod @Parameters
    $Response
}

function New-LeLoadTest {
    Param (
        [string]$TestName,
        [string]$Description,
        [string]$AccountGroupId,
        [string]$LauncherGroupId,
        [string]$ConnectorType,
        [string]$TargetRDPHost, # This is either RDP Host or Storefront URL
        [string]$ServerUrl,
        [string]$TargetResource
    )

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

    $Header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $token"
    }

    if ($ConnectorType -eq "RDP"){
        $Body = @"
{
    "type": "LoadTest",
    "name": "$TestName",
    "description": "$Description",
    "connector": {
        "type": "Rdp",
        "hostList": [{
            "endpoint": "$TargetRDPHost",
            "enabled": true
        }]
    },
    "accountGroups": [
        "$AccountGroupId"
    ],
    "launcherGroups": [
        "$LauncherGroupId"
    ]
}
"@
    } elseif ($ConnectorType -eq "StoreFront") {
        $Body = @"
{
    "type": "LoadTest",
    "name": "$TestName",
    "description": "$Description",
    "connector": {
        "type": "Storefront",
        "serverUrl": "$ServerUrl",
        "resource": "$TargetResource"
    },
    "accountGroups": [
        "$AccountGroupId"
    ],
    "launcherGroups": [
        "$LauncherGroupId"
    ]
}
"@
    }
    

    $Parameters = @{
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/tests"
        Headers     = $Header
        Method      = "POST"
        body        = $Body
        ContentType = "application/json"
    }
    
    #Write-Host $Parameters.body
    $Response = Invoke-RestMethod @Parameters
    $Response
}

function New-LeContinuousTest {
    Param (
        [string]$TestName,
        [string]$Description,
        [string]$AccountGroupId,
        [string]$LauncherGroupId,
        [string]$ConnectorType,
        [string]$TargetRDPHost, # This is either RDP Host or Storefront URL
        [string]$ServerUrl,
        [string]$TargetResource
    )

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

    $Header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $token"
    }

# Endpoint is set to false because the account group is empty
    if ($ConnectorType -eq "RDP"){
        $Body = @"
{
"type": "ContinuousTest",
"name": "$TestName",
"description": "$Description",
"isEnabled": "false",
"connector": {
    "type": "Rdp",
    "hostList": [{
        "endpoint": "$TargetRDPHost",
        "enabled": true
    }]
},
"accountGroups": [
    "$AccountGroupId"
],
"launcherGroups": [
    "$LauncherGroupId"
]
}
"@
    } elseif ($ConnectorType -eq "StoreFront") {
        $Body = @"
{
    "type": "ContinuousTest",
    "name": "$TestName",
    "description": "$Description",
    "connector": {
        "type": "Storefront",
        "serverUrl": "$ServerUrl",
        "resource": "$TargetResource"
    },
    "accountGroups": [
        "$AccountGroupId"
    ],
    "launcherGroups": [
        "$LauncherGroupId"
    ]
}
"@
    }

    $Parameters = @{
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/tests"
        Headers     = $Header
        Method      = "POST"
        body        = $Body
        ContentType = "application/json"
    }
    
    #Write-Host $Parameters.body
    $Response = Invoke-RestMethod @Parameters
    $Response
}



function Import-Tests {
    param (
        [string]$AccountGroupIds,
        [string]$LauncherGroupId,
        [string]$TargetRDPHost, # This is either RDP Host or Store Resource
        [string]$ServerUrl,
        [string]$TargetResource # This is Storefront URL
    )

    #Write-Host $AccountGroupIds
    
    $AppTestGroupId = $AccountGroupIds.Substring(0, 36)
    $LoadTestGroupId = $AccountGroupIds.Substring(37, 36)
    $ContinuousTestGroupId = $AccountGroupIds.Substring(74, 36)
    
    $ids = @()
    Write-Host "[TESTS] Start: Beginning test creation process..." -ForegroundColor "White"
 
    $TestName = "RDP Application Test"
    Write-Host "[TESTS] Attempting to create $TestName..." -ForegroundColor "Yellow"
    $RDPAppTestId = New-LeApplicationTest -TestName $TestName -Description "This test will validate the performance and functionality of the workflow." -AccountGroupId $AppTestGroupId -LauncherGroupId $LauncherGroupId -ConnectorType "RDP" -TargetRDPHost $TargetRDPHost
    Write-Host "[TESTS] $TestName test created successfully..." -ForegroundColor "Green"
    $Id = $RDPAppTestId."id"
    $ids += $Id
    Write-Host "[DEBUG] $TestName id: $Id..." -ForegroundColor "Blue"

    $TestName = "StoreFront Application Test"
    Write-Host "[TESTS] Attempting to create $TestName..." -ForegroundColor "Yellow"
    $StoreFrontAppTestId = New-LeApplicationTest -TestName $TestName -Description "This test will validate the performance and functionality of the workflow." -AccountGroupId $AppTestGroupId -LauncherGroupId $LauncherGroupId -ConnectorType "Storefront" -ServerUrl $ServerUrl -TargetResource $TargetResource
    Write-Host "[TESTS] $TestName test created successfully..." -ForegroundColor "Green"
    $Id = $StoreFrontAppTestId."id"
    $ids += $Id
    Write-Host "[DEBUG] $TestName id: $Id..." -ForegroundColor "Blue"
 
    $TestName = "RDP Load Test"
    Write-Host "[TESTS] Attempting to create $TestName..." -ForegroundColor "Yellow"
    $RDPLoadTestId = New-LeLoadTest -TestName $TestName -Description "Baseline your virtual desktop host's performance and capacity." -AccountGroupId $LoadTestGroupId -LauncherGroupId $LauncherGroupId -ConnectorType "RDP" -TargetRDPHost $TargetRDPHost
    Write-Host "[TESTS] $TestName test created successfully..." -ForegroundColor "Green"
    $Id = $RDPLoadTestId."id"
    $ids += $Id
    Write-Host "[DEBUG] $TestName id: $Id..." -ForegroundColor "Blue"

    $TestName = "StoreFront Load Test"
    Write-Host "[TESTS] Attempting to create $TestName..." -ForegroundColor "Yellow"
    $StoreFrontLoadTestId = New-LeApplicationTest -TestName $TestName -Description "This test will validate the performance and functionality of the workflow." -AccountGroupId $AppTestGroupId -LauncherGroupId $LauncherGroupId -ConnectorType "Storefront" -ServerUrl $ServerUrl -TargetResource $TargetResource
    Write-Host "[TESTS] $TestName test created successfully..." -ForegroundColor "Green"
    $Id = $StoreFrontLoadTestId."id"
    $ids += $Id
    Write-Host "[DEBUG] $TestName id: $Id..." -ForegroundColor "Blue"
    
    $TestName = "RDP Continuous Test"
    Write-Host "[TESTS] Start: Attempting to create $TestName..." -ForegroundColor "Yellow"
    $RDPContinuousTestId = New-LeContinuousTest -TestName $TestName -Description "Have a canary in the coalmine hunting for failure." -AccountGroupId $ContinuousTestGroupId -LauncherGroupId $LauncherGroupId -ConnectorType "RDP" -TargetRDPHost $TargetRDPHost
    Write-Host "[TESTS] $TestName test created successfully..." -ForegroundColor "Green"
    $Id = $RDPContinuousTestId."id"
    $ids += $Id
    Write-Host "[DEBUG] $TestName id: $Id..." -ForegroundColor "Blue"

    $TestName = "StoreFront Continuous Test"
    Write-Host "[TESTS] Start: Attempting to create $TestName..." -ForegroundColor "Yellow"
    $StoreFrontContinuousTestId = New-LeContinuousTest -TestName $TestName -Description "Have a canary in the coalmine hunting for failure." -AccountGroupId $ContinuousTestGroupId -LauncherGroupId $LauncherGroupId -ConnectorType "Storefront" -ServerUrl $ServerUrl -TargetResource $TargetResource
    Write-Host "[TESTS] $TestName test created successfully..." -ForegroundColor "Green"
    $Id = $StoreFrontContinuousTestId."id"
    $ids += $Id
    Write-Host "[DEBUG] $TestName id: $Id..." -ForegroundColor "Blue"

    Write-Host "[TESTS] End: Tests have been created..." -ForegroundColor "White"
 
    $ids
}

# Query for existing accounts
function Remove-LeTest {
    Param (
        [string]$TestId
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
        accountId = $TestId
    } 

    $Parameters = @{
        Uri         = "https://" + $global:fqdn + "/publicApi/v5/tests" + "/$TestId"
        Headers     = $Header
        Method      = "DELETE"
        body        = $Body
        ContentType = "application/json"
    }
    
    
    #$Parameters.body.accountId
    $Response = Invoke-RestMethod @Parameters
    $Response
}

function Get-LeApplicationsForTest {
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
    $SampleAppIds
}

function Debug-Cleanup {
    param(
        $AccountIds,
        $AccountGroupIds,
        $LauncherGroupId,
        $TestIds
    )

    
    Foreach ($Id in $AccountIds) {
        Start-Sleep 0.25
        Remove-LeAccount $Id
    }
    Write-Host "[CLEANUP] Accounts removed..." -ForegroundColor "Red"

    Write-Host "[CLEANUP] Attempting to remove account groups..." -ForegroundColor "Red"
    Foreach ($Id in $AccountGroupIds) {
        Start-Sleep 0.25
        Remove-LeAccountGroup $Id
    }
    Write-Host "[CLEANUP] Account groups removed..." -ForegroundColor "Red"

    Write-Host "[CLEANUP] Attempting to remove Launcher group..." -ForegroundColor "Red"
    Remove-LeLauncherGroup -LauncherGroupId $LauncherGroupId | Out-Null
    Write-Host "[CLEANUP] Launcher group removed..." -ForegroundColor "Red"

    Write-Host "[CLEANUP] Attempting to remove tests..." -ForegroundColor "Red"
    $TestTypes = @("RDP Application Test", "StoreFront Application Test", "RDP Load Test", , "StoreFront Load Test", "RDP Continuous Test", "StoreFront Continuous Test")
    $Index = 0
    Foreach ($Test in $TestTypes) {
        $Id = $TestIds[$Index]
        $Type = $TestTypes[$Index]
        Write-Host "[DEBUG] Attempting to remove $Type id: $Id" -ForegroundColor "Blue"
        Remove-LeTest -TestId $Id | Out-Null
        $Index++
    }
    Write-Host "[CLEANUP] Tests have been removed..." -ForegroundColor "Green"
    
}

function Main {
    param (
        $FilePath,
        $ConnectorType,
        $TargetRDPHost = "10.111.23.1",
        $ServerUrl = "https://storefront.contoso.org",
        $TargetResource = "TargetResource",
        $Debug = "Y"
    )
  
    # Import .csv file of accounts into the appliance
    #Write-Host "[ACCOUNTS] Start: Beginning account import process..." -ForegroundColor "White"
    #$AccountIds = Import-LeAccounts -FilePath $FilePath
    #Write-Host "[ACCOUNTS] End: Account import process completed..." -ForegroundColor "White"

    # Create empty account groups to add users to
    Write-Host "[GROUPS] Start: Beginning account groups creation process..." -ForegroundColor "White"
    $AccountGroupIds = Import-AccountGroups
    Write-Host "[GROUPS] End: Account groups have been created..." -ForegroundColor "White"

    # Create empty launcher group to add launchers to
    # In 4.10 this will no longer be needed, should be a default group for new installations
    Write-Host "[GROUPS] Start: Beginning launcher group creation process..." -ForegroundColor "White"
    $LauncherGroupId = Import-LeLauncherGroup -LauncherGroupName "All Launchers" -Description "This is a group containing all launchers."
    Write-Host "[GROUPS] End: Launcher groups have been created..." -ForegroundColor "White"

    # AppId, LoadId, ContId
    Write-Host "[CLEANUP] Attempting to create tests..." -ForegroundColor "White"
    $TestIds = Import-Tests -AccountGroupId $AccountGroupIds -LauncherGroupId $LauncherGroupId -TargetRDPHost $TargetRDPHost -ServerUrl $ServerUrl -TargetResource $TargetResource
    Write-Host "[TESTS] End: Tests have been created..." -ForegroundColor "White"
    
    # Create continuous test
    # Create load test

    if ($Debug -eq "Y") {
        Write-Host "[CLEANUP] Start: Beginning cleanup process..." -ForegroundColor "White"
        Debug-Cleanup -AccountIds $AccountIds -AccountGroupIds $AccountGroupIds -LauncherGroupId $LauncherGroupId -TestIds $TestIds
        Write-Host "[CLEANUP] End: Cleanup process has been completed..." -ForegroundColor "White"
    } 
    
    Write-Host "[DEBUG] Script has completed. Enjoy your proof of concept..." -ForegroundColor "Green"
    
}

# Pass non-sensitive arguments here, and call it from the command line: ".\ProofOfValue.ps1 -Fqdn <YOUR_FQDN> -Token <YOUR_SECRET_TOKEN>"
Main -FilePath ".\Accounts.csv" -Debug "Y"


#[string]$Fqdn,
#[string]$Token,
#[string]$FilePath,
#[string]$ConnectorType,
#[string]$Target # For now this will be either RDP host or Storefront URL

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
