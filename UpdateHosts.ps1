Param(
    $fqdn = "YOUR_FQDN",
    $token = "YOUR_CONFIGURATION_LEVEL_TOKEN",
    $testId = "YOUR_TEST_ID_TO_CHANGE",
    $hostsToAdd = @("HOST_TO_ADD_1", "HOST_TO_ADD_2", "HOST_TO_ADD_100")
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
function Get-LeTest {
    Param (
        [string]$testId,
        [string]$include = "environment"
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
        testId    = $testId
        include   = $include 
    } 

    $Parameters = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v5/tests' + "/$testId"
        Headers     = $Header
        Method      = 'GET'
        body        = $Body
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @Parameters
    $Response
}

function Update-LeTest {
    Param (
        [string]$testId,
        [string]$body
    )

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

    $Header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $global:token"
    }

    $Parameters = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v5/tests' + "/$testId"
        Headers     = $Header
        Method      = 'PUT'
        body        = $body
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @Parameters
    $Response
}

# Get current state json configuration of test to modify
$responseBody = Get-LeTest -testId $testId
# $responseBody.environment.connector.hostList

# Create Request Body by pulling all of the unchanged properties directly from the response body
$requestBody = New-Object -TypeName PSObject
$requestBody | Add-Member -MemberType NoteProperty -Name "type" -Value $responseBody.type
$requestBody | Add-Member -MemberType NoteProperty -Name "scheduleType" -Value $responseBody.scheduleType
$requestBody | Add-Member -MemberType NoteProperty -Name "intervalInMinutes" -Value $responseBody.scheduleIntervalInMinutes
$requestBody | Add-Member -MemberType NoteProperty -Name "numberOfSessions" -Value $responseBody.numberOfSessions
$requestBody | Add-Member -MemberType NoteProperty -Name "enableCustomScreenshots" -Value $responseBody.enableCustomScreenshots
$requestBody | Add-Member -MemberType NoteProperty -Name "repeatCount" -Value $responseBody.repeatCount
$requestBody | Add-Member -MemberType NoteProperty -Name "isRepeatEnabled" -Value $responseBody.isRepeatEnabled
$requestBody | Add-Member -MemberType NoteProperty -Name "isEnabled" -Value $responseBody.isEnabled
$requestBody | Add-Member -MemberType NoteProperty -Name "restartOnComplete" -Value $responseBody.restartOnComplete
$requestBody | Add-Member -MemberType NoteProperty -Name "name" -Value $responseBody.name
$requestBody | Add-Member -MemberType NoteProperty -Name "description" -Value $responseBody.description
$requestBody | Add-Member -MemberType NoteProperty -Name "environmentUpdate" -Value $responseBody.environment


# For each RDP host to add to environment, create a new object and append to the original list
for ($i = 0; $i -lt $hostsToAdd.Length; $i++) {
    $newRow = New-Object -TypeName PSObject
    $newRow | Add-Member -MemberType NoteProperty -Name "enabled" -Value "True"
    $newRow | Add-Member -MemberType NoteProperty -Name "endpoint" -Value $hostsToAdd[$i]
    $requestBody.environmentUpdate.connector.hostList += $newRow
}

# Remove unchanged properties from request object
$requestBody.environmentUpdate.PSObject.properties.remove('launcherGroups')
$requestBody.environmentUpdate.PSObject.properties.remove('accountGroups')

# Convert object to json for PUT request
$requestBody = $requestBody | ConvertTo-Json -Depth 8
 
# Update test to modify with updated request body
Update-LeTest -testId $testId -body $requestBody
Write-Host "Test with ID $testId has been successfully updated with your provided list of hosts."
