Param(
    $fqdn = "demolab.loginvsi.com",
    $token = "GuxK2MHmD5FqxYDWQTxd1HJATZ79rPbURMQQPxF2TFE",
    $testId = "60dbc113-00c5-47f6-8814-d36f64143427",
    $hostsToAdd = @("172.173.162.2")
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
$requestBody | Add-Member -MemberType NoteProperty -Name "numberOfSessions" -Value $responseBody.numberOfSessions
$requestBody | Add-Member -MemberType NoteProperty -Name "rampUpDurationInMinutes" -Value $responseBody.rampUpDurationInMinutes
$requestBody | Add-Member -MemberType NoteProperty -Name "euxEnabled" -Value $responseBody.euxEnabled
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
