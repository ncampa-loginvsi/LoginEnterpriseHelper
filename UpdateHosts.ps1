Param(
    $fqdn = "YOUR_FQDN",
    $token = "YOUR_API_CONFIGURATION_TOKEN",
    $testId = "ID_OF_TEST_TO_MODIFY",
    $hostsToAdd = @("HOST_TO_ADD_1", "HOST_TO_ADD_2")
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
        [string]$include = "all"
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
$requestBody = Get-LeTest -testId $testId

# For each RDP host to add to environment, create a new object and append to the original list
for ($i = 0; $i -lt $hostsToAdd.Length; $i++) {
    $newRow = New-Object -TypeName PSObject
    $newRow | Add-Member -MemberType NoteProperty -Name "enabled" -Value "True"
    $newRow | Add-Member -MemberType NoteProperty -Name "endpoint" -Value $hostsToAdd[$i]
    $requestBody.environment.connector.hostList += $newRow
}

# Convert custom object back to Json for request body
$requestBody = $requestBody | ConvertTo-Json -Depth 7

# Update test to modify with updated request body
Update-LeTest -testId $testId -body $requestBody
