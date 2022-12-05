# Login Enterprise

This repository contains useful commands and scripts for use with Login Enterprise public API.

## AccountManagement.ps1 (Supported API versions: v5)

This script can be used to edit account passwords after creating them in bulk. You might have accounts LoginEnt0001, ..., LoginEnt1000. Because bulk creation does not currently allow for unique passwords, it may seem tidious to manually edit each account, certainly as the number of accounts increases. 

### Algorithm:
* Import the CSV file
* For each Username in the CSV:
   * Query an account that matches the row username and domain
   * Modify the account to an updated password

#### Parameters:
* ```fqdn```: The fully qualified domain name of your Login Enterprise virtual appliance
* ```token```: The token generated by Login Enterprise with Configuration level access
* ```pathToCSV```: The filepath to a CSV file containing test user account information
* ```domain```: The desired domain of the user accounts that will be modified 
* ```count```: The number of accounts to query, between 1 and 10,000

The CSV must have the following two columns, in Titlecase. If User1 does not exist, or is not a part of contoso.org domain, it will return error 405. 

| Username    | Password            | Domain           | 
| ----------- | ------------------- |------------------|
| User1       | User1Password       | contoso.org      |
| ...         | ...                 | ...              |
| UserN       | UserNPassword       | contoso.org      |

_Note: The CSV may have other columns. However, the "Username", "Password", and "Domain" columns MUST exist, and be titled as shown above._
## Autologon.ps1

This script enables automatic logons after rebooting a machine. The script download and installs chocolatey package manager, in order to download and install Windows AutoLogon. You will need to provide the parameters listed below.

### Algorithm:
* Download/ install chocolatey
* Downoad/ install Windows Autologon
* Modify registry to configure automatic logins for desired user and number of logins

#### Parameters:
*```DefaultUsername```: The username to enable automatic logins for
*```DefaultPassword```: The username to enable automatic logins for
*```DefaultDomain```: The domain that the user to enable automatic logins belongs to 
*```AutoLogonCount```: The number of times to allow autologons (decrements each login)

## UpdateHosts.ps1

Given a test ID and a list of IP addresses of RDS hosts, this script will append them to your Multi-Host Configuration. 

### Algorithm:
* Get the test environment configuration from the test desired to modify
* For each host in hostsToAdd argument:
  * Append them to the original json in hostList
* Update test using modified JSON request from first step

#### Parameters:
* ```fqdn```: The fully qualified domain name of your Login Enterprise virtual appliance
* ```token```: The token generated by Login Enterprise with Configuration level access
* ```testId```: The ID of the test that you wish to update Multi-Host configuration for
* ```hostsToAdd```: The array of hosts to append to your test environment configuration
