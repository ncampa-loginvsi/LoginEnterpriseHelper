# This script downloads chocolatey package manager, in order to install Autologon. 
# Upon reboot, the script will login as $DefaultUsername, $DefaultPassword, using the $DefaultDomain
# The number of automatic logins is dictated by $AutoLogonCount i.e. $AutoLogonCount = 1 logs in once
Param(
  $DefaultUsername, 
  $DefaultPassword, 
  $DefaultDomain, 
  $AutoLogonCount
)

# Download chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Autologon Package
choco install autologon -y

# Set Registry credentials for Autologon
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String 
Set-ItemProperty $RegPath "DefaultUsername" -Value "$DefaultUsername" -type String 
Set-ItemProperty $RegPath "DefaultPassword" -Value "$DefaultPassword" -type String
Set-ItemProperty $RegPath "AutoLogonCount" -Value "$AutoLogonCount" -type String

# Enable Autologon
Start-Process "C:\ProgramData\chocolatey\lib\autologon\tools\Autologon.exe" -ArgumentList $DefaultUsername, $DefaultDomain, $DefaultPassword, "/accepteula"

Write-Host "AutoLogon Has Been Enabled"

