# Install Autologon Package
choco install autologon -y

# Set Registry credentials for Autologon
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$DefaultUsername = "lab-admin"
$DefaultDomain = "ad.lab"
$DefaultPassword = "P@`$`$w0rd1234!"
$AutoLogonCount = "2"

Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String 
Set-ItemProperty $RegPath "DefaultUsername" -Value "$DefaultUsername" -type String 
Set-ItemProperty $RegPath "DefaultPassword" -Value "$DefaultPassword" -type String
Set-ItemProperty $RegPath "AutoLogonCount" -Value "$AutoLogonCount" -type String

# Enable Autologon
Start-Process "C:\ProgramData\chocolatey\lib\autologon\tools\Autologon.exe" -ArgumentList $DefaultUsername, $DefaultDomain, $DefaultPassword, "/accepteula"

Write-Host "AutoLogon Has Been Enabled"

