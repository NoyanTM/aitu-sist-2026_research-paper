# References: 
# https://docs.ansible.com/projects/ansible/latest/os_guide/windows_ssh.html
# https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-overview

# Install and enable components of OpenSSH
Get-WindowsCapability -Name OpenSSH.Server* -Online | Add-WindowsCapability -Online

# Start and configure OpenSSH to run automatically
Set-Service -Name sshd -StartupType Automatic -Status Running

# Set firewall rules for OpenSSH
$firewallParams = @{
    Name        = 'sshd-Server-In-TCP'
    DisplayName = 'Inbound rule for OpenSSH Server (sshd) on TCP port 22'
    Action      = 'Allow'
    Direction   = 'Inbound'
    Enabled     = 'True'
    Profile     = 'Any'
    Protocol    = 'TCP'
    LocalPort   = 22
}
New-NetFirewallRule @firewallParams

# Set default shell to powershell.exe instead of cmd.exe
$shellParams = @{
    Path         = 'HKLM:\SOFTWARE\OpenSSH'
    Name         = 'DefaultShell'
    Value        = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    PropertyType = 'String'
    Force        = $true
}
New-ItemProperty @shellParams
