$ErrorActionPreference = "Stop"

Write-Output "Changing PowerShell Execution Policy to Unrestricted ..."
Update-ExecutionPolicy -Policy Unrestricted

Write-Output "Setting network connections to Private ..."
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

Write-Output "Opening Remote Desktop firewall port ..."
#netsh advfirewall firewall add rule name="Remote Desktop" dir=in localport=3389 protocol=TCP action=allow
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

$enableArgs = @{Force = $true}
try {
    $command = Get-Command Enable-PSRemoting
    if ($command.Parameters.Keys -contains "skipnetworkprofilecheck") {
        $enableArgs.skipnetworkprofilecheck = $true
    }
}
catch {
    $global:error.RemoveAt(0)
}

Write-Output "Setting up WinRM ..."
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow

Enable-PSRemoting @enableArgs
Enable-WSManCredSSP -Force -Role Server
winrm set winrm/config/client/auth '@{Basic="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
Write-Output "... WinRM setup complete"