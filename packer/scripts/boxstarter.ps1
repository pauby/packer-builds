<# $WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
Remove-ItemProperty -Path $WinlogonPath -Name AutoAdminLogon
Remove-ItemProperty -Path $WinlogonPath -Name DefaultUserName

iex ((new-object net.webclient).DownloadString('https://raw.githubusercontent.com/mwrock/boxstarter/master/BuildScripts/bootstrapper.ps1'))
Get-Boxstarter -Force

$secpasswd = ConvertTo-SecureString "vagrant" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("vagrant", $secpasswd)

Import-Module $env:ProgramData\Boxstarter\Boxstarter.Chocolatey\Boxstarter.Chocolatey.psd1
Install-BoxstarterPackage -PackageName a:\build.ps1 -Credential $cred
read-host
#>

Write-Host "Setting network connections to Private ..."
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

Write-Host "Opening Remote Desktop firewall port ..."
Enable-RemoteDesktop
netsh advfirewall firewall add rule name="Remote Desktop" dir=in localport=3389 protocol=TCP action=allow

Update-ExecutionPolicy -Policy Unrestricted

Write-Host "Setting up WinRM ..."
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow

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

Enable-PSRemoting @enableArgs
Enable-WSManCredSSP -Force -Role Server
winrm set winrm/config/client/auth '@{Basic="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
Write-Host "... WinRM setup complete"