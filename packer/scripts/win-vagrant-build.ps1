$ErrorActionPreference = "Stop"

Import-Module a:\PSWinBuildToolkit.psm1

Write-Output "Performing base Vagrant requirements for Windows boxes..."
Disable-UAC

Write-Output "Disable password complexity ..."
secedit /configure /cfg a:\disable-password-complexity.inf /db secedit.sdb /overwrite /quiet

$os = Get-OS
if ($os.platform -eq "Server") {
	Write-Output "Disabling Shutdown Tracker ..."
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name ShutdownReasonOn -Value 1 -Force | Out-Null

	Write-Output "Disabling Server Manager startup at logon ..."
	New-ItemProperty -Path HKCU:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -Value 1 -Force | Out-Null
}


$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
New-ItemProperty -Path $WinlogonPath -Name AutoAdminLogon -Value "1" -Force | Out-Null
New-ItemProperty -Path $WinlogonPath -Name DefaultUserName -Value "vagrant" -Force | Out-Null
New-ItemProperty -Path $WinlogonPath -Name DefaultUserPassword -Value "vagrant" -Force | Out-Null