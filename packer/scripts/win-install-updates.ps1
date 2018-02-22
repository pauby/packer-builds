$ErrorActionPreference = "Stop"

Import-Module Boxstarter.Bootstrapper
Import-Module Boxstarter.WinConfig

Write-Output "Installing Windows Updates - this WILL take a long time ..."
Install-WindowsUpdate -AcceptEula

if(Test-PendingReboot){ 
	Invoke-Reboot 
}