$ErrorActionPreference = "Stop"

#
# Should really reboot before running this particularly if you have disabled the page file
#

Import-Module a:\PSWinBuildToolkit.psm1

Write-Output "Configuring Sysprep status in Registry ..."
Set-ItemProperty -Path "HKLM:\System\Setup\Status\SysprepStatus" -Name "CleanupState" -Value 2 -Force
Set-ItemProperty -Path "HKLM:\System\Setup\Status\SysprepStatus" -Name "GeneralizationState" -Value 7 -Force
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsNT\CurrentVersion\SoftwareProtectionPlatform" -Name "SkipRearm" -Value 1

Write-Output "Configure to recreate pagefile after sysprep ..."
$System = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges

if ($system -ne $null) {
  $System.AutomaticManagedPagefile = $true
  $System.Put() | Out-Null
}

Write-Output "Copying Sysprep unattendfile to the correct location ..."
mkdir C:\Windows\Panther\Unattend -force | Out-Null
copy-item a:\postunattend.xml C:\Windows\Panther\Unattend\unattend.xml | Out-Null

Write-Output "Running sysprep..."
C:\windows\system32\sysprep\sysprep.exe /generalize /oobe /shutdown /unattend:C:\Windows\Panther\Unattend\unattend.xml