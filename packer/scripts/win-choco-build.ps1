$ErrorActionPreference = "Stop"

Import-Module "a:\PSWinBuildToolkit.psm1"

# Disable Internet Explorer ESC in Server OS
if ((Get-OS).platform -eq "Server") {
    # Registry way
    # Adapted from http://stackoverflow.com/a/29571064/18475
    #$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    #$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    #New-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force -EA SilentlyContinue | Out-Null
    #New-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force -EA SilentlyContinue | Out-Null
    #Stop-Process -Name Explorer -Force
    #Write-Output "IE Enhanced Security Configuration (ESC) has been disabled."

    # Boxstarter way
    Disable-InternetExplorerESC
}

# http://techrena.net/disable-ie-set-up-first-run-welcome-screen/
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1 -PropertyType "DWord" -Force | Out-Null
Write-Output "IE first run welcome screen has been disabled."