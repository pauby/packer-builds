$ErrorActionPreference = "Stop"

Write-Output 'Setting Windows Update service to Manual startup type.'
Stop-Service -Name wuauserv | Set-Service -StartupType Disabled