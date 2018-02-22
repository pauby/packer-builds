Write-BoxstarterMessage "Setting up WinRM ..."
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
Write-BoxstarterMessage "... WinRM setup complete"