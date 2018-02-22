
function Get-OS {

    Param (
        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$ComputerName = "localhost"
    )

    Begin {}

    Process {
        try {
            $osData = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
        }
        catch {
            throw $Error[0]
        }

        @{
            name = $osData.Caption;
            architecture = $osData.OSArchitecture;
            platform = switch ($osData.ProductType) { 
                1 { "Workstation" }
                2 { "Domain Controller" } 
                3 { "Server" }
            }
            type = switch ($osData.OSType) { 
                18 { "Windows" } 
            }
            version = $osData.Version;
            buildnumber = $osData.BuildNumber;
         }
    }

    End {}
}

Function Test-RegistryValue 
{
    param(
        [Alias("RegistryPath")]
        [Parameter(Position = 0)]
        [String]$Path
        ,
        [Alias("KeyName")]
        [Parameter(Position = 1)]
        [String]$Name
    )

    process 
    {
        if (Test-Path $Path) 
        {
            $Key = Get-Item -LiteralPath $Path
            if ($Key.GetValue($Name, $null) -ne $null)
            {
                if ($PassThru)
                {
                    Get-ItemProperty $Path $Name
                }       
                else
                {
                    $true
                }
            }
            else
            {
                $false
            }
        }
        else
        {
            $false
        }
    }
}

Function Disable-UAC
{
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -PropertyType "DWord" -Force
}

Function Disable-PageFile
{
    $cs = gwmi Win32_ComputerSystem
    if ($cs.AutomaticManagedPagefile) 
    {
		try {
			$cs.AutomaticManagedPagefile = $false
			$PutOptions = New-Object System.Management.PutOptions
			$PutOptions.Type = 2
			$cs.PsBase.Put()
			$true
		}
		catch {
			$false
		}
    }
    $false
}

Function Enable-PageFile
{
    $cs = gwmi Win32_ComputerSystem
    if (!$cs.AutomaticManagedPagefile) {
        $cs.AutomaticManagedPagefile = $True
        $false
    }
    $true
}

Function Remove-PageFile
{
    $pg = gwmi win32_pagefileusage
    if ($pg) {
        remove-item $pg.name -force
        $true
    }
    $false
}

function Test-EmptyPassword
{
    Param 
    (
        [Parameter(Mandatory=$true)]
        [string]
        $Username,
        
        [Parameter(Mandatory=$false)]
        [string]
        $Computername = "localhost"
    )
    
    $user = [ADSI]("WinNT://" + $Computername+ "/" + $Username + ", user")
    try 
    {
        $user.invoke("ChangePassword","","DummyPassword")    
    }
    catch [System.Exception] 
    {
        return $false
    }
    
    $user.invoke("ChangePassword","DummyPassword","")  
    return $true
}

# http://stackoverflow.com/questions/9701840/how-to-create-a-shortcut-using-powershell
function Set-Shortcut
{
	Param
	(
		[Parameter(Mandatory=$true)]
		[string]
		$TargetPath,
		
		[Parameter(Mandatory=$false)]
		[string]
		$TargetArguments,
		
		[Parameter(Mandatory=$true)]
		[string]
		$ShortcutPath
		)
		
	$WshShell = New-Object -comObject WScript.Shell
	$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
	$Shortcut.TargetPath = $TargetPath
	if (-not [string]::IsNullOrEmpty($TargetArguments))
	{
		write-host "arguments - $targetarguments"
		$Shortcut.Arguments = $TargetArguments		
	}
	$Shortcut.Save()
}

# https://github.com/mwrock/packer-templates/blob/master/scripts/Test-Command.ps1
function Test-Command($cmdname) {
    try {
        Get-Command -Name $cmdname -ErrorAction Stop
        return $true
    }
    catch {
        $global:error.RemoveAt(0)
        return $false
    }
}

<#    
	# Change international settings
	Write-Step "Configuring International Settings."
    Write-StepSub "Setting to UK."
	Invoke-Expression "regedit /s $(Join-Path -Path $scriptPath -ChildPath 'Tools\InternationalSettings-UK.reg')"
	$cmd = "intl.cpl,,/f:$(Join-Path -Path $scriptPath -ChildPath 'Tools\RegionalSettings.xml')"
	Invoke-Expression "rundll32.exe shell32,Control_RunDLL '$cmd'"
    
    # Renaming first network interface
    Write-Step "Configuring Primary Network Interface."
    Write-StepSub "Renaming first network adapter to 'LAN' and configuring it's connection profile to 'Private'."
    Get-NetAdapter | Select -first 1 | Rename-NetAdapter -NewName "LAN" -Passthru | Set-NetConnectionProfile -NetworkCategory Private

	# Copy bginfo
	Write-Step "Configuring BGInfo." 
    $defaultStartup = "$($env:SystemDrive)\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    $bginfoLocalPath = (Join-Path -Path $env:PUBLIC -ChildPath "Documents\bginfo")
    Write-StepSub "Copying BGInfo to $bginfoLocalPath"
    if (-not (Test-Path $bginfoLocalPath))
    {
        New-Item -Path $bginfoLocalPath -ItemType Directory
    }
    Copy-Item -Path (Join-Path -Path $toolsPath -ChildPath "bginfo") -Destination $bginfoLocalPath -Recurse -Force
    
    Write-StepSub "Creating shortcut for BGInfo in Startup folders."
    if (-not (Test-Path $defaultStartup))
    {
        New-Item -Path $defaultStartup -ItemType Directory
    }
    Set-Shortcut -TargetPath "$bginfoLocalPath\bginfo.exe" -TargetArguments "$bginfoLocalPath\default.bgi /timer:0 /nolicprompt" -ShortcutPath "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\bginfo.lnk"
	Set-Shortcut -TargetPath "$bginfoLocalPath\bginfo.exe" -TargetArguments "$bginfoLocalPath\default.bgi /timer:0 /nolicprompt" -ShortcutPath "$defaultStartup\bginfo.lnk"
#    Copy-Item -Path (Join-Path -Path $toolsPath -ChildPath "bginfo\bginfo.cmd") -Destination $defaultStartup
#    Copy-Item -Path  (Join-Path -Path $toolsPath -ChildPath "bginfo\bginfo.cmd") -Destination (Join-Path -Path $env:USERPROFILE -ChildPath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\bginfo.cmd")
	
    # Set the script to run at login and reboot (C:\WINDOWS\system32\WindowsPowerShell\v1.0\)
    $cmd = "$(Join-Path -Path $scriptPath -ChildPath 'nircmdc.exe') elevate powershell.exe -ExecutionPolicy Unrestricted -NoExit -file $($MyInvocation.MyCommand.Definition) -AfterReboot"
    Write-Step "Configuring script to run on login."
    Write-StepSub "Adding command '$cmd' to RunOnce registry setting."
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name PackVM -Value $cmd
    
    Restart-Computer -Confirm
    Exit
}

Write-Step "Configuring Pagefile." 
Write-StepSub "Enabling pagefile."
Invoke-Expression 'wmic computersystem set AutomaticManagedPagefile=true'

Write-Step "Removing Windows Updates"
$sdPath = Join-Path $env:SystemRoot -ChildPath "SoftwareDistribution"
if (Test-Path $sdPath)
{
    Write-StepSub "Deleting $sdPath"
    # we don't start the service afterwards as it will simply create the SoftwareDistribution folders again before 
    # packiung the VM
    Stop-Service -Name wuauserv
    Remove-Item -Path $sdPath -Recurse -Force
}
else  
{
        Write-StepSub "No updates found ($sdPath does not exist)."
}

# Turn off System Restore - only works on non-server OS
$os = Get-WmiObject -class Win32_OperatingSystem
if ($os.caption -notmatch "Server")
{
    #client OS
    Write-Step "Configuring System Restore."
    Write-StepSub "Disabling system restore on drive $env:SystemDrive"
    Disable-ComputerRestore -drive $env:SystemDrive    
}

# Deleting old shadow copies
Write-Step "Configuring Shadow Copies."
Write-StepSub "Deleting shadow copies."
Invoke-Expression 'vssadmin delete shadows /all /quiet'


# Run CCleaner
Write-Step "Cleaning Disks and Wiping Free Space."
Write-StepSub "Running CC Cleaner."
start-process (Join-Path -Path $ScriptPath -ChildPath "Tools\CC\CCleaner64.exe") -argumentlist "/auto" -wait

# Zeroing free space
#Write-Host 'Zeroing free space.' -ForegroundColor Green
#Write-Host 'Please wait as this can take some time!' -ForegroundColor Red
#Invoke-Expression ".\Write-ZeroesToFreeSpace.ps1 C:"

# Defrag
Write-StepSub "Defrag Disk Drives."
start-process 'defrag.exe' -ArgumentList "$env:SystemDrive /H /X" -nonewwindow -wait

#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Disable UAC
#Write-Host 'Disabling UAC.' -ForegroundColor Green
#Disable-UAC

# Setup WinRM
# see http://serverfault.com/questions/337905/enabling-powershell-remoting-access-is-denied
# error is likely because password is blank
Write-Step "Configuring PowerShell Remoting."
Write-StepSub "Enabling PowerShell remoting."
Enable-PSRemoting -Force
Write-StepSub "Configuring PowerShell remoting settings."
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="512"}' | Out-Null
winrm set winrm/config '@{MaxTimeoutms="1800000"}' | Out-Null
winrm set winrm/config/service '@{AllowUnencrypted="true"}' | Out-Null
winrm set winrm/config/service/auth '@{Basic="true"}' | Out-Null

Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value True
Set-Item WSMan:\localhost\Service\Auth\Basic -Value True


#Setup RDP




# Deleting Packages
$os = Get-WmiObject -class Win32_OperatingSystem
if ($os.caption -match "Windows 10" -or $os.caption -match "Windows 8")
{
    Write-Step "Removing Problematic Packages."
    $packages = @( "Microsoft.WindowsMaps", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.XboxApp", "Microsoft.ZuneVideo", "Microsoft.ZuneMusic", "Microsoft.3DBuilder", 
        "AcerIncorporated.AcerExplorer" )
    foreach ($package in $packages)
    {
        Write-StepSub "Removing package '$packages' (if it is installed)."
        get-appxpackage $package | remove-appxpackage
    }
    
    # these packages I don't know the full names of yet hence the searches
    Write-StepSub "Removing Candy Crush."    
    Get-AppxPackage | where { $_PackageFullName -like "king.com*"} | Remove-AppxPackage

    Write-StepSub "Removing Twitter."
    Get-AppxPackage | where { $_PackageFullName -like "*twitter*"} | Remove-AppxPackage
}

# Final prep
Write-Step "Final Preparation."
Write-StepSub "Deleting build directory $scriptPath"
Remove-Item $scriptPath -Recurse -Force

# Sysprep
Write-StepSub "Sysprep'ing the computer."
Read-Host "Press ENTER to continue with Sysprep."
Invoke-Expression -Command "$(Join-Path -Path $env:SystemRoot -ChildPath '\system32\sysprep\sysprep.exe') /generalize /oobe /shutdown"

# Update help

#>