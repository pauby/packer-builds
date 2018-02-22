Import-Module a:\PSWinBuildToolkit.psm1

Write-Output "Disabling the page file..."
Disable-PageFile

if (Test-Command -cmdname 'Uninstall-WindowsFeature') {
    Write-Output "Removing unused Windows Features..."
    Remove-WindowsFeature -Name 'Powershell-ISE'
    Get-WindowsFeature | 
    ? { $_.InstallState -eq 'Available' } | 
    Uninstall-WindowsFeature -Remove
}

Write-Output "Remove AppX packages ..."
$packages = Get-AppxPackage -AllUser | Where PublisherId -eq 8wekyb3d8bbwe | select -Property PackageFullName

# Do this twice as there are some dependencies that are not removed the first time
$packages | % { Remove-AppxPackage $_.packagefullname -EA SilentlyContinue }
$packages | % { Remove-AppxPackage $_.packagefullname -EA SilentlyContinue }

$packages | % { Remove-AppxProvisionedPackage -Online -PackageName $_.packagefullname -EA SilentlyContinue }

Write-Output "Cleaning SxS ..."
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase

@(
    "$env:localappdata\Nuget",
    "$env:localappdata\temp\*",
    "$env:windir\logs",
    "$env:windir\panther",
    "$env:windir\temp\*",
    "$env:windir\winsxs\manifestcache"
) | % {
        if(Test-Path $_) {
            Write-Output "Removing $_"
            try {
              Takeown /d Y /R /f $_ | Out-Null
              Icacls $_ /GRANT:r administrators:F /T /c /q  2>&1 | Out-Null
              Remove-Item $_ -Recurse -Force -EA SilentlyContinue | Out-Null 
            } 
			catch { 
				$global:error.RemoveAt(0) 
			}
        }
    }
Write-Output "... Finished cleaning SxS"

Write-Output "Defragging C: ..."
if (Test-Command -cmdname 'Optimize-Volume') {
    Optimize-Volume -DriveLetter C
    } else {
    Defrag.exe c: /H
}
Write-Output "... Finished defragging C:"

Write-Output "Zeroing out empty space ..."
$FilePath="c:\zero.tmp"
$Volume = Get-WmiObject win32_logicaldisk -filter "DeviceID='C:'"
$ArraySize= 64kb
$SpaceToLeave= $Volume.Size * 0.05
$FileSize= $Volume.FreeSpace - $SpacetoLeave
$ZeroArray= new-object byte[]($ArraySize)
 
$Stream= [io.File]::OpenWrite($FilePath)
try {
   $CurFileSize = 0
    while($CurFileSize -lt $FileSize) {
        $Stream.Write($ZeroArray,0, $ZeroArray.Length)
        $CurFileSize +=$ZeroArray.Length
    }
}
finally {
    if($Stream) {
        $Stream.Close()
    }
}
 
Remove-Item $FilePath -Force
Write-Output "... Finished zeroing empty space"