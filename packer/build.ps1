$ErrorActionPreference = "Stop"

$scripts = @(
    "a:\Disable-WindowsUpdateService.ps1",
    "a:\win-vagrant-build.ps1",
    "a:\win-choco-build.ps1",
    "a:\win-clean-image.ps1",
    "a:\win-prepare-sysprep.ps1"
) | ForEach-Object {
    iex $_
}
