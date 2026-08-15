#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallRoot
)

$ErrorActionPreference = 'Stop'
$neutronAmsiGuid = '{ADACFA90-B877-414D-A818-2EA5291E290E}'
$neutronWscGuid = 'ac0008b0-564a-44f8-8ec7-f2a2d82a8fe8'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    if ($InstallRoot) { $arguments += @('-InstallRoot', ('"{0}"' -f $InstallRoot)) }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs -Wait
    exit $LASTEXITCODE
}

if (-not $InstallRoot) {
    $InstallRoot = (Get-ItemProperty -LiteralPath 'HKLM:\Software\Neutron' -ErrorAction SilentlyContinue).InstallLocation
}
if (-not $InstallRoot) { $InstallRoot = Join-Path $env:ProgramFiles 'Neutron' }
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$programFilesRoot = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
if (-not $InstallRoot.StartsWith($programFilesRoot, [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($InstallRoot) -ne 'Neutron') {
    throw "Güvenli olmayan kurulum yolu reddedildi: $InstallRoot"
}

Get-Process -Name Neutron -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
& "$env:SystemRoot\System32\schtasks.exe" /delete /tn NeutronWatchdog /f 2>$null | Out-Null
& "$env:SystemRoot\System32\sc.exe" stop NeutronService 2>$null | Out-Null
& "$env:SystemRoot\System32\sc.exe" delete NeutronService 2>$null | Out-Null

$dll = Join-Path $InstallRoot 'resources\runtime\amsi\x64\NeutronAmsiProvider.dll'
if (Test-Path -LiteralPath $dll -PathType Leaf) {
    & "$env:SystemRoot\System32\regsvr32.exe" /s /u $dll
}
foreach ($registryPath in @(
    "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\$neutronAmsiGuid",
    "HKLM:\SOFTWARE\Classes\CLSID\$neutronAmsiGuid",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\AMSI\Providers\$neutronAmsiGuid",
    "HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID\$neutronAmsiGuid"
)) {
    Remove-Item -LiteralPath $registryPath -Recurse -Force -ErrorAction SilentlyContinue
}
Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct `
    -Filter "instanceGuid='$neutronWscGuid'" -ErrorAction SilentlyContinue |
    Remove-CimInstance -ErrorAction SilentlyContinue
Get-NetFirewallRule -Name 'Neutron-FW-*' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

$uninstaller = Join-Path $InstallRoot 'Uninstall.exe'
$appExecutable = Join-Path $InstallRoot 'Neutron.exe'
$parkedExecutable = Join-Path $InstallRoot 'Neutron.exe.cleanup-disabled'
if (Test-Path -LiteralPath $appExecutable -PathType Leaf) {
    Move-Item -LiteralPath $appExecutable -Destination $parkedExecutable -Force
}
if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
    throw "Kaldırıcı bulunamadı: $uninstaller"
}
$process = Start-Process -FilePath $uninstaller -Wait -PassThru
if ($process.ExitCode -ne 0) {
    if ((Test-Path -LiteralPath $parkedExecutable) -and -not (Test-Path -LiteralPath $appExecutable)) {
        Move-Item -LiteralPath $parkedExecutable -Destination $appExecutable -Force
    }
    throw "Neutron kaldırıcı kod $($process.ExitCode) ile durdu."
}
Remove-Item -LiteralPath $parkedExecutable -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $InstallRoot -ErrorAction SilentlyContinue
Write-Host 'Neutron kaldırıldı; yalnız Neutron bileşenleri temizlendi.' -ForegroundColor Green
