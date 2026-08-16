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

$registeredRoot = (Get-ItemProperty -LiteralPath 'HKLM:\Software\Neutron' -ErrorAction SilentlyContinue).InstallLocation
if (-not $InstallRoot) { $InstallRoot = $registeredRoot }
if (-not $InstallRoot) { $InstallRoot = Join-Path $env:ProgramFiles 'Neutron' }
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
$allowedRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | ForEach-Object {
    [IO.Path]::GetFullPath($_).TrimEnd('\') + '\'
}
$insideProgramFiles = @($allowedRoots | Where-Object {
    $InstallRoot.StartsWith($_, [StringComparison]::OrdinalIgnoreCase)
}).Count -gt 0
$matchesRegisteredRoot = $registeredRoot -and
    $InstallRoot.Equals([IO.Path]::GetFullPath($registeredRoot).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
$hasNeutronMarkers = (Test-Path -LiteralPath (Join-Path $InstallRoot 'Uninstall.exe') -PathType Leaf) -and (
    (Test-Path -LiteralPath (Join-Path $InstallRoot 'Neutron.exe') -PathType Leaf) -or
    (Test-Path -LiteralPath (Join-Path $InstallRoot 'resources\app\src\main.cjs') -PathType Leaf)
)
if ((-not $insideProgramFiles -and -not $matchesRegisteredRoot) -or -not $hasNeutronMarkers -or
    $InstallRoot.Equals([IO.Path]::GetPathRoot($InstallRoot), [StringComparison]::OrdinalIgnoreCase)) {
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

Remove-Item -LiteralPath 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Neutron' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Neutron' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\Neutron.exe' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKLM:\Software\Neutron' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:Public 'Desktop\Neutron.lnk') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Neutron.lnk') -Force -ErrorAction SilentlyContinue

$deleteOnReboot = $false
try {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
} catch {
    # The current PowerShell process may already have loaded the old AMSI DLL.
    # Schedule only the already-validated Neutron tree for deletion at reboot.
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NeutronDelayedDelete {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool MoveFileEx(string existingName, string newName, int flags);
}
'@
    $entries = @(Get-ChildItem -LiteralPath $InstallRoot -Recurse -Force -ErrorAction SilentlyContinue)
    foreach ($entry in @($entries | Where-Object { -not $_.PSIsContainer })) {
        $fullPath = [IO.Path]::GetFullPath($entry.FullName)
        if (-not $fullPath.StartsWith($InstallRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Kurulum ağacı dışındaki yol reddedildi: $fullPath"
        }
        [void][NeutronDelayedDelete]::MoveFileEx($fullPath, $null, 4)
    }
    foreach ($entry in @($entries | Where-Object { $_.PSIsContainer } | Sort-Object { $_.FullName.Length } -Descending)) {
        [void][NeutronDelayedDelete]::MoveFileEx($entry.FullName, $null, 4)
    }
    [void][NeutronDelayedDelete]::MoveFileEx($InstallRoot, $null, 4)
    $deleteOnReboot = $true
}

if ($deleteOnReboot) {
    Write-Host 'Neutron kayıtları temizlendi. Kilitli program dosyaları yeniden başlatmada silinecek.' -ForegroundColor Yellow
    Write-Host 'Şimdi bilgisayarı yeniden başlatın.' -ForegroundColor Yellow
} else {
    Write-Host 'Neutron tamamen kaldırıldı; yalnız Neutron bileşenleri temizlendi.' -ForegroundColor Green
}
