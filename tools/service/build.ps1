#Requires -Version 5.1
# Builds tools/service/NeutronServiceHost.cpp into
# runtime/service/x64/NeutronServiceHost.exe. Mirrors tools/amsi/build.ps1.
param(
    [string]$Architecture = "x64"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$sourceDir = $PSScriptRoot
$outDir = Join-Path $repoRoot "runtime\service\$Architecture"
$objDir = Join-Path $repoRoot "build\service\$Architecture"

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe bulunamadı. Visual Studio Build Tools (C++ ile masaüstü geliştirme) kurulu mu?"
}
$installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installPath) {
    throw "MSVC C++ araçları bulunamadı. Visual Studio Installer'da 'C++ ile masaüstü geliştirme' iş yükünü kontrol edin."
}
$vcvarsall = Join-Path $installPath "VC\Auxiliary\Build\vcvarsall.bat"
if (-not (Test-Path $vcvarsall)) {
    throw "vcvarsall.bat bulunamadı: $vcvarsall"
}

$sourcePath = Join-Path $sourceDir "NeutronServiceHost.cpp"
$exePath = Join-Path $outDir "NeutronServiceHost.exe"

$cmd = "call `"$vcvarsall`" $Architecture && " +
       "cl.exe /nologo /std:c++17 /EHsc /W3 /O2 /MT /D_WINDOWS /DUNICODE /D_UNICODE " +
       "/Fo`"$objDir\\`" `"$sourcePath`" " +
       "/link /nologo /SUBSYSTEM:CONSOLE " +
       "/OUT:`"$exePath`" advapi32.lib"

Write-Host "Derleniyor ($Architecture): $exePath"
cmd /c $cmd
if ($LASTEXITCODE -ne 0) {
    throw "Derleme başarısız oldu (çıkış kodu $LASTEXITCODE)."
}

Write-Host "Neutron Service Host derlendi: $exePath"
