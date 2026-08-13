#Requires -Version 5.1
# Builds tools/amsi/*.cpp into runtime/amsi/x64/NeutronAmsiProvider.dll using
# the MSVC toolchain located via vswhere. Mirrors the intent of
# tools/engine/*.spec (produce a versioned artifact under runtime/) without
# pulling in a heavier build system, matching this repo's existing
# preference for small purpose-built scripts (see tools/build-windows-icon.cjs).
param(
    [string]$Architecture = "x64"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$sourceDir = $PSScriptRoot
$outDir = Join-Path $repoRoot "runtime\amsi\$Architecture"
$objDir = Join-Path $repoRoot "build\amsi\$Architecture"

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

$sources = @(
    "NeutronAmsi.cpp",
    "PipeClient.cpp",
    "AmsiProvider.cpp",
    "ClassFactory.cpp",
    "Dll.cpp"
) | ForEach-Object { Join-Path $sourceDir $_ }

$dllPath = Join-Path $outDir "NeutronAmsiProvider.dll"

$sourceArgs = ($sources | ForEach-Object { '"{0}"' -f $_ }) -join " "
$cmd = "call `"$vcvarsall`" $Architecture && " +
       "cl.exe /nologo /std:c++17 /EHsc /W3 /O2 /MT /D_WINDOWS /DUNICODE /D_UNICODE " +
       "/Fo`"$objDir\\`" $sourceArgs " +
       "/link /nologo /DLL /DEF:`"$sourceDir\NeutronAmsiProvider.def`" " +
       "/OUT:`"$dllPath`" ole32.lib oleaut32.lib advapi32.lib amsi.lib"

Write-Host "Derleniyor ($Architecture): $dllPath"
cmd /c $cmd
if ($LASTEXITCODE -ne 0) {
    throw "Derleme başarısız oldu (çıkış kodu $LASTEXITCODE)."
}

Write-Host "Neutron AMSI Provider derlendi: $dllPath"
