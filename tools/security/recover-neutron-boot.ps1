[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WindowsDirectory,

    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$windowsPath = [System.IO.Path]::GetFullPath($WindowsDirectory).TrimEnd('\\')
$activeWindows = if ($env:SystemRoot) { [System.IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\\') } else { '' }

if ($activeWindows -and $windowsPath.Equals($activeWindows, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Bu araç çalışan Windows üzerinde kullanılmaz. Normal Windows açılıyorsa Neutron kaldırıcısını kullanın; açılmıyorsa WinRE Komut İstemi içinden çevrimdışı Windows klasörünü belirtin.'
}

$systemHive = Join-Path $windowsPath 'System32\config\SYSTEM'
$softwareHive = Join-Path $windowsPath 'System32\config\SOFTWARE'
if (-not (Test-Path -LiteralPath $systemHive -PathType Leaf)) {
    throw "Çevrimdışı SYSTEM hive bulunamadı: $systemHive"
}
if (-not (Test-Path -LiteralPath $softwareHive -PathType Leaf)) {
    throw "Çevrimdışı SOFTWARE hive bulunamadı: $softwareHive"
}

$driveRoot = [System.IO.Path]::GetPathRoot($windowsPath)
$recoveryRoot = Join-Path $driveRoot 'Neutron-Recovery'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$sessionRoot = Join-Path $recoveryRoot $stamp
$systemMountName = 'NeutronOfflineSystem'
$softwareMountName = 'NeutronOfflineSoftware'
$systemMount = "HKLM:\$systemMountName"
$softwareMount = "HKLM:\$softwareMountName"

function Invoke-RegExe {
    param([string[]]$Arguments)
    $reg = Join-Path $env:SystemRoot 'System32\reg.exe'
    & $reg @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "reg.exe başarısız oldu (kod $LASTEXITCODE): $($Arguments -join ' ')"
    }
}

function Get-RegistryValues {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @{} }
    $item = Get-ItemProperty -LiteralPath $Path
    $result = @{}
    foreach ($property in $item.PSObject.Properties) {
        if ($property.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
            $result[$property.Name] = $property.Value
        }
    }
    return $result
}

New-Item -ItemType Directory -Force -Path $sessionRoot | Out-Null
if ($Apply) {
    Copy-Item -LiteralPath $systemHive -Destination (Join-Path $sessionRoot 'SYSTEM.before-neutron-recovery') -Force
    Copy-Item -LiteralPath $softwareHive -Destination (Join-Path $sessionRoot 'SOFTWARE.before-neutron-recovery') -Force
}

$systemLoaded = $false
$softwareLoaded = $false
try {
    Invoke-RegExe -Arguments @('load', "HKLM\$systemMountName", $systemHive)
    $systemLoaded = $true
    Invoke-RegExe -Arguments @('load', "HKLM\$softwareMountName", $softwareHive)
    $softwareLoaded = $true

    $select = Get-ItemProperty -LiteralPath "$systemMount\Select"
    $controlSetName = 'ControlSet{0:D3}' -f [int]$select.Current
    $servicesRoot = "$systemMount\$controlSetName\Services"
    $classRoot = "$systemMount\$controlSetName\Control\Class"

    $legacyDrivers = @()
    Get-ChildItem -LiteralPath $servicesRoot -ErrorAction SilentlyContinue | ForEach-Object {
        $values = Get-RegistryValues -Path $_.PSPath
        $type = if ($null -ne $values.Type) { [int]$values.Type } else { 0 }
        $identity = "$($_.PSChildName) $($values.DisplayName) $($values.ImagePath)"
        if (((($type -band 1) -ne 0) -or (($type -band 2) -ne 0)) -and $identity -match '(?i)neutron') {
            $legacyDrivers += [pscustomobject]@{
                Name = $_.PSChildName
                Type = $type
                Start = $values.Start
                ImagePath = $values.ImagePath
                DisplayName = $values.DisplayName
            }
        }
    }
    $legacyNames = @($legacyDrivers | ForEach-Object { $_.Name })

    $filterReferences = @()
    Get-ChildItem -LiteralPath $classRoot -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($filterName in @('UpperFilters', 'LowerFilters')) {
            $item = Get-ItemProperty -LiteralPath $_.PSPath -Name $filterName -ErrorAction SilentlyContinue
            $values = if ($null -ne $item) { @($item.$filterName) } else { @() }
            $matches = @($values | Where-Object { $legacyNames -contains [string]$_ })
            if ($matches.Count -gt 0) {
                $filterReferences += [pscustomobject]@{
                    ClassKey = $_.PSChildName
                    ValueName = $filterName
                    Before = $values
                    Matched = $matches
                }
            }
        }
    }

    $servicePath = Join-Path $servicesRoot 'NeutronService'
    $serviceValues = Get-RegistryValues -Path $servicePath
    $amsiProviderPath = "$softwareMount\Microsoft\AMSI\Providers\{ADACFA90-B877-414D-A818-2EA5291E290E}"
    $amsiClsidPath = "$softwareMount\Classes\CLSID\{ADACFA90-B877-414D-A818-2EA5291E290E}"
    $taskPath = Join-Path $windowsPath 'System32\Tasks\NeutronWatchdog'

    $report = [ordered]@{
        GeneratedAt = (Get-Date).ToString('o')
        WindowsDirectory = $windowsPath
        Apply = [bool]$Apply
        ControlSet = $controlSetName
        LegacyDrivers = $legacyDrivers
        FilterReferences = $filterReferences
        NeutronService = $serviceValues
        AmsiProviderRegistered = (Test-Path -LiteralPath $amsiProviderPath)
        AmsiClsidRegistered = (Test-Path -LiteralPath $amsiClsidPath)
        WatchdogTaskPresent = (Test-Path -LiteralPath $taskPath -PathType Leaf)
    }
    $reportPath = Join-Path $sessionRoot 'report.json'
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8

    if (-not $Apply) {
        Write-Host "Yalnız denetim tamamlandı; hiçbir şey değiştirilmedi. Rapor: $reportPath"
        Write-Host "Değişiklik uygulamak için aynı komutu -Apply ile tekrar çalıştırın."
        return
    }

    foreach ($driver in $legacyDrivers) {
        $driverPath = Join-Path $servicesRoot $driver.Name
        Set-ItemProperty -LiteralPath $driverPath -Name Start -Value 4
        $overridePath = Join-Path $driverPath 'StartOverride'
        if (Test-Path -LiteralPath $overridePath) {
            foreach ($valueName in (Get-Item -LiteralPath $overridePath).GetValueNames()) {
                Set-ItemProperty -LiteralPath $overridePath -Name $valueName -Value 4
            }
        }
    }

    foreach ($reference in $filterReferences) {
        $classPath = Join-Path $classRoot $reference.ClassKey
        $kept = @($reference.Before | Where-Object { $legacyNames -notcontains [string]$_ })
        if ($kept.Count -eq 0) {
            Remove-ItemProperty -LiteralPath $classPath -Name $reference.ValueName -ErrorAction Stop
        } else {
            Set-ItemProperty -LiteralPath $classPath -Name $reference.ValueName -Value ([string[]]$kept)
        }
    }

    if (Test-Path -LiteralPath $servicePath) {
        Set-ItemProperty -LiteralPath $servicePath -Name Start -Value 4
    }
    Remove-Item -LiteralPath $amsiProviderPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $amsiClsidPath -Recurse -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $taskPath -PathType Leaf) {
        Move-Item -LiteralPath $taskPath -Destination (Join-Path $sessionRoot 'NeutronWatchdog.task.disabled') -Force
    }

    Write-Host 'Neutron başlangıç bileşenleri çevrimdışı olarak devre dışı bırakıldı.'
    Write-Host "Tam hive yedekleri ve rapor: $sessionRoot"
    Write-Host 'Şimdi bilgisayarı yeniden başlatın. Windows açılırsa yeni Neutron kaldırıcısını çalıştırın.'
}
finally {
    Set-Location $driveRoot
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    if ($softwareLoaded) { Invoke-RegExe -Arguments @('unload', "HKLM\$softwareMountName") }
    if ($systemLoaded) { Invoke-RegExe -Arguments @('unload', "HKLM\$systemMountName") }
}
