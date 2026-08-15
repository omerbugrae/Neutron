'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

function psQuoteSingle(value) {
  return String(value).replace(/'/g, "''");
}

function readResultFile(resultPath) {
  try {
    const content = fs.readFileSync(resultPath, 'utf8').replace(/^\uFEFF/, '');
    const parsed = JSON.parse(content);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  } finally {
    try { fs.unlinkSync(resultPath); } catch { /* best effort */ }
  }
}

function spawnPowerShell(argumentsList) {
  return new Promise((resolve) => {
    const child = spawn('powershell.exe', argumentsList, {
      windowsHide: true,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout = `${stdout}${chunk}`.slice(-20_000); });
    child.stderr.on('data', (chunk) => { stderr = `${stderr}${chunk}`.slice(-20_000); });
    child.once('error', (error) => resolve({ status: null, error, stdout, stderr }));
    child.once('close', (status) => resolve({ status, stdout, stderr }));
  });
}

async function runPowerShell(psCommand, options = {}) {
  const elevated = options.elevated !== false;
  const resultPath = path.join(os.tmpdir(), `neutron-security-${process.pid}-${crypto.randomUUID()}.json`);
  const quotedResultPath = psQuoteSingle(resultPath);
  const wrappedCommand =
    `$ErrorActionPreference = 'Stop'; ` +
    `try { & { ${psCommand} }; ` +
    `@{ ok = $true } | ConvertTo-Json -Compress | Set-Content -LiteralPath '${quotedResultPath}' -Encoding UTF8; exit 0 ` +
    `} catch { ` +
    `@{ ok = $false; message = $_.Exception.Message } | ConvertTo-Json -Compress | ` +
    `Set-Content -LiteralPath '${quotedResultPath}' -Encoding UTF8; exit 1 }`;
  const encoded = Buffer.from(wrappedCommand, 'utf16le').toString('base64');

  let processResult;
  if (elevated) {
    const outerCommand =
      `try { ` +
      `$p = Start-Process -FilePath 'powershell.exe' ` +
      `-ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','${encoded}') ` +
      `-Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode ` +
      `} catch { exit 1223 }`;
    processResult = await spawnPowerShell(['-NoProfile', '-NonInteractive', '-Command', outerCommand]);
  } else {
    processResult = await spawnPowerShell(['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded]);
  }

  const detail = readResultFile(resultPath);
  if (processResult.error) return { ok: false, message: processResult.error.message };
  if (processResult.status === 1223) {
    return { ok: false, code: 'ELEVATION_CANCELLED', message: 'Yönetici izni verilmedi.' };
  }
  if (processResult.status !== 0 || detail?.ok === false) {
    const message = detail?.message || processResult.stderr.trim() || processResult.stdout.trim();
    return {
      ok: false,
      code: 'PRIVILEGED_COMMAND_FAILED',
      exitCode: processResult.status,
      message: message || `Yönetici işlemi başarısız oldu (kod ${processResult.status}).`,
    };
  }
  return { ok: true };
}

function amsiRegistrationCommand(dllPath, unregister = false) {
  const unregisterArgument = unregister ? "'/u'," : '';
  return (
    `$regsvr = Join-Path $env:SystemRoot 'System32\\regsvr32.exe'; ` +
    `$arguments = @('/s',${unregisterArgument} '${psQuoteSingle(dllPath)}'); ` +
    `& $regsvr @arguments; ` +
    `if ($LASTEXITCODE -ne 0) { throw 'AMSI kaydı başarısız oldu (regsvr32 kodu ' + $LASTEXITCODE + ').' }`
  );
}

function watchdogCreateCommand(taskName, executable, args = []) {
  const target = [executable, ...args]
    .map((value) => `"${String(value).replace(/"/g, '\\"')}"`)
    .join(' ');
  return (
    `$schtasks = Join-Path $env:SystemRoot 'System32\\schtasks.exe'; ` +
    `$taskAction = '${psQuoteSingle(target)}'; ` +
    `& $schtasks /create /tn '${psQuoteSingle(taskName)}' /tr $taskAction /sc minute /mo 2 /rl highest /f; ` +
    `if ($LASTEXITCODE -ne 0) { throw 'Watchdog görevi oluşturulamadı (schtasks kodu ' + $LASTEXITCODE + ').' }`
  );
}

function watchdogDeleteCommand(taskName) {
  return (
    `$schtasks = Join-Path $env:SystemRoot 'System32\\schtasks.exe'; ` +
    `& $schtasks /delete /tn '${psQuoteSingle(taskName)}' /f; ` +
    `if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) { ` +
    `throw 'Watchdog görevi kaldırılamadı (schtasks kodu ' + $LASTEXITCODE + ').' }`
  );
}

function windowsSecurityCenterRestoreCommand(instanceGuid) {
  const quotedGuid = psQuoteSingle(instanceGuid);
  return (
    `$service = Get-Service -Name 'wscsvc' -ErrorAction SilentlyContinue; ` +
    `if (-not $service) { throw 'Windows Güvenlik Merkezi hizmeti bulunamadı.' }; ` +
    `$existing = Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct ` +
    `-Filter "instanceGuid='${quotedGuid}'" -ErrorAction SilentlyContinue; ` +
    `if ($existing) { $existing | Remove-CimInstance -ErrorAction Stop }; ` +
    `if ($service.Status -eq 'Stopped' -and $service.StartType -ne 'Disabled') { ` +
    `Start-Service -Name 'wscsvc' -ErrorAction Stop }`
  );
}

// Older experimental builds may have registered a kernel/file-system driver
// even though current Neutron releases ship no .sys/INF/CAT files. A stale
// boot-start filter is capable of producing INACCESSIBLE_BOOT_DEVICE before
// any user-mode Neutron component runs. Discover only driver services whose
// service name, display name or image path contains "Neutron", back up their
// metadata, detach their exact service names from class Upper/LowerFilters,
// force Start/StartOverride to Disabled, and then ask SCM to delete them.
// Other vendors' services and filter entries are never touched.
function legacyDriverCleanupCommand() {
  return [
    `$serviceRoot = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services'`,
    `$legacyDrivers = @()`,
    `Get-ChildItem -LiteralPath $serviceRoot -ErrorAction SilentlyContinue | ForEach-Object { ` +
      `$item = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue; ` +
      `$type = if ($null -ne $item.Type) { [int]$item.Type } else { 0 }; ` +
      `$identity = \"$($_.PSChildName) $($item.DisplayName) $($item.ImagePath)\"; ` +
      `if ((($type -band 1) -ne 0 -or ($type -band 2) -ne 0) -and $identity -match '(?i)neutron') { ` +
        `$legacyDrivers += [pscustomobject]@{ Name = $_.PSChildName; Type = $type; Start = $item.Start; ImagePath = $item.ImagePath; DisplayName = $item.DisplayName } } }`,
    `if ($legacyDrivers.Count -gt 0) { ` +
      `$backupDir = Join-Path $env:ProgramData 'Neutron\\recovery'; ` +
      `New-Item -ItemType Directory -Force -Path $backupDir | Out-Null; ` +
      `$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'; ` +
      `$legacyDrivers | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $backupDir \"legacy-drivers-$stamp.json\") -Encoding UTF8 }`,
    `$legacyNames = @($legacyDrivers | ForEach-Object { $_.Name })`,
    `if ($legacyNames.Count -gt 0) { ` +
      `Get-ChildItem -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class' -ErrorAction SilentlyContinue | ForEach-Object { ` +
        `$classKey = $_.PSPath; ` +
        `foreach ($filterName in @('UpperFilters','LowerFilters')) { ` +
          `$values = @((Get-ItemProperty -LiteralPath $classKey -Name $filterName -ErrorAction SilentlyContinue).$filterName); ` +
          `if ($values.Count -gt 0) { ` +
            `$kept = @($values | Where-Object { $legacyNames -notcontains [string]$_ }); ` +
            `if ($kept.Count -ne $values.Count) { ` +
              `if ($kept.Count -eq 0) { Remove-ItemProperty -LiteralPath $classKey -Name $filterName -ErrorAction Stop } ` +
              `else { Set-ItemProperty -LiteralPath $classKey -Name $filterName -Value ([string[]]$kept) -ErrorAction Stop } } } } } }`,
    `$sc = Join-Path $env:SystemRoot 'System32\\sc.exe'`,
    `foreach ($driver in $legacyDrivers) { ` +
      `$serviceKey = Join-Path $serviceRoot $driver.Name; ` +
      `Set-ItemProperty -LiteralPath $serviceKey -Name Start -Value 4 -ErrorAction Stop; ` +
      `$overrideKey = Join-Path $serviceKey 'StartOverride'; ` +
      `if (Test-Path -LiteralPath $overrideKey) { ` +
        `foreach ($valueName in (Get-Item -LiteralPath $overrideKey).GetValueNames()) { ` +
          `Set-ItemProperty -LiteralPath $overrideKey -Name $valueName -Value 4 -ErrorAction Stop } }; ` +
      `& $sc stop $driver.Name | Out-Null; ` +
      `& $sc delete $driver.Name | Out-Null; ` +
      `if ($LASTEXITCODE -notin @(0,1060,1062,1072)) { throw \"Eski Neutron sürücüsü kaldırılamadı: $($driver.Name) (kod $LASTEXITCODE).\" } }`,
  ].join('; ');
}

function serviceInstallCommand(serviceName, hostPath, oldDataDir) {
  const quotedService = psQuoteSingle(serviceName);
  const quotedHost = psQuoteSingle(hostPath);
  const quotedOldData = psQuoteSingle(oldDataDir);
  return [
    `$dataDir = Join-Path $env:ProgramData 'Neutron\\data'`,
    `if ((Test-Path -LiteralPath '${quotedOldData}') -and -not (Test-Path -LiteralPath $dataDir)) { ` +
      `New-Item -ItemType Directory -Force -Path (Split-Path $dataDir) | Out-Null; ` +
      `Copy-Item -LiteralPath '${quotedOldData}' -Destination $dataDir -Recurse -Force }`,
    `$serviceKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\${quotedService}'`,
    `if (Test-Path -LiteralPath $serviceKey) { ` +
      `$existingType = [int](Get-ItemProperty -LiteralPath $serviceKey -Name Type -ErrorAction Stop).Type; ` +
      `if (($existingType -band 1) -ne 0 -or ($existingType -band 2) -ne 0) { ` +
        `Set-ItemProperty -LiteralPath $serviceKey -Name Start -Value 4 -ErrorAction Stop; ` +
        `throw 'Aynı adlı eski Neutron kernel sürücüsü devre dışı bırakıldı. Güvenli kurulum için bilgisayarı yeniden başlatın.' } }`,
    `$existing = Get-Service -Name '${quotedService}' -ErrorAction SilentlyContinue`,
    `if ($existing) { ` +
      `if ($existing.Status -ne 'Stopped') { Stop-Service -Name '${quotedService}' -Force -ErrorAction Stop }; ` +
      `$sc = Join-Path $env:SystemRoot 'System32\\sc.exe'; & $sc delete '${quotedService}' | Out-Null; ` +
      `if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1060) { throw 'Eski servis kaldırılamadı.' }; ` +
      `for ($i = 0; $i -lt 40 -and (Get-Service -Name '${quotedService}' -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 250 } }`,
    `if (Get-Service -Name '${quotedService}' -ErrorAction SilentlyContinue) { throw 'Eski servis silinmeyi bekliyor. Bilgisayarı yeniden başlatıp tekrar deneyin.' }`,
    `$binaryPath = '${psQuoteSingle(`"${hostPath}"`)}'`,
    `New-Service -Name '${quotedService}' -BinaryPathName $binaryPath -DisplayName 'Neutron Protection Service' -StartupType Automatic | Out-Null`,
    `$sc = Join-Path $env:SystemRoot 'System32\\sc.exe'`,
    `& $sc config '${quotedService}' start= delayed-auto | Out-Null`,
    `if ($LASTEXITCODE -ne 0) { throw 'Gecikmeli servis başlangıcı ayarlanamadı.' }`,
    `Start-Service -Name '${quotedService}' -ErrorAction Stop`,
    `(Get-Service -Name '${quotedService}' -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(15))`,
    `$running = Get-Service -Name '${quotedService}' -ErrorAction Stop`,
    `if ($running.Status -ne 'Running') { throw 'Neutron servisi çalışır duruma geçemedi.' }`,
  ].join('; ');
}

function serviceUninstallCommand(serviceName) {
  const quotedService = psQuoteSingle(serviceName);
  return (
    `$service = Get-Service -Name '${quotedService}' -ErrorAction SilentlyContinue; ` +
    `if ($service -and $service.Status -ne 'Stopped') { ` +
      `Stop-Service -Name '${quotedService}' -Force -ErrorAction Stop; ` +
      `$service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15)) }; ` +
    `if ($service) { ` +
      `$sc = Join-Path $env:SystemRoot 'System32\\sc.exe'; & $sc delete '${quotedService}' | Out-Null; ` +
      `if ($LASTEXITCODE -notin @(0,1060,1072)) { throw 'Neutron servisi kaldırılamadı (kod ' + $LASTEXITCODE + ').' } }`
  );
}

module.exports = {
  amsiRegistrationCommand,
  legacyDriverCleanupCommand,
  psQuoteSingle,
  runPowerShell,
  serviceInstallCommand,
  serviceUninstallCommand,
  watchdogCreateCommand,
  watchdogDeleteCommand,
  windowsSecurityCenterRestoreCommand,
};
