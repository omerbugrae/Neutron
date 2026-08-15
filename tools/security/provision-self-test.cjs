#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const {
  amsiRegistrationCommand,
  legacyDriverCleanupCommand,
  runPowerShell,
  serviceInstallCommand,
  serviceUninstallCommand,
  watchdogCreateCommand,
  windowsSecurityCenterRestoreCommand,
} = require('../../src/windows-security.cjs');

const installRoot = String.raw`C:\Program Files\Neutron Test`;
const dll = `${installRoot}\\resources\\runtime\\amsi\\x64\\NeutronAmsiProvider.dll`;
const exe = `${installRoot}\\Neutron.exe`;
const service = `${installRoot}\\resources\\runtime\\service\\x64\\NeutronServiceHost.exe`;

const amsi = amsiRegistrationCommand(dll, false);
assert.match(amsi, /@arguments/);
assert.ok(amsi.includes(dll), 'AMSI DLL path must stay one PowerShell argument');
assert.match(amsi, /LASTEXITCODE/);

const watchdog = watchdogCreateCommand('NeutronWatchdog', exe, ['--hidden']);
assert.ok(watchdog.includes(`"${exe}"`), 'watchdog executable must be quoted');
assert.match(watchdog, /schtasks\.exe/);

const serviceCommand = serviceInstallCommand('NeutronService', service, String.raw`C:\Users\Test User\AppData\Roaming\Neutron\data`);
assert.ok(serviceCommand.includes(`"${service}"`), 'service binary path must be quoted');
assert.match(serviceCommand, /New-Service/);
assert.match(serviceCommand, /Start-Service/);
assert.match(serviceCommand, /Status -ne 'Running'/);
assert.match(serviceCommand, /start= delayed-auto/);
assert.match(serviceCommand, /TimeSpan.*FromSeconds\(15\)/);
assert.doesNotMatch(serviceCommand, /SERVICE_BOOT_START|SERVICE_SYSTEM_START|start=\s*boot|start=\s*system/i);
assert.doesNotMatch(serviceCommand, /actions=\s*restart/i);

const serviceUninstall = serviceUninstallCommand('NeutronService');
assert.match(serviceUninstall, /WaitForStatus\('Stopped'/);
assert.match(serviceUninstall, /LASTEXITCODE/);

const legacyCleanup = legacyDriverCleanupCommand();
assert.match(legacyCleanup, /CurrentControlSet\\Services/);
assert.match(legacyCleanup, /UpperFilters/);
assert.match(legacyCleanup, /LowerFilters/);
assert.match(legacyCleanup, /Start -Value 4/);
assert.match(legacyCleanup, /type -band 1/);
assert.match(legacyCleanup, /type -band 2/);
assert.match(legacyCleanup, /legacy-drivers-/);

const securityCenterRestore = windowsSecurityCenterRestoreCommand('ac0008b0-564a-44f8-8ec7-f2a2d82a8fe8');
assert.match(securityCenterRestore, /Get-Service -Name 'wscsvc'/);
assert.match(securityCenterRestore, /Remove-CimInstance/);
assert.match(securityCenterRestore, /Start-Service -Name 'wscsvc'/);
assert.doesNotMatch(securityCenterRestore, /WinDefend|DisableAntiSpyware|Set-MpPreference/);

function assertPowerShellParses(command) {
  const parser = [
    '$tokens = $null; $errors = $null',
    '[System.Management.Automation.Language.Parser]::ParseInput($env:NEUTRON_TEST_COMMAND, [ref]$tokens, [ref]$errors) | Out-Null',
    'if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }',
  ].join('; ');
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', parser], {
    encoding: 'utf8',
    windowsHide: true,
    env: { ...process.env, NEUTRON_TEST_COMMAND: command },
  });
  assert.equal(result.status, 0, result.stderr || 'PowerShell command failed to parse');
}

assertPowerShellParses(amsi);
assertPowerShellParses(watchdog);
assertPowerShellParses(serviceCommand);
assertPowerShellParses(serviceUninstall);
assertPowerShellParses(legacyCleanup);
assertPowerShellParses(securityCenterRestore);

(async () => {
  const harmless = await runPowerShell("$value = 2 + 2; if ($value -ne 4) { throw 'math' }", { elevated: false });
  assert.equal(harmless.ok, true);
  const expectedFailure = await runPowerShell("throw 'NEUTRON_SELF_TEST_SENTINEL'", { elevated: false });
  assert.equal(expectedFailure.ok, false);
  assert.match(expectedFailure.message, /NEUTRON_SELF_TEST_SENTINEL/);
  console.log('Güvenlik provision komut öz testi başarılı (hiçbir sistem kaydı uygulanmadı).');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
