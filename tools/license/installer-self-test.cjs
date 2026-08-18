#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { generateLicense } = require('../../src/license.cjs');

const root = path.resolve(__dirname, '..', '..');
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const installer = fs.readFileSync(path.join(root, 'tools', 'installer', 'neutron.nsi'), 'utf8');
const main = fs.readFileSync(path.join(root, 'src', 'main.cjs'), 'utf8');

// Pinned to the literal '0.31.0' this assertion went stale the moment the
// version moved on, and had to be edited every release to assert nothing
// useful. What actually matters is that the version parses into the four
// numeric parts VIProductVersion requires -- toFileVersion() pads short
// versions, so two and three part versions are both legitimate here.
assert.match(packageJson.version, /^\d+(\.\d+){1,3}$/);
assert.ok(installer.indexOf('Page custom LicensePageCreate LicensePageLeave') < installer.indexOf('MUI_PAGE_INSTFILES'));
assert.ok(installer.indexOf('--activate-license-file') < installer.indexOf('--provision-security'));
assert.match(installer, /NeutronStage/);
assert.match(installer, /robocopy\.exe/);
assert.match(installer, /license_verification_failed/);
assert.match(installer, /previous-activation\.key/);

// Risk acceptance must come before the activation page, and must be gated on
// the checkbox rather than being a page the user can page straight past.
assert.match(installer, /MUI_LICENSEPAGE_CHECKBOX/);
assert.ok(installer.indexOf('MUI_PAGE_LICENSE') < installer.indexOf('Page custom LicensePageCreate'));

// Progress feedback during the three multi-minute external calls comes from
// the status line above the bar, not from the file list: the list pane stays
// hidden, and DetailPrint runs in textonly mode so each message replaces the
// previous one instead of scrolling a wall of paths past the user.
assert.match(installer, /ShowInstDetails nevershow/);
assert.match(installer, /SetDetailsPrint textonly/);
assert.match(installer, /DetailPrint/);
// The File extraction must not print, or it overwrites the status message
// once per extracted file.
assert.ok(installer.indexOf('SetDetailsPrint none') < installer.indexOf('File /r'));

// The AMSI provider DLL is mapped into other processes and cannot be
// overwritten in place; it has to be moved aside before robocopy runs, or
// every upgrade fails with robocopy exit code 9.
assert.ok(installer.indexOf('NeutronAmsiProvider.dll') < installer.indexOf('robocopy.exe'));
assert.match(installer, /regsvr32\.exe" \/s \/u/);
assert.match(installer, /nsExec::ExecToStack.*--activate-license-file/);
assert.match(installer, /nsExec::ExecToStack.*--provision-security/);
assert.doesNotMatch(installer, /ExecWait|ExecToLog/);
assert.doesNotMatch(installer, /MB_RETRYCANCEL/);
assert.match(installer, /Goto cleanup_fallback/);
assert.match(installer, /remove-stuck-neutron\.ps1/);
assert.match(installer, /provision_rollback_done/);
assert.match(installer, /Eksik kurulum geri alındı/);
assert.match(installer, /ReadRegStr \$LicenseDeviceHash HKLM .*MachineGuid/);
assert.doesNotMatch(installer, /license-device\.ps1/);
assert.match(installer, /Program yazarıyla lisans kodu almak için iletişime geçin/);
assert.match(main, /isActivateLicenseFileMode/);
assert.match(main, /saveLicense\(key, \{ machineWide: true \}\)/);
assert.match(main, /ProgramData/);
assert.match(main, /windowsSecurityCenterRestoreCommand/);
assert.match(main, /NEUTRON_INTERNAL_PATHS: internalPaths/);
// Provisioning must treat only AMSI and the service as mandatory, and roll
// back if either fails. The assertion used to pin the exact expression
// `Object.entries(results).filter(...)`, which stopped matching once the
// mandatory set became an explicit list -- pinning the shape of a line rather
// than the behaviour behind it. Match the rollback contract instead.
assert.match(main, /const failedCore = \[/);
assert.match(main, /\['amsi', results\.amsi\]/);
assert.match(main, /\['service', results\.service\]/);
assert.match(main, /if \(failedCore\.length\) \{/);

const signingKeys = crypto.generateKeyPairSync('ed25519');
const longestSupportedKey = generateLicense({
  license_id: 'x'.repeat(80),
  customer_name: 'y'.repeat(100),
  edition: 'z'.repeat(40),
  device_hash: 'a'.repeat(64),
  expires_at: '2099-01-01T00:00:00.000Z',
}, signingKeys.privateKey);
assert.ok(longestSupportedKey.length < 1024, 'NSIS tek satırlık lisans alanı en uzun desteklenen anahtarı taşımalı');

console.log('Kurulum lisans akışı öz testi başarılı (sistem değişikliği uygulanmadı).');
