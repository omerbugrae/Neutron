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

assert.equal(packageJson.version, '0.31.0');
assert.ok(installer.indexOf('Page custom LicensePageCreate LicensePageLeave') < installer.indexOf('MUI_PAGE_INSTFILES'));
assert.ok(installer.indexOf('--activate-license-file') < installer.indexOf('--provision-security'));
assert.match(installer, /NeutronStage/);
assert.match(installer, /robocopy\.exe/);
assert.match(installer, /license_verification_failed/);
assert.match(installer, /previous-activation\.key/);
assert.match(installer, /ShowInstDetails nevershow/);
assert.match(installer, /ShowUninstDetails nevershow/);
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
assert.match(main, /failedCore = Object\.entries\(results\)\.filter\(\(\[, result\]\) => !result\.ok\)/);

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
