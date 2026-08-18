#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

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

// --- No install-time licence page ------------------------------------------
//
// Licensing moved to a Supabase-backed account system that lives inside the
// app (src/activation.html, src/supabase-client.cjs) and opens on first
// launch, not inside the NSIS wizard. Asking for an NTR1 key, a device code
// or a MachineGuid read during install would be dead UI for a feature the
// app no longer has -- these assertions exist to catch that regressing back
// in, not to describe what the installer should do.
for (const dead of [
  'LicensePageCreate', 'LicensePageLeave', '--activate-license-file',
  'activation.key', 'previous-activation.key', 'HadPreviousLicense',
  'LicenseDeviceHash', 'NTR1-', 'DeleteLicenseData',
]) {
  assert.doesNotMatch(installer, new RegExp(dead.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
    `kurulum sihirbazı artık "${dead}" içermemeli`);
}
for (const dead of ['isActivateLicenseFileMode', 'saveLicense(', 'parseLicense(', 'activeLicensePath']) {
  assert.doesNotMatch(main, new RegExp(dead.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
    `main.cjs artık "${dead}" içermemeli`);
}

// Risk acceptance is the one thing installation still gates on: no key entry
// to check afterwards, so the MUI license/risk page has to stand on its own
// before file extraction starts.
assert.match(installer, /MUI_LICENSEPAGE_CHECKBOX/);
assert.ok(installer.indexOf('MUI_PAGE_LICENSE') < installer.indexOf('MUI_PAGE_INSTFILES'));

assert.match(installer, /NeutronStage/);
assert.match(installer, /robocopy\.exe/);

// Progress feedback during the multi-minute provisioning call comes from the
// status line above the bar, not from the file list: the list pane stays
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
assert.match(installer, /nsExec::ExecToStack.*--provision-security/);
assert.doesNotMatch(installer, /ExecWait|ExecToLog/);
assert.doesNotMatch(installer, /MB_RETRYCANCEL/);
assert.match(installer, /Goto cleanup_fallback/);
assert.match(installer, /remove-stuck-neutron\.ps1/);
assert.match(installer, /provision_failed/);
assert.match(installer, /Eksik kurulum geri alındı/);

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

// --- Kaldırma sihirbazı ----------------------------------------------------
//
// Kaldırıcının veri sayfası, onay sayfasından sonra ve dosyalar silinmeye
// başlamadan önce gelmeli: seçim, geri alınamaz silme işleminden önce
// yapılmış olmalı.
assert.ok(installer.indexOf('UninstPage custom un.OptionsPageCreate') > installer.indexOf('MUI_UNPAGE_CONFIRM'));
assert.ok(installer.indexOf('UninstPage custom un.OptionsPageCreate') < installer.indexOf('MUI_UNPAGE_INSTFILES'));
assert.match(installer, /Function un\.OptionsPageLeave/);

// Sessiz kaldırma (QuietUninstallString, /S) özel sayfaları göstermez. O
// durumda un.onInit varsayılanı geçerli olur ve "silme" olmalı -- otomatik
// bir kaldırma kullanıcı verisini asla sormadan silmemeli.
assert.match(installer, /StrCpy \$DeleteUserData "0"/);
// Karantina kalıcı olarak silineceği için tek bir onay kutusu yeterli değil;
// ayrıca açık bir onay sorulmalı.
assert.match(installer, /MB_YESNO\|MB_ICONEXCLAMATION/);

// Hesap sistemine geçmeden önceki bir sürümden yükseltenlerde
// $ProgramDataDir\Neutron\license bir kalıntı olarak kalabilir; ayrı bir
// soru olmadan, kullanıcı verisiyle birlikte sessizce temizlenmeli.
assert.match(installer, /RMDir \/r "\$ProgramDataDir\\\\Neutron\\\\data"/);
assert.match(installer, /RMDir \/r "\$ProgramDataDir\\\\Neutron\\\\license"/);
assert.doesNotMatch(installer, /RMDir \/r "\$ProgramDataDir\\\\Neutron"\s*$/m);

// Kaldırma yardımcısı kurulumla birlikte gelmeli ve Başlat menüsünden
// erişilebilmeli: ona ihtiyaç duyulan an, tam da Uninstall.exe çalışmadığı
// andır.
assert.match(installer, /File \/oname=remove-neutron-completely\.cmd/);
assert.match(installer, /Neutron Kaldırma Yardımcısı \(yönetici\)\.lnk/);
assert.match(installer, /Neutron'u Kaldır\.lnk/);
// Yükseltmede eski düz kısayol kaldırılmazsa menüde iki Neutron görünür.
assert.match(installer, /Delete "\$SMPROGRAMS\\\\Neutron\.lnk"/);
assert.match(installer, /RMDir "\$SMPROGRAMS\\\\Neutron"/);

// Denetim Masası kaydı: kaldırma yolu, boyut ve iletişim bilgisi.
assert.match(installer, /"UninstallString"/);
assert.match(installer, /"QuietUninstallString"/);
assert.match(installer, /"EstimatedSize"/);
assert.match(installer, /"HelpLink"/);
assert.match(installer, /\$\{GetSize\}/);
assert.match(installer, /!include "FileFunc\.nsh"/);

// Kaldırma yardımcısının kendisi: Neutron'a ait olmayan hiçbir şeyi silmemeli
// ve kurulum yolunu doğrulamadan hiçbir klasörü kaldırmamalı.
const removalHelper = fs.readFileSync(
  path.join(root, 'tools', 'security', 'remove-neutron-completely.cmd'), 'utf8');
assert.match(removalHelper, /goto unsafe_path/);
assert.match(removalHelper, /goto missing_markers/);
assert.match(removalHelper, /sc\.exe delete NeutronService/);
assert.match(removalHelper, /Start Menu\\Programs\\Neutron/);
assert.match(removalHelper, /AppData\\Roaming\\Neutron/);
// Kullanıcı verisi asla sorulmadan silinmemeli.
assert.match(removalHelper, /set \/p "PURGE_DATA=/);

// --- Hesap sistemi (Supabase) ----------------------------------------------
//
// Bu üç dosya kurulum akışının yerini alan asıl doğrulama mekanizması:
// hesap ilk açılışta doğrulanır, tam offline imzalı anahtar yerine.
const activationHtml = fs.readFileSync(path.join(root, 'src', 'activation.html'), 'utf8');
const activationJs = fs.readFileSync(path.join(root, 'src', 'activation.js'), 'utf8');
const supabaseClient = fs.readFileSync(path.join(root, 'src', 'supabase-client.cjs'), 'utf8');

assert.match(activationHtml, /data-form="signin"/);
assert.match(activationHtml, /data-form="signup"/);
assert.doesNotMatch(activationHtml, /NTR1/);
assert.match(supabaseClient, /rpc\/heartbeat/);
assert.doesNotMatch(activationHtml, /Cihaz değişikliği iste/);
assert.doesNotMatch(supabaseClient, /request_device_change/);

console.log('Kurulum ve hesap sistemi öz testi başarılı (sistem değişikliği uygulanmadı).');
