const { app, BrowserWindow, dialog, ipcMain, Menu, nativeImage, Notification, shell, Tray } = require('electron');
const { spawn, execFileSync } = require('child_process');
const https = require('https');
const net = require('net');
const { existsSync, readFileSync, writeFileSync, mkdirSync } = require('fs');
const path = require('path');
const { ProtonUpdater } = require('./proton-updater.cjs');
const { FeatureUpdater } = require('./feature-updater.cjs');
const {
  decryptStoredLicense, deviceHash, encryptStoredLicense, parseLicense,
} = require('./license.cjs');
const {
  amsiRegistrationCommand,
  psQuoteSingle,
  runPowerShell,
  serviceInstallCommand,
  serviceUninstallCommand,
  watchdogCreateCommand,
  watchdogDeleteCommand,
  windowsSecurityCenterRestoreCommand,
} = require('./windows-security.cjs');

const WINDOWS_APP_USER_MODEL_ID = 'com.neutron.security.Neutron';
const NEUTRON_LOGO_PATH = path.join(__dirname, '..', 'assets', 'neutron-logo.png');
const NEUTRON_ICON_PATH = path.join(__dirname, '..', 'assets', 'neutron.ico');
const isPrepareUninstallMode = process.argv.includes('--prepare-uninstall');
const isProvisionSecurityMode = process.argv.includes('--provision-security');
const isInstallProtonArchiveMode = process.argv.includes('--install-proton-archive');
const isActivateLicenseFileMode = process.argv.includes('--activate-license-file');
const isMaintenanceMode = isPrepareUninstallMode || isProvisionSecurityMode || isInstallProtonArchiveMode || isActivateLicenseFileMode;

// See startEnabledWatchers() for the rationale. Read through a function rather
// than captured once so tools that spawn the app inherit it predictably.
function isDevSafeMode() {
  return process.env.NEUTRON_DEV_SAFE === '1';
}

app.setName('Neutron');
if (process.platform === 'win32') app.setAppUserModelId(WINDOWS_APP_USER_MODEL_ID);

// The NSIS uninstaller launches a short-lived cleanup instance while the normal
// app may still own the single-instance lock. Cleanup never creates a window.
const hasSingleInstanceLock = isMaintenanceMode || app.requestSingleInstanceLock();
if (!hasSingleInstanceLock) {
  app.quit();
} else {
  // The watchdog relaunches Neutron.exe --hidden on a schedule to restart it
  // if it was killed. When it is already running that relaunch loses the lock
  // and exits -- but it still fires this event, so an unconditional
  // showMainWindow() made the window pop open on its own every time the task
  // ran. Only a launch the *user* performed should raise the window.
  app.on('second-instance', (_event, argv) => {
    if (Array.isArray(argv) && argv.includes('--hidden')) return;
    showMainWindow();
  });
}

let activeScan = null;
let protectionWatcher = null;
let behaviorWatcher = null;
let webWatcher = null;
let amsiService = null;
let networkWatcher = null;
let memoryWatcher = null;
let usbWatcher = null;
let ransomwareWatcher = null;
let mainWindow = null;
let tray = null;
let isQuitting = false;
let hasShownTrayHint = false;
let protonUpdatePromise = null;
let featureUpdatePromise = null;
let activeLicense = null;
let appSettings = {
  start_with_windows: false,
  protection_enabled: true,
  behavior_protection_enabled: true,
  web_protection_enabled: true,
  amsi_protection_enabled: false,
  watchdog_protection_enabled: false,
  wsc_registration_enabled: false,
  cloud_lookup_enabled: false,
  malwarebazaar_api_key: '',
  virustotal_api_key: '',
  network_protection_enabled: false,
  service_mode_enabled: false,
  memory_scan_enabled: false,
  usb_protection_enabled: true,
  ransomware_protection_enabled: true,
  notifications_enabled: true,
  watch_paths: [],
  scan_max_files: 1500,
  scheduled_scan_enabled: true,
  scheduled_scan_last_run_at: 0,
  signature_auto_update_enabled: true,
  signature_update_interval_hours: 6,
  signature_update_last_check_at: 0,
  signature_update_last_success_at: 0,
  signature_update_last_error: '',
};

function neutronImage(size) {
  const candidates = process.platform === 'win32'
    ? [NEUTRON_ICON_PATH, NEUTRON_LOGO_PATH]
    : [NEUTRON_LOGO_PATH, NEUTRON_ICON_PATH];
  for (const candidate of candidates) {
    const source = nativeImage.createFromPath(candidate);
    if (!source.isEmpty()) {
      const image = Number.isInteger(size)
        ? source.resize({ width: size, height: size, quality: 'best' })
        : source;
      image.setTemplateImage(false);
      return image;
    }
  }
  return undefined;
}

function sendScanEvent(webContents, payload) {
  if (!webContents.isDestroyed()) {
    webContents.send('scan:event', payload);
  }
}

function sendProtectionEvent(payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('protection:event', payload);
  }
}

function sendProtonUpdateEvent(payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('proton:update-event', payload);
  }
}

function sendFeatureUpdateEvent(payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('feature:update-event', payload);
  }
}

function showMainWindow() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

function userLicensePath() {
  return path.join(app.getPath('userData'), 'license', 'activation.key');
}

function machineLicensePath() {
  return path.join(process.env.ProgramData || 'C:\\ProgramData', 'Neutron', 'license', 'activation.key');
}

function readableLicensePaths() {
  const userPath = userLicensePath();
  const machinePath = machineLicensePath();
  return app.isPackaged && machinePath !== userPath
    ? [machinePath, userPath]
    : [userPath];
}

// The licence is also kept in HKLM, and that is the copy the app trusts first.
//
// The installer activates while elevated and wrote only to
// ProgramData\Neutron\license. Whether the desktop app -- a normal,
// unelevated process, possibly a different account than the one that clicked
// through UAC -- can then read that file depends on directory ACLs, on
// ProgramData resolving the same way in both contexts, and on the folder
// surviving. It did not, and the app asked for a licence that had already
// been entered.
//
// HKLM\SOFTWARE\Neutron has none of those failure modes: the elevated
// installer can always write it, every user can always read it, and the
// uninstaller already deletes the key. reg.exe is used rather than a native
// module so no build dependency is added for four lines of registry access.
const LICENSE_REGISTRY_KEY = 'HKLM\\SOFTWARE\\Neutron';
const LICENSE_REGISTRY_VALUE = 'ActivationKey';

function regExePath() {
  return path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'reg.exe');
}

function readMachineLicenseFromRegistry() {
  if (process.platform !== 'win32') return null;
  try {
    const output = execFileSync(
      regExePath(),
      ['query', LICENSE_REGISTRY_KEY, '/v', LICENSE_REGISTRY_VALUE, '/reg:64'],
      { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] },
    );
    const match = new RegExp(`${LICENSE_REGISTRY_VALUE}\\s+REG_SZ\\s+([^\\r\\n]+)`, 'i').exec(output);
    return match ? match[1].trim() : null;
  } catch {
    // Absent value: reg.exe exits non-zero. Not an error, just no licence.
    return null;
  }
}

function writeMachineLicenseToRegistry(key) {
  if (process.platform !== 'win32') return false;
  // Dev-safe mode never touches HKLM. The file copy still works, so the app
  // remains usable for development without leaving machine-wide state behind.
  if (isDevSafeMode()) return false;
  try {
    execFileSync(
      regExePath(),
      ['add', LICENSE_REGISTRY_KEY, '/v', LICENSE_REGISTRY_VALUE, '/t', 'REG_SZ',
        '/d', String(key).trim(), '/f', '/reg:64'],
      { windowsHide: true, stdio: 'ignore' },
    );
    return true;
  } catch {
    // Writing HKLM needs elevation. In-app activation by a normal user
    // legitimately cannot do this, and falls back to the file copy.
    return false;
  }
}

function removeMachineLicenseFromRegistry() {
  if (process.platform !== 'win32') return;
  try {
    execFileSync(
      regExePath(),
      ['delete', LICENSE_REGISTRY_KEY, '/v', LICENSE_REGISTRY_VALUE, '/f', '/reg:64'],
      { windowsHide: true, stdio: 'ignore' },
    );
  } catch { /* nothing stored, or not elevated */ }
}

let activeLicensePath = null;

// licenseStatus() spawns reg.exe synchronously and reads files. requireLicense()
// calls it on every scan start, every settings write and every watcher start --
// 17 call sites -- so each one blocked the main process, and with it the whole
// UI, for the length of a subprocess spawn. The result only changes when the
// licence is saved or removed, both of which clear this.
const LICENSE_STATUS_CACHE_MS = 5000;
let licenseStatusCache = null;
let licenseStatusCachedAt = 0;

function invalidateLicenseStatusCache() {
  licenseStatusCache = null;
  licenseStatusCachedAt = 0;
}

function licenseStatus() {
  if (licenseStatusCache && Date.now() - licenseStatusCachedAt < LICENSE_STATUS_CACHE_MS) {
    return licenseStatusCache;
  }
  const status = computeLicenseStatus();
  licenseStatusCache = status;
  licenseStatusCachedAt = Date.now();
  return status;
}

function computeLicenseStatus() {
  // Every failure is recorded with the path it came from. The installer
  // activates machine-wide into ProgramData, so when the app then claims to
  // be unlicensed the useful question is always "which file, and why did it
  // not parse" -- a bare "enter a licence" message hides whether the file is
  // missing, unreadable, or bound to a different device hash.
  const failures = [];

  // Once a machine-wide copy has been read and accepted, keep a copy in this
  // user's own profile. The machine-wide copies live in ProgramData and HKLM,
  // both of which the app can only read, never repair; a profile copy is one
  // this account always owns. Best effort -- failing to mirror must never
  // turn a working licence into a blocked app.
  // The mirror is written in the same envelope it was read in, never in the
  // clear: this copy lands in the user's profile, which is the least
  // protected of the three locations.
  const mirrorToUserProfile = (key) => {
    try {
      const target = userLicensePath();
      if (existsSync(target)) return;
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, `${encryptStoredLicense(key)}\n`, { encoding: 'utf8', mode: 0o600 });
    } catch { /* the machine-wide copy still works */ }
  };

  const registryKey = readMachineLicenseFromRegistry();
  if (registryKey) {
    try {
      const key = decryptStoredLicense(registryKey);
      activeLicense = parseLicense(key);
      activeLicensePath = LICENSE_REGISTRY_KEY;
      mirrorToUserProfile(key);
      return { ok: true, active: true, license: activeLicense };
    } catch (error) {
      failures.push({ path: LICENSE_REGISTRY_KEY, reason: error.message });
    }
  } else {
    failures.push({ path: LICENSE_REGISTRY_KEY, reason: 'Kayıt bulunamadı.' });
  }

  for (const candidate of readableLicensePaths()) {
    if (!existsSync(candidate)) {
      failures.push({ path: candidate, reason: 'Dosya yok.' });
      continue;
    }
    try {
      const stored = decryptStoredLicense(readFileSync(candidate, 'utf8').trim());
      activeLicense = parseLicense(stored);
      activeLicensePath = candidate;
      mirrorToUserProfile(stored);
      return { ok: true, active: true, license: activeLicense };
    } catch (error) {
      const reason = error?.code === 'EACCES' || error?.code === 'EPERM'
        ? `Dosya okunamadı (erişim reddedildi): ${error.message}`
        : error.message;
      failures.push({ path: candidate, reason });
    }
  }
  activeLicense = null;
  activeLicensePath = null;

  let currentDeviceHash = null;
  let deviceHashError = null;
  try {
    currentDeviceHash = deviceHash();
  } catch (error) {
    deviceHashError = error.message;
  }

  // A licence file that exists but did not parse is a different situation
  // from no licence at all, and the user needs to be told which one it is.
  const presentButRejected = failures.find((failure) => failure.reason !== 'Dosya yok.');
  // Expiry is singled out because it is the only failure the user can fix by
  // renewing rather than by re-entering something. parseLicense reports it as
  // a message, so it is matched here rather than being re-derived -- there is
  // exactly one place that decides a licence has expired (license.cjs) and it
  // should stay that way.
  const expired = failures.some((failure) => /suresi dolmus/i.test(failure.reason || ''));
  return {
    ok: true,
    active: false,
    expired,
    deviceHash: currentDeviceHash,
    failures,
    message: deviceHashError
      || (expired
        ? 'Neutron lisansınızın süresi doldu. Korumaların yeniden başlaması için lisansı yenileyin.'
        : presentButRejected
          ? `Lisans dosyası bulundu ama kabul edilmedi (${presentButRejected.path}): ${presentButRejected.reason}`
          : 'Kurulum sırasında geçerli bir lisans girilmesi gerekiyor.'),
  };
}

function requireLicense() {
  const status = licenseStatus();
  return status.active ? null : { ok: false, code: 'LICENSE_REQUIRED', message: 'Neutron etkinleştirilmedi.' };
}

// deviceHash() now throws on Windows rather than silently substituting a
// per-user identity (see license.cjs). Callers that only want it for display
// must not turn that into an unhandled failure of their own operation.
function safeDeviceHash() {
  try {
    return deviceHash();
  } catch {
    return null;
  }
}

function saveLicense(key, options = {}) {
  try {
    const license = parseLicense(String(key || ''));
    const target = options.machineWide ? machineLicensePath() : userLicensePath();
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    // Both copies go down in the same envelope. The registry one especially:
    // HKLM\Software\Neutron is world-readable by design (every account has to
    // be able to see the activation), so a plaintext key there was readable by
    // any process on the machine.
    const stored = encryptStoredLicense(key);
    writeFileSync(target, `${stored}\n`, { encoding: 'utf8', mode: 0o600 });
    // Machine-wide activation is the installer's path, and it runs elevated,
    // so this is where the registry copy every account can read gets written.
    // The file above stays as the fallback and for unelevated in-app activation.
    if (options.machineWide) writeMachineLicenseToRegistry(stored);
    activeLicense = license;
    activeLicensePath = target;
    invalidateLicenseStatusCache();
    return { ok: true, active: true, license };
  } catch (error) {
    invalidateLicenseStatusCache();
    return { ok: false, active: false, deviceHash: safeDeviceHash(), message: error.message };
  }
}

function removeStoredLicense() {
  // Each copy is removed independently. Chained in one try block, an
  // unelevated user hitting EPERM on the ProgramData copy aborted the rest:
  // the registry entry survived, in-memory state was never cleared, and the
  // app stayed licensed while reporting failure.
  const failed = [];
  for (const target of readableLicensePaths()) {
    try {
      if (existsSync(target)) require('fs').rmSync(target, { force: true });
    } catch (error) {
      failed.push(`${target}: ${error.message}`);
    }
  }
  try {
    removeMachineLicenseFromRegistry();
  } catch (error) {
    failed.push(`${LICENSE_REGISTRY_KEY}: ${error.message}`);
  }
  activeLicense = null;
  activeLicensePath = null;
  invalidateLicenseStatusCache();
  if (failed.length) {
    return {
      ok: false,
      active: licenseStatus().active,
      deviceHash: safeDeviceHash(),
      message: `Bazı lisans kopyaları kaldırılamadı (yönetici izni gerekebilir): ${failed.join(' | ')}`,
    };
  }
  return { ok: true, active: false, deviceHash: safeDeviceHash() };
}

function revealStoredLicense() {
  const status = licenseStatus();
  if (!status.active) return { ok: false, message: 'Gösterilecek etkin lisans yok.' };
  // activeLicensePath is a registry key, not a file path, when the licence
  // came from HKLM -- reading it as a file would throw.
  if (activeLicensePath === LICENSE_REGISTRY_KEY) {
    const stored = readMachineLicenseFromRegistry();
    if (!stored) return { ok: false, message: 'Kayıtlı lisans okunamadı.' };
    try {
      return { ok: true, key: decryptStoredLicense(stored) };
    } catch (error) {
      return { ok: false, message: `Kayıtlı lisans okunamadı: ${error.message}` };
    }
  }
  // The file was readable when licenseStatus() ran, but that may have been up
  // to the cache lifetime ago; an unguarded read here throws through the IPC
  // handler instead of returning a result the renderer can display.
  try {
    return { ok: true, key: decryptStoredLicense(readFileSync(activeLicensePath, 'utf8').trim()) };
  } catch (error) {
    return { ok: false, message: `Lisans dosyası okunamadı: ${error.message}` };
  }
}

function openProtectionEvent(eventId) {
  showMainWindow();
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const sendTarget = () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('protection:open-event', { eventId: eventId || null });
    }
  };
  if (mainWindow.webContents.isLoadingMainFrame()) {
    mainWindow.webContents.once('did-finish-load', sendTarget);
  } else {
    sendTarget();
  }
}

function showFindingNotification(event, title) {
  if (!appSettings.notifications_enabled || !Notification.isSupported()) return;
  const finding = event.finding || {};
  const quarantined = event.action === 'quarantined';
  const notificationTitle = title || (quarantined ? 'Neutron tehdidi engelledi' : 'Neutron tehdit buldu');
  const actionDetail = quarantined
    ? 'Dosya güvenli karantinaya alındı.'
    : 'İnceleme ve işlem gerekiyor.';
  const notification = new Notification({
    title: notificationTitle,
    body: `${event.file_name || 'Öğe'}: ${finding.reason || 'Şüpheli öğe bulundu'} ${actionDetail}`,
    icon: neutronImage(64),
    silent: false,
  });
  notification.on('click', () => openProtectionEvent(event.event_id));
  notification.show();
}

// The burst brake is the one event the user must not miss: protection has
// partially stood itself down, and until they look at Quarantine they have no
// way of knowing. It ignores the notification preference for that reason --
// this is a state change in the product, not a detection.
function showAutoQuarantineBrakeNotification(event) {
  if (!Notification.isSupported()) return;
  const notification = new Notification({
    title: 'Neutron otomatik karantinayı durdurdu',
    body: event.message || 'Anormal sayıda otomatik karantina algılandı.',
    icon: neutronImage(64),
    silent: false,
  });
  notification.on('click', () => showMainWindow());
  notification.show();
}

function shouldNotifyWatchFinding(event) {
  const finding = event?.finding || {};
  if (event?.action === 'quarantined') return true;
  if (['test-signature', 'signature', 'cloud-reputation'].includes(finding.kind)) return true;
  return Number(finding.risk_score) >= 60;
}

function updateTrayMenu() {
  if (!tray) return;
  const protectionActive = Boolean(protectionWatcher);
  const behaviorActive = Boolean(behaviorWatcher);
  const tooltip = protectionActive && behaviorActive
    ? 'Neutron — Dosya ve davranış koruması etkin'
    : protectionActive
      ? 'Neutron — Dosya koruması etkin'
      : behaviorActive
        ? 'Neutron — Davranış izleme etkin'
        : 'Neutron — Koruma kapalı';
  tray.setToolTip(tooltip);
  tray.setContextMenu(Menu.buildFromTemplate([
    {
      label: 'Neutron’u aç',
      click: showMainWindow,
    },
    { type: 'separator' },
    {
      label: protectionActive ? 'Gerçek zamanlı korumayı kapat' : 'Gerçek zamanlı korumayı aç',
      click: async () => {
        if (protectionActive) {
          if (!confirmProtectionOff()) return;
          await updateApplicationSetting('protection_enabled', false);
        } else {
          await updateApplicationSetting('protection_enabled', true);
        }
        updateTrayMenu();
      },
    },
    {
      label: behaviorActive ? 'Davranış izlemeyi kapat' : 'Davranış izlemeyi aç',
      click: async () => {
        await updateApplicationSetting('behavior_protection_enabled', !behaviorActive);
        updateTrayMenu();
      },
    },
    { type: 'separator' },
    {
      label: 'Neutron’dan çık',
      click: () => {
        if (!confirmQuit()) return;
        isQuitting = true;
        app.quit();
      },
    },
  ]));
}

// Neither dialog is a hard security boundary -- same-user malware calling
// our IPC handlers directly would bypass it entirely -- but it stops
// casual/social-engineered disabling and naive UI-automation scripts that
// don't also dismiss a confirmation dialog.
function confirmProtectionOff() {
  const choice = dialog.showMessageBoxSync({
    type: 'warning',
    buttons: ['Vazgeç', 'Korumayı kapat'],
    defaultId: 0,
    cancelId: 0,
    title: 'Gerçek zamanlı korumayı kapat',
    message: 'Gerçek zamanlı korumayı kapatmak istediğinizden emin misiniz?',
    detail: 'Kapatılırsa yeni ve değişen dosyalar denetlenmeyecek.',
  });
  return choice === 1;
}

function confirmQuit() {
  const choice = dialog.showMessageBoxSync({
    type: 'warning',
    buttons: ['Vazgeç', 'Çıkış yap'],
    defaultId: 0,
    cancelId: 0,
    title: 'Neutron’dan çık',
    message: 'Neutron’dan çıkmak istediğinizden emin misiniz?',
    detail: 'Uygulama tamamen kapanacak ve gerçek zamanlı koruma durdurulacak.',
  });
  return choice === 1;
}

function createTray() {
  if (tray) return tray;
  const trayImage = neutronImage(32);
  if (!trayImage) {
    console.error(`Neutron tray icon could not be loaded: ${NEUTRON_ICON_PATH}`);
    return null;
  }
  tray = new Tray(trayImage);
  tray.on('click', showMainWindow);
  tray.on('double-click', showMainWindow);
  updateTrayMenu();
  return tray;
}

function resolvePython() {
  const virtualEnvironmentPython = path.join(
    __dirname,
    '..',
    'venv',
    'Scripts',
    'python.exe'
  );

  return existsSync(virtualEnvironmentPython)
    ? virtualEnvironmentPython
    : process.platform === 'win32'
      ? 'python'
      : 'python3';
}

function bundledEnginePath() {
  const architecture = process.arch === 'ia32' ? 'x86' : 'x64';
  const runtimeRoot = app.isPackaged
    ? path.join(process.resourcesPath, 'runtime', 'engine')
    : path.join(__dirname, '..', 'runtime', 'engine');
  return path.join(runtimeRoot, architecture, 'neutron-engine', 'neutron-engine.exe');
}

function amsiDllPath() {
  const architecture = process.arch === 'ia32' ? 'x86' : 'x64';
  const runtimeRoot = app.isPackaged
    ? path.join(process.resourcesPath, 'runtime', 'amsi')
    : path.join(__dirname, '..', 'runtime', 'amsi');
  return path.join(runtimeRoot, architecture, 'NeutronAmsiProvider.dll');
}

// AMSI registration must keep the Program Files DLL path as one argument.
// The old Start-Process ArgumentList construction split paths containing
// spaces and regsvr32 returned code 3. The shared command builder quotes the
// path and the asynchronous runner keeps Electron's main thread responsive.
//
// When we are already elevated (the installer case) regsvr32 is spawned
// directly instead of through PowerShell. Registering an AMSI provider from
// inside a PowerShell process is a trap: PowerShell is itself an AMSI host
// and scans every statement, so the statement *after* regsvr32 loads the
// brand-new provider in-process. A faulty provider then takes the host down
// (0xC0000374) before it can report anything, and the failure looks like
// "registration failed" when registration in fact succeeded.
function runRegsvr32Directly(dllPath, unregister) {
  const regsvr32 = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'regsvr32.exe');
  const args = unregister ? ['/s', '/u', dllPath] : ['/s', dllPath];
  return new Promise((resolve) => {
    const child = spawn(regsvr32, args, { windowsHide: true, shell: false, stdio: 'ignore' });
    child.once('error', (error) => resolve({ ok: false, message: error.message }));
    child.once('close', (code) => {
      if (code === 0) return resolve({ ok: true });
      resolve({
        ok: false,
        code: 'PRIVILEGED_COMMAND_FAILED',
        exitCode: code,
        message: `AMSI kaydı başarısız oldu (regsvr32 kodu ${code}).`,
      });
    });
  });
}

function runElevatedRegsvr32(dllPath, unregister, options = {}) {
  // The other privileged choke point: registering the AMSI provider COM
  // object machine-wide. See runElevatedPowerShell for the same reasoning.
  if (isDevSafeMode()) {
    return Promise.resolve({
      ok: false,
      code: 'DEV_SAFE_MODE',
      message: 'NEUTRON_DEV_SAFE=1: AMSI kaydı yapılmadı (geliştirme modu).',
    });
  }
  if (!existsSync(dllPath)) {
    return Promise.resolve({
      ok: false,
      message: 'AMSI sağlayıcı DLL bulunamadı. Önce "npm run amsi:build" ile derlenmeli.',
    });
  }
  if (options.elevated === false) return runRegsvr32Directly(dllPath, unregister);
  return runPowerShell(amsiRegistrationCommand(dllPath, unregister), options);
}

// Every AMSI host in the system -- PowerShell, wscript, Office -- loads this
// DLL in-process from now on, so a provider that faults takes those hosts
// with it. Before leaving a fresh registration in place, spend one throwaway
// PowerShell process proving that an AMSI-scanned statement still survives.
// If it does not, the registration is rolled back immediately: a machine
// whose PowerShell has been made unusable is a far worse outcome than an
// installation without AMSI protection.
// The probe runs during installation, immediately after ~500 MB has been
// written to Program Files -- so the disk is busy, Defender is scanning the
// freshly written tree, and a PowerShell cold start is far slower than it
// would ever be on an idle machine. 30 s was not enough, and the failure was
// then reported as a provider crash.
//
// That misreport mattered: Node gives close() a null code when the child was
// killed by a signal, which is exactly what our own timeout does. So "kod
// null" meant "we killed it", not "it died" -- and a healthy registration was
// rolled back on the strength of it. A timeout and a heap corruption are now
// distinguished, because they call for opposite conclusions.
// Ceiling for the baseline measurement, and the floor for the verification
// budget derived from it. A machine that cannot start PowerShell at all
// inside two minutes has a problem this code cannot diagnose.
const AMSI_PROBE_CEILING_MS = 120_000;
const AMSI_PROBE_FLOOR_MS = 45_000;
// How much slower than the unmodified baseline the provider is allowed to
// make a PowerShell start before we call it hung rather than slow.
const AMSI_PROBE_SLACK_FACTOR = 4;

function runAmsiProbeOnce(timeoutMs) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    let timedOut = false;
    const child = spawn(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', "& { Write-Output 'neutron-amsi-probe' }"],
      { windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    let stdout = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout = `${stdout}${chunk}`.slice(-4_000); });
    child.stderr.resume();
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill(); } catch { /* best effort */ }
    }, timeoutMs);
    child.once('error', (error) => {
      clearTimeout(timer);
      resolve({ ok: false, timedOut: false, message: error.message });
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      const elapsedMs = Date.now() - startedAt;
      const elapsedSeconds = Math.round(elapsedMs / 1000);
      if (code === 0 && stdout.includes('neutron-amsi-probe')) {
        return resolve({ ok: true, elapsedMs, elapsedSeconds });
      }
      if (timedOut) {
        return resolve({
          ok: false,
          timedOut: true,
          elapsedSeconds,
          message: `Windows PowerShell ${elapsedSeconds} saniye içinde yanıt vermedi.`,
        });
      }
      const status = Number(code) >>> 0;
      resolve({
        ok: false,
        timedOut: false,
        exitCode: code,
        message: status === 0xC0000374
          ? 'Windows PowerShell işlemi çöktü (STATUS_HEAP_CORRUPTION / 0xC0000374).'
          : `Windows PowerShell beklenmedik biçimde sonlandı (kod ${code}).`,
      });
    });
  });
}

// Every AMSI host in the system -- PowerShell, wscript, Office -- loads this
// DLL in-process from now on, so a provider that faults takes those hosts
// with it. Before leaving a fresh registration in place, spend one throwaway
// PowerShell process proving that an AMSI-scanned statement still survives.
// If it does not, the registration is rolled back immediately: a machine
// whose PowerShell has been made unusable is a far worse outcome than an
// installation without AMSI protection.
async function probeAmsiHostSurvivesScan(baseline) {
  // Any fixed timeout is a guess about hardware we have never seen. The
  // baseline measured before registration says how long a PowerShell cold
  // start costs on *this* machine with *this* disk under *these* conditions,
  // so the budget is derived from it instead: the question worth asking is
  // "did the provider make this dramatically slower", not "did it beat a
  // number someone picked on a fast laptop".
  const budget = baseline?.ok
    ? Math.min(AMSI_PROBE_CEILING_MS, Math.max(AMSI_PROBE_FLOOR_MS, baseline.elapsedMs * AMSI_PROBE_SLACK_FACTOR))
    : AMSI_PROBE_CEILING_MS;

  let attempt = await runAmsiProbeOnce(budget);
  // A timeout is retried once; a crash is not. A provider that corrupts the
  // host heap does so immediately and deterministically, so retrying tells us
  // nothing and only doubles the damage. A timeout is the opposite: the most
  // likely cause is transient disk contention from the install that just
  // finished, and by the retry the relevant pages are usually cached.
  if (!attempt.ok && attempt.timedOut) attempt = await runAmsiProbeOnce(budget);
  if (attempt.ok) return { ok: true };

  const baselineNote = baseline?.ok
    ? ` Sağlayıcı kaydedilmeden önce aynı ölçüm ${baseline.elapsedSeconds} saniye sürmüştü.`
    : '';
  return {
    ok: false,
    code: attempt.timedOut ? 'AMSI_PROBE_TIMEOUT' : 'AMSI_PROVIDER_UNSAFE',
    exitCode: attempt.exitCode ?? null,
    budgetSeconds: Math.round(budget / 1000),
    baselineSeconds: baseline?.ok ? baseline.elapsedSeconds : null,
    message: attempt.timedOut
      ? `AMSI sağlayıcısı doğrulanamadı, kayıt geri alındı: ${attempt.message}${baselineNote} `
        + 'Bu bir çökme değil, yanıt gecikmesidir.'
      : `AMSI sağlayıcısı yüklendikten sonra Windows PowerShell çalışamadı, kayıt geri alındı. ${attempt.message}`,
  };
}

// Registers the provider and keeps it only if the probe above passes.
async function registerAmsiProviderVerified(options = {}) {
  const dllPath = amsiDllPath();
  // Measured before the provider is registered, so it reflects the machine
  // and not the thing under test. Also pays the PowerShell cold-start cost
  // once up front, which is the single largest term on a slow disk -- the
  // verification run afterwards then starts from a warm cache, exactly as the
  // comparison assumes.
  const baseline = await runAmsiProbeOnce(AMSI_PROBE_CEILING_MS);
  const registration = await runElevatedRegsvr32(dllPath, false, options);
  if (!registration.ok) return registration;
  const probe = await probeAmsiHostSurvivesScan(baseline);
  if (probe.ok) return registration;
  await runElevatedRegsvr32(dllPath, true, options);
  return probe;
}

const WATCHDOG_TASK_NAME = 'NeutronWatchdog';

// A Windows Scheduled Task, not a kernel driver: it periodically relaunches
// Neutron.exe. app.requestSingleInstanceLock() (see top of file) already
// makes that a no-op if Neutron is alive, so this alone gives "restart if
// killed" behaviour for free. The task definition is created from an
// elevated process so it lives under %SystemRoot%\System32\Tasks with an
// admin-only-modify ACL -- ordinary same-user malware can't just
// `schtasks /delete` it. This is deliberately not a defense against an
// admin-level attacker, who can always self-elevate and remove it.
function watchdogExecPath() {
  return { exe: process.execPath, args: app.isPackaged ? ['--hidden'] : [app.getAppPath(), '--hidden'] };
}

// Single choke point for every privileged system change Neutron makes:
// watchdog scheduled task, Windows service install/uninstall, firewall rules,
// system-audit fixes. Guarding it here covers all of them at once, instead of
// relying on remembering to guard each IPC handler that leads to one.
function runElevatedPowerShell(psCommand, options = {}) {
  if (isDevSafeMode()) {
    return Promise.resolve({
      ok: false,
      code: 'DEV_SAFE_MODE',
      message: 'NEUTRON_DEV_SAFE=1: sistem değişikliği yapılmadı (geliştirme modu).',
    });
  }
  return runPowerShell(psCommand, options);
}

function registerWatchdogTask(options = {}) {
  const { exe, args } = watchdogExecPath();
  return runElevatedPowerShell(watchdogCreateCommand(WATCHDOG_TASK_NAME, exe, args), options);
}

function unregisterWatchdogTask(options = {}) {
  return runElevatedPowerShell(watchdogDeleteCommand(WATCHDOG_TASK_NAME), options);
}

// Uygulama bazlı güvenlik duvarı: Neutron paket filtreleme yapmaz, Windows'un
// kendi WFP tabanlı güvenlik duvarını (zaten uygulama bazlı kural desteği
// var) PowerShell'in NetSecurity modülü üzerinden yönetir. engine.py sadece
// bookkeeping tablosunu tutar (admin gerektirmez) -- gerçek kural
// ekleme/kaldırma/aç-kapa burada, runElevatedPowerShell() ile (watchdog
// task'la aynı UAC deseni) yapılır. Kural adı (ruleName) engine.py'nin
// firewall_rule_name() ile ürettiği deterministik isimle birebir eşleşir.
function firewallAddCommand(ruleName, programPath, action, direction) {
  const psDirection = direction === 'in' ? 'Inbound' : 'Outbound';
  const psAction = action === 'allow' ? 'Allow' : 'Block';
  return (
    `try { Get-NetFirewallRule -Name '${psQuoteSingle(ruleName)}' -ErrorAction Stop | Remove-NetFirewallRule } catch {}; ` +
    `New-NetFirewallRule -Name '${psQuoteSingle(ruleName)}' -DisplayName '${psQuoteSingle(ruleName)}' ` +
    `-Direction ${psDirection} -Action ${psAction} -Program '${psQuoteSingle(programPath)}' -Profile Any -Enabled True`
  );
}

function firewallRemoveCommand(ruleName) {
  return `Remove-NetFirewallRule -Name '${psQuoteSingle(ruleName)}'`;
}

function firewallSetEnabledCommand(ruleName, enabled) {
  return `Set-NetFirewallRule -Name '${psQuoteSingle(ruleName)}' -Enabled ${enabled ? 'True' : 'False'}`;
}

// System audit one-click fixes. The engine only ever reads the registry;
// every state change lives here, behind a fixed table. The id arriving over
// IPC selects a table entry -- it is never interpolated into the command --
// so a renderer bug cannot turn this into arbitrary elevated execution.
//
// `restart` marks fixes Windows only honours after a reboot, so the UI can
// say so instead of leaving the user staring at an unchanged audit result.
const AUDIT_FIXES = {
  defender_policy: {
    label: 'Defender ilkesini kaldır',
    confirm: 'Defender\'ı tamamen kapatan grup ilkesi kaldırılsın mı?',
    command:
      "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' " +
      "-Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue",
  },
  defender_realtime: {
    label: 'Gerçek zamanlı korumayı aç',
    confirm: 'Microsoft Defender gerçek zamanlı koruması açılsın mı?',
    command: 'Set-MpPreference -DisableRealtimeMonitoring $false',
  },
  firewall_enable: {
    label: 'Güvenlik duvarını aç',
    confirm: 'Kapalı olan güvenlik duvarı profilleri açılsın mı?',
    command: 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True',
  },
  uac_enable_lua: {
    label: 'UAC\'yi aç',
    confirm: 'Kullanıcı Hesabı Denetimi açılsın mı? Değişiklik yeniden başlatmadan sonra etkin olur.',
    restart: true,
    command:
      "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' " +
      "-Name 'EnableLUA' -Value 1 -Type DWord",
  },
  uac_consent: {
    label: 'Yönetici onayını iste',
    confirm: 'Yönetici yükseltmelerinde onay istemi geri getirilsin mi?',
    command:
      "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' " +
      "-Name 'ConsentPromptBehaviorAdmin' -Value 5 -Type DWord",
  },
  uac_secure_desktop: {
    label: 'Güvenli masaüstünü aç',
    confirm: 'UAC istemi güvenli masaüstünde gösterilsin mi?',
    command:
      "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' " +
      "-Name 'PromptOnSecureDesktop' -Value 1 -Type DWord",
  },
  autologon_disable: {
    label: 'Otomatik oturum açmayı kapat',
    confirm:
      'Otomatik oturum açma kapatılsın ve kayıt defterinde duran düz metin parola silinsin mi? '
      + 'Bilgisayar açılışında yeniden parola sorulacak.',
    command:
      "$winlogon = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'; " +
      "Set-ItemProperty -Path $winlogon -Name 'AutoAdminLogon' -Value '0' -Type String; " +
      "Remove-ItemProperty -Path $winlogon -Name 'DefaultPassword' -ErrorAction SilentlyContinue",
  },
  lsa_runasppl: {
    label: 'LSA korumasını aç',
    confirm: 'lsass.exe korumalı süreç olarak çalıştırılsın mı? Değişiklik yeniden başlatmadan sonra etkin olur.',
    restart: true,
    command:
      "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' " +
      "-Name 'RunAsPPL' -Value 1 -Type DWord",
  },
  smb1_disable: {
    label: 'SMBv1\'i kapat',
    confirm: 'SMBv1 sunucu ve istemcisi kapatılsın mı? Değişiklik yeniden başlatmadan sonra tamamlanır.',
    restart: true,
    command:
      "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' " +
      "-Name 'SMB1' -Value 0 -Type DWord; " +
      "try { Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart -ErrorAction Stop | Out-Null } catch {}",
  },
  rdp_nla: {
    label: 'NLA\'yı zorunlu kıl',
    confirm: 'Uzak Masaüstü için Ağ Düzeyinde Kimlik Doğrulama zorunlu kılınsın mı?',
    command:
      "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' " +
      "-Name 'UserAuthentication' -Value 1 -Type DWord",
  },
  rdp_disable: {
    label: 'Uzak Masaüstü\'nü kapat',
    confirm: 'Uzak Masaüstü kapatılsın mı? Bu makineye uzaktan bağlanıyorsan bağlantın kesilir.',
    command:
      "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' " +
      "-Name 'fDenyTSConnections' -Value 1 -Type DWord",
  },
  windows_update_enable: {
    label: 'Otomatik güncellemeyi aç',
    confirm: 'Otomatik güncellemeyi kapatan ilke kaldırılsın mı?',
    command:
      "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' " +
      "-Name 'NoAutoUpdate' -ErrorAction SilentlyContinue",
  },
  autorun_disable: {
    label: 'AutoRun\'ı kapat',
    confirm: 'Tüm sürücü türleri için AutoRun kapatılsın mı?',
    command:
      "$key = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; " +
      "if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }; " +
      "Set-ItemProperty -Path $key -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord",
  },
  // HKCU, so this one needs no elevation at all -- prompting for admin on a
  // per-user Explorer preference would be asking for more rights than the
  // change requires.
  file_extensions_show: {
    label: 'Uzantıları göster',
    confirm: 'Bilinen dosya uzantıları Gezgin\'de gösterilsin mi?',
    elevated: false,
    note: 'Ayar yazıldı. Dosya Gezgini yeniden başlatıldığında (veya bir sonraki oturum açılışında) görünür olacak.',
    command:
      "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' " +
      "-Name 'HideFileExt' -Value 0 -Type DWord",
  },
};

function applyAuditFix(fixId) {
  if (!Object.prototype.hasOwnProperty.call(AUDIT_FIXES, fixId)) {
    return Promise.resolve({ ok: false, message: 'Bilinmeyen düzeltme.' });
  }
  const fix = AUDIT_FIXES[fixId];
  if (process.platform !== 'win32') {
    return Promise.resolve({ ok: false, message: 'Bu düzeltme yalnızca Windows üzerinde çalışır.' });
  }
  return runPowerShell(fix.command, { elevated: fix.elevated !== false });
}

// Startup manager: only HKLM registry values and the all-users Startup
// folder reach these (HKCU + per-user Startup folder are handled directly,
// non-elevated, inside engine.py's startup_disable_entry/startup_restore_entry).
function startupRegistryPath(hive, keyPath) {
  return `${hive === 'HKLM' ? 'HKLM' : 'HKCU'}:\\${keyPath}`;
}

function startupRegistryDeleteCommand(hive, keyPath, valueName) {
  return `Remove-ItemProperty -Path '${psQuoteSingle(startupRegistryPath(hive, keyPath))}' -Name '${psQuoteSingle(valueName)}' -ErrorAction Stop`;
}

function startupRegistrySetCommand(hive, keyPath, valueName, value) {
  return `Set-ItemProperty -Path '${psQuoteSingle(startupRegistryPath(hive, keyPath))}' -Name '${psQuoteSingle(valueName)}' -Value '${psQuoteSingle(value)}' -Type String -ErrorAction Stop`;
}

function startupMoveCommand(sourcePath, destinationPath) {
  return `Move-Item -LiteralPath '${psQuoteSingle(sourcePath)}' -Destination '${psQuoteSingle(destinationPath)}' -Force -ErrorAction Stop`;
}

// Fixed GUID identifying Neutron's Windows Security Center product entry.
const WSC_INSTANCE_GUID = 'ac0008b0-564a-44f8-8ec7-f2a2d82a8fe8';

// EXPERIMENTAL, not verified against a live Windows Security Center yet
// (see plan notes): registers Neutron as an AntiVirusProduct in the
// root\SecurityCenter2 WMI namespace, the mechanism third-party AVs use so
// Windows Defender steps back to a passive/monitoring role instead of
// running redundantly alongside. Two open unknowns this can't resolve from
// code alone: (1) full effect is documented as tied to Microsoft Virus
// Initiative membership + a signed build, neither of which Neutron has;
// (2) `productState` (397568 / 0x061010, "enabled, up to date") is a
// value reverse-engineered by the community, not something Microsoft
// documents -- cross-check it against Defender's own registered value
// once this can be tested live. Harmless either way: worst case Neutron
// just shows up as a listed product without Defender actually going
// passive.
function wscQuote(value) {
  return String(value).replace(/'/g, "''");
}

function registerWscProvider() {
  return Promise.resolve({
    ok: false,
    code: 'WSC_REGISTRATION_UNSUPPORTED',
    message: 'Windows Güvenlik Merkezi, imzasız ve Microsoft MVI kaydı olmayan bir antivirüsün destekli biçimde kaydedilmesine izin vermiyor. Diğer korumalar bundan etkilenmez.',
  });
}

function unregisterWscProvider(options = {}) {
  return runElevatedPowerShell(windowsSecurityCenterRestoreCommand(WSC_INSTANCE_GUID), options);
}

// --- Windows Service architecture (opt-in, additive) ---------------------
// Added alongside the original per-subprocess model rather than replacing
// it in one pass: this session's main.cjs had already grown a lot (AMSI,
// watchdog, WSC, cloud lookup, network watcher) and a full rip-out-the-
// spawners rewrite couldn't be safely verified without re-reading the
// whole file fresh. So: when `service_mode_enabled` is off (default),
// nothing here is used and the app behaves exactly as before. When on,
// createWindow() connects to the service pipe instead of spawning the
// watch* subprocesses directly -- see connectServicePipe() call sites.
const SERVICE_PIPE_NAME = '\\\\.\\pipe\\neutron-service';
const SERVICE_NAME = 'NeutronService';

function serviceHostPath() {
  const architecture = process.arch === 'ia32' ? 'x86' : 'x64';
  const runtimeRoot = app.isPackaged
    ? path.join(process.resourcesPath, 'runtime', 'service')
    : path.join(__dirname, '..', 'runtime', 'service');
  return path.join(runtimeRoot, architecture, 'NeutronServiceHost.exe');
}

function installProtectionService(options = {}) {
  const hostPath = serviceHostPath();
  if (!existsSync(hostPath)) {
    return Promise.resolve({ ok: false, message: 'Servis çalıştırıcı bulunamadı. Önce "npm run service:build" ile derlenmeli.' });
  }
  const oldDataDir = path.join(app.getPath('userData'), 'data');
  // Provisioning already attempts the broad legacy-driver cleanup once.
  // Do not prepend that large registry sweep here: on a few Windows builds
  // Windows PowerShell itself can terminate with STATUS_HEAP_CORRUPTION.
  // serviceInstallCommand still blocks an exact same-name kernel driver.
  return runElevatedPowerShell(serviceInstallCommand(SERVICE_NAME, hostPath, oldDataDir), options);
}

function uninstallProtectionService(options = {}) {
  return runElevatedPowerShell(serviceUninstallCommand(SERVICE_NAME), options);
}

let serviceSocket = null;
let serviceConnected = false;
let serviceReconnectTimer = null;

function handleServiceEvent(event) {
  if (!event || typeof event.type !== 'string') return;
  sendProtectionEvent(event);
  if (event.settings) appSettings = { ...appSettings, ...event.settings };
  if (event.type === 'auto-quarantine-brake') {
    if (event.ml_disabled) appSettings.ml_assisted_detection_enabled = false;
    showAutoQuarantineBrakeNotification(event);
    return;
  }
  if (
    ['behavior-finding', 'network-finding', 'amsi-finding'].includes(event.type)
    || (event.type === 'watch-finding' && shouldNotifyWatchFinding(event))
  ) {
    showFindingNotification(event);
  }
}

function connectServicePipe() {
  if (serviceSocket) return;
  const socket = net.createConnection(SERVICE_PIPE_NAME);
  serviceSocket = socket;
  let buffer = '';
  socket.on('connect', () => {
    serviceConnected = true;
    sendProtectionEvent({ type: 'service-connected' });
    updateTrayMenu();
  });
  socket.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    const lines = buffer.split(/\r?\n/);
    buffer = lines.pop() || '';
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        handleServiceEvent(JSON.parse(line));
      } catch {
        /* ignore malformed line from the service pipe */
      }
    }
  });
  const onDisconnect = () => {
    serviceConnected = false;
    serviceSocket = null;
    sendProtectionEvent({ type: 'service-disconnected' });
    updateTrayMenu();
    if (!serviceReconnectTimer && appSettings.service_mode_enabled) {
      serviceReconnectTimer = setTimeout(() => {
        serviceReconnectTimer = null;
        connectServicePipe();
      }, 3000);
    }
  };
  socket.on('error', onDisconnect);
  socket.on('close', onDisconnect);
}

function disconnectServicePipe() {
  if (serviceReconnectTimer) {
    clearTimeout(serviceReconnectTimer);
    serviceReconnectTimer = null;
  }
  if (serviceSocket) {
    serviceSocket.destroy();
    serviceSocket = null;
  }
  serviceConnected = false;
}

// Fire-and-forget: the service replies over the same broadcast stream
// handleServiceEvent already relays to the renderer, matching this app's
// existing event-driven style rather than adding request/response
// correlation for a pipe that only ever has one client (the UI itself).
function sendServiceCommand(command) {
  if (!serviceSocket || !serviceConnected) {
    return { ok: false, message: 'Koruma servisine bağlı değil.' };
  }
  serviceSocket.write(`${JSON.stringify(command)}\n`);
  return { ok: true };
}

// --- App update check (GitHub Releases, no server) -------------------------
// Squirrel used to drive silent, unattended self-update through Electron's
// built-in autoUpdater; MSI installs don't speak that protocol, and there is
// no verified WiX-native equivalent. This is the explicit tradeoff of
// switching to a real setup wizard: update checks still poll GitHub
// Releases (no custom server, same as every other "someone else's server"
// decision made this session), but installing a new version is now a
// manual step -- a notification links out to the release page, where the
// user downloads and runs the new MSI themselves.
const UPDATE_CHECK_API_URL = 'https://api.github.com/repos/omerbugrae/Neutron/releases/latest';
const UPDATE_CHECK_INTERVAL_MS = 4 * 60 * 60 * 1000;
let updateCheckTimer = null;
let latestUpdateInfo = null; // { version, url } once a newer release is found

function compareVersions(a, b) {
  const partsA = String(a).split('.').map(Number);
  const partsB = String(b).split('.').map(Number);
  for (let index = 0; index < Math.max(partsA.length, partsB.length); index += 1) {
    const diff = (partsA[index] || 0) - (partsB[index] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function checkForAppUpdate() {
  if (!app.isPackaged || process.platform !== 'win32') return;
  const request = https.get(
    UPDATE_CHECK_API_URL,
    { headers: { 'User-Agent': 'Neutron-Update-Check' } },
    (response) => {
      let body = '';
      response.on('data', (chunk) => { body = `${body}${chunk}`.slice(0, 200_000); });
      response.on('end', () => {
        try {
          const release = JSON.parse(body);
          const remoteVersion = String(release.tag_name || '').replace(/^v/, '');
          if (remoteVersion && compareVersions(remoteVersion, app.getVersion()) > 0) {
            latestUpdateInfo = { version: remoteVersion, url: release.html_url };
            sendProtectionEvent({ type: 'update-ready', version: remoteVersion });
            if (appSettings.notifications_enabled && Notification.isSupported()) {
              const notification = new Notification({
                title: 'Yeni Neutron sürümü var',
                body: `${remoteVersion} sürümü indirilebilir. İndirme sayfasını açmak için tıklayın.`,
                icon: neutronImage(64),
                silent: true,
              });
              notification.on('click', () => shell.openExternal(latestUpdateInfo.url));
              notification.show();
            }
          }
        } catch (error) {
          console.error('Neutron güncelleme denetimi ayrıştırılamadı:', error.message);
        }
      });
    },
  );
  request.on('error', (error) => {
    // Best-effort background feature: a network hiccup or missing release
    // must never interrupt the app, same "fail open" stance as AMSI/cloud
    // lookup elsewhere this session.
    console.error('Neutron güncelleme denetimi başarısız:', error.message);
  });
  request.setTimeout(10_000, () => request.destroy());
}

function startUpdateChecks() {
  if (!app.isPackaged || process.platform !== 'win32') return;
  setTimeout(checkForAppUpdate, 30_000);
  updateCheckTimer = setInterval(checkForAppUpdate, UPDATE_CHECK_INTERVAL_MS);
}

// Removes the machine-wide bits that a plain file delete wouldn't touch (the
// AMSI COM/HKLM registration, the watchdog scheduled task, the WSC WMI
// instance, the service, firewall rules), in a single elevation prompt
// rather than several. Best-effort: none of these may have ever been
// registered if the user never opted into these settings, so failures here
// are swallowed.
//
// NSIS calls this automatically through Neutron.exe --prepare-uninstall
// before deleting the application files. The Settings action remains as a
// manual recovery path if an installation is removed in a nonstandard way.
function cleanupPrivilegedComponentsOnUninstall(options = {}) {
  const dllPath = amsiDllPath();
  const amsiUnregisterLine = existsSync(dllPath)
    ? amsiRegistrationCommand(dllPath, true)
    : `Remove-Item -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{ADACFA90-B877-414D-A818-2EA5291E290E}' -Recurse -Force -ErrorAction SilentlyContinue; ` +
      `Remove-Item -LiteralPath 'HKLM:\\SOFTWARE\\Classes\\CLSID\\{ADACFA90-B877-414D-A818-2EA5291E290E}' -Recurse -Force -ErrorAction SilentlyContinue`;
  const wscUnregisterLine =
    `try { Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct ` +
    `-Filter "instanceGuid='${wscQuote(WSC_INSTANCE_GUID)}'" -ErrorAction SilentlyContinue | ` +
    `Remove-CimInstance -ErrorAction SilentlyContinue } catch {}`;
  const serviceUnregisterLine = serviceUninstallCommand(SERVICE_NAME);
  const firewallUnregisterLine =
    `try { Get-NetFirewallRule -Name 'Neutron-FW-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue } catch {}`;
  // Each component is isolated in its own try/catch and the failures are
  // collected, rather than chaining everything with ';' under
  // $ErrorActionPreference='Stop'. Chained, the first component that threw
  // aborted every later one -- so a machine that never enabled the watchdog
  // kept its service and firewall rules -- and the caller got one opaque
  // message with no indication of what had actually been removed.
  //
  // The broad legacy driver sweep is deliberately absent: it is the command
  // that crashed Windows PowerShell with 0xC0000374 (see
  // provisionDefaultSecurityComponents). tools/security/ carries the offline
  // recovery scripts for the old experimental builds that need it.
  const steps = [
    ['AMSI kaydı', amsiUnregisterLine],
    ['Watchdog görevi', watchdogDeleteCommand(WATCHDOG_TASK_NAME)],
    ['Güvenlik Merkezi kaydı', wscUnregisterLine],
    ['Neutron servisi', serviceUnregisterLine],
    ['Güvenlik duvarı kuralları', firewallUnregisterLine],
  ].filter(([, command]) => Boolean(command));

  const psCommand = [
    `$failed = @()`,
    ...steps.map(([label, command]) =>
      `try { ${command} } catch { $failed += '${psQuoteSingle(label)}: ' + $_.Exception.Message }`),
    `if ($failed.Count -gt 0) { throw ($failed -join ' | ') }`,
  ].join('; ');
  return runElevatedPowerShell(psCommand, options);
}

function machineDataDirectory() {
  return path.join(process.env.ProgramData || 'C:\\ProgramData', 'Neutron', 'data');
}

async function writeSettingsToDataDirectory(settings, dataDirectory) {
  for (const [key, value] of Object.entries(settings)) {
    const result = await runEngineAction(
      ['--setting-set', key, '--value-json', JSON.stringify(value)],
      'settings-updated',
      { env: { NEUTRON_DATA_DIR: dataDirectory } },
    );
    if (!result.ok) return { ...result, setting: key };
  }
  return { ok: true };
}

async function writeProvisionSettings(settings) {
  for (const [key, value] of Object.entries(settings)) {
    const result = await writeAppSetting(key, value);
    if (!result.ok) return { ...result, setting: key };
  }
  return writeSettingsToDataDirectory(settings, machineDataDirectory());
}

// Called only by the elevated NSIS installer. It deliberately avoids a
// second UAC prompt (elevated:false), persists the same settings for both
// the desktop app and LocalSystem service, and reports every component.
async function provisionDefaultSecurityComponents() {
  // Provisioning registers an AMSI COM provider machine-wide, installs a
  // Windows service and writes HKLM. None of that belongs on a development
  // machine, and all of it is awkward to undo by hand.
  if (isDevSafeMode()) {
    return {
      ok: true,
      skipped: true,
      results: {},
      warnings: ['NEUTRON_DEV_SAFE=1: güvenlik bileşenleri bilerek kurulmadı.'],
      message: 'Geliştirme modu: sistem değişikliği yapılmadı.',
    };
  }
  const disabledSettings = {
    amsi_protection_enabled: false,
    watchdog_protection_enabled: false,
    service_mode_enabled: false,
    wsc_registration_enabled: false,
  };
  const settingsResult = await writeProvisionSettings(disabledSettings);
  if (!settingsResult.ok) {
    return { ok: false, stage: 'settings', message: settingsResult.message || 'Koruma ayarları kaydedilemedi.' };
  }

  // Do not run the old broad Services/Class registry sweep during setup.
  // It crashed Windows PowerShell with 0xC0000374 on a clean test machine.
  // The service installer below still performs a targeted same-name kernel
  // driver check; the offline Recovery script remains available for older
  // experimental installations that actually carried a file-system driver.
  const legacy = {
    ok: true,
    skipped: true,
    message: 'Geniş eski sürücü taraması kurulum sırasında güvenli biçimde atlandı.',
  };

  const results = {
    amsi: await registerAmsiProviderVerified({ elevated: false }),
    watchdog: {
      ok: true,
      skipped: true,
      message: 'Windows servisi aktifken çakışan ikinci bir otomatik başlangıç oluşturulmaması için varsayılan kapalı.',
    },
    service: null,
    // Remove only Neutron's obsolete experimental WMI entry, then leave
    // Windows Security/Defender as the authoritative registered provider.
    wsc: await unregisterWscProvider({ elevated: false }),
    legacy,
  };

  if (results.amsi.ok) {
    results.service = await installProtectionService({ elevated: false });
  } else {
    results.service = { ok: false, skipped: true, message: 'AMSI kurulamadığı için servis kurulumu başlatılmadı.' };
  }

  // WSC cleanup only removes an obsolete experimental registration. Some
  // Windows editions or enterprise policies do not expose SecurityCenter2,
  // so it is deliberately not a mandatory protection component.
  const failedCore = [
    ['amsi', results.amsi],
    ['service', results.service],
  ].filter(([, result]) => !result?.ok);
  if (failedCore.length) {
    if (results.service?.ok) await uninstallProtectionService({ elevated: false });
    if (results.amsi?.ok) await runElevatedRegsvr32(amsiDllPath(), true, { elevated: false });
    await writeProvisionSettings(disabledSettings);
  } else {
    const activationSettings = await writeProvisionSettings({
      amsi_protection_enabled: true,
      watchdog_protection_enabled: false,
      service_mode_enabled: true,
      wsc_registration_enabled: false,
    });
    results.settings = activationSettings;
    if (!activationSettings.ok) {
      failedCore.push(['settings', activationSettings]);
      await uninstallProtectionService({ elevated: false });
      await runElevatedRegsvr32(amsiDllPath(), true, { elevated: false });
      await writeProvisionSettings(disabledSettings);
    }
  }
  return {
    ok: failedCore.length === 0,
    results,
    warnings: [
      ...(legacy.skipped ? [legacy.message] : []),
      ...(!legacy.ok ? [`Eski sürücü temizliği atlandı: ${legacy.message}`] : []),
      ...(!results.wsc.ok ? [`Windows Güvenlik Merkezi temizliği atlandı: ${results.wsc.message}`] : []),
    ],
    message: failedCore.length
      ? failedCore.map(([name, result]) => `${name}: ${result.message}`).join(' | ')
      : 'AMSI ve gecikmeli Windows servisi etkinleştirildi.',
  };
}

function resolveEngine(argumentsList = []) {
  const executable = bundledEnginePath();
  const useBundledEngine = app.isPackaged || process.env.NEUTRON_USE_BUNDLED_ENGINE === '1';
  if (useBundledEngine) {
    return {
      command: executable,
      arguments: [...argumentsList, '--json-lines'],
      cwd: path.dirname(executable),
      bundled: true,
    };
  }

  const enginePath = path.join(__dirname, 'engine.py');
  return {
    command: resolvePython(),
    arguments: [enginePath, ...argumentsList, '--json-lines'],
    cwd: path.dirname(enginePath),
    bundled: false,
  };
}

function engineEnvironment() {
  const internalPaths = app.isPackaged
    ? path.dirname(process.execPath)
    : ['src', 'tools', 'tests', 'runtime', 'build', 'venv', 'node_modules', 'data']
      .map((entry) => path.join(__dirname, '..', entry))
      .join(path.delimiter);
  return {
    ...process.env,
    // Geliştirmede proje verisi görünür kalır; kurulumda kullanıcıya ait yazılabilir alan kullanılır.
    NEUTRON_DATA_DIR: process.env.NEUTRON_DATA_DIR || (app.isPackaged
      ? path.join(app.getPath('userData'), 'data')
      : path.join(__dirname, '..', 'data')),
    NEUTRON_BUNDLED_DATA_DIR: path.join(__dirname, '..', 'data'),
    NEUTRON_INTERNAL_PATHS: internalPaths,
    NEUTRON_ARCHIVE_HOST: process.execPath,
    NEUTRON_ARCHIVE_SCRIPT: path.join(__dirname, 'neutron-archive.cjs'),
    NEUTRON_ARCHIVE_RUN_AS_NODE: '1',
  };
}

function readScanHistory() {
  const engine = resolveEngine(['--history', '--limit', '5']);

  return new Promise((resolve) => {
    const child = spawn(
      engine.command,
      engine.arguments,
      {
        cwd: engine.cwd,
        windowsHide: true,
        shell: false,
        env: engineEnvironment(),
        stdio: ['ignore', 'pipe', 'pipe'],
      }
    );
    let output = '';

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      output = `${output}${chunk}`.slice(0, 200_000);
    });
    child.once('error', () => resolve({ ok: false, scans: [] }));
    child.once('close', () => {
      try {
        const event = JSON.parse(output.trim().split(/\r?\n/).at(-1));
        resolve(event.type === 'history'
          ? { ok: true, scans: event.scans }
          : { ok: false, scans: [] });
      } catch {
        resolve({ ok: false, scans: [] });
      }
    });
  });
}

function runEngineAction(argumentsList, expectedType, options = {}) {
  const engine = resolveEngine(argumentsList);
  return new Promise((resolve) => {
    const hasInput = typeof options.stdin === 'string' || Buffer.isBuffer(options.stdin);
    const child = spawn(engine.command, engine.arguments, {
      cwd: engine.cwd, windowsHide: true, shell: false,
      env: { ...engineEnvironment(), ...(options.env || {}) },
      stdio: [hasInput ? 'pipe' : 'ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { output = `${output}${chunk}`.slice(0, 200_000); });
    child.once('error', () => resolve({ ok: false, message: 'Neutron motoru başlatılamadı.' }));
    child.once('close', () => {
      try {
        const event = JSON.parse(output.trim().split(/\r?\n/).at(-1));
        resolve(event.type === expectedType ? { ok: true, ...event } : { ok: false, message: event.message || 'İşlem tamamlanamadı.' });
      } catch {
        resolve({ ok: false, message: 'Neutron motorundan geçersiz yanıt alındı.' });
      }
    });
    if (hasInput) {
      child.stdin.once('error', () => {});
      child.stdin.end(options.stdin);
    }
  });
}

async function runExclusionMutation(argumentsList) {
  const restartProtection = Boolean(protectionWatcher);
  if (restartProtection) stopProtectionWatcher({ silent: true });
  try {
    return await runEngineAction(argumentsList, 'exclusions-updated');
  } finally {
    if (restartProtection && !protectionWatcher) startProtectionWatcher();
  }
}

function createProtonUpdater() {
  return new ProtonUpdater({
    releasesUrl: process.env.NEUTRON_PROTON_RELEASES_URL || undefined,
    publicKeyPath: path.join(__dirname, 'security', 'proton-signing-public.pem'),
    packagedKeyPath: path.join(process.resourcesPath, 'runtime', 'proton', 'proton-runtime.key'),
    updateDirectory: path.join(app.getPath('userData'), 'proton-updates'),
    userAgent: `Neutron/${app.getVersion()}`,
    appVersion: app.getVersion(),
    allowLoopback: process.env.NEUTRON_PROTON_ALLOW_LOOPBACK === '1',
    onEvent: sendProtonUpdateEvent,
  });
}

function createFeatureUpdater() {
  return new FeatureUpdater({
    releasesUrl: process.env.NEUTRON_FEATURE_RELEASES_URL || process.env.NEUTRON_PROTON_RELEASES_URL || undefined,
    publicKeyPath: path.join(__dirname, 'security', 'proton-signing-public.pem'),
    packagedKeyPath: path.join(process.resourcesPath, 'runtime', 'proton', 'proton-runtime.key'),
    featureDirectory: path.join(app.getPath('userData'), 'data', 'ml', 'ember2024'),
    userAgent: `Neutron/${app.getVersion()}`,
    appVersion: app.getVersion(),
    allowLoopback: process.env.NEUTRON_FEATURE_ALLOW_LOOPBACK === '1',
    onEvent: sendFeatureUpdateEvent,
  });
}

function featureUpdateMessage(error) {
  if (['NETWORK_ERROR', 'REQUEST_TIMEOUT', 'HTTP_ERROR', 'TOO_MANY_REDIRECTS', 'RATE_LIMITED'].includes(error?.code)) {
    return 'Feature Update service is temporarily unavailable.';
  }
  if (error?.code === 'APP_TOO_OLD') return 'This Feature Update requires a newer Neutron version.';
  if (['INVALID_SIGNATURE_DOCUMENT', 'INVALID_MANIFEST', 'VERSION_MISMATCH', 'INVALID_DECRYPTION_KEY', 'MISSING_DECRYPTION_KEY'].includes(error?.code)) {
    return 'Feature Update could not be verified.';
  }
  return 'Feature Update could not be installed. Please try again later.';
}

async function performFeatureUpdate() {
  if (featureUpdatePromise) return featureUpdatePromise;
  featureUpdatePromise = (async () => {
    try {
      const updater = createFeatureUpdater();
      const check = await updater.check();
      if (check.revoked && check.currentVersion !== '0.00.000') {
        updater.quarantineCurrentFeature('killswitch');
        sendFeatureUpdateEvent({ stage: 'revoked', version: check.currentVersion });
      }
      if (!check.available) {
        const status = updater.status();
        sendFeatureUpdateEvent({ stage: 'current', version: check.latestVersion || status.version });
        return {
          ...status,
          updated: false,
          revoked: Boolean(check.revoked),
          message: check.revoked
            ? 'This Machine Learning Feature Update was revoked and has been disabled. No replacement version is published yet.'
            : check.reason === 'no-release'
              ? 'No Machine Learning Feature Update has been published yet.'
              : 'Machine Learning Feature Update is current.',
        };
      }
      return await updater.downloadAndInstall(check);
    } catch (error) {
      console.error('Feature Update failed:', error);
      const message = featureUpdateMessage(error);
      sendFeatureUpdateEvent({ stage: 'error', message });
      return { ok: false, code: error?.code || 'FEATURE_UPDATE_FAILED', message };
    }
  })();
  try {
    return await featureUpdatePromise;
  } finally {
    featureUpdatePromise = null;
  }
}

function protonUpdateMessage(error) {
  const connectionErrors = new Set([
    'NETWORK_ERROR',
    'REQUEST_TIMEOUT',
    'HTTP_ERROR',
    'TOO_MANY_REDIRECTS',
    'RATE_LIMITED',
  ]);
  const validationErrors = new Set([
    'INVALID_SIGNATURE_DOCUMENT',
    'VERSION_MISMATCH',
    'INVALID_DECRYPTION_KEY',
    'MISSING_DECRYPTION_KEY',
  ]);
  if (connectionErrors.has(error?.code)) return 'Güncelleme hizmetine şu anda bağlanılamıyor.';
  if (validationErrors.has(error?.code)) return 'Bu güncelleme kullanıma hazırlanamadı.';
  if (error?.code === 'ENGINE_TOO_OLD') return 'Bu güncelleme için Neutron’un daha yeni bir sürümü gerekiyor.';
  return 'Proton güncellenemedi. Lütfen daha sonra yeniden deneyin.';
}

// Reaction to a signed Proton revocation: get off the bad version immediately
// by rolling back to the newest archived version that is not itself revoked.
//
// Rolling back rather than simply disabling is what keeps this safe to fire
// automatically -- the scanner ends up on the last known-good rule set instead
// of on nothing at all. If every archived version is revoked there is no safe
// target, and the honest move is to say so rather than to leave the user
// believing a rollback happened.
async function rollBackRevokedProton(status, check) {
  const revoked = new Set(check.revokedVersions || []);
  const target = (status.rollback_versions || []).find((version) => !revoked.has(version));
  if (!target) {
    const message = 'Kurulu Proton sürümü geri çekildi ancak geri dönülebilecek doğrulanmış bir sürüm yok. '
      + 'Lütfen güncellemeleri kontrol edin.';
    await writeAppSetting('signature_update_last_error', message);
    sendProtonUpdateEvent({ stage: 'revoked-no-target', version: check.currentVersion, message });
    return { ok: false, code: 'PROTON_REVOKED_NO_TARGET', revoked: true, message };
  }
  sendProtonUpdateEvent({ stage: 'revoked', version: check.currentVersion, target });
  const result = await rollbackProtonUpdate(target);
  return {
    ...result,
    revoked: true,
    revoked_version: check.currentVersion,
    message: result.ok
      ? `Kurulu Proton sürümü geri çekildi; doğrulanmış ${target} sürümüne dönüldü.`
      : (result.message || 'Geri çekilen Proton sürümünden geri dönülemedi.'),
  };
}

async function performProtonUpdate(options = {}) {
  if (protonUpdatePromise) return protonUpdatePromise;
  protonUpdatePromise = (async () => {
    let restartProtection = false;
    try {
      await writeAppSetting('signature_update_last_check_at', Date.now());
      const status = await runEngineAction(['--signature-status'], 'signature-status');
      if (!status.ok) throw new Error(status.message || 'Proton sürümü okunamadı.');
      const updater = createProtonUpdater();
      const check = await updater.check(status.version || '1.00.001');
      // Revocation is handled before anything else: whether or not a newer
      // release exists, the machine must not stay on a withdrawn rule set.
      if (check.revoked) return await rollBackRevokedProton(status, check);
      if (!check.available) {
        sendProtonUpdateEvent({ stage: 'current', version: check.latestVersion || status.version });
        await writeAppSetting('signature_update_last_success_at', Date.now());
        await writeAppSetting('signature_update_last_error', '');
        return {
          ok: true,
          updated: false,
          message: check.reason === 'no-release'
            ? 'Henüz yayımlanmış Proton güncellemesi yok.'
            : 'Proton zaten güncel.',
          ...status,
        };
      }

      const downloaded = await updater.downloadAndDecrypt(check);
      sendProtonUpdateEvent({ stage: 'installing', version: downloaded.version });
      restartProtection = Boolean(protectionWatcher);
      if (restartProtection) stopProtectionWatcher({ silent: true });
      const installed = await runEngineAction(
        ['--install-proton-stdin'],
        'signature-updated',
        { stdin: JSON.stringify(downloaded.payload) },
      );
      if (!installed.ok) throw new Error(installed.message || 'Proton motor tarafından kabul edilmedi.');
      let archiveWarning = null;
      let archived = null;
      try {
        archived = updater.archiveVerifiedUpdate(downloaded);
      } catch {
        archiveWarning = 'Güncelleme tamamlandı ancak yerel yedek oluşturulamadı.';
      }
      if (archived && appSettings.service_mode_enabled && serviceConnected) {
        const serviceUpdate = sendServiceCommand({
          cmd: 'install_proton_archive',
          package_path: path.join(updater.updateDirectory, archived.package_file),
          signature_path: path.join(updater.updateDirectory, archived.signature_file),
          version: downloaded.version,
        });
        if (!serviceUpdate.ok) archiveWarning = 'Güncelleme masaüstü motoruna kuruldu; sistem servisine aktarılamadı.';
      }
      sendProtonUpdateEvent({ stage: 'complete', version: downloaded.version });
      await writeAppSetting('signature_update_last_success_at', Date.now());
      await writeAppSetting('signature_update_last_error', '');
      return { ...installed, updated: true, version: downloaded.version, archive_warning: archiveWarning };
    } catch (error) {
      console.error('Proton update failed:', error);
      const message = protonUpdateMessage(error);
      await writeAppSetting('signature_update_last_error', message);
      sendProtonUpdateEvent({ stage: 'error', message });
      return { ok: false, code: error?.code || 'PROTON_UPDATE_FAILED', message };
    } finally {
      if (restartProtection && !protectionWatcher) startProtectionWatcher();
    }
  })();
  try {
    return await protonUpdatePromise;
  } finally {
    protonUpdatePromise = null;
  }
}

async function rollbackProtonUpdate(version = '') {
  const restartProtection = Boolean(protectionWatcher);
  try {
    if (restartProtection) stopProtectionWatcher({ silent: true });
    const args = ['--rollback-proton'];
    if (version) args.push(String(version));
    const result = await runEngineAction(args, 'signature-rolled-back');
    if (result.ok) {
      sendProtonUpdateEvent({ stage: 'rolled-back', version: result.version });
      await writeAppSetting('signature_update_last_success_at', Date.now());
      await writeAppSetting('signature_update_last_error', '');
    }
    return result;
  } finally {
    if (restartProtection && !protectionWatcher) startProtectionWatcher();
  }
}

async function readAppSettings() {
  const result = await runEngineAction(['--settings'], 'settings');
  if (result.ok && result.settings) appSettings = { ...appSettings, ...result.settings };
  return { ok: result.ok, settings: appSettings, message: result.message };
}

async function writeAppSetting(key, value) {
  const result = await runEngineAction(
    ['--setting-set', key, '--value-json', JSON.stringify(value)],
    'settings-updated'
  );
  if (result.ok && result.settings) appSettings = { ...appSettings, ...result.settings };
  return result;
}

function startScan(webContents, options = {}) {
  const licenseError = requireLicense();
  if (licenseError) return licenseError;
  if (activeScan) {
    return {
      ok: false,
      message: 'Zaten çalışan bir tarama var.',
    };
  }

  const scanId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const engine = resolveEngine(
    options.targetPath
      ? [options.fullScan ? '--full-scan' : '--scan-path', options.targetPath]
      : [options.scheduled ? '--scheduled-quick-scan' : '--quick-scan']
  );
  const child = spawn(
    engine.command,
    engine.arguments,
    {
      cwd: engine.cwd,
      windowsHide: true,
      shell: false,
      env: engineEnvironment(),
      stdio: ['ignore', 'pipe', 'pipe'],
    }
  );

  activeScan = { id: scanId, child, webContents, cancelledByUser: false };
  let pendingOutput = '';
  let standardError = '';
  let engineReportedError = false;

  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    pendingOutput += chunk;
    const lines = pendingOutput.split(/\r?\n/);
    pendingOutput = lines.pop() || '';

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.type === 'error') engineReportedError = true;
        sendScanEvent(webContents, event);
        if (options.onEvent) options.onEvent(event);
      } catch {
        engineReportedError = true;
        sendScanEvent(webContents, {
          type: 'error',
          message: 'Tarama motorundan geçersiz yanıt alındı.',
        });
      }
    }
  });

  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    standardError = `${standardError}${chunk}`.slice(-2_000);
  });

  child.once('error', () => {
    engineReportedError = true;
    sendScanEvent(webContents, {
      type: 'error',
      message: 'Python tarama motoru başlatılamadı.',
    });
  });

  child.once('close', (code) => {
    const wasCancelled = activeScan?.id === scanId && activeScan.cancelledByUser;

    if (!wasCancelled && pendingOutput.trim()) {
      try {
        sendScanEvent(webContents, JSON.parse(pendingOutput));
      } catch {
        // Motor kapanırken yarım kalan satır kullanıcıya gösterilmez.
      }
    }

    if (wasCancelled) {
      sendScanEvent(webContents, { type: 'cancelled' });
    } else if (code !== 0 && !engineReportedError && activeScan?.id === scanId) {
      sendScanEvent(webContents, {
        type: 'error',
        message: standardError.trim() || 'Tarama motoru beklenmeyen şekilde durdu.',
      });
    }

    if (activeScan?.id === scanId) {
      activeScan = null;
    }
  });

  return { ok: true, scanId };
}

function cancelScan() {
  if (!activeScan) return { ok: false, message: 'Çalışan bir tarama yok.' };
  activeScan.cancelledByUser = true;
  activeScan.child.kill();
  return { ok: true };
}

// Item 7 of plan.md, done as a scheduled *quick* scan rather than a full
// disk scan: Neutron is already tray-resident whenever any protection
// toggle is on (window 'close' hides instead of quitting -- see
// createWindow()), so a plain in-process daily timer covers the common
// case without needing a second elevated Windows Scheduled Task next to
// the watchdog one. If the app genuinely isn't running at the 24h mark
// (fully quit, or the PC was off), the check below simply catches up the
// next time it starts -- there is no missed-run backlog to worry about.
const SCHEDULED_SCAN_INTERVAL_MS = 24 * 60 * 60 * 1000;
const SCHEDULED_SCAN_CHECK_INTERVAL_MS = 60 * 60 * 1000;
let scheduledScanTimer = null;

function runScheduledScanIfDue() {
  if (!appSettings.scheduled_scan_enabled) return;
  if (!licenseStatus().active) return;
  if (activeScan) return;
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const lastRunAt = Number(appSettings.scheduled_scan_last_run_at) || 0;
  if (Date.now() - lastRunAt < SCHEDULED_SCAN_INTERVAL_MS) return;

  const result = startScan(mainWindow.webContents, {
    scheduled: true,
    onEvent: (event) => {
      if (event.type !== 'complete') return;
      writeAppSetting('scheduled_scan_last_run_at', Date.now());
      if (!appSettings.notifications_enabled || !Notification.isSupported()) return;
      const confirmedCount = Number(event.confirmed_count) || 0;
      const reviewCount = Number(event.review_count) || 0;
      const body = confirmedCount > 0
        ? `${confirmedCount} kesin tehdit bulgusu var, incelemeniz gerekiyor.`
        : reviewCount > 0
          ? `${reviewCount} inceleme bulgusu var. Ayrıntılar için Neutron'u açın.`
          : `${Number(event.scanned) || 0} dosya tarandı, tehdit bulunamadı.`;
      new Notification({
        title: 'Zamanlanmış hızlı tarama tamamlandı',
        body,
        icon: neutronImage(64),
        silent: true,
      }).show();
    },
  });
  if (!result.ok) console.error('Zamanlanmış hızlı tarama başlatılamadı:', result.message);
}

function startScheduledScanTimer() {
  // A scheduled quick scan walks the whole user profile, writes scan history
  // and -- since automatic quarantine now applies to scans -- can move files.
  // None of that on a development machine.
  if (isDevSafeMode()) return;
  if (scheduledScanTimer) return;
  scheduledScanTimer = setInterval(runScheduledScanIfDue, SCHEDULED_SCAN_CHECK_INTERVAL_MS);
  setTimeout(runScheduledScanIfDue, 2 * 60 * 1000);
}

const SIGNATURE_UPDATE_TIMER_INTERVAL_MS = 60 * 60 * 1000;
let signatureUpdateTimer = null;

function runAutomaticSignatureUpdateIfDue() {
  if (!appSettings.signature_auto_update_enabled || protonUpdatePromise) return;
  const intervalHours = Math.max(1, Math.min(Number(appSettings.signature_update_interval_hours) || 6, 24));
  const lastCheckAt = Number(appSettings.signature_update_last_check_at) || 0;
  if (Date.now() - lastCheckAt < intervalHours * 60 * 60 * 1000) return;
  performProtonUpdate({ automatic: true }).catch((error) => {
    console.error('Automatic Proton update failed:', error);
  });
}

// Piggybacks on the hourly signature timer instead of a dedicated interval:
// Feature Update (ML models) has no download-new-version auto-timer today
// (installing 200+ MB unattended is opt-in only), but a revoked model set
// must still get disabled automatically even if the user never opens the
// Feature Update card again. The kill switch document itself is a few KB,
// so this stays cheap regardless.
const FEATURE_KILLSWITCH_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;
let lastFeatureKillSwitchCheckAt = 0;

async function runAutomaticFeatureKillSwitchCheckIfDue() {
  if (featureUpdatePromise) return;
  if (Date.now() - lastFeatureKillSwitchCheckAt < FEATURE_KILLSWITCH_CHECK_INTERVAL_MS) return;
  const updater = createFeatureUpdater();
  if (!updater.status().ready) return;
  lastFeatureKillSwitchCheckAt = Date.now();
  try {
    const check = await updater.check();
    if (check.revoked) {
      updater.quarantineCurrentFeature('killswitch');
      sendFeatureUpdateEvent({ stage: 'revoked', version: check.currentVersion });
    }
  } catch (error) {
    console.error('Automatic Feature Update kill switch check failed:', error);
  }
}

function startAutomaticSignatureUpdateTimer() {
  // Downloads Proton and installs it into the local database, and runs the
  // Feature Update kill switch check which can quarantine the model
  // directory. Both write state; neither belongs on a development machine.
  if (isDevSafeMode()) return;
  if (signatureUpdateTimer) return;
  const tick = () => {
    runAutomaticSignatureUpdateIfDue();
    runAutomaticFeatureKillSwitchCheckIfDue().catch(() => {});
  };
  signatureUpdateTimer = setInterval(tick, SIGNATURE_UPDATE_TIMER_INTERVAL_MS);
  setTimeout(tick, 90 * 1000);
}

function protectionStatus() {
  // In service mode the LocalSystem service owns every watcher, so this
  // process deliberately spawns none of them (see createWindow). Readiness
  // therefore cannot be read off the local child handles -- they are all
  // null by design -- and has to follow the service connection instead.
  // Reading them anyway is what left AMSI and web protection reporting
  // "Başlatılıyor" forever while the service was in fact running them.
  const viaService = Boolean(appSettings.service_mode_enabled);
  const moduleReady = (configured, localWatcher) => (viaService
    ? Boolean(configured && serviceConnected)
    : Boolean(localWatcher?.ready));
  const moduleRunning = (configured, localWatcher) => (viaService
    ? Boolean(configured && serviceConnected)
    : Boolean(localWatcher));

  return {
    ok: true,
    enabled: moduleRunning(appSettings.protection_enabled, protectionWatcher),
    ready: moduleReady(appSettings.protection_enabled, protectionWatcher),
    behaviorEnabled: moduleRunning(appSettings.behavior_protection_enabled, behaviorWatcher),
    behaviorReady: moduleReady(appSettings.behavior_protection_enabled, behaviorWatcher),
    behaviorConfigured: Boolean(appSettings.behavior_protection_enabled),
    webEnabled: moduleRunning(appSettings.web_protection_enabled, webWatcher),
    webReady: moduleReady(appSettings.web_protection_enabled, webWatcher),
    webConfigured: Boolean(appSettings.web_protection_enabled),
    amsiEnabled: moduleRunning(appSettings.amsi_protection_enabled, amsiService),
    amsiReady: moduleReady(appSettings.amsi_protection_enabled, amsiService),
    amsiConfigured: Boolean(appSettings.amsi_protection_enabled),
    watchdogConfigured: Boolean(appSettings.watchdog_protection_enabled),
    wscConfigured: Boolean(appSettings.wsc_registration_enabled),
    wscAvailable: false,
    wscMessage: 'Windows Güvenlik Merkezi ve Microsoft Defender normal durumda bırakılır; eski Neutron test kaydı kurulumda temizlenir.',
    networkEnabled: moduleRunning(appSettings.network_protection_enabled, networkWatcher),
    networkReady: moduleReady(appSettings.network_protection_enabled, networkWatcher),
    networkConfigured: Boolean(appSettings.network_protection_enabled),
    serviceConfigured: Boolean(appSettings.service_mode_enabled),
    serviceConnected: Boolean(serviceConnected),
    memoryEnabled: moduleRunning(appSettings.memory_scan_enabled, memoryWatcher),
    memoryReady: moduleReady(appSettings.memory_scan_enabled, memoryWatcher),
    memoryConfigured: Boolean(appSettings.memory_scan_enabled),
    usbEnabled: moduleRunning(appSettings.usb_protection_enabled, usbWatcher),
    usbReady: moduleReady(appSettings.usb_protection_enabled, usbWatcher),
    usbConfigured: Boolean(appSettings.usb_protection_enabled),
    ransomwareEnabled: moduleRunning(appSettings.ransomware_protection_enabled, ransomwareWatcher),
    ransomwareReady: moduleReady(appSettings.ransomware_protection_enabled, ransomwareWatcher),
    ransomwareConfigured: Boolean(appSettings.ransomware_protection_enabled),
  };
}

function startWebWatcher() {
  if (requireLicense()) return;
  if (webWatcher) return protectionStatus();
  const engine = resolveEngine(['--watch-web', '--exit-with-parent']);
  const child = spawn(engine.command, engine.arguments, { cwd: engine.cwd, windowsHide: true, shell: false, env: engineEnvironment(), stdio: ['pipe', 'pipe', 'pipe'] });
  const watcher = { child, ready: false, stopping: false, pending: '', stderr: '' };
  webWatcher = watcher;
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    watcher.pending += chunk;
    const lines = watcher.pending.split(/\r?\n/); watcher.pending = lines.pop() || '';
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.type === 'web-ready') watcher.ready = true; if (watcher.ready) noteWatcherHealthy('webWatcher');
        sendProtectionEvent(event);
        if (event.type === 'web-finding') showFindingNotification(event, 'Neutron zararlı indirme kaynağı algıladı');
      } catch { sendProtectionEvent({ type: 'web-error', message: 'Web korumasından geçersiz yanıt alındı.' }); }
    }
  });
  child.stderr.setEncoding('utf8'); child.stderr.on('data', (chunk) => { watcher.stderr = `${watcher.stderr}${chunk}`.slice(-2000); });
  child.once('close', (code) => {
    const current = webWatcher === watcher; if (current) webWatcher = null;
    if (current && !watcher.stopping && code !== 0) {
      scheduleWatcherRestart('webWatcher', () => Boolean(appSettings.web_protection_enabled), startWebWatcher);
      sendProtectionEvent({ type: 'web-error', message: watcher.stderr.trim() || 'Web koruması durdu.' });
    }
    else if (current && !watcher.silent) sendProtectionEvent({ type: 'web-stopped' });
  });
  return protectionStatus();
}

function stopWebWatcher(options = {}) {
  if (!webWatcher) return protectionStatus();
  webWatcher.stopping = true; webWatcher.silent = Boolean(options.silent); webWatcher.child.kill(); webWatcher = null;
  return protectionStatus();
}

function startBehaviorWatcher() {
  if (requireLicense()) return;
  if (behaviorWatcher) return protectionStatus();
  const engine = resolveEngine(['--watch-behavior', '--exit-with-parent']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const watcher = { child, ready: false, stopping: false, pending: '', stderr: '' };
  behaviorWatcher = watcher;
  updateTrayMenu();
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    watcher.pending += chunk;
    const lines = watcher.pending.split(/\r?\n/);
    watcher.pending = lines.pop() || '';
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.type === 'behavior-ready') watcher.ready = true; if (watcher.ready) noteWatcherHealthy('behaviorWatcher');
        sendProtectionEvent(event);
        if (event.type === 'behavior-finding') {
          showFindingNotification(event, 'Neutron şüpheli davranış algıladı');
        }
      } catch {
        sendProtectionEvent({ type: 'behavior-error', message: 'Davranış motorundan geçersiz yanıt alındı.' });
      }
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { watcher.stderr = `${watcher.stderr}${chunk}`.slice(-2_000); });
  child.once('error', () => {
    if (behaviorWatcher === watcher) behaviorWatcher = null;
    updateTrayMenu();
    sendProtectionEvent({ type: 'behavior-error', message: 'Davranış izleme motoru başlatılamadı.' });
  });
  child.once('close', (code) => {
    const isCurrentWatcher = behaviorWatcher === watcher;
    if (isCurrentWatcher) behaviorWatcher = null;
    updateTrayMenu();
    if (isCurrentWatcher && !watcher.stopping && code !== 0) {
      scheduleWatcherRestart('behaviorWatcher', () => Boolean(appSettings.behavior_protection_enabled), startBehaviorWatcher);
      sendProtectionEvent({
        type: 'behavior-error',
        message: watcher.stderr.trim() || 'Davranış izleme beklenmeyen şekilde durdu.',
      });
    } else if (isCurrentWatcher && !watcher.silent) {
      sendProtectionEvent({ type: 'behavior-stopped' });
    }
  });
  return protectionStatus();
}

function stopBehaviorWatcher(options = {}) {
  if (!behaviorWatcher) return protectionStatus();
  behaviorWatcher.stopping = true;
  behaviorWatcher.silent = Boolean(options.silent);
  behaviorWatcher.child.kill();
  behaviorWatcher = null;
  updateTrayMenu();
  return protectionStatus();
}

function startNetworkWatcher() {
  if (requireLicense()) return;
  if (networkWatcher) return protectionStatus();
  const engine = resolveEngine(['--watch-network', '--exit-with-parent']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const watcher = { child, ready: false, stopping: false, pending: '', stderr: '' };
  networkWatcher = watcher;
  updateTrayMenu();
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    watcher.pending += chunk;
    const lines = watcher.pending.split(/\r?\n/);
    watcher.pending = lines.pop() || '';
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.type === 'network-ready') watcher.ready = true; if (watcher.ready) noteWatcherHealthy('networkWatcher');
        sendProtectionEvent(event);
        if (event.type === 'network-finding') {
          showFindingNotification(event, 'Neutron bilinen kötü amaçlı bir IP adresine bağlantı algıladı');
        }
      } catch {
        sendProtectionEvent({ type: 'network-error', message: 'Ağ izleme motorundan geçersiz yanıt alındı.' });
      }
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { watcher.stderr = `${watcher.stderr}${chunk}`.slice(-2_000); });
  child.once('error', () => {
    if (networkWatcher === watcher) networkWatcher = null;
    updateTrayMenu();
    sendProtectionEvent({ type: 'network-error', message: 'Ağ izleme motoru başlatılamadı.' });
  });
  child.once('close', (code) => {
    const isCurrentWatcher = networkWatcher === watcher;
    if (isCurrentWatcher) networkWatcher = null;
    updateTrayMenu();
    if (isCurrentWatcher && !watcher.stopping && code !== 0) {
      scheduleWatcherRestart('networkWatcher', () => Boolean(appSettings.network_protection_enabled), startNetworkWatcher);
      sendProtectionEvent({
        type: 'network-error',
        message: watcher.stderr.trim() || 'Ağ izleme beklenmeyen şekilde durdu.',
      });
    } else if (isCurrentWatcher && !watcher.silent) {
      sendProtectionEvent({ type: 'network-stopped' });
    }
  });
  return protectionStatus();
}

function stopNetworkWatcher(options = {}) {
  if (!networkWatcher) return protectionStatus();
  networkWatcher.stopping = true;
  networkWatcher.silent = Boolean(options.silent);
  networkWatcher.child.kill();
  networkWatcher = null;
  updateTrayMenu();
  return protectionStatus();
}

// Same-user visibility only outside service mode -- SeDebugPrivilege
// (needed to read other users'/higher-integrity processes' memory) is
// only reliably available when this runs inside the LocalSystem service.
function startMemoryWatcher() {
  if (requireLicense()) return;
  if (memoryWatcher) return protectionStatus();
  const engine = resolveEngine(['--watch-memory', '--exit-with-parent']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const watcher = { child, ready: false, stopping: false, pending: '', stderr: '' };
  memoryWatcher = watcher;
  updateTrayMenu();
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    watcher.pending += chunk;
    const lines = watcher.pending.split(/\r?\n/);
    watcher.pending = lines.pop() || '';
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.type === 'memory-ready') watcher.ready = true; if (watcher.ready) noteWatcherHealthy('memoryWatcher');
        sendProtectionEvent(event);
        if (event.type === 'memory-finding') {
          showFindingNotification(event, 'Neutron şüpheli bellek/process injection etkinliği algıladı');
        }
      } catch {
        sendProtectionEvent({ type: 'memory-error', message: 'Bellek tarama motorundan geçersiz yanıt alındı.' });
      }
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { watcher.stderr = `${watcher.stderr}${chunk}`.slice(-2_000); });
  child.once('error', () => {
    if (memoryWatcher === watcher) memoryWatcher = null;
    updateTrayMenu();
    sendProtectionEvent({ type: 'memory-error', message: 'Bellek tarama motoru başlatılamadı.' });
  });
  child.once('close', (code) => {
    const isCurrentWatcher = memoryWatcher === watcher;
    if (isCurrentWatcher) memoryWatcher = null;
    updateTrayMenu();
    if (isCurrentWatcher && !watcher.stopping && code !== 0) {
      scheduleWatcherRestart('memoryWatcher', () => Boolean(appSettings.memory_scan_enabled), startMemoryWatcher);
      sendProtectionEvent({
        type: 'memory-error',
        message: watcher.stderr.trim() || 'Bellek taraması beklenmeyen şekilde durdu.',
      });
    } else if (isCurrentWatcher && !watcher.silent) {
      sendProtectionEvent({ type: 'memory-stopped' });
    }
  });
  return protectionStatus();
}

function stopMemoryWatcher(options = {}) {
  if (!memoryWatcher) return protectionStatus();
  memoryWatcher.stopping = true;
  memoryWatcher.silent = Boolean(options.silent);
  memoryWatcher.child.kill();
  memoryWatcher = null;
  updateTrayMenu();
  return protectionStatus();
}

function startUsbWatcher() {
  if (requireLicense()) return;
  if (usbWatcher) return protectionStatus();
  const engine = resolveEngine(['--watch-usb', '--exit-with-parent']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const watcher = { child, ready: false, stopping: false, pending: '', stderr: '' };
  usbWatcher = watcher;
  updateTrayMenu();
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    watcher.pending += chunk;
    const lines = watcher.pending.split(/\r?\n/);
    watcher.pending = lines.pop() || '';
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.type === 'usb-ready') watcher.ready = true; if (watcher.ready) noteWatcherHealthy('usbWatcher');
        sendProtectionEvent(event);
        if (event.type === 'auto-quarantine-brake') {
          if (event.ml_disabled) appSettings.ml_assisted_detection_enabled = false;
          showAutoQuarantineBrakeNotification(event);
        } else if (event.type === 'usb-finding') {
          showFindingNotification(event, 'Neutron çıkarılabilir medyada tehdit algıladı');
        }
      } catch {
        sendProtectionEvent({ type: 'usb-error', message: 'USB izleme motorundan geçersiz yanıt alındı.' });
      }
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { watcher.stderr = `${watcher.stderr}${chunk}`.slice(-2_000); });
  child.once('error', () => {
    if (usbWatcher === watcher) usbWatcher = null;
    updateTrayMenu();
    sendProtectionEvent({ type: 'usb-error', message: 'USB izleme motoru başlatılamadı.' });
  });
  child.once('close', (code) => {
    const isCurrentWatcher = usbWatcher === watcher;
    if (isCurrentWatcher) usbWatcher = null;
    updateTrayMenu();
    if (isCurrentWatcher && !watcher.stopping && code !== 0) {
      scheduleWatcherRestart('usbWatcher', () => Boolean(appSettings.usb_protection_enabled), startUsbWatcher);
      sendProtectionEvent({
        type: 'usb-error',
        message: watcher.stderr.trim() || 'USB izleme beklenmeyen şekilde durdu.',
      });
    } else if (isCurrentWatcher && !watcher.silent) {
      sendProtectionEvent({ type: 'usb-stopped' });
    }
  });
  return protectionStatus();
}

function stopUsbWatcher(options = {}) {
  if (!usbWatcher) return protectionStatus();
  usbWatcher.stopping = true;
  usbWatcher.silent = Boolean(options.silent);
  usbWatcher.child.kill();
  usbWatcher = null;
  updateTrayMenu();
  return protectionStatus();
}

function startRansomwareWatcher() {
  if (requireLicense()) return;
  if (ransomwareWatcher) return protectionStatus();
  const engine = resolveEngine(['--watch-ransomware', '--exit-with-parent']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const watcher = { child, ready: false, stopping: false, pending: '', stderr: '' };
  ransomwareWatcher = watcher;
  updateTrayMenu();
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    watcher.pending += chunk;
    const lines = watcher.pending.split(/\r?\n/);
    watcher.pending = lines.pop() || '';
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.type === 'ransomware-ready') watcher.ready = true; if (watcher.ready) noteWatcherHealthy('ransomwareWatcher');
        sendProtectionEvent(event);
        if (event.type === 'ransomware-finding') {
          // Ignores the notification preference: encryption in progress is
          // the one thing where minutes of delay changes the outcome.
          showFindingNotification(
            event,
            event.signal === 'canary'
              ? 'Neutron fidye yazılımı belirtisi algıladı'
              : 'Neutron toplu dosya şifreleme algıladı',
          );
        }
      } catch {
        sendProtectionEvent({ type: 'ransomware-error', message: 'Fidye yazılımı korumasından geçersiz yanıt alındı.' });
      }
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { watcher.stderr = `${watcher.stderr}${chunk}`.slice(-2_000); });
  child.once('error', () => {
    if (ransomwareWatcher === watcher) ransomwareWatcher = null;
    updateTrayMenu();
    sendProtectionEvent({ type: 'ransomware-error', message: 'Fidye yazılımı koruması başlatılamadı.' });
  });
  child.once('close', (code) => {
    const isCurrentWatcher = ransomwareWatcher === watcher;
    if (isCurrentWatcher) ransomwareWatcher = null;
    updateTrayMenu();
    if (isCurrentWatcher && !watcher.stopping && code !== 0) {
      scheduleWatcherRestart('ransomwareWatcher', () => Boolean(appSettings.ransomware_protection_enabled), startRansomwareWatcher);
      sendProtectionEvent({
        type: 'ransomware-error',
        message: watcher.stderr.trim() || 'Fidye yazılımı koruması beklenmeyen şekilde durdu.',
      });
    } else if (isCurrentWatcher && !watcher.silent) {
      sendProtectionEvent({ type: 'ransomware-stopped' });
    }
  });
  return protectionStatus();
}

function stopRansomwareWatcher(options = {}) {
  if (!ransomwareWatcher) return protectionStatus();
  ransomwareWatcher.stopping = true;
  ransomwareWatcher.silent = Boolean(options.silent);
  ransomwareWatcher.child.kill();
  ransomwareWatcher = null;
  updateTrayMenu();
  return protectionStatus();
}

function startAmsiService() {
  if (requireLicense()) return;
  if (amsiService) return protectionStatus();
  const engine = resolveEngine(['--amsi-service', '--exit-with-parent']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const service = { child, ready: false, stopping: false, pending: '', stderr: '' };
  amsiService = service;
  updateTrayMenu();
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    service.pending += chunk;
    const lines = service.pending.split(/\r?\n/);
    service.pending = lines.pop() || '';
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.type === 'amsi-ready') {
          service.ready = true;
          updateTrayMenu();
        }
        sendProtectionEvent(event);
        if (event.type === 'amsi-finding') {
          showFindingNotification(event, 'Neutron çalıştırma öncesi zararlı betik engelledi');
        }
      } catch {
        sendProtectionEvent({ type: 'amsi-error', message: 'AMSI servisinden geçersiz yanıt alındı.' });
      }
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { service.stderr = `${service.stderr}${chunk}`.slice(-2_000); });
  child.once('error', () => {
    if (amsiService === service) amsiService = null;
    updateTrayMenu();
    sendProtectionEvent({ type: 'amsi-error', message: 'AMSI koruma servisi başlatılamadı.' });
  });
  child.once('close', (code) => {
    const isCurrentService = amsiService === service;
    if (isCurrentService) amsiService = null;
    updateTrayMenu();
    if (isCurrentService && !service.stopping && code !== 0) {
      sendProtectionEvent({
        type: 'amsi-error',
        message: service.stderr.trim() || 'AMSI koruma servisi beklenmeyen şekilde durdu.',
      });
    } else if (isCurrentService && !service.silent) {
      sendProtectionEvent({ type: 'amsi-stopped' });
    }
  });
  return protectionStatus();
}

function stopAmsiService(options = {}) {
  if (!amsiService) return protectionStatus();
  amsiService.stopping = true;
  amsiService.silent = Boolean(options.silent);
  amsiService.child.kill();
  amsiService = null;
  updateTrayMenu();
  return protectionStatus();
}

function startProtectionWatcher() {
  if (requireLicense()) return;
  if (protectionWatcher) return protectionStatus();

  const engine = resolveEngine(['--watch', '--exit-with-parent']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const watcher = { child, ready: false, stopping: false, pending: '', stderr: '' };
  protectionWatcher = watcher;
  updateTrayMenu();

  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    watcher.pending += chunk;
    const lines = watcher.pending.split(/\r?\n/);
    watcher.pending = lines.pop() || '';
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.type === 'watch-ready') {
          watcher.ready = true;
          updateTrayMenu();
        }
        sendProtectionEvent(event);
        if (event.type === 'auto-quarantine-brake') {
          if (event.ml_disabled) appSettings.ml_assisted_detection_enabled = false;
          showAutoQuarantineBrakeNotification(event);
        } else if (event.type === 'watch-finding' && shouldNotifyWatchFinding(event)) {
          showFindingNotification(event);
        }
      } catch {
        sendProtectionEvent({ type: 'watch-error', message: 'Koruma motorundan geçersiz yanıt alındı.' });
      }
    }
  });

  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    watcher.stderr = `${watcher.stderr}${chunk}`.slice(-2_000);
  });
  child.once('error', () => {
    if (protectionWatcher === watcher) protectionWatcher = null;
    updateTrayMenu();
    sendProtectionEvent({ type: 'watch-error', message: 'Gerçek zamanlı koruma motoru başlatılamadı.' });
  });
  child.once('close', (code) => {
    const isCurrentWatcher = protectionWatcher === watcher;
    if (isCurrentWatcher) protectionWatcher = null;
    updateTrayMenu();
    if (isCurrentWatcher && !watcher.stopping && code !== 0) {
      sendProtectionEvent({
        type: 'watch-error',
        message: watcher.stderr.trim() || 'Gerçek zamanlı koruma beklenmeyen şekilde durdu.',
      });
    } else if (isCurrentWatcher && !watcher.silent) {
      sendProtectionEvent({ type: 'watch-stopped' });
    }
  });

  return protectionStatus();
}

function stopProtectionWatcher(options = {}) {
  if (!protectionWatcher) return protectionStatus();
  protectionWatcher.stopping = true;
  protectionWatcher.silent = Boolean(options.silent);
  protectionWatcher.child.kill();
  protectionWatcher = null;
  updateTrayMenu();
  return protectionStatus();
}

async function updateApplicationSetting(key, value) {
  const allowedKeys = new Set([
    'start_with_windows',
    'protection_enabled',
    'behavior_protection_enabled',
    'web_protection_enabled',
    'amsi_protection_enabled',
    'watchdog_protection_enabled',
    'wsc_registration_enabled',
    'cloud_lookup_enabled',
    'ml_assisted_detection_enabled',
    'malwarebazaar_api_key',
    'virustotal_api_key',
    'network_protection_enabled',
    'service_mode_enabled',
    'memory_scan_enabled',
    'usb_protection_enabled',
    'ransomware_protection_enabled',
    'notifications_enabled',
    'watch_paths',
    'scan_max_files',
    'scheduled_scan_enabled',
    'signature_auto_update_enabled',
    'signature_update_interval_hours',
  ]);
  if (!allowedKeys.has(key)) return { ok: false, message: 'Desteklenmeyen ayar.' };

  const result = await writeAppSetting(key, value);
  if (!result.ok) return result;

  // setLoginItemSettings writes a Run entry under HKCU, which survives long
  // after the development session that created it.
  if (key === 'start_with_windows' && !isDevSafeMode()) {
    const openAtLogin = Boolean(appSettings.start_with_windows);
    app.setLoginItemSettings({
      openAtLogin,
      path: process.execPath,
      args: app.isPackaged ? ['--hidden'] : [app.getAppPath(), '--hidden'],
    });
  }

  if (key === 'protection_enabled') {
    appSettings.protection_enabled ? startProtectionWatcher() : stopProtectionWatcher();
  } else if (key === 'behavior_protection_enabled') {
    appSettings.behavior_protection_enabled ? startBehaviorWatcher() : stopBehaviorWatcher();
  } else if (key === 'web_protection_enabled') {
    appSettings.web_protection_enabled ? startWebWatcher() : stopWebWatcher();
  } else if (key === 'amsi_protection_enabled') {
    appSettings.amsi_protection_enabled ? startAmsiService() : stopAmsiService();
  } else if (key === 'network_protection_enabled') {
    appSettings.network_protection_enabled ? startNetworkWatcher() : stopNetworkWatcher();
  } else if (key === 'memory_scan_enabled') {
    appSettings.memory_scan_enabled ? startMemoryWatcher() : stopMemoryWatcher();
  } else if (key === 'ransomware_protection_enabled') {
    appSettings.ransomware_protection_enabled ? startRansomwareWatcher() : stopRansomwareWatcher();
  } else if (key === 'usb_protection_enabled') {
    appSettings.usb_protection_enabled ? startUsbWatcher() : stopUsbWatcher();
  } else if ((key === 'watch_paths' || key === 'scan_max_files') && protectionWatcher) {
    stopProtectionWatcher({ silent: true });
    startProtectionWatcher();
  }
  return { ok: true, settings: appSettings };
}

// The enabled-watcher list was written out three times (startup, activation,
// service-mode fallback). Adding a watcher meant remembering all three, and a
// missed one silently left that protection off in whichever path was forgotten.
// A watcher process that exits non-zero while it was supposed to be running
// used to just report an error and stay dead: the module silently stopped
// protecting until the user noticed and toggled it. Restart it, with backoff
// and a cap so a permanently broken watcher cannot spin.
const WATCHER_RESTART_LIMIT = 5;
const watcherRestartCounts = new Map();

function scheduleWatcherRestart(key, isEnabled, start) {
  const attempts = (watcherRestartCounts.get(key) || 0) + 1;
  if (!isEnabled() || attempts > WATCHER_RESTART_LIMIT) return false;
  watcherRestartCounts.set(key, attempts);
  const delay = Math.min(60_000, 2_000 * 2 ** (attempts - 1));
  setTimeout(() => {
    if (isEnabled()) start();
  }, delay).unref?.();
  return true;
}

function noteWatcherHealthy(key) {
  watcherRestartCounts.delete(key);
}

// --- Activation window ----------------------------------------------------
//
// A separate top-level window rather than an overlay inside the main UI. The
// overlay it replaces could only ever appear if the main window was already
// open and loaded, which is the wrong dependency: the situations that need
// activation most are the ones where the main UI is blocked, hidden in the
// tray, or was never shown because the app started with --hidden.
let activationWindow = null;

function openActivationWindow(reason = 'missing') {
  if (activationWindow && !activationWindow.isDestroyed()) {
    if (activationWindow.isMinimized()) activationWindow.restore();
    activationWindow.show();
    activationWindow.focus();
    return activationWindow;
  }
  const applicationIcon = neutronImage();
  activationWindow = new BrowserWindow({
    width: 560,
    height: 620,
    resizable: false,
    minimizable: true,
    maximizable: false,
    frame: false,
    backgroundColor: '#050a18',
    show: false,
    icon: applicationIcon || NEUTRON_ICON_PATH,
    // Not parented to mainWindow on purpose: mainWindow may not exist, and a
    // child window would be hidden along with a tray-minimised parent.
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      spellcheck: false,
      preload: path.join(__dirname, 'activation-preload.cjs'),
    },
  });
  if (applicationIcon && process.platform === 'win32') activationWindow.setIcon(applicationIcon);
  activationWindow.once('ready-to-show', () => {
    activationWindow?.show();
    activationWindow?.focus();
  });
  activationWindow.on('closed', () => { activationWindow = null; });
  activationWindow.loadFile(path.join(__dirname, 'activation.html'), {
    query: { reason: String(reason) },
  });
  return activationWindow;
}

function closeActivationWindow() {
  if (activationWindow && !activationWindow.isDestroyed()) activationWindow.close();
  activationWindow = null;
}

// --- Licence enforcement while the app is running -------------------------
//
// The licence used to be checked once, at startup, by an in-app overlay. That
// left the case nobody had covered: a licence that expires while Neutron is
// running. Every watcher had already been started, so protection carried on
// indefinitely past the expiry date, the user was never told, and the only
// symptom was that IPC calls began returning LICENSE_REQUIRED.
//
// Enforcement now runs on a timer instead. On expiry the watchers are stopped
// (an unlicensed Neutron must not keep scanning), the user is told plainly
// that the machine is no longer protected, and the activation window opens.
// While the machine stays unlicensed the reminder repeats, because a single
// notification at the moment of expiry is easy to miss and the consequence --
// running with no protection at all -- is not a quiet one.
const LICENSE_CHECK_INTERVAL_MS = 15 * 60 * 1000;
const LICENSE_REMINDER_INTERVAL_MS = 4 * 60 * 60 * 1000;
let licenseCheckTimer = null;
let lastLicenseReminderAt = 0;
let licenseWasActive = null;

function stopAllWatchers(options = { silent: true }) {
  disconnectServicePipe();
  stopProtectionWatcher(options);
  stopBehaviorWatcher(options);
  stopWebWatcher(options);
  stopAmsiService(options);
  stopNetworkWatcher(options);
  stopMemoryWatcher(options);
  stopUsbWatcher(options);
  stopRansomwareWatcher(options);
}

function notifyLicenseLapsed(reason) {
  if (!appSettings.notifications_enabled || !Notification.isSupported()) return;
  new Notification({
    title: reason === 'expired' ? 'Neutron lisansı sona erdi' : 'Neutron etkinleştirilmedi',
    body: 'Tüm korumalar durduruldu. Bu bilgisayar şu anda Neutron tarafından korunmuyor.',
    icon: neutronImage(64),
    urgency: 'critical',
  }).show();
}

// Returns true when the licence is valid. Called on startup, on the timer,
// and after any change to the stored licence.
function enforceLicenseState(options = {}) {
  const status = licenseStatus();
  if (status.active) {
    if (licenseWasActive === false) {
      // Recovered: close the activation window and bring protection back.
      closeActivationWindow();
      startEnabledWatchers();
      updateTrayMenu();
    }
    licenseWasActive = true;
    lastLicenseReminderAt = 0;
    return true;
  }

  // Distinguishing expiry from a missing licence matters to the user: one is
  // "renew", the other is "you never activated this".
  const reason = status.expired ? 'expired' : (status.license || status.failures?.length ? 'invalid' : 'missing');
  const justLapsed = licenseWasActive !== false;
  licenseWasActive = false;

  stopAllWatchers();
  updateTrayMenu();

  const now = Date.now();
  if (justLapsed || now - lastLicenseReminderAt >= LICENSE_REMINDER_INTERVAL_MS) {
    lastLicenseReminderAt = now;
    notifyLicenseLapsed(reason);
    openActivationWindow(justLapsed ? reason : 'reminder');
  } else if (options.forceWindow) {
    openActivationWindow(reason);
  }
  return false;
}

function startLicenseWatchdog() {
  if (licenseCheckTimer) return;
  licenseCheckTimer = setInterval(() => {
    invalidateLicenseStatusCache();
    enforceLicenseState();
  }, LICENSE_CHECK_INTERVAL_MS);
}

function startEnabledWatchers() {
  // Development safety switch. Running `npm start` on a development machine
  // otherwise turns on real-time protection over the whole user profile,
  // plants ransomware canary files in Documents/Desktop/Pictures/Downloads,
  // and starts watchers that write scan history and quarantine entries -- on
  // the machine the developer is working from, not the test machine.
  //
  // NEUTRON_DEV_SAFE=1 makes the app inert: it opens, the UI works, nothing
  // observes or modifies the machine. Deliberately env-driven rather than a
  // setting, so it cannot be left switched on in a shipped build by accident.
  if (isDevSafeMode()) {
    sendProtectionEvent({
      type: 'watch-error',
      message: 'NEUTRON_DEV_SAFE=1: korumalar bilerek başlatılmadı (geliştirme modu).',
    });
    return;
  }
  if (!licenseStatus().active) return;
  if (appSettings.service_mode_enabled) {
    connectServicePipe();
    return;
  }
  if (appSettings.protection_enabled) startProtectionWatcher();
  if (appSettings.behavior_protection_enabled) startBehaviorWatcher();
  if (appSettings.web_protection_enabled) startWebWatcher();
  if (appSettings.amsi_protection_enabled) startAmsiService();
  if (appSettings.network_protection_enabled) startNetworkWatcher();
  if (appSettings.memory_scan_enabled) startMemoryWatcher();
  if (appSettings.usb_protection_enabled) startUsbWatcher();
  if (appSettings.ransomware_protection_enabled) startRansomwareWatcher();
}

async function createWindow() {
  const startHidden = process.argv.includes('--hidden');
  const applicationIcon = neutronImage();
  const window = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    frame: false,
    transparent: false,
    backgroundColor: '#050a18',
    show: false,
    icon: applicationIcon || NEUTRON_ICON_PATH,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webgl: true,
      spellcheck: false,
      backgroundThrottling: true,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });

  if (applicationIcon && process.platform === 'win32') window.setIcon(applicationIcon);

  mainWindow = window;
  createTray();
  window.once('ready-to-show', () => {
    if (!startHidden) window.show();
  });
  window.on('close', (event) => {
    if (isQuitting) return;
    event.preventDefault();
    window.hide();
    if (!hasShownTrayHint && appSettings.notifications_enabled && Notification.isSupported()) {
      hasShownTrayHint = true;
      new Notification({
        title: 'Neutron arka planda çalışıyor',
        body: 'Koruma devam ediyor. Neutron’u sistem tepsisi simgesinden yeniden açabilirsiniz.',
        icon: neutronImage(64),
        silent: true,
      }).show();
    }
  });
  // Registered before the await below: closing the window while the page is
  // still loading used to skip this entirely, leaving mainWindow pointing at a
  // destroyed BrowserWindow.
  window.once('closed', () => {
    if (mainWindow === window) mainWindow = null;
  });

  await readAppSettings();

  // Watchers must not start until the renderer is listening. They emit their
  // readiness events immediately ('watch-ready', 'service-connected'), and
  // anything sent before loadFile() resolves lands on a webContents with no
  // listeners and is dropped -- leaving modules stuck on "Başlatılıyor" in the
  // UI even though the process behind them was running fine.
  await window.loadFile(path.join(__dirname, 'neutron-ui.html'));

  // Runs before the watchers: if the licence has lapsed this stops them being
  // started at all and opens the activation window, rather than starting
  // protection and tearing it down again a moment later.
  enforceLicenseState({ forceWindow: true });
  startLicenseWatchdog();

  startEnabledWatchers();
  startUpdateChecks();
  startScheduledScanTimer();
  startAutomaticSignatureUpdateTimer();
}

Menu.setApplicationMenu(null);

ipcMain.on('window:minimize', (event) => {
  BrowserWindow.fromWebContents(event.sender)?.minimize();
});

ipcMain.on('window:toggle-maximize', (event) => {
  const window = BrowserWindow.fromWebContents(event.sender);
  if (!window) return;
  window.isMaximized() ? window.unmaximize() : window.maximize();
});

ipcMain.on('window:close', (event) => {
  BrowserWindow.fromWebContents(event.sender)?.close();
});

ipcMain.on('activation:close', (event) => {
  BrowserWindow.fromWebContents(event.sender)?.close();
});

ipcMain.handle('license:status', () => licenseStatus());
ipcMain.handle('license:activate', (_event, key) => {
  const result = saveLicense(key);
  if (result.ok) {
    // enforceLicenseState does the whole recovery -- restart the watchers,
    // refresh the tray and close the activation window -- so the success path
    // is the same one the watchdog takes. Duplicating it here is how the two
    // drift apart.
    invalidateLicenseStatusCache();
    licenseWasActive = false;
    enforceLicenseState();
  }
  return result;
});
ipcMain.handle('license:deactivate', () => removeStoredLicense());
ipcMain.handle('license:reveal', () => revealStoredLicense());

ipcMain.handle('scan:start', (event) => startScan(event.sender));
ipcMain.handle('scan:cancel', () => cancelScan());
ipcMain.handle('scan:drives', () => {
  const licenseError = requireLicense(); if (licenseError) return licenseError;
  const drives = [];
  if (process.platform === 'win32') {
    for (let code = 67; code <= 90; code += 1) {
      const root = `${String.fromCharCode(code)}:\\`;
      if (existsSync(root)) drives.push({ path: root, label: `Yerel Disk (${root.slice(0, 2)})` });
    }
  } else {
    drives.push({ path: '/', label: 'Sistem diski (/)' });
  }
  return { ok: true, drives };
});
ipcMain.handle('scan:full', (event, targetPath) => {
  const allowed = process.platform === 'win32'
    ? /^[A-Z]:\\$/i.test(String(targetPath || ''))
    : targetPath === '/';
  if (!allowed || !existsSync(targetPath)) return { ok: false, message: 'Seçilen sürücü kullanılamıyor.' };
  return startScan(event.sender, { targetPath, fullScan: true });
});
ipcMain.handle('scan:choose-folder', async (event) => {
  if (activeScan) return { ok: false, message: 'Zaten çalışan bir tarama var.' };
  const window = BrowserWindow.fromWebContents(event.sender);
  const selection = await dialog.showOpenDialog(window, {
    title: 'Taranacak klasörü seç',
    buttonLabel: 'Bu klasörü tara',
    properties: ['openDirectory'],
  });
  if (selection.canceled || !selection.filePaths[0]) return { ok: false, cancelled: true };
  return startScan(event.sender, { targetPath: selection.filePaths[0] });
});
ipcMain.handle('scan:choose-custom', async (event) => {
  if (activeScan) return { ok: false, message: 'Zaten çalışan bir tarama var.' };
  const window = BrowserWindow.fromWebContents(event.sender);
  const choice = await dialog.showMessageBox(window, {
    type: 'question',
    title: 'Özel tarama',
    message: 'Ne taramak istiyorsunuz?',
    detail: 'Tek bir dosya veya bir klasör seçebilirsiniz.',
    buttons: ['Dosya seç', 'Klasör seç', 'İptal'],
    defaultId: 0,
    cancelId: 2,
    noLink: true,
  });
  if (choice.response === 2) return { ok: false, cancelled: true };
  const chooseFile = choice.response === 0;
  const selection = await dialog.showOpenDialog(window, {
    title: chooseFile ? 'Taranacak dosyayı seç' : 'Taranacak klasörü seç',
    buttonLabel: 'Seçileni tara',
    properties: [chooseFile ? 'openFile' : 'openDirectory'],
    filters: chooseFile ? [
      { name: 'Tüm dosyalar', extensions: ['*'] },
    ] : undefined,
  });
  if (selection.canceled || !selection.filePaths[0]) return { ok: false, cancelled: true };
  return startScan(event.sender, { targetPath: selection.filePaths[0] });
});
ipcMain.handle('scan:history', () => readScanHistory());
ipcMain.handle('protection:start', async () => {
  const result = await updateApplicationSetting('protection_enabled', true);
  return result.ok ? protectionStatus() : result;
});
ipcMain.handle('protection:stop', async () => {
  if (!confirmProtectionOff()) return { ok: false, code: 'CONFIRMATION_CANCELLED', message: 'İşlem iptal edildi.' };
  const result = await updateApplicationSetting('protection_enabled', false);
  return result.ok ? protectionStatus() : result;
});
ipcMain.handle('protection:status', () => requireLicense() || protectionStatus());
ipcMain.handle('protection:amsi-register', async () => {
  const licenseError = requireLicense();
  if (licenseError) return licenseError;
  const result = await registerAmsiProviderVerified();
  if (!result.ok) return result;
  return updateApplicationSetting('amsi_protection_enabled', true);
});
// The privileged step runs first and the setting is only persisted once it
// actually succeeded. Writing the setting up front meant a declined UAC
// prompt left the setting off while the component stayed installed: the
// toggle then reported a state the machine did not have, and pressing it
// again did nothing visible.
ipcMain.handle('protection:amsi-unregister', async () => {
  const result = await runElevatedRegsvr32(amsiDllPath(), true);
  if (!result.ok) return result;
  return updateApplicationSetting('amsi_protection_enabled', false);
});
ipcMain.handle('protection:watchdog-register', async () => {
  const licenseError = requireLicense();
  if (licenseError) return licenseError;
  const result = await registerWatchdogTask();
  if (!result.ok) return result;
  return updateApplicationSetting('watchdog_protection_enabled', true);
});
ipcMain.handle('protection:watchdog-unregister', async () => {
  const result = await unregisterWatchdogTask();
  if (!result.ok) return result;
  return updateApplicationSetting('watchdog_protection_enabled', false);
});
ipcMain.handle('protection:wsc-register', async () => {
  const licenseError = requireLicense();
  if (licenseError) return licenseError;
  const result = await registerWscProvider();
  if (!result.ok) return result;
  return updateApplicationSetting('wsc_registration_enabled', true);
});
ipcMain.handle('protection:wsc-unregister', async () => {
  const result = await unregisterWscProvider();
  if (!result.ok) return result;
  return updateApplicationSetting('wsc_registration_enabled', false);
});
ipcMain.handle('protection:service-install', async () => {
  const licenseError = requireLicense();
  if (licenseError) return licenseError;
  const result = await installProtectionService();
  if (!result.ok) return result;
  const settingResult = await updateApplicationSetting('service_mode_enabled', true);
  if (settingResult.ok) connectServicePipe();
  return settingResult;
});
ipcMain.handle('protection:service-uninstall', async () => {
  await updateApplicationSetting('service_mode_enabled', false);
  disconnectServicePipe();
  return await uninstallProtectionService();
});
ipcMain.handle('protection:service-status', () => ({
  ok: true,
  connected: serviceConnected,
  configured: Boolean(appSettings.service_mode_enabled),
}));
ipcMain.handle('app:get-version', () => ({ ok: true, version: app.getVersion(), packaged: app.isPackaged }));
ipcMain.handle('app:check-for-update', () => {
  if (!app.isPackaged || process.platform !== 'win32') {
    return { ok: false, message: 'Güncelleme denetimi yalnızca kurulu (paketlenmiş) sürümde çalışır.' };
  }
  checkForAppUpdate();
  return { ok: true, latestUpdateInfo };
});
ipcMain.handle('app:prepare-uninstall', async () => {
  return await cleanupPrivilegedComponentsOnUninstall();
});
ipcMain.handle('web:check-url', (_event, url) => requireLicense() || runEngineAction(['--check-url', String(url || '')], 'url-reputation'));
ipcMain.handle('web:open-url', async (_event, url) => {
  const result = await runEngineAction(['--check-url', String(url || '')], 'url-reputation');
  if (!result.ok || !result.safe) return result;
  await shell.openExternal(result.url);
  return { ...result, opened: true };
});
ipcMain.handle('protection:history', () => runEngineAction(['--protection-history', '--limit', '20'], 'protection-history'));
ipcMain.handle('protection:action', async (_event, itemId, action) => {
  if (!Number.isInteger(itemId) || itemId < 1 || !['remediate', 'quarantine', 'trust', 'trust-publisher', 'ignore'].includes(action)) {
    return { ok: false, message: 'Geçersiz tehdit işlemi.' };
  }
  if (action === 'remediate') {
    const restartProtection = Boolean(protectionWatcher);
    if (restartProtection) stopProtectionWatcher({ silent: true });
    try {
      const result = await runEngineAction(['--incident-remediate', String(itemId)], 'incident-remediated');
      if (!result.ok) return result;
      const ruleName = `Neutron-Incident-${result.incident_id}-Outbound`;
      const firewall = await runElevatedPowerShell(
        firewallAddCommand(ruleName, result.target_path, 'block', 'out'),
      );
      if (!firewall.ok) {
        return {
          ...result,
          partial: true,
          message: `Dosya ve süreç müdahalesi tamamlandı; ağ engelleme uygulanamadı: ${firewall.message}`,
        };
      }
      const recorded = await runEngineAction(
        ['--incident-record-firewall', String(result.incident_id), '--value-json', JSON.stringify({ rule_name: ruleName, target_path: result.target_path })],
        'incident-firewall-recorded',
      );
      return { ...result, firewall: recorded.ok, rule_name: ruleName };
    } finally {
      if (restartProtection && !protectionWatcher) startProtectionWatcher();
    }
  }
  const restartProtection = ['trust', 'trust-publisher'].includes(action) && Boolean(protectionWatcher);
  if (restartProtection) stopProtectionWatcher({ silent: true });
  try {
    return await runEngineAction(
      ['--protection-action', String(itemId), '--disposition', action],
      'protection-action',
    );
  } finally {
    if (restartProtection && !protectionWatcher) startProtectionWatcher();
  }
});
ipcMain.handle('incident:rollback', async (_event, incidentId) => {
  if (!Number.isInteger(incidentId) || incidentId < 1) return { ok: false, message: 'Geçersiz müdahale kaydı.' };
  const status = await runEngineAction(['--incident-status', String(incidentId)], 'incident-status');
  if (!status.ok) return status;
  const firewallActions = (Array.isArray(status.actions) ? status.actions : []).filter(
    (entry) => entry.action_type === 'firewall-block' && entry.state === 'applied',
  );
  for (const action of firewallActions) {
    let detail = {};
    try { detail = JSON.parse(action.after_json || '{}'); } catch { detail = {}; }
    if (!detail.rule_name) continue;
    const removed = await runElevatedPowerShell(
      `try { Remove-NetFirewallRule -Name '${psQuoteSingle(detail.rule_name)}' -ErrorAction Stop } catch {}`,
    );
    if (!removed.ok) return removed;
    const finalized = await runEngineAction(
      ['--incident-finalize-external-rollback', String(action.id)],
      'incident-external-rollback-finalized',
    );
    if (!finalized.ok) return finalized;
  }
  return runEngineAction(['--incident-rollback', String(incidentId)], 'incident-rolled-back');
});
ipcMain.handle('signature:status', () => runEngineAction(['--signature-status'], 'signature-status'));
ipcMain.handle('engine:status', async () => {
  const [engineVersion, yaraStatus, signatureStatus] = await Promise.all([
    runEngineAction(['--engine-version'], 'engine-version'),
    runEngineAction(['--yara-status'], 'yara-status'),
    runEngineAction(['--signature-status'], 'signature-status'),
  ]);
  return {
    ok: Boolean(engineVersion.ok),
    version: engineVersion.version || null,
    frozen: Boolean(engineVersion.frozen),
    yara: yaraStatus,
    proton: signatureStatus,
    protection: protectionStatus(),
  };
});
ipcMain.handle('yara:status', () => runEngineAction(['--yara-status'], 'yara-status'));
ipcMain.handle('cache:status', () => runEngineAction(['--cache-status'], 'cache-status'));
ipcMain.handle('cache:clear', async () => {
  if (activeScan) {
    return { ok: false, message: 'Tarama sürerken önbellek temizlenemez.' };
  }
  const restartProtection = Boolean(protectionWatcher);
  if (restartProtection) stopProtectionWatcher({ silent: true });
  try {
    return await runEngineAction(['--cache-clear'], 'cache-cleared');
  } finally {
    if (restartProtection && !protectionWatcher) startProtectionWatcher();
  }
});
ipcMain.handle('signature:update', () => performProtonUpdate());
ipcMain.handle('signature:rollback', (_event, version) => rollbackProtonUpdate(version));
ipcMain.handle('feature:status', () => createFeatureUpdater().status());
ipcMain.handle('feature:update', () => performFeatureUpdate());
ipcMain.handle('settings:get', () => readAppSettings());
ipcMain.handle('settings:update', (_event, key, value) => updateApplicationSetting(key, value));
ipcMain.handle('settings:choose-watch-folder', async (event) => {
  const window = BrowserWindow.fromWebContents(event.sender);
  const selection = await dialog.showOpenDialog(window, {
    title: 'İzlenecek klasörü seç',
    buttonLabel: 'Klasörü ekle',
    properties: ['openDirectory'],
  });
  if (selection.canceled || !selection.filePaths[0]) return { ok: false, cancelled: true };
  return { ok: true, path: selection.filePaths[0] };
});
ipcMain.handle('exclusions:list', () => runEngineAction(['--exclusions'], 'exclusions'));
ipcMain.handle('exclusions:add-folder', async (event) => {
  const window = BrowserWindow.fromWebContents(event.sender);
  const selection = await dialog.showOpenDialog(window, {
    title: 'İstisna bırakılacak klasörü seç',
    buttonLabel: 'İstisna olarak ekle',
    properties: ['openDirectory'],
  });
  if (selection.canceled || !selection.filePaths[0]) return { ok: false, cancelled: true };
  return runExclusionMutation(['--exclusion-add-folder', selection.filePaths[0]]);
});
ipcMain.handle('exclusions:add-extension', (_event, extension) => {
  if (typeof extension !== 'string' || extension.length > 18) {
    return { ok: false, message: 'Geçersiz dosya uzantısı.' };
  }
  return runExclusionMutation(['--exclusion-add-extension', extension]);
});
ipcMain.handle('exclusions:trust-hash', (_event, sha256, label) => {
  if (typeof sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(sha256)) {
    return { ok: false, message: 'Dosyanın geçerli bir SHA-256 özeti yok.' };
  }
  const safeLabel = typeof label === 'string' ? label.slice(0, 260) : '';
  return runExclusionMutation(['--exclusion-add-hash', sha256, '--label', safeLabel]);
});
ipcMain.handle('exclusions:remove', (_event, itemId) => {
  if (!Number.isInteger(itemId) || itemId < 1) {
    return { ok: false, message: 'Geçersiz istisna kaydı.' };
  }
  return runExclusionMutation(['--exclusion-remove', String(itemId)]);
});
ipcMain.handle('quarantine:list', () => runEngineAction(['--quarantine-list'], 'quarantine-list'));
ipcMain.handle('quarantine:add', (_event, finding) => {
  if (!finding || typeof finding.path !== 'string' || typeof finding.reason !== 'string') {
    return { ok: false, message: 'Geçersiz tarama bulgusu.' };
  }
  return runEngineAction(['--quarantine', finding.path, '--reason', finding.reason], 'quarantined');
});
ipcMain.handle('quarantine:restore', (_event, itemId) => {
  if (!Number.isInteger(itemId) || itemId < 1) return { ok: false, message: 'Geçersiz karantina kaydı.' };
  return runEngineAction(['--restore', String(itemId)], 'restored');
});
ipcMain.handle('quarantine:delete', (_event, itemId) => {
  if (!Number.isInteger(itemId) || itemId < 1) return { ok: false, message: 'Geçersiz karantina kaydı.' };
  return runEngineAction(['--delete-quarantine', String(itemId)], 'deleted');
});

ipcMain.handle('firewall:list', () => runEngineAction(['--firewall-list'], 'firewall-rules'));
ipcMain.handle('firewall:recent-apps', () => runEngineAction(['--firewall-recent-apps'], 'firewall-recent-apps'));
ipcMain.handle('firewall:choose-app', async (event) => {
  const window = BrowserWindow.fromWebContents(event.sender);
  const selection = await dialog.showOpenDialog(window, {
    title: 'Kural eklenecek uygulamayı seç',
    buttonLabel: 'Uygulamayı ekle',
    properties: ['openFile'],
    filters: [{ name: 'Uygulamalar', extensions: ['exe'] }],
  });
  if (selection.canceled || !selection.filePaths[0]) return { ok: false, cancelled: true };
  return { ok: true, path: selection.filePaths[0] };
});
ipcMain.handle('firewall:add-rule', async (_event, programPath, action, direction) => {
  if (typeof programPath !== 'string' || !programPath.trim()) {
    return { ok: false, message: 'Geçersiz uygulama yolu.' };
  }
  const safeAction = action === 'allow' ? 'allow' : 'block';
  const safeDirection = direction === 'in' ? 'in' : 'out';
  const dbResult = await runEngineAction(
    ['--firewall-add-rule', programPath, '--firewall-action', safeAction, '--firewall-direction', safeDirection],
    'firewall-rule-added',
  );
  if (!dbResult.ok) return dbResult;
  const elevated = await runElevatedPowerShell(
    firewallAddCommand(dbResult.rule_name, dbResult.program_path, safeAction, safeDirection),
  );
  if (!elevated.ok) {
    // Windows Firewall'a hiç eklenemediyse Neutron'un kendi listesinde de
    // görünmemeli -- gerçekte var olmayan bir kural gösterilmesin.
    await runEngineAction(['--firewall-remove-rule', String(dbResult.id)], 'firewall-rule-removed');
    return elevated;
  }
  return dbResult;
});
ipcMain.handle('firewall:remove-rule', async (_event, ruleId, ruleName) => {
  if (!Number.isInteger(ruleId) || ruleId < 1 || typeof ruleName !== 'string' || !ruleName.trim()) {
    return { ok: false, message: 'Geçersiz güvenlik duvarı kaydı.' };
  }
  const elevated = await runElevatedPowerShell(firewallRemoveCommand(ruleName));
  if (!elevated.ok) return elevated;
  return runEngineAction(['--firewall-remove-rule', String(ruleId)], 'firewall-rule-removed');
});
ipcMain.handle('firewall:toggle-rule', async (_event, ruleId, ruleName, enabled) => {
  if (!Number.isInteger(ruleId) || ruleId < 1 || typeof ruleName !== 'string' || !ruleName.trim()) {
    return { ok: false, message: 'Geçersiz güvenlik duvarı kaydı.' };
  }
  const nextEnabled = Boolean(enabled);
  const elevated = await runElevatedPowerShell(firewallSetEnabledCommand(ruleName, nextEnabled));
  if (!elevated.ok) return elevated;
  return runEngineAction(
    ['--firewall-toggle-rule', String(ruleId), '--value-json', JSON.stringify(nextEnabled)],
    'firewall-rule-toggled',
  );
});

ipcMain.handle('startup:list', () => runEngineAction(['--startup-list'], 'startup-items'));
ipcMain.handle('startup:disable', async (_event, item) => {
  if (
    !item || typeof item.source !== 'string' || typeof item.key_path !== 'string' ||
    typeof item.value_name !== 'string' || typeof item.command !== 'string'
  ) {
    return { ok: false, message: 'Geçersiz başlangıç öğesi.' };
  }
  const payload = {
    source: item.source, hive: item.hive || null, key_path: item.key_path,
    view: Number.isInteger(item.view) ? item.view : 0, value_name: item.value_name, command: item.command,
  };
  const dbResult = await runEngineAction(
    ['--startup-disable', '--value-json', JSON.stringify(payload)], 'startup-item-disabled',
  );
  if (!dbResult.ok || !dbResult.needs_elevation) return dbResult;
  const command = dbResult.source === 'registry'
    ? startupRegistryDeleteCommand(dbResult.hive, dbResult.key_path, dbResult.value_name)
    : startupMoveCommand(dbResult.original_path, dbResult.stored_path);
  const elevated = await runElevatedPowerShell(command);
  if (!elevated.ok) {
    await runEngineAction(['--startup-cancel-disable', String(dbResult.id)], 'startup-item-cancelled');
    return elevated;
  }
  return runEngineAction(['--startup-finalize-disable', String(dbResult.id)], 'startup-item-finalized');
});
ipcMain.handle('startup:restore', async (_event, itemId) => {
  if (!Number.isInteger(itemId) || itemId < 1) return { ok: false, message: 'Geçersiz başlangıç kaydı.' };
  const result = await runEngineAction(['--startup-restore', String(itemId)], 'startup-item-restored');
  if (!result.ok || !result.needs_elevation) return result;
  const command = result.source === 'registry'
    ? startupRegistrySetCommand(result.hive, result.key_path, result.value_name, result.original_path)
    : startupMoveCommand(result.stored_path, result.original_path);
  const elevated = await runElevatedPowerShell(command);
  if (!elevated.ok) return elevated;
  return runEngineAction(['--startup-finalize-restore', String(itemId)], 'startup-item-finalized');
});
ipcMain.handle('vulnerability:scan', () => runEngineAction(['--check-vulnerable-software'], 'vulnerable-software'));
ipcMain.handle('system:audit', () => runEngineAction(['--system-audit'], 'system-audit'));
ipcMain.handle('system:audit-fix-info', () => Object.fromEntries(
  Object.entries(AUDIT_FIXES).map(([id, fix]) => [id, {
    label: fix.label,
    confirm: fix.confirm,
    restart: Boolean(fix.restart),
    note: fix.note || '',
  }])
));
ipcMain.handle('system:audit-fix', (event, fixId) => applyAuditFix(String(fixId || '')));
ipcMain.handle('ml:shadow-report', () => runEngineAction(['--ml-shadow-report'], 'ml-shadow-report'));
ipcMain.handle('performance:temp-usage', () => runEngineAction(['--temp-usage'], 'temp-usage'));
ipcMain.handle('performance:temp-clean', () => runEngineAction(['--temp-clean'], 'temp-cleaned'));
ipcMain.handle('performance:memory-status', () => runEngineAction(['--memory-status'], 'memory-status'));
ipcMain.handle('performance:memory-trim', () => runEngineAction(['--memory-trim'], 'memory-trimmed'));

async function installLocalProtonArchiveForService() {
  const flagIndex = process.argv.indexOf('--install-proton-archive');
  const packagePath = process.argv[flagIndex + 1];
  const signaturePath = process.argv[flagIndex + 2];
  const expectedVersion = process.argv[flagIndex + 3];
  if (!packagePath || !signaturePath || !expectedVersion) {
    return { ok: false, message: 'Proton bakım argümanları eksik.' };
  }
  const updater = createProtonUpdater();
  const verified = updater.verifyLocalArchive(packagePath, signaturePath, expectedVersion);
  return runEngineAction(
    ['--install-proton-stdin'], 'signature-updated', { stdin: JSON.stringify(verified.payload) },
  );
}

function activateSetupLicenseFile() {
  const flagIndex = process.argv.indexOf('--activate-license-file');
  const sourcePath = process.argv[flagIndex + 1];
  if (!sourcePath || !existsSync(sourcePath)) {
    return { ok: false, message: 'Kurulum lisans dosyası bulunamadı.' };
  }
  try {
    const key = readFileSync(sourcePath, 'utf8').trim();
    return saveLicense(key, { machineWide: true });
  } catch (error) {
    return { ok: false, message: error.message };
  }
}

if (isInstallProtonArchiveMode) {
  app.whenReady().then(async () => {
    const result = await installLocalProtonArchiveForService();
    process.stdout.write(`${JSON.stringify({ type: 'service-proton-maintenance', ...result })}\n`);
    app.exit(result.ok ? 0 : 1);
  }).catch((error) => {
    console.error('Neutron Proton service maintenance failed:', error);
    app.exit(1);
  });
} else if (isActivateLicenseFileMode) {
  app.whenReady().then(() => {
    const result = activateSetupLicenseFile();
    process.stdout.write(`${JSON.stringify({ type: 'setup-license-activated', ...result })}\n`);
    app.exit(result.ok ? 0 : 1);
  }).catch((error) => {
    console.error('Neutron setup license activation failed:', error);
    app.exit(1);
  });
} else if (isProvisionSecurityMode) {
  app.whenReady().then(async () => {
    const result = await provisionDefaultSecurityComponents();
    process.stdout.write(`${JSON.stringify({ type: 'security-provisioned', ...result })}\n`);
    app.exit(result.ok ? 0 : 1);
  }).catch((error) => {
    console.error('Neutron security provisioning failed:', error);
    app.exit(1);
  });
} else if (isPrepareUninstallMode) {
  app.whenReady().then(async () => {
    const result = await cleanupPrivilegedComponentsOnUninstall({ elevated: false });
    app.exit(result.ok ? 0 : 1);
  }).catch((error) => {
    console.error('Neutron uninstall cleanup failed:', error);
    app.exit(1);
  });
} else {
  app.whenReady().then(createWindow).catch((error) => {
    console.error('Neutron startup failed:', error);
  });
}

app.on('window-all-closed', () => {
  // The tray owns the background lifecycle; explicit Exit is required.
});

app.on('activate', () => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    showMainWindow();
  } else {
    createWindow();
  }
});

// Windows tells the app the session is ending before it starts killing
// processes. Without this, shutdown reached the watchers as a hard terminate
// and the window 'close' handler below still tried to keep the app alive,
// which is what puts Windows on the "this app is preventing shutdown" screen.
app.on('session-end', () => {
  isQuitting = true;
  app.quit();
});

app.on('before-quit', () => {
  isQuitting = true;
  activeScan?.child.kill();
  activeScan = null;

  // This used to name only three watchers explicitly, so amsiService,
  // networkWatcher, memoryWatcher, usbWatcher and ransomwareWatcher survived
  // the app: five orphaned engine processes still holding the data directory,
  // which is exactly what makes an uninstall fail with locked files. Reading
  // the list from one place means a new watcher cannot be forgotten again.
  const watchers = [
    protectionWatcher, behaviorWatcher, webWatcher, amsiService,
    networkWatcher, memoryWatcher, usbWatcher, ransomwareWatcher,
  ];
  for (const watcher of watchers) {
    if (!watcher) continue;
    watcher.stopping = true;
    try {
      watcher.child.kill();
    } catch { /* already gone */ }
  }
  protectionWatcher = null;
  behaviorWatcher = null;
  webWatcher = null;
  amsiService = null;
  networkWatcher = null;
  memoryWatcher = null;
  usbWatcher = null;
  ransomwareWatcher = null;

  for (const timer of [updateCheckTimer, scheduledScanTimer, signatureUpdateTimer, licenseCheckTimer]) {
    if (timer) clearInterval(timer);
  }
  updateCheckTimer = null;
  scheduledScanTimer = null;
  signatureUpdateTimer = null;
  licenseCheckTimer = null;

  if (serviceSocket) {
    try {
      serviceSocket.destroy();
    } catch { /* already closed */ }
    serviceSocket = null;
  }
  if (serviceReconnectTimer) {
    clearTimeout(serviceReconnectTimer);
    serviceReconnectTimer = null;
  }

  tray?.destroy();
  tray = null;
});
