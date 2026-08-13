const { app, autoUpdater, BrowserWindow, dialog, ipcMain, Menu, nativeImage, Notification, shell, Tray } = require('electron');
const { spawn, spawnSync } = require('child_process');
const net = require('net');
const { existsSync, readFileSync, writeFileSync, mkdirSync } = require('fs');
const path = require('path');
const { ProtonUpdater } = require('./proton-updater.cjs');
const { deviceHash, parseLicense } = require('./license.cjs');

const WINDOWS_APP_USER_MODEL_ID = 'com.neutron.security.Neutron';
const NEUTRON_LOGO_PATH = path.join(__dirname, '..', 'assets', 'neutron-logo.png');
const NEUTRON_ICON_PATH = path.join(__dirname, '..', 'assets', 'neutron.ico');

app.setName('Neutron');
if (process.platform === 'win32') app.setAppUserModelId(WINDOWS_APP_USER_MODEL_ID);

if (process.platform === 'win32' && process.argv.includes('--squirrel-uninstall')) {
  // Best-effort; cleanupPrivilegedComponentsOnUninstall and the functions
  // it calls are hoisted function declarations, safe to call here even
  // though they're defined further down the file.
  cleanupPrivilegedComponentsOnUninstall();
}

if (require('electron-squirrel-startup')) {
  app.quit();
}

const hasSingleInstanceLock = app.requestSingleInstanceLock();
if (!hasSingleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => showMainWindow());
}

let activeScan = null;
let protectionWatcher = null;
let behaviorWatcher = null;
let webWatcher = null;
let amsiService = null;
let networkWatcher = null;
let memoryWatcher = null;
let usbWatcher = null;
let mainWindow = null;
let tray = null;
let isQuitting = false;
let hasShownTrayHint = false;
let protonUpdatePromise = null;
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
  notifications_enabled: true,
  watch_paths: [],
  scan_max_files: 1500,
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

function showMainWindow() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

function licensePath() {
  return path.join(app.getPath('userData'), 'license', 'activation.key');
}

function licenseStatus() {
  try {
    const stored = readFileSync(licensePath(), 'utf8').trim();
    activeLicense = parseLicense(stored);
    return { ok: true, active: true, license: activeLicense };
  } catch (error) {
    activeLicense = null;
    return { ok: true, active: false, deviceHash: deviceHash(), message: error.message };
  }
}

function requireLicense() {
  const status = licenseStatus();
  return status.active ? null : { ok: false, code: 'LICENSE_REQUIRED', message: 'Neutron etkinleştirilmedi.' };
}

function saveLicense(key) {
  try {
    const license = parseLicense(String(key || ''));
    const target = licensePath();
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    writeFileSync(target, `${String(key).trim()}\n`, { encoding: 'utf8', mode: 0o600 });
    activeLicense = license;
    return { ok: true, active: true, license };
  } catch (error) {
    return { ok: false, active: false, deviceHash: deviceHash(), message: error.message };
  }
}

function removeStoredLicense() {
  try {
    const target = licensePath();
    if (existsSync(target)) require('fs').rmSync(target, { force: true });
    activeLicense = null;
    return { ok: true, active: false, deviceHash: deviceHash() };
  } catch (error) {
    return { ok: false, message: error.message };
  }
}

function revealStoredLicense() {
  const status = licenseStatus();
  if (!status.active) return { ok: false, message: 'Gösterilecek etkin lisans yok.' };
  return { ok: true, key: readFileSync(licensePath(), 'utf8').trim() };
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

// AMSI provider registration writes machine-wide HKEY_LOCAL_MACHINE keys
// (see tools/amsi/Dll.cpp DllRegisterServer), which requires admin rights
// that a per-user Squirrel install does not have. We ask for elevation
// per-action via a UAC consent prompt rather than bundling an elevated
// installer step, so registration only happens when the user explicitly
// opts in to script protection.
function runElevatedRegsvr32(dllPath, unregister) {
  if (!existsSync(dllPath)) {
    return {
      ok: false,
      message: 'AMSI sağlayıcı DLL bulunamadı. Önce "npm run amsi:build" ile derlenmeli.',
    };
  }
  const regsvr32Args = unregister ? ['/s', '/u', dllPath] : ['/s', dllPath];
  const quotedArgs = regsvr32Args
    .map((value) => `'${String(value).replace(/'/g, "''")}'`)
    .join(',');
  const psCommand =
    `try { ` +
    `$p = Start-Process -FilePath 'regsvr32.exe' -ArgumentList ${quotedArgs} -Verb RunAs -Wait -PassThru -WindowStyle Hidden; ` +
    `exit $p.ExitCode ` +
    `} catch { exit 1223 }`;
  const result = spawnSync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', psCommand],
    { windowsHide: true },
  );
  if (result.error) return { ok: false, message: result.error.message };
  if (result.status === 1223) {
    return { ok: false, code: 'ELEVATION_CANCELLED', message: 'Yönetici izni verilmedi.' };
  }
  if (result.status !== 0) {
    return { ok: false, message: `Kayıt işlemi başarısız oldu (kod ${result.status}).` };
  }
  return { ok: true };
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

function runElevatedPowerShell(psCommand) {
  const encoded = Buffer.from(psCommand, 'utf16le').toString('base64');
  const outerCommand =
    `try { ` +
    `$p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','${encoded}') -Verb RunAs -Wait -PassThru -WindowStyle Hidden; ` +
    `exit $p.ExitCode ` +
    `} catch { exit 1223 }`;
  const result = spawnSync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', outerCommand],
    { windowsHide: true },
  );
  if (result.error) return { ok: false, message: result.error.message };
  if (result.status === 1223) {
    return { ok: false, code: 'ELEVATION_CANCELLED', message: 'Yönetici izni verilmedi.' };
  }
  if (result.status !== 0) {
    return { ok: false, message: `İşlem başarısız oldu (kod ${result.status}).` };
  }
  return { ok: true };
}

function registerWatchdogTask() {
  const { exe, args } = watchdogExecPath();
  const quotedTarget = [exe, ...args].map((value) => `"${String(value).replace(/"/g, '\\"')}"`).join(' ');
  const psCommand =
    `schtasks /create /tn '${WATCHDOG_TASK_NAME}' /tr '${quotedTarget.replace(/'/g, "''")}' ` +
    `/sc minute /mo 2 /rl highest /f`;
  return runElevatedPowerShell(psCommand);
}

function unregisterWatchdogTask() {
  return runElevatedPowerShell(`schtasks /delete /tn '${WATCHDOG_TASK_NAME}' /f`);
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
  const exePath = process.execPath;
  const psCommand =
    `$existing = Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct ` +
    `-Filter "instanceGuid='${wscQuote(WSC_INSTANCE_GUID)}'" -ErrorAction SilentlyContinue; ` +
    `if ($existing) { $existing | Remove-CimInstance -ErrorAction SilentlyContinue }; ` +
    `New-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct -Property @{ ` +
    `displayName='Neutron Security'; instanceGuid='${wscQuote(WSC_INSTANCE_GUID)}'; ` +
    `pathToSignedProductExe='${wscQuote(exePath)}'; pathToSignedReportingExe='${wscQuote(exePath)}'; ` +
    `productState=397568 } | Out-Null`;
  return runElevatedPowerShell(psCommand);
}

function unregisterWscProvider() {
  const psCommand =
    `$existing = Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct ` +
    `-Filter "instanceGuid='${wscQuote(WSC_INSTANCE_GUID)}'" -ErrorAction SilentlyContinue; ` +
    `if ($existing) { $existing | Remove-CimInstance -ErrorAction SilentlyContinue }`;
  return runElevatedPowerShell(psCommand);
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

// One elevation prompt that installs the Windows Service AND folds in the
// AMSI + WSC registrations that otherwise each need their own UAC prompt
// (registerWscProvider/runElevatedRegsvr32 above still exist standalone
// for users who enable those features without service mode).
function installProtectionService() {
  const hostPath = serviceHostPath();
  if (!existsSync(hostPath)) {
    return { ok: false, message: 'Servis çalıştırıcı bulunamadı. Önce "npm run service:build" ile derlenmeli.' };
  }
  const dllPath = amsiDllPath();
  const oldDataDir = path.join(app.getPath('userData'), 'data').replace(/'/g, "''");
  const amsiLine = existsSync(dllPath)
    ? `try { regsvr32 /s '${dllPath.replace(/'/g, "''")}' } catch {}`
    : '';
  const wscLine =
    `try { $e = Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct ` +
    `-Filter "instanceGuid='${wscQuote(WSC_INSTANCE_GUID)}'" -ErrorAction SilentlyContinue; ` +
    `if ($e) { $e | Remove-CimInstance -ErrorAction SilentlyContinue }; ` +
    `New-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct -Property @{ ` +
    `displayName='Neutron Security'; instanceGuid='${wscQuote(WSC_INSTANCE_GUID)}'; ` +
    `pathToSignedProductExe='${wscQuote(process.execPath)}'; pathToSignedReportingExe='${wscQuote(process.execPath)}'; ` +
    `productState=397568 } | Out-Null } catch {}`;
  const psCommand = [
    `$dataDir = Join-Path $env:ProgramData 'Neutron\\data'`,
    `if ((Test-Path '${oldDataDir}') -and -not (Test-Path $dataDir)) { ` +
      `New-Item -ItemType Directory -Force -Path (Split-Path $dataDir) | Out-Null; ` +
      `Copy-Item -Path '${oldDataDir}' -Destination $dataDir -Recurse -Force }`,
    `if (Get-Service -Name '${SERVICE_NAME}' -ErrorAction SilentlyContinue) { sc.exe delete '${SERVICE_NAME}' | Out-Null }`,
    `sc.exe create '${SERVICE_NAME}' binPath= '"${hostPath}"' start= auto | Out-Null`,
    `sc.exe failure '${SERVICE_NAME}' reset= 86400 actions= restart/5000/restart/5000/restart/15000 | Out-Null`,
    `sc.exe start '${SERVICE_NAME}' | Out-Null`,
    amsiLine,
    wscLine,
  ].filter(Boolean).join('; ');
  return runElevatedPowerShell(psCommand);
}

function uninstallProtectionService() {
  return runElevatedPowerShell(
    `try { sc.exe stop '${SERVICE_NAME}' | Out-Null } catch {}; ` +
    `try { sc.exe delete '${SERVICE_NAME}' | Out-Null } catch {}`,
  );
}

let serviceSocket = null;
let serviceConnected = false;
let serviceReconnectTimer = null;

function handleServiceEvent(event) {
  if (!event || typeof event.type !== 'string') return;
  sendProtectionEvent(event);
  if (event.settings) appSettings = { ...appSettings, ...event.settings };
  if (['watch-finding', 'behavior-finding', 'network-finding', 'amsi-finding'].includes(event.type)) {
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

// --- App auto-update (GitHub Releases, no server) -------------------------
// Squirrel.Windows (already the installer, see maker-squirrel above) drives
// this through Electron's built-in autoUpdater; it only needs a feed URL
// to poll. GitHub Releases serves static files at predictable URLs
// (including a stable "latest" redirect), so that feed URL just points at
// a GitHub Release -- no custom update server, matching every other
// "someone else's server" decision made this session (cloud lookup,
// network indicators). Only meaningful in a packaged, Squirrel-installed
// build: autoUpdater errors out (or is simply unavailable) in dev.
const UPDATE_FEED_URL = 'https://github.com/omerbugrae/Neutron/releases/latest/download';
const UPDATE_CHECK_INTERVAL_MS = 4 * 60 * 60 * 1000;
let updateCheckTimer = null;
let updateReadyToInstall = false;

function confirmInstallUpdate() {
  const choice = dialog.showMessageBoxSync({
    type: 'info',
    buttons: ['Sonra', 'Şimdi yeniden başlat'],
    defaultId: 1,
    cancelId: 0,
    title: 'Güncelleme hazır',
    message: 'Yeni bir Neutron sürümü indirildi.',
    detail: 'Kurulumu tamamlamak için uygulamanın yeniden başlatılması gerekiyor.',
  });
  return choice === 1;
}

function checkForAppUpdate() {
  if (!app.isPackaged || process.platform !== 'win32') return;
  try {
    autoUpdater.setFeedURL({ url: UPDATE_FEED_URL });
    autoUpdater.checkForUpdates();
  } catch (error) {
    // Best-effort background feature: a network hiccup or missing release
    // must never interrupt the app, same "fail open" stance as AMSI/cloud
    // lookup elsewhere this session.
    console.error('Neutron güncelleme denetimi başarısız:', error.message);
  }
}

function startUpdateChecks() {
  if (!app.isPackaged || process.platform !== 'win32') return;
  autoUpdater.on('update-downloaded', () => {
    updateReadyToInstall = true;
    sendProtectionEvent({ type: 'update-ready' });
    if (confirmInstallUpdate()) autoUpdater.quitAndInstall();
  });
  autoUpdater.on('error', (error) => {
    console.error('Neutron autoUpdater hatası:', error?.message || error);
  });
  setTimeout(checkForAppUpdate, 30_000);
  updateCheckTimer = setInterval(checkForAppUpdate, UPDATE_CHECK_INTERVAL_MS);
}

// Runs at --squirrel-uninstall: removes the machine-wide bits that a plain
// file delete wouldn't touch (the AMSI COM/HKLM registration, the
// watchdog scheduled task, and the WSC WMI instance), in a single
// elevation prompt rather than three. Best-effort: none of these may have
// ever been registered if the user never opted into these settings, so
// failures here are swallowed.
function cleanupPrivilegedComponentsOnUninstall() {
  const dllPath = amsiDllPath();
  const amsiUnregisterLine = existsSync(dllPath)
    ? `try { regsvr32 /s /u '${dllPath.replace(/'/g, "''")}' } catch {}`
    : '';
  const wscUnregisterLine =
    `try { Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct ` +
    `-Filter "instanceGuid='${wscQuote(WSC_INSTANCE_GUID)}'" -ErrorAction SilentlyContinue | ` +
    `Remove-CimInstance -ErrorAction SilentlyContinue } catch {}`;
  const serviceUnregisterLine =
    `try { sc.exe stop '${SERVICE_NAME}' | Out-Null } catch {}; ` +
    `try { sc.exe delete '${SERVICE_NAME}' | Out-Null } catch {}`;
  const psCommand = [
    amsiUnregisterLine,
    `try { schtasks /delete /tn '${WATCHDOG_TASK_NAME}' /f } catch {}`,
    wscUnregisterLine,
    serviceUnregisterLine,
  ].filter(Boolean).join('; ');
  runElevatedPowerShell(psCommand);
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
  const developmentInternalPaths = app.isPackaged
    ? ''
    : ['src', 'tools', 'tests', 'runtime', 'build', 'venv', 'node_modules', 'data']
      .map((entry) => path.join(__dirname, '..', entry))
      .join(path.delimiter);
  return {
    ...process.env,
    // Geliştirmede proje verisi görünür kalır; kurulumda kullanıcıya ait yazılabilir alan kullanılır.
    NEUTRON_DATA_DIR: app.isPackaged
      ? path.join(app.getPath('userData'), 'data')
      : path.join(__dirname, '..', 'data'),
    NEUTRON_BUNDLED_DATA_DIR: path.join(__dirname, '..', 'data'),
    NEUTRON_INTERNAL_PATHS: developmentInternalPaths,
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
      env: engineEnvironment(), stdio: [hasInput ? 'pipe' : 'ignore', 'pipe', 'pipe'],
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

async function performProtonUpdate() {
  if (protonUpdatePromise) return protonUpdatePromise;
  protonUpdatePromise = (async () => {
    let restartProtection = false;
    try {
      const status = await runEngineAction(['--signature-status'], 'signature-status');
      if (!status.ok) throw new Error(status.message || 'Proton sürümü okunamadı.');
      const updater = createProtonUpdater();
      const check = await updater.check(status.version || '1.00.001');
      if (!check.available) {
        sendProtonUpdateEvent({ stage: 'current', version: check.latestVersion || status.version });
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
      try {
        updater.archiveVerifiedUpdate(downloaded);
      } catch {
        archiveWarning = 'Güncelleme tamamlandı ancak yerel yedek oluşturulamadı.';
      }
      sendProtonUpdateEvent({ stage: 'complete', version: downloaded.version });
      return { ...installed, updated: true, version: downloaded.version, archive_warning: archiveWarning };
    } catch (error) {
      console.error('Proton update failed:', error);
      const message = protonUpdateMessage(error);
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
      : ['--quick-scan']
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

  activeScan = { id: scanId, child, webContents };
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
    if (pendingOutput.trim()) {
      try {
        sendScanEvent(webContents, JSON.parse(pendingOutput));
      } catch {
        // Motor kapanırken yarım kalan satır kullanıcıya gösterilmez.
      }
    }

    if (code !== 0 && !engineReportedError && activeScan?.id === scanId) {
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

function protectionStatus() {
  return {
    ok: true,
    enabled: Boolean(protectionWatcher),
    ready: Boolean(protectionWatcher?.ready),
    behaviorEnabled: Boolean(behaviorWatcher),
    behaviorReady: Boolean(behaviorWatcher?.ready),
    behaviorConfigured: Boolean(appSettings.behavior_protection_enabled),
    webEnabled: Boolean(webWatcher),
    webReady: Boolean(webWatcher?.ready),
    webConfigured: Boolean(appSettings.web_protection_enabled),
    amsiEnabled: Boolean(amsiService),
    amsiReady: Boolean(amsiService?.ready),
    amsiConfigured: Boolean(appSettings.amsi_protection_enabled),
    watchdogConfigured: Boolean(appSettings.watchdog_protection_enabled),
    wscConfigured: Boolean(appSettings.wsc_registration_enabled),
    networkEnabled: Boolean(networkWatcher),
    networkReady: Boolean(networkWatcher?.ready),
    networkConfigured: Boolean(appSettings.network_protection_enabled),
    serviceConfigured: Boolean(appSettings.service_mode_enabled),
    serviceConnected: Boolean(serviceConnected),
    memoryEnabled: Boolean(memoryWatcher),
    memoryReady: Boolean(memoryWatcher?.ready),
    memoryConfigured: Boolean(appSettings.memory_scan_enabled),
    usbEnabled: Boolean(usbWatcher),
    usbReady: Boolean(usbWatcher?.ready),
    usbConfigured: Boolean(appSettings.usb_protection_enabled),
  };
}

function startWebWatcher() {
  if (requireLicense()) return;
  if (webWatcher) return protectionStatus();
  const engine = resolveEngine(['--watch-web']);
  const child = spawn(engine.command, engine.arguments, { cwd: engine.cwd, windowsHide: true, shell: false, env: engineEnvironment(), stdio: ['ignore', 'pipe', 'pipe'] });
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
        if (event.type === 'web-ready') watcher.ready = true;
        sendProtectionEvent(event);
        if (event.type === 'web-finding') showFindingNotification(event, 'Neutron zararlı indirme kaynağı algıladı');
      } catch { sendProtectionEvent({ type: 'web-error', message: 'Web korumasından geçersiz yanıt alındı.' }); }
    }
  });
  child.stderr.setEncoding('utf8'); child.stderr.on('data', (chunk) => { watcher.stderr = `${watcher.stderr}${chunk}`.slice(-2000); });
  child.once('close', (code) => {
    const current = webWatcher === watcher; if (current) webWatcher = null;
    if (current && !watcher.stopping && code !== 0) sendProtectionEvent({ type: 'web-error', message: watcher.stderr.trim() || 'Web koruması durdu.' });
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
  const engine = resolveEngine(['--watch-behavior']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['ignore', 'pipe', 'pipe'],
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
        if (event.type === 'behavior-ready') watcher.ready = true;
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
  const engine = resolveEngine(['--watch-network']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['ignore', 'pipe', 'pipe'],
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
        if (event.type === 'network-ready') watcher.ready = true;
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
  const engine = resolveEngine(['--watch-memory']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['ignore', 'pipe', 'pipe'],
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
        if (event.type === 'memory-ready') watcher.ready = true;
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
  const engine = resolveEngine(['--watch-usb']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['ignore', 'pipe', 'pipe'],
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
        if (event.type === 'usb-ready') watcher.ready = true;
        sendProtectionEvent(event);
        if (event.type === 'usb-finding') {
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

function startAmsiService() {
  if (requireLicense()) return;
  if (amsiService) return protectionStatus();
  const engine = resolveEngine(['--amsi-service']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['ignore', 'pipe', 'pipe'],
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

  const engine = resolveEngine(['--watch']);
  const child = spawn(engine.command, engine.arguments, {
    cwd: engine.cwd,
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['ignore', 'pipe', 'pipe'],
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
        if (event.type === 'watch-finding') showFindingNotification(event);
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
    'malwarebazaar_api_key',
    'virustotal_api_key',
    'network_protection_enabled',
    'service_mode_enabled',
    'memory_scan_enabled',
    'usb_protection_enabled',
    'notifications_enabled',
    'watch_paths',
    'scan_max_files',
  ]);
  if (!allowedKeys.has(key)) return { ok: false, message: 'Desteklenmeyen ayar.' };

  const result = await writeAppSetting(key, value);
  if (!result.ok) return result;

  if (key === 'start_with_windows') {
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
  } else if (key === 'usb_protection_enabled') {
    appSettings.usb_protection_enabled ? startUsbWatcher() : stopUsbWatcher();
  } else if ((key === 'watch_paths' || key === 'scan_max_files') && protectionWatcher) {
    stopProtectionWatcher({ silent: true });
    startProtectionWatcher();
  }
  return { ok: true, settings: appSettings };
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
  await readAppSettings();
  if (licenseStatus().active) {
    if (appSettings.service_mode_enabled) {
      connectServicePipe();
    } else {
      if (appSettings.protection_enabled) startProtectionWatcher();
      if (appSettings.behavior_protection_enabled) startBehaviorWatcher();
      if (appSettings.web_protection_enabled) startWebWatcher();
      if (appSettings.amsi_protection_enabled) startAmsiService();
      if (appSettings.network_protection_enabled) startNetworkWatcher();
      if (appSettings.memory_scan_enabled) startMemoryWatcher();
      if (appSettings.usb_protection_enabled) startUsbWatcher();
    }
  }
  startUpdateChecks();
  await window.loadFile(path.join(__dirname, 'neutron-ui.html'));
  window.once('closed', () => {
    if (mainWindow === window) mainWindow = null;
  });
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

ipcMain.handle('license:status', () => licenseStatus());
ipcMain.handle('license:activate', (_event, key) => {
  const result = saveLicense(key);
  if (result.ok) {
    if (appSettings.service_mode_enabled) {
      connectServicePipe();
    } else {
      if (appSettings.protection_enabled) startProtectionWatcher();
      if (appSettings.behavior_protection_enabled) startBehaviorWatcher();
      if (appSettings.web_protection_enabled) startWebWatcher();
      if (appSettings.amsi_protection_enabled) startAmsiService();
      if (appSettings.network_protection_enabled) startNetworkWatcher();
      if (appSettings.memory_scan_enabled) startMemoryWatcher();
      if (appSettings.usb_protection_enabled) startUsbWatcher();
    }
  }
  return result;
});
ipcMain.handle('license:deactivate', () => removeStoredLicense());
ipcMain.handle('license:reveal', () => revealStoredLicense());

ipcMain.handle('scan:start', (event) => startScan(event.sender));
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
  const result = runElevatedRegsvr32(amsiDllPath(), false);
  if (!result.ok) return result;
  return updateApplicationSetting('amsi_protection_enabled', true);
});
ipcMain.handle('protection:amsi-unregister', async () => {
  await updateApplicationSetting('amsi_protection_enabled', false);
  return runElevatedRegsvr32(amsiDllPath(), true);
});
ipcMain.handle('protection:watchdog-register', async () => {
  const licenseError = requireLicense();
  if (licenseError) return licenseError;
  const result = registerWatchdogTask();
  if (!result.ok) return result;
  return updateApplicationSetting('watchdog_protection_enabled', true);
});
ipcMain.handle('protection:watchdog-unregister', async () => {
  await updateApplicationSetting('watchdog_protection_enabled', false);
  return unregisterWatchdogTask();
});
ipcMain.handle('protection:wsc-register', async () => {
  const licenseError = requireLicense();
  if (licenseError) return licenseError;
  const result = registerWscProvider();
  if (!result.ok) return result;
  return updateApplicationSetting('wsc_registration_enabled', true);
});
ipcMain.handle('protection:wsc-unregister', async () => {
  await updateApplicationSetting('wsc_registration_enabled', false);
  return unregisterWscProvider();
});
ipcMain.handle('protection:service-install', async () => {
  const licenseError = requireLicense();
  if (licenseError) return licenseError;
  const result = installProtectionService();
  if (!result.ok) return result;
  const settingResult = await updateApplicationSetting('service_mode_enabled', true);
  if (settingResult.ok) connectServicePipe();
  return settingResult;
});
ipcMain.handle('protection:service-uninstall', async () => {
  await updateApplicationSetting('service_mode_enabled', false);
  disconnectServicePipe();
  return uninstallProtectionService();
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
  return { ok: true, updateReadyToInstall };
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
  if (!Number.isInteger(itemId) || itemId < 1 || !['quarantine', 'trust', 'ignore'].includes(action)) {
    return { ok: false, message: 'Geçersiz tehdit işlemi.' };
  }
  const restartProtection = action === 'trust' && Boolean(protectionWatcher);
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

app.whenReady().then(createWindow).catch((error) => {
  console.error('Neutron startup failed:', error);
});

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

app.on('before-quit', () => {
  isQuitting = true;
  activeScan?.child.kill();
  activeScan = null;
  if (protectionWatcher) {
    protectionWatcher.stopping = true;
    protectionWatcher.child.kill();
    protectionWatcher = null;
  }
  if (behaviorWatcher) {
    behaviorWatcher.stopping = true;
    behaviorWatcher.child.kill();
    behaviorWatcher = null;
  }
  if (webWatcher) {
    webWatcher.stopping = true;
    webWatcher.child.kill();
    webWatcher = null;
  }
  tray?.destroy();
  tray = null;
});
