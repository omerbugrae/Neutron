const { app, BrowserWindow, dialog, ipcMain, Menu, nativeImage, Notification, Tray } = require('electron');
const { spawn } = require('child_process');
const { existsSync } = require('fs');
const path = require('path');
const { ProtonUpdater } = require('./proton-updater.cjs');

const WINDOWS_APP_USER_MODEL_ID = app.isPackaged
  ? 'com.squirrel.neutron.Neutron'
  : 'com.neutron.security.development';
const NEUTRON_LOGO_PATH = path.join(__dirname, '..', 'assets', 'neutron-logo.png');
const NEUTRON_ICON_PATH = path.join(__dirname, '..', 'assets', 'neutron.ico');

app.setName('Neutron');
if (process.platform === 'win32') app.setAppUserModelId(WINDOWS_APP_USER_MODEL_ID);

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
let mainWindow = null;
let tray = null;
let isQuitting = false;
let hasShownTrayHint = false;
let protonUpdatePromise = null;
let appSettings = {
  start_with_windows: false,
  protection_enabled: true,
  behavior_protection_enabled: true,
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

function showFindingNotification(event, title = 'Neutron bir dosyayı işaretledi') {
  if (!appSettings.notifications_enabled || !Notification.isSupported()) return;
  const finding = event.finding || {};
  const notification = new Notification({
    title,
    body: `${event.file_name || 'Öğe'}: ${finding.reason || 'İnceleme gerekiyor'}`,
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
        await updateApplicationSetting('protection_enabled', !protectionActive);
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
        isQuitting = true;
        app.quit();
      },
    },
  ]));
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
    packagedKeyPath: path.join(process.resourcesPath, 'proton', 'proton-runtime.key'),
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
  if (activeScan) {
    return {
      ok: false,
      message: 'Zaten çalışan bir tarama var.',
    };
  }

  const scanId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const engine = resolveEngine(
    options.targetPath ? ['--scan-path', options.targetPath] : ['--quick-scan']
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
  };
}

function startBehaviorWatcher() {
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
    if (behaviorWatcher === watcher) behaviorWatcher = null;
    updateTrayMenu();
    if (!watcher.stopping && code !== 0) {
      sendProtectionEvent({
        type: 'behavior-error',
        message: watcher.stderr.trim() || 'Davranış izleme beklenmeyen şekilde durdu.',
      });
    } else if (!watcher.silent) {
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

function startProtectionWatcher() {
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
    if (protectionWatcher === watcher) protectionWatcher = null;
    updateTrayMenu();
    if (!watcher.stopping && code !== 0) {
      sendProtectionEvent({
        type: 'watch-error',
        message: watcher.stderr.trim() || 'Gerçek zamanlı koruma beklenmeyen şekilde durdu.',
      });
    } else if (!watcher.silent) {
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
  if (appSettings.protection_enabled) startProtectionWatcher();
  if (appSettings.behavior_protection_enabled) startBehaviorWatcher();
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

ipcMain.handle('scan:start', (event) => startScan(event.sender));
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
ipcMain.handle('scan:history', () => readScanHistory());
ipcMain.handle('protection:start', async () => {
  const result = await updateApplicationSetting('protection_enabled', true);
  return result.ok ? protectionStatus() : result;
});
ipcMain.handle('protection:stop', async () => {
  const result = await updateApplicationSetting('protection_enabled', false);
  return result.ok ? protectionStatus() : result;
});
ipcMain.handle('protection:status', () => protectionStatus());
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
  tray?.destroy();
  tray = null;
});
