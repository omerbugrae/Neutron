const { app, BrowserWindow, dialog, ipcMain, Menu, Notification } = require('electron');
const { spawn } = require('child_process');
const { existsSync } = require('fs');
const path = require('path');

if (require('electron-squirrel-startup')) {
  app.quit();
}

let activeScan = null;
let protectionWatcher = null;
let mainWindow = null;

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

function engineEnvironment() {
  return {
    ...process.env,
    // Prototip aşamasında geçmiş dosyası proje içinde görünür tutulur.
    NEUTRON_DATA_DIR: path.join(__dirname, '..', 'data'),
  };
}

function readScanHistory() {
  const enginePath = path.join(__dirname, 'engine.py');

  return new Promise((resolve) => {
    const child = spawn(
      resolvePython(),
      [enginePath, '--history', '--limit', '5', '--json-lines'],
      {
        cwd: path.dirname(enginePath),
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

function runEngineAction(argumentsList, expectedType) {
  const enginePath = path.join(__dirname, 'engine.py');
  return new Promise((resolve) => {
    const child = spawn(resolvePython(), [enginePath, ...argumentsList, '--json-lines'], {
      cwd: path.dirname(enginePath), windowsHide: true, shell: false,
      env: engineEnvironment(), stdio: ['ignore', 'pipe', 'pipe'],
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
  });
}

function startScan(webContents, options = {}) {
  if (activeScan) {
    return {
      ok: false,
      message: 'Zaten çalışan bir tarama var.',
    };
  }

  const enginePath = path.join(__dirname, 'engine.py');
  const scanId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const engineArguments = options.targetPath
    ? [enginePath, '--scan-path', options.targetPath, '--json-lines']
    : [enginePath, '--quick-scan', '--json-lines'];
  const child = spawn(
    resolvePython(),
    engineArguments,
    {
      cwd: path.dirname(enginePath),
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
  };
}

function startProtectionWatcher() {
  if (protectionWatcher) return protectionStatus();

  const enginePath = path.join(__dirname, 'engine.py');
  const child = spawn(resolvePython(), [enginePath, '--watch', '--json-lines'], {
    cwd: path.dirname(enginePath),
    windowsHide: true,
    shell: false,
    env: engineEnvironment(),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const watcher = { child, ready: false, stopping: false, pending: '', stderr: '' };
  protectionWatcher = watcher;

  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    watcher.pending += chunk;
    const lines = watcher.pending.split(/\r?\n/);
    watcher.pending = lines.pop() || '';
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.type === 'watch-ready') watcher.ready = true;
        sendProtectionEvent(event);
        if (event.type === 'watch-finding' && Notification.isSupported()) {
          const finding = event.finding || {};
          new Notification({
            title: 'Neutron bir dosyayı işaretledi',
            body: `${event.file_name || 'Dosya'}: ${finding.reason || 'İnceleme gerekiyor'}`,
            silent: false,
          }).show();
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
    sendProtectionEvent({ type: 'watch-error', message: 'Gerçek zamanlı koruma motoru başlatılamadı.' });
  });
  child.once('close', (code) => {
    if (protectionWatcher === watcher) protectionWatcher = null;
    if (!watcher.stopping && code !== 0) {
      sendProtectionEvent({
        type: 'watch-error',
        message: watcher.stderr.trim() || 'Gerçek zamanlı koruma beklenmeyen şekilde durdu.',
      });
    } else {
      sendProtectionEvent({ type: 'watch-stopped' });
    }
  });

  return protectionStatus();
}

function stopProtectionWatcher() {
  if (!protectionWatcher) return { ok: true, enabled: false, ready: false };
  protectionWatcher.stopping = true;
  protectionWatcher.child.kill();
  protectionWatcher = null;
  return { ok: true, enabled: false, ready: false };
}

function createWindow() {
  const window = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    frame: false,
    transparent: false,
    backgroundColor: '#050a18',
    icon: path.join(__dirname, '..', 'assets', 'neutron.ico'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webgl: true,
      spellcheck: false,
      backgroundThrottling: true,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });

  mainWindow = window;
  window.loadFile(path.join(__dirname, 'neutron-ui.html'));
  // Start the engine while the launch screen is visible. The renderer can read
  // its state when ready without briefly assuming that protection is disabled.
  startProtectionWatcher();
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
ipcMain.handle('protection:start', () => startProtectionWatcher());
ipcMain.handle('protection:stop', () => stopProtectionWatcher());
ipcMain.handle('protection:status', () => protectionStatus());
ipcMain.handle('protection:history', () => runEngineAction(['--protection-history', '--limit', '20'], 'protection-history'));
ipcMain.handle('signature:status', () => runEngineAction(['--signature-status'], 'signature-status'));
ipcMain.handle('yara:status', () => runEngineAction(['--yara-status'], 'yara-status'));
ipcMain.handle('signature:update', async () => {
  const restartProtection = Boolean(protectionWatcher);
  if (restartProtection) stopProtectionWatcher();
  const result = await runEngineAction(['--signature-update'], 'signature-updated');
  if (restartProtection) startProtectionWatcher();
  return result;
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

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  activeScan?.child.kill();
  activeScan = null;
  if (protectionWatcher) {
    protectionWatcher.stopping = true;
    protectionWatcher.child.kill();
    protectionWatcher = null;
  }
});
