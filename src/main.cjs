const { app, BrowserWindow, ipcMain, Menu } = require('electron');
const path = require('path');

function createWindow() {
  const window = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    frame: false,
    transparent: false,
    backgroundColor: '#050a18',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webgl: true,
      spellcheck: false,
      backgroundThrottling: true,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });

  window.loadFile(path.join(__dirname, 'neutron-ui.html'));
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

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
