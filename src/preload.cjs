const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('neutronWindow', {
  minimize: () => ipcRenderer.send('window:minimize'),
  toggleMaximize: () => ipcRenderer.send('window:toggle-maximize'),
  close: () => ipcRenderer.send('window:close'),
});

contextBridge.exposeInMainWorld('neutronEngine', {
  startQuickScan: () => ipcRenderer.invoke('scan:start'),
  chooseFolderAndScan: () => ipcRenderer.invoke('scan:choose-folder'),
  getScanHistory: () => ipcRenderer.invoke('scan:history'),
  startProtection: () => ipcRenderer.invoke('protection:start'),
  stopProtection: () => ipcRenderer.invoke('protection:stop'),
  getProtectionStatus: () => ipcRenderer.invoke('protection:status'),
  getProtectionHistory: () => ipcRenderer.invoke('protection:history'),
  getSignatureStatus: () => ipcRenderer.invoke('signature:status'),
  getYaraStatus: () => ipcRenderer.invoke('yara:status'),
  updateSignatures: () => ipcRenderer.invoke('signature:update'),
  getQuarantine: () => ipcRenderer.invoke('quarantine:list'),
  addToQuarantine: (finding) => ipcRenderer.invoke('quarantine:add', finding),
  restoreFromQuarantine: (itemId) => ipcRenderer.invoke('quarantine:restore', itemId),
  deleteFromQuarantine: (itemId) => ipcRenderer.invoke('quarantine:delete', itemId),
  onScanEvent: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('scan:event', listener);
    return () => ipcRenderer.removeListener('scan:event', listener);
  },
  onProtectionEvent: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('protection:event', listener);
    return () => ipcRenderer.removeListener('protection:event', listener);
  },
});
