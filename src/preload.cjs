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
  applyProtectionAction: (itemId, action) => ipcRenderer.invoke('protection:action', itemId, action),
  getEngineStatus: () => ipcRenderer.invoke('engine:status'),
  getSignatureStatus: () => ipcRenderer.invoke('signature:status'),
  getYaraStatus: () => ipcRenderer.invoke('yara:status'),
  getAnalysisCacheStatus: () => ipcRenderer.invoke('cache:status'),
  clearAnalysisCache: () => ipcRenderer.invoke('cache:clear'),
  updateSignatures: () => ipcRenderer.invoke('signature:update'),
  getSettings: () => ipcRenderer.invoke('settings:get'),
  updateSetting: (key, value) => ipcRenderer.invoke('settings:update', key, value),
  chooseWatchFolder: () => ipcRenderer.invoke('settings:choose-watch-folder'),
  getExclusions: () => ipcRenderer.invoke('exclusions:list'),
  addExclusionFolder: () => ipcRenderer.invoke('exclusions:add-folder'),
  addExclusionExtension: (extension) => ipcRenderer.invoke('exclusions:add-extension', extension),
  trustFileHash: (sha256, label) => ipcRenderer.invoke('exclusions:trust-hash', sha256, label),
  removeExclusion: (itemId) => ipcRenderer.invoke('exclusions:remove', itemId),
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
  onOpenProtectionEvent: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('protection:open-event', listener);
    return () => ipcRenderer.removeListener('protection:open-event', listener);
  },
  onProtonUpdateEvent: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('proton:update-event', listener);
    return () => ipcRenderer.removeListener('proton:update-event', listener);
  },
});
