const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('neutronWindow', {
  minimize: () => ipcRenderer.send('window:minimize'),
  toggleMaximize: () => ipcRenderer.send('window:toggle-maximize'),
  close: () => ipcRenderer.send('window:close'),
});

contextBridge.exposeInMainWorld('neutronEngine', {
  getLicenseStatus: () => ipcRenderer.invoke('license:status'),
  activateLicense: (key) => ipcRenderer.invoke('license:activate', key),
  deactivateLicense: () => ipcRenderer.invoke('license:deactivate'),
  revealLicense: () => ipcRenderer.invoke('license:reveal'),
  startQuickScan: () => ipcRenderer.invoke('scan:start'),
  getScanDrives: () => ipcRenderer.invoke('scan:drives'),
  startFullScan: (targetPath) => ipcRenderer.invoke('scan:full', targetPath),
  chooseCustomScan: () => ipcRenderer.invoke('scan:choose-custom'),
  chooseFolderAndScan: () => ipcRenderer.invoke('scan:choose-folder'),
  getScanHistory: () => ipcRenderer.invoke('scan:history'),
  startProtection: () => ipcRenderer.invoke('protection:start'),
  stopProtection: () => ipcRenderer.invoke('protection:stop'),
  getProtectionStatus: () => ipcRenderer.invoke('protection:status'),
  registerAmsiProtection: () => ipcRenderer.invoke('protection:amsi-register'),
  unregisterAmsiProtection: () => ipcRenderer.invoke('protection:amsi-unregister'),
  registerWatchdogProtection: () => ipcRenderer.invoke('protection:watchdog-register'),
  unregisterWatchdogProtection: () => ipcRenderer.invoke('protection:watchdog-unregister'),
  registerWscProtection: () => ipcRenderer.invoke('protection:wsc-register'),
  unregisterWscProtection: () => ipcRenderer.invoke('protection:wsc-unregister'),
  installProtectionService: () => ipcRenderer.invoke('protection:service-install'),
  uninstallProtectionService: () => ipcRenderer.invoke('protection:service-uninstall'),
  getServiceStatus: () => ipcRenderer.invoke('protection:service-status'),
  getAppVersion: () => ipcRenderer.invoke('app:get-version'),
  checkForAppUpdate: () => ipcRenderer.invoke('app:check-for-update'),
  prepareUninstall: () => ipcRenderer.invoke('app:prepare-uninstall'),
  checkUrlReputation: (url) => ipcRenderer.invoke('web:check-url', url),
  openSafeUrl: (url) => ipcRenderer.invoke('web:open-url', url),
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
  getFirewallRules: () => ipcRenderer.invoke('firewall:list'),
  getFirewallRecentApps: () => ipcRenderer.invoke('firewall:recent-apps'),
  chooseFirewallApp: () => ipcRenderer.invoke('firewall:choose-app'),
  addFirewallRule: (programPath, action, direction) => ipcRenderer.invoke('firewall:add-rule', programPath, action, direction),
  removeFirewallRule: (ruleId, ruleName) => ipcRenderer.invoke('firewall:remove-rule', ruleId, ruleName),
  toggleFirewallRule: (ruleId, ruleName, enabled) => ipcRenderer.invoke('firewall:toggle-rule', ruleId, ruleName, enabled),
  getStartupItems: () => ipcRenderer.invoke('startup:list'),
  disableStartupItem: (item) => ipcRenderer.invoke('startup:disable', item),
  restoreStartupItem: (itemId) => ipcRenderer.invoke('startup:restore', itemId),
  getVulnerableSoftware: () => ipcRenderer.invoke('vulnerability:scan'),
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
