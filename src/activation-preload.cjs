'use strict';

// Dedicated bridge for the activation window.
//
// It deliberately does NOT reuse preload.cjs: that surface exposes scanning,
// quarantine, firewall and settings channels, none of which this window has
// any business reaching. An unlicensed machine is exactly the state where the
// smallest possible attack surface matters, so this window gets the three
// channels it actually uses and nothing else.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('neutron', {
  getLicenseStatus: () => ipcRenderer.invoke('license:status'),
  activateLicense: (key) => ipcRenderer.invoke('license:activate', key),
  closeWindow: () => ipcRenderer.send('activation:close'),
});
