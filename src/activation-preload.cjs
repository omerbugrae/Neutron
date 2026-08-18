'use strict';

// Dedicated bridge for the activation window.
//
// It deliberately does NOT reuse preload.cjs: that surface exposes scanning,
// quarantine, firewall and settings channels, none of which this window has
// any business reaching. An unlicensed machine is exactly the state where the
// smallest possible attack surface matters, so this window gets only the
// account channels it actually uses.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('neutron', {
  getStatus: () => ipcRenderer.invoke('license:status'),
  signUp: (email, password, customerName) => ipcRenderer.invoke('account:sign-up', email, password, customerName),
  signIn: (email, password) => ipcRenderer.invoke('account:sign-in', email, password),
  signOut: () => ipcRenderer.invoke('account:sign-out'),
  refresh: () => ipcRenderer.invoke('account:refresh'),
  closeWindow: () => ipcRenderer.send('activation:close'),
});
