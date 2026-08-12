#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createWindowsInstaller } = require('electron-winstaller');

const root = path.resolve(__dirname, '..');
const electronDist = path.join(root, 'node_modules', 'electron', 'dist');
const appDirectory = path.join(root, 'build', 'test-package', 'Neutron-win32-x64');
const resourcesDirectory = path.join(appDirectory, 'resources');
const appResources = path.join(resourcesDirectory, 'app');
const outputDirectory = path.join(root, 'out', 'test-setup');

function copy(source, destination) {
  fs.cpSync(source, destination, { recursive: true, force: true });
}

function copyIfPresent(source, destination) {
  if (fs.existsSync(source)) copy(source, destination);
}

if (!fs.existsSync(path.join(electronDist, 'electron.exe'))) {
  throw new Error('Yerel Electron çalışma zamanı bulunamadı. Önce npm install çalıştırın.');
}
if (!fs.existsSync(path.join(root, 'runtime', 'engine', 'x64'))) {
  throw new Error('x64 Neutron motoru bulunamadı. Önce npm run engine:build çalıştırın.');
}

fs.rmSync(path.join(root, 'build', 'test-package'), { recursive: true, force: true });
fs.rmSync(outputDirectory, { recursive: true, force: true });
fs.mkdirSync(appResources, { recursive: true });

copy(electronDist, appDirectory);
fs.renameSync(path.join(appDirectory, 'electron.exe'), path.join(appDirectory, 'Neutron.exe'));
copy(path.join(root, 'runtime'), path.join(resourcesDirectory, 'runtime'));

for (const entry of ['assets', 'src', 'tools']) {
  copy(path.join(root, entry), path.join(appResources, entry));
}
for (const entry of ['package.json', 'package-lock.json']) {
  copy(path.join(root, entry), path.join(appResources, entry));
}

const productionModules = [
  ['electron-squirrel-startup', 'electron-squirrel-startup'],
  ['debug', 'debug'],
  ['ms', 'ms'],
];
for (const [sourceName, destinationName] of productionModules) {
  copyIfPresent(
    path.join(root, 'node_modules', sourceName),
    path.join(appResources, 'node_modules', destinationName),
  );
}

fs.mkdirSync(outputDirectory, { recursive: true });

createWindowsInstaller({
  appDirectory,
  outputDirectory,
  authors: 'Neutron',
  owners: 'Neutron',
  name: 'neutron',
  title: 'Neutron',
  description: 'Neutron desktop security application',
  version: require(path.join(root, 'package.json')).version,
  exe: 'Neutron.exe',
  setupExe: 'NeutronSetup-Test.exe',
  setupIcon: path.join(root, 'assets', 'neutron.ico'),
  iconUrl: 'https://raw.githubusercontent.com/omerbugrae/Neutron/main/assets/neutron.ico',
  noMsi: true,
  noDelta: true,
}).then(() => {
  process.stdout.write(`Test kurucusu oluşturuldu: ${path.join(outputDirectory, 'NeutronSetup-Test.exe')}\n`);
}).catch((error) => {
  process.stderr.write(`Test kurucusu oluşturulamadı: ${error.stack || error.message}\n`);
  process.exitCode = 1;
});
