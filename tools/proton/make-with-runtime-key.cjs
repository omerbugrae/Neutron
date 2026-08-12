#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const projectRoot = path.resolve(__dirname, '..', '..');

function argumentValue(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

function fail(message) {
  console.error(`Hata: ${message}`);
  process.exitCode = 1;
}

const defaultKey = path.join(path.dirname(projectRoot), 'NeutronSecret', 'proton-encryption.key');
const sourceKey = path.resolve(argumentValue('--key') || process.env.NEUTRON_PROTON_KEY_FILE || defaultKey);
const runtimeDirectory = path.join(projectRoot, 'runtime', 'proton');
const runtimeKey = path.join(runtimeDirectory, 'proton-runtime.key');

if (!fs.existsSync(sourceKey) || !fs.statSync(sourceKey).isFile()) {
  fail(`Proton çalışma anahtarı bulunamadı: ${sourceKey}\nKullanım: npm.cmd run make:proton -- --key <proton-encryption.key>`);
} else if (path.resolve(sourceKey) === path.resolve(runtimeKey)) {
  fail('Kaynak anahtar geçici paketleme hedefiyle aynı olamaz.');
} else {
  try {
    fs.mkdirSync(runtimeDirectory, { recursive: true });
    fs.copyFileSync(sourceKey, runtimeKey, fs.constants.COPYFILE_EXCL);
    const result = process.platform === 'win32'
      ? spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', 'npm.cmd run make:win:x64'], {
        cwd: projectRoot,
        stdio: 'inherit',
        windowsHide: true,
        shell: false,
        env: process.env,
      })
      : spawnSync('npm', ['run', 'make:win:x64'], {
        cwd: projectRoot,
        stdio: 'inherit',
        shell: false,
        env: process.env,
      });
    if (result.error) throw result.error;
    if (result.status !== 0) process.exitCode = result.status || 1;
  } catch (error) {
    fail(error.message);
  } finally {
    try {
      if (fs.existsSync(runtimeKey)) fs.rmSync(runtimeKey, { force: true });
      if (fs.existsSync(runtimeDirectory) && fs.readdirSync(runtimeDirectory).length === 0) {
        fs.rmdirSync(runtimeDirectory);
      }
    } catch (error) {
      console.error(`Uyarı: geçici Proton anahtarı temizlenemedi: ${error.message}`);
      process.exitCode = process.exitCode || 1;
    }
  }
}
