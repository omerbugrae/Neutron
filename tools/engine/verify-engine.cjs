#!/usr/bin/env node
'use strict';

const { spawnSync } = require('node:child_process');
const { existsSync, readFileSync } = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..', '..');
const architecture = process.argv[2] || 'x64';
const expectedMachine = architecture === 'x86' ? 0x014c : 0x8664;
const engineDirectory = path.join(projectRoot, 'runtime', 'engine', architecture, 'neutron-engine');
const executable = path.join(engineDirectory, 'neutron-engine.exe');
const pythonDll = path.join(engineDirectory, '_internal', 'python311.dll');

function fail(message) {
  process.stderr.write(`Neutron Engine doğrulama hatası: ${message}\n`);
  process.exit(1);
}

if (!existsSync(executable)) fail(`${executable} bulunamadı.`);
if (!existsSync(pythonDll)) fail('Gömülü Python çalışma zamanı bulunamadı.');

const header = readFileSync(executable);
if (header.length < 256 || header.readUInt16LE(0) !== 0x5a4d) fail('EXE MZ başlığı geçersiz.');
const peOffset = header.readUInt32LE(0x3c);
if (peOffset + 6 > header.length || header.readUInt32LE(peOffset) !== 0x00004550) {
  fail('EXE PE başlığı geçersiz.');
}
const machine = header.readUInt16LE(peOffset + 4);
if (machine !== expectedMachine) {
  fail(`Mimari uyuşmuyor: beklenen 0x${expectedMachine.toString(16)}, bulunan 0x${machine.toString(16)}.`);
}

function runEngine(argumentsList, expectedType) {
  const result = spawnSync(executable, [...argumentsList, '--json-lines'], {
    cwd: engineDirectory,
    encoding: 'utf8',
    windowsHide: true,
    shell: false,
    env: { ...process.env, NEUTRON_DATA_DIR: path.join(projectRoot, 'data') },
    timeout: 15_000,
  });
  if (result.error) fail(result.error.message);
  if (result.status !== 0) fail(result.stderr || `motor ${result.status} koduyla kapandı.`);
  const line = result.stdout.trim().split(/\r?\n/).at(-1);
  let event;
  try {
    event = JSON.parse(line);
  } catch {
    fail('Motor geçerli JSON Lines çıktısı vermedi.');
  }
  if (event.type !== expectedType) fail(`${expectedType} yerine ${event.type || 'bilinmeyen'} alındı.`);
  return event;
}

const version = runEngine(['--engine-version'], 'engine-version');
const yara = runEngine(['--yara-status'], 'yara-status');
if (!version.frozen) fail('Motor PyInstaller frozen modunda çalışmıyor.');
if (!yara.available) fail(`Gömülü YARA kullanılamıyor: ${yara.message || 'bilinmeyen hata'}`);

process.stdout.write(
  `Neutron Engine ${version.version} doğrulandı (${architecture}, YARA ${yara.version}, ${yara.rule_files} kural).\n`,
);
