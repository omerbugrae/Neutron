#!/usr/bin/env node
'use strict';

// PE header sanity check for NeutronServiceHost.exe, mirroring
// tools/engine/verify-engine.cjs's approach. Can't exercise SCM behavior
// here (that needs an elevated `sc.exe create`/`start`, done at install
// time, not build time) -- this just catches "didn't build" / "wrong
// architecture" before packaging.
const { existsSync, readFileSync } = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..', '..');
const architecture = process.argv[2] || 'x64';
const expectedMachine = architecture === 'x86' ? 0x014c : 0x8664;
const executable = path.join(projectRoot, 'runtime', 'service', architecture, 'NeutronServiceHost.exe');

function fail(message) {
  process.stderr.write(`Neutron Service Host doğrulama hatası: ${message}\n`);
  process.exit(1);
}

if (!existsSync(executable)) fail(`${executable} bulunamadı. Önce "npm run service:build" çalıştırın.`);

const header = readFileSync(executable);
if (header.length < 64 || header.readUInt16LE(0) !== 0x5a4d) fail('EXE MZ başlığı geçersiz.');
const peOffset = header.readUInt32LE(0x3c);
if (peOffset + 6 > header.length || header.readUInt32LE(peOffset) !== 0x00004550) {
  fail('EXE PE başlığı geçersiz.');
}
const machine = header.readUInt16LE(peOffset + 4);
if (machine !== expectedMachine) {
  fail(`Mimari uyuşmuyor: beklenen 0x${expectedMachine.toString(16)}, bulunan 0x${machine.toString(16)}.`);
}

process.stdout.write(`Neutron Service Host doğrulandı (${architecture}).\n`);
