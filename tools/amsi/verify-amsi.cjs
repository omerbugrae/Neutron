#!/usr/bin/env node
'use strict';

// Mirrors tools/engine/verify-engine.cjs: a small dependency-free PE
// export-table check so packaging fails fast if the AMSI provider DLL is
// missing, wrong-architecture, or was built without its COM entry points.
const { existsSync, readFileSync } = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..', '..');
const architecture = process.argv[2] || 'x64';
const expectedMachine = architecture === 'x86' ? 0x014c : 0x8664;
const dllPath = path.join(projectRoot, 'runtime', 'amsi', architecture, 'NeutronAmsiProvider.dll');

function fail(message) {
  process.stderr.write(`Neutron AMSI Provider doğrulama hatası: ${message}\n`);
  process.exit(1);
}

if (!existsSync(dllPath)) fail(`${dllPath} bulunamadı. Önce "npm run amsi:build" çalıştırın.`);

const buffer = readFileSync(dllPath);
if (buffer.length < 64 || buffer.readUInt16LE(0) !== 0x5a4d) fail('DLL MZ başlığı geçersiz.');
const peOffset = buffer.readUInt32LE(0x3c);
if (peOffset + 24 > buffer.length || buffer.readUInt32LE(peOffset) !== 0x00004550) {
  fail('DLL PE başlığı geçersiz.');
}
const machine = buffer.readUInt16LE(peOffset + 4);
if (machine !== expectedMachine) {
  fail(`Mimari uyuşmuyor: beklenen 0x${expectedMachine.toString(16)}, bulunan 0x${machine.toString(16)}.`);
}

const numberOfSections = buffer.readUInt16LE(peOffset + 6);
const sizeOfOptionalHeader = buffer.readUInt16LE(peOffset + 20);
const optionalHeaderOffset = peOffset + 24;
const magic = buffer.readUInt16LE(optionalHeaderOffset);
const isPE32Plus = magic === 0x20b;
if (magic !== 0x10b && !isPE32Plus) fail('Bilinmeyen PE Optional Header türü.');

// Export table is DataDirectory[0]; its offset in the optional header
// differs between PE32 and PE32+ because PE32+ drops the 4-byte
// BaseOfData field.
const dataDirectoryOffset = optionalHeaderOffset + (isPE32Plus ? 112 : 96);
const exportDirectoryRva = buffer.readUInt32LE(dataDirectoryOffset);
const exportDirectorySize = buffer.readUInt32LE(dataDirectoryOffset + 4);
if (exportDirectoryRva === 0 || exportDirectorySize === 0) fail('DLL hiçbir sembol dışa aktarmıyor.');

const sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;
const sections = [];
for (let i = 0; i < numberOfSections; i += 1) {
  const base = sectionHeadersOffset + i * 40;
  sections.push({
    virtualAddress: buffer.readUInt32LE(base + 12),
    virtualSize: buffer.readUInt32LE(base + 8),
    rawPointer: buffer.readUInt32LE(base + 20),
  });
}

function rvaToOffset(rva) {
  const section = sections.find(
    (candidate) => rva >= candidate.virtualAddress && rva < candidate.virtualAddress + candidate.virtualSize,
  );
  if (!section) fail(`RVA 0x${rva.toString(16)} için bölüm bulunamadı.`);
  return section.rawPointer + (rva - section.virtualAddress);
}

function readCString(offset) {
  let end = offset;
  while (end < buffer.length && buffer[end] !== 0) end += 1;
  return buffer.toString('ascii', offset, end);
}

const exportDirOffset = rvaToOffset(exportDirectoryRva);
const numberOfNames = buffer.readUInt32LE(exportDirOffset + 24);
const addressOfNamesRva = buffer.readUInt32LE(exportDirOffset + 32);
const addressOfNamesOffset = rvaToOffset(addressOfNamesRva);

const exportedNames = new Set();
for (let i = 0; i < numberOfNames; i += 1) {
  const nameRva = buffer.readUInt32LE(addressOfNamesOffset + i * 4);
  exportedNames.add(readCString(rvaToOffset(nameRva)));
}

const required = ['DllGetClassObject', 'DllCanUnloadNow', 'DllRegisterServer', 'DllUnregisterServer'];
const missing = required.filter((name) => !exportedNames.has(name));
if (missing.length > 0) fail(`Eksik dışa aktarımlar: ${missing.join(', ')}.`);

process.stdout.write(
  `Neutron AMSI Provider doğrulandı (${architecture}, ${exportedNames.size} dışa aktarım).\n`,
);
