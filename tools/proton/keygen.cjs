#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { keyIdFromPublicKey } = require('../../src/proton-format.cjs');

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function stop(message) {
  console.error(`Hata: ${message}`);
  process.exit(1);
}

const outputArgument = argument('--output');
if (!outputArgument) {
  stop('Proje dışındaki güvenli klasörü --output ile belirtin. Örnek: npm run proton:keygen -- --output C:\\Neutron-Secrets');
}

const projectRoot = path.resolve(__dirname, '..', '..');
const outputDirectory = path.resolve(outputArgument);
const relativeToProject = path.relative(projectRoot, outputDirectory);
if (!relativeToProject || (!relativeToProject.startsWith('..') && !path.isAbsolute(relativeToProject))) {
  stop('Gizli anahtar klasörü Neutron proje klasörünün içinde olamaz.');
}

const encryptionKeyPath = path.join(outputDirectory, 'proton-encryption.key');
const privateKeyPath = path.join(outputDirectory, 'proton-signing-private.pem');
const publicKeyPath = path.join(outputDirectory, 'proton-signing-public.pem');
const informationPath = path.join(outputDirectory, 'proton-key-info.json');
const targets = [encryptionKeyPath, privateKeyPath, publicKeyPath, informationPath];

fs.mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
for (const target of targets) {
  if (fs.existsSync(target)) stop(`Var olan anahtar dosyasının üzerine yazılmayacak: ${target}`);
}

const encryptionKey = crypto.randomBytes(32);
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
const keyId = keyIdFromPublicKey(publicPem);
const createdAt = new Date().toISOString();

fs.writeFileSync(encryptionKeyPath, `${encryptionKey.toString('base64')}\n`, { flag: 'wx', mode: 0o600 });
fs.writeFileSync(privateKeyPath, privatePem, { flag: 'wx', mode: 0o600 });
fs.writeFileSync(publicKeyPath, publicPem, { flag: 'wx', mode: 0o644 });
fs.writeFileSync(
  informationPath,
  `${JSON.stringify({ key_id: keyId, created_at: createdAt, algorithms: ['AES-256-GCM', 'Ed25519'] }, null, 2)}\n`,
  { flag: 'wx', mode: 0o644 },
);

console.log('Proton yayın anahtarları oluşturuldu.');
console.log(`Klasör: ${outputDirectory}`);
console.log(`Anahtar kimliği: ${keyId}`);
console.log('UYARI: proton-encryption.key ve proton-signing-private.pem dosyalarını GitHub’a yüklemeyin.');
console.log('Bu iki dosyanın çevrimdışı, şifreli bir yedeğini oluşturun.');
