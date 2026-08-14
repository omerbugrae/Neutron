#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  buildPackage,
  keyIdFromPublicKey,
  normalizeSource,
  readEncryptionKey,
  readJsonFile,
  verifyPackageSignature,
} = require('../../src/proton-format.cjs');

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function stop(message) {
  console.error(`Hata: ${message}`);
  process.exit(1);
}

try {
  const sourceArgument = argument('--source');
  const keysArgument = argument('--keys');
  const outputArgument = argument('--output');
  if (!sourceArgument || !keysArgument || !outputArgument) {
    stop('Kullanım: npm run proton:pack -- --source <definitions.json> --keys <anahtar-klasörü> --output <yayın-klasörü>');
  }

  const sourcePath = path.resolve(sourceArgument);
  const keysDirectory = path.resolve(keysArgument);
  const outputDirectory = path.resolve(outputArgument);
  const encryptionKey = readEncryptionKey(path.join(keysDirectory, 'proton-encryption.key'));
  const privatePem = fs.readFileSync(path.join(keysDirectory, 'proton-signing-private.pem'));
  const publicPem = fs.readFileSync(path.join(keysDirectory, 'proton-signing-public.pem'));
  const privateKey = crypto.createPrivateKey(privatePem);
  const publicKey = crypto.createPublicKey(publicPem);
  const derivedPublicKey = crypto.createPublicKey(privateKey);
  if (keyIdFromPublicKey(publicKey) !== keyIdFromPublicKey(derivedPublicKey)) {
    stop('Özel ve açık imzalama anahtarları aynı çifte ait değil.');
  }

  const payload = normalizeSource(readJsonFile(sourcePath), sourcePath);
  const built = buildPackage(payload, encryptionKey, privateKey, publicKey);
  verifyPackageSignature(built.packageBytes, built.signatureDocument, publicKey);

  fs.mkdirSync(outputDirectory, { recursive: true });
  const baseName = `proton-${payload.version}`;
  const packagePath = path.join(outputDirectory, `${baseName}.pdbx`);
  const signaturePath = path.join(outputDirectory, `${baseName}.pdbx.sig`);
  if (fs.existsSync(packagePath) || fs.existsSync(signaturePath)) {
    stop(`Aynı sürümün çıktısı zaten mevcut: ${baseName}`);
  }
  built.signatureDocument.package_file = path.basename(packagePath);
  fs.writeFileSync(packagePath, built.packageBytes, { flag: 'wx' });
  fs.writeFileSync(signaturePath, `${JSON.stringify(built.signatureDocument, null, 2)}\n`, { flag: 'wx' });

  console.log(`Proton ${payload.version} paketi oluşturuldu.`);
  console.log(`Paket: ${packagePath}`);
  console.log(`İmza: ${signaturePath}`);
  console.log(`Hash imzası: ${payload.signatures.length}`);
  console.log(`YARA dosyası: ${payload.yara_rules.length}`);
  console.log(`Anahtar kimliği: ${built.header.signing_key_id}`);
} catch (error) {
  stop(error.message);
}
