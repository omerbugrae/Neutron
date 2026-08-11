#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  decryptPackage,
  parsePackage,
  readEncryptionKey,
  readJsonFile,
  verifyPackageSignature,
} = require('./proton-format.cjs');

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function stop(message) {
  console.error(`Hata: ${message}`);
  process.exit(1);
}

try {
  const packageArgument = argument('--package');
  const signatureArgument = argument('--signature');
  const publicKeyArgument = argument('--public-key');
  const encryptionKeyArgument = argument('--encryption-key');
  if (!packageArgument || !signatureArgument || !publicKeyArgument) {
    stop('Kullanım: npm run proton:verify -- --package <paket.pdbx> --signature <paket.pdbx.sig> --public-key <public.pem> [--encryption-key <aes.key>]');
  }

  const packageBytes = fs.readFileSync(path.resolve(packageArgument));
  const signatureDocument = readJsonFile(path.resolve(signatureArgument), 64 * 1024);
  const publicKey = fs.readFileSync(path.resolve(publicKeyArgument));
  verifyPackageSignature(packageBytes, signatureDocument, publicKey);
  const { header } = parsePackage(packageBytes);

  console.log('Dijital imza geçerli.');
  console.log(`Veritabanı: ${header.database_name} ${header.database_version}`);
  console.log(`Anahtar kimliği: ${header.signing_key_id}`);
  if (encryptionKeyArgument) {
    const encryptionKey = readEncryptionKey(path.resolve(encryptionKeyArgument));
    const result = decryptPackage(packageBytes, encryptionKey);
    console.log('AES-256-GCM doğrulaması ve paket çözme işlemi başarılı.');
    console.log(`Hash imzası: ${result.payload.signatures.length}`);
    console.log(`YARA dosyası: ${result.payload.yara_rules.length}`);
  } else {
    console.log('Şifre çözme testi atlandı; --encryption-key verilmedi.');
  }
} catch (error) {
  stop(error.message);
}
