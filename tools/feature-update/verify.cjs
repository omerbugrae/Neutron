#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  decryptFeatureFile, readEncryptionKey, validateManifest, verifyManifestSignature,
} = require('../../src/feature-update-format.cjs');

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

try {
  const version = argument('--version');
  const input = path.resolve(argument('--input') || 'feature-dist');
  const keys = path.resolve(argument('--keys') || 'proton-secrets');
  if (!/^\d+\.\d{2}\.\d{3}$/.test(String(version || ''))) throw new Error('Usage: npm run feature:verify -- --version 1.00.001 --keys <key-directory> [--input <release-directory>]');
  const manifestBytes = fs.readFileSync(path.join(input, `feature-${version}.json`));
  const signature = JSON.parse(fs.readFileSync(path.join(input, `feature-${version}.json.sig`), 'utf8'));
  verifyManifestSignature(manifestBytes, signature, fs.readFileSync(path.join(keys, 'proton-signing-public.pem')));
  const manifest = validateManifest(JSON.parse(manifestBytes.toString('utf8')));
  const encryptionKey = readEncryptionKey(path.join(keys, 'proton-encryption.key'));
  let chunkCount = 0;
  for (const entry of manifest.files) {
    const fileHash = crypto.createHash('sha256');
    let bytes = 0;
    for (const chunk of entry.chunks) {
      const plaintext = decryptFeatureFile(fs.readFileSync(path.join(input, chunk.asset)), chunk, encryptionKey);
      fileHash.update(plaintext);
      bytes += plaintext.length;
      chunkCount += 1;
    }
    if (bytes !== entry.plaintext_bytes || fileHash.digest('hex') !== entry.plaintext_sha256) throw new Error(`File verification failed: ${entry.name}`);
  }
  console.log(`Machine Learning Feature Update ${version} verified (${manifest.files.length} files, ${chunkCount} encrypted chunks).`);
} catch (error) {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
}
