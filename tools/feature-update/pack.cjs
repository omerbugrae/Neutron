#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  FEATURE_NAME, MANIFEST_SCHEMA, MAX_CHUNK_PLAINTEXT_BYTES, canonicalManifest, encryptFeatureFile,
  readEncryptionKey, sha256, signManifest, validateManifest, verifyManifestSignature,
} = require('../../src/feature-update-format.cjs');
const { keyIdFromPublicKey } = require('../../src/proton-format.cjs');

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function stop(message) {
  console.error(`Error: ${message}`);
  process.exit(1);
}

try {
  const version = argument('--version');
  const sourceDirectory = path.resolve(argument('--source') || 'data/ml/ember2024');
  const keysDirectory = path.resolve(argument('--keys') || 'proton-secrets');
  const outputDirectory = path.resolve(argument('--output') || 'feature-dist');
  const minimumAppVersion = argument('--minimum-app-version') || '0.31.0';
  if (!/^\d+\.\d{2}\.\d{3}$/.test(String(version || ''))) stop('Usage: npm run feature:pack -- --version 1.00.001 --keys <key-directory> [--source <model-directory>] [--output <release-directory>]');

  const encryptionKey = readEncryptionKey(path.join(keysDirectory, 'proton-encryption.key'));
  const privateKey = crypto.createPrivateKey(fs.readFileSync(path.join(keysDirectory, 'proton-signing-private.pem')));
  const publicKey = crypto.createPublicKey(fs.readFileSync(path.join(keysDirectory, 'proton-signing-public.pem')));
  if (keyIdFromPublicKey(publicKey) !== keyIdFromPublicKey(crypto.createPublicKey(privateKey))) stop('Signing keys are not a matching pair.');

  const provenance = JSON.parse(fs.readFileSync(path.join(sourceDirectory, 'MODEL_PROVENANCE.json'), 'utf8'));
  const modelNames = provenance.models.map((entry) => entry.file).sort((left, right) => left.localeCompare(right));
  if (modelNames.length !== 14) stop('MODEL_PROVENANCE.json must list exactly 14 models.');
  const fileNames = [...modelNames, 'ensemble.json', 'MODEL_PROVENANCE.json'];
  fs.mkdirSync(outputDirectory, { recursive: true });
  const entries = [];
  for (let index = 0; index < fileNames.length; index += 1) {
    const name = fileNames[index];
    const sourcePath = path.join(sourceDirectory, name);
    const sourceStat = fs.statSync(sourcePath);
    const fileHash = crypto.createHash('sha256');
    const chunks = [];
    const descriptor = fs.openSync(sourcePath, 'r');
    let position = 0;
    let chunkIndex = 0;
    try {
      while (position < sourceStat.size) {
        const requested = Math.min(MAX_CHUNK_PLAINTEXT_BYTES, sourceStat.size - position);
        const plaintext = Buffer.allocUnsafe(requested);
        const bytesRead = fs.readSync(descriptor, plaintext, 0, requested, position);
        if (bytesRead !== requested) stop(`Could not read complete source model: ${name}`);
        position += bytesRead;
        chunkIndex += 1;
        fileHash.update(plaintext);
        const { encrypted, nonce, authTag } = encryptFeatureFile(plaintext, encryptionKey);
        const asset = `feature-${version}-${String(index + 1).padStart(3, '0')}-${String(chunkIndex).padStart(3, '0')}.nfchunk`;
        const assetPath = path.join(outputDirectory, asset);
        if (fs.existsSync(assetPath)) stop(`Output already exists: ${assetPath}`);
        fs.writeFileSync(assetPath, encrypted, { flag: 'wx' });
        chunks.push({
          asset,
          plaintext_sha256: sha256(plaintext), plaintext_bytes: plaintext.length,
          encrypted_sha256: sha256(encrypted), encrypted_bytes: encrypted.length,
          nonce_base64: nonce.toString('base64'), auth_tag_base64: authTag.toString('base64'),
          compression: 'gzip', encryption: 'aes-256-gcm',
        });
      }
    } finally {
      fs.closeSync(descriptor);
    }
    const plaintextHash = fileHash.digest('hex');
    const expected = provenance.models.find((entry) => entry.file === name)?.sha256;
    if (expected && plaintextHash !== expected) stop(`Source model hash mismatch: ${name}`);
    entries.push({
      name,
      plaintext_sha256: plaintextHash,
      plaintext_bytes: sourceStat.size,
      chunks,
    });
    console.log(`[${index + 1}/${fileNames.length}] ${name} -> ${chunks.length} encrypted chunk(s)`);
  }

  const manifest = validateManifest({
    schema: MANIFEST_SCHEMA, feature: FEATURE_NAME,
    display_name: 'Machine Learning Feature Update', version,
    minimum_app_version: minimumAppVersion, created_at: new Date().toISOString(), files: entries,
  });
  const manifestBytes = canonicalManifest(manifest);
  const signature = signManifest(manifestBytes, privateKey, publicKey);
  verifyManifestSignature(manifestBytes, signature, publicKey);
  const manifestPath = path.join(outputDirectory, `feature-${version}.json`);
  const signaturePath = `${manifestPath}.sig`;
  if (fs.existsSync(manifestPath) || fs.existsSync(signaturePath)) stop('Manifest output already exists.');
  fs.writeFileSync(manifestPath, manifestBytes, { flag: 'wx' });
  fs.writeFileSync(signaturePath, `${JSON.stringify(signature, null, 2)}\n`, { flag: 'wx' });
  const chunkCount = entries.reduce((sum, entry) => sum + entry.chunks.length, 0);
  console.log(`Machine Learning Feature Update ${version} created (${entries.length} files, ${chunkCount} encrypted chunks).`);
  console.log(`GitHub release tag: feature-v${version}`);
} catch (error) {
  stop(error.message);
}
