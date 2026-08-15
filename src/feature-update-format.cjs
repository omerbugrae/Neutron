'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const {
  keyIdFromPublicKey,
  readEncryptionKey,
  sha256,
  verifyPackageSignature,
} = require('./proton-format.cjs');

const MANIFEST_SCHEMA = 'neutron.feature-update.manifest/v1';
const SIGNATURE_FORMAT = 'neutron-feature-signature/v1';
const FEATURE_NAME = 'machine-learning-models';
const VERSION_PATTERN = /^\d+\.\d{2}\.\d{3}$/;
const SAFE_FILE_PATTERN = /^(?:EMBER2024_[A-Za-z0-9_]+\.model|ensemble\.json|MODEL_PROVENANCE\.json)$/;
const MAX_PLAINTEXT_BYTES = 768 * 1024 * 1024;
const MAX_CHUNK_PLAINTEXT_BYTES = 32 * 1024 * 1024;
const MAX_CHUNK_ENCRYPTED_BYTES = 40 * 1024 * 1024;

function fail(message) {
  throw new Error(message);
}

function canonicalManifest(manifest) {
  return Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}

function validateManifest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Feature Update manifest is invalid.');
  if (value.schema !== MANIFEST_SCHEMA || value.feature !== FEATURE_NAME) fail('Unsupported Feature Update manifest.');
  if (!VERSION_PATTERN.test(String(value.version || ''))) fail('Feature Update version is invalid.');
  if (!Array.isArray(value.files) || value.files.length !== 16) fail('Feature Update must contain 14 models and 2 metadata files.');
  const names = new Set();
  const assets = new Set();
  for (const entry of value.files) {
    if (!entry || typeof entry !== 'object' || !SAFE_FILE_PATTERN.test(String(entry.name || ''))) fail('Feature Update contains an unsafe file name.');
    if (path.basename(entry.name) !== entry.name || names.has(entry.name.toLowerCase())) fail('Feature Update contains a duplicate file.');
    if (!/^[a-f0-9]{64}$/.test(String(entry.plaintext_sha256 || ''))) fail('Feature Update plaintext hash is invalid.');
    if (!Number.isSafeInteger(entry.plaintext_bytes) || entry.plaintext_bytes < 1 || entry.plaintext_bytes > MAX_PLAINTEXT_BYTES) fail('Feature Update file size is invalid.');
    if (!Array.isArray(entry.chunks) || entry.chunks.length < 1 || entry.chunks.length > 32) fail('Feature Update chunk list is invalid.');
    let chunkPlaintextTotal = 0;
    for (const chunk of entry.chunks) {
      if (!/^feature-\d+\.\d{2}\.\d{3}-\d{3}-\d{3}\.nfchunk$/.test(String(chunk.asset || '')) || assets.has(chunk.asset)) fail('Feature Update asset name is invalid.');
      for (const field of ['plaintext_sha256', 'encrypted_sha256']) {
        if (!/^[a-f0-9]{64}$/.test(String(chunk[field] || ''))) fail(`Feature Update chunk ${field} is invalid.`);
      }
      if (!Number.isSafeInteger(chunk.plaintext_bytes) || chunk.plaintext_bytes < 1 || chunk.plaintext_bytes > MAX_CHUNK_PLAINTEXT_BYTES) fail('Feature Update chunk size is invalid.');
      if (!Number.isSafeInteger(chunk.encrypted_bytes) || chunk.encrypted_bytes < 1 || chunk.encrypted_bytes > MAX_CHUNK_ENCRYPTED_BYTES) fail('Feature Update encrypted chunk size is invalid.');
      if (Buffer.from(String(chunk.nonce_base64 || ''), 'base64').length !== 12) fail('Feature Update nonce is invalid.');
      if (Buffer.from(String(chunk.auth_tag_base64 || ''), 'base64').length !== 16) fail('Feature Update authentication tag is invalid.');
      if (chunk.compression !== 'gzip' || chunk.encryption !== 'aes-256-gcm') fail('Feature Update codec is unsupported.');
      chunkPlaintextTotal += chunk.plaintext_bytes;
      assets.add(chunk.asset);
    }
    if (chunkPlaintextTotal !== entry.plaintext_bytes) fail('Feature Update chunk sizes do not match the file size.');
    names.add(entry.name.toLowerCase());
  }
  const modelCount = value.files.filter((entry) => entry.name.endsWith('.model')).length;
  if (modelCount !== 14 || !names.has('ensemble.json') || !names.has('model_provenance.json')) fail('Feature Update file set is incomplete.');
  return value;
}

function encryptFeatureFile(plaintext, encryptionKey) {
  if (!Buffer.isBuffer(plaintext) || plaintext.length < 1 || plaintext.length > MAX_CHUNK_PLAINTEXT_BYTES) fail('Feature Update source chunk size is invalid.');
  const compressed = zlib.gzipSync(plaintext, { level: 9, mtime: 0 });
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, nonce, { authTagLength: 16 });
  const encrypted = Buffer.concat([cipher.update(compressed), cipher.final()]);
  return { encrypted, nonce, authTag: cipher.getAuthTag() };
}

function decryptFeatureFile(encrypted, entry, encryptionKey) {
  if (!Buffer.isBuffer(encrypted) || encrypted.length !== entry.encrypted_bytes || sha256(encrypted) !== entry.encrypted_sha256) fail(`Feature Update asset failed verification: ${entry.asset}`);
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    encryptionKey,
    Buffer.from(entry.nonce_base64, 'base64'),
    { authTagLength: 16 },
  );
  decipher.setAuthTag(Buffer.from(entry.auth_tag_base64, 'base64'));
  let compressed;
  try {
    compressed = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch {
    fail(`Feature Update asset could not be decrypted: ${entry.asset}`);
  }
  let plaintext;
  try {
    plaintext = zlib.gunzipSync(compressed, { maxOutputLength: entry.plaintext_bytes });
  } catch {
    fail(`Feature Update asset could not be decompressed: ${entry.asset}`);
  }
  if (plaintext.length !== entry.plaintext_bytes || sha256(plaintext) !== entry.plaintext_sha256) fail(`Feature Update plaintext failed verification: ${entry.name}`);
  return plaintext;
}

function signManifest(manifestBytes, privateKey, publicKey) {
  const packageHash = sha256(manifestBytes);
  const signature = crypto.sign(null, manifestBytes, privateKey);
  return {
    format: SIGNATURE_FORMAT,
    algorithm: 'Ed25519',
    key_id: keyIdFromPublicKey(publicKey),
    manifest_sha256: packageHash,
    signature_base64: signature.toString('base64'),
  };
}

function verifyManifestSignature(manifestBytes, signatureDocument, publicKey) {
  if (!signatureDocument || signatureDocument.format !== SIGNATURE_FORMAT || signatureDocument.algorithm !== 'Ed25519') fail('Feature Update signature document is invalid.');
  if (signatureDocument.key_id !== keyIdFromPublicKey(publicKey)) fail('Feature Update signing key does not match.');
  if (signatureDocument.manifest_sha256 !== sha256(manifestBytes)) fail('Feature Update manifest hash does not match.');
  const signature = Buffer.from(String(signatureDocument.signature_base64 || ''), 'base64');
  if (signature.length !== 64 || !crypto.verify(null, manifestBytes, publicKey, signature)) fail('Feature Update signature is invalid.');
  return true;
}

module.exports = {
  FEATURE_NAME,
  MANIFEST_SCHEMA,
  MAX_PLAINTEXT_BYTES,
  MAX_CHUNK_PLAINTEXT_BYTES,
  SIGNATURE_FORMAT,
  canonicalManifest,
  decryptFeatureFile,
  encryptFeatureFile,
  readEncryptionKey,
  sha256,
  signManifest,
  validateManifest,
  verifyManifestSignature,
};
