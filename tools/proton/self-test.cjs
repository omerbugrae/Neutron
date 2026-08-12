#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {
  buildPackage,
  decryptPackage,
  parsePackage,
  verifyPackageSignature,
} = require('./proton-format.cjs');

const encryptionKey = crypto.randomBytes(32);
const keys = crypto.generateKeyPairSync('ed25519');
const payload = {
  schema: 'neutron.proton.payload/v1',
  database_name: 'Proton',
  version: '1.00.002',
  minimum_engine_version: '0.1.0',
  provenance: { source_name: 'Self test', source_url: 'https://example.invalid/proton', collected_at: '2026-08-11T00:00:00.000Z', license: 'Test only', review_policy: 'Automated verification only' },
  created_at: '2026-08-11T00:00:00.000Z',
  signatures: [{
    sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
    file_size: 68,
    name: 'EICAR güvenli test imzası',
    severity: 'high',
  }],
  yara_rules: [{
    name: 'safe_test.yar',
    sha256: '0'.repeat(64),
    content: 'rule Neutron_Safe_Test { condition: false }',
  }],
};

const built = buildPackage(payload, encryptionKey, keys.privateKey, keys.publicKey);
assert.equal(verifyPackageSignature(built.packageBytes, built.signatureDocument, keys.publicKey), true);
assert.equal(parsePackage(built.packageBytes).header.database_version, payload.version);
const decrypted = decryptPackage(built.packageBytes, encryptionKey);
assert.deepEqual(decrypted.payload, payload);

const changedPackage = Buffer.from(built.packageBytes);
changedPackage[changedPackage.length - 1] ^= 1;
assert.throws(
  () => verifyPackageSignature(changedPackage, built.signatureDocument, keys.publicKey),
  /özeti uyuşmuyor/,
);
assert.throws(
  () => decryptPackage(built.packageBytes, crypto.randomBytes(32)),
  /Paket çözülemedi/,
);

console.log('Proton paket biçimi öz testi başarılı.');
