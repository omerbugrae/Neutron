#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { publish } = require('./publish.cjs');

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'neutron-proton-publish-'));
try {
  const keysDirectory = path.join(testRoot, 'keys');
  const outputDirectory = path.join(testRoot, 'dist');
  fs.mkdirSync(keysDirectory, { recursive: true });
  const encryptionKey = crypto.randomBytes(32);
  const keys = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(path.join(keysDirectory, 'proton-encryption.key'), `${encryptionKey.toString('base64')}\n`);
  fs.writeFileSync(
    path.join(keysDirectory, 'proton-signing-private.pem'),
    keys.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  );
  fs.writeFileSync(
    path.join(keysDirectory, 'proton-signing-public.pem'),
    keys.publicKey.export({ type: 'spki', format: 'pem' }),
  );

  const calls = [];
  const runGh = (argumentsList) => {
    calls.push(argumentsList);
    if (argumentsList[0] === 'release' && argumentsList[1] === 'view') return { status: 1, stdout: '', stderr: 'not found' };
    return { status: 0, stdout: '', stderr: '' };
  };
  const result = publish({
    source: path.join(__dirname, 'examples', 'definitions.json'),
    keys: keysDirectory,
    output: outputDirectory,
    repository: 'omerbugrae/NeutronProton',
  }, { runGh });

  assert.equal(result.tag, 'proton-v1.00.006');
  assert.equal(fs.existsSync(result.packagePath), true);
  assert.equal(fs.existsSync(result.signaturePath), true);
  const createCall = calls.find((call) => call[0] === 'release' && call[1] === 'create');
  assert.ok(createCall, 'Release oluşturma çağrısı yapılmalıydı.');
  assert.ok(createCall.includes('proton-v1.00.006'));
  assert.ok(createCall.includes('--repo'));
  assert.equal(calls.some((call) => call.join(' ').includes('proton-signing-private.pem')), false);
  assert.equal(calls.some((call) => call.join(' ').includes('proton-encryption.key')), false);
  console.log('Proton otomatik yayın öz testi başarılı.');
} finally {
  const resolvedRoot = path.resolve(testRoot);
  const resolvedTemp = path.resolve(os.tmpdir());
  if (resolvedRoot.startsWith(`${resolvedTemp}${path.sep}`)) {
    fs.rmSync(resolvedRoot, { recursive: true, force: true });
  }
}
