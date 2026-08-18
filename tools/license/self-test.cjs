#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { decryptStoredLicense, encryptStoredLicense, generateLicense } = require('../../src/license.cjs');
const keys = crypto.generateKeyPairSync('ed25519');
const key = generateLicense({ license_id: 'test-license', edition: 'Standard', device_hash: 'a'.repeat(64), expires_at: '2099-01-01T00:00:00.000Z' }, keys.privateKey);
assert.match(key, /^NTR1-(?:[0-9A-HJKMNP-TV-Z]{5}-)*[0-9A-HJKMNP-TV-Z]{1,5}$/);
assert.ok(key.includes('-'));

// Storage envelope. The properties that matter are that the key does not
// survive to disk in readable form, that it comes back byte-identical, and
// that installations predating the envelope still load.
const stored = encryptStoredLicense(key);
assert.ok(!stored.includes(key), 'sifreli depoda anahtar duz metin gorunuyor');
assert.match(stored, /^NTRENC1:/);
assert.equal(decryptStoredLicense(stored), key);
assert.equal(decryptStoredLicense(key), key, 'eski duz metin kayitlar okunabilir kalmali');
assert.equal(decryptStoredLicense(`${stored}\n`), key, 'sondaki bosluk depoyu bozmamali');

// Any edit to the envelope must fail closed rather than return partial data.
const parts = stored.split(':');
const flipped = Buffer.from(parts[3], 'base64');
flipped[0] ^= 0xff;
assert.throws(() => decryptStoredLicense([parts[0], parts[1], parts[2], flipped.toString('base64')].join(':')));
assert.throws(() => decryptStoredLicense('NTRENC1:bozuk'));

// Two encryptions of the same key must differ: a fixed nonce would make the
// stored value a stable fingerprint of the licence across machines.
assert.notEqual(encryptStoredLicense(key), encryptStoredLicense(key));

console.log('Lisans imzalama ve depolama oz testi basarili.');
