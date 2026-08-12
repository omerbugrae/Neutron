#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { generateLicense } = require('../../src/license.cjs');
const keys = crypto.generateKeyPairSync('ed25519');
const key = generateLicense({ license_id: 'test-license', edition: 'Standard', device_hash: 'a'.repeat(64), expires_at: '2099-01-01T00:00:00.000Z' }, keys.privateKey);
assert.match(key, /^NTR1-(?:[0-9A-HJKMNP-TV-Z]{5}-)*[0-9A-HJKMNP-TV-Z]{1,5}$/);
assert.ok(key.includes('-'));
console.log('Lisans imzalama oz testi basarili.');
