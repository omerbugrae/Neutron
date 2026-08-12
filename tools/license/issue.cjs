#!/usr/bin/env node
'use strict';
const crypto = require('node:crypto'); const fs = require('node:fs'); const { generateLicense } = require('../../src/license.cjs');
function arg(name) { const i = process.argv.indexOf(name); return i < 0 ? undefined : process.argv[i + 1]; }
const privatePath = arg('--private-key'), deviceHash = arg('--device'), licenseId = arg('--id');
if (!privatePath || !deviceHash || !licenseId) throw new Error('Kullanim: npm run license:issue -- --private-key <license-signing-private.pem> --device <cihaz-hashi> --id <lisans-id> [--customer "Musteri adi"] [--edition Standard] [--expires 2027-01-01T00:00:00Z]');
const privateKey = crypto.createPrivateKey(fs.readFileSync(privatePath));
console.log(generateLicense({ license_id: licenseId, customer_name: arg('--customer') || licenseId, device_hash: deviceHash, edition: arg('--edition') || 'Standard', expires_at: arg('--expires') }, privateKey));
