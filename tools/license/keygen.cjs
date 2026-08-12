#!/usr/bin/env node
'use strict';
const crypto = require('node:crypto'); const fs = require('node:fs'); const path = require('node:path');
function argument(name) { const index = process.argv.indexOf(name); return index >= 0 ? process.argv[index + 1] : undefined; }
const output = argument('--output'); const publicOutput = argument('--public-output');
if (!output || !publicOutput) throw new Error('Kullanim: npm run license:keygen -- --output <proje-disi-gizli-klasor> --public-output <src/security/license-signing-public.pem>');
const privatePath = path.join(path.resolve(output), 'license-signing-private.pem'); const publicPath = path.resolve(publicOutput);
if (fs.existsSync(privatePath) || fs.existsSync(publicPath)) throw new Error('Anahtar dosyalarinin uzerine yazilmaz.');
const keys = crypto.generateKeyPairSync('ed25519'); fs.mkdirSync(path.dirname(privatePath), { recursive: true }); fs.mkdirSync(path.dirname(publicPath), { recursive: true });
fs.writeFileSync(privatePath, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' }); fs.writeFileSync(publicPath, keys.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644, flag: 'wx' });
console.log(`Ozel lisans anahtari: ${privatePath}`); console.log(`Uygulama acik anahtari: ${publicPath}`);
