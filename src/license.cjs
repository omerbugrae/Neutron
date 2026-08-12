'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const LICENSE_FORMAT = 'neutron-license/v1';
const PUBLIC_KEY_PATH = path.join(__dirname, 'security', 'license-signing-public.pem');
const DISPLAY_PREFIX = 'NTR1';
const BASE32_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function base64url(value) { return Buffer.from(value).toString('base64url'); }
function unbase64url(value) { return Buffer.from(value, 'base64url'); }
function canonical(value) { return Buffer.from(JSON.stringify(value), 'utf8'); }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function base32Encode(bytes) {
  let accumulator = 0; let bits = 0; let output = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte; bits += 8;
    while (bits >= 5) { output += BASE32_ALPHABET[(accumulator >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) output += BASE32_ALPHABET[(accumulator << (5 - bits)) & 31];
  return output;
}
function base32Decode(value) {
  let accumulator = 0; let bits = 0; const bytes = [];
  for (const character of value) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index < 0) throw new Error('Lisans anahtari karakteri gecersiz.');
    accumulator = (accumulator << 5) | index; bits += 5;
    if (bits >= 8) { bytes.push((accumulator >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(bytes);
}
function formatActivationKey(bytes) {
  const encoded = base32Encode(bytes);
  return `${DISPLAY_PREFIX}-${encoded.match(/.{1,5}/g).join('-')}`;
}
function clean(value, label, max) {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > max || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} gecersiz.`);
  return value.trim();
}
function deviceMaterial() {
  if (process.platform === 'win32') {
    try {
      const output = execFileSync('reg.exe', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'], { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
      const match = /MachineGuid\s+REG_SZ\s+([^\r\n]+)/i.exec(output);
      if (match) return `win:${match[1].trim()}`;
    } catch { /* fall through */ }
  }
  return `${process.platform}:${os.hostname()}:${os.userInfo().username}`;
}
function deviceHash() { return sha256(`Neutron device binding v1|${deviceMaterial()}`); }
function readPublicKey() {
  if (!fs.existsSync(PUBLIC_KEY_PATH)) throw new Error('Lisans dogrulama anahtari bu derlemeye eklenmemis.');
  const key = fs.readFileSync(PUBLIC_KEY_PATH);
  try { return crypto.createPublicKey(key); } catch { throw new Error('Lisans dogrulama acik anahtari gecersiz.'); }
}
function parseLicense(key) {
  const raw = clean(key, 'Lisans anahtari', 12000);
  let payload; let signature;
  if (raw.toUpperCase().startsWith(`${DISPLAY_PREFIX}-`)) {
    const bytes = base32Decode(raw.toUpperCase().replace(/-/g, '').slice(DISPLAY_PREFIX.length));
    if (bytes.length < 67) throw new Error('Lisans anahtari eksik.');
    const payloadLength = bytes.readUInt16BE(0);
    if (payloadLength < 2 || payloadLength + 66 !== bytes.length) throw new Error('Lisans anahtari bicimi gecersiz.');
    try { payload = JSON.parse(bytes.subarray(2, 2 + payloadLength).toString('utf8')); } catch { throw new Error('Lisans verisi okunamadi.'); }
    signature = bytes.subarray(2 + payloadLength);
  } else throw new Error('Eski lisans bicimi desteklenmiyor. NTR1 ile baslayan yeni aktivasyon anahtari kullanin.');
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Lisans verisi gecersiz.');
  if (signature.length !== 64 || !crypto.verify(null, canonical(payload), readPublicKey(), signature)) throw new Error('Lisans imzasi gecersiz.');
  if (payload.format !== LICENSE_FORMAT) throw new Error('Desteklenmeyen lisans bicimi.');
  clean(payload.license_id, 'Lisans kimligi', 80); clean(payload.device_hash, 'Cihaz baglantisi', 64);
  if (!/^[a-f0-9]{64}$/i.test(payload.device_hash)) throw new Error('Lisans cihaz baglantisi gecersiz.');
  if (payload.device_hash !== deviceHash()) throw new Error('Bu lisans farkli bir bilgisayara bagli.');
  if (payload.expires_at && (!Number.isFinite(Date.parse(payload.expires_at)) || Date.parse(payload.expires_at) < Date.now())) throw new Error('Lisansin suresi dolmus.');
  return { licenseId: payload.license_id, customerName: clean(payload.customer_name || payload.license_id, 'Musteri adi', 100), edition: clean(payload.edition || 'Standard', 'Surum', 40), expiresAt: payload.expires_at || null, issuedAt: payload.issued_at || null, deviceHash: payload.device_hash };
}
function generateLicense(payload, privateKey) {
  const normalized = { format: LICENSE_FORMAT, license_id: clean(payload.license_id, 'Lisans kimligi', 80), customer_name: clean(payload.customer_name || payload.license_id, 'Musteri adi', 100), edition: clean(payload.edition || 'Standard', 'Surum', 40), issued_at: new Date().toISOString(), device_hash: clean(payload.device_hash, 'Cihaz baglantisi', 64), ...(payload.expires_at ? { expires_at: payload.expires_at } : {}) };
  if (!/^[a-f0-9]{64}$/i.test(normalized.device_hash)) throw new Error('Cihaz baglantisi 64 karakterlik SHA-256 olmali.');
  const signature = crypto.sign(null, canonical(normalized), privateKey);
  const body = canonical(normalized);
  if (body.length > 65535) throw new Error('Lisans verisi cok buyuk.');
  const length = Buffer.alloc(2); length.writeUInt16BE(body.length);
  return formatActivationKey(Buffer.concat([length, body, signature]));
}
module.exports = { LICENSE_FORMAT, PUBLIC_KEY_PATH, deviceHash, generateLicense, parseLicense };
