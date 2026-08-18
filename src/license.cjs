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
    // Absolute path, not bare 'reg.exe': resolving through PATH means the
    // lookup can fail in one process context and succeed in another.
    const regPath = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'reg.exe');
    try {
      const output = execFileSync(regPath, ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'], { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
      const match = /MachineGuid\s+REG_SZ\s+([^\r\n]+)/i.exec(output);
      if (match) return `win:${match[1].trim()}`;
    } catch { /* handled below */ }
    // Falling back to hostname+username here would be worse than failing.
    // MachineGuid is machine-wide and identical everywhere; the fallback is
    // per-user, so a single failed lookup silently produces a different
    // device hash. That is exactly how a licence activated by the elevated
    // installer stops matching the same licence read by the desktop app --
    // the key is fine, the binding moved underneath it. Fail loudly instead.
    throw new Error('Cihaz kimligi okunamadi (MachineGuid). Lisans dogrulanamaz.');
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

// --- Licence storage at rest ----------------------------------------------
//
// The activation key used to be written to disk and to HKLM verbatim, so any
// process or account able to read the file could lift a working key straight
// out of it. It is signed and device-bound, so it is worthless on another
// machine -- but on *this* machine it is still the credential, and leaving a
// credential lying around in plaintext is not something to do just because
// the blast radius is small.
//
// Keying: AES-256-GCM under a key derived from the machine's own MachineGuid,
// the same material the device binding already uses. That choice is what
// makes the elevated installer, the desktop app and the LocalSystem service
// all able to read the same file -- a per-user secret would break exactly the
// hand-off the installer depends on.
//
// Be precise about what this is and is not: the key material sits in the
// registry on the same machine, so this is not confidentiality against
// someone who already controls the box, and it is not DPAPI. It raises the
// cost of casual key harvesting and keeps the credential out of plaintext at
// rest. Claiming more would be dishonest.
const STORAGE_PREFIX = 'NTRENC1';
const STORAGE_KDF_SALT = 'Neutron license storage v1';
let storageKeyCache = null;

function storageKey() {
  // scrypt is intentionally slow, and the licence is read on a 5 s cache miss
  // from every IPC guard -- deriving it per read would be a self-inflicted
  // stall. The material cannot change while the process lives.
  if (!storageKeyCache) storageKeyCache = crypto.scryptSync(deviceMaterial(), STORAGE_KDF_SALT, 32);
  return storageKeyCache;
}

function encryptStoredLicense(key) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', storageKey(), nonce, { authTagLength: 16 });
  const ciphertext = Buffer.concat([cipher.update(String(key).trim(), 'utf8'), cipher.final()]);
  return [
    STORAGE_PREFIX,
    nonce.toString('base64'),
    cipher.getAuthTag().toString('base64'),
    ciphertext.toString('base64'),
  ].join(':');
}

// Accepts both envelopes and bare keys. Installations made before this existed
// hold plaintext, and refusing to read them would lock working machines out
// over a storage-format change; they are re-encrypted the next time anything
// calls saveLicense (which every install and activation does).
function decryptStoredLicense(stored) {
  const text = String(stored || '').trim();
  if (!text.startsWith(`${STORAGE_PREFIX}:`)) return text;
  const parts = text.split(':');
  if (parts.length !== 4) throw new Error('Lisans deposu bicimi gecersiz.');
  const [, nonce, authTag, ciphertext] = parts;
  try {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm', storageKey(), Buffer.from(nonce, 'base64'), { authTagLength: 16 },
    );
    decipher.setAuthTag(Buffer.from(authTag, 'base64'));
    return Buffer.concat([
      decipher.update(Buffer.from(ciphertext, 'base64')), decipher.final(),
    ]).toString('utf8').trim();
  } catch {
    // Wrong machine, tampered envelope, or a MachineGuid that changed under
    // us. All three mean the same thing to every caller: there is no usable
    // licence here.
    throw new Error('Kayitli lisans bu bilgisayarda cozulemedi.');
  }
}

module.exports = {
  LICENSE_FORMAT,
  PUBLIC_KEY_PATH,
  decryptStoredLicense,
  deviceHash,
  encryptStoredLicense,
  generateLicense,
  parseLicense,
};
