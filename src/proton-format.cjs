'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const PACKAGE_MAGIC = Buffer.from('NPDBX001', 'ascii');
const PACKAGE_FORMAT = 'neutron-proton-package';
const PACKAGE_FORMAT_VERSION = 1;
const PAYLOAD_SCHEMA = 'neutron.proton.payload/v1';
const SIGNATURE_FORMAT = 'neutron-proton-signature/v1';
const VERSION_PATTERN = /^\d+\.\d{2}\.\d{3}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const MAX_SOURCE_BYTES = 64 * 1024 * 1024;
const MAX_RULE_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_RULE_BYTES = 16 * 1024 * 1024;
const MAX_SIGNATURES = 1_000_000;
const MAX_RULES = 256;
const MAX_WEB_INDICATORS = 500_000;
const MAX_HEADER_BYTES = 64 * 1024;
const SOURCE_URL_PATTERN = /^https:\/\/[^\s/$.?#][^\s]*$/i;

function fail(message) {
  throw new Error(message);
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function keyIdFromPublicKey(publicKey) {
  const normalizedKey = publicKey?.type === 'public'
    ? publicKey
    : crypto.createPublicKey(publicKey);
  const der = normalizedKey.export({
    type: 'spki',
    format: 'der',
  });
  return `ed25519:${sha256(der).slice(0, 24)}`;
}

function readLimitedFile(filePath, maximumBytes, label) {
  const stats = fs.statSync(filePath);
  if (!stats.isFile()) fail(`${label} normal bir dosya değil: ${filePath}`);
  if (stats.size > maximumBytes) {
    fail(`${label} izin verilen boyutu aşıyor (${stats.size} > ${maximumBytes}).`);
  }
  return fs.readFileSync(filePath);
}

function readJsonFile(filePath, maximumBytes = MAX_SOURCE_BYTES) {
  const bytes = readLimitedFile(filePath, maximumBytes, 'JSON kaynağı');
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail(`Geçersiz JSON (${filePath}): ${error.message}`);
  }
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${label} bir JSON nesnesi olmalı.`);
  }
  return value;
}

function cleanText(value, label, maximumLength) {
  if (typeof value !== 'string') fail(`${label} metin olmalı.`);
  const result = value.trim();
  if (!result || result.length > maximumLength) {
    fail(`${label} 1-${maximumLength} karakter arasında olmalı.`);
  }
  if (/[\u0000-\u001f\u007f]/.test(result)) fail(`${label} kontrol karakteri içeremez.`);
  return result;
}

function validateVersion(value, label = 'version') {
  const version = cleanText(value, label, 32);
  if (!VERSION_PATTERN.test(version)) {
    fail(`${label}, x.xx.xxx biçiminde olmalı (örnek: 1.00.002).`);
  }
  return version;
}

function normalizeSeverity(value) {
  const severity = cleanText(value, 'signature.severity', 16).toLowerCase();
  if (!['low', 'medium', 'high', 'critical'].includes(severity)) {
    fail(`Desteklenmeyen önem seviyesi: ${severity}`);
  }
  return severity;
}

function normalizeProvenance(value) {
  assertPlainObject(value, 'provenance');
  const collectedAt = cleanText(value.collected_at, 'provenance.collected_at', 64);
  if (Number.isNaN(Date.parse(collectedAt))) fail('provenance.collected_at must be an ISO timestamp.');
  const sourceUrl = cleanText(value.source_url, 'provenance.source_url', 1024);
  if (!SOURCE_URL_PATTERN.test(sourceUrl)) fail('provenance.source_url must be an HTTPS URL.');
  return {
    source_name: cleanText(value.source_name, 'provenance.source_name', 120),
    source_url: sourceUrl,
    collected_at: collectedAt,
    license: cleanText(value.license, 'provenance.license', 160),
    review_policy: cleanText(value.review_policy, 'provenance.review_policy', 240),
  };
}

function resolveContainedPath(baseDirectory, relativePath, label) {
  const cleanRelative = cleanText(relativePath, label, 240);
  if (path.isAbsolute(cleanRelative)) fail(`${label} mutlak yol olamaz.`);
  const base = path.resolve(baseDirectory);
  const resolved = path.resolve(base, cleanRelative);
  const relative = path.relative(base, resolved);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
    fail(`${label} kaynak klasörünün dışına çıkamaz: ${cleanRelative}`);
  }
  return resolved;
}

function normalizeSource(source, sourcePath) {
  assertPlainObject(source, 'Proton kaynağı');
  const sourceDirectory = path.dirname(path.resolve(sourcePath));
  const databaseName = cleanText(source.database_name, 'database_name', 32);
  if (databaseName !== 'Proton') fail('database_name yalnızca "Proton" olabilir.');
  const version = validateVersion(source.version);
  const minimumEngineVersion = cleanText(
    source.minimum_engine_version || '0.1.0',
    'minimum_engine_version',
    32,
  );
  const provenance = normalizeProvenance(source.provenance);

  if (!Array.isArray(source.signatures)) fail('signatures bir dizi olmalı.');
  if (source.signatures.length > MAX_SIGNATURES) fail('Çok fazla hash imzası var.');
  const seenHashes = new Set();
  const signatures = source.signatures.map((entry, index) => {
    assertPlainObject(entry, `signatures[${index}]`);
    const digest = cleanText(entry.sha256, `signatures[${index}].sha256`, 64).toLowerCase();
    if (!SHA256_PATTERN.test(digest)) fail(`Geçersiz SHA-256: signatures[${index}]`);
    if (seenHashes.has(digest)) fail(`Yinelenen SHA-256: ${digest}`);
    seenHashes.add(digest);
    if (!Number.isSafeInteger(entry.file_size) || entry.file_size < 0) {
      fail(`signatures[${index}].file_size negatif olmayan tam sayı olmalı.`);
    }
    return {
      sha256: digest,
      file_size: entry.file_size,
      name: cleanText(entry.name, `signatures[${index}].name`, 160),
      severity: normalizeSeverity(entry.severity),
    };
  });

  if (!Array.isArray(source.yara_rules)) fail('yara_rules bir dizi olmalı.');
  if (source.yara_rules.length > MAX_RULES) fail('Çok fazla YARA kural dosyası var.');
  const seenRuleNames = new Set();
  let totalRuleBytes = 0;
  const yaraRules = source.yara_rules.map((entry, index) => {
    assertPlainObject(entry, `yara_rules[${index}]`);
    const fileName = cleanText(entry.name, `yara_rules[${index}].name`, 120);
    if (path.basename(fileName) !== fileName || !/^[a-zA-Z0-9._-]+\.yar$/.test(fileName)) {
      fail(`Geçersiz YARA dosya adı: ${fileName}`);
    }
    const normalizedName = fileName.toLowerCase();
    if (seenRuleNames.has(normalizedName)) fail(`Yinelenen YARA dosyası: ${fileName}`);
    seenRuleNames.add(normalizedName);
    const rulePath = resolveContainedPath(
      sourceDirectory,
      entry.path,
      `yara_rules[${index}].path`,
    );
    const contentBytes = readLimitedFile(rulePath, MAX_RULE_BYTES, `YARA kuralı ${fileName}`);
    totalRuleBytes += contentBytes.length;
    if (totalRuleBytes > MAX_TOTAL_RULE_BYTES) fail('YARA kurallarının toplam boyutu çok büyük.');
    const content = contentBytes.toString('utf8');
    if (content.includes('\u0000')) fail(`${fileName} ikili veri içeriyor.`);
    return {
      name: fileName,
      sha256: sha256(contentBytes),
      content,
    };
  });

  const rawWebIndicators = source.web_indicators || [];
  if (!Array.isArray(rawWebIndicators) || rawWebIndicators.length > MAX_WEB_INDICATORS) fail('web_indicators listesi geçersiz.');
  const seenWebIndicators = new Set();
  const webIndicators = rawWebIndicators.map((entry, index) => {
    assertPlainObject(entry, `web_indicators[${index}]`);
    const type = cleanText(entry.type, `web_indicators[${index}].type`, 16).toLowerCase();
    if (!['domain', 'url'].includes(type)) fail(`Desteklenmeyen web göstergesi türü: ${type}`);
    let value = cleanText(entry.value, `web_indicators[${index}].value`, 2048).toLowerCase();
    if (type === 'domain') value = value.replace(/^\.+|\.+$/g, '');
    if ((type === 'url' && !/^https?:\/\//.test(value)) || (type === 'domain' && !/^[a-z0-9.-]+$/.test(value))) fail(`Geçersiz web göstergesi: ${index}`);
    const identity = `${type}:${value}`;
    if (seenWebIndicators.has(identity)) fail(`Yinelenen web göstergesi: ${value}`);
    seenWebIndicators.add(identity);
    return { type, value, name: cleanText(entry.name, `web_indicators[${index}].name`, 160), severity: normalizeSeverity(entry.severity) };
  });

  if (signatures.length === 0 && yaraRules.length === 0 && webIndicators.length === 0) {
    fail('Proton paketi en az bir hash imzası veya YARA kuralı içermeli.');
  }
  return {
    schema: PAYLOAD_SCHEMA,
    database_name: databaseName,
    version,
    minimum_engine_version: minimumEngineVersion,
    provenance,
    created_at: new Date().toISOString(),
    signatures,
    yara_rules: yaraRules,
    web_indicators: webIndicators,
  };
}

function readEncryptionKey(keyPath) {
  const encoded = readLimitedFile(keyPath, 1024, 'AES anahtarı').toString('utf8').trim();
  let key;
  if (/^[a-fA-F0-9]{64}$/.test(encoded)) key = Buffer.from(encoded, 'hex');
  else key = Buffer.from(encoded, 'base64');
  if (key.length !== 32) fail('AES anahtarı tam olarak 32 bayt olmalı.');
  return key;
}

function buildPackage(payload, encryptionKey, privateKey, publicKey) {
  const keyId = keyIdFromPublicKey(publicKey);
  const descriptor = {
    format: PACKAGE_FORMAT,
    format_version: PACKAGE_FORMAT_VERSION,
    database_name: payload.database_name,
    database_version: payload.version,
    created_at: payload.created_at,
    compression: 'gzip',
    encryption: 'aes-256-gcm',
    signing_key_id: keyId,
  };
  const aad = Buffer.from(JSON.stringify(descriptor), 'utf8');
  const payloadBytes = Buffer.from(JSON.stringify(payload), 'utf8');
  const compressed = zlib.gzipSync(payloadBytes, { level: 9, mtime: 0 });
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const header = {
    ...descriptor,
    nonce_base64: nonce.toString('base64'),
    auth_tag_base64: authTag.toString('base64'),
    payload_sha256: sha256(payloadBytes),
    ciphertext_sha256: sha256(ciphertext),
    encrypted_bytes: ciphertext.length,
  };
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  if (headerBytes.length > MAX_HEADER_BYTES) fail('Paket başlığı çok büyük.');
  const headerLength = Buffer.alloc(4);
  headerLength.writeUInt32BE(headerBytes.length, 0);
  const packageBytes = Buffer.concat([PACKAGE_MAGIC, headerLength, headerBytes, ciphertext]);
  const signature = crypto.sign(null, packageBytes, privateKey);
  return {
    packageBytes,
    signatureDocument: {
      format: SIGNATURE_FORMAT,
      algorithm: 'Ed25519',
      key_id: keyId,
      package_sha256: sha256(packageBytes),
      signature_base64: signature.toString('base64'),
    },
    header,
  };
}

function parsePackage(packageBytes) {
  if (!Buffer.isBuffer(packageBytes)) fail('Paket Buffer olmalı.');
  if (packageBytes.length < PACKAGE_MAGIC.length + 4) fail('Proton paketi eksik.');
  if (!packageBytes.subarray(0, PACKAGE_MAGIC.length).equals(PACKAGE_MAGIC)) {
    fail('Proton paket sihirli değeri geçersiz.');
  }
  const headerLength = packageBytes.readUInt32BE(PACKAGE_MAGIC.length);
  if (headerLength < 2 || headerLength > MAX_HEADER_BYTES) fail('Paket başlık boyutu geçersiz.');
  const headerStart = PACKAGE_MAGIC.length + 4;
  const ciphertextStart = headerStart + headerLength;
  if (ciphertextStart >= packageBytes.length) fail('Paket şifreli içerik taşımıyor.');
  let header;
  try {
    header = JSON.parse(packageBytes.subarray(headerStart, ciphertextStart).toString('utf8'));
  } catch (error) {
    fail(`Paket başlığı okunamadı: ${error.message}`);
  }
  assertPlainObject(header, 'Paket başlığı');
  if (header.format !== PACKAGE_FORMAT || header.format_version !== PACKAGE_FORMAT_VERSION) {
    fail('Desteklenmeyen Proton paket biçimi.');
  }
  const ciphertext = packageBytes.subarray(ciphertextStart);
  if (sha256(ciphertext) !== header.ciphertext_sha256) fail('Şifreli içerik özeti uyuşmuyor.');
  return { header, ciphertext };
}

function verifyPackageSignature(packageBytes, signatureDocument, publicKey) {
  assertPlainObject(signatureDocument, 'İmza belgesi');
  if (signatureDocument.format !== SIGNATURE_FORMAT || signatureDocument.algorithm !== 'Ed25519') {
    fail('Desteklenmeyen Proton imza biçimi.');
  }
  const expectedKeyId = keyIdFromPublicKey(publicKey);
  if (signatureDocument.key_id !== expectedKeyId) fail('İmza anahtarı kimliği uyuşmuyor.');
  if (signatureDocument.package_sha256 !== sha256(packageBytes)) fail('Paket SHA-256 özeti uyuşmuyor.');
  const signature = Buffer.from(signatureDocument.signature_base64 || '', 'base64');
  if (signature.length !== 64 || !crypto.verify(null, packageBytes, publicKey, signature)) {
    fail('Proton paketinin dijital imzası geçersiz.');
  }
  return true;
}

function decryptPackage(packageBytes, encryptionKey) {
  const { header, ciphertext } = parsePackage(packageBytes);
  const descriptor = {
    format: header.format,
    format_version: header.format_version,
    database_name: header.database_name,
    database_version: header.database_version,
    created_at: header.created_at,
    compression: header.compression,
    encryption: header.encryption,
    signing_key_id: header.signing_key_id,
  };
  const nonce = Buffer.from(header.nonce_base64 || '', 'base64');
  const authTag = Buffer.from(header.auth_tag_base64 || '', 'base64');
  if (nonce.length !== 12 || authTag.length !== 16) fail('Paket AES-GCM parametreleri geçersiz.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, nonce, {
    authTagLength: 16,
  });
  decipher.setAAD(Buffer.from(JSON.stringify(descriptor), 'utf8'));
  decipher.setAuthTag(authTag);
  let compressed;
  try {
    compressed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    fail('Paket çözülemedi: anahtar yanlış veya paket değiştirilmiş.');
  }
  let payloadBytes;
  try {
    payloadBytes = zlib.gunzipSync(compressed, { maxOutputLength: MAX_SOURCE_BYTES });
  } catch (error) {
    fail(`Paket açma işlemi başarısız: ${error.message}`);
  }
  if (sha256(payloadBytes) !== header.payload_sha256) fail('Çözülmüş veri özeti uyuşmuyor.');
  let payload;
  try {
    payload = JSON.parse(payloadBytes.toString('utf8'));
  } catch (error) {
    fail(`Çözülmüş Proton verisi okunamadı: ${error.message}`);
  }
  if (payload.schema !== PAYLOAD_SCHEMA || payload.version !== header.database_version) {
    fail('Çözülmüş Proton şeması veya sürümü geçersiz.');
  }
  return { header, payload };
}

module.exports = {
  PACKAGE_MAGIC,
  SIGNATURE_FORMAT,
  buildPackage,
  decryptPackage,
  keyIdFromPublicKey,
  normalizeSource,
  normalizeProvenance,
  parsePackage,
  readEncryptionKey,
  readJsonFile,
  sha256,
  validateVersion,
  verifyPackageSignature,
};
