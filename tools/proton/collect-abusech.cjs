#!/usr/bin/env node
'use strict';

// Collects metadata only. It never downloads or opens a malware sample.
const fs = require('node:fs');
const path = require('node:path');
const { normalizeSource, readJsonFile, validateVersion } = require('./proton-format.cjs');

const URLHAUS_URLS = 'https://urlhaus-api.abuse.ch/v1/urls/recent/';
const URLHAUS_PAYLOADS = 'https://urlhaus-api.abuse.ch/v1/payloads/recent/';
const MALWAREBAZAAR_API = 'https://mb-api.abuse.ch/api/v1/';
const SHA256 = /^[a-f0-9]{64}$/i;

function argument(name) { const index = process.argv.indexOf(name); return index >= 0 ? process.argv[index + 1] : undefined; }
function stop(message) { console.error(`Hata: ${message}`); process.exitCode = 1; }
function boundedInteger(value, fallback, minimum, maximum, label) {
  if (value === undefined) return fallback;
  if (!/^\d+$/.test(value)) throw new Error(`${label} tam sayi olmali.`);
  const result = Number(value);
  if (result < minimum || result > maximum) throw new Error(`${label} ${minimum}-${maximum} arasinda olmali.`);
  return result;
}
function cleanName(...values) {
  const text = values.filter(Boolean).join(' - ').replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return (text || 'abuse.ch malware indicator').slice(0, 160);
}
function resolveContainedPath(baseDirectory, relativePath) {
  if (typeof relativePath !== 'string' || !relativePath.trim() || path.isAbsolute(relativePath)) throw new Error('YARA kaynak yolu gecersiz.');
  const base = path.resolve(baseDirectory);
  const resolved = path.resolve(base, relativePath);
  const relative = path.relative(base, resolved);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('YARA kaynak yolu kaynak klasorunun disina cikamaz.');
  return resolved;
}
function materializeCandidate(candidate, sourcePath, outputPath) {
  const outputDirectory = path.dirname(outputPath);
  const rulesDirectory = path.join(outputDirectory, 'rules');
  const sourceDirectory = path.dirname(sourcePath);
  const rules = (candidate.yara_rules || []).map((entry) => {
    const input = resolveContainedPath(sourceDirectory, entry.path);
    const output = path.join(rulesDirectory, entry.name);
    return { ...entry, path: `rules/${entry.name}`, input, output };
  });
  if (rules.some((entry) => fs.existsSync(entry.output))) throw new Error(`Aday YARA cikti dosyasi zaten var: ${rules.find((entry) => fs.existsSync(entry.output)).output}`);
  fs.mkdirSync(rulesDirectory, { recursive: true });
  try {
    for (const entry of rules) fs.copyFileSync(entry.input, entry.output, fs.constants.COPYFILE_EXCL);
    const outputSource = { ...candidate, yara_rules: rules.map(({ input, output, ...entry }) => entry) };
    normalizeSource(outputSource, outputPath);
    fs.writeFileSync(outputPath, `${JSON.stringify(outputSource, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
    return outputSource;
  } catch (error) {
    for (const entry of rules) if (fs.existsSync(entry.output)) fs.rmSync(entry.output, { force: true });
    throw error;
  }
}
async function requestJson(url, options) {
  const response = await fetch(url, { ...options, headers: { 'Auth-Key': options.authKey, ...(options.headers || {}) }, signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`${new URL(url).hostname} HTTP ${response.status}`);
  try { return await response.json(); } catch { throw new Error(`${new URL(url).hostname} JSON yaniti gecersiz.`); }
}

async function collect(options, dependencies = {}) {
  const fetchJson = dependencies.requestJson || requestJson;
  const sourcePath = path.resolve(options.source);
  const authKey = options.authKey || process.env.NEUTRON_ABUSECH_AUTH_KEY;
  if (!authKey || authKey.length < 16) throw new Error('NEUTRON_ABUSECH_AUTH_KEY tanimli degil veya gecersiz. Anahtari komuta yazmayin.');
  const limit = boundedInteger(options.limit, 500, 1, 1000, '--limit');
  const rawSource = readJsonFile(sourcePath);
  if (!rawSource || typeof rawSource !== 'object' || Array.isArray(rawSource)
    || rawSource.database_name !== 'Proton'
    || typeof rawSource.minimum_engine_version !== 'string'
    || !Array.isArray(rawSource.signatures)
    || !Array.isArray(rawSource.web_indicators)
    || !Array.isArray(rawSource.yara_rules)) {
    throw new Error('Toplama kaynagi Proton temel semasini icermiyor.');
  }
  const base = rawSource;
  const version = validateVersion(options.version);
  const [urls, payloads, bazaar] = await Promise.all([
    fetchJson(`${URLHAUS_URLS}limit/${limit}/`, { method: 'GET', authKey }),
    fetchJson(`${URLHAUS_PAYLOADS}limit/${limit}/`, { method: 'GET', authKey }),
    fetchJson(MALWAREBAZAAR_API, { method: 'POST', authKey, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ query: 'recent_detections', hours: String(options.hours || 24) }) }),
  ]);
  for (const response of [urls, payloads, bazaar]) if (!['ok', 'no_results'].includes(response.query_status)) throw new Error(`Kaynak sorgusu basarisiz: ${response.query_status || 'bilinmeyen yanit'}`);
  const signatures = new Map(base.signatures.map((entry) => [entry.sha256, entry]));
  const indicators = new Map(base.web_indicators.map((entry) => [`${entry.type}:${entry.value}`, entry]));
  let urlhausUrlCount = 0, urlhausPayloadCount = 0, malwareBazaarCount = 0;
  for (const entry of urls.urls || []) {
    const value = typeof entry.url === 'string' ? entry.url.trim().toLowerCase() : '';
    const key = `url:${value}`;
    if (entry.url_status !== 'online' || entry.threat !== 'malware_download' || !/^https?:\/\//.test(value) || indicators.has(key)) continue;
    indicators.set(key, { type: 'url', value, name: cleanName('URLhaus', entry.tags?.join(', '), entry.host), severity: 'high' }); urlhausUrlCount += 1;
  }
  for (const entry of payloads.payloads || []) {
    const digest = typeof entry.sha256_hash === 'string' ? entry.sha256_hash.toLowerCase() : ''; const size = Number(entry.file_size);
    if (!SHA256.test(digest) || !Number.isSafeInteger(size) || size < 0 || signatures.has(digest)) continue;
    signatures.set(digest, { sha256: digest, file_size: size, name: cleanName('URLhaus payload', entry.signature, entry.file_type), severity: 'high' }); urlhausPayloadCount += 1;
  }
  for (const entry of bazaar.data || []) {
    const digest = typeof entry.sha256_hash === 'string' ? entry.sha256_hash.toLowerCase() : ''; const size = Number(entry.file_size);
    if (!SHA256.test(digest) || !Number.isSafeInteger(size) || size < 0 || signatures.has(digest)) continue;
    signatures.set(digest, { sha256: digest, file_size: size, name: cleanName('MalwareBazaar', entry.signature, entry.file_name), severity: 'high' }); malwareBazaarCount += 1;
  }
  const collected = { ...rawSource, database_name: base.database_name, minimum_engine_version: base.minimum_engine_version, version, provenance: {
    source_name: 'Neutron curated abuse.ch threat intelligence', source_url: 'https://urlhaus.abuse.ch/api/', collected_at: new Date().toISOString(),
    license: 'abuse.ch Community API terms and fair-use principles apply',
    review_policy: 'Automated intake accepts only URLhaus online malware_download URLs and file hashes with valid SHA-256 plus byte size; provenance is retained and each candidate must pass package validation before signing.',
  }, signatures: [...signatures.values()], web_indicators: [...indicators.values()] };
  return { source: collected, statistics: { urlhausUrlCount, urlhausPayloadCount, malwareBazaarCount } };
}

async function main() {
  const source = argument('--source'), output = argument('--output'), version = argument('--version');
  if (!source || !output || !version) throw new Error('Kullanim: npm run proton:collect -- --source <definitions.json> --version <x.xx.xxx> --output <definitions.json> [--limit 500] [--hours 24]');
  const outputPath = path.resolve(output);
  if (fs.existsSync(outputPath)) throw new Error(`Cikti zaten var, uzerine yazilmaz: ${outputPath}`);
  const result = await collect({ source, version, limit: argument('--limit'), hours: boundedInteger(argument('--hours'), 24, 1, 168, '--hours') });
  materializeCandidate(result.source, path.resolve(source), outputPath);
  console.log(`Aday Proton kaynagi olusturuldu: ${outputPath}`);
  console.log(`URLhaus URL: +${result.statistics.urlhausUrlCount}; URLhaus dosya hashi: +${result.statistics.urlhausPayloadCount}; MalwareBazaar dosya hashi: +${result.statistics.malwareBazaarCount}`);
  console.log('Dosyayi inceleyin; sonra proton:publish ile imzalayip yayinlayin. API anahtari dosyaya yazilmadi.');
}
if (require.main === module) main().catch((error) => stop(error.message));
module.exports = { collect, materializeCandidate };
