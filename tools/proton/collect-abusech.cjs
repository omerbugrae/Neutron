#!/usr/bin/env node
'use strict';

// Collects metadata only. It never downloads or opens a malware sample.
const fs = require('node:fs');
const path = require('node:path');
const { normalizeSource, readJsonFile, validateVersion } = require('../../src/proton-format.cjs');
const { resolveNextVersion } = require('./next-version.cjs');

const URLHAUS_URLS = 'https://urlhaus-api.abuse.ch/v1/urls/recent/';
const URLHAUS_PAYLOADS = 'https://urlhaus-api.abuse.ch/v1/payloads/recent/';
const MALWAREBAZAAR_API = 'https://mb-api.abuse.ch/api/v1/';
const THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1/';
const SHA256 = /^[a-f0-9]{64}$/i;
const DOMAIN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const THREATFOX_MINIMUM_CONFIDENCE = 75;
// MalwareBazaar tum arsivi tek uc noktadan vermiyor ve liste uc noktalari (get_siglist/get_taglist) yok.
// Hacim bu yuzden uc eksende taranir: aile, etiket ve dosya turu. Ekseler cakisir; tekrarlar SHA-256 ile elenir.
const MALWAREBAZAAR_FAMILIES = [
  'AgentTesla', 'AsyncRAT', 'RedLineStealer', 'Formbook', 'Loki', 'SnakeKeylogger', 'RemcosRAT', 'NanoCore',
  'njrat', 'QuasarRAT', 'Vidar', 'Raccoon', 'Amadey', 'Smoke Loader', 'GuLoader', 'ModiLoader', 'Mirai',
  'Emotet', 'IcedID', 'Qakbot', 'TrickBot', 'Dridex', 'Ursnif', 'BumbleBee', 'CobaltStrike', 'Sliver',
  'Lumma', 'StealC', 'Rhadamanthys', 'DCRat', 'XWorm', 'Warzone', 'AveMariaRAT', 'Nemty', 'LockBit',
  'BlackCat', 'Conti', 'Ryuk', 'Phobos', 'STOP', 'Dharma', 'Sodinokibi', 'Mallox', 'GandCrab',
  'Gozi', 'Zloader', 'Danabot', 'Arkei', 'Azorult', 'Mars Stealer', 'MassLogger', 'Matiex', 'Nexus',
  'PrivateLoader', 'Socks5Systemz', 'Tofsee', 'Pikabot', 'Latrodectus', 'CoinMiner', 'XMRig', 'Neshta',
  'Adwind', 'Agent', 'Ammyy', 'Andromeda', 'Anubis', 'ArechClient2', 'Ave Maria', 'BackNet', 'BanLoad',
  'BazaLoader', 'BitRAT', 'BlackBasta', 'BlackGuard', 'BlackMoon', 'BlackNET', 'Bladabindi', 'Blister',
  'Bozok', 'BruteRatel', 'Buer', 'ChromeLoader', 'Chthonic', 'Clop', 'CryptBot', 'Cryptolocker',
  'CyberGate', 'Dacls', 'DarkComet', 'DarkGate', 'DarkTrack', 'DarkVNC', 'Deimos', 'DiamondFox',
  'Djvu', 'DridexLoader', 'Ekans', 'ElectroRAT', 'Emmenhtal', 'ERMAC', 'Eternity', 'Ficker', 'FlawedAmmyy',
  'Gafgyt', 'Gh0stRAT', 'Glupteba', 'Gootkit', 'Grandoreiro', 'Hancitor', 'Hawkeye', 'Heodo', 'HijackLoader',
  'Hive', 'HydraCrypt', 'Imminent', 'Jigsaw', 'Kelihos', 'KeyBase', 'Kimsuky', 'Kovter', 'Kutaki',
  'LimeRAT', 'LokiBot', 'Lokibot', 'Maze', 'Medusa', 'MedusaLocker', 'Metasploit', 'MetaStealer',
  'Meterpreter', 'MimiKatz', 'Mispadu', 'Mekotio', 'NetSupport', 'NetWire', 'NjRAT', 'Nokoyawa',
  'Nymaim', 'Obfuscator', 'Octopus', 'Orcus', 'Ousaban', 'Panda', 'ParallaxRAT', 'PlugX', 'PoisonIvy',
  'Predator', 'Punisher', 'PureCrypter', 'PureLogs', 'Pony', 'PyInstaller', 'PythonStealer', 'Rekoobe',
  'Revenge', 'RevengeRAT', 'Rhysida', 'RisePro', 'RomCom', 'RuRAT', 'Ryzerlo', 'SectopRAT', 'ServHelper',
  'ShadowPad', 'SharpHound', 'Sharik', 'Shiz', 'SilentBuilder', 'SmokeLoader', 'Snatch', 'SolarMarker',
  'Sorillus', 'Spynote', 'Stop', 'Strela', 'Stealerium', 'SystemBC', 'TeamBot', 'TeslaCrypt', 'Tinba',
  'TinyNuke', 'Trickbot', 'Truebot', 'Ta505', 'Unam', 'Upatre', 'Valak', 'VenomRAT', 'Vjw0rm',
  'WannaCry', 'WhiteSnake', 'WSHRAT', 'Wacatac', 'XLoader', 'XRed', 'Yakuza', 'Zebrocy', 'Zeus',
  'ZeusPanda', 'Zharkbot', 'ZgRAT', 'Zusy', 'a310Logger', 'ClipBanker', 'Coinminer', 'Downloader',
  'Dropper', 'Keylogger', 'Ransomware', 'Stealer', 'Trojan', 'Worm', 'Backdoor', 'Rootkit',
];
const MALWAREBAZAAR_TAGS = [
  'opendir', 'phishing', 'banker', 'loader', 'rat', 'stealer', 'ransomware', 'miner', 'keylogger',
  'apt', 'booking', 'invoice', 'payment', 'purchase-order', 'shipping', 'resume', 'signed', 'unsigned',
  'upx', 'themida', 'vmprotect', 'obfuscated', 'packed', 'dotnet', 'delphi', 'golang', 'rust', 'nsis',
  'autoit', 'py2exe', 'pyinstaller', 'inno', 'msix', 'appx', 'clickfix', 'fakecaptcha', 'smtp',
  'telegram', 'discord', 'ftp', 'tor', 'proxy', 'anti-vm', 'anti-debug', 'exfil', 'webinject',
  'maldoc', 'macro', 'vba', 'shellcode', 'downloader', 'dropper', 'wiper', 'worm', 'bootkit',
  'uac-bypass', 'privesc', 'persistence', 'lolbin', 'reverse-shell', 'c2', 'cobaltstrike-beacon',
];
const MALWAREBAZAAR_FILE_TYPES = [
  'exe', 'dll', 'elf', 'apk', 'doc', 'docx', 'xls', 'xlsx', 'xlsm', 'rtf', 'pdf', 'js', 'jse', 'vbs',
  'vbe', 'ps1', 'jar', 'msi', 'lnk', 'iso', 'img', 'zip', 'rar', '7z', 'gz', 'sh', 'py', 'hta', 'chm',
  'one', 'wsf', 'bat', 'cmd', 'swf', 'xll', 'ppt', 'pptx', 'pub', 'mht', 'html', 'url', 'dmg', 'macho',
  'deb', 'rpm', 'sys', 'ocx', 'scr', 'cpl', 'msc', 'reg', 'udf', 'vhd', 'cab', 'ace', 'arj', 'eml',
];

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
// Kalabalik kovalar (ornegin file_type=exe) 1000 kayitlik yaniti 30 saniyede yetistiremiyor.
const REQUEST_TIMEOUT_MS = 120_000;

async function requestJson(url, options) {
  const response = await fetch(url, { ...options, headers: { 'Auth-Key': options.authKey, ...(options.headers || {}) }, signal: AbortSignal.timeout(options.timeoutMs || REQUEST_TIMEOUT_MS) });
  if (!response.ok) throw new Error(`${new URL(url).hostname} HTTP ${response.status}`);
  try { return await response.json(); } catch { throw new Error(`${new URL(url).hostname} JSON yaniti gecersiz.`); }
}

function assertQueryStatus(response, label) {
  const status = response?.query_status;
  if (!['ok', 'no_results'].includes(status)) throw new Error(`${label} sorgusu basarisiz: ${status || 'bilinmeyen yanit'}`);
  return response;
}

// Aile sorgulari tek tek yapilir; ayni anda az sayida istek acarak API'yi yormadan toplu hacim cekilir.
async function mapWithConcurrency(items, concurrency, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor; cursor += 1;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

function addSignature(signatures, entry, label) {
  const digest = typeof entry.sha256_hash === 'string' ? entry.sha256_hash.toLowerCase() : '';
  const size = Number(entry.file_size);
  if (!SHA256.test(digest) || !Number.isSafeInteger(size) || size < 0 || signatures.has(digest)) return false;
  signatures.set(digest, { sha256: digest, file_size: size, name: cleanName(label, entry.signature, entry.file_name || entry.file_type), severity: 'high' });
  return true;
}

async function collect(options, dependencies = {}) {
  const fetchJson = dependencies.requestJson || requestJson;
  const sourcePath = path.resolve(options.source);
  const authKey = options.authKey || process.env.NEUTRON_ABUSECH_AUTH_KEY;
  if (!authKey || authKey.length < 16) throw new Error('NEUTRON_ABUSECH_AUTH_KEY tanimli degil veya gecersiz. Anahtari komuta yazmayin.');
  const limit = boundedInteger(options.limit, 1000, 1, 1000, '--limit');
  const bulkLimit = boundedInteger(options.bulkLimit ?? options.familyLimit, 1000, 0, 1000, '--bulk-limit');
  const threatfoxDays = boundedInteger(options.threatfoxDays, 7, 1, 7, '--threatfox-days');
  const concurrency = boundedInteger(options.concurrency, 4, 1, 8, '--concurrency');
  const bulkQueries = bulkLimit === 0 ? [] : [
    ...(options.families || MALWAREBAZAAR_FAMILIES).map((value) => ({ axis: 'family', query: 'get_siginfo', key: 'signature', value })),
    ...(options.tags || MALWAREBAZAAR_TAGS).map((value) => ({ axis: 'tag', query: 'get_taginfo', key: 'tag', value })),
    ...(options.fileTypes || MALWAREBAZAAR_FILE_TYPES).map((value) => ({ axis: 'file_type', query: 'get_file_type', key: 'file_type', value })),
  ];
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
  const postForm = (url, form) => fetchJson(url, { method: 'POST', authKey, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form) });
  const [urls, payloads, bazaar, threatfox] = await Promise.all([
    fetchJson(`${URLHAUS_URLS}limit/${limit}/`, { method: 'GET', authKey }).then((response) => assertQueryStatus(response, 'URLhaus URL')),
    fetchJson(`${URLHAUS_PAYLOADS}limit/${limit}/`, { method: 'GET', authKey }).then((response) => assertQueryStatus(response, 'URLhaus payload')),
    // get_recent yanitinda file_size var; recent_detections yanitinda yok ve imza semasi boyutu zorunlu kiliyor.
    postForm(MALWAREBAZAAR_API, { query: 'get_recent', selector: '100' }).then((response) => assertQueryStatus(response, 'MalwareBazaar')),
    fetchJson(THREATFOX_API, { method: 'POST', authKey, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: 'get_iocs', days: threatfoxDays }) }).then((response) => assertQueryStatus(response, 'ThreatFox')),
  ]);
  const signatures = new Map(base.signatures.map((entry) => [entry.sha256, entry]));
  const indicators = new Map(base.web_indicators.map((entry) => [`${entry.type}:${entry.value}`, entry]));
  let urlhausUrlCount = 0, urlhausPayloadCount = 0, malwareBazaarCount = 0, malwareBazaarFamilyCount = 0, threatFoxCount = 0;
  for (const entry of urls.urls || []) {
    const value = typeof entry.url === 'string' ? entry.url.trim().toLowerCase() : '';
    const key = `url:${value}`;
    if (entry.url_status !== 'online' || entry.threat !== 'malware_download' || !/^https?:\/\//.test(value) || indicators.has(key)) continue;
    indicators.set(key, { type: 'url', value, name: cleanName('URLhaus', entry.tags?.join(', '), entry.host), severity: 'high' }); urlhausUrlCount += 1;
  }
  for (const entry of payloads.payloads || []) {
    if (addSignature(signatures, entry, 'URLhaus payload')) urlhausPayloadCount += 1;
  }
  for (const entry of bazaar.data || []) {
    if (addSignature(signatures, entry, 'MalwareBazaar')) malwareBazaarCount += 1;
  }
  for (const entry of threatfox.data || []) {
    const type = entry.ioc_type === 'url' ? 'url' : entry.ioc_type === 'domain' ? 'domain' : '';
    const value = typeof entry.ioc === 'string' ? entry.ioc.trim().toLowerCase() : '';
    if (!type || !value || Number(entry.confidence_level) < THREATFOX_MINIMUM_CONFIDENCE) continue;
    if (type === 'url' ? !/^https?:\/\//.test(value) : !DOMAIN.test(value)) continue;
    const key = `${type}:${value}`;
    if (indicators.has(key)) continue;
    indicators.set(key, { type, value, name: cleanName('ThreatFox', entry.malware_printable || entry.malware, entry.threat_type), severity: 'high' }); threatFoxCount += 1;
  }
  // Tek bir sorgunun duşmesi tum toplamayi iptal etmemeli; ancak sessizce 1000 hash kaybetmemek icin once yeniden denenir.
  const failedQueries = [];
  const bulkResponses = await mapWithConcurrency(bulkQueries, concurrency, async (descriptor) => {
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      try {
        return assertQueryStatus(
          await postForm(MALWAREBAZAAR_API, { query: descriptor.query, [descriptor.key]: descriptor.value, limit: String(bulkLimit) }),
          `MalwareBazaar ${descriptor.axis}=${descriptor.value}`,
        );
      } catch (error) {
        if (attempt === 3) { failedQueries.push(`${descriptor.axis}=${descriptor.value}: ${error.message}`); return { query_status: 'no_results', data: [] }; }
        await new Promise((resolve) => setTimeout(resolve, 500 * attempt));
      }
    }
    return { query_status: 'no_results', data: [] };
  });
  for (const response of bulkResponses) {
    for (const entry of response.data || []) if (addSignature(signatures, entry, 'MalwareBazaar')) malwareBazaarFamilyCount += 1;
  }
  const collected = { ...rawSource, database_name: base.database_name, minimum_engine_version: base.minimum_engine_version, version, provenance: {
    source_name: 'Neutron curated abuse.ch threat intelligence', source_url: 'https://urlhaus.abuse.ch/api/', collected_at: new Date().toISOString(),
    license: 'abuse.ch Community API terms and fair-use principles apply',
    review_policy: `Automated intake: URLhaus online malware_download URLs, URLhaus/MalwareBazaar hashes with valid SHA-256 and byte size, ThreatFox url/domain at confidence >= ${THREATFOX_MINIMUM_CONFIDENCE}. Every candidate must pass package validation before signing.`,
  }, signatures: [...signatures.values()], web_indicators: [...indicators.values()] };
  return { source: collected, statistics: { urlhausUrlCount, urlhausPayloadCount, malwareBazaarCount, malwareBazaarFamilyCount, threatFoxCount, bulkQueryCount: bulkQueries.length, failedQueries } };
}

async function main() {
  const source = argument('--source'), output = argument('--output'), version = argument('--version');
  if (!source || !output) throw new Error('Kullanim: npm run proton:collect -- --source <definitions.json> --output <definitions.json> [--version x.xx.xxx] [--repo OWNER/REPO] [--limit 1000] [--bulk-limit 1000] [--threatfox-days 7] [--concurrency 4]');
  const outputPath = path.resolve(output);
  if (fs.existsSync(outputPath)) throw new Error(`Cikti zaten var, uzerine yazilmaz: ${outputPath}`);
  // --version verilmezse yayimlanmis en yuksek surumun derleme hanesi bir artirilir (docs/proton-versioning.md).
  let resolvedVersion = version;
  if (!resolvedVersion) {
    const next = resolveNextVersion({ repository: argument('--repo') });
    resolvedVersion = next.version;
    console.log(`Surum otomatik belirlendi: ${next.previousVersion ? `${next.previousVersion} -> ` : 'ilk yayin -> '}${next.version}`);
  }
  const result = await collect({ source, version: resolvedVersion, limit: argument('--limit'), bulkLimit: argument('--bulk-limit'), threatfoxDays: argument('--threatfox-days'), concurrency: argument('--concurrency') });
  materializeCandidate(result.source, path.resolve(source), outputPath);
  console.log(`Aday Proton kaynagi olusturuldu: ${outputPath}`);
  console.log(`URLhaus URL: +${result.statistics.urlhausUrlCount}; ThreatFox gostergesi: +${result.statistics.threatFoxCount}`);
  console.log(`URLhaus dosya hashi: +${result.statistics.urlhausPayloadCount}; MalwareBazaar guncel: +${result.statistics.malwareBazaarCount}; MalwareBazaar toplu tarama (${result.statistics.bulkQueryCount} sorgu): +${result.statistics.malwareBazaarFamilyCount}`);
  console.log(`Toplam: ${result.source.signatures.length} hash imzasi, ${result.source.web_indicators.length} web gostergesi.`);
  if (result.statistics.failedQueries.length) {
    console.warn(`Uyari: ${result.statistics.failedQueries.length} toplu sorgu 3 denemede de basarisiz oldu ve atlandi:`);
    for (const failure of result.statistics.failedQueries.slice(0, 10)) console.warn(`  - ${failure}`);
  }
  console.log('Dosyayi inceleyin; sonra proton:publish ile imzalayip yayinlayin. API anahtari dosyaya yazilmadi.');
}
if (require.main === module) main().catch((error) => stop(error.message));
module.exports = { collect, materializeCandidate };
