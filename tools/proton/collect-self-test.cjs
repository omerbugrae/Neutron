#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { collect, materializeCandidate } = require('./collect-abusech.cjs');
const { resolveNextVersion } = require('./next-version.cjs');
// Istekler artik URL ve govdeye gore ayrisiyor; sahte katman da ayni sekilde yonlendiriyor.
async function fakeRequestJson(url, options) {
  const body = typeof options.body === 'string' ? options.body : String(options.body || '');
  if (url.includes('/urls/recent/')) {
    return { query_status: 'ok', urls: [{ url_status: 'online', threat: 'malware_download', url: 'https://bad.example/a.exe', host: 'bad.example', tags: ['test'] }, { url_status: 'offline', threat: 'malware_download', url: 'https://old.example/a.exe' }] };
  }
  if (url.includes('/payloads/recent/')) {
    return { query_status: 'ok', payloads: [{ sha256_hash: 'a'.repeat(64), file_size: '42', signature: 'TestFamily', file_type: 'exe' }] };
  }
  if (url.includes('threatfox')) {
    return { query_status: 'ok', data: [
      { ioc_type: 'domain', ioc: 'evil.example', confidence_level: 100, malware_printable: 'TestFamily', threat_type: 'payload_delivery' },
      { ioc_type: 'domain', ioc: 'lowtrust.example', confidence_level: 10, malware_printable: 'TestFamily' },
      { ioc_type: 'ip:port', ioc: '10.0.0.1:443', confidence_level: 100, malware_printable: 'TestFamily' },
    ] };
  }
  if (body.includes('get_recent')) {
    return { query_status: 'ok', data: [{ sha256_hash: 'b'.repeat(64), file_size: '84', signature: 'SecondFamily', file_name: 'sample.exe' }] };
  }
  if (body.includes('get_siginfo')) {
    if (body.includes('BrokenFamily')) throw new Error('mb-api.abuse.ch HTTP 500');
    return { query_status: 'ok', data: [{ sha256_hash: 'c'.repeat(64), file_size: '126', signature: 'ThirdFamily', file_name: 'family.exe' }] };
  }
  if (body.includes('get_taginfo')) {
    return { query_status: 'ok', data: [{ sha256_hash: 'd'.repeat(64), file_size: '168', signature: 'TaggedFamily', file_name: 'tagged.exe' }] };
  }
  if (body.includes('get_file_type')) {
    return { query_status: 'ok', data: [{ sha256_hash: 'e'.repeat(64), file_size: '210', signature: 'TypedFamily', file_name: 'typed.dll' }] };
  }
  throw new Error(`beklenmeyen istek: ${url} ${body}`);
}
// Surum turetme kurallari: docs/proton-versioning.md
function testVersionResolution() {
  const fakeGh = (tags) => () => ({ status: 0, stdout: JSON.stringify(tags.map((tag_name) => ({ tag_name }))) });
  assert.equal(resolveNextVersion({ runGh: fakeGh([]) }).version, '1.00.001', 'ilk yayin 1.00.001 olmali');
  // En yuksek sürüm sayisal olarak secilir, listedeki siraya gore degil.
  assert.equal(resolveNextVersion({ runGh: fakeGh(['proton-v1.00.005', 'proton-v1.00.150', 'proton-v1.00.101']) }).version, '1.00.151');
  assert.equal(resolveNextVersion({ runGh: fakeGh(['proton-v1.00.999']) }).version, '1.01.000', 'derleme hanesi 999 sonrasi ara haneye tasinmali');
  assert.equal(resolveNextVersion({ runGh: fakeGh(['proton-v2.03.007']) }).version, '2.03.008');
  // Proton disi veya bozuk etiketler yok sayilir.
  assert.equal(resolveNextVersion({ runGh: fakeGh(['v9.9.9', 'proton-v1.0.5', 'proton-v1.00.010']) }).version, '1.00.011');
  assert.equal(resolveNextVersion({ runGh: fakeGh(['proton-v1.00.150']) }).previousVersion, '1.00.150');
  assert.throws(() => resolveNextVersion({ runGh: fakeGh(['proton-v1.99.999']) }), /Surum alani doldu/);
  assert.throws(() => resolveNextVersion({ runGh: () => ({ status: 1, stderr: 'yetki yok' }) }), /GitHub yayin listesi okunamadi/);
}

async function main() {
  const result = await collect(
    { source: path.join(__dirname, 'examples', 'definitions.json'), version: '1.00.007', authKey: 'a'.repeat(16), limit: 5, families: ['ThirdFamily', 'BrokenFamily'], tags: ['loader'], fileTypes: ['dll'], bulkLimit: 10, threatfoxDays: 1 },
    { requestJson: fakeRequestJson },
  );
  assert.equal(result.source.version, '1.00.007');
  assert.ok(result.source.web_indicators.some((entry) => entry.value === 'https://bad.example/a.exe'));
  assert.ok(result.source.web_indicators.some((entry) => entry.type === 'domain' && entry.value === 'evil.example'));
  assert.ok(!result.source.web_indicators.some((entry) => entry.value === 'lowtrust.example'), 'dusuk guvenli ThreatFox gostergesi elenmeli');
  assert.ok(!result.source.web_indicators.some((entry) => entry.value.includes('10.0.0.1')), 'ip:port turu desteklenmiyor');
  assert.ok(result.source.signatures.some((entry) => entry.sha256 === 'a'.repeat(64)));
  assert.ok(result.source.signatures.some((entry) => entry.sha256 === 'b'.repeat(64)));
  assert.ok(result.source.signatures.some((entry) => entry.sha256 === 'c'.repeat(64)), 'aile taramasi hashi eklenmeli');
  assert.ok(result.source.signatures.some((entry) => entry.sha256 === 'd'.repeat(64)), 'etiket taramasi hashi eklenmeli');
  assert.ok(result.source.signatures.some((entry) => entry.sha256 === 'e'.repeat(64)), 'dosya turu taramasi hashi eklenmeli');
  assert.equal(result.statistics.bulkQueryCount, 4, 'iki aile, bir etiket, bir dosya turu');
  assert.equal(result.statistics.malwareBazaarFamilyCount, 3);
  assert.equal(result.statistics.failedQueries.length, 1, 'duşen sorgu sessizce yutulmamali, raporlanmali');
  assert.match(result.statistics.failedQueries[0], /BrokenFamily/);
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'neutron-proton-collect-'));
  try {
    const candidatePath = path.join(temporaryRoot, 'candidate.json');
    materializeCandidate(result.source, path.join(__dirname, 'examples', 'definitions.json'), candidatePath);
    assert.equal(fs.existsSync(candidatePath), true);
    assert.equal(fs.existsSync(path.join(temporaryRoot, 'rules', 'proton_safe_test.yar')), true);
  } finally { fs.rmSync(temporaryRoot, { recursive: true, force: true }); }
  testVersionResolution();
  console.log('abuse.ch Proton toplayici oz testi basarili.');
}
main().catch((error) => { throw error; });
