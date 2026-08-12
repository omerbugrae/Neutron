#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { collect, materializeCandidate } = require('./collect-abusech.cjs');
const responses = [
  { query_status: 'ok', urls: [{ url_status: 'online', threat: 'malware_download', url: 'https://bad.example/a.exe', host: 'bad.example', tags: ['test'] }, { url_status: 'offline', threat: 'malware_download', url: 'https://old.example/a.exe' }] },
  { query_status: 'ok', payloads: [{ sha256_hash: 'a'.repeat(64), file_size: '42', signature: 'TestFamily', file_type: 'exe' }] },
  { query_status: 'ok', data: [{ sha256_hash: 'b'.repeat(64), file_size: '84', signature: 'SecondFamily', file_name: 'sample.exe' }] },
];
async function main() {
  let index = 0;
  const result = await collect({ source: path.join(__dirname, 'examples', 'definitions.json'), version: '1.00.007', authKey: 'a'.repeat(16), limit: 5, hours: 24 }, { requestJson: async () => responses[index++] });
  assert.equal(result.source.version, '1.00.007');
  assert.ok(result.source.web_indicators.some((entry) => entry.value === 'https://bad.example/a.exe'));
  assert.ok(result.source.signatures.some((entry) => entry.sha256 === 'a'.repeat(64)));
  assert.ok(result.source.signatures.some((entry) => entry.sha256 === 'b'.repeat(64)));
  assert.deepEqual(result.statistics, { urlhausUrlCount: 1, urlhausPayloadCount: 1, malwareBazaarCount: 1 });
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'neutron-proton-collect-'));
  try {
    const candidatePath = path.join(temporaryRoot, 'candidate.json');
    materializeCandidate(result.source, path.join(__dirname, 'examples', 'definitions.json'), candidatePath);
    assert.equal(fs.existsSync(candidatePath), true);
    assert.equal(fs.existsSync(path.join(temporaryRoot, 'rules', 'proton_safe_test.yar')), true);
  } finally { fs.rmSync(temporaryRoot, { recursive: true, force: true }); }
  console.log('abuse.ch Proton toplayici oz testi basarili.');
}
main().catch((error) => { throw error; });
