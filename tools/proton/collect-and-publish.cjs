#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { collect, materializeCandidate } = require('./collect-abusech.cjs');
const { publish } = require('./publish.cjs');

function argument(name) { const index = process.argv.indexOf(name); return index >= 0 ? process.argv[index + 1] : undefined; }
function stop(message) { console.error(`Hata: ${message}`); process.exitCode = 1; }

async function main() {
  const source = argument('--source'); const version = argument('--version'); const keys = argument('--keys'); const output = argument('--output'); const repository = argument('--repo');
  if (!source || !version || !keys || !output) throw new Error('Kullanim: npm run proton:sync -- --source <definitions.json> --version <x.xx.xxx> --keys <anahtar-klasoru> --output <yayin-klasoru> [--repo OWNER/REPO]');
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'neutron-proton-feed-'));
  try {
    const candidatePath = path.join(temporaryRoot, 'definitions.json');
    const result = await collect({ source, version, limit: argument('--limit'), hours: argument('--hours') });
    materializeCandidate(result.source, path.resolve(source), candidatePath);
    const published = publish({ source: candidatePath, keys, output, repository });
    console.log(`Gercek kaynaklardan Proton ${published.version} toplandi, imzalandi ve yayimlandi.`);
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}
main().catch((error) => stop(error.message));
