#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { collect, materializeCandidate } = require('./collect-abusech.cjs');
const { publish } = require('./publish.cjs');
const { resolveNextVersion } = require('./next-version.cjs');

function argument(name) { const index = process.argv.indexOf(name); return index >= 0 ? process.argv[index + 1] : undefined; }
function hasFlag(name) { return process.argv.includes(name); }
function stop(message) { console.error(`Hata: ${message}`); process.exitCode = 1; }

// Bir sonraki toplamanin bu yayinin ustunde kumulatif calismasi icin, yayimlanan adayi
// kaynak dosyanin uzerine yazar. Bu olmadan her toplama ayni statik tabandan basladigi
// icin surumler birbirinin ust kumesi olmayabilir ve guncelleyici en son surumu indirdiginde
// atlanan bir surume ozgu gostergeler hic istemciye ulasmaz (bkz. docs/proton-versioning.md).
function persistAsNewBase(candidatePath, sourcePath) {
  fs.copyFileSync(candidatePath, sourcePath);
}

async function main() {
  const source = argument('--source'); const version = argument('--version'); const keys = argument('--keys'); const output = argument('--output'); const repository = argument('--repo');
  const persistBase = hasFlag('--persist-base');
  if (!source || !keys || !output) throw new Error('Kullanim: npm run proton:sync -- --source <definitions.json> --keys <anahtar-klasoru> --output <yayin-klasoru> [--version x.xx.xxx] [--repo OWNER/REPO] [--persist-base]');
  // --version verilmezse yayimlanmis en yuksek surumun derleme hanesi bir artirilir (docs/proton-versioning.md).
  let resolvedVersion = version;
  if (!resolvedVersion) {
    const next = resolveNextVersion({ repository });
    resolvedVersion = next.version;
    console.log(`Surum otomatik belirlendi: ${next.previousVersion ? `${next.previousVersion} -> ` : 'ilk yayin -> '}${next.version}`);
  }
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'neutron-proton-feed-'));
  try {
    const candidatePath = path.join(temporaryRoot, 'definitions.json');
    const result = await collect({ source, version: resolvedVersion, limit: argument('--limit'), bulkLimit: argument('--bulk-limit'), maxBulkQueries: argument('--max-bulk-queries'), threatfoxDays: argument('--threatfox-days'), concurrency: argument('--concurrency') });
    materializeCandidate(result.source, path.resolve(source), candidatePath);
    const published = publish({ source: candidatePath, keys, output, repository });
    console.log(`Gercek kaynaklardan Proton ${published.version} toplandi, imzalandi ve yayimlandi.`);
    if (persistBase) {
      persistAsNewBase(candidatePath, path.resolve(source));
      console.log(`Kaynak dosya guncellendi, bir sonraki toplama ${published.version} uzerine kumulatif calisacak: ${path.resolve(source)}`);
    }
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}
main().catch((error) => stop(error.message));
