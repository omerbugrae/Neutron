#!/usr/bin/env node
'use strict';

// Sonraki Proton surumunu yayimlanmis GitHub Release'lerinden turetir.
// Kural dokumani: docs/proton-versioning.md
const { spawnSync } = require('node:child_process');
const { DEFAULT_REPOSITORY } = require('./publish.cjs');

const TAG_PATTERN = /^proton-v(\d+)\.(\d{2})\.(\d{3})$/;
const FIRST_VERSION = { major: 1, minor: 0, build: 1 };
const MAXIMUM_BUILD = 999;
const MAXIMUM_MINOR = 99;

function formatVersion({ major, minor, build }) {
  return `${major}.${String(minor).padStart(2, '0')}.${String(build).padStart(3, '0')}`;
}

function compareVersions(left, right) {
  return (left.major - right.major) || (left.minor - right.minor) || (left.build - right.build);
}

function parseTag(tagName) {
  const match = TAG_PATTERN.exec(typeof tagName === 'string' ? tagName.trim() : '');
  return match ? { major: Number(match[1]), minor: Number(match[2]), build: Number(match[3]) } : null;
}

// Yayimlanmis en yuksek surumun derleme hanesi bir artar; 999'u gecerse ara sürüm hanesine tasinir.
function incrementBuild(version) {
  if (version.build < MAXIMUM_BUILD) return { ...version, build: version.build + 1 };
  if (version.minor < MAXIMUM_MINOR) return { major: version.major, minor: version.minor + 1, build: 0 };
  throw new Error('Surum alani doldu: ana surumu elle yukseltin ve docs/proton-versioning.md dosyasini guncelleyin.');
}

function defaultRunGh(argumentsList) {
  return spawnSync(process.env.NEUTRON_GH_BIN || 'gh', argumentsList, { encoding: 'utf8', windowsHide: true });
}

// `gh release list --json` bu depoda bos donebiliyor; REST uc noktasi guvenilir sonuc veriyor.
function readPublishedVersions(repository, runGh) {
  const result = runGh(['api', `repos/${repository}/releases?per_page=100`, '--paginate']);
  if (result.error?.code === 'ENOENT') throw new Error('GitHub CLI bulunamadi; surum numarasi turetilemedi.');
  if (result.status !== 0) throw new Error(`GitHub yayin listesi okunamadi: ${(result.stderr || '').trim() || 'bilinmeyen hata'}`);
  const documents = String(result.stdout || '').trim();
  if (!documents) return [];
  // --paginate birden fazla JSON dizisini arka arkaya yazabilir.
  const versions = [];
  for (const chunk of documents.replace(/\]\s*\[/g, '][').split(/(?<=\])(?=\[)/)) {
    let parsed;
    try { parsed = JSON.parse(chunk); } catch { throw new Error('GitHub yayin listesi JSON olarak cozulemedi.'); }
    for (const release of Array.isArray(parsed) ? parsed : []) {
      const version = parseTag(release?.tag_name);
      if (version) versions.push(version);
    }
  }
  return versions;
}

function resolveNextVersion(options = {}) {
  const repository = options.repository || DEFAULT_REPOSITORY;
  const runGh = options.runGh || defaultRunGh;
  const published = options.publishedVersions || readPublishedVersions(repository, runGh);
  if (!published.length) {
    return { version: formatVersion(FIRST_VERSION), previousVersion: null, repository };
  }
  const latest = published.reduce((highest, entry) => (compareVersions(entry, highest) > 0 ? entry : highest));
  return { version: formatVersion(incrementBuild(latest)), previousVersion: formatVersion(latest), repository };
}

if (require.main === module) {
  try {
    const index = process.argv.indexOf('--repo');
    const resolved = resolveNextVersion({ repository: index >= 0 ? process.argv[index + 1] : undefined });
    console.log(resolved.version);
  } catch (error) {
    console.error(`Hata: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { compareVersions, formatVersion, incrementBuild, parseTag, resolveNextVersion };
