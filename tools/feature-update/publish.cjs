#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const DEFAULT_REPOSITORY = 'omerbugrae/NeutronProton';

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function gh(argumentsList, silent = false) {
  return spawnSync(process.env.NEUTRON_GH_BIN || 'gh', argumentsList, {
    encoding: 'utf8', windowsHide: true, stdio: silent ? ['ignore', 'pipe', 'pipe'] : 'inherit',
  });
}

function runPack(version, source, keys, output, minimumAppVersion) {
  const result = spawnSync(process.execPath, [path.join(__dirname, 'pack.cjs'),
    '--version', version, '--source', source, '--keys', keys, '--output', output,
    '--minimum-app-version', minimumAppVersion,
  ], { encoding: 'utf8', windowsHide: true, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error('Feature Update package creation failed.');
}

try {
  const version = argument('--version');
  const source = path.resolve(argument('--source') || 'data/ml/ember2024');
  const keys = path.resolve(argument('--keys') || 'proton-secrets');
  const output = path.resolve(argument('--output') || 'feature-dist');
  const repository = argument('--repo') || DEFAULT_REPOSITORY;
  const minimumAppVersion = argument('--minimum-app-version') || '0.31.0';
  if (!/^\d+\.\d{2}\.\d{3}$/.test(String(version || '')) || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new Error('Usage: npm run feature:publish -- --version 1.00.001 --keys <key-directory> [--repo OWNER/REPO]');
  }
  const availability = gh(['--version'], true);
  if (availability.error || availability.status !== 0) throw new Error('GitHub CLI is not available.');
  if (gh(['auth', 'status', '--hostname', 'github.com'], true).status !== 0) throw new Error('GitHub CLI is not authenticated.');
  const tag = `feature-v${version}`;
  if (gh(['release', 'view', tag, '--repo', repository, '--json', 'tagName'], true).status === 0) throw new Error(`${tag} already exists; Feature Update releases are immutable.`);
  const manifestPath = path.join(output, `feature-${version}.json`);
  if (!fs.existsSync(manifestPath)) runPack(version, source, keys, output, minimumAppVersion);
  const assets = fs.readdirSync(output)
    .filter((name) => name === `feature-${version}.json` || name === `feature-${version}.json.sig` || (name.startsWith(`feature-${version}-`) && name.endsWith('.nfchunk')))
    .map((name) => path.join(output, name));
  if (assets.length < 18) throw new Error('Feature Update output is incomplete.');
  const notes = [
    `Machine Learning Feature Update ${version}.`, '',
    '- 14 EMBER2024 models',
    '- AES-256-GCM encrypted assets',
    '- Ed25519 signed manifest',
    '- Installed only after complete hash and signature verification',
  ].join('\n');
  const created = gh(['release', 'create', tag, ...assets, '--repo', repository, '--title', `Machine Learning Feature Update ${version}`, '--notes', notes]);
  if (created.error) throw created.error;
  if (created.status !== 0) throw new Error('GitHub Feature Update release could not be created.');
  console.log(`Published ${tag} to ${repository}.`);
} catch (error) {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
}
