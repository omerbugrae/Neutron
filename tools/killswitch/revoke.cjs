#!/usr/bin/env node
'use strict';

// Emergency kill switch publisher for both signed update channels.
//
//   npm run killswitch:revoke -- --channel proton  --version 1.00.007 --keys <dir>
//   npm run killswitch:revoke -- --channel feature --version 1.00.001 --keys <dir>
//   ... add --unrevoke to take a version back off the list.
//
// A normal proton-v/feature-v release is immutable and carries the full
// payload, so neither is something you can withdraw in a hurry. This script
// instead publishes a small, separately signed revocation list under that
// channel's own mutable release. Clients verify it on every update check and
// on their automatic timers, then act:
//
//   * feature  -- quarantines the installed model set (renamed aside, not
//                 deleted) so the engine falls back to its no-ML path.
//   * proton   -- rolls back to the newest archived non-revoked version, so
//                 the scanner keeps working on the last known-good rules.
//
// Note this only ever ADDS a step; a client that cannot reach or verify the
// document keeps running exactly as before.

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const {
  canonicalKillSwitch, channelConfig, emptyKillSwitch,
  signKillSwitch, validateKillSwitch, verifyKillSwitchSignature,
} = require('../../src/killswitch-format.cjs');
const { keyIdFromPublicKey } = require('../../src/proton-format.cjs');

const DEFAULT_REPOSITORY = 'omerbugrae/NeutronProton';

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function stop(message) {
  console.error(`Error: ${message}`);
  process.exit(1);
}

function gh(argumentsList, silent = false) {
  return spawnSync(process.env.NEUTRON_GH_BIN || 'gh', argumentsList, {
    encoding: 'utf8', windowsHide: true, stdio: silent ? ['ignore', 'pipe', 'pipe'] : 'inherit',
  });
}

// Reads the channel's current revocation list, verifying its signature before
// trusting it. Editing a document we could not verify would mean re-signing
// attacker-supplied content with the real key, so a present-but-unverifiable
// document is a hard stop, not something to overwrite silently.
function fetchExistingDocument(repository, channelName, config, publicKey) {
  const view = gh(['release', 'view', config.tag, '--repo', repository, '--json', 'tagName'], true);
  if (view.status !== 0) return { exists: false, document: emptyKillSwitch(channelName) };
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'neutron-killswitch-'));
  try {
    const download = gh([
      'release', 'download', config.tag, '--repo', repository, '--dir', temporaryDirectory,
      '--pattern', `${config.assetName}*`, '--clobber',
    ], true);
    if (download.status !== 0) stop(`${config.tag} exists but its revocation list could not be downloaded.`);
    const documentPath = path.join(temporaryDirectory, config.assetName);
    const signaturePath = `${documentPath}.sig`;
    if (!fs.existsSync(documentPath) || !fs.existsSync(signaturePath)) {
      stop(`${config.tag} exists but is missing ${config.assetName} or its signature.`);
    }
    const documentBytes = fs.readFileSync(documentPath);
    verifyKillSwitchSignature(documentBytes, JSON.parse(fs.readFileSync(signaturePath, 'utf8')), publicKey);
    return { exists: true, document: validateKillSwitch(JSON.parse(documentBytes.toString('utf8')), channelName) };
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

try {
  const channelName = argument('--channel');
  const version = argument('--version');
  const keysDirectory = path.resolve(argument('--keys') || 'proton-secrets');
  const outputDirectory = path.resolve(argument('--output') || 'feature-dist');
  const repository = argument('--repo') || DEFAULT_REPOSITORY;
  const unrevoke = process.argv.includes('--unrevoke');
  if (!['feature', 'proton'].includes(String(channelName)) || !/^\d+\.\d{2}\.\d{3}$/.test(String(version || ''))) {
    stop('Usage: npm run killswitch:revoke -- --channel <feature|proton> --version X.XX.XXX --keys <key-directory> [--repo OWNER/REPO] [--unrevoke]');
  }
  const config = channelConfig(channelName);

  const availability = gh(['--version'], true);
  if (availability.error || availability.status !== 0) stop('GitHub CLI is not available.');
  if (gh(['auth', 'status', '--hostname', 'github.com'], true).status !== 0) stop('GitHub CLI is not authenticated.');

  const privateKey = crypto.createPrivateKey(fs.readFileSync(path.join(keysDirectory, 'proton-signing-private.pem')));
  const publicKey = crypto.createPublicKey(fs.readFileSync(path.join(keysDirectory, 'proton-signing-public.pem')));
  if (keyIdFromPublicKey(publicKey) !== keyIdFromPublicKey(crypto.createPublicKey(privateKey))) stop('Signing keys are not a matching pair.');

  const { exists, document } = fetchExistingDocument(repository, channelName, config, publicKey);
  const revoked = new Set(document.revoked_versions);
  if (unrevoke) {
    if (!revoked.delete(version)) stop(`${version} is not currently revoked on the ${channelName} channel.`);
  } else {
    if (revoked.has(version)) stop(`${version} is already revoked on the ${channelName} channel.`);
    revoked.add(version);
  }

  const nextDocument = validateKillSwitch({
    ...emptyKillSwitch(channelName),
    revoked_versions: [...revoked].sort(),
    updated_at: new Date().toISOString(),
  }, channelName);
  const documentBytes = canonicalKillSwitch(nextDocument);
  const signature = signKillSwitch(documentBytes, privateKey, publicKey);
  verifyKillSwitchSignature(documentBytes, signature, publicKey);

  fs.mkdirSync(outputDirectory, { recursive: true });
  const documentPath = path.join(outputDirectory, config.assetName);
  const signaturePath = `${documentPath}.sig`;
  fs.writeFileSync(documentPath, documentBytes);
  fs.writeFileSync(signaturePath, `${JSON.stringify(signature, null, 2)}\n`);

  if (!exists) {
    const notes = [
      `${config.title}.`, '',
      '- Ed25519 signed revocation list, verified by every Neutron client',
      '- This release is intentionally mutable: assets are replaced in place',
      '  by re-running this tool, never deleted and re-created.',
    ].join('\n');
    const created = gh(['release', 'create', config.tag, documentPath, signaturePath, '--repo', repository, '--title', config.title, '--notes', notes]);
    if (created.error) throw created.error;
    if (created.status !== 0) stop('GitHub kill switch release could not be created.');
  } else {
    const uploaded = gh(['release', 'upload', config.tag, documentPath, signaturePath, '--repo', repository, '--clobber']);
    if (uploaded.error) throw uploaded.error;
    if (uploaded.status !== 0) stop('GitHub kill switch release could not be updated.');
  }
  console.log(`${unrevoke ? 'Un-revoked' : 'Revoked'} ${version} on the ${channelName} channel.`);
  console.log(`Current revocation list: ${nextDocument.revoked_versions.join(', ') || '(empty)'}`);
} catch (error) {
  stop(error.message);
}
