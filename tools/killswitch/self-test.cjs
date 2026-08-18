#!/usr/bin/env node
'use strict';

// Kill switch document self-test (plan.md item 7).
//
// This document decides whether working software gets disabled on a user's
// machine, so the properties worth pinning down are the ones that stop it
// being abused: only the real key can author one, a list published for one
// channel cannot be replayed against the other, and anything malformed is
// rejected rather than partly believed.
//
// Runs offline against freshly generated throwaway keys -- no network, no
// GitHub, no access to the real signing material.

const assert = require('node:assert');
const crypto = require('node:crypto');
const {
  canonicalKillSwitch, channelConfig, emptyKillSwitch,
  signKillSwitch, validateKillSwitch, verifyKillSwitchSignature,
} = require('../../src/killswitch-format.cjs');

let passed = 0;
let failed = 0;

function check(name, run) {
  try {
    run();
    passed += 1;
    console.log(`  ok  ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`FAIL  ${name}\n      ${error.message}`);
  }
}

function throws(run, hint) {
  assert.throws(run, (error) => error instanceof Error, hint);
}

const keys = crypto.generateKeyPairSync('ed25519');
const other = crypto.generateKeyPairSync('ed25519');

function documentFor(channel, versions) {
  return validateKillSwitch({ ...emptyKillSwitch(channel), revoked_versions: versions }, channel);
}

console.log('Kill switch format self-test');

check('an empty list is valid for both channels', () => {
  for (const channel of ['feature', 'proton']) {
    assert.deepStrictEqual(validateKillSwitch(emptyKillSwitch(channel), channel).revoked_versions, []);
  }
});

check('a signed document verifies with the matching public key', () => {
  const bytes = canonicalKillSwitch(documentFor('proton', ['1.00.007']));
  const signature = signKillSwitch(bytes, keys.privateKey, keys.publicKey);
  assert.strictEqual(verifyKillSwitchSignature(bytes, signature, keys.publicKey), true);
});

check('a document signed by a different key is refused', () => {
  const bytes = canonicalKillSwitch(documentFor('proton', ['1.00.007']));
  const signature = signKillSwitch(bytes, other.privateKey, other.publicKey);
  throws(() => verifyKillSwitchSignature(bytes, signature, keys.publicKey), 'foreign key accepted');
});

check('editing the document after signing invalidates it', () => {
  const bytes = canonicalKillSwitch(documentFor('proton', ['1.00.007']));
  const signature = signKillSwitch(bytes, keys.privateKey, keys.publicKey);
  const tampered = canonicalKillSwitch(documentFor('proton', ['1.00.007', '1.00.008']));
  throws(() => verifyKillSwitchSignature(tampered, signature, keys.publicKey), 'tampered document accepted');
});

check('a truncated or flipped signature is refused', () => {
  const bytes = canonicalKillSwitch(documentFor('feature', ['1.00.001']));
  const signature = signKillSwitch(bytes, keys.privateKey, keys.publicKey);
  const raw = Buffer.from(signature.signature_base64, 'base64');

  const flipped = Buffer.from(raw);
  flipped[0] ^= 0xff;
  throws(() => verifyKillSwitchSignature(bytes, { ...signature, signature_base64: flipped.toString('base64') }, keys.publicKey));

  const short = raw.subarray(0, 63);
  throws(() => verifyKillSwitchSignature(bytes, { ...signature, signature_base64: short.toString('base64') }, keys.publicKey));
});

check('a validly signed document cannot be replayed onto the other channel', () => {
  // Both channels are signed by the same key, so cross-channel replay is the
  // realistic attack: revoke every Proton version by re-publishing the
  // feature list. The channel name is inside the signed bytes to stop it.
  const bytes = canonicalKillSwitch(documentFor('feature', ['1.00.001']));
  const signature = signKillSwitch(bytes, keys.privateKey, keys.publicKey);
  assert.strictEqual(verifyKillSwitchSignature(bytes, signature, keys.publicKey), true);
  throws(
    () => validateKillSwitch(JSON.parse(bytes.toString('utf8')), 'proton'),
    'feature list accepted on the proton channel',
  );
});

check('malformed documents are rejected outright', () => {
  const cases = [
    null,
    'not an object',
    [],
    { schema: 'wrong', channel: channelConfig('proton').channel, revoked_versions: [] },
    { ...emptyKillSwitch('proton'), revoked_versions: 'not-an-array' },
    { ...emptyKillSwitch('proton'), revoked_versions: ['1.0.0'] },
    { ...emptyKillSwitch('proton'), revoked_versions: ['not-a-version'] },
    { ...emptyKillSwitch('proton'), revoked_versions: ['1.00.007', '1.00.007'] },
    { ...emptyKillSwitch('proton'), revoked_versions: Array.from({ length: 257 }, (_v, i) => `1.00.${String(i).padStart(3, '0')}`) },
  ];
  for (const value of cases) {
    throws(() => validateKillSwitch(value, 'proton'), `accepted: ${JSON.stringify(value)?.slice(0, 60)}`);
  }
});

check('an unknown channel name is refused', () => {
  throws(() => channelConfig('nope'));
  throws(() => validateKillSwitch(emptyKillSwitch('proton'), 'nope'));
});

check('the two channels use distinct release tags and asset names', () => {
  const feature = channelConfig('feature');
  const proton = channelConfig('proton');
  assert.notStrictEqual(feature.tag, proton.tag);
  assert.notStrictEqual(feature.assetName, proton.assetName);
  assert.notStrictEqual(feature.channel, proton.channel);
});

check('canonical encoding is stable across equal documents', () => {
  // The signature covers the exact bytes, so two equal documents must encode
  // identically or verification becomes order-dependent.
  const first = canonicalKillSwitch(documentFor('proton', ['1.00.007', '1.00.009']));
  const second = canonicalKillSwitch(documentFor('proton', ['1.00.007', '1.00.009']));
  assert.ok(first.equals(second));
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exitCode = failed === 0 ? 0 : 1;
