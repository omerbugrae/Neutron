'use strict';

// Shared emergency-revocation document for both signed update channels.
//
// Neutron publishes two kinds of update from the same GitHub repository and
// the same Ed25519 key: Proton (hash signatures, YARA rules, web indicators)
// and the Machine Learning Feature Update (EMBER2024 models). Both are
// immutable once released -- which is exactly what you want for integrity,
// and exactly what you do not want when a release turns out to be harmful and
// has to be withdrawn from machines that already installed it.
//
// The kill switch is the answer to that: a small, separately signed list of
// revoked versions, published under its own mutable release per channel.
// Pushing a revocation is a few KB and takes seconds, where re-cutting a
// Feature Update means re-uploading hundreds of megabytes.
//
// Both channels share this one implementation deliberately. Two near-identical
// signature verifiers is how one of them ends up subtly weaker than the other.

const crypto = require('node:crypto');
const { keyIdFromPublicKey, sha256 } = require('./proton-format.cjs');

const KILLSWITCH_SCHEMA = 'neutron.killswitch/v1';
const KILLSWITCH_SIGNATURE_FORMAT = 'neutron-killswitch-signature/v1';
const VERSION_PATTERN = /^\d+\.\d{2}\.\d{3}$/;
const MAX_REVOKED_VERSIONS = 256;

// Per-channel constants. `channel` is embedded in the signed document, so a
// revocation list for one channel can never be replayed against the other
// even though both are signed by the same key.
const CHANNELS = {
  feature: {
    channel: 'machine-learning-models',
    tag: 'feature-killswitch',
    assetName: 'feature-revocations.json',
    title: 'Machine Learning Feature Update kill switch',
  },
  proton: {
    channel: 'proton-signatures',
    tag: 'proton-killswitch',
    assetName: 'proton-revocations.json',
    title: 'Proton kill switch',
  },
};

function fail(message) {
  throw new Error(message);
}

function channelConfig(name) {
  const config = CHANNELS[name];
  if (!config) fail(`Unknown kill switch channel: ${name}`);
  return config;
}

function canonicalKillSwitch(document) {
  return Buffer.from(`${JSON.stringify(document, null, 2)}\n`, 'utf8');
}

function emptyKillSwitch(channelName) {
  return {
    schema: KILLSWITCH_SCHEMA,
    channel: channelConfig(channelName).channel,
    revoked_versions: [],
  };
}

// Validation is strict on purpose. This document decides whether working
// software gets disabled on a user's machine, so anything unexpected in it is
// treated as a broken document rather than quietly ignored -- callers already
// fail open when validation throws.
function validateKillSwitch(value, channelName) {
  const expected = channelConfig(channelName).channel;
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Kill switch document is invalid.');
  if (value.schema !== KILLSWITCH_SCHEMA) fail('Unsupported kill switch schema.');
  if (value.channel !== expected) fail(`Kill switch document belongs to a different channel: ${value.channel}`);
  if (!Array.isArray(value.revoked_versions)) fail('Kill switch revocation list is invalid.');
  if (value.revoked_versions.length > MAX_REVOKED_VERSIONS) fail('Kill switch revocation list is too long.');
  const versions = value.revoked_versions.map((entry) => String(entry));
  if (!versions.every((entry) => VERSION_PATTERN.test(entry))) fail('Kill switch contains an invalid version.');
  if (new Set(versions).size !== versions.length) fail('Kill switch contains a duplicate version.');
  return { ...value, revoked_versions: versions };
}

function signKillSwitch(documentBytes, privateKey, publicKey) {
  return {
    format: KILLSWITCH_SIGNATURE_FORMAT,
    algorithm: 'Ed25519',
    key_id: keyIdFromPublicKey(publicKey),
    document_sha256: sha256(documentBytes),
    signature_base64: crypto.sign(null, documentBytes, privateKey).toString('base64'),
  };
}

function verifyKillSwitchSignature(documentBytes, signatureDocument, publicKey) {
  if (!signatureDocument || signatureDocument.format !== KILLSWITCH_SIGNATURE_FORMAT || signatureDocument.algorithm !== 'Ed25519') {
    fail('Kill switch signature document is invalid.');
  }
  if (signatureDocument.key_id !== keyIdFromPublicKey(publicKey)) fail('Kill switch signing key does not match.');
  if (signatureDocument.document_sha256 !== sha256(documentBytes)) fail('Kill switch document hash does not match.');
  const signature = Buffer.from(String(signatureDocument.signature_base64 || ''), 'base64');
  if (signature.length !== 64 || !crypto.verify(null, documentBytes, publicKey, signature)) fail('Kill switch signature is invalid.');
  return true;
}

module.exports = {
  CHANNELS,
  KILLSWITCH_SCHEMA,
  KILLSWITCH_SIGNATURE_FORMAT,
  MAX_REVOKED_VERSIONS,
  canonicalKillSwitch,
  channelConfig,
  emptyKillSwitch,
  signKillSwitch,
  validateKillSwitch,
  verifyKillSwitchSignature,
};
