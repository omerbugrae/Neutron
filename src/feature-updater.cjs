'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  decryptFeatureFile,
  readEncryptionKey,
  validateManifest,
  verifyManifestSignature,
} = require('./feature-update-format.cjs');
const { compareVersions, fetchBytes } = require('./proton-updater.cjs');

const DEFAULT_RELEASES_URL = 'https://api.github.com/repos/omerbugrae/NeutronProton/releases?per_page=30';
const RELEASE_TAG_PATTERN = /^feature-v(\d+\.\d{2}\.\d{3})$/;
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_SIGNATURE_BYTES = 64 * 1024;
const MAX_ASSET_BYTES = 40 * 1024 * 1024;

class FeatureUpdateError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'FeatureUpdateError';
    this.code = code;
  }
}

function parseJson(bytes, code, message) {
  try { return JSON.parse(bytes.toString('utf8')); } catch { throw new FeatureUpdateError(code, message); }
}

function selectLatestFeatureRelease(releases) {
  if (!Array.isArray(releases)) throw new FeatureUpdateError('INVALID_RELEASES', 'Feature Update release list is invalid.');
  return releases
    .filter((release) => release && !release.draft && !release.prerelease)
    .map((release) => {
      const match = RELEASE_TAG_PATTERN.exec(String(release.tag_name || ''));
      return match ? { release, version: match[1] } : null;
    })
    .filter(Boolean)
    .sort((left, right) => compareVersions(right.version, left.version))[0] || null;
}

function assetByName(release, name) {
  const asset = (Array.isArray(release.assets) ? release.assets : []).find((item) => item?.name === name);
  if (!asset?.browser_download_url) throw new FeatureUpdateError('MISSING_ASSET', `Feature Update asset is missing: ${name}`);
  return asset;
}

function currentFeatureVersion(featureDirectory) {
  try {
    const current = JSON.parse(fs.readFileSync(path.join(featureDirectory, 'current.json'), 'utf8'));
    return /^\d+\.\d{2}\.\d{3}$/.test(String(current.version || '')) ? current.version : '0.00.000';
  } catch { return '0.00.000'; }
}

function loadFeatureKey(packagedKeyPath) {
  if (process.env.NEUTRON_FEATURE_KEY_BASE64) {
    const key = Buffer.from(process.env.NEUTRON_FEATURE_KEY_BASE64.trim(), 'base64');
    if (key.length !== 32) throw new FeatureUpdateError('INVALID_DECRYPTION_KEY', 'Feature Update runtime key is invalid.');
    return key;
  }
  const keyPath = process.env.NEUTRON_FEATURE_KEY_FILE || packagedKeyPath;
  if (!keyPath || !fs.existsSync(keyPath)) throw new FeatureUpdateError('MISSING_DECRYPTION_KEY', 'Feature Update runtime key is not available.');
  return readEncryptionKey(keyPath);
}

function installStagedFeature(stagingDirectory, featureDirectory, version) {
  const parent = path.dirname(featureDirectory);
  const backup = `${featureDirectory}.previous`;
  fs.mkdirSync(parent, { recursive: true });
  fs.writeFileSync(path.join(stagingDirectory, 'current.json'), `${JSON.stringify({ feature: 'machine-learning-models', version, installed_at: new Date().toISOString() }, null, 2)}\n`, { flag: 'wx' });
  if (fs.existsSync(backup)) fs.rmSync(backup, { recursive: true, force: true });
  let movedCurrent = false;
  try {
    if (fs.existsSync(featureDirectory)) {
      fs.renameSync(featureDirectory, backup);
      movedCurrent = true;
    }
    fs.renameSync(stagingDirectory, featureDirectory);
  } catch (error) {
    if (movedCurrent && !fs.existsSync(featureDirectory) && fs.existsSync(backup)) fs.renameSync(backup, featureDirectory);
    throw error;
  }
}

class FeatureUpdater {
  constructor(options) {
    this.releasesUrl = options.releasesUrl || DEFAULT_RELEASES_URL;
    this.publicKeyPath = options.publicKeyPath;
    this.packagedKeyPath = options.packagedKeyPath;
    this.featureDirectory = options.featureDirectory;
    this.userAgent = options.userAgent || 'Neutron/0.1.0';
    this.appVersion = options.appVersion || '0.0.0';
    this.allowLoopback = Boolean(options.allowLoopback);
    this.onEvent = options.onEvent || (() => {});
  }

  emit(stage, detail = {}) { this.onEvent({ stage, ...detail }); }

  status() {
    const version = currentFeatureVersion(this.featureDirectory);
    const ready = version !== '0.00.000' && fs.existsSync(path.join(this.featureDirectory, 'ensemble.json'));
    return { ok: true, ready, version: ready ? version : null, model_count: ready ? fs.readdirSync(this.featureDirectory).filter((name) => name.endsWith('.model')).length : 0 };
  }

  async check() {
    this.emit('checking');
    const bytes = await fetchBytes(this.releasesUrl, { maximumBytes: 2 * 1024 * 1024, accept: 'application/vnd.github+json', userAgent: this.userAgent, allowLoopback: this.allowLoopback });
    const latest = selectLatestFeatureRelease(parseJson(bytes, 'INVALID_RELEASES', 'Feature Update release list could not be read.'));
    const currentVersion = currentFeatureVersion(this.featureDirectory);
    if (!latest) return { available: false, reason: 'no-release', currentVersion };
    if (compareVersions(latest.version, currentVersion) <= 0) return { available: false, reason: 'current', currentVersion, latestVersion: latest.version };
    return { available: true, currentVersion, latestVersion: latest.version, candidate: latest };
  }

  async downloadAndInstall(checkResult) {
    if (!checkResult?.available || !checkResult.candidate) throw new FeatureUpdateError('NO_UPDATE', 'No Feature Update is available.');
    const version = checkResult.latestVersion;
    const release = checkResult.candidate.release;
    const manifestName = `feature-${version}.json`;
    const signatureName = `${manifestName}.sig`;
    this.emit('downloading-manifest', { version });
    const manifestBytes = await fetchBytes(assetByName(release, manifestName).browser_download_url, { maximumBytes: MAX_MANIFEST_BYTES, userAgent: this.userAgent, allowLoopback: this.allowLoopback });
    const signatureBytes = await fetchBytes(assetByName(release, signatureName).browser_download_url, { maximumBytes: MAX_SIGNATURE_BYTES, userAgent: this.userAgent, allowLoopback: this.allowLoopback });
    const publicKey = fs.readFileSync(this.publicKeyPath);
    verifyManifestSignature(manifestBytes, parseJson(signatureBytes, 'INVALID_SIGNATURE_DOCUMENT', 'Feature Update signature could not be read.'), publicKey);
    const manifest = validateManifest(parseJson(manifestBytes, 'INVALID_MANIFEST', 'Feature Update manifest could not be read.'));
    if (manifest.version !== version) throw new FeatureUpdateError('VERSION_MISMATCH', 'Feature Update release and manifest versions do not match.');
    if (compareVersions(this.appVersion, manifest.minimum_app_version || '0.0.0') < 0) throw new FeatureUpdateError('APP_TOO_OLD', `Feature Update ${version} requires a newer Neutron version.`);
    const key = loadFeatureKey(this.packagedKeyPath);
    const parent = path.dirname(this.featureDirectory);
    fs.mkdirSync(parent, { recursive: true });
    const staging = path.join(parent, `.ember2024-${process.pid}-${crypto.randomBytes(6).toString('hex')}.tmp`);
    fs.mkdirSync(staging, { recursive: false, mode: 0o700 });
    let receivedTotal = 0;
    const expectedTotal = manifest.files.reduce(
      (sum, entry) => sum + entry.chunks.reduce((fileSum, chunk) => fileSum + chunk.encrypted_bytes, 0),
      0,
    );
    try {
      for (let index = 0; index < manifest.files.length; index += 1) {
        const entry = manifest.files[index];
        const targetPath = path.join(staging, entry.name);
        const descriptor = fs.openSync(targetPath, 'wx', 0o600);
        const fileHash = crypto.createHash('sha256');
        let written = 0;
        try {
          for (const chunk of entry.chunks) {
            const encrypted = await fetchBytes(assetByName(release, chunk.asset).browser_download_url, {
              maximumBytes: Math.min(MAX_ASSET_BYTES, chunk.encrypted_bytes + 1),
              userAgent: this.userAgent,
              allowLoopback: this.allowLoopback,
              onProgress: ({ receivedBytes }) => {
                const progress = Math.min(99, Math.round(((receivedTotal + receivedBytes) / expectedTotal) * 100));
                this.emit('downloading', { version, progress, file: index + 1, files: manifest.files.length });
              },
            });
            const plaintext = decryptFeatureFile(encrypted, chunk, key);
            fs.writeSync(descriptor, plaintext, 0, plaintext.length, written);
            fileHash.update(plaintext);
            written += plaintext.length;
            receivedTotal += encrypted.length;
          }
        } finally {
          fs.closeSync(descriptor);
        }
        if (written !== entry.plaintext_bytes || fileHash.digest('hex') !== entry.plaintext_sha256) {
          throw new FeatureUpdateError('FILE_HASH_MISMATCH', `Feature Update file failed verification: ${entry.name}`);
        }
      }
      this.emit('installing', { version });
      installStagedFeature(staging, this.featureDirectory, version);
      this.emit('complete', { version });
      return { ok: true, updated: true, version, model_count: 14 };
    } catch (error) {
      try { fs.rmSync(staging, { recursive: true, force: true }); } catch { /* best effort */ }
      throw error;
    }
  }
}

module.exports = { DEFAULT_RELEASES_URL, FeatureUpdateError, FeatureUpdater, currentFeatureVersion, selectLatestFeatureRelease };
