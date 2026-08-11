#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { buildPackage, sha256 } = require('./proton-format.cjs');
const { ProtonUpdater } = require('../../src/proton-updater.cjs');

async function main() {
  const projectRoot = path.resolve(__dirname, '..', '..');
  const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'neutron-proton-updater-'));
  let server;
  try {
    const encryptionKey = crypto.randomBytes(32);
    const keys = crypto.generateKeyPairSync('ed25519');
    const publicPem = keys.publicKey.export({ type: 'spki', format: 'pem' });
    const publicKeyPath = path.join(testRoot, 'public.pem');
    const encryptionKeyPath = path.join(testRoot, 'encryption.key');
    fs.writeFileSync(publicKeyPath, publicPem);
    fs.writeFileSync(encryptionKeyPath, `${encryptionKey.toString('base64')}\n`);

    const yaraContent = 'rule Proton_Update_Safe_Test { strings: $a = "NEUTRON_UPDATE_SAFE_TEST" condition: $a }';
    const payload = {
      schema: 'neutron.proton.payload/v1',
      database_name: 'Proton',
      version: '1.00.002',
      minimum_engine_version: '0.1.0',
      created_at: '2026-08-11T00:00:00.000Z',
      signatures: [{
        sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
        file_size: 68,
        name: 'EICAR güvenli test imzası',
        severity: 'high',
      }],
      yara_rules: [{
        name: 'proton_update_safe_test.yar',
        sha256: sha256(Buffer.from(yaraContent, 'utf8')),
        content: yaraContent,
      }],
    };
    const built = buildPackage(payload, encryptionKey, keys.privateKey, keys.publicKey);
    built.signatureDocument.package_file = 'proton-1.00.002.pdbx';
    const signatureBytes = Buffer.from(`${JSON.stringify(built.signatureDocument)}\n`, 'utf8');

    server = http.createServer((request, response) => {
      const origin = `http://127.0.0.1:${server.address().port}`;
      if (request.url === '/releases') {
        const body = Buffer.from(JSON.stringify([{
          tag_name: 'proton-v1.00.002',
          draft: false,
          prerelease: false,
          assets: [
            { name: 'proton-1.00.002.pdbx', browser_download_url: `${origin}/package` },
            { name: 'proton-1.00.002.pdbx.sig', browser_download_url: `${origin}/signature` },
          ],
        }]));
        response.writeHead(200, { 'content-type': 'application/json', 'content-length': body.length });
        response.end(body);
        return;
      }
      const body = request.url === '/package'
        ? built.packageBytes
        : request.url === '/signature' ? signatureBytes : null;
      if (!body) {
        response.writeHead(404).end();
        return;
      }
      response.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': body.length });
      response.end(body);
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });

    const updater = new ProtonUpdater({
      releasesUrl: `http://127.0.0.1:${server.address().port}/releases`,
      publicKeyPath,
      packagedKeyPath: encryptionKeyPath,
      updateDirectory: path.join(testRoot, 'archive'),
      appVersion: '0.1.0',
      allowLoopback: true,
    });
    const check = await updater.check('1.00.001');
    assert.equal(check.available, true);
    assert.equal(check.latestVersion, '1.00.002');
    const downloaded = await updater.downloadAndDecrypt(check);
    assert.deepEqual(downloaded.payload, payload);

    const python = process.platform === 'win32'
      ? path.join(projectRoot, 'venv', 'Scripts', 'python.exe')
      : path.join(projectRoot, 'venv', 'bin', 'python');
    const enginePath = path.join(projectRoot, 'src', 'engine.py');
    const dataDirectory = path.join(testRoot, 'data');
    const install = spawnSync(python, [enginePath, '--install-proton-stdin', '--json-lines'], {
      cwd: path.dirname(enginePath),
      env: { ...process.env, NEUTRON_DATA_DIR: dataDirectory },
      input: JSON.stringify(downloaded.payload),
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 2 * 1024 * 1024,
    });
    assert.equal(install.status, 0, install.stderr || install.stdout);
    const installEvent = JSON.parse(install.stdout.trim().split(/\r?\n/).at(-1));
    assert.equal(installEvent.type, 'signature-updated');
    assert.equal(installEvent.version, '1.00.002');
    assert.equal(installEvent.source, 'github-release');
    assert.equal(installEvent.yara_rule_files, 1);

    const invalidYara = 'rule Proton_Broken { condition: }';
    const invalidPayload = {
      ...downloaded.payload,
      version: '1.00.003',
      yara_rules: [{
        name: 'broken.yar',
        sha256: sha256(Buffer.from(invalidYara, 'utf8')),
        content: invalidYara,
      }],
    };
    const rejected = spawnSync(python, [enginePath, '--install-proton-stdin', '--json-lines'], {
      cwd: path.dirname(enginePath),
      env: { ...process.env, NEUTRON_DATA_DIR: dataDirectory },
      input: JSON.stringify(invalidPayload),
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 2 * 1024 * 1024,
    });
    assert.equal(rejected.status, 2, 'Bozuk YARA paketi reddedilmeliydi.');
    const statusAfterRejection = spawnSync(python, [enginePath, '--signature-status', '--json-lines'], {
      cwd: path.dirname(enginePath),
      env: { ...process.env, NEUTRON_DATA_DIR: dataDirectory },
      encoding: 'utf8',
      windowsHide: true,
    });
    assert.equal(statusAfterRejection.status, 0);
    const retainedStatus = JSON.parse(statusAfterRejection.stdout.trim().split(/\r?\n/).at(-1));
    assert.equal(retainedStatus.version, '1.00.002', 'Reddedilen paket kurulu sürümü değiştirmemeli.');

    const archived = updater.archiveVerifiedUpdate(downloaded);
    assert.equal(archived.version, '1.00.002');
    assert.equal(fs.existsSync(path.join(testRoot, 'archive', archived.package_file)), true);
    const currentCheck = await updater.check('1.00.002');
    assert.equal(currentCheck.available, false);
    assert.equal(currentCheck.reason, 'current');
    console.log('Proton GitHub güncelleme uçtan uca öz testi başarılı.');
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    const resolvedRoot = path.resolve(testRoot);
    const resolvedTemp = path.resolve(os.tmpdir());
    if (resolvedRoot.startsWith(`${resolvedTemp}${path.sep}`)) {
      fs.rmSync(resolvedRoot, { recursive: true, force: true });
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
