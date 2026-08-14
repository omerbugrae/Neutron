#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { readJsonFile, validateVersion } = require('../../src/proton-format.cjs');

const DEFAULT_REPOSITORY = 'omerbugrae/NeutronProton';
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

function githubCliExecutable() {
  const configured = process.env.NEUTRON_GH_BIN;
  if (configured) return configured;
  if (process.platform === 'win32') {
    const candidates = [
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'GitHub CLI', 'gh.exe'),
      path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'GitHub CLI', 'gh.exe'),
      process.env.LOCALAPPDATA
        ? path.join(process.env.LOCALAPPDATA, 'Programs', 'GitHub CLI', 'gh.exe')
        : null,
      process.env.LOCALAPPDATA
        ? path.join(process.env.LOCALAPPDATA, 'Microsoft', 'WinGet', 'Links', 'gh.exe')
        : null,
    ].filter(Boolean);
    const installed = candidates.find((candidate) => fs.existsSync(candidate));
    if (installed) return installed;
  }
  return 'gh';
}

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function defaultGhRunner(argumentsList, options = {}) {
  return spawnSync(githubCliExecutable(), argumentsList, {
    encoding: 'utf8',
    windowsHide: true,
    stdio: options.silent ? ['ignore', 'pipe', 'pipe'] : 'inherit',
  });
}

function runNodeTool(scriptPath, argumentsList) {
  const result = spawnSync(process.execPath, [scriptPath, ...argumentsList], {
    encoding: 'utf8',
    windowsHide: true,
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${path.basename(scriptPath)} işlemi başarısız oldu.`);
}

function assertGhAvailable(runGh) {
  const version = runGh(['--version'], { silent: true });
  if (version.error?.code === 'ENOENT') {
    throw new Error('GitHub CLI bulunamadı. Önce "winget install --id GitHub.cli" komutuyla kurun.');
  }
  if (version.error || version.status !== 0) throw new Error('GitHub CLI çalıştırılamadı.');
  const authentication = runGh(['auth', 'status', '--hostname', 'github.com'], { silent: true });
  if (authentication.status !== 0) {
    throw new Error('GitHub oturumu açık değil. Önce "gh auth login" komutunu çalıştırın.');
  }
}

function publish(options, dependencies = {}) {
  const runGh = dependencies.runGh || defaultGhRunner;
  const sourcePath = path.resolve(options.source);
  const keysDirectory = path.resolve(options.keys);
  const outputDirectory = path.resolve(options.output);
  const repository = options.repository || DEFAULT_REPOSITORY;
  if (!REPOSITORY_PATTERN.test(repository)) throw new Error('GitHub deposu OWNER/REPO biçiminde olmalı.');

  const source = readJsonFile(sourcePath);
  const version = validateVersion(source.version);
  if (source.database_name !== 'Proton') throw new Error('Yalnız Proton veritabanı yayımlanabilir.');
  const tag = `proton-v${version}`;
  const packageName = `proton-${version}.pdbx`;
  const signatureName = `${packageName}.sig`;
  const packagePath = path.join(outputDirectory, packageName);
  const signaturePath = path.join(outputDirectory, signatureName);
  const publicKeyPath = path.join(keysDirectory, 'proton-signing-public.pem');
  const encryptionKeyPath = path.join(keysDirectory, 'proton-encryption.key');

  assertGhAvailable(runGh);
  const existingRelease = runGh(
    ['release', 'view', tag, '--repo', repository, '--json', 'tagName'],
    { silent: true },
  );
  if (existingRelease.status === 0) {
    throw new Error(`${tag} zaten GitHub üzerinde yayımlanmış. Yayınların üzerine yazılmaz.`);
  }

  fs.mkdirSync(outputDirectory, { recursive: true });
  const packageExists = fs.existsSync(packagePath);
  const signatureExists = fs.existsSync(signaturePath);
  if (packageExists !== signatureExists) {
    throw new Error('Yayın klasöründe paketin yalnız bir parçası var; klasörü düzeltip yeniden deneyin.');
  }
  if (!packageExists) {
    runNodeTool(path.join(__dirname, 'pack.cjs'), [
      '--source', sourcePath,
      '--keys', keysDirectory,
      '--output', outputDirectory,
    ]);
  } else {
    console.log(`${tag} paketi zaten yerelde var; yeniden doğrulanarak kullanılacak.`);
  }

  runNodeTool(path.join(__dirname, 'verify.cjs'), [
    '--package', packagePath,
    '--signature', signaturePath,
    '--public-key', publicKeyPath,
    '--encryption-key', encryptionKeyPath,
  ]);

  const releaseNotes = [
    `Proton ${version} tehdit tanımı güncellemesi.`,
    '',
    '- AES-256-GCM ile şifrelenmiş veritabanı paketi',
    '- Ed25519 ile imzalanmış yayın',
    '- Yalnız resmi Neutron güncelleme istemcisi için',
  ].join('\n');
  const creation = runGh([
    'release', 'create', tag,
    packagePath,
    signaturePath,
    '--repo', repository,
    '--title', `Proton ${version}`,
    '--notes', releaseNotes,
  ]);
  if (creation.error) throw creation.error;
  if (creation.status !== 0) {
    throw new Error('GitHub Release oluşturulamadı; yerel paketler yeniden denemek için korundu.');
  }
  console.log(`Proton ${version}, ${repository} deposunda ${tag} etiketiyle yayımlandı.`);
  return { repository, tag, version, packagePath, signaturePath };
}

if (require.main === module) {
  try {
    const source = argument('--source');
    const keys = argument('--keys');
    const output = argument('--output');
    const repository = argument('--repo') || DEFAULT_REPOSITORY;
    if (!source || !keys || !output) {
      throw new Error('Kullanım: npm run proton:publish -- --source <definitions.json> --keys <anahtar-klasörü> --output <yayın-klasörü> [--repo OWNER/REPO]');
    }
    publish({ source, keys, output, repository });
  } catch (error) {
    console.error(`Hata: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { DEFAULT_REPOSITORY, publish };
