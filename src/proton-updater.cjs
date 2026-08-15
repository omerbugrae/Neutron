'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  decryptPackage,
  readEncryptionKey,
  verifyPackageSignature,
} = require('./proton-format.cjs');

const DEFAULT_RELEASES_URL = 'https://api.github.com/repos/omerbugrae/NeutronProton/releases?per_page=30';
const RELEASE_TAG_PATTERN = /^proton-v(\d+\.\d{2}\.\d{3})$/;
const MAX_API_BYTES = 2 * 1024 * 1024;
const MAX_PACKAGE_BYTES = 72 * 1024 * 1024;
const MAX_SIGNATURE_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_REDIRECTS = 5;

class ProtonUpdateError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ProtonUpdateError';
    this.code = code;
  }
}

function compareVersions(left, right) {
  const parse = (value) => String(value || '0.00.000').split('.').map((part) => Number(part));
  const a = parse(left);
  const b = parse(right);
  for (let index = 0; index < 3; index += 1) {
    if ((a[index] || 0) !== (b[index] || 0)) return (a[index] || 0) - (b[index] || 0);
  }
  return 0;
}

function isLoopback(hostname) {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
}

function assertAllowedUrl(rawUrl, allowLoopback = false) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new ProtonUpdateError('INVALID_URL', 'Proton güncelleme adresi geçersiz.');
  }
  if (allowLoopback && isLoopback(url.hostname) && ['http:', 'https:'].includes(url.protocol)) return url;
  const allowedHost = url.hostname === 'api.github.com'
    || url.hostname === 'github.com'
    || url.hostname === 'objects.githubusercontent.com'
    || url.hostname.endsWith('.githubusercontent.com');
  if (url.protocol !== 'https:' || !allowedHost) {
    throw new ProtonUpdateError('UNTRUSTED_URL', 'Proton güncellemesi güvenilmeyen bir adrese yönlendirildi.');
  }
  return url;
}

async function fetchBytes(rawUrl, options = {}) {
  const maximumBytes = options.maximumBytes;
  const allowLoopback = Boolean(options.allowLoopback);
  let currentUrl = assertAllowedUrl(rawUrl, allowLoopback);
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs || REQUEST_TIMEOUT_MS);
    let response;
    try {
      response = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'Accept': options.accept || 'application/octet-stream',
          'User-Agent': options.userAgent || 'Neutron/0.1.0',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      });
    } catch (error) {
      clearTimeout(timer);
      const timedOut = error?.name === 'AbortError';
      throw new ProtonUpdateError(
        timedOut ? 'REQUEST_TIMEOUT' : 'NETWORK_ERROR',
        timedOut ? 'Proton sunucusu zamanında yanıt vermedi.' : 'Proton sunucusuna bağlanılamadı.',
      );
    }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      clearTimeout(timer);
      const location = response.headers.get('location');
      if (!location || redirects === MAX_REDIRECTS) {
        throw new ProtonUpdateError('TOO_MANY_REDIRECTS', 'Proton indirmesi çok fazla yönlendirme içeriyor.');
      }
      currentUrl = assertAllowedUrl(new URL(location, currentUrl).toString(), allowLoopback);
      continue;
    }
    if (!response.ok) {
      clearTimeout(timer);
      const rateLimited = response.status === 403 || response.status === 429;
      throw new ProtonUpdateError(
        rateLimited ? 'RATE_LIMITED' : 'HTTP_ERROR',
        rateLimited
          ? 'GitHub sorgu sınırına ulaşıldı. Daha sonra yeniden deneyin.'
          : `Proton sunucusu HTTP ${response.status} yanıtı verdi.`,
      );
    }

    const declaredLength = Number(response.headers.get('content-length'));
    if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
      clearTimeout(timer);
      throw new ProtonUpdateError('DOWNLOAD_TOO_LARGE', 'Proton güncelleme dosyası izin verilen boyutu aşıyor.');
    }
    if (!response.body) {
      clearTimeout(timer);
      throw new ProtonUpdateError('EMPTY_RESPONSE', 'Proton sunucusu boş yanıt verdi.');
    }
    const reader = response.body.getReader();
    const chunks = [];
    let receivedBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        receivedBytes += value.byteLength;
        if (receivedBytes > maximumBytes) {
          await reader.cancel();
          throw new ProtonUpdateError('DOWNLOAD_TOO_LARGE', 'Proton güncelleme dosyası izin verilen boyutu aşıyor.');
        }
        chunks.push(Buffer.from(value));
        options.onProgress?.({ receivedBytes, totalBytes: declaredLength || null });
      }
    } catch (error) {
      if (error instanceof ProtonUpdateError) throw error;
      throw new ProtonUpdateError(
        error?.name === 'AbortError' ? 'REQUEST_TIMEOUT' : 'NETWORK_ERROR',
        error?.name === 'AbortError'
          ? 'Proton indirmesi zamanında tamamlanamadı.'
          : 'Proton indirmesi sırasında bağlantı kesildi.',
      );
    } finally {
      clearTimeout(timer);
    }
    if (receivedBytes === 0) throw new ProtonUpdateError('EMPTY_RESPONSE', 'Proton sunucusu boş yanıt verdi.');
    return Buffer.concat(chunks, receivedBytes);
  }
  throw new ProtonUpdateError('TOO_MANY_REDIRECTS', 'Proton indirmesi tamamlanamadı.');
}

function selectLatestRelease(releases) {
  if (!Array.isArray(releases)) throw new ProtonUpdateError('INVALID_RELEASES', 'GitHub sürüm yanıtı geçersiz.');
  const candidates = releases
    .filter((release) => release && !release.draft && !release.prerelease)
    .map((release) => {
      const match = RELEASE_TAG_PATTERN.exec(String(release.tag_name || ''));
      return match ? { release, version: match[1] } : null;
    })
    .filter(Boolean)
    .sort((left, right) => compareVersions(right.version, left.version));
  return candidates[0] || null;
}

function releaseAssets(candidate) {
  const assets = Array.isArray(candidate.release.assets) ? candidate.release.assets : [];
  const packageName = `proton-${candidate.version}.pdbx`;
  const signatureName = `${packageName}.sig`;
  const packageAsset = assets.find((asset) => asset?.name === packageName);
  const signatureAsset = assets.find((asset) => asset?.name === signatureName);
  if (!packageAsset?.browser_download_url || !signatureAsset?.browser_download_url) {
    throw new ProtonUpdateError('MISSING_ASSETS', `Proton ${candidate.version} yayını gerekli paketleri içermiyor.`);
  }
  return { packageName, packageAsset, signatureAsset };
}

function parseSignatureDocument(bytes) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new ProtonUpdateError('INVALID_SIGNATURE_DOCUMENT', 'Proton imza belgesi okunamadı.');
  }
}

function loadRuntimeEncryptionKey(options = {}) {
  if (process.env.NEUTRON_PROTON_KEY_BASE64) {
    const key = Buffer.from(process.env.NEUTRON_PROTON_KEY_BASE64.trim(), 'base64');
    if (key.length !== 32) throw new ProtonUpdateError('INVALID_DECRYPTION_KEY', 'Proton çalışma anahtarı geçersiz.');
    return key;
  }
  const candidates = [
    process.env.NEUTRON_PROTON_KEY_FILE,
    options.packagedKeyPath,
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return readEncryptionKey(candidate);
  }
  throw new ProtonUpdateError(
    'MISSING_DECRYPTION_KEY',
    'Proton güncelleme anahtarı bu Neutron derlemesine bağlanmamış.',
  );
}

function writeEncryptedArchive(updateDirectory, version, packageBytes, signatureBytes) {
  fs.mkdirSync(updateDirectory, { recursive: true, mode: 0o700 });
  const packageName = `proton-${version}.pdbx`;
  const signatureName = `${packageName}.sig`;
  const packagePath = path.join(updateDirectory, packageName);
  const signaturePath = path.join(updateDirectory, signatureName);
  const writeOnceAtomically = (target, bytes) => {
    if (fs.existsSync(target)) return;
    const temporary = path.join(updateDirectory, `.${path.basename(target)}-${process.pid}-${crypto.randomBytes(6).toString('hex')}.tmp`);
    try {
      fs.writeFileSync(temporary, bytes, { flag: 'wx', mode: 0o600 });
      fs.renameSync(temporary, target);
    } finally {
      try { fs.rmSync(temporary, { force: true }); } catch { /* best effort */ }
    }
  };
  writeOnceAtomically(packagePath, packageBytes);
  writeOnceAtomically(signaturePath, signatureBytes);
  const current = {
    database_name: 'Proton',
    version,
    package_file: packageName,
    signature_file: signatureName,
    installed_at: new Date().toISOString(),
  };
  const currentPath = path.join(updateDirectory, 'current.json');
  const previousPath = path.join(updateDirectory, 'previous.json');
  const temporaryPath = path.join(updateDirectory, `.current-${process.pid}-${crypto.randomBytes(6).toString('hex')}.tmp`);
  fs.writeFileSync(temporaryPath, `${JSON.stringify(current, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  let movedCurrent = false;
  try {
    if (fs.existsSync(previousPath)) fs.rmSync(previousPath, { force: true });
    if (fs.existsSync(currentPath)) {
      fs.renameSync(currentPath, previousPath);
      movedCurrent = true;
    }
    fs.renameSync(temporaryPath, currentPath);
  } catch (error) {
    if (movedCurrent && !fs.existsSync(currentPath) && fs.existsSync(previousPath)) {
      fs.renameSync(previousPath, currentPath);
    }
    throw error;
  } finally {
    try { fs.rmSync(temporaryPath, { force: true }); } catch { /* best effort */ }
  }
  return current;
}

class ProtonUpdater {
  constructor(options) {
    this.releasesUrl = options.releasesUrl || DEFAULT_RELEASES_URL;
    this.publicKeyPath = options.publicKeyPath;
    this.packagedKeyPath = options.packagedKeyPath;
    this.updateDirectory = options.updateDirectory;
    this.userAgent = options.userAgent || 'Neutron/0.1.0';
    this.appVersion = options.appVersion || '0.0.0';
    this.allowLoopback = Boolean(options.allowLoopback);
    this.onEvent = options.onEvent || (() => {});
  }

  emit(stage, detail = {}) {
    this.onEvent({ stage, ...detail });
  }

  async check(currentVersion) {
    this.emit('checking');
    const apiBytes = await fetchBytes(this.releasesUrl, {
      maximumBytes: MAX_API_BYTES,
      accept: 'application/vnd.github+json',
      userAgent: this.userAgent,
      allowLoopback: this.allowLoopback,
    });
    let releases;
    try {
      releases = JSON.parse(apiBytes.toString('utf8'));
    } catch {
      throw new ProtonUpdateError('INVALID_RELEASES', 'GitHub sürüm listesi okunamadı.');
    }
    const latest = selectLatestRelease(releases);
    if (!latest) return { available: false, reason: 'no-release', currentVersion };
    if (compareVersions(latest.version, currentVersion) <= 0) {
      return { available: false, reason: 'current', currentVersion, latestVersion: latest.version };
    }
    return { available: true, currentVersion, latestVersion: latest.version, candidate: latest };
  }

  async downloadAndDecrypt(checkResult) {
    if (!checkResult?.available || !checkResult.candidate) {
      throw new ProtonUpdateError('NO_UPDATE', 'Kurulacak yeni Proton sürümü yok.');
    }
    const assets = releaseAssets(checkResult.candidate);
    this.emit('downloading', { version: checkResult.latestVersion, progress: 0 });
    const packageBytes = await fetchBytes(assets.packageAsset.browser_download_url, {
      maximumBytes: MAX_PACKAGE_BYTES,
      userAgent: this.userAgent,
      allowLoopback: this.allowLoopback,
      onProgress: ({ receivedBytes, totalBytes }) => {
        const progress = totalBytes ? Math.min(99, Math.round((receivedBytes / totalBytes) * 100)) : null;
        this.emit('downloading', { version: checkResult.latestVersion, progress, receivedBytes, totalBytes });
      },
    });
    const signatureBytes = await fetchBytes(assets.signatureAsset.browser_download_url, {
      maximumBytes: MAX_SIGNATURE_BYTES,
      userAgent: this.userAgent,
      allowLoopback: this.allowLoopback,
    });
    this.emit('verifying', { version: checkResult.latestVersion });
    const publicKey = fs.readFileSync(this.publicKeyPath);
    const signatureDocument = parseSignatureDocument(signatureBytes);
    verifyPackageSignature(packageBytes, signatureDocument, publicKey);
    const encryptionKey = loadRuntimeEncryptionKey({ packagedKeyPath: this.packagedKeyPath });
    const { header, payload } = decryptPackage(packageBytes, encryptionKey);
    if (payload.version !== checkResult.latestVersion || header.database_version !== checkResult.latestVersion) {
      throw new ProtonUpdateError('VERSION_MISMATCH', 'GitHub yayını ile Proton paket sürümü uyuşmuyor.');
    }
    if (compareVersions(this.appVersion, payload.minimum_engine_version || '0.0.0') < 0) {
      throw new ProtonUpdateError(
        'ENGINE_TOO_OLD',
        `Proton ${payload.version}, Neutron ${payload.minimum_engine_version} veya daha yeni bir sürüm gerektiriyor.`,
      );
    }
    return { version: payload.version, payload, packageBytes, signatureBytes };
  }

  verifyLocalArchive(packagePath, signaturePath, expectedVersion) {
    const packageStat = fs.statSync(packagePath);
    const signatureStat = fs.statSync(signaturePath);
    if (!packageStat.isFile() || packageStat.size <= 0 || packageStat.size > MAX_PACKAGE_BYTES) {
      throw new ProtonUpdateError('DOWNLOAD_TOO_LARGE', 'Yerel Proton paketi geçersiz veya çok büyük.');
    }
    if (!signatureStat.isFile() || signatureStat.size <= 0 || signatureStat.size > MAX_SIGNATURE_BYTES) {
      throw new ProtonUpdateError('INVALID_SIGNATURE_DOCUMENT', 'Yerel Proton imza belgesi geçersiz.');
    }
    const packageBytes = fs.readFileSync(packagePath);
    const signatureBytes = fs.readFileSync(signaturePath);
    const signatureDocument = parseSignatureDocument(signatureBytes);
    const publicKey = fs.readFileSync(this.publicKeyPath);
    verifyPackageSignature(packageBytes, signatureDocument, publicKey);
    const encryptionKey = loadRuntimeEncryptionKey({ packagedKeyPath: this.packagedKeyPath });
    const { header, payload } = decryptPackage(packageBytes, encryptionKey);
    if (payload.version !== expectedVersion || header.database_version !== expectedVersion) {
      throw new ProtonUpdateError('VERSION_MISMATCH', 'Yerel Proton paketi beklenen sürümle uyuşmuyor.');
    }
    if (compareVersions(this.appVersion, payload.minimum_engine_version || '0.0.0') < 0) {
      throw new ProtonUpdateError('ENGINE_TOO_OLD', 'Yerel Proton paketi daha yeni bir Neutron sürümü gerektiriyor.');
    }
    return { version: payload.version, payload, packageBytes, signatureBytes };
  }

  archiveVerifiedUpdate(result) {
    return writeEncryptedArchive(
      this.updateDirectory,
      result.version,
      result.packageBytes,
      result.signatureBytes,
    );
  }
}

module.exports = {
  DEFAULT_RELEASES_URL,
  ProtonUpdateError,
  ProtonUpdater,
  compareVersions,
  fetchBytes,
  releaseAssets,
  selectLatestRelease,
};
