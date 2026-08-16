#!/usr/bin/env node
'use strict';

/*
 * Neutron Archive Engine protocol v1
 *
 * The process accepts one ZIP archive as raw stdin and emits JSON Lines. It
 * never writes archive members to disk. Every allocation and decompression is
 * bounded before it happens; the Python scanner applies the same limits again.
 *
 * This first engine version intentionally supports ZIP only. 7Z and RAR are
 * detected by the caller but are not delegated to an installed application.
 */

const { once } = require('node:events');
const process = require('node:process');
const zlib = require('node:zlib');

const PROTOCOL_VERSION = 1;
const ENGINE_VERSION = '1.0.0';
const MAX_INPUT_BYTES = 64 * 1024 * 1024;
const MAX_MEMBER_BYTES = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES = 128 * 1024 * 1024;
const MAX_MEMBERS = 512;
const MAX_COMPRESSION_RATIO = 250;
const MAX_NAME_BYTES = 4096;
const EOCD_MIN_SIZE = 22;
const EOCD_SEARCH_SIZE = 65_535 + EOCD_MIN_SIZE;

class ArchiveError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ArchiveError';
    this.code = code;
  }
}

async function emit(event) {
  const line = `${JSON.stringify(event)}\n`;
  if (!process.stdout.write(line, 'utf8')) {
    await once(process.stdout, 'drain');
  }
}

function readUInt16(buffer, offset, label) {
  if (offset < 0 || offset + 2 > buffer.length) {
    throw new ArchiveError('truncated', `${label} alanı arşiv sınırının dışında.`);
  }
  return buffer.readUInt16LE(offset);
}

function readUInt32(buffer, offset, label) {
  if (offset < 0 || offset + 4 > buffer.length) {
    throw new ArchiveError('truncated', `${label} alanı arşiv sınırının dışında.`);
  }
  return buffer.readUInt32LE(offset);
}

function checkedSlice(buffer, start, length, label) {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length)
      || start < 0 || length < 0 || start + length > buffer.length) {
    throw new ArchiveError('truncated', `${label} arşiv sınırının dışında.`);
  }
  return buffer.subarray(start, start + length);
}

function findEndOfCentralDirectory(buffer) {
  const start = Math.max(0, buffer.length - EOCD_SEARCH_SIZE);
  for (let offset = buffer.length - EOCD_MIN_SIZE; offset >= start; offset -= 1) {
    if (buffer.readUInt32LE(offset) !== 0x06054b50) continue;
    const commentLength = readUInt16(buffer, offset + 20, 'EOCD comment length');
    if (offset + EOCD_MIN_SIZE + commentLength === buffer.length) return offset;
  }
  throw new ArchiveError('invalid-eocd', 'ZIP merkez dizin sonu bulunamadı.');
}

function decodeMemberName(bytes, utf8) {
  if (bytes.length > MAX_NAME_BYTES) {
    throw new ArchiveError('name-too-long', 'ZIP üye adı güvenlik sınırını aşıyor.');
  }
  const value = bytes.toString(utf8 ? 'utf8' : 'latin1').replaceAll('\0', '');
  return value || 'isimsiz-üye';
}

function parseCentralDirectory(buffer) {
  const eocd = findEndOfCentralDirectory(buffer);
  const diskNumber = readUInt16(buffer, eocd + 4, 'disk number');
  const centralDisk = readUInt16(buffer, eocd + 6, 'central disk');
  const diskEntries = readUInt16(buffer, eocd + 8, 'disk entries');
  const totalEntries = readUInt16(buffer, eocd + 10, 'total entries');
  const centralSize = readUInt32(buffer, eocd + 12, 'central size');
  const centralOffset = readUInt32(buffer, eocd + 16, 'central offset');

  if (diskNumber !== 0 || centralDisk !== 0 || diskEntries !== totalEntries) {
    throw new ArchiveError('multi-disk', 'Çok parçalı ZIP arşivleri desteklenmiyor.');
  }
  if (totalEntries === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) {
    throw new ArchiveError('zip64', 'ZIP64 bu motor sürümünde desteklenmiyor.');
  }
  if (centralOffset + centralSize > eocd || centralOffset > buffer.length) {
    throw new ArchiveError('invalid-central-directory', 'ZIP merkez dizini geçersiz konumda.');
  }

  const entries = [];
  let cursor = centralOffset;
  const acceptedEntries = Math.min(totalEntries, MAX_MEMBERS);
  for (let index = 0; index < acceptedEntries; index += 1) {
    if (readUInt32(buffer, cursor, 'central signature') !== 0x02014b50) {
      throw new ArchiveError('invalid-central-entry', 'ZIP merkez dizin kaydı geçersiz.');
    }
    const madeBy = readUInt16(buffer, cursor + 4, 'made by');
    const flags = readUInt16(buffer, cursor + 8, 'flags');
    const method = readUInt16(buffer, cursor + 10, 'method');
    const expectedCrc = readUInt32(buffer, cursor + 16, 'crc32');
    const compressedSize = readUInt32(buffer, cursor + 20, 'compressed size');
    const uncompressedSize = readUInt32(buffer, cursor + 24, 'uncompressed size');
    const nameLength = readUInt16(buffer, cursor + 28, 'name length');
    const extraLength = readUInt16(buffer, cursor + 30, 'extra length');
    const commentLength = readUInt16(buffer, cursor + 32, 'comment length');
    const diskStart = readUInt16(buffer, cursor + 34, 'disk start');
    const externalAttributes = readUInt32(buffer, cursor + 38, 'external attributes');
    const localOffset = readUInt32(buffer, cursor + 42, 'local offset');
    const recordLength = 46 + nameLength + extraLength + commentLength;
    const nameBytes = checkedSlice(buffer, cursor + 46, nameLength, 'member name');

    if (diskStart !== 0) {
      throw new ArchiveError('multi-disk', 'Üye farklı bir ZIP diskine işaret ediyor.');
    }
    if ([compressedSize, uncompressedSize, localOffset].includes(0xffffffff)) {
      throw new ArchiveError('zip64', 'ZIP64 üye kaydı bu motor sürümünde desteklenmiyor.');
    }
    const hostSystem = madeBy >>> 8;
    const unixMode = hostSystem === 3 ? (externalAttributes >>> 16) & 0xffff : 0;
    entries.push({
      name: decodeMemberName(nameBytes, Boolean(flags & 0x0800)),
      flags,
      method,
      expectedCrc,
      compressedSize,
      uncompressedSize,
      localOffset,
      isLink: (unixMode & 0o170000) === 0o120000,
      isDirectory: nameBytes.at(-1) === 0x2f || (unixMode & 0o170000) === 0o040000,
    });
    cursor += recordLength;
    if (cursor > centralOffset + centralSize) {
      throw new ArchiveError('invalid-central-directory', 'ZIP merkez dizin boyutu tutarsız.');
    }
  }
  return { entries, totalEntries };
}

function compressedPayload(buffer, entry) {
  const offset = entry.localOffset;
  if (readUInt32(buffer, offset, 'local signature') !== 0x04034b50) {
    throw new ArchiveError('invalid-local-entry', 'ZIP yerel dosya kaydı geçersiz.');
  }
  const localFlags = readUInt16(buffer, offset + 6, 'local flags');
  const localMethod = readUInt16(buffer, offset + 8, 'local method');
  const nameLength = readUInt16(buffer, offset + 26, 'local name length');
  const extraLength = readUInt16(buffer, offset + 28, 'local extra length');
  if (localMethod !== entry.method || (localFlags & 0x1) !== (entry.flags & 0x1)) {
    throw new ArchiveError('header-mismatch', 'ZIP merkez ve yerel kayıtları uyuşmuyor.');
  }
  return checkedSlice(
    buffer,
    offset + 30 + nameLength + extraLength,
    entry.compressedSize,
    'compressed member data',
  );
}

let crcTable = null;
function crc32(buffer) {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let value = 0; value < 256; value += 1) {
      let current = value;
      for (let bit = 0; bit < 8; bit += 1) {
        current = (current & 1) ? (0xedb88320 ^ (current >>> 1)) : (current >>> 1);
      }
      crcTable[value] = current >>> 0;
    }
  }
  let result = 0xffffffff;
  for (const byte of buffer) result = crcTable[(result ^ byte) & 0xff] ^ (result >>> 8);
  return (result ^ 0xffffffff) >>> 0;
}

function inflateEntry(buffer, entry) {
  const input = compressedPayload(buffer, entry);
  let output;
  if (entry.method === 0) {
    // MAX_MEMBER_BYTES is enforced against the *declared* uncompressed size,
    // which the archive controls. A stored member can declare 1 MB and carry
    // a 64 MB payload; the size mismatch below rejects it, but only after the
    // copy has already been made. Bound the input first.
    if (input.length > MAX_MEMBER_BYTES) {
      throw new ArchiveError('member-limit', 'ZIP üyesinin ham boyutu güvenlik sınırını aşıyor.');
    }
    output = Buffer.from(input);
  } else if (entry.method === 8) {
    output = zlib.inflateRawSync(input, { maxOutputLength: MAX_MEMBER_BYTES + 1 });
  } else {
    throw new ArchiveError('unsupported-method', `ZIP sıkıştırma yöntemi ${entry.method} desteklenmiyor.`);
  }
  if (output.length !== entry.uncompressedSize) {
    throw new ArchiveError('size-mismatch', 'ZIP üyesinin açılmış boyutu kayıtla uyuşmuyor.');
  }
  if (crc32(output) !== entry.expectedCrc) {
    throw new ArchiveError('crc-mismatch', 'ZIP üyesinin CRC32 doğrulaması başarısız.');
  }
  return output;
}

async function readStdin() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > MAX_INPUT_BYTES) {
      throw new ArchiveError('input-limit', 'Arşiv giriş boyutu güvenlik sınırını aşıyor.');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

async function scanZip(buffer) {
  const { entries, totalEntries } = parseCentralDirectory(buffer);
  await emit({
    type: 'archive', protocol: PROTOCOL_VERSION, engine: ENGINE_VERSION,
    format: 'zip', members_declared: totalEntries, members_accepted: entries.length,
  });
  if (totalEntries > MAX_MEMBERS) {
    await emit({ type: 'warning', code: 'member-limit', message: `${MAX_MEMBERS} üyeden sonrası atlandı.` });
  }

  let expandedBytes = 0;
  let emittedMembers = 0;
  for (const entry of entries) {
    if (entry.isDirectory) continue;
    const base = {
      type: 'member', name: entry.name,
      declared_size: entry.uncompressedSize, compressed_size: entry.compressedSize,
      encrypted: Boolean(entry.flags & 0x1), is_link: entry.isLink,
    };
    if (base.encrypted) {
      await emit({ ...base, skipped: 'encrypted' });
      continue;
    }
    if (entry.isLink) {
      await emit({ ...base, skipped: 'link' });
      continue;
    }
    if (entry.uncompressedSize > MAX_MEMBER_BYTES) {
      await emit({ ...base, skipped: 'member-limit' });
      continue;
    }
    const ratio = entry.compressedSize > 0 ? entry.uncompressedSize / entry.compressedSize : 0;
    if (entry.uncompressedSize >= 1024 * 1024 && ratio > MAX_COMPRESSION_RATIO) {
      await emit({ ...base, skipped: 'compression-ratio' });
      continue;
    }
    if (expandedBytes + entry.uncompressedSize > MAX_TOTAL_BYTES) {
      await emit({ type: 'warning', code: 'total-limit', message: 'Toplam açılmış boyut sınırına ulaşıldı.' });
      break;
    }
    try {
      const data = inflateEntry(buffer, entry);
      expandedBytes += data.length;
      emittedMembers += 1;
      await emit({ ...base, data: data.toString('base64') });
    } catch (error) {
      const code = error instanceof ArchiveError ? error.code : 'decompression-failed';
      await emit({ ...base, skipped: code });
    }
  }
  await emit({ type: 'end', members: emittedMembers, expanded_bytes: expandedBytes });
}

async function main() {
  try {
    if (process.argv.includes('--version')) {
      await emit({ type: 'version', protocol: PROTOCOL_VERSION, engine: ENGINE_VERSION, formats: ['zip'] });
      return;
    }
    const input = await readStdin();
    await scanZip(input);
  } catch (error) {
    const code = error instanceof ArchiveError ? error.code : 'internal-error';
    await emit({ type: 'error', code, message: error.message || 'Arşiv motoru hatası.' });
    process.exitCode = 2;
  }
}

main();
