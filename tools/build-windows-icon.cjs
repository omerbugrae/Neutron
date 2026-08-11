'use strict';

const { app, nativeImage } = require('electron');
const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');
const sourcePath = path.join(projectRoot, 'assets', 'neutron-logo.png');
const outputPath = path.join(projectRoot, 'assets', 'neutron.ico');
const sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256];

function buildIcon() {
  const source = nativeImage.createFromPath(sourcePath);
  if (source.isEmpty()) throw new Error(`Neutron logo dosyası okunamadı: ${sourcePath}`);
  const images = sizes.map((size) => ({
    size,
    bytes: source.resize({ width: size, height: size, quality: 'best' }).toPNG(),
  }));
  const headerSize = 6 + (images.length * 16);
  const header = Buffer.alloc(headerSize);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);
  let offset = headerSize;
  images.forEach((image, index) => {
    const entry = 6 + (index * 16);
    header.writeUInt8(image.size === 256 ? 0 : image.size, entry);
    header.writeUInt8(image.size === 256 ? 0 : image.size, entry + 1);
    header.writeUInt8(0, entry + 2);
    header.writeUInt8(0, entry + 3);
    header.writeUInt16LE(1, entry + 4);
    header.writeUInt16LE(32, entry + 6);
    header.writeUInt32LE(image.bytes.length, entry + 8);
    header.writeUInt32LE(offset, entry + 12);
    offset += image.bytes.length;
  });
  fs.writeFileSync(outputPath, Buffer.concat([header, ...images.map((image) => image.bytes)]));
  const verification = nativeImage.createFromPath(outputPath);
  if (verification.isEmpty()) throw new Error('Oluşturulan Neutron ICO dosyası doğrulanamadı.');
  console.log(`Neutron Windows ikonu oluşturuldu: ${outputPath}`);
  console.log(`Boyutlar: ${sizes.join(', ')} px`);
}

app.whenReady().then(() => {
  try {
    buildIcon();
    app.exit(0);
  } catch (error) {
    console.error(`Hata: ${error.message}`);
    app.exit(1);
  }
});
