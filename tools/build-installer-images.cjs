'use strict';

const { app, nativeImage } = require('electron');
const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');
const sourcePath = path.join(projectRoot, 'assets', 'neutron-logo.png');
const bannerPath = path.join(projectRoot, 'assets', 'installer-banner.bmp');
const dialogPath = path.join(projectRoot, 'assets', 'installer-dialog.bmp');

// Plain light background, not the app's own dark theme: WixUI_Common's
// stock Welcome/Exit dialog text controls render in a dark, fixed color we
// can't override without forking the bundled WiX dialog templates, so a
// dark full-bleed background makes the title/body text unreadable (found by
// actually looking at a real build -- see plan notes). White keeps the
// stock text legible while still branding the page with the logo.
const BACKGROUND = { r: 0xff, g: 0xff, b: 0xff };

function makeCanvas(width, height) {
  const buffer = Buffer.alloc(width * height * 4);
  for (let i = 0; i < width * height; i += 1) {
    buffer[i * 4] = BACKGROUND.b;
    buffer[i * 4 + 1] = BACKGROUND.g;
    buffer[i * 4 + 2] = BACKGROUND.r;
    buffer[i * 4 + 3] = 255;
  }
  return buffer;
}

// The source logo is a fully opaque square (no real alpha at its edges), so
// pasting it verbatim leaves a visible rectangular seam against a
// differently-colored canvas. Feathering a circular falloff over the source
// image's own alpha fades it smoothly into the background regardless of
// canvas color, instead of a hard-edged box.
function featherAlpha(col, row, imageWidth, imageHeight) {
  const cx = imageWidth / 2;
  const cy = imageHeight / 2;
  const maxRadius = Math.min(imageWidth, imageHeight) / 2;
  const distance = Math.hypot(col - cx, row - cy) / maxRadius;
  const featherStart = 0.55;
  const featherEnd = 1;
  if (distance <= featherStart) return 1;
  if (distance >= featherEnd) return 0;
  return 1 - (distance - featherStart) / (featherEnd - featherStart);
}

function pasteImage(canvas, canvasWidth, canvasHeight, image, imageWidth, imageHeight, x, y) {
  for (let row = 0; row < imageHeight; row += 1) {
    const cy = y + row;
    if (cy < 0 || cy >= canvasHeight) continue;
    for (let col = 0; col < imageWidth; col += 1) {
      const cx = x + col;
      if (cx < 0 || cx >= canvasWidth) continue;
      const srcIndex = (row * imageWidth + col) * 4;
      const dstIndex = (cy * canvasWidth + cx) * 4;
      const alpha = (image[srcIndex + 3] / 255) * featherAlpha(col, row, imageWidth, imageHeight);
      for (let channel = 0; channel < 3; channel += 1) {
        canvas[dstIndex + channel] = Math.round(
          image[srcIndex + channel] * alpha + canvas[dstIndex + channel] * (1 - alpha),
        );
      }
    }
  }
}

// MUI2 bitmaps are plain 24bpp BMP files. Written by hand (bottom-up rows,
// 4-byte row padding) so the installer image build needs no extra dependency.
function bufferToBmp(buffer, width, height) {
  const rowSize = Math.floor((24 * width + 31) / 32) * 4;
  const pixelArraySize = rowSize * height;
  const fileSize = 54 + pixelArraySize;
  const bmp = Buffer.alloc(fileSize);
  bmp.write('BM', 0);
  bmp.writeUInt32LE(fileSize, 2);
  bmp.writeUInt32LE(0, 6);
  bmp.writeUInt32LE(54, 10);
  bmp.writeUInt32LE(40, 14);
  bmp.writeInt32LE(width, 18);
  bmp.writeInt32LE(height, 22);
  bmp.writeUInt16LE(1, 26);
  bmp.writeUInt16LE(24, 28);
  bmp.writeUInt32LE(0, 30);
  bmp.writeUInt32LE(pixelArraySize, 34);
  bmp.writeInt32LE(2835, 38);
  bmp.writeInt32LE(2835, 42);
  bmp.writeUInt32LE(0, 46);
  bmp.writeUInt32LE(0, 50);
  let offset = 54;
  for (let row = height - 1; row >= 0; row -= 1) {
    for (let col = 0; col < width; col += 1) {
      const srcIndex = (row * width + col) * 4;
      bmp[offset] = buffer[srcIndex];
      bmp[offset + 1] = buffer[srcIndex + 1];
      bmp[offset + 2] = buffer[srcIndex + 2];
      offset += 3;
    }
    offset += rowSize - width * 3;
  }
  return bmp;
}

function buildBitmap(outputPath, width, height, logoSize) {
  const source = nativeImage.createFromPath(sourcePath);
  if (source.isEmpty()) throw new Error(`Neutron logo dosyası okunamadı: ${sourcePath}`);
  const logo = source.resize({ width: logoSize, height: logoSize, quality: 'best' });
  const canvas = makeCanvas(width, height);
  const x = Math.round((width - logoSize) / 2);
  const y = Math.round((height - logoSize) / 2);
  pasteImage(canvas, width, height, logo.toBitmap(), logoSize, logoSize, x, y);
  fs.writeFileSync(outputPath, bufferToBmp(canvas, width, height));
}

app.whenReady().then(() => {
  try {
    // Standard MUI2 sizes: 150x57 header and 164x314 Welcome/Finish artwork.
    buildBitmap(bannerPath, 150, 57, 42);
    buildBitmap(dialogPath, 164, 314, 142);
    console.log(`Kurulum banner görseli oluşturuldu: ${bannerPath}`);
    console.log(`Kurulum arka plan görseli oluşturuldu: ${dialogPath}`);
    app.exit(0);
  } catch (error) {
    console.error(`Hata: ${error.message}`);
    app.exit(1);
  }
});
