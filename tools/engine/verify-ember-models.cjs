'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..', '..');
const modelRoot = path.join(projectRoot, 'data', 'ml', 'ember2024');
const expected = new Map([
  ['EMBER2024_APK.model', 'a13274463201e7d3ddec74b098350051266fcf0812aff302617397f1765cbc90'],
  ['EMBER2024_Dot_Net.model', 'cbd91b4a823d5dac3f56f38640a5599836501ccbd4fcce273d28c9aed0afc24c'],
  ['EMBER2024_ELF.model', '8e4072938955ac6020f80bca6cff7c12e97865102d578b3099e2011048eb9c43'],
  ['EMBER2024_PDF.model', 'a7e30eb883f8918cf28aaa98b6124cf2eb25a98ea3d58f3053a4fb49e24c3161'],
  ['EMBER2024_PE.model', '4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99'],
  ['EMBER2024_Win32.model', 'b1e9fc174e4fcc6c0aba3ff29eb6d96ee9e240057f76940a8a1d6009ac0a4267'],
  ['EMBER2024_Win64.model', '8eddddc26eb346d74810a0dfcc672342eca5709ece4da259934d6d3c77ca971b'],
  ['EMBER2024_all.model', 'af4ec038685797c586142d177965fe451cac96f424f631aeb66f8d116c161d07'],
  ['EMBER2024_behavior.model', '33a86f31b9c807533b8e957393b54fd3b77a0168ae288edf4344a417fb49716b'],
  ['EMBER2024_exploit.model', '3d132b17fff763c24c447afa24b60939032fa95b14905dc1fbddb79701cbae01'],
  ['EMBER2024_family.model', '3897caaa1a3e4a9e0d23277d890e2267123f2e1f94fbfb4f2e2a36f7b6ce3af2'],
  ['EMBER2024_file_property.model', '6bc87d796843f89fa79d29e9cc12c49b8ee1ad01aa3024314d28b6a2175728ea'],
  ['EMBER2024_group.model', 'ef202c5c8d7056d0e9a3bb660962256f9c9ad501e7b6ea5bfac1467a09afc08b'],
  ['EMBER2024_packer.model', 'b11c3679e8462c23d020642872b5c06ca43b660bc188dbf836b2ff0e05686b7d'],
]);

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const digest = crypto.createHash('sha256');
    const input = fs.createReadStream(filePath, { highWaterMark: 1024 * 1024 });
    input.on('error', reject);
    input.on('data', (chunk) => digest.update(chunk));
    input.on('end', () => resolve(digest.digest('hex')));
  });
}

async function main() {
  for (const [name, expectedHash] of expected) {
    const modelPath = path.join(modelRoot, name);
    if (!fs.statSync(modelPath, { throwIfNoEntry: false })?.isFile()) {
      throw new Error(`Yayın EMBER modeli eksik: ${name}`);
    }
    const actualHash = await sha256File(modelPath);
    if (actualHash !== expectedHash) {
      throw new Error(`Yayın EMBER modeli SHA-256 uyuşmuyor: ${name}`);
    }
  }
  console.log(`EMBER2024 yayın modelleri doğrulandı (${expected.size} dosya).`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
