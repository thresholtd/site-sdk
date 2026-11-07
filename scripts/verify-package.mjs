import { createHash } from 'node:crypto';
import { lstat, readFile, readdir } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

export const PACKAGE_FILES = Object.freeze(['package.json', 'index.d.ts', 'jsx-runtime.d.ts', 'jsx-dev-runtime.d.ts', 'tsconfig.json', 'vocabulary.json', 'diagnostics.json', 'schema/manifest.schema.json', 'schema/source.schema.json', 'README.md', 'CHANGELOG.md', 'LICENSE']);
export const ZIP_FILES = Object.freeze(`AGENTS.md
AUTHORING.md
LICENSE
diagnostics/diagnostics.json
examples/minimal-static/src/pages/About.tsx
examples/minimal-static/src/pages/Home.tsx
examples/minimal-static/src/sections/Testimonials.tsx
examples/minimal-static/src/styles/catalog-sections.css
examples/minimal-static/src/styles/site.css
examples/minimal-static/thresho.site.json
examples/onsite-checkout-editorial/src/cart.css
examples/onsite-checkout-editorial/src/components/Card.tsx
examples/onsite-checkout-editorial/src/components/Shell.tsx
examples/onsite-checkout-editorial/src/pages/Basket.tsx
examples/onsite-checkout-editorial/src/pages/Catalog.tsx
examples/onsite-checkout-editorial/src/pages/Checkout.tsx
examples/onsite-checkout-editorial/src/pages/Detail.tsx
examples/onsite-checkout-editorial/src/pages/Home.tsx
examples/onsite-checkout-editorial/src/sections/Testimonials.tsx
examples/onsite-checkout-editorial/src/styles/catalog-sections.css
examples/onsite-checkout-editorial/src/styles/site.css
examples/onsite-checkout-editorial/thresho.site.json
examples/onsite-checkout-inline/src/cart.css
examples/onsite-checkout-inline/src/components/Card.tsx
examples/onsite-checkout-inline/src/components/Shell.tsx
examples/onsite-checkout-inline/src/pages/Basket.tsx
examples/onsite-checkout-inline/src/pages/Catalog.tsx
examples/onsite-checkout-inline/src/pages/Checkout.tsx
examples/onsite-checkout-inline/src/pages/Detail.tsx
examples/onsite-checkout-inline/src/pages/Home.tsx
examples/onsite-checkout-inline/src/sections/Testimonials.tsx
examples/onsite-checkout-inline/src/styles/catalog-sections.css
examples/onsite-checkout-inline/src/styles/site.css
examples/onsite-checkout-inline/thresho.site.json
examples/retail-apparel/src/components/Card.tsx
examples/retail-apparel/src/components/Shell.tsx
examples/retail-apparel/src/pages/Catalog.tsx
examples/retail-apparel/src/pages/Detail.tsx
examples/retail-apparel/src/pages/Home.tsx
examples/retail-apparel/src/sections/Testimonials.tsx
examples/retail-apparel/src/styles/catalog-sections.css
examples/retail-apparel/src/styles/site.css
examples/retail-apparel/thresho.site.json
examples/retail-home-goods/src/components/Card.tsx
examples/retail-home-goods/src/components/Shell.tsx
examples/retail-home-goods/src/pages/Catalog.tsx
examples/retail-home-goods/src/pages/Detail.tsx
examples/retail-home-goods/src/pages/Home.tsx
examples/retail-home-goods/src/sections/Testimonials.tsx
examples/retail-home-goods/src/styles/catalog-sections.css
examples/retail-home-goods/src/styles/site.css
examples/retail-home-goods/thresho.site.json
external-authoring.md
fixtures/invalid/invalid-asset.svg
fixtures/invalid/invalid-dynamic.tsx
fixtures/invalid/invalid-effect.tsx
fixtures/invalid/invalid-fetch.tsx
fixtures/invalid/invalid-handler.tsx
fixtures/invalid/invalid-import.tsx
pack.json
rules/compiler-limits.json
rules/css-assets.json
schema/manifest.schema.json
schema/source.schema.json
sdk/components.json
validator.md
vocabulary/capabilities.json
vocabulary/descriptors.json`.split('\n'));

export const TOOLING_FILES = Object.freeze([
  'AGENTS.md', 'CONTRIBUTING.md', '.gitignore', '.github/copilot-instructions.md',
  'scripts/verify-package.mjs', 'scripts/publish.mjs', 'tests/verify-package.test.mjs', 'tests/publish.test.mjs',
  '.github/workflows/publish.yml', '.github/workflows/bootstrap-publish.yml',
]);
const publicInstructionSha256 = Object.freeze({
  'AGENTS.md': '2a7945f4ba16663f65f7b7f470263b605c0d940ea5b2862a2af69e2437c6c421',
  '.github/copilot-instructions.md': '71a6c509e7434fea781b0a5f98976ca148577cdf0fc3ed70bbe4cda78fe55704'
});
const allowedDirectories = new Set(['schema', 'release', 'scripts', 'tests', '.github', '.github/workflows']);
const decoder = new TextDecoder('utf-8', { fatal: true });
const stableVersion = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const hash = (algorithm, bytes) => createHash(algorithm).update(bytes).digest('hex');
const credentials = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----|\b(?:npm_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16})\b/;
const fail = message => { throw new Error(message); };
const requireThat = (condition, message) => { if (!condition) fail(message); };
const equalSets = (actual, expected, label) => requireThat(actual.length === expected.length && [...actual].sort().every((name, index) => name === [...expected].sort()[index]), `${label}: unexpected or missing entries`);
const keys = (value, expected, label) => {
  requireThat(value !== null && typeof value === 'object' && !Array.isArray(value), `${label}: object required`);
  equalSets(Object.keys(value), expected, label);
};

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function safePath(name) {
  requireThat(typeof name === 'string' && name.length > 0 && Buffer.byteLength(name, 'utf8') <= 256 && !/[\\\u0000-\u001f\u007f]/.test(name) && !name.startsWith('/') && !/^[A-Za-z]:/.test(name) && name.split('/').every(part => part && part !== '.' && part !== '..'), `unsafe archive path: ${name}`);
  return name;
}

export function crc32(bytes) {
  let crc = 0xffffffff;
  for (const value of bytes) {
    crc ^= value;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function parseStoreZip(input) {
  const bytes = Buffer.from(input);
  requireThat(bytes.length >= 22 && bytes.length <= 1048576, 'ZIP input size is outside its bound');
  const end = bytes.length - 22;
  requireThat(bytes.readUInt32LE(end) === 0x06054b50 && bytes.readUInt16LE(end + 20) === 0, 'ZIP EOCD or trailing data is invalid');
  requireThat(bytes.readUInt16LE(end + 4) === 0 && bytes.readUInt16LE(end + 6) === 0, 'ZIP must use one disk');
  const count = bytes.readUInt16LE(end + 10);
  requireThat(count > 0 && count <= 256 && bytes.readUInt16LE(end + 8) === count, 'ZIP entry count is invalid');
  const centralStart = bytes.readUInt32LE(end + 16);
  const centralSize = bytes.readUInt32LE(end + 12);
  requireThat(centralStart + centralSize === end, 'ZIP central directory is not contiguous');
  const entries = new Map();
  const local = [];
  let offset = 0;
  let contentSize = 0;
  for (let index = 0; index < count; index += 1) {
    requireThat(offset + 30 <= centralStart && bytes.readUInt32LE(offset) === 0x04034b50, 'ZIP local entry is truncated or noncontiguous');
    requireThat(bytes.readUInt16LE(offset + 4) === 20 && bytes.readUInt16LE(offset + 6) === 0 && bytes.readUInt16LE(offset + 8) === 0 && bytes.readUInt16LE(offset + 28) === 0, 'ZIP local format must be plain STORE without flags or extras');
    requireThat(bytes.readUInt16LE(offset + 10) === 0 && bytes.readUInt16LE(offset + 12) === 0, 'ZIP timestamps must be deterministic');
    const nameLength = bytes.readUInt16LE(offset + 26);
    const size = bytes.readUInt32LE(offset + 22);
    const crc = bytes.readUInt32LE(offset + 14);
    const dataStart = offset + 30 + nameLength;
    requireThat(nameLength > 0 && nameLength <= 256 && bytes.readUInt32LE(offset + 18) === size && dataStart + size <= centralStart, 'ZIP local name or size is invalid');
    const name = safePath(decoder.decode(bytes.subarray(offset + 30, dataStart)));
    requireThat(!entries.has(name) && (local.length === 0 || local.at(-1).name < name), 'ZIP entry is duplicated or out of order');
    contentSize += size;
    requireThat(contentSize <= 524288, 'ZIP content exceeds its processing limit');
    const body = bytes.subarray(dataStart, dataStart + size);
    requireThat(crc32(body) === crc, `ZIP CRC mismatch: ${name}`);
    local.push({ name, crc, size, offset });
    entries.set(name, body);
    offset = dataStart + size;
  }
  requireThat(offset === centralStart, 'ZIP contains padding before its central directory');
  for (const entry of local) {
    requireThat(offset + 46 <= end && bytes.readUInt32LE(offset) === 0x02014b50, 'ZIP central entry is truncated');
    requireThat(bytes.readUInt16LE(offset + 4) === 20 && bytes.readUInt16LE(offset + 6) === 20 && bytes.readUInt16LE(offset + 8) === 0 && bytes.readUInt16LE(offset + 10) === 0, 'ZIP central format is unsupported');
    requireThat(bytes.readUInt16LE(offset + 12) === 0 && bytes.readUInt16LE(offset + 14) === 0 && bytes.readUInt16LE(offset + 30) === 0 && bytes.readUInt16LE(offset + 32) === 0 && bytes.readUInt16LE(offset + 34) === 0 && bytes.readUInt16LE(offset + 36) === 0 && bytes.readUInt32LE(offset + 38) === 0, 'ZIP central flags, extras, links or attributes are unsupported');
    const nameLength = bytes.readUInt16LE(offset + 28);
    requireThat(nameLength > 0 && nameLength <= 256 && offset + 46 + nameLength <= end, 'ZIP central name is invalid');
    const name = safePath(decoder.decode(bytes.subarray(offset + 46, offset + 46 + nameLength)));
    requireThat(name === entry.name && bytes.readUInt32LE(offset + 16) === entry.crc && bytes.readUInt32LE(offset + 20) === entry.size && bytes.readUInt32LE(offset + 24) === entry.size && bytes.readUInt32LE(offset + 42) === entry.offset, `ZIP central/local disagreement: ${name}`);
    offset += 46 + nameLength;
  }
  requireThat(offset === end, 'ZIP central directory has extra data');
  return entries;
}

function tarString(bytes) {
  const end = bytes.indexOf(0);
  if (end >= 0) requireThat(bytes.subarray(end).every(value => value === 0), 'tar string has data after NUL');
  const value = bytes.subarray(0, end < 0 ? bytes.length : end);
  requireThat(value.every(byte => byte >= 32 && byte < 127), 'tar string is not ASCII');
  return value.toString('ascii');
}

function octal(bytes) {
  requireThat(bytes.every(value => value < 128), 'tar numeric field is not octal');
  const text = bytes.toString('ascii');
  requireThat(/^[0-7\u0000 ]+$/.test(text), 'tar numeric field is not octal');
  const digits = text.replace(/[\u0000 ]/g, '');
  requireThat(digits.length === 0 || /^[0-7]+[\u0000 ]*$/.test(text.trimStart()), 'tar numeric field has embedded padding');
  const value = digits ? BigInt(`0o${digits}`) : 0n;
  requireThat(value <= BigInt(Number.MAX_SAFE_INTEGER), 'tar numeric field overflows');
  return Number(value);
}

export function parseUstarTarball(input) {
  const compressed = Buffer.from(input);
  requireThat(compressed.length > 0 && compressed.length <= 1048576, 'tarball compressed size exceeds its bound');
  let bytes;
  try { bytes = gunzipSync(compressed, { maxOutputLength: 2097152 }); } catch { fail('tarball gzip is invalid or oversized'); }
  requireThat(bytes.length >= 1024 && bytes.length % 512 === 0, 'tarball size or zero end padding is invalid');
  const files = new Map();
  let offset = 0;
  while (offset + 512 <= bytes.length && !bytes.subarray(offset, offset + 512).every(value => value === 0)) {
    const header = bytes.subarray(offset, offset + 512);
    requireThat(header.subarray(257, 263).equals(Buffer.from('ustar\0')) && header.subarray(263, 265).equals(Buffer.from('00')), 'tar header is not USTAR');
    const checksum = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    requireThat(octal(header.subarray(148, 156)) === checksum, 'tar header checksum mismatch');
    for (const [start, length] of [[100, 8], [108, 8], [116, 8], [124, 12], [136, 12], [329, 8], [337, 8]]) octal(header.subarray(start, start + length));
    requireThat((octal(header.subarray(100, 108)) & 0o111) === 0, 'tar member has executable permissions');
    requireThat(header[156] === 0 || header[156] === 48, 'tar extensions and links are refused');
    requireThat(tarString(header.subarray(157, 257)) === '', 'tar member has a link target');
    const prefix = tarString(header.subarray(345, 500));
    const name = safePath(`${prefix ? `${prefix}/` : ''}${tarString(header.subarray(0, 100))}`);
    requireThat(name.startsWith('package/') && PACKAGE_FILES.includes(name.slice(8)) && !files.has(name), `tar member is unexpected or duplicated: ${name}`);
    requireThat(files.size < PACKAGE_FILES.length, 'tarball has too many regular members');
    const size = octal(header.subarray(124, 136));
    const dataStart = offset + 512;
    const next = dataStart + Math.ceil(size / 512) * 512;
    requireThat(size <= 1048576 && next <= bytes.length, 'tar member is truncated or oversized');
    requireThat(bytes.subarray(dataStart + size, next).every(value => value === 0), 'tar member padding is not zero');
    files.set(name, bytes.subarray(dataStart, dataStart + size));
    offset = next;
  }
  requireThat(bytes.length - offset >= 1024 && bytes.subarray(offset).every(value => value === 0), 'tar zero end padding or trailing data is invalid');
  equalSets([...files.keys()], PACKAGE_FILES.map(name => `package/${name}`), 'tarball inventory');
  return files;
}

export function verifyTarball(bytes, packageFiles) {
  const files = parseUstarTarball(bytes);
  for (const name of PACKAGE_FILES) requireThat(files.get(`package/${name}`).equals(packageFiles.get(name)), `tarball differs from generated package: ${name}`);
  return `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
}

async function regularFile(path, label) {
  const stat = await lstat(path);
  requireThat(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 1048576, `${label}: regular bounded file required`);
  return readFile(path);
}

function expectedExports() {
  return {
    '.': { types: './index.d.ts' }, './jsx-runtime': { types: './jsx-runtime.d.ts' }, './jsx-dev-runtime': { types: './jsx-dev-runtime.d.ts' },
    './diagnostics.json': './diagnostics.json', './tsconfig.json': './tsconfig.json', './schema/manifest.schema.json': './schema/manifest.schema.json', './schema/source.schema.json': './schema/source.schema.json', './vocabulary.json': './vocabulary.json',
  };
}

export function verifyDiagnosticCatalog(bytes) {
  const value = JSON.parse(decoder.decode(bytes));
  keys(value, ['formatVersion', 'diagnostics'], 'diagnostic catalog');
  requireThat(Buffer.from(bytes).equals(Buffer.from(`${canonicalJson(value)}\n`)), 'diagnostic catalog must use canonical JSON');
  requireThat(value.formatVersion === 2 && Array.isArray(value.diagnostics) && value.diagnostics.length === 40, 'diagnostic catalog format or population is invalid');
  const seen = new Set();
  const populations = { sourceError: 0, sourceWarning: 0, overlayError: 0 };
  for (const entry of value.diagnostics) {
    keys(entry, ['code', 'family', 'severity', 'message', 'cause', 'fix', 'docsAnchor', 'docsUrl'], 'diagnostic record');
    requireThat(typeof entry.code === 'string' && /^[A-Z]+(?:_[A-Z]+)*$/.exec(entry.code)?.[0] === entry.code && entry.code.length <= 80 && !seen.has(entry.code), 'diagnostic code is invalid or duplicated');
    seen.add(entry.code);
    for (const [name, maximum] of [['message', 512], ['cause', 1024], ['fix', 1024]]) requireThat(typeof entry[name] === 'string' && [...entry[name]].length >= 1 && [...entry[name]].length <= maximum, `diagnostic ${name} is outside its bound`);
    const anchor = entry.code.toLowerCase().replaceAll('_', '-');
    requireThat(entry.docsAnchor === anchor && entry.docsAnchor.length <= 80 && entry.docsUrl === `https://docs.thresho.com/reference/diagnostics#${anchor}` && entry.docsUrl.length <= 75, 'diagnostic URL does not match its code');
    if (entry.family === 'source' && entry.severity === 'error') populations.sourceError += 1;
    else if (entry.family === 'source' && entry.severity === 'warning') populations.sourceWarning += 1;
    else if (entry.family === 'overlay' && entry.severity === 'error') populations.overlayError += 1;
    else fail('diagnostic family or severity is invalid');
  }
  requireThat(populations.sourceError === 33 && populations.sourceWarning === 2 && populations.overlayError === 5, 'diagnostic catalog family population is invalid');
  return value;
}

async function inventory(root, allowed) {
  const found = new Map();
  async function walk(directory, prefix = '') {
    for (const name of await readdir(directory)) {
      if (!prefix && (name === '.git' || name === 'node_modules')) continue;
      const relative = prefix ? `${prefix}/${name}` : name;
      safePath(relative);
      const path = join(directory, name);
      const stat = await lstat(path);
      requireThat(!stat.isSymbolicLink(), `public source symlink refused: ${relative}`);
      if (stat.isDirectory()) {
        requireThat(allowedDirectories.has(relative), `unexpected public directory: ${relative}`);
        await walk(path, relative);
      } else {
        requireThat(stat.isFile() && allowed.has(relative), `unexpected public file: ${relative}`);
        const bytes = await regularFile(path, relative);
        if (!relative.endsWith('.zip')) requireThat(!credentials.test(bytes.toString('utf8')), `credential pattern in public source: ${relative}`);
        found.set(relative, bytes);
      }
    }
  }
  await walk(root);
  return found;
}

export async function verifyPackage({ root, tag, tarballPath } = {}) {
  requireThat(typeof root === 'string' && isAbsolute(root), 'absolute public repository directory required');
  root = resolve(root);
  requireThat(!(await lstat(root)).isSymbolicLink() && (await lstat(root)).isDirectory(), 'public repository root must be a regular directory');
  const packageBytes = await regularFile(join(root, 'package.json'), 'package.json');
  const packageJson = JSON.parse(decoder.decode(packageBytes));
  keys(packageJson, ['name', 'version', 'type', 'license', 'repository', 'types', 'exports', 'files', 'thresho'], 'package.json');
  requireThat(packageJson.name === '@thresho/site-sdk' && packageJson.type === 'module' && packageJson.license === 'MIT' && packageJson.types === './index.d.ts', 'package identity or declaration entry is invalid');
  requireThat(stableVersion.test(packageJson.version) && packageJson.version.startsWith('2.') && tag === `v${packageJson.version}`, 'tag must exactly match the stable package version');
  keys(packageJson.repository, ['type', 'url'], 'repository');
  requireThat(packageJson.repository.type === 'git' && packageJson.repository.url === 'git+https://github.com/thresholtd/site-sdk.git', 'package repository is not the approved public repository');
  requireThat(canonicalJson(packageJson.exports) === canonicalJson(expectedExports()), 'package export map is invalid');
  requireThat(Array.isArray(packageJson.files), 'package files allowlist is missing');
  equalSets(packageJson.files, PACKAGE_FILES.filter(name => name !== 'package.json'), 'package files');
  keys(packageJson.thresho, ['formatVersion', 'compilerVersion', 'vocabularyDigest'], 'package thresho metadata');
  requireThat(packageJson.thresho.formatVersion === 2 && /^site-source-compiler\/[1-9][0-9]*$/.test(packageJson.thresho.compilerVersion) && /^[a-f0-9]{64}$/.test(packageJson.thresho.vocabularyDigest), 'package compiler metadata is invalid');
  const fileName = `thresho-authoring-pack-${packageJson.version}.zip`;
  const releasePaths = [`release/${fileName}`, 'release/SHA256SUMS', 'release/manifest.json'];
  const found = await inventory(root, new Set([...PACKAGE_FILES, ...releasePaths, ...TOOLING_FILES]));
  const required = [...PACKAGE_FILES, ...releasePaths, ...TOOLING_FILES.filter(name => name !== '.github/workflows/bootstrap-publish.yml')];
  for (const name of required) requireThat(found.has(name), `missing public file: ${name}`);
  for (const [name, digest] of Object.entries(publicInstructionSha256)) requireThat(hash('sha256', found.get(name)) === digest, `approved public instruction bytes differ: ${name}`);
  const manifestBytes = found.get('release/manifest.json');
  const manifest = JSON.parse(decoder.decode(manifestBytes));
  keys(manifest, ['packId', 'formatVersion', 'version', 'compilerVersion', 'vocabularyDigest', 'fileName', 'sha256', 'byteLength'], 'release manifest');
  requireThat(manifestBytes.equals(Buffer.from(`${canonicalJson(manifest)}\n`)), 'release manifest must use canonical JSON and a final newline');
  const zip = found.get(`release/${fileName}`);
  const checksum = found.get('release/SHA256SUMS');
  requireThat(manifest.packId === 'thresho.presentation.authoring.format-2' && manifest.formatVersion === 2 && manifest.version === packageJson.version && manifest.compilerVersion === packageJson.thresho.compilerVersion && manifest.vocabularyDigest === packageJson.thresho.vocabularyDigest && manifest.fileName === fileName, 'release manifest identity differs from the package');
  requireThat(manifest.byteLength === zip.length && manifest.sha256 === hash('sha256', zip), 'release ZIP size or digest mismatch');
  requireThat(checksum.equals(Buffer.from(`${manifest.sha256}  ${fileName}\n`)), 'release SHA256SUMS differs from the ZIP');
  const entries = parseStoreZip(zip);
  equalSets([...entries.keys()], ZIP_FILES, 'approved ZIP inventory');
  for (const [name, bytes] of entries) {
    const text = decoder.decode(bytes);
    requireThat(!credentials.test(text), `credential pattern in ZIP entry: ${name}`);
    if (name.startsWith('examples/')) requireThat(!/https?:\/\/|javascript:|data:|\b(?:tenantId|siteId|customerId)\b|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(text), `unsafe public example: ${name}`);
  }
  const pack = JSON.parse(decoder.decode(entries.get('pack.json')));
  requireThat(pack.packId === manifest.packId && pack.formatVersion === 2 && pack.version === packageJson.version, 'pack.json identity differs from the package');
  verifyDiagnosticCatalog(found.get('diagnostics.json'));
  requireThat(found.get('diagnostics.json').equals(entries.get('diagnostics/diagnostics.json')), 'npm and ZIP diagnostic catalogs differ');
  requireThat(found.get('LICENSE').equals(entries.get('LICENSE')) && found.get('LICENSE').toString('utf8').startsWith('MIT License\n'), 'package and pack MIT licence bytes differ');
  for (const name of ['minimal-static', 'retail-apparel', 'retail-home-goods', 'onsite-checkout-inline', 'onsite-checkout-editorial']) requireThat(entries.has(`examples/${name}/thresho.site.json`), `missing public example: ${name}`);
  const packageFiles = new Map(PACKAGE_FILES.map(name => [name, found.get(name)]));
  let tarball;
  let integrity;
  if (tarballPath !== undefined) {
    requireThat(typeof tarballPath === 'string' && isAbsolute(tarballPath), 'absolute tarball path required');
    tarball = await regularFile(tarballPath, 'tarball');
    integrity = verifyTarball(tarball, packageFiles);
  }
  return { packageJson, manifest, packageFiles, zip, checksum, ...(tarball ? { tarball, integrity } : {}) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const parsed = {};
  let usage = false;
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!['--tag', '--tarball'].includes(key) || !value || Object.hasOwn(parsed, key)) { usage = true; break; }
    parsed[key] = value;
  }
  if (usage || !parsed['--tag']) {
    process.stderr.write('usage: node scripts/verify-package.mjs --tag v<version> [--tarball <absolute-tgz-path>]\n');
    process.exitCode = 2;
  } else {
    try {
      const result = await verifyPackage({ root: resolve(fileURLToPath(new URL('../', import.meta.url))), tag: parsed['--tag'], tarballPath: parsed['--tarball'] });
      process.stdout.write(`verified ${result.packageJson.name}@${result.packageJson.version} ${result.manifest.sha256}\n`);
    } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
  }
}
