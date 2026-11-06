import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, test } from 'node:test';
import { gzipSync } from 'node:zlib';
import { canonicalJson, crc32, PACKAGE_FILES, parseStoreZip, parseUstarTarball, verifyPackage, verifyTarball, verifyDiagnosticCatalog, ZIP_FILES } from '../scripts/verify-package.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const temporary = [];
afterEach(async () => { await Promise.all(temporary.splice(0).map(path => rm(path, { recursive: true, force: true }))); });

async function fixture() {
  const path = await mkdtemp(join(tmpdir(), 'site-sdk-verifier-'));
  temporary.push(path);
  await cp(root, path, { recursive: true, filter: source => !['.git', 'node_modules'].includes(relative(root, source).split('/')[0]) });
  return path;
}

async function packageJson(path, mutate) {
  const value = JSON.parse(await readFile(join(path, 'package.json'), 'utf8'));
  mutate(value);
  await writeFile(join(path, 'package.json'), `${JSON.stringify(value, null, 2)}\n`);
}

function storeZip(values) {
  const entries = [...values].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  const local = [];
  const central = [];
  let offset = 0;
  for (const [name, value] of entries) {
    const body = Buffer.from(value);
    const encoded = Buffer.from(name);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50); header.writeUInt16LE(20, 4);
    header.writeUInt32LE(crc32(body), 14); header.writeUInt32LE(body.length, 18); header.writeUInt32LE(body.length, 22); header.writeUInt16LE(encoded.length, 26);
    local.push(header, encoded, body);
    const index = Buffer.alloc(46);
    index.writeUInt32LE(0x02014b50); index.writeUInt16LE(20, 4); index.writeUInt16LE(20, 6);
    index.writeUInt32LE(crc32(body), 16); index.writeUInt32LE(body.length, 20); index.writeUInt32LE(body.length, 24); index.writeUInt16LE(encoded.length, 28); index.writeUInt32LE(offset, 42);
    central.push(index, encoded);
    offset += header.length + encoded.length + body.length;
  }
  const centralBytes = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10); end.writeUInt32LE(centralBytes.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, centralBytes, end]);
}

async function replaceZip(path, bytes, update = true) {
  const manifestPath = join(path, 'release/manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  await writeFile(join(path, 'release', manifest.fileName), bytes);
  if (update) {
    manifest.sha256 = createHash('sha256').update(bytes).digest('hex');
    manifest.byteLength = bytes.length;
    await writeFile(manifestPath, `${canonicalJson(manifest)}\n`);
    await writeFile(join(path, 'release/SHA256SUMS'), `${manifest.sha256}  ${manifest.fileName}\n`);
  }
}

function tarChecksum(header) {
  header.fill(32, 148, 156);
  const sum = header.reduce((total, value) => total + value, 0);
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
}

function ustar(values, mutate = () => {}) {
  const records = [];
  let index = 0;
  for (const [name, body] of values) {
    const header = Buffer.alloc(512);
    header.write(name, 0, 100, 'ascii');
    header.write('0000644\0', 100, 8, 'ascii'); header.write('0000000\0', 108, 8, 'ascii'); header.write('0000000\0', 116, 8, 'ascii');
    header.write(`${body.length.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii'); header.write('00000000000\0', 136, 12, 'ascii');
    header[156] = 48; header.write('ustar\0', 257, 6, 'ascii'); header.write('00', 263, 2, 'ascii');
    mutate(header, index++);
    tarChecksum(header);
    records.push(header, Buffer.from(body), Buffer.alloc((512 - body.length % 512) % 512));
  }
  return Buffer.concat([...records, Buffer.alloc(1024)]);
}

async function packageFiles(path) {
  return new Map(await Promise.all(PACKAGE_FILES.map(async name => [`package/${name}`, await readFile(join(path, name))])));
}

test('T4 accepts the unchanged generated public package and fixed ZIP inventory', async () => {
  const verified = await verifyPackage({ root: await fixture(), tag: 'v2.1.1' });
  assert.equal(verified.packageJson.name, '@thresho/site-sdk');
  assert.equal(verified.manifest.sha256, '4fa6e2758f90aab060d871799d47e3eca750b45b52ed21c18efd242c667a0ccc');
  assert.equal(verified.packageFiles.size, 12);
  assert.equal(parseStoreZip(verified.zip).size, 58);
  assert.deepEqual([...parseStoreZip(verified.zip).keys()], ZIP_FILES);
});

for (const tag of ['2.0.0', 'v2.0.1', 'v02.0.0', 'v2.0.0-beta.1', 'v2.0.0\n', 'v2.0.0;touch bad']) {
  test(`T4 rejects unsafe or mismatched tag ${JSON.stringify(tag)}`, async () => {
    await assert.rejects(verifyPackage({ root: await fixture(), tag }), /tag must exactly match/);
  });
}

for (const key of ['scripts', 'dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies', 'bundledDependencies', 'bundleDependencies', 'main', 'module', 'browser', 'bin']) {
  test(`T4 rejects forbidden package key ${key}`, async () => {
    const path = await fixture();
    await packageJson(path, value => { value[key] = {}; });
    await assert.rejects(verifyPackage({ root: path, tag: 'v2.1.1' }), /package.json: unexpected or missing entries/);
  });
}

for (const [name, mutate, expected] of [
  ['package name', value => { value.name = '@other/site-sdk'; }, /package identity/],
  ['repository', value => { value.repository.url = 'https://example.invalid/private'; }, /approved public repository/],
  ['export runtime', value => { value.exports['.'].default = './index.js'; }, /export map/],
  ['package files', value => { value.files.push('scripts/publish.mjs'); }, /package files/],
  ['metadata shape', value => { value.thresho.unexpected = true; }, /thresho metadata/],
  ['vocabulary digest', value => { value.thresho.vocabularyDigest = 'wrong'; }, /compiler metadata/],
  ['semver', value => { value.version = '2.00.0'; }, /stable package version/],
]) {
  test(`T4 rejects malformed ${name}`, async () => {
    const path = await fixture();
    await packageJson(path, mutate);
    await assert.rejects(verifyPackage({ root: path, tag: 'v2.1.1' }), expected);
  });
}

test('T4 refuses missing, extra, credential-bearing and linked public files', async () => {
  const missing = await fixture();
  await rm(join(missing, 'index.d.ts'));
  await assert.rejects(verifyPackage({ root: missing, tag: 'v2.1.1' }), /missing public file: index.d.ts/);
  const extra = await fixture();
  await writeFile(join(extra, 'unexpected.js'), 'export default 1;');
  await assert.rejects(verifyPackage({ root: extra, tag: 'v2.1.1' }), /unexpected public file: unexpected.js/);
  const credentials = await fixture();
  await writeFile(join(credentials, 'CONTRIBUTING.md'), `npm_${'a'.repeat(36)}`);
  await assert.rejects(verifyPackage({ root: credentials, tag: 'v2.1.1' }), /credential pattern/);
  const linked = await fixture();
  await rm(join(linked, 'LICENSE'));
  await symlink(join(root, 'LICENSE'), join(linked, 'LICENSE'));
  await assert.rejects(verifyPackage({ root: linked, tag: 'v2.1.1' }), /symlink refused/);
  const alias = `${await fixture()}-alias`;
  temporary.push(alias);
  await symlink(root, alias, 'dir');
  for (const suffix of ['', '/', '/.']) await assert.rejects(verifyPackage({ root: `${alias}${suffix}`, tag: 'v2.1.1' }), /root must be a regular directory/);
});

test('T4 refuses private instruction replacement under both approved public filenames', async () => {
  const privateCanon = ['# Internal engineering rules', '', '<!-- THRESHO-CANON:START -->', 'Synthetic private operating instructions.', '<!-- THRESHO-CANON:END -->', ''].join('\n');
  for (const name of ['AGENTS.md', '.github/copilot-instructions.md']) {
    const path = await fixture();
    await writeFile(join(path, name), privateCanon);
    await assert.rejects(verifyPackage({ root: path, tag: 'v2.1.1' }), /approved public instruction bytes differ/);
    const changed = await fixture();
    await writeFile(join(changed, name), `${await readFile(join(changed, name), 'utf8')}\nchanged\n`);
    await assert.rejects(verifyPackage({ root: changed, tag: 'v2.1.1' }), /approved public instruction bytes differ/);
  }
});

test('T4 refuses internal instruction and agent directories when empty or populated', async () => {
  for (const directory of ['.github/instructions', '.github/agents']) {
    for (const populated of [false, true]) {
      const path = await fixture();
      await mkdir(join(path, directory));
      if (populated) await writeFile(join(path, directory, 'internal.md'), 'Synthetic private instruction file.\n');
      await assert.rejects(verifyPackage({ root: path, tag: 'v2.1.1' }), /unexpected public directory/);
    }
  }
});

test('T5 refuses ZIP digest, byte length, checksum and manifest identity mismatches', async () => {
  const path = await fixture();
  const original = await verifyPackage({ root: path, tag: 'v2.1.1' });
  await replaceZip(path, Buffer.concat([original.zip, Buffer.from([0])]), false);
  await assert.rejects(verifyPackage({ root: path, tag: 'v2.1.1' }), /ZIP size or digest mismatch/);
  await replaceZip(path, original.zip);
  await writeFile(join(path, 'release/SHA256SUMS'), 'wrong\n');
  await assert.rejects(verifyPackage({ root: path, tag: 'v2.1.1' }), /SHA256SUMS/);
  await replaceZip(path, original.zip);
  const manifest = { ...original.manifest, packId: 'wrong' };
  await writeFile(join(path, 'release/manifest.json'), `${canonicalJson(manifest)}\n`);
  await assert.rejects(verifyPackage({ root: path, tag: 'v2.1.1' }), /manifest identity/);
});

test('T5 recomputed digests cannot admit extra ZIP files, altered identity or unsafe examples', async () => {
  for (const variant of ['extra', 'identity', 'external', 'uuid', 'licence']) {
    const path = await fixture();
    const verified = await verifyPackage({ root: path, tag: 'v2.1.1' });
    const entries = parseStoreZip(verified.zip);
    if (variant === 'extra') entries.set('private-runtime.js', Buffer.from('unapproved'));
    if (variant === 'identity') entries.set('pack.json', Buffer.from(JSON.stringify({ ...JSON.parse(entries.get('pack.json')), version: '9.0.0' })));
    if (variant === 'external') entries.set('examples/minimal-static/src/pages/Home.tsx', Buffer.from('https://private.example.invalid/source'));
    if (variant === 'uuid') entries.set('examples/minimal-static/src/pages/Home.tsx', Buffer.from('00000000-0000-4000-8000-000000000001'));
    if (variant === 'licence') entries.set('LICENSE', Buffer.from('different'));
    await replaceZip(path, storeZip(entries));
    await assert.rejects(verifyPackage({ root: path, tag: 'v2.1.1' }), variant === 'extra' ? /approved ZIP inventory/ : variant === 'identity' ? /pack.json identity/ : variant === 'licence' ? /licence bytes differ/ : /unsafe public example/);
  }
});

test('T5 every ZIP entry rejects credentials after an attacker recomputes both checksums', async () => {
  for (const name of ['AUTHORING.md', 'examples/minimal-static/src/pages/Home.tsx']) {
    for (const value of [`npm_${'a'.repeat(36)}`, `github_pat_${'a'.repeat(40)}`, `ghp_${'a'.repeat(36)}`, `AKIA${'A'.repeat(16)}`, ['-----BEGIN ', 'ENCRYPTED PRIVATE KEY', '-----'].join('')]) {
      const path = await fixture();
      const verified = await verifyPackage({ root: path, tag: 'v2.1.1' });
      const entries = parseStoreZip(verified.zip);
      entries.set(name, Buffer.from(value));
      await replaceZip(path, storeZip(entries));
      await assert.rejects(verifyPackage({ root: path, tag: 'v2.1.1' }), /credential pattern in ZIP entry/);
    }
  }
});

test('T5 all canonical UUID forms are refused in public examples', async () => {
  for (const uuid of ['00000000-0000-7000-8000-000000000001', '00000000-0000-0000-0000-000000000000', 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF']) {
    const path = await fixture();
    const verified = await verifyPackage({ root: path, tag: 'v2.1.1' });
    const entries = parseStoreZip(verified.zip);
    entries.set('examples/minimal-static/src/pages/Home.tsx', Buffer.from(uuid));
    await replaceZip(path, storeZip(entries));
    await assert.rejects(verifyPackage({ root: path, tag: 'v2.1.1' }), /unsafe public example/);
  }
});

test('T5 refuses malformed ZIP structure independently from digest checks', async () => {
  const verified = await verifyPackage({ root: await fixture(), tag: 'v2.1.1' });
  const central = verified.zip.readUInt32LE(verified.zip.length - 6);
  const variants = [
    ['truncation', bytes => bytes.subarray(0, bytes.length - 10), /EOCD|central|truncated/],
    ['trailing byte', bytes => Buffer.concat([bytes, Buffer.from([0])]), /EOCD/],
    ['CRC corruption', bytes => { bytes[30 + bytes.readUInt16LE(26)] ^= 1; return bytes; }, /CRC mismatch/],
    ['central offset', bytes => { bytes.writeUInt32LE(1, central + 42); return bytes; }, /central\/local disagreement/],
    ['flags', bytes => { bytes.writeUInt16LE(8, 6); return bytes; }, /plain STORE/],
    ['compression', bytes => { bytes.writeUInt16LE(8, 8); return bytes; }, /plain STORE/],
    ['extra field', bytes => { bytes.writeUInt16LE(1, 28); return bytes; }, /plain STORE/],
    ['symlink', bytes => { bytes.writeUInt32LE(0xa0000000, central + 38); return bytes; }, /links or attributes/],
    ['multiple disks', bytes => { bytes.writeUInt16LE(1, bytes.length - 18); return bytes; }, /one disk/],
  ];
  for (const [name, mutate, expected] of variants) assert.throws(() => parseStoreZip(mutate(Buffer.from(verified.zip))), expected, name);
  assert.throws(() => parseStoreZip(storeZip([['../private', Buffer.from('x')]])), /unsafe archive path/);
  assert.throws(() => parseStoreZip(storeZip([['a', Buffer.from('x')], ['a', Buffer.from('x')]])), /duplicated or out of order/);
  assert.throws(() => parseStoreZip(storeZip([['a'.repeat(257), Buffer.from('x')]])), /name or size/);
  assert.throws(() => parseStoreZip(storeZip([['a', Buffer.alloc(524289)]])), /content exceeds/);
  assert.throws(() => parseStoreZip(storeZip(Array.from({ length: 257 }, (_, index) => [`f${index.toString().padStart(3, '0')}`, Buffer.alloc(0)]))), /entry count/);
  assert.throws(() => parseStoreZip(Buffer.alloc(1048577)), /input size/);
});

test('T6 accepts the actual npm tarball and matches all twelve regular member bytes', { timeout: 45000 }, async () => {
  const path = await fixture();
  const destination = await mkdtemp(join(tmpdir(), 'site-sdk-pack-'));
  temporary.push(destination);
  const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', destination], { cwd: path, encoding: 'utf8', timeout: 30000 }));
  const tarballPath = join(destination, packed[0].filename);
  const verified = await verifyPackage({ root: path, tag: 'v2.1.1', tarballPath });
  assert.equal(parseUstarTarball(verified.tarball).size, 12);
  assert.equal(verified.integrity, `sha512-${createHash('sha512').update(verified.tarball).digest('base64')}`);
});

test('T6 rejects unsafe tar records, members, permissions and numeric fields', async () => {
  const files = await packageFiles(await fixture());
  for (const type of ['x', 'g', 'L', 'K', 'S', '1', '2', '3', '5']) assert.throws(() => parseUstarTarball(gzipSync(ustar(files, (header, index) => { if (index === 0) header[156] = type.charCodeAt(0); }))), /extensions and links/);
  assert.throws(() => parseUstarTarball(gzipSync(ustar(files, (header, index) => { if (!index) header.write('0000755\0', 100, 8, 'ascii'); }))), /executable permissions/);
  assert.throws(() => parseUstarTarball(gzipSync(ustar(files, (header, index) => { if (!index) header[124] = 128; }))), /not octal/);
  assert.throws(() => parseUstarTarball(gzipSync(ustar(files, (header, index) => { if (!index) header[135] = 128; }))), /not octal/);
  assert.throws(() => parseUstarTarball(gzipSync(ustar(files, (header, index) => { if (!index) header.write('target', 157); }))), /link target/);
  const badPath = [...files]; badPath[0] = ['package/../secret', badPath[0][1]];
  assert.throws(() => parseUstarTarball(gzipSync(ustar(badPath))), /unsafe archive path/);
  const duplicate = [...files]; duplicate[1] = [duplicate[0][0], duplicate[1][1]];
  assert.throws(() => parseUstarTarball(gzipSync(ustar(duplicate))), /unexpected or duplicated/);
  const extra = [...files, ['package/runtime.js', Buffer.from('export default 1;')]];
  assert.throws(() => parseUstarTarball(gzipSync(ustar(extra))), /unexpected or duplicated/);
  assert.throws(() => parseUstarTarball(gzipSync(ustar([...files].slice(1)))), /inventory/);
});

test('T6 bounds gzip expansion and rejects tar corruption or altered file bytes', async () => {
  const path = await fixture();
  const files = await packageFiles(path);
  const tar = ustar(files);
  const headerCorrupt = Buffer.from(tar); headerCorrupt[1] ^= 1;
  assert.throws(() => parseUstarTarball(gzipSync(headerCorrupt)), /checksum mismatch/);
  const endCorrupt = Buffer.from(tar); endCorrupt[endCorrupt.length - 1] = 1;
  assert.throws(() => parseUstarTarball(gzipSync(endCorrupt)), /zero end padding|trailing data/);
  const paddingCorrupt = Buffer.from(tar); paddingCorrupt[512 + files.get('package/package.json').length] = 1;
  assert.throws(() => parseUstarTarball(gzipSync(paddingCorrupt)), /member padding/);
  assert.throws(() => parseUstarTarball(gzipSync(Buffer.alloc(2097153))), /gzip is invalid or oversized/);
  assert.throws(() => parseUstarTarball(Buffer.alloc(1048577)), /compressed size/);
  assert.throws(() => parseUstarTarball(gzipSync(tar.subarray(0, tar.length - 513))), /size or zero end padding/);
  const verified = await verifyPackage({ root: path, tag: 'v2.1.1' });
  const changed = new Map(files); changed.set('package/index.d.ts', Buffer.from('altered'));
  assert.throws(() => verifyTarball(gzipSync(ustar(changed)), verified.packageFiles), /differs from generated package: index.d.ts/);
});


test('T56 verifies the immutable forty-code catalog shared by npm and ZIP', async () => {
  const path = await fixture();
  const verified = await verifyPackage({ root: path, tag: 'v2.1.1' });
  const bytes = verified.packageFiles.get('diagnostics.json');
  const catalog = verifyDiagnosticCatalog(bytes);
  assert.equal(catalog.diagnostics.length, 40);
  assert.deepEqual(catalog.diagnostics.find(value => value.code === 'INVALID_PACKAGE').docsUrl, 'https://docs.thresho.com/reference/diagnostics#invalid-package');
  assert.equal(catalog.diagnostics.find(value => value.code === 'SEO_TITLE_LENGTH').severity, 'warning');
  assert.equal(catalog.diagnostics.find(value => value.code === 'OVERLAY_COMPILE_FAILED').family, 'overlay');
  assert.ok(bytes.equals(parseStoreZip(verified.zip).get('diagnostics/diagnostics.json')));
  assert.equal(verified.packageJson.exports['./diagnostics.json'], './diagnostics.json');
});

for (const [name, mutate, expected] of [
  ['format', value => { value.formatVersion = 1; }, /format or population/],
  ['population', value => { value.diagnostics.pop(); }, /format or population/],
  ['unknown field', value => { value.diagnostics[0].unexpected = true; }, /diagnostic record/],
  ['duplicate code', value => { value.diagnostics[0].code = value.diagnostics[1].code; value.diagnostics[0].docsAnchor = value.diagnostics[1].docsAnchor; value.diagnostics[0].docsUrl = value.diagnostics[1].docsUrl; }, /duplicated/],
  ['prototype code', value => { value.diagnostics[0].code = 'constructor'; }, /diagnostic code/],
  ['paired trailing newline', value => { const entry = value.diagnostics[0]; entry.code += '\n'; entry.docsAnchor += '\n'; entry.docsUrl += '\n'; }, /diagnostic code/],
  ['alternate origin', value => { value.diagnostics[0].docsUrl = value.diagnostics[0].docsUrl.replace('docs.thresho.com', 'evil.invalid'); }, /URL does not match/],
  ['anchor substitution', value => { value.diagnostics[0].docsUrl = 'https://docs.thresho.com/reference/diagnostics#invalid-package'; }, /URL does not match/],
  ['anchor', value => { value.diagnostics[0].docsAnchor = 'other'; }, /URL does not match/],
  ['family severity', value => { value.diagnostics[0].family = 'overlay'; value.diagnostics[0].severity = 'warning'; }, /family or severity/],
  ['empty cause', value => { value.diagnostics[0].cause = ''; }, /cause is outside/],
  ['message bound', value => { value.diagnostics[0].message = '🙂'.repeat(513); }, /message is outside/],
  ['fix bound', value => { value.diagnostics[0].fix = 'x'.repeat(1025); }, /fix is outside/],
]) {
  test(`T56 refuses a recomputed public catalog with invalid ${name}`, async () => {
    const path = await fixture();
    const value = JSON.parse(await readFile(join(path, 'diagnostics.json'), 'utf8'));
    mutate(value);
    const bytes = Buffer.from(`${canonicalJson(value)}\n`);
    await writeFile(join(path, 'diagnostics.json'), bytes);
    const manifest = JSON.parse(await readFile(join(path, 'release/manifest.json'), 'utf8'));
    const entries = parseStoreZip(await readFile(join(path, 'release', manifest.fileName)));
    entries.set('diagnostics/diagnostics.json', bytes);
    await replaceZip(path, storeZip(entries));
    await assert.rejects(verifyPackage({ root: path, tag: 'v2.1.1' }), expected);
  });
}

test('T56 refuses catalog byte drift even when each catalog is valid', async () => {
  const path = await fixture();
  const value = JSON.parse(await readFile(join(path, 'diagnostics.json'), 'utf8'));
  value.diagnostics[0].message = 'A different valid explanatory message.';
  await writeFile(join(path, 'diagnostics.json'), `${canonicalJson(value)}\n`);
  await assert.rejects(verifyPackage({ root: path, tag: 'v2.1.1' }), /npm and ZIP diagnostic catalogs differ/);
});
