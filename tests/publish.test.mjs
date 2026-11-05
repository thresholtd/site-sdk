import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, cp, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, mock, test } from 'node:test';
import { gzipSync } from 'node:zlib';
import { boundedDownload, createCliPorts, downloadStageTarball, npmFailureCode, publishRelease, stageInitial, statementFromAudit, verifyAuditedProvenance, verifyCliMode, verifyProvenance, verifyRuntime } from '../scripts/publish.mjs';
import { canonicalJson, crc32, PACKAGE_FILES, parseStoreZip, verifyPackage } from '../scripts/verify-package.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const sourceCommit = 'a'.repeat(40);
const otherCommit = 'b'.repeat(40);
const tag = 'v2.0.0';
const publicCertificate = 'MIIChzCCAi2gAwIBAgIUVSfz6LcPUqnxpm1fmk1RKusiIq8wCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcU3ludGhldGljIHNpdGUgU0RLIHB1Ymxpc2hlcjAeFw0yNjExMDUwMjI1MTFaFw0yNjExMDYwMjI1MTFaMCcxJTAjBgNVBAMMHFN5bnRoZXRpYyBzaXRlIFNESyBwdWJsaXNoZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARAdrq8jxtQCFNT4ldlT5FYRByxxR3Wl6TMR4fIXQZNxYVGvAyJ0WJ2R3w9tBma02eOZ8mYO6ZCmYz8mUCzKyrdo4IBNTCCATEwHQYDVR0OBBYEFPwJ0JaPxfKN8pU6Zj1O8JUwIKjHMA8GA1UdEwEB/wQFMAMBAf8waQYDVR0RBGIwYIZeaHR0cHM6Ly9naXRodWIuY29tL3RocmVzaG9sdGQvc2l0ZS1zZGsvLmdpdGh1Yi93b3JrZmxvd3MvYm9vdHN0cmFwLXB1Ymxpc2gueW1sQHJlZnMvaGVhZHMvbWFpbjA7BgorBgEEAYO/MAEIBC0MK2h0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20wOAYKKwYBBAGDvzABDQQqDChhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhMB0GCisGAQQBg78wAQsEDwwNZ2l0aHViLWhvc3RlZDAKBggqhkjOPQQDAgNIADBFAiEArLmAAaLUPWlmJMAui7FDeWtsDtVZfqWI9Up3iSvSABICIA45FjzcoOPhsYfhMJ0nFN32UHOUaXAq/gC3IVOJIOlo';
const temporary = [];
afterEach(async () => { mock.restoreAll(); await Promise.all(temporary.splice(0).map(path => rm(path, { recursive: true, force: true }))); });

function ustar(files) {
  const records = [];
  for (const [name, body] of files) {
    const header = Buffer.alloc(512);
    header.write(`package/${name}`, 0, 100, 'ascii');
    header.write('0000644\0', 100, 8, 'ascii'); header.write('0000000\0', 108, 8, 'ascii'); header.write('0000000\0', 116, 8, 'ascii');
    header.write(`${body.length.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii'); header.write('00000000000\0', 136, 12, 'ascii');
    header[156] = 48; header.write('ustar\0', 257, 6, 'ascii'); header.write('00', 263, 2, 'ascii');
    header.fill(32, 148, 156);
    header.write(`${header.reduce((sum, value) => sum + value, 0).toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
    records.push(header, Buffer.from(body), Buffer.alloc((512 - body.length % 512) % 512));
  }
  return Buffer.concat([...records, Buffer.alloc(1024)]);
}

function storeZip(entries) {
  const records = [];
  const index = [];
  let offset = 0;
  const sorted = [...entries].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  for (const [name, body] of sorted) {
    const encoded = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50); local.writeUInt16LE(20, 4); local.writeUInt32LE(crc32(body), 14); local.writeUInt32LE(body.length, 18); local.writeUInt32LE(body.length, 22); local.writeUInt16LE(encoded.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt32LE(crc32(body), 16); central.writeUInt32LE(body.length, 20); central.writeUInt32LE(body.length, 24); central.writeUInt16LE(encoded.length, 28); central.writeUInt32LE(offset, 42);
    records.push(local, encoded, body);
    index.push(central, encoded);
    offset += 30 + encoded.length + body.length;
  }
  const central = Buffer.concat(index);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(sorted.length, 8); end.writeUInt16LE(sorted.length, 10); end.writeUInt32LE(central.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...records, central, end]);
}

async function poisonedPack(input, name, value) {
  const entries = parseStoreZip(input.verified.zip);
  entries.set(name, Buffer.from(value));
  const bytes = storeZip(entries);
  const manifest = { ...input.verified.manifest, sha256: createHash('sha256').update(bytes).digest('hex'), byteLength: bytes.length };
  await writeFile(join(input.root, 'release', manifest.fileName), bytes);
  await writeFile(join(input.root, 'release/manifest.json'), `${canonicalJson(manifest)}\n`);
  await writeFile(join(input.root, 'release/SHA256SUMS'), `${manifest.sha256}  ${manifest.fileName}\n`);
}

function provenance(tarball) {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'pkg:npm/%40thresho/site-sdk@2.0.0', digest: { sha512: createHash('sha512').update(tarball).digest('hex') } }],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
        externalParameters: { workflow: { repository: 'https://github.com/thresholtd/site-sdk', path: '.github/workflows/bootstrap-publish.yml', ref: 'refs/heads/main' } },
        resolvedDependencies: [{ uri: 'git+https://github.com/thresholtd/site-sdk@refs/heads/main', digest: { gitCommit: sourceCommit } }],
      },
      runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' }, metadata: { invocationId: 'https://github.com/thresholtd/site-sdk/actions/runs/123/attempts/1' } },
    },
  };
}

function audited(statement, certificate = publicCertificate) {
  return { statement, bundle: { mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json', dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString('base64') }, verificationMaterial: { certificate: { rawBytes: certificate } } } };
}

function der(tag, body) {
  const value = Buffer.from(body);
  const size = value.length < 128 ? Buffer.from([value.length]) : value.length < 256 ? Buffer.from([129, value.length]) : Buffer.from([130, value.length >> 8, value.length & 255]);
  return Buffer.concat([Buffer.from([tag]), size, value]);
}

function derParts(bytes) {
  const nodes = [];
  let position = 0;
  while (position < bytes.length) {
    const tag = bytes[position++];
    let length = bytes[position++];
    if (length & 128) {
      const count = length & 127;
      length = 0;
      for (let index = 0; index < count; index += 1) length = length * 256 + bytes[position++];
    }
    nodes.push({ tag, body: bytes.subarray(position, position + length) });
    position += length;
  }
  return nodes;
}

const encodeParts = parts => Buffer.concat(parts.map(part => der(part.tag, part.body)));

function certificateWith(change) {
  const root = derParts(Buffer.from(publicCertificate, 'base64'))[0];
  const outer = derParts(root.body);
  const tbs = derParts(outer[0].body);
  const wrapper = derParts(tbs.at(-1).body)[0];
  const extensions = derParts(wrapper.body).map(extension => derParts(extension.body));
  const updated = change(extensions) ?? extensions;
  tbs.at(-1).body = der(48, Buffer.concat(updated.map(parts => der(48, encodeParts(parts)))));
  outer[0].body = encodeParts(tbs);
  return der(48, encodeParts(outer)).toString('base64');
}

function certificateValue(oid, value, tag = 12) {
  return certificateWith(extensions => {
    const extension = extensions.find(parts => parts[0].body.toString('hex') === oid);
    extension.at(-1).body = der(tag, Buffer.from(value));
  });
}

function certificateSan(value) {
  return certificateValue('551d11', der(134, Buffer.from(value)), 48);
}

async function prepared() {
  const path = await mkdtemp(join(tmpdir(), 'site-sdk-controller-'));
  temporary.push(path);
  const publicRoot = join(path, 'public');
  await cp(root, publicRoot, { recursive: true, filter: source => !['.git', 'node_modules'].includes(relative(root, source).split('/')[0]) });
  const files = new Map(await Promise.all(PACKAGE_FILES.map(async name => [name, await readFile(join(publicRoot, name))])));
  const rawTar = ustar(files);
  const tarball = gzipSync(rawTar, { level: 9 });
  const tarballPath = join(path, 'package.tgz');
  await writeFile(tarballPath, tarball);
  const verified = await verifyPackage({ root: publicRoot, tag, tarballPath });
  return { root: publicRoot, tarballPath, tarball, rawTar, verified };
}

function fakePorts(prepared, options = {}) {
  const writes = [];
  const reads = [];
  const events = [];
  const state = {
    tag: options.tag ?? null,
    release: options.release ? { id: 1, tagName: tag, sourceCommit, ...options.release } : null,
    assets: new Map(options.assets ?? []),
    package: options.package ?? null,
    statement: options.statement ?? provenance(prepared.tarball),
    failedRead: options.failedRead,
  };
  const lost = new Set(options.lost ?? []);
  const noApply = new Set(options.noApply ?? []);
  const observe = name => {
    reads.push(name);
    if (state.failedRead === name) throw new Error(`${name} read unavailable`);
    if (options.failedReadAfter?.[0] === name && writes.includes(options.failedReadAfter[1])) throw new Error(`${name} read unavailable after write`);
  };
  const apply = (name, effect) => {
    writes.push(name);
    if (noApply.has(name)) throw new Error(`${name} write did not apply`);
    effect();
    if (lost.has(name)) throw new Error(`${name} response was lost`);
  };
  const matching = () => ({ name: '@thresho/site-sdk', version: '2.0.0', tarball: prepared.tarball, integrity: prepared.verified.integrity });
  const ports = {
    npm: {
      async readVersion(version) { assert.equal(version, '2.0.0'); observe('npm.readVersion'); return state.package; },
      async publish(path) {
        assert.equal(path, prepared.tarballPath);
        apply('npm.publish', () => { assert.equal(state.package, null); state.package = matching(); if (options.tagChangesDuringNpm) state.tag = otherCommit; });
      },
      async verifySignatures(version) { assert.equal(version, '2.0.0'); observe('npm.verifySignatures'); return options.audited ?? audited(state.statement); },
    },
    github: {
      async readTag(value) { assert.equal(value, tag); observe('github.readTag'); return state.tag; },
      async readRelease(value) { assert.equal(value, tag); observe('github.readRelease'); return state.release === null ? null : { ...state.release, assets: [...state.assets.keys()].map(name => ({ name })) }; },
      async readAsset(release, name) { assert.equal(release.id, 1); observe('github.readAsset'); return state.assets.get(name); },
      async createTag(value, commit) { assert.equal(value, tag); assert.equal(commit, sourceCommit); apply('github.createTag', () => { assert.equal(state.tag, null); state.tag = commit; }); },
      async createRelease(value, commit, notes) {
        assert.equal(value, tag); assert.equal(commit, sourceCommit); assert.match(notes, /Source commit: a{40}/); assert.match(notes, /Tarball integrity: sha512-/);
        apply('github.createRelease', () => { assert.equal(state.release, null); assert.equal(state.tag, sourceCommit); state.release = { id: 1, tagName: tag, sourceCommit }; });
      },
      async uploadAsset(release, name, bytes) { assert.equal(release.id, 1); apply(`github.uploadAsset:${name}`, () => { assert.equal(state.assets.has(name), false); state.assets.set(name, Buffer.from(bytes)); }); },
    },
  };
  const context = { head: sourceCommit, clean: true, sha: sourceCommit, actions: 'true', repository: 'thresholtd/site-sdk', workflowRef: 'thresholtd/site-sdk/.github/workflows/bootstrap-publish.yml@refs/heads/main', ref: 'refs/heads/main', event: 'workflow_dispatch' };
  const run = (mode = 'publish', overrides = {}) => publishRelease({ mode, root: prepared.root, tag, tarballPath: prepared.tarballPath, sourceCommit: mode === 'release-only' ? sourceCommit : undefined, context, ports, onEvent: event => events.push(event), ...overrides });
  return { ports, state, writes, reads, events, context, run, matching };
}

test('T10 publishes absent npm, tag, release and assets only after verification', async () => {
  const input = await prepared();
  const fake = fakePorts(input);
  const result = await fake.run();
  assert.equal(result.state, 'complete');
  assert.equal(result.sourceCommit, sourceCommit);
  assert.equal(result.publicDownloadUrl, 'https://github.com/thresholtd/site-sdk/releases/download/v2.0.0/thresho-authoring-pack-2.0.0.zip');
  assert.deepEqual(fake.writes, ['npm.publish', 'github.createTag', 'github.createRelease', 'github.uploadAsset:thresho-authoring-pack-2.0.0.zip', 'github.uploadAsset:SHA256SUMS']);
  assert.equal(fake.events.filter(event => event.status === 'attempt').length, fake.writes.length);
  assert.equal(fake.events.filter(event => event.status === 'observed').length, fake.writes.length);
  assert.ok(fake.reads.indexOf('github.readTag') < fake.reads.indexOf('npm.readVersion'));
});

test('T10 normal publish refuses an existing matching npm version without a write', async () => {
  const input = await prepared();
  const fake = fakePorts(input);
  fake.state.package = fake.matching();
  await assert.rejects(fake.run(), /already exists/);
  assert.deepEqual(fake.writes, []);
});

for (const [name, value, expected] of [
  ['AUTHORING.md', `npm_${'a'.repeat(36)}`, /credential pattern in ZIP entry/],
  ['examples/minimal-static/src/pages/Home.tsx', ['-----BEGIN ', 'ENCRYPTED PRIVATE KEY', '-----'].join(''), /credential pattern in ZIP entry/],
  ...['00000000-0000-7000-8000-000000000001', '00000000-0000-0000-0000-000000000000', 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'].map(value => ['examples/minimal-static/src/pages/Home.tsx', value, /unsafe public example/]),
]) {
  test(`T10 recomputed pack checksums cannot bypass prewrite privacy checks for ${name} ${value.slice(-12)}`, async () => {
    const input = await prepared();
    await poisonedPack(input, name, value);
    const fake = fakePorts(input);
    await assert.rejects(fake.run(), expected);
    assert.deepEqual(fake.writes, []);
    assert.deepEqual(fake.reads, []);
  });
}

test('T10 release-only verifies an existing package and completes only missing release stages', async () => {
  const input = await prepared();
  const fake = fakePorts(input, { tag: sourceCommit, release: {}, assets: [['SHA256SUMS', input.verified.checksum]] });
  fake.state.package = fake.matching();
  await fake.run('release-only');
  assert.deepEqual(fake.writes, ['github.uploadAsset:thresho-authoring-pack-2.0.0.zip']);
  fake.writes.splice(0);
  await fake.run('release-only');
  assert.deepEqual(fake.writes, []);
  assert.ok(fake.reads.includes('npm.verifySignatures'));
});

test('T10 recovery binds actual public gzip bytes and signed digest without requiring local repack equality', async () => {
  const input = await prepared();
  const fake = fakePorts(input);
  const actualTarball = gzipSync(input.rawTar, { level: 1 });
  assert.notDeepEqual(actualTarball, input.tarball);
  const actualIntegrity = `sha512-${createHash('sha512').update(actualTarball).digest('base64')}`;
  fake.state.package = { ...fake.matching(), tarball: actualTarball, integrity: actualIntegrity };
  fake.state.statement = provenance(actualTarball);
  const result = await fake.run('release-only');
  assert.equal(result.integrity, actualIntegrity);
  assert.ok(!fake.writes.includes('npm.publish'));
});

for (const operation of ['npm.publish', 'github.createTag', 'github.createRelease', 'github.uploadAsset:thresho-authoring-pack-2.0.0.zip', 'github.uploadAsset:SHA256SUMS']) {
  test(`T10 reads back an applied ${operation} write after its response is lost`, async () => {
    const fake = fakePorts(await prepared(), { lost: [operation] });
    assert.equal((await fake.run()).state, 'complete');
    assert.equal(fake.writes.filter(name => name === operation).length, 1);
    assert.ok(fake.events.some(event => event.status === 'observed' && event.responseReceived === false));
  });
  test(`T10 stops when ${operation} failed before application`, async () => {
    const fake = fakePorts(await prepared(), { noApply: [operation] });
    await assert.rejects(fake.run(), /absent or malformed|was not observed|write failed: UNKNOWN/);
    assert.equal(fake.writes.at(-1), operation);
    assert.equal(fake.writes.filter(name => name === operation).length, 1);
  });
}

for (const operation of ['github.readTag', 'github.readRelease', 'npm.readVersion']) {
  test(`T10 fails closed on an unconfirmed ${operation}`, async () => {
    const fake = fakePorts(await prepared(), { failedRead: operation });
    await assert.rejects(fake.run(), /read unavailable/);
    assert.deepEqual(fake.writes, []);
  });
}

test('T10 requires actual signature verification after npm write and stops release writes on failure', async () => {
  const fake = fakePorts(await prepared(), { failedRead: 'npm.verifySignatures' });
  await assert.rejects(fake.run(), /npm.verifySignatures read unavailable/);
  assert.deepEqual(fake.writes, ['npm.publish']);
});

for (const [read, write] of [['npm.readVersion', 'npm.publish'], ['github.readTag', 'github.createTag'], ['github.readRelease', 'github.createRelease'], ['github.readAsset', 'github.uploadAsset:thresho-authoring-pack-2.0.0.zip']]) {
  test(`T10 stops when ${read} cannot confirm an applied ${write} write`, async () => {
    const fake = fakePorts(await prepared(), { failedReadAfter: [read, write], lost: [write] });
    await assert.rejects(fake.run(), /read unavailable after write/);
    assert.equal(fake.writes.at(-1), write);
    assert.equal(fake.writes.filter(operation => operation === write).length, 1);
  });
}

for (const [name, options, expected] of [
  ['conflicting tag', { tag: otherCommit }, /another source commit/],
  ['conflicting release', { tag: sourceCommit, release: { sourceCommit: otherCommit } }, /another source commit/],
  ['release without tag', { release: {} }, /another source commit/],
  ['unexpected asset', { tag: sourceCommit, release: {}, assets: [['unknown.txt', Buffer.from('x')]] }, /unexpected remote release asset/],
  ['conflicting asset', { tag: sourceCommit, release: {}, assets: [['SHA256SUMS', Buffer.from('x')]] }, /conflicting remote release asset/],
  ['asset read failure', { tag: sourceCommit, release: {}, assets: [['SHA256SUMS', Buffer.from('x')]], failedRead: 'github.readAsset' }, /read unavailable/],
]) {
  test(`T10 refuses ${name} before npm or GitHub mutation`, async () => {
    const fake = fakePorts(await prepared(), options);
    await assert.rejects(fake.run(), expected);
    assert.deepEqual(fake.writes, []);
  });
}

test('T10 rechecks source/tag state after npm and before release mutation', async () => {
  const fake = fakePorts(await prepared(), { tagChangesDuringNpm: true });
  await assert.rejects(fake.run(), /another source commit/);
  assert.deepEqual(fake.writes, ['npm.publish']);
});

for (const [name, change] of [
  ['missing clean state', context => { delete context.clean; }],
  ['dirty source', context => { context.clean = false; }],
  ['wrong HEAD', context => { context.head = otherCommit; }],
  ['wrong repository', context => { context.repository = 'other/site-sdk'; }],
  ['local process', context => { context.actions = 'false'; }],
  ['wrong workflow path', context => { context.workflowRef = 'thresholtd/site-sdk/.github/workflows/other.yml@refs/heads/main'; }],
  ['unapproved ref', context => { context.workflowRef = 'thresholtd/site-sdk/.github/workflows/bootstrap-publish.yml@refs/heads/other'; context.ref = 'refs/heads/other'; }],
  ['nonmanual bootstrap', context => { context.event = 'push'; }],
]) {
  test(`T10 refuses publication with ${name}`, async () => {
    const fake = fakePorts(await prepared());
    change(fake.context);
    await assert.rejects(fake.run(), /checkout|GITHUB_SHA|workflow|bootstrap/);
    assert.deepEqual(fake.writes, []);
  });
}

test('T10 release-only requires explicit reviewed source and an observed matching package', async () => {
  const fake = fakePorts(await prepared());
  await assert.rejects(fake.run('release-only', { sourceCommit: undefined }), /explicit source commit/);
  await assert.rejects(fake.run('release-only', { sourceCommit: otherCommit }), /explicit source commit/);
  await assert.rejects(fake.run('release-only'), /absent or malformed/);
  fake.state.package = { ...fake.matching(), integrity: 'sha512-wrong' };
  await assert.rejects(fake.run('release-only'), /integrity differ/);
  fake.state.package = { ...fake.matching(), tarball: gzipSync(Buffer.alloc(1024)) };
  await assert.rejects(fake.run('release-only'), /tarball inventory/);
  assert.deepEqual(fake.writes, []);
});

for (const [name, change, expected] of [
  ['subject digest', statement => { statement.subject[0].digest.sha512 = '0'.repeat(128); }, /subject digest/],
  ['repository', statement => { statement.predicate.buildDefinition.externalParameters.workflow.repository = 'https://github.com/other/site-sdk'; }, /repository or workflow/],
  ['source commit', statement => { statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = otherCommit; }, /source commit/],
  ['workflow path', statement => { statement.predicate.buildDefinition.externalParameters.workflow.path = '.github/workflows/publish.yml'; }, /repository or workflow/],
  ['hosted builder', statement => { statement.predicate.runDetails.builder.id = 'https://github.com/actions/runner/self-hosted'; }, /not GitHub-hosted/],
  ['source URI', statement => { statement.predicate.buildDefinition.resolvedDependencies[0].uri = 'git+https://example.invalid/source'; }, /source commit/],
  ['statement version', statement => { statement._type = 'https://in-toto.io/Statement/v0.1'; }, /SLSA v1/],
  ['invocation identity', statement => { statement.predicate.runDetails.metadata.invocationId = 'https://github.com/other/site-sdk/actions/runs/123/attempts/1'; }, /invocation identity/],
]) {
  test(`T9/T10 refuses mismatched ${name} provenance before release mutation`, async () => {
    const input = await prepared();
    const statement = provenance(input.tarball);
    change(statement);
    const fake = fakePorts(input, { statement });
    fake.state.package = fake.matching();
    await assert.rejects(fake.run('release-only'), expected);
    assert.deepEqual(fake.writes, []);
  });
}

test('T9 accepts only the documented clean npm audited provenance bundle for the exact package', () => {
  const statement = provenance(Buffer.from('signed source'));
  const { bundle } = audited(statement);
  const report = { invalid: [], missing: [], verified: [{ name: '@thresho/site-sdk', version: '2.0.0', registry: 'https://registry.npmjs.org/', attestationBundles: [{ predicateType: 'https://slsa.dev/provenance/v1', statement, bundle }] }] };
  assert.deepEqual(statementFromAudit(report, '2.0.0'), { statement, bundle });
  assert.throws(() => statementFromAudit({ ...report, invalid: [{}] }, '2.0.0'), /clean audited result/);
  assert.throws(() => statementFromAudit({ ...report, missing: [{}] }, '2.0.0'), /clean audited result/);
  assert.throws(() => statementFromAudit({ ...report, verified: [] }, '2.0.0'), /exact package provenance/);
  assert.throws(() => statementFromAudit(report, '2.0.1'), /exact package provenance/);
  const different = structuredClone(report); different.verified[0].attestationBundles[0].statement.subject[0].name = 'other';
  assert.throws(() => statementFromAudit(different, '2.0.0'), /differs from its signed bundle/);
  verifyProvenance(statement, { version: '2.0.0', tag, sourceCommit, tarball: Buffer.from('signed source') });
});

test('T9 binds the exact audited certificate to the signed public workflow identity', () => {
  const tarball = Buffer.from('synthetic reviewed tarball');
  const value = audited(provenance(tarball));
  verifyAuditedProvenance(value, { version: '2.0.0', tag, sourceCommit, tarball });
  const statement = structuredClone(value.statement);
  statement.predicate.runDetails.metadata.invocationId = 'https://github.com/thresholtd/site-sdk/actions/runs/456/attempts/1';
  assert.throws(() => verifyAuditedProvenance({ ...value, statement }, { version: '2.0.0', tag, sourceCommit, tarball }), /differs from its signed bundle/);
});

const approvedSan = 'https://github.com/thresholtd/site-sdk/.github/workflows/bootstrap-publish.yml@refs/heads/main';
for (const [name, certificate, expected] of [
  ['workflow', () => certificateSan(approvedSan.replace('bootstrap-publish.yml', 'other.yml')), /workflow identity/],
  ['ref', () => certificateSan(approvedSan.replace('refs/heads/main', 'refs/heads/other')), /workflow identity/],
  ['SAN suffix', () => certificateSan(`${approvedSan}/extra`), /workflow identity/],
  ['multiple SANs', () => certificateValue('551d11', Buffer.concat([der(134, Buffer.from(approvedSan)), der(134, Buffer.from('https://other.invalid/workflow'))]), 48), /workflow identity/],
  ['issuer', () => certificateValue('2b0601040183bf300108', 'https://other.invalid/issuer'), /issuer differs/],
  ['source digest', () => certificateValue('2b0601040183bf30010d', otherCommit), /source digest differs/],
  ['runner', () => certificateValue('2b0601040183bf30010b', 'self-hosted'), /runner environment differs/],
  ['missing issuer', () => certificateWith(extensions => extensions.filter(parts => parts[0].body.toString('hex') !== '2b0601040183bf300108')), /issuer extension is missing/],
  ['missing source digest', () => certificateWith(extensions => extensions.filter(parts => parts[0].body.toString('hex') !== '2b0601040183bf30010d')), /source digest extension is missing/],
  ['missing runner', () => certificateWith(extensions => extensions.filter(parts => parts[0].body.toString('hex') !== '2b0601040183bf30010b')), /runner environment extension is missing/],
  ['missing SAN', () => certificateWith(extensions => extensions.filter(parts => parts[0].body.toString('hex') !== '551d11')), /workflow identity/],
  ['duplicate OID', () => certificateWith(extensions => [...extensions, extensions.find(parts => parts[0].body.toString('hex') === '2b0601040183bf300108')]), /duplicate extension OID/],
  ['malformed UTF8', () => certificateValue('2b0601040183bf300108', Buffer.from([195])), /encoded data|UTF-8/],
  ['UTF8 byte order mark', () => certificateValue('2b0601040183bf300108', Buffer.concat([Buffer.from([239, 187, 191]), Buffer.from('https://token.actions.githubusercontent.com')])), /issuer differs/],
  ['wrong string type', () => certificateValue('2b0601040183bf300108', 'https://token.actions.githubusercontent.com', 19), /issuer differs/],
  ['extension trailing data', () => certificateWith(extensions => { extensions.find(parts => parts[0].body.toString('hex') === '2b0601040183bf300108').at(-1).body = Buffer.concat([der(12, Buffer.from('https://token.actions.githubusercontent.com')), Buffer.from([0])]); }), /issuer differs/],
  ['nonminimal DER', () => certificateWith(extensions => { const part = extensions.find(parts => parts[0].body.toString('hex') === '2b0601040183bf300108').at(-1); const text = Buffer.from('https://token.actions.githubusercontent.com'); part.body = Buffer.concat([Buffer.from([12, 129, text.length]), text]); }), /length is not minimal/],
  ['trailing certificate', () => Buffer.concat([Buffer.from(publicCertificate, 'base64'), Buffer.from([0])]).toString('base64'), /one complete certificate/],
  ['truncated certificate', () => Buffer.from(publicCertificate, 'base64').subarray(0, 40).toString('base64'), /container is truncated/],
  ['indefinite DER', () => { const bytes = Buffer.from(publicCertificate, 'base64'); bytes[1] = 128; return bytes.toString('base64'); }, /length is not minimal/],
  ['overlong DER', () => { const bytes = Buffer.from(publicCertificate, 'base64'); return Buffer.concat([Buffer.from([48, 131, 0]), bytes.subarray(2)]).toString('base64'); }, /length is not minimal/],
  ['oversized certificate', () => 'A'.repeat(21852), /bounded canonical base64/],
  ['noncanonical base64', () => `${publicCertificate}\n`, /bounded canonical base64/],
  ['extension child bound', () => certificateWith(extensions => Array.from({ length: 129 }, () => extensions[0])), /child count exceeds/],
  ['nonminimal OID', () => certificateWith(extensions => { const oid = extensions[0][0]; oid.body = Buffer.concat([Buffer.from([128]), oid.body]); }), /OID is not canonical/],
]) {
  test(`T9 certificate ${name} refusal precedes every release write despite matching statement claims`, async () => {
    const input = await prepared();
    const fake = fakePorts(input, { audited: audited(provenance(input.tarball), certificate()) });
    fake.state.package = fake.matching();
    await assert.rejects(fake.run('release-only'), expected);
    assert.deepEqual(fake.writes, []);
  });
}

for (const [name, mutate] of [
  ['old bundle profile', value => { value.bundle.mediaType = 'application/vnd.dev.sigstore.bundle+json;version=0.2'; }],
  ['public key', value => { value.bundle.verificationMaterial.publicKey = {}; }],
  ['certificate chain', value => { value.bundle.verificationMaterial.x509CertificateChain = {}; }],
  ['missing leaf', value => { delete value.bundle.verificationMaterial.certificate; }],
  ['extra leaf fields', value => { value.bundle.verificationMaterial.certificate.extra = true; }],
]) {
  test(`T9 refuses ${name} in the audited bundle`, async () => {
    const input = await prepared();
    const value = audited(provenance(input.tarball));
    mutate(value);
    const fake = fakePorts(input, { audited: value });
    fake.state.package = fake.matching();
    await assert.rejects(fake.run('release-only'), /single-certificate v0.3 profile/);
    assert.deepEqual(fake.writes, []);
  });
}

test('T10 rejects missing required ports and event recording', async () => {
  const fake = fakePorts(await prepared());
  await assert.rejects(fake.run('publish', { ports: {} }), /required npm port/);
  await assert.rejects(fake.run('publish', { ports: { npm: fake.ports.npm } }), /required GitHub port/);
  await assert.rejects(fake.run('publish', { onEvent: undefined }), /event recorder/);
  assert.deepEqual(fake.writes, []);
});

function workflowPolicy(source, bootstrap) {
  for (const pin of ['actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', 'actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1']) assert.ok(source.includes(pin), 'commit-pinned action required');
  for (const value of ['runs-on: ubuntu-24.04', 'timeout-minutes: 20', 'environment: npm-publish', 'contents: read', 'contents: write', 'id-token: write', 'group: site-sdk-publication', 'cancel-in-progress: false', 'persist-credentials: false', 'package-manager-cache: false', "node-version: '24.21.0'", 'registry-url: https://registry.npmjs.org', "scope: '@thresho'", 'test "$(node --version)" = "v24.21.0"', 'test "$(npm --version)" = "11.19.0"']) assert.ok(source.includes(value), `missing workflow policy ${value}`);
  assert.ok(source.indexOf('test "$(npm --version)"') < source.indexOf('node scripts/publish.mjs'), 'runtime validation must precede publication');
  assert.ok(source.includes('workflow_dispatch:') && !/^\s+push:/m.test(source), 'publication requires explicit manual dispatch');
  assert.ok(!/\b(?:npm ci|npm install|npm publish)\b/.test(source), 'workflow must use verified publication tooling');
  assert.ok(source.indexOf('node scripts/verify-package.mjs') < source.indexOf('node scripts/publish.mjs'), 'verification must precede publication');
  for (const line of source.split('\n').filter(line => /\bnode scripts\//.test(line))) assert.ok(!/\$\{\{/.test(line), 'untrusted workflow input must pass through environment variables');
  if (bootstrap) assert.ok(source.includes('NPM_ACCESS_TOKEN: ${{ secrets.NPM_ACCESS_TOKEN }}') && source.includes('test "$RELEASE_TAG" = "v2.0.0"') && source.includes('node scripts/publish.mjs stage-initial --tag "$RELEASE_TAG"') && !source.includes('node scripts/publish.mjs publish --tag'), 'bootstrap must stage only the initial version with the temporary token');
  else assert.ok(!/NPM_ACCESS_TOKEN|NODE_AUTH_TOKEN|secrets\./.test(source), 'permanent publication must not read an npm token');
}

test('T7 workflow sources enforce the publication policy and reject policy mutations', async () => {
  const permanent = await readFile(join(root, '.github/workflows/publish.yml'), 'utf8');
  workflowPolicy(permanent, false);
  for (const [from, to] of [['ubuntu-24.04', 'self-hosted'], ['timeout-minutes: 20', 'timeout-minutes: 360'], ['environment: npm-publish', 'environment: other'], ['cancel-in-progress: false', 'cancel-in-progress: true'], ['id-token: write', 'id-token: read'], ["node-version: '24.21.0'", "node-version: '24'"], ['11.19.0', '11.5.1'], ['actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', 'actions/checkout@main']]) assert.throws(() => workflowPolicy(permanent.replace(from, to), false));
  assert.throws(() => workflowPolicy(`${permanent}\nNPM_ACCESS_TOKEN: secret\n`, false), /must not read an npm token/);
  let bootstrap;
  try { bootstrap = await readFile(join(root, '.github/workflows/bootstrap-publish.yml'), 'utf8'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (bootstrap !== undefined) workflowPolicy(bootstrap, true);
});

test('T7 runtime capability preflight accepts only the audited Node and npm pair', () => {
  verifyRuntime({ nodeVersion: 'v24.21.0', npmVersion: '11.19.0' });
  for (const runtime of [{ nodeVersion: 'v24.20.0', npmVersion: '11.19.0' }, { nodeVersion: 'v24.21.0', npmVersion: '11.5.1' }, { nodeVersion: 'v24.21.0', npmVersion: '12.0.0' }, {}]) assert.throws(() => verifyRuntime(runtime), /requires Node v24.21.0 and npm 11.19.0/);
});

test('T7 CLI derives a clean checkout and validates runtime before package or vendor operations', async () => {
  const source = await readFile(join(root, 'scripts/publish.mjs'), 'utf8');
  const cli = source.slice(source.indexOf('async function main(args)'));
  assert.ok(cli.includes("['status', '--porcelain']"));
  assert.ok(cli.indexOf('requireThat(clean,') < cli.indexOf('await mkdtemp'));
  assert.ok(cli.indexOf('verifyRuntime({') < cli.indexOf("['pack',"));
  assert.ok(cli.indexOf('verifyRuntime({') < cli.indexOf('await createCliPorts'));
});

test('T10 bounded public downloads reject unapproved origins before a request', async () => {
  const requests = [];
  mock.method(globalThis, 'fetch', async url => { requests.push(url); return new Response('public'); });
  for (const url of ['http://registry.npmjs.org/file', 'https://other.invalid/file', 'https://user:secret@registry.npmjs.org/file', 'https://registry.npmjs.org:444/file', 'https://registry.npmjs.org/file#fragment']) await assert.rejects(boundedDownload(url, 100), /origin is not approved/);
  assert.deepEqual(requests, []);
});

test('T10 bounded public downloads validate streaming and declared lengths', async () => {
  mock.method(globalThis, 'fetch', async () => new Response('public'));
  assert.deepEqual(await boundedDownload('https://registry.npmjs.org/package.tgz', 6), Buffer.from('public'));
  await assert.rejects(boundedDownload('https://registry.npmjs.org/package.tgz', 5), /download bound/);
  for (const length of ['7', '-1', 'invalid']) {
    mock.method(globalThis, 'fetch', async () => new Response('public', { headers: { 'content-length': length } }));
    await assert.rejects(boundedDownload('https://registry.npmjs.org/package.tgz', 6), /download bound/);
  }
  mock.method(globalThis, 'fetch', async () => new Response('error', { status: 503 }));
  await assert.rejects(boundedDownload('https://registry.npmjs.org/package.tgz', 100), /download failed/);
  mock.method(globalThis, 'fetch', async () => { throw new Error('connection reset'); });
  await assert.rejects(boundedDownload('https://registry.npmjs.org/package.tgz', 100), /connection reset/);
});

test('T10 bounded downloads refuse registry redirects and constrain every GitHub redirect', async () => {
  mock.method(globalThis, 'fetch', async () => new Response(null, { status: 302, headers: { location: 'https://release-assets.githubusercontent.com/asset' } }));
  await assert.rejects(boundedDownload('https://registry.npmjs.org/package.tgz', 100), /must not redirect/);
  let requests = 0;
  mock.method(globalThis, 'fetch', async url => {
    requests += 1;
    return url.hostname === 'github.com' ? new Response(null, { status: 302, headers: { location: 'https://release-assets.githubusercontent.com/asset' } }) : new Response('asset');
  });
  assert.deepEqual(await boundedDownload('https://github.com/thresholtd/site-sdk/releases/download/v2.0.0/file.zip', 5, { github: true }), Buffer.from('asset'));
  assert.equal(requests, 2);
  mock.method(globalThis, 'fetch', async () => new Response(null, { status: 302, headers: { location: 'https://private.invalid/asset' } }));
  await assert.rejects(boundedDownload('https://github.com/asset', 100, { github: true }), /origin is not approved/);
  mock.method(globalThis, 'fetch', async () => new Response(null, { status: 302, headers: { location: 'https://github.com/again' } }));
  await assert.rejects(boundedDownload('https://github.com/asset', 100, { github: true }), /redirect limit/);
});

async function commandBoundary(rules, { bootstrap = false } = {}) {
  const path = await realpath(await mkdtemp(join(tmpdir(), 'site-sdk-command-boundary-')));
  temporary.push(path);
  const bin = join(path, 'bin');
  const scratch = join(path, 'scratch');
  const publicRoot = join(path, 'public');
  await Promise.all([mkdir(bin), mkdir(scratch), mkdir(publicRoot)]);
  const rulesPath = join(path, 'rules.json');
  const logPath = join(path, 'calls.jsonl');
  await writeFile(rulesPath, JSON.stringify(rules));
  await writeFile(logPath, '');
  const executable = `#!${process.execPath}\nimport { appendFileSync, readFileSync } from 'node:fs';\nimport { basename } from 'node:path';\nconst args = process.argv.slice(2);\nconst tool = basename(process.argv[1]);\nappendFileSync(process.env.SDK_FAKE_LOG, JSON.stringify({ tool, args, cwd: process.cwd(), userconfig: process.env.NPM_CONFIG_USERCONFIG, hasAuthToken: Boolean(process.env.NODE_AUTH_TOKEN) }) + '\\n');\nconst rules = JSON.parse(readFileSync(process.env.SDK_FAKE_RULES, 'utf8'));\nconst rule = rules.find(value => value.tool === tool && value.prefix.every((arg, index) => args[index] === arg));\nif (!rule) { process.stderr.write('unexpected fake command'); process.exit(97); }\nprocess.stdout.write(rule.stdout ?? '');\nprocess.stderr.write(rule.stderr ?? '');\nprocess.exit(rule.code ?? 0);\n`;
  await writeFile(join(path, 'package.json'), '{"type":"module"}\n');
  for (const name of ['npm', 'gh']) {
    await writeFile(join(bin, name), executable);
    await chmod(join(bin, name), 0o700);
  }
  const env = { PATH: bin, SDK_FAKE_RULES: rulesPath, SDK_FAKE_LOG: logPath };
  if (bootstrap) env.NPM_ACCESS_TOKEN = 'synthetic-test-token';
  const ports = await createCliPorts({ root: publicRoot, scratch, bootstrap, env });
  return { ports, scratch, root: publicRoot, async calls() { return (await readFile(logPath, 'utf8')).trim().split('\n').filter(Boolean).map(line => JSON.parse(line)); } };
}

const npmRule = (operation, value, code = 0) => ({ tool: 'npm', prefix: [operation], stdout: typeof value === 'string' ? value : JSON.stringify(value), code });
const ghRule = (path, value, status = 200) => ({ tool: 'gh', prefix: ['api', '--include', path], stdout: `HTTP/2.0 ${status} ${status === 200 ? 'OK' : 'Error'}\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(value)}\n`, code: status === 200 ? 0 : 1 });

test('T10 real npm command adapter confirms only machine-readable E404 and pins both raw registry options', async () => {
  for (const rule of [npmRule('view', { error: { code: 'E404' } }, 1), { ...npmRule('view', '', 1), stderr: JSON.stringify({ error: { code: 'E404' } }) }]) {
    const boundary = await commandBoundary([rule]);
    assert.equal(await boundary.ports.npm.readVersion('2.0.0'), null);
    const [call] = await boundary.calls();
    assert.deepEqual(call.args, ['view', '@thresho/site-sdk@2.0.0', '--json', '--registry=https://registry.npmjs.org/', '--@thresho:registry=https://registry.npmjs.org/']);
    assert.equal(call.cwd, boundary.root);
    assert.equal(call.hasAuthToken, false);
  }
  for (const rule of [npmRule('view', { error: { code: 'E401' } }, 1), npmRule('view', 'network E404 text', 1), npmRule('view', 'malformed'), npmRule('view', { name: '@other/sdk', version: '2.0.0', dist: {} })]) {
    const boundary = await commandBoundary([rule]);
    await assert.rejects(boundary.ports.npm.readVersion('2.0.0'), /state read failed|metadata is malformed/);
  }
});

test('T10 real npm adapter downloads the exact public tarball without authentication', async () => {
  const bytes = Buffer.from('synthetic public tarball');
  const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
  const boundary = await commandBoundary([npmRule('view', { name: '@thresho/site-sdk', version: '2.0.0', dist: { integrity, tarball: 'https://registry.npmjs.org/@thresho/site-sdk/-/site-sdk-2.0.0.tgz' } })]);
  const requests = [];
  mock.method(globalThis, 'fetch', async (url, options) => { requests.push({ url: url.href, options }); return new Response(bytes); });
  assert.deepEqual(await boundary.ports.npm.readVersion('2.0.0'), { name: '@thresho/site-sdk', version: '2.0.0', integrity, tarball: bytes });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].options.headers, undefined);
  assert.equal(requests[0].url, 'https://registry.npmjs.org/@thresho/site-sdk/-/site-sdk-2.0.0.tgz');
});

test('T9 real npm audit adapter preserves the same verified bundle and isolates the temporary install', async () => {
  const value = audited(provenance(Buffer.from('synthetic audited artifact')));
  const report = { invalid: [], missing: [], verified: [{ name: '@thresho/site-sdk', version: '2.0.0', registry: 'https://registry.npmjs.org/', attestationBundles: [{ predicateType: 'https://slsa.dev/provenance/v1', ...value }] }] };
  const boundary = await commandBoundary([npmRule('install', ''), npmRule('audit', report)]);
  assert.deepEqual(await boundary.ports.npm.verifySignatures('2.0.0'), value);
  const calls = await boundary.calls();
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0].args, ['install', '@thresho/site-sdk@2.0.0', '--ignore-scripts', '--no-audit', '--no-fund', '--save-exact', '--registry=https://registry.npmjs.org/', '--@thresho:registry=https://registry.npmjs.org/']);
  assert.deepEqual(calls[1].args, ['audit', 'signatures', '--json', '--include-attestations', '--registry=https://registry.npmjs.org/', '--@thresho:registry=https://registry.npmjs.org/']);
  assert.notEqual(calls[0].cwd, boundary.root);
  assert.equal(calls[0].cwd, calls[1].cwd);
  await assert.rejects(stat(calls[0].cwd), { code: 'ENOENT' });
});

test('T9 real npm audit adapter fails closed on unsigned, malformed and unavailable audit results', async () => {
  for (const rule of [npmRule('audit', { invalid: [{}], missing: [], verified: [] }), npmRule('audit', { invalid: [], missing: [{}], verified: [] }), npmRule('audit', { invalid: [], missing: [], verified: [] }), npmRule('audit', 'invalid JSON'), npmRule('audit', 'unavailable', 1)]) {
    const boundary = await commandBoundary([npmRule('install', ''), rule]);
    await assert.rejects(boundary.ports.npm.verifySignatures('2.0.0'));
    const calls = await boundary.calls();
    assert.equal(calls.at(-1).args[0], 'audit');
    await assert.rejects(stat(calls[0].cwd), { code: 'ENOENT' });
  }
});

test('T9 real npm adapter does not audit a failed install and removes its temporary directory', async () => {
  const boundary = await commandBoundary([npmRule('install', 'unavailable', 1)]);
  await assert.rejects(boundary.ports.npm.verifySignatures('2.0.0'));
  const calls = await boundary.calls();
  assert.deepEqual(calls.map(call => call.args[0]), ['install']);
  await assert.rejects(stat(calls[0].cwd), { code: 'ENOENT' });
});

test('T10 real bootstrap adapter writes a private placeholder config and publishes the explicit verified tarball', async () => {
  const boundary = await commandBoundary([npmRule('publish', '')], { bootstrap: true });
  const tarballPath = join(boundary.scratch, 'verified.tgz');
  await writeFile(tarballPath, 'synthetic tarball');
  await boundary.ports.npm.publish(tarballPath);
  const [call] = await boundary.calls();
  assert.deepEqual(call.args, ['publish', tarballPath, '--access', 'public', '--provenance', '--ignore-scripts', '--registry=https://registry.npmjs.org/', '--@thresho:registry=https://registry.npmjs.org/']);
  assert.equal(call.hasAuthToken, true);
  assert.equal((await stat(call.userconfig)).mode & 0o777, 0o600);
  const config = await readFile(call.userconfig, 'utf8');
  assert.equal(config, '//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}\n');
  assert.ok(!config.includes('synthetic-test-token'));
});

test('T10 real GitHub adapter distinguishes confirmed HTTP 404 from unavailable or malformed reads', async () => {
  const path = 'repos/thresholtd/site-sdk/git/ref/tags/v2.0.0';
  const absent = await commandBoundary([ghRule(path, { message: 'Not Found' }, 404)]);
  assert.equal(await absent.ports.github.readTag(tag), null);
  for (const rule of [ghRule(path, { message: 'Unauthorized' }, 401), { tool: 'gh', prefix: ['api', '--include'], stdout: '404 text without HTTP headers', code: 1 }, { tool: 'gh', prefix: ['api', '--include'], stdout: JSON.stringify({ object: { type: 'commit', sha: sourceCommit } }) }]) {
    const boundary = await commandBoundary([rule]);
    await assert.rejects(boundary.ports.github.readTag(tag), /state read failed|response is malformed/);
  }
});

test('T10 real GitHub adapter resolves annotated tags and consumes every release asset page', async () => {
  const prefix = 'repos/thresholtd/site-sdk';
  const asset = name => ({ name, browser_download_url: `https://github.com/thresholtd/site-sdk/releases/download/${tag}/${name}` });
  const boundary = await commandBoundary([
    ghRule(`${prefix}/git/ref/tags/${tag}`, { object: { type: 'tag', sha: otherCommit } }),
    ghRule(`${prefix}/git/tags/${otherCommit}`, { object: { type: 'commit', sha: sourceCommit } }),
    ghRule(`${prefix}/releases/tags/${tag}`, { id: 7, draft: false, prerelease: false, tag_name: tag, target_commitish: sourceCommit }),
    { tool: 'gh', prefix: ['api', '--paginate', '--slurp', `${prefix}/releases/7/assets?per_page=100`], stdout: JSON.stringify([[asset('SHA256SUMS')], [asset('thresho-authoring-pack-2.0.0.zip')]]) },
  ]);
  assert.equal(await boundary.ports.github.readTag(tag), sourceCommit);
  const release = await boundary.ports.github.readRelease(tag);
  assert.deepEqual(release.assets.map(value => value.name), ['SHA256SUMS', 'thresho-authoring-pack-2.0.0.zip']);
  mock.method(globalThis, 'fetch', async (url, options) => { assert.equal(options.headers, undefined); assert.equal(url.href, 'https://github.com/thresholtd/site-sdk/releases/download/v2.0.0/SHA256SUMS'); return new Response('public checksum'); });
  assert.deepEqual(await boundary.ports.github.readAsset(release, 'SHA256SUMS'), Buffer.from('public checksum'));
  const calls = await boundary.calls();
  assert.ok(calls.some(call => call.args.includes('--paginate') && call.args.includes('--slurp')));
});

test('T10 real GitHub adapter refuses malformed pagination and invalid release identities', async () => {
  const path = 'repos/thresholtd/site-sdk/releases/tags/v2.0.0';
  const release = { id: 7, draft: false, prerelease: false, tag_name: tag, target_commitish: sourceCommit };
  for (const value of [{ ...release, draft: true }, { ...release, prerelease: true }, { ...release, target_commitish: 'main' }, { ...release, id: -1 }]) {
    const boundary = await commandBoundary([ghRule(path, value)]);
    await assert.rejects(boundary.ports.github.readRelease(tag), /identity is malformed/);
    assert.equal((await boundary.calls()).length, 1);
  }
  const boundary = await commandBoundary([ghRule(path, release), { tool: 'gh', prefix: ['api', '--paginate', '--slurp'], stdout: JSON.stringify({ assets: [] }) }]);
  await assert.rejects(boundary.ports.github.readRelease(tag), /inventory is malformed/);
});

test('T10 real GitHub write adapter uses immutable targets, notes files and upload without replacement', async () => {
  const boundary = await commandBoundary([{ tool: 'gh', prefix: ['api', '--method', 'POST'], stdout: '{}' }, { tool: 'gh', prefix: ['release', 'create'], stdout: '' }, { tool: 'gh', prefix: ['release', 'upload'], stdout: '' }]);
  await boundary.ports.github.createTag(tag, sourceCommit);
  await boundary.ports.github.createRelease(tag, sourceCommit, 'Synthetic reviewed source\n');
  await boundary.ports.github.uploadAsset({ tagName: tag }, 'SHA256SUMS', Buffer.from('synthetic checksum\n'));
  const calls = await boundary.calls();
  assert.deepEqual(calls[0].args, ['api', '--method', 'POST', 'repos/thresholtd/site-sdk/git/refs', '-f', 'ref=refs/tags/v2.0.0', '-f', `sha=${sourceCommit}`]);
  assert.deepEqual(calls[1].args, ['release', 'create', tag, '--repo', 'thresholtd/site-sdk', '--target', sourceCommit, '--title', tag, '--notes-file', join(boundary.scratch, 'release-notes.md'), '--verify-tag']);
  assert.equal(await readFile(join(boundary.scratch, 'release-notes.md'), 'utf8'), 'Synthetic reviewed source\n');
  assert.deepEqual(calls[2].args, ['release', 'upload', tag, join(boundary.scratch, 'SHA256SUMS'), '--repo', 'thresholtd/site-sdk']);
  assert.ok(!calls.some(call => call.args.includes('--clobber') || call.args.includes('--force')));
});

const stageId = '00000000-0000-4000-8000-000000000001';
const differentStageId = '00000000-0000-4000-8000-000000000002';

function stagingFake(input, options = {}) {
  const fake = fakePorts(input, options);
  const stage = { id: stageId, packageName: '@thresho/site-sdk', version: '2.0.0', tag: 'latest', access: 'public', shasum: createHash('sha1').update(options.tarball ?? input.tarball).digest('hex'), status: 'staged', ...options.stage };
  const state = { stages: options.initial ?? [] };
  fake.ports.npm.listStages = async () => {
    fake.reads.push('npm.listStages');
    if (options.listFailure === true || (options.listFailure === 'after' && fake.writes.includes('npm.stage'))) throw new Error('npm stage state read failed');
    return state.stages;
  };
  fake.ports.npm.readStageTarball = async id => {
    fake.reads.push('npm.readStageTarball');
    assert.equal(id, stageId);
    if (options.tarballFailure) throw new Error('npm stage tarball read failed');
    return options.tarball ?? input.tarball;
  };
  fake.ports.npm.stagePublish = async path => {
    assert.equal(path, input.tarballPath);
    fake.writes.push('npm.stage');
    if (!options.noApply) state.stages = options.after ?? [stage];
    if (options.lost || options.noApply) throw options.writeError ?? new Error('synthetic lost stage response');
    return options.response === undefined ? { stageId } : options.response;
  };
  const run = overrides => stageInitial({ root: input.root, tag, tarballPath: input.tarballPath, context: fake.context, ports: fake.ports, onEvent: event => fake.events.push(event), ...overrides });
  return { ...fake, stage, stageState: state, runStage: run };
}

test('T12 stage-initial attributes a confirmed staged result without a GitHub write', async () => {
  const input = await prepared();
  const fake = stagingFake(input);
  const result = await fake.runStage();
  assert.deepEqual(result, { state: 'pending-approval', version: '2.0.0', stageId, sourceCommit, integrity: input.verified.integrity, approval: 'Owner approval with interactive npm 2FA is required for this exact stage.' });
  assert.deepEqual(fake.writes, ['npm.stage']);
  assert.equal(fake.reads.filter(operation => operation === 'npm.listStages').length, 2);
  assert.equal(fake.reads.filter(operation => operation === 'npm.readStageTarball').length, 1);
  assert.deepEqual(fake.events.map(event => event.status), ['attempt', 'observed']);
});

test('T12 validating stage is attributed as incomplete without an approval recommendation', async () => {
  const fake = stagingFake(await prepared(), { stage: { status: 'validating' } });
  const result = await fake.runStage();
  assert.equal(result.state, 'observed-incomplete');
  assert.equal(result.sourceCommit, sourceCommit);
  assert.equal(Object.hasOwn(result, 'approval'), false);
  assert.deepEqual(fake.writes, ['npm.stage']);
});

test('T12 existing identical stage never adopts the current source or recommends approval', async () => {
  const input = await prepared();
  const fake = stagingFake(input);
  fake.stageState.stages = [{ ...fake.stage, sourceCommit: otherCommit }];
  await assert.rejects(fake.runStage(), /existing npm stage is unattributed/);
  assert.deepEqual(fake.writes, []);
  assert.deepEqual(fake.events, []);
  assert.ok(fake.reads.includes('npm.readStageTarball'));
});

test('T12 lost stage response verifies readback but refuses source attribution and approval', async () => {
  const fake = stagingFake(await prepared(), { lost: true });
  await assert.rejects(fake.runStage(), /observed npm stage is unattributed/);
  assert.deepEqual(fake.writes, ['npm.stage']);
  const unattributed = fake.events.find(event => event.status === 'unattributed');
  assert.equal(unattributed.stageId, stageId);
  assert.equal(Object.hasOwn(unattributed, 'sourceCommit'), false);
  assert.equal(fake.events.some(event => event.status === 'observed'), false);
  assert.ok(fake.reads.includes('npm.readStageTarball'));
});

for (const [name, change] of [
  ['dirty source', context => { context.clean = false; }],
  ['missing clean proof', context => { delete context.clean; }],
  ['wrong SHA', context => { context.sha = otherCommit; }],
  ['missing full HEAD', context => { context.head = 'short'; }],
  ['wrong repository', context => { context.repository = 'other/site-sdk'; }],
  ['local execution', context => { context.actions = 'false'; }],
  ['wrong workflow', context => { context.workflowRef = 'thresholtd/site-sdk/.github/workflows/publish.yml@refs/heads/main'; }],
  ['tag execution', context => { context.workflowRef = 'thresholtd/site-sdk/.github/workflows/bootstrap-publish.yml@refs/tags/v2.0.0'; context.ref = 'refs/tags/v2.0.0'; }],
  ['nonmanual event', context => { context.event = 'push'; }],
]) {
  test(`T13 stage-initial refuses ${name} before vendor reads or writes`, async () => {
    const fake = stagingFake(await prepared());
    change(fake.context);
    await assert.rejects(fake.runStage(), /checkout|GITHUB_SHA|workflow|bootstrap/);
    assert.deepEqual(fake.writes, []);
    assert.deepEqual(fake.reads, []);
  });
}

test('T13 CLI refuses initial direct publication and staging another version before adapter creation', async () => {
  const fake = stagingFake(await prepared());
  assert.throws(() => verifyCliMode({ mode: 'publish', version: '2.0.0', tag, context: fake.context }), /requires stage-initial/);
  assert.throws(() => verifyCliMode({ mode: 'stage-initial', version: '2.1.0', tag: 'v2.1.0', context: fake.context }), /only version 2.0.0/);
  const source = await readFile(join(root, 'scripts/publish.mjs'), 'utf8');
  const cli = source.slice(source.indexOf('async function main(args)'));
  assert.ok(cli.indexOf('verifyCliMode({') < cli.indexOf('await mkdtemp'));
  assert.ok(cli.indexOf('verifyCliMode({') < cli.indexOf('await createCliPorts'));
  assert.deepEqual(fake.writes, []);
});

for (const [name, options, expected] of [
  ['conflicting tag', { tag: otherCommit }, /another source commit/],
  ['conflicting release', { tag: sourceCommit, release: { sourceCommit: otherCommit } }, /another source commit/],
  ['failed stage list', { listFailure: true }, /state read failed/],
  ['malformed inventory', { initial: {} }, /inventory is malformed/],
  ['too many stages', { initial: Array.from({ length: 101 }, () => ({ version: '1.0.0' })) }, /exceeds its bound/],
]) {
  test(`T13 staging preflight refuses ${name}`, async () => {
    const fake = stagingFake(await prepared(), options);
    await assert.rejects(fake.runStage(), expected);
    assert.deepEqual(fake.writes, []);
  });
}

test('T13 staging refuses an already published version and failed absence reads', async () => {
  const input = await prepared();
  const existing = stagingFake(input);
  existing.state.package = existing.matching();
  await assert.rejects(existing.runStage(), /public npm version already exists/);
  assert.deepEqual(existing.writes, []);
  const unavailable = stagingFake(input, { failedRead: 'npm.readVersion' });
  await assert.rejects(unavailable.runStage(), /read unavailable/);
  assert.deepEqual(unavailable.writes, []);
});

for (const [name, metadata, expected] of [
  ['invalid ID', { id: '../unsafe' }, /identity or metadata/],
  ['wrong package', { packageName: '@other/site-sdk' }, /identity or metadata/],
  ['wrong access', { access: 'private' }, /identity or metadata/],
  ['wrong tag', { tag: 'next' }, /identity or metadata/],
  ['malformed SHA-1', { shasum: 'x'.repeat(40) }, /identity or metadata/],
  ['wrong SHA-1', { shasum: '0'.repeat(40) }, /SHA-1 differs/],
  ['unknown status', { status: 'approved' }, /status is unknown/],
]) {
  test(`T13 stage readback refuses ${name}`, async () => {
    const fake = stagingFake(await prepared(), { stage: metadata });
    await assert.rejects(fake.runStage(), expected);
    assert.deepEqual(fake.writes, ['npm.stage']);
    assert.equal(fake.events.some(event => event.status === 'observed'), false);
  });
}

test('T13 stage readback requires a single matching response ID and successful read', async () => {
  const input = await prepared();
  for (const options of [{ response: { stageId: differentStageId } }, { after: [] }, { listFailure: 'after' }, { tarballFailure: true }]) {
    const fake = stagingFake(input, options);
    await assert.rejects(fake.runStage(), /readback differs|write failed: UNKNOWN|state read failed|tarball read failed/);
    assert.deepEqual(fake.writes, ['npm.stage']);
  }
  const duplicate = stagingFake(input);
  duplicate.stageState.stages = [duplicate.stage, { ...duplicate.stage, id: differentStageId }];
  await assert.rejects(duplicate.runStage(), /multiple npm stages/);
  assert.deepEqual(duplicate.writes, []);
});

test('T13 stage tarball checks enforce member bytes, SHA-512 and the processing bound', async () => {
  const input = await prepared();
  const changedFiles = new Map(input.verified.packageFiles);
  changedFiles.set('index.d.ts', Buffer.from('altered member'));
  for (const [tarball, expected] of [[gzipSync(input.rawTar, { level: 1 }), /SHA-512 differs/], [gzipSync(ustar(changedFiles)), /differs from generated package/], [Buffer.alloc(1048577), /exceeds its bound/]]) {
    const fake = stagingFake(input, { tarball });
    await assert.rejects(fake.runStage(), expected);
    assert.deepEqual(fake.writes, ['npm.stage']);
    assert.equal(fake.events.some(event => event.status === 'observed'), false);
  }
});

test('T13 stage ports and event recording are mandatory', async () => {
  const fake = stagingFake(await prepared());
  await assert.rejects(fake.runStage({ ports: {} }), /required npm stage port/);
  await assert.rejects(fake.runStage({ ports: { npm: fake.ports.npm } }), /required GitHub stage preflight port/);
  await assert.rejects(fake.runStage({ onEvent: undefined }), /event recorder/);
  assert.deepEqual(fake.writes, []);
});

test('T13 a full stage page is permitted and malformed attribution responses remain unattributed', async () => {
  const input = await prepared();
  const full = stagingFake(input, { initial: Array.from({ length: 100 }, () => ({ version: '1.0.0' })) });
  assert.equal((await full.runStage()).state, 'pending-approval');
  for (const response of [null, {}, { stageId: 'unsafe' }]) {
    const fake = stagingFake(input, { response });
    await assert.rejects(fake.runStage(), /unattributed/);
    assert.equal(fake.events.some(event => event.status === 'observed'), false);
    assert.deepEqual(fake.writes, ['npm.stage']);
  }
  const duplicate = stagingFake(input);
  duplicate.ports.npm.stagePublish = async () => { duplicate.writes.push('npm.stage'); duplicate.stageState.stages = [duplicate.stage, { ...duplicate.stage, id: differentStageId }]; return { stageId }; };
  await assert.rejects(duplicate.runStage(), /multiple npm stages/);
  assert.deepEqual(duplicate.writes, ['npm.stage']);
});

test('T14 real stage adapter uses exact list and publish arguments and retains only the response ID', async () => {
  const response = { '@thresho/site-sdk': { name: '@thresho/site-sdk', version: '2.0.0', stageId, diagnostic: 'discard this field' } };
  const boundary = await commandBoundary([{ tool: 'npm', prefix: ['stage', 'list'], stdout: '[]' }, { tool: 'npm', prefix: ['stage', 'publish'], stdout: JSON.stringify(response) }], { bootstrap: true });
  assert.deepEqual(await boundary.ports.npm.listStages(), []);
  const tarball = join(boundary.scratch, 'verified.tgz');
  assert.deepEqual(await boundary.ports.npm.stagePublish(tarball), { stageId });
  const calls = await boundary.calls();
  assert.deepEqual(calls[0].args, ['stage', 'list', '@thresho/site-sdk', '--json', '--registry=https://registry.npmjs.org/', '--@thresho:registry=https://registry.npmjs.org/']);
  assert.deepEqual(calls[1].args, ['stage', 'publish', tarball, '--access', 'public', '--tag', 'latest', '--provenance', '--ignore-scripts', '--json', '--registry=https://registry.npmjs.org/', '--@thresho:registry=https://registry.npmjs.org/']);
  assert.ok(calls.every(call => call.hasAuthToken));
  assert.ok(!calls.some(call => call.args.includes('download') || call.args.includes('approve') || call.args.includes('reject')));
});

test('T14 stage adapter refuses malformed JSON, multiple packages and absent response identity', async () => {
  const secret = `npm_${'x'.repeat(36)}`;
  for (const output of [secret, '{}', JSON.stringify({ '@thresho/site-sdk': { name: '@thresho/site-sdk', version: '2.0.0', stageId }, other: { stageId: differentStageId } }), JSON.stringify({ '@thresho/site-sdk': { name: '@thresho/site-sdk', version: '2.0.0', stageId: `${stageId}/${secret}` } })]) {
    const boundary = await commandBoundary([{ tool: 'npm', prefix: ['stage', 'publish'], stdout: output }], { bootstrap: true });
    await assert.rejects(boundary.ports.npm.stagePublish('/tmp/verified.tgz'), error => error.message === 'npm.stage write failed: UNKNOWN' && !JSON.stringify(error).includes(secret));
  }
  const failed = await commandBoundary([{ tool: 'npm', prefix: ['stage', 'list'], stdout: secret, stderr: secret, code: 1 }], { bootstrap: true });
  await assert.rejects(failed.ports.npm.listStages(), error => error.message === 'npm stage state read failed' && !JSON.stringify(error).includes(secret));
});

test('T14 authenticated stage download uses only the validated fixed registry URL', async () => {
  const boundary = await commandBoundary([], { bootstrap: true });
  const requests = [];
  mock.method(globalThis, 'fetch', async (url, options) => { requests.push({ url, options }); return new Response('bounded stage bytes'); });
  assert.deepEqual(await boundary.ports.npm.readStageTarball(stageId), Buffer.from('bounded stage bytes'));
  assert.equal(requests[0].url, `https://registry.npmjs.org/-/stage/${stageId}/tarball`);
  assert.deepEqual(requests[0].options.headers, { Authorization: 'Bearer synthetic-test-token' });
  assert.equal(requests[0].options.redirect, 'manual');
  assert.ok(requests[0].options.signal instanceof AbortSignal);
  for (const id of ['../other', `${stageId}?token=unsafe`, stageId.toUpperCase().replace('00000001', '0000000A')]) await assert.rejects(boundary.ports.npm.readStageTarball(id), /stage ID is invalid/);
  assert.equal(requests.length, 1);
});

test('T14 stage download enforces the streaming limit at its exact bound', async () => {
  mock.method(globalThis, 'fetch', async () => new Response(Buffer.alloc(1048576)));
  assert.equal((await downloadStageTarball(stageId, 'synthetic-token')).length, 1048576);
  mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream({ start(controller) { controller.enqueue(Buffer.alloc(524288)); controller.enqueue(Buffer.alloc(524288)); controller.enqueue(Buffer.alloc(1)); controller.close(); } })));
  await assert.rejects(downloadStageTarball(stageId, 'synthetic-token'), /^Error: npm stage tarball read failed$/);
  mock.method(globalThis, 'fetch', async () => new Response('x', { headers: { 'content-length': '1048577' } }));
  await assert.rejects(downloadStageTarball(stageId, 'synthetic-token'), /^Error: npm stage tarball read failed$/);
});

test('T14 stage download refuses redirects, failed reads and timeout without credential text', async () => {
  const secret = `npm_${'x'.repeat(36)}`;
  let calls = 0;
  for (const status of [301, 302, 307, 308, 401, 404, 503]) {
    mock.method(globalThis, 'fetch', async () => { calls += 1; return new Response(null, { status, headers: { location: `https://other.invalid/${secret}` } }); });
    await assert.rejects(downloadStageTarball(stageId, secret), error => error.message === 'npm stage tarball read failed' && !JSON.stringify(error).includes(secret));
  }
  assert.equal(calls, 7);
  mock.method(globalThis, 'fetch', async () => { throw new Error(`connection failed ${secret}`); });
  await assert.rejects(downloadStageTarball(stageId, secret), /^Error: npm stage tarball read failed$/);
  mock.method(AbortSignal, 'timeout', milliseconds => { assert.equal(milliseconds, 30000); return AbortSignal.abort(new Error(`timeout ${secret}`)); });
  mock.method(globalThis, 'fetch', async (url, options) => { assert.ok(options.signal.aborted); throw options.signal.reason; });
  await assert.rejects(downloadStageTarball(stageId, secret), /^Error: npm stage tarball read failed$/);
});

test('T15 npm diagnostics accept only exact allowlisted JSON codes or npm code lines', () => {
  const secret = `npm_${'x'.repeat(36)}`;
  for (const code of ['EOTP', 'E401', 'E403', 'E404', 'E_STAGE_REQUIRED', 'EPRIVATE', 'EPUBLISHCONFLICT', 'EUSAGE']) {
    assert.equal(npmFailureCode({ stdout: JSON.stringify({ error: { code, message: secret }, token: secret }) }), code);
    assert.equal(npmFailureCode({ stderr: `${secret}\nnpm error code ${code}\nhttps://other.invalid/${secret}` }), code);
  }
  for (const error of [{ code: 'EOTP', message: secret }, { stdout: JSON.stringify({ error: { code: `EOTP ${secret}` } }) }, { stderr: `npm error code EOTP ${secret}` }, { stdout: `message EOTP ${secret}` }, { stdout: JSON.stringify({ error: { code: 'UNKNOWN_VENDOR_CODE' }, token: secret }) }]) assert.equal(npmFailureCode(error), 'UNKNOWN');
});

test('T15 failed unobserved stage and direct publish writes retain only a safe refusal code', async () => {
  const input = await prepared();
  const secret = `npm_${'x'.repeat(36)}`;
  const writeError = Object.assign(new Error(secret), { stdout: JSON.stringify({ error: { code: 'EOTP', message: secret }, url: `https://other.invalid/${secret}` }), stderr: secret });
  const staged = stagingFake(input, { noApply: true, writeError });
  await assert.rejects(staged.runStage(), error => error.message === 'npm.stage write failed: EOTP' && !JSON.stringify(error).includes(secret));
  assert.deepEqual(staged.writes, ['npm.stage']);
  const direct = fakePorts(input);
  direct.ports.npm.publish = async () => { direct.writes.push('npm.publish'); throw writeError; };
  await assert.rejects(direct.run(), error => error.message === 'npm.publish write failed: EOTP' && !JSON.stringify(error).includes(secret));
  assert.deepEqual(direct.writes, ['npm.publish']);
  assert.ok(!JSON.stringify([...staged.events, ...direct.events]).includes(secret));
});

test('T15 actual stage and publish command adapters discard every unapproved diagnostic field', async () => {
  const secret = `npm_${'x'.repeat(36)}`;
  for (const operation of ['stage', 'publish']) {
    const boundary = await commandBoundary([{ tool: 'npm', prefix: [operation], stdout: JSON.stringify({ error: { code: 'E403', message: secret }, token: secret }), stderr: secret, code: 1 }], { bootstrap: true });
    const write = operation === 'stage' ? boundary.ports.npm.stagePublish : boundary.ports.npm.publish;
    await assert.rejects(write('/tmp/verified.tgz'), error => error.message === `npm.${operation} write failed: E403` && !JSON.stringify(error).includes(secret) && !error.stack.includes(secret));
  }
});

test('T15 vendor JSON parse errors never repeat credential text', async () => {
  const secret = `npm_${'x'.repeat(36)}`;
  const audit = await commandBoundary([npmRule('install', ''), npmRule('audit', `not JSON ${secret}`)]);
  await assert.rejects(audit.ports.npm.verifySignatures('2.0.0'), error => error.message === 'npm signature audit response is malformed' && !JSON.stringify(error).includes(secret));
  const github = await commandBoundary([{ tool: 'gh', prefix: ['api', '--include'], stdout: `HTTP/2.0 200 OK\r\n\r\nnot JSON ${secret}` }]);
  await assert.rejects(github.ports.github.readTag(tag), error => error.message === 'GitHub state response is malformed' && !JSON.stringify(error).includes(secret));
});
