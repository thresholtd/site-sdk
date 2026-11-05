import { execFile } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { canonicalJson, verifyPackage, verifyTarball } from './verify-package.mjs';

const execute = promisify(execFile);
const repository = 'thresholtd/site-sdk';
const repositoryUrl = `https://github.com/${repository}`;
const registry = 'https://registry.npmjs.org';
const shaPattern = /^[a-f0-9]{40}$/;
const workflowPath = version => version === '2.0.0' ? '.github/workflows/bootstrap-publish.yml' : '.github/workflows/publish.yml';
const requireThat = (condition, message) => { if (!condition) throw new Error(message); };
const sha512 = bytes => createHash('sha512').update(bytes).digest('hex');
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function canonicalBase64(value, limit, label) {
  requireThat(typeof value === 'string' && value.length > 0 && value.length <= 4 * Math.ceil(limit / 3) && value.length % 4 === 0 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value), `${label} must use bounded canonical base64`);
  const bytes = Buffer.from(value, 'base64');
  requireThat(bytes.length <= limit && bytes.toString('base64') === value, `${label} must use bounded canonical base64`);
  return bytes;
}

function derNode(bytes, offset, end, depth = 0) {
  requireThat(depth <= 8 && offset + 2 <= end, 'certificate DER depth or header is invalid');
  const start = offset;
  const tag = bytes[offset++];
  requireThat((tag & 31) !== 31 && tag !== 0, 'certificate DER tag is unsupported');
  let length = bytes[offset++];
  if (length >= 128) {
    const count = length & 127;
    requireThat(count > 0 && count <= 3 && offset + count <= end && bytes[offset] !== 0, 'certificate DER length is not minimal');
    length = 0;
    for (let index = 0; index < count; index += 1) length = length * 256 + bytes[offset++];
    requireThat(length >= 128, 'certificate DER length is not minimal');
  }
  requireThat(offset + length <= end, 'certificate DER container is truncated');
  return { bytes, start, tag, content: offset, end: offset + length, depth, value: bytes.subarray(offset, offset + length) };
}

function derChildren(node) {
  const values = [];
  let offset = node.content;
  while (offset < node.end) {
    requireThat(values.length < 128, 'certificate DER child count exceeds its bound');
    const child = derNode(node.bytes, offset, node.end, node.depth + 1);
    values.push(child);
    offset = child.end;
  }
  requireThat(offset === node.end, 'certificate DER container has trailing data');
  return values;
}

function certificateExtensions(bytes) {
  const root = derNode(bytes, 0, bytes.length);
  requireThat(root.tag === 48 && root.end === bytes.length, 'certificate DER must contain one complete certificate');
  const certificate = derChildren(root);
  requireThat(certificate.length === 3 && certificate[0].tag === 48 && certificate[1].tag === 48 && certificate[2].tag === 3, 'certificate DER structure is invalid');
  const tbs = derChildren(certificate[0]);
  requireThat(tbs.length >= 8 && tbs[0].tag === 160 && [2, 48, 48, 48, 48, 48].every((tag, index) => tbs[index + 1]?.tag === tag), 'certificate TBSCertificate structure is invalid');
  const version = derChildren(tbs[0]);
  requireThat(version.length === 1 && version[0].tag === 2 && version[0].value.equals(Buffer.from([2])), 'certificate must use X.509 version 3');
  const tail = tbs.slice(7);
  requireThat(tail.at(-1)?.tag === 163 && tail.every((node, index) => [129, 130, 163].includes(node.tag) && (index === 0 || tail[index - 1].tag < node.tag)), 'certificate explicit extension container is invalid');
  const explicit = derChildren(tail.at(-1));
  requireThat(explicit.length === 1 && explicit[0].tag === 48, 'certificate extensions must use one explicit sequence');
  const extensions = new Map();
  for (const extension of derChildren(explicit[0])) {
    requireThat(extension.tag === 48, 'certificate extension is not a sequence');
    const parts = derChildren(extension);
    requireThat((parts.length === 2 || parts.length === 3) && parts[0].tag === 6 && parts[0].value.length > 0 && parts.at(-1).tag === 4, 'certificate extension structure is invalid');
    if (parts.length === 3) requireThat(parts[1].tag === 1 && parts[1].value.equals(Buffer.from([255])), 'certificate extension critical flag is not canonical DER');
    let boundary = true;
    for (const byte of parts[0].value) {
      requireThat(!boundary || byte !== 128, 'certificate extension OID is not canonical DER');
      boundary = (byte & 128) === 0;
    }
    requireThat(boundary, 'certificate extension OID is truncated');
    const oid = parts[0].value.toString('hex');
    requireThat(!extensions.has(oid), 'certificate contains a duplicate extension OID');
    extensions.set(oid, parts.at(-1));
  }
  return extensions;
}

export function verifyAuditedProvenance(audited, expected) {
  requireThat(audited && typeof audited === 'object' && audited.bundle && audited.statement, 'verified provenance must retain its audited bundle');
  const { statement, bundle } = audited;
  verifyProvenance(statement, expected);
  const payload = canonicalBase64(bundle.dsseEnvelope?.payload, 1048576, 'audited statement');
  requireThat(canonicalJson(JSON.parse(utf8.decode(payload))) === canonicalJson(statement), 'audited statement differs from its signed bundle');
  const material = bundle.verificationMaterial;
  requireThat(bundle.mediaType === 'application/vnd.dev.sigstore.bundle.v0.3+json' && material && !Object.hasOwn(material, 'publicKey') && !Object.hasOwn(material, 'x509CertificateChain') && material.certificate && Object.keys(material.certificate).length === 1 && Object.hasOwn(material.certificate, 'rawBytes'), 'audited bundle must use the approved single-certificate v0.3 profile');
  const bytes = canonicalBase64(material.certificate.rawBytes, 16384, 'signing certificate');
  const extensions = certificateExtensions(bytes);
  const certificate = new X509Certificate(bytes);
  requireThat(certificate.raw.equals(bytes), 'signing certificate DER was not consumed completely');
  const workflow = statement.predicate.buildDefinition.externalParameters.workflow;
  requireThat(certificate.subjectAltName === `URI:${repositoryUrl}/${workflow.path}@${workflow.ref}`, 'signing certificate workflow identity differs from the approved workflow and ref');
  for (const [oid, value, label] of [
    ['2b0601040183bf300108', 'https://token.actions.githubusercontent.com', 'issuer'],
    ['2b0601040183bf30010d', expected.sourceCommit, 'source digest'],
    ['2b0601040183bf30010b', 'github-hosted', 'runner environment'],
  ]) {
    const extension = extensions.get(oid);
    requireThat(extension !== undefined, `signing certificate ${label} extension is missing`);
    const text = derNode(extension.bytes, extension.content, extension.end, extension.depth + 1);
    requireThat(text.tag === 12 && text.end === extension.end && utf8.decode(text.value) === value, `signing certificate ${label} differs from the approved publisher`);
  }
}

export function verifyRuntime({ nodeVersion, npmVersion }) {
  requireThat(nodeVersion === 'v24.21.0' && npmVersion === '11.19.0', 'publication requires Node v24.21.0 and npm 11.19.0');
}

export function verifyProvenance(statement, { version, tag, sourceCommit, tarball }) {
  requireThat(statement?._type === 'https://in-toto.io/Statement/v1' && statement.predicateType === 'https://slsa.dev/provenance/v1', 'provenance must be an npm GitHub SLSA v1 statement');
  requireThat(Array.isArray(statement.subject) && statement.subject.length === 1, 'provenance subject is invalid');
  const subject = statement.subject[0];
  requireThat(subject.name === `pkg:npm/%40thresho/site-sdk@${version}` && subject.digest?.sha512 === sha512(tarball) && Object.keys(subject.digest).length === 1, 'provenance subject digest differs from the verified tarball');
  const definition = statement.predicate?.buildDefinition;
  const workflow = definition?.externalParameters?.workflow;
  requireThat(definition?.buildType === 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1' && workflow?.repository === repositoryUrl && workflow.path === workflowPath(version), 'provenance repository or workflow path differs from the approved publisher');
  requireThat(workflow.ref === 'refs/heads/main' || workflow.ref === `refs/tags/${tag}`, 'provenance workflow ref is not an approved main or version ref');
  requireThat(Array.isArray(definition.resolvedDependencies) && definition.resolvedDependencies.length === 1, 'provenance source dependency is invalid');
  const dependency = definition.resolvedDependencies[0];
  requireThat(dependency.uri === `git+${repositoryUrl}@${workflow.ref}` && dependency.digest?.gitCommit === sourceCommit, 'provenance source commit differs from the reviewed checkout');
  requireThat(statement.predicate?.runDetails?.builder?.id === 'https://github.com/actions/runner/github-hosted', 'provenance builder is not GitHub-hosted');
  requireThat(new RegExp(`^https://github\\.com/${repository}/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*$`).test(statement.predicate.runDetails.metadata?.invocationId ?? ''), 'provenance invocation identity is invalid');
}

function validatePorts(ports, onEvent) {
  for (const method of ['readVersion', 'publish', 'verifySignatures']) requireThat(typeof ports?.npm?.[method] === 'function', `required npm port is missing: ${method}`);
  for (const method of ['readTag', 'readRelease', 'readAsset', 'createTag', 'createRelease', 'uploadAsset']) requireThat(typeof ports?.github?.[method] === 'function', `required GitHub port is missing: ${method}`);
  requireThat(typeof onEvent === 'function', 'required publication event recorder is missing');
}

async function inspectGithub(ports, { tag, sourceCommit, assets }) {
  const remoteTag = await ports.github.readTag(tag);
  requireThat(remoteTag === null || remoteTag === sourceCommit, 'remote tag points to another source commit');
  const release = await ports.github.readRelease(tag);
  if (release !== null) {
    requireThat(remoteTag !== null && release.tagName === tag && release.sourceCommit === sourceCommit, 'remote release belongs to another source commit');
    requireThat(Array.isArray(release.assets) && release.assets.every(asset => asset && typeof asset.name === 'string') && new Set(release.assets.map(asset => asset.name)).size === release.assets.length, 'release asset inventory is invalid');
    for (const asset of release.assets) {
      requireThat(assets.has(asset.name), `unexpected remote release asset: ${asset.name}`);
      const bytes = await ports.github.readAsset(release, asset.name);
      requireThat(Buffer.isBuffer(bytes) && bytes.equals(assets.get(asset.name)), `conflicting remote release asset: ${asset.name}`);
    }
  }
  return { remoteTag, release };
}

async function matchingPackage(ports, verified, sourceCommit, tag, current) {
  const remote = current === undefined ? await ports.npm.readVersion(verified.packageJson.version) : current;
  requireThat(remote !== null && remote.name === verified.packageJson.name && remote.version === verified.packageJson.version && typeof remote.integrity === 'string' && Buffer.isBuffer(remote.tarball), 'published npm version is absent or malformed');
  requireThat(verifyTarball(remote.tarball, verified.packageFiles) === remote.integrity, 'published npm tarball bytes or integrity differ from the verified source');
  const audited = await ports.npm.verifySignatures(verified.packageJson.version);
  verifyAuditedProvenance(audited, { version: verified.packageJson.version, tag, sourceCommit, tarball: remote.tarball });
  return remote;
}

export async function publishRelease({ mode, root, tag, tarballPath, sourceCommit, context, ports, onEvent } = {}) {
  validatePorts(ports, onEvent);
  requireThat(mode === 'publish' || mode === 'release-only', 'publication mode must be publish or release-only');
  requireThat(typeof context?.head === 'string' && shaPattern.test(context.head), 'checkout HEAD must be a full source commit');
  requireThat(context.clean === true, 'publication checkout must be clean at the reviewed source commit');
  const verified = await verifyPackage({ root, tag, tarballPath });
  requireThat(verified.tarball && verified.integrity, 'a verified local npm tarball is required');
  let observedPackage;
  if (mode === 'publish') {
    requireThat(context.actions === 'true' && context.repository === repository && shaPattern.test(context.sha ?? '') && context.head === context.sha, 'publish checkout does not match GITHUB_SHA in the approved repository');
    const expectedWorkflow = `${repository}/${workflowPath(verified.packageJson.version)}@`;
    requireThat(typeof context.workflowRef === 'string' && context.workflowRef.startsWith(expectedWorkflow), 'publish workflow identity differs from the fixed public path');
    const workflowRef = context.workflowRef.slice(expectedWorkflow.length);
    requireThat(workflowRef === 'refs/heads/main' || workflowRef === `refs/tags/${tag}`, 'publish workflow ref is not main or the exact version tag');
    requireThat(context.ref === workflowRef && ['workflow_dispatch', 'push'].includes(context.event), 'publish event/ref context is inconsistent');
    if (verified.packageJson.version === '2.0.0') requireThat(context.event === 'workflow_dispatch' && context.ref === 'refs/heads/main', 'bootstrap publish requires a manual dispatch on public main');
    sourceCommit = context.head;
  } else {
    requireThat(shaPattern.test(sourceCommit ?? '') && context.head === sourceCommit, 'release-only checkout must equal the explicit source commit');
  }
  const assets = new Map([[verified.manifest.fileName, verified.zip], ['SHA256SUMS', verified.checksum]]);
  const identity = { tag, sourceCommit, assets };
  await inspectGithub(ports, identity);
  const current = await ports.npm.readVersion(verified.packageJson.version);
  if (mode === 'publish') {
    requireThat(current === null, 'npm version already exists; use explicit release-only recovery');
    onEvent({ operation: 'npm.publish', status: 'attempt', version: verified.packageJson.version, sourceCommit });
    let received = true;
    try { await ports.npm.publish(tarballPath); } catch { received = false; }
    observedPackage = await matchingPackage(ports, verified, sourceCommit, tag);
    onEvent({ operation: 'npm.publish', status: 'observed', responseReceived: received, version: verified.packageJson.version, integrity: observedPackage.integrity, sourceCommit });
  } else {
    observedPackage = await matchingPackage(ports, verified, sourceCommit, tag, current);
    onEvent({ operation: 'npm.existing', status: 'verified', version: verified.packageJson.version, integrity: observedPackage.integrity, sourceCommit });
  }
  let state = await inspectGithub(ports, identity);
  if (state.remoteTag === null) {
    onEvent({ operation: 'github.createTag', status: 'attempt', tag, sourceCommit });
    let received = true;
    try { await ports.github.createTag(tag, sourceCommit); } catch { received = false; }
    state = await inspectGithub(ports, identity);
    requireThat(state.remoteTag === sourceCommit, 'tag creation was not observed at the reviewed source commit');
    onEvent({ operation: 'github.createTag', status: 'observed', responseReceived: received, tag, sourceCommit });
  }
  state = await inspectGithub(ports, identity);
  if (state.release === null) {
    onEvent({ operation: 'github.createRelease', status: 'attempt', tag, sourceCommit });
    let received = true;
    const notes = `@thresho/site-sdk ${verified.packageJson.version}\n\nSource commit: ${sourceCommit}\nTarball integrity: ${observedPackage.integrity}\nAuthoring pack SHA-256: ${verified.manifest.sha256}\n`;
    try { await ports.github.createRelease(tag, sourceCommit, notes); } catch { received = false; }
    state = await inspectGithub(ports, identity);
    requireThat(state.release !== null, 'release creation was not observed');
    onEvent({ operation: 'github.createRelease', status: 'observed', responseReceived: received, tag, sourceCommit });
  }
  for (const [name, bytes] of assets) {
    state = await inspectGithub(ports, identity);
    requireThat(state.remoteTag === sourceCommit && state.release !== null, 'release state disappeared before an asset write');
    if (state.release.assets.some(asset => asset.name === name)) continue;
    onEvent({ operation: 'github.uploadAsset', status: 'attempt', tag, name, sourceCommit });
    let received = true;
    try { await ports.github.uploadAsset(state.release, name, bytes); } catch { received = false; }
    state = await inspectGithub(ports, identity);
    requireThat(state.release?.assets.some(asset => asset.name === name), `asset upload was not observed: ${name}`);
    onEvent({ operation: 'github.uploadAsset', status: 'observed', responseReceived: received, tag, name, sourceCommit });
  }
  state = await inspectGithub(ports, identity);
  requireThat(state.release !== null && state.release.assets.length === assets.size, 'release is not complete');
  return { state: 'complete', version: verified.packageJson.version, tag, sourceCommit, integrity: observedPackage.integrity, publicDownloadUrl: `${repositoryUrl}/releases/download/${tag}/${verified.manifest.fileName}` };
}

async function command(name, args, options = {}) {
  try { return await execute(name, args, { encoding: 'utf8', timeout: 120000, maxBuffer: 4194304, ...options }); }
  catch (error) { error.publicOperation = name; throw error; }
}

export async function boundedDownload(value, limit, { github = false } = {}) {
  let url = new URL(value);
  for (let redirect = 0; redirect < 6; redirect += 1) {
    const hosts = github ? ['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'] : ['registry.npmjs.org'];
    requireThat(url.protocol === 'https:' && hosts.includes(url.hostname) && !url.port && !url.username && !url.password && !url.hash, 'download origin is not approved');
    const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(30000) });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      requireThat(github && response.headers.has('location'), 'registry downloads must not redirect');
      await response.body?.cancel();
      url = new URL(response.headers.get('location'), url);
      continue;
    }
    requireThat(response.status === 200, 'public asset download failed');
    const length = response.headers.get('content-length');
    requireThat(length === null || (/^[0-9]+$/.test(length) && Number(length) <= limit), 'public asset exceeds its download bound');
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > limit) throw new Error('public asset exceeds its download bound');
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }
  throw new Error('public asset redirect limit exceeded');
}

function npm404(error) {
  for (const output of [error.stdout, error.stderr]) {
    try { if (JSON.parse(output).error?.code === 'E404') return true; } catch { continue; }
  }
  return false;
}

async function ghRead(path, env) {
  let output;
  try { output = (await command('gh', ['api', '--include', path], { env })).stdout; }
  catch (error) {
    if (/^HTTP\/\S+\s+404(?:\s|$)/.test(error.stdout ?? '')) return null;
    throw new Error('GitHub state read failed');
  }
  const split = output.search(/\r?\n\r?\n/);
  requireThat(split >= 0 && /^HTTP\/\S+\s+200(?:\s|$)/.test(output), 'GitHub state response is malformed');
  return JSON.parse(output.slice(split).trim());
}

export function statementFromAudit(report, version) {
  requireThat(Array.isArray(report?.invalid) && report.invalid.length === 0 && Array.isArray(report.missing) && report.missing.length === 0 && Array.isArray(report.verified), 'npm signature verification did not provide a clean audited result');
  const packages = report.verified.filter(item => item.name === '@thresho/site-sdk' && item.version === version && item.registry === `${registry}/`);
  requireThat(packages.length === 1 && Array.isArray(packages[0].attestationBundles), 'npm did not verify the exact package provenance');
  const bundles = packages[0].attestationBundles.filter(item => item.predicateType === 'https://slsa.dev/provenance/v1');
  requireThat(bundles.length === 1 && typeof bundles[0].bundle?.dsseEnvelope?.payload === 'string', 'npm did not verify one supported provenance bundle');
  const statement = JSON.parse(utf8.decode(canonicalBase64(bundles[0].bundle.dsseEnvelope.payload, 1048576, 'audited statement')));
  if (bundles[0].statement !== undefined) requireThat(canonicalJson(statement) === canonicalJson(bundles[0].statement), 'audited provenance statement differs from its signed bundle');
  return { statement, bundle: bundles[0].bundle };
}

export async function createCliPorts({ root, scratch, bootstrap, env = process.env }) {
  const npmEnv = { ...env };
  if (bootstrap) {
    requireThat(typeof env.NPM_ACCESS_TOKEN === 'string' && env.NPM_ACCESS_TOKEN.length > 0, 'bootstrap token is missing from the protected environment');
    const config = join(scratch, 'npmrc');
    await writeFile(config, '//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}\n', { mode: 0o600 });
    npmEnv.NODE_AUTH_TOKEN = env.NPM_ACCESS_TOKEN;
    npmEnv.NPM_CONFIG_USERCONFIG = config;
  }
  const npmArgs = ['--registry=https://registry.npmjs.org/', '--@thresho:registry=https://registry.npmjs.org/'];
  const api = `repos/${repository}`;
  const gh = {
    async readTag(tag) {
      let object = await ghRead(`${api}/git/ref/tags/${encodeURIComponent(tag)}`, env);
      if (object === null) return null;
      object = object.object;
      for (let depth = 0; depth < 8; depth += 1) {
        requireThat(shaPattern.test(object?.sha ?? ''), 'GitHub tag object is malformed');
        if (object.type === 'commit') return object.sha;
        requireThat(object.type === 'tag', 'GitHub tag object is not a commit');
        const annotated = await ghRead(`${api}/git/tags/${object.sha}`, env);
        requireThat(annotated !== null, 'GitHub annotated tag disappeared');
        object = annotated.object;
      }
      throw new Error('GitHub annotated tag depth exceeds its bound');
    },
    async readRelease(tag) {
      const release = await ghRead(`${api}/releases/tags/${encodeURIComponent(tag)}`, env);
      if (release === null) return null;
      requireThat(Number.isSafeInteger(release.id) && release.id > 0 && !release.draft && !release.prerelease && release.tag_name === tag && shaPattern.test(release.target_commitish ?? ''), 'GitHub release identity is malformed');
      const pages = JSON.parse((await command('gh', ['api', '--paginate', '--slurp', `${api}/releases/${release.id}/assets?per_page=100`], { env })).stdout);
      requireThat(Array.isArray(pages) && pages.every(Array.isArray), 'GitHub asset inventory is malformed');
      return { id: release.id, tagName: release.tag_name, sourceCommit: release.target_commitish, assets: pages.flat().map(asset => ({ name: asset.name, downloadUrl: asset.browser_download_url })) };
    },
    async readAsset(release, name) {
      const asset = release.assets.find(item => item.name === name);
      requireThat(asset?.downloadUrl === `${repositoryUrl}/releases/download/${release.tagName}/${name}`, 'release asset URL differs from its immutable identity');
      return boundedDownload(asset.downloadUrl, name.endsWith('.zip') ? 1048576 : 4096, { github: true });
    },
    async createTag(tag, sourceCommit) { await command('gh', ['api', '--method', 'POST', `${api}/git/refs`, '-f', `ref=refs/tags/${tag}`, '-f', `sha=${sourceCommit}`], { env }); },
    async createRelease(tag, sourceCommit, notes) {
      const notesPath = join(scratch, 'release-notes.md');
      await writeFile(notesPath, notes);
      await command('gh', ['release', 'create', tag, '--repo', repository, '--target', sourceCommit, '--title', tag, '--notes-file', notesPath, '--verify-tag'], { env });
    },
    async uploadAsset(release, name, bytes) {
      const path = join(scratch, name);
      await writeFile(path, bytes);
      await command('gh', ['release', 'upload', release.tagName, path, '--repo', repository], { env });
    },
  };
  const npm = {
    async readVersion(version) {
      let manifest;
      try { manifest = JSON.parse((await command('npm', ['view', `@thresho/site-sdk@${version}`, '--json', ...npmArgs], { cwd: root, env: npmEnv })).stdout); }
      catch (error) { if (npm404(error)) return null; throw new Error('npm version state read failed'); }
      requireThat(manifest?.name === '@thresho/site-sdk' && manifest.version === version && typeof manifest.dist?.integrity === 'string' && typeof manifest.dist.tarball === 'string', 'npm registry version metadata is malformed');
      const tarball = await boundedDownload(manifest.dist.tarball, 1048576);
      return { name: manifest.name, version, integrity: manifest.dist.integrity, tarball };
    },
    async publish(tarballPath) { await command('npm', ['publish', tarballPath, '--access', 'public', '--provenance', '--ignore-scripts', ...npmArgs], { cwd: root, env: npmEnv }); },
    async verifySignatures(version) {
      const auditPath = await mkdtemp(join(tmpdir(), 'site-sdk-signatures-'));
      try {
        await writeFile(join(auditPath, 'package.json'), JSON.stringify({ name: 'site-sdk-provenance-check', version: '1.0.0', private: true }));
        await command('npm', ['install', `@thresho/site-sdk@${version}`, '--ignore-scripts', '--no-audit', '--no-fund', '--save-exact', ...npmArgs], { cwd: auditPath, env: npmEnv });
        const report = JSON.parse((await command('npm', ['audit', 'signatures', '--json', '--include-attestations', ...npmArgs], { cwd: auditPath, env: npmEnv })).stdout);
        return statementFromAudit(report, version);
      } finally { await rm(auditPath, { recursive: true, force: true }); }
    },
  };
  return { npm, github: gh };
}

async function main(args) {
  const mode = args.shift();
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    requireThat(['--tag', '--source-commit'].includes(args[index]) && args[index + 1] && !Object.hasOwn(options, args[index]), 'usage: node scripts/publish.mjs <publish|release-only> --tag v<version> [--source-commit <sha>]');
    options[args[index]] = args[index + 1];
  }
  requireThat(['publish', 'release-only'].includes(mode) && options['--tag'], 'publication mode and --tag are required');
  requireThat(mode === 'release-only' ? shaPattern.test(options['--source-commit'] ?? '') : options['--source-commit'] === undefined, 'source commit is required only in release-only mode');
  const root = resolve(fileURLToPath(new URL('../', import.meta.url)));
  const head = (await command('git', ['rev-parse', 'HEAD'], { cwd: root })).stdout.trim();
  const clean = (await command('git', ['status', '--porcelain'], { cwd: root })).stdout === '';
  const context = { head, clean, actions: process.env.GITHUB_ACTIONS, repository: process.env.GITHUB_REPOSITORY, sha: process.env.GITHUB_SHA, workflowRef: process.env.GITHUB_WORKFLOW_REF, ref: process.env.GITHUB_REF, event: process.env.GITHUB_EVENT_NAME };
  requireThat(clean, 'publication checkout must be clean at the reviewed source commit');
  verifyRuntime({ nodeVersion: process.version, npmVersion: (await command('npm', ['--version'])).stdout.trim() });
  const verified = await verifyPackage({ root, tag: options['--tag'] });
  if (mode === 'publish') {
    const prefix = `${repository}/${workflowPath(verified.packageJson.version)}@`;
    requireThat(context.workflowRef?.startsWith(prefix) && context.actions === 'true' && context.repository === repository && context.sha === head, 'publication requires the approved GitHub workflow checkout');
  }
  const scratch = await mkdtemp(join(tmpdir(), 'site-sdk-publication-'));
  try {
    const packed = JSON.parse((await command('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', scratch], { cwd: root })).stdout);
    requireThat(Array.isArray(packed) && packed.length === 1 && /^thresho-site-sdk-[0-9.]+\.tgz$/.test(packed[0].filename), 'npm pack returned an unexpected tarball');
    const ports = await createCliPorts({ root, scratch, bootstrap: mode === 'publish' && context.workflowRef?.startsWith(`${repository}/.github/workflows/bootstrap-publish.yml@`) });
    const result = await publishRelease({ mode, root, tag: options['--tag'], tarballPath: join(scratch, packed[0].filename), sourceCommit: options['--source-commit'], context, ports, onEvent: event => process.stdout.write(`${JSON.stringify(event)}\n`) });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally { await rm(scratch, { recursive: true, force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.publicOperation ? `${error.publicOperation} operation failed` : error.message}\n`); process.exitCode = 1; }
}
