# AGENTS.md — site-sdk

<!-- THRESHO-CANON:START -->
<!-- Generated from AGENTS.public.md by scripts/sync-agents.sh. Do not edit inside these markers. -->
# Public SDK engineering rules

This repository is intended for public types and schemas for thresho site authoring.
Keep internal operating documents, service topology, credentials and customer data out of this repository and its history.

Use camelCase for HTTP JSON fields. Preserve the published schema's field names, enums and validation bounds.
Validate data from a trust boundary. Use exact integers or decimals with an explicit currency for money.

**Tenant context.** Use `X-Tenant-Id` as declared by each operation. Context-resolved operations require the header.
Path-resolved operations allow the header to be omitted. When both the header and a `tenantId` path selector are present, their parsed UUIDs must agree.
The declared Core tenant-selector contract refuses a disagreement with `400 BAD_REQUEST` and `tenant ID mismatch` before it installs tenant context.
Tenant selection does not grant access. Apply the operation's declared authorization requirements.

Read the installed dependency version and its official documentation before a dependency change.
Write no explanatory code comments. License headers, build directives, generated banners and machine-read annotations are permitted.
Run the relevant configured checks after implementation. State which checks ran and what remains unverified.
Do not invent a build or test command when no toolchain is configured.
<!-- THRESHO-CANON:END -->

## Repository brief

Repository: `thresholtd/site-sdk`.

This repository publishes the declaration-only `@thresho/site-sdk` package and its authoring pack.
The package and release files are generated. Change their source in thresho-forger, then regenerate this public copy.
Do not add runtime JavaScript, package scripts or dependencies to the npm package.
Keep publication tooling under `scripts/` and tests under `tests/`.

Use Node v24.21.0 and npm 11.19.0 for the publication tools.
Run `node --check scripts/verify-package.mjs` and `node --check scripts/publish.mjs` after implementation.
Run `node --test tests/verify-package.test.mjs tests/publish.test.mjs` for targeted validation.
Run `node scripts/verify-package.mjs --tag v<version>` to verify the generated package and ZIP.
The public package has no build command or npm test script.

Publish reviewed source through the protected `npm-publish` environment.
Use OIDC for regular releases. The initial version uses a temporary owner workflow, which is removed after publication.
Verify the existing package before a release-only recovery. Never overwrite a version, tag or release asset.
