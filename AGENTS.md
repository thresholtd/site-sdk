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

This public repository currently contains engineering instructions. It has no SDK source, package manifest, build configuration or configured test command.
Do not claim that an application build or test passed. When source is added, read its manifests and use its configured checks.
