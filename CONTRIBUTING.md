# Contribute to the site SDK

The generated package and authoring pack come from the compiler vocabulary in thresho-forger.
Change that source first. Regenerate the public copy with Forger's `scripts/sync-site-sdk.ts`.
The public repository must contain only its approved package files, release assets, instructions and tooling.

Finish source changes before verification. Run the named Node test files and the package verifier.
Do not install dependencies into the public package or add package scripts.
The package has no executable JavaScript or runtime dependency.

Publish only reviewed source through the protected `npm-publish` environment.
Use Node v24.21.0 and npm 11.19.0 for publication.
Use the permanent `publish.yml` workflow with OIDC for each new version.
Keep tokens out of source, logs, evidence and workflow inputs.

Publication is immutable. Never overwrite a package version, tag or release asset.
If a write response is lost, inspect its remote state.
Use `release-only` with the exact source commit to complete an observed package publication.
This mode verifies the existing package integrity and provenance before any release write.
For version 2.0.0 recovery, use source commit `70f59a95d287204aae96acfd404ac510dfd4683b`.

## Diagnostic catalog 2.1 contract

The generated 2.1.0 release adds diagnostics.json as a static JSON export.
Its formatVersion is 2 and diagnostics lists 40 existing authoring codes.
Each record has code, family, severity, message, cause, fix, docsAnchor and docsUrl.
Documentation URLs use https://docs.thresho.com/reference/diagnostics with an anchor formed from the lowercase code and hyphens in place of underscores.
The npm package and authoring ZIP contain identical catalog bytes.
The exact npm inventory becomes twelve files; unknown files remain refused.
The package remains declarations and schemas with no runtime JavaScript, scripts or dependencies.
Update the generated package, version record, changelog and release files together.
Verify the generated package and ZIP, then publish reviewed main through the protected OIDC workflow.
Keep existing versions, tags and release assets immutable.
