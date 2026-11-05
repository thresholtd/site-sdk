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
