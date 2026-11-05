# Contribute to the site SDK

The generated package and authoring pack come from the compiler vocabulary in thresho-forger.
Change that source first. Regenerate the public copy with Forger's `scripts/sync-site-sdk.ts`.
The public repository must contain only its approved package files, release assets, instructions and tooling.

Finish source changes before verification. Run the named Node test files and the package verifier.
Do not install dependencies into the public package or add package scripts.
The package has no executable JavaScript or runtime dependency.

Publish only reviewed source through the protected `npm-publish` environment.
Use Node v24.21.0 and npm 11.19.0 for publication.
Use the temporary bootstrap workflow for version 2.0.0. Use OIDC for later versions.
The bootstrap workflow stages the initial package with its provenance attachment.
It does not approve the stage or create GitHub release assets.
Approve only the exact stage ID and source commit from a confirmed `pending-approval` workflow result.
Complete approval through interactive npm 2FA. Then use `release-only` with that source commit.
An `observed-incomplete` result requires a separate stage status check before approval.
An earlier stage or a lost stage response has no attributed source identity in this workflow.
Do not retry, delete or approve such a stage from its byte equality alone.
Keep tokens out of source, logs, evidence and workflow inputs.

Publication is immutable. Never overwrite a package version, tag or release asset.
If a write response is lost, inspect its remote state.
Use `release-only` with the exact source commit to complete an observed package publication.
This mode verifies the existing package integrity and provenance before any release write.
