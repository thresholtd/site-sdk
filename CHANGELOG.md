# Changelog

## 2.5.0

Make uploaded TrueType font declarations portable: retain the logical slot, digest and face settings, and remove asset identities and delivery URLs from source. Target compiler 12.

## 2.4.1

Allow image declarations and extension image slots within the source byte and processing budgets without an image-count ceiling.
Retain the maximum of 32 video declarations independently from image declarations.

## 2.4.0

Add managed social image identities to route search metadata and allow editable content keys up to 128 characters.
Keep format 2, compiler 11, journey and runtime versions unchanged.

## 2.3.0

Add named color and text styles, paired light and dark colors, breakpoint sizes and uploaded TrueType font slots to the format 2 source schema.
Keep compiler 11, journey and runtime versions unchanged. Existing source produces the same compiled output when these optional declarations are absent.

## 2.2.0

Add section layout metadata, named leaf slots and the section kit source schema to the format 2 SDK and authoring pack.
Publish the current page and section authoring guidance with compiler 11 compatibility. Existing format, journey and runtime versions remain unchanged.

## 2.1.1

Update page authoring guidance and the minimal static example with an About page.
Keep the declaration and schema contract, format 2 and compiler 10 unchanged.

## 2.1.0

Add the generated diagnostic catalog with canonical documentation URLs for all 40 authoring codes.
Keep package format 2 and compiler 10.

## 2.0.0

Initial public format 2 SDK. Generate declaration-only element types, manifest types, JSON schemas and vocabulary from Forger.
The compiler remains authoritative for accepted source.
