# @thresho/site-sdk

Install the public authoring types:

```sh
npm install -D @thresho/site-sdk
```

Extend the package configuration in your workspace tsconfig.json:

```json
{"extends":"@thresho/site-sdk/tsconfig.json","include":["src/**/*.tsx"]}
```

Run TypeScript with no output. This package contains no JavaScript runtime, React dependency or install script.
It supports editor completion and local type checks. Source check, preview and submission still require sign-in to thresho.

Associate the manifest schema in your editor workspace settings:

```json
{"json.schemas":[{"fileMatch":["thresho.site.json"],"url":"./node_modules/@thresho/site-sdk/schema/manifest.schema.json"}]}
```

Do not add a $schema key to the manifest. The compiler refuses unknown manifest keys.

Import the named Catalog, Product, Cart, Checkout, Presentation, Form and Content namespaces.
Use a component reference for Catalog.Products item, or supply authored children.
Local component props can use the exported SiteChild type through an inline type reference.

TypeScript checks admitted element names, ordinary prop names, literal enums, required props and declared child permissions.
The compiler also checks source syntax, literal values, route capabilities, ancestry, checkout composition, expanded child emptiness,
manifest cross-field predicates, uniqueness, bounds and runtime safety. A successful type check does not establish compiler acceptance.
Unknown hyphenated JSX attributes, JSX children attributes, spreads and structural excess-property cases can pass TypeScript and fail the compiler.
Content.Text collects and discards its authored children; put visible text in the named content field.
Empty fragments do not satisfy the compiler's Catalog.Products child requirement.

The vocabulary.json file records the shared compiler vocabulary and enforcement boundaries.
The diagnostic catalog is supplied by a later SDK release.

Version 2.x targets package format 2. Additions require a minor release; type corrections require a patch release.
Removal or narrowing requires a major format release.

The SDK and public authoring pack use the MIT licence. The thresho compiler and service runtime are separate products.
