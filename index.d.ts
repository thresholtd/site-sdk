/** Generated from the compiler vocabulary. Do not edit. */
import type { JSX } from "./jsx-runtime.js";
export type SiteChild = JSX.Element | string | number | boolean | null | undefined | readonly SiteChild[];
/** @remarks The compiler enforces source syntax, scope, nesting, bounds and cross-field constraints. TypeScript alone does not establish source acceptance. */
export type SiteSourceManifest = { "kind": "thresho.website.source"; "formatVersion": 2; "id": string; "name": string; "journeys": Array<"presentation-retail-journey.v2">; "locales"?: { "default": string; "supported": Array<string>; }; "routes": Array<{ "path": string; "entry": string; "capability"?: "commerce.discovery" | "commerce.productPurchase" | "commerce.cart"; "role"?: "home" | "content" | "catalog" | "product" | "cart" | "checkout" | "confirmation" | "account" | "notFound"; "seo"?: { "title"?: string; "description"?: string; "ogImage"?: string; "noindex"?: boolean; }; }>; "content": Record<string, (string) | (Record<string, string>)>; "styles"?: Array<string>; "globalStyles"?: { "colors": Array<{ "id": string; "name": string; "light": string; "dark": string; }>; "textStyles": Array<{ "id": string; "name": string; "fontSlot": string; "weight": number; "lineHeight": number; "sizes": { "desktop": number; "tablet": number; "phone": number; }; }>; }; "fonts"?: Array<({ "slot": string; "family": "manrope" | "playfair-display"; "weight"?: number; "style"?: "normal" | "italic"; "display"?: "auto" | "block" | "swap" | "fallback" | "optional"; "preload"?: boolean; }) | ({ "slot": string; "family": "uploaded"; "name": string; "assetId": string; "url": string; "sha256": string; "weight": number; "style": "normal" | "italic"; "display": "swap"; "preload": boolean; })>; "media"?: Array<{ "slot": string; "kind": "image" | "video"; "backend": "r2" | "stream"; "poster"?: string; "hero"?: boolean; }>; "forms"?: Array<{ "formId": string; "formKind": "contact" | "lead" | "newsletter" | "booking" | "review"; "heading": string; "subheading"?: string; "submitLabel": string; "successMessage": string; "consent": { "label": string; "privacyPath": string; }; "fields": Array<{ "name": string; "kind": "text" | "email" | "tel" | "url" | "number" | "textarea" | "select" | "checkbox" | "radio-group" | "date" | "time"; "label": string; "purpose": "name" | "email" | "phone" | "company" | "role" | "message" | "service" | "budget" | "date" | "time" | "partySize" | "rating" | "notes" | "address" | "city" | "postalCode" | "country" | "url" | "quantity" | "preference"; "required"?: boolean; "hint"?: string; "placeholder"?: string; "autoComplete"?: string; "maxLength"?: number; "minLength"?: number; "min"?: (number) | (string); "max"?: (number) | (string); "step"?: number; "rows"?: number; "options"?: Array<{ "value": string; "label": string; }>; }>; }>; "extension"?: { "sectionKits"?: Array<{ "id": string; "label": string; "category": "hero" | "features" | "content" | "gallery" | "testimonials" | "pricing" | "faq" | "team" | "logos" | "contact" | "callToAction" | "footer"; "family": string | null; "file": string; "export": string; "slots": Array<{ "name": string; "nodeId": string; }>; }>; "contentKeys"?: Array<string>; "imageSlots"?: Array<string>; "tokens"?: Array<{ "token": "--presentation-color-accent" | "--presentation-color-surface" | "--presentation-type-scale" | "--presentation-gap" | "--presentation-radius" | "--presentation-columns"; "minimum"?: number; "maximum"?: number; "allowedValues"?: Array<"var(--presentation-palette-accent)" | "var(--presentation-palette-ink)" | "var(--presentation-palette-muted)" | "var(--presentation-palette-line)" | "var(--presentation-palette-surface)">; }>; "anchors"?: Array<{ "route": string; "nodeId": string; "properties": Array<"data-design-columns" | "data-design-columns-tablet" | "data-design-columns-mobile" | "data-design-gap" | "data-design-image-ratio" | "data-design-typography" | "data-design-color" | "data-design-visibility" | "data-design-repeat" | "data-design-facet-search">; }>; "regions"?: Array<{ "id": string; "route": string; "nodeId": string; "position": "before" | "after" | "inside-start" | "inside-end"; "allowedBlocks": Array<"Content.Text" | "Catalog.Root" | "Catalog.Products" | "Catalog.ResultCount" | "Catalog.Filters" | "Catalog.PriceRange" | "Catalog.SelectedFilters" | "Catalog.Sort" | "Catalog.Categories" | "Catalog.FilterPanel" | "Catalog.ClearFilters" | "Catalog.Search" | "Catalog.Pickup" | "Catalog.LoadMore" | "Catalog.Status" | "Product.Link" | "Product.Image" | "Product.Options" | "Product.Name" | "Product.Description" | "Product.CompareAtPrice" | "Product.Rating" | "Product.Badge" | "Product.Pickup" | "Product.Availability" | "Product.GalleryImage" | "Product.GalleryThumbnails" | "Product.GalleryPrevious" | "Product.GalleryNext" | "Product.Specifications" | "Product.SKU" | "Presentation.Image" | "Presentation.Video" | "Presentation.Icon" | "Form.Contact" | "Form.Lead" | "Form.Newsletter" | "Form.Booking" | "Form.Review">; "minimumBlocks"?: number; "maximumBlocks"?: number; }>; "routeKits"?: Array<{ "id": string; "label": string; "template": string; "pathPattern": string; }>; }; };
export type SiteSourceInput = { manifest: SiteSourceManifest; files: Record<string, string> };
export type SiteSourceRoute = SiteSourceManifest["routes"][number];
export type SiteSourceRouteSeo = NonNullable<SiteSourceRoute["seo"]>;
export type SiteLocales = NonNullable<SiteSourceManifest["locales"]>;
export type SiteFontSlot = NonNullable<SiteSourceManifest["fonts"]>[number];
export type SiteMediaSlot = NonNullable<SiteSourceManifest["media"]>[number];
export type SiteFormDefinition = NonNullable<SiteSourceManifest["forms"]>[number];
export type SiteFormField = SiteFormDefinition["fields"][number];
export type SiteSourceExtension = NonNullable<SiteSourceManifest["extension"]>;
export type SiteSourceExtensionToken = NonNullable<SiteSourceExtension["tokens"]>[number];
export type SiteSourceExtensionAnchor = NonNullable<SiteSourceExtension["anchors"]>[number];
export type SiteSourceExtensionRegion = NonNullable<SiteSourceExtension["regions"]>[number];
export type SiteSourceExtensionRouteKit = NonNullable<SiteSourceExtension["routeKits"]>[number];
export declare const Content: {
  readonly "Text": (props: { "field": string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
};
export declare const Catalog: {
  readonly "Root": (props: { "className"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "Products": (props: { "className"?: string; "nodeId"?: string; } & ({ item: string | (() => JSX.Element); children?: SiteChild } | { item?: never; children: SiteChild })) => JSX.Element;
  readonly "ResultCount": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Filters": (props: { "className"?: string; "data-design-facet-search"?: true | false | "true" | "false"; "nodeId"?: string; }) => JSX.Element;
  readonly "PriceRange": (props: { "className"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "SelectedFilters": (props: { "className"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "Sort": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Categories": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "FilterPanel": (props: { "className"?: string; "label"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "ClearFilters": (props: { "className"?: string; "label"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "Search": (props: { "className"?: string; "label"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "Pickup": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "LoadMore": (props: { "className"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "Status": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
};
export declare const Product: {
  readonly "Link": (props: { "className"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "Image": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "QuickAdd": (props: { "className"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "Options": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Name": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Description": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "CompareAtPrice": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Rating": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Badge": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Pickup": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Price": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "PurchaseTerms": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Availability": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "GalleryImage": (props: { "className"?: string; "label"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "GalleryThumbnails": (props: { "className"?: string; "label"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "GalleryPrevious": (props: { "className"?: string; "label"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "GalleryNext": (props: { "className"?: string; "label"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "Specifications": (props: { "className"?: string; "label"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "SKU": (props: { "className"?: string; "nodeId"?: string; }) => JSX.Element;
};
export declare const Cart: {
  readonly "Summary": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Lines": (props: { "className"?: string; "label"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "LineQuantity": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "LineRemove": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Adjustment": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Total": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Checkout": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
};
export declare const Checkout: {
  readonly "Root": (props: { "className"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "Coordinator": (props: { "className"?: string; "nodeId"?: string; children?: SiteChild; }) => JSX.Element;
  readonly "Contact": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Fulfillment": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Summary": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Payment": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Submit": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Status": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Confirmation": (props: { "className"?: string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
};
export declare const Presentation: {
  readonly "Image": (props: { "className"?: string; "slot": string; "alt": string; "nodeId"?: string; }) => JSX.Element;
  readonly "Video": (props: { "className"?: string; "slot": string; "label"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Icon": (props: { "className"?: string; "name": "menu" | "search" | "heart" | "user" | "bag" | "chevron-down" | "arrow-left" | "arrow-right" | "x" | "plus" | "minus" | "star"; "nodeId"?: string; }) => JSX.Element;
};
export declare const Form: {
  readonly "Contact": (props: { "form": string; "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Lead": (props: { "form": string; "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Newsletter": (props: { "form": string; "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Booking": (props: { "form": string; "className"?: string; "nodeId"?: string; }) => JSX.Element;
  readonly "Review": (props: { "form": string; "className"?: string; "nodeId"?: string; }) => JSX.Element;
};
