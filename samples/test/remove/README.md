# Testing Removal Feature

This is for testing purpose. The sbomasm removing feature supports following:

- "field removal for document,
- "field removal" for single component",
- "field removal" for all components",
- "component removal" for specific component,
- "component removal" for all component

## 1. Field Removal for Document

### 1.1 Based on the fields

1. Remove `author` from document

```bash
sbomasm rm --field author --scope document samples/test/remove/complete-sbom.spdx.json -o remove-author-person.sbom.spdx.json
```

- SPDX: It removes all the author of type `Person` from `creationInfo.creators`

```bash
sbomasm rm --field author --scope document samples/test/remove/complete-sbom.cdx.json -o remove-metadata-author.sbom.cdx.json
```

- CDX: It removes all the author from `metadata.authors`

Similarly, you can remove all other document related fields from these respective spec SBOMs. As these SBOMs contains all fields.

Commands would be:

```bash

# license
sbomasm rm --field license --scope document   samples/test/remove/complete-sbom.spdx.json -o remove-license.sbom.spdx.json

sbomasm rm --field license --scope document   samples/test/remove/complete-sbom.cdx.json -o remove-metadata-license.sbom.cdx.json

# lifecycle
sbomasm rm --field lifecycle --scope document   samples/test/remove/complete-sbom.spdx.json -o remove-lifecycle.sbom.spdx.json

sbomasm rm --field lifecycle --scope document   samples/test/remove/complete-sbom.cdx.json -o remove-metadata-lifecycle.sbom.cdx.json

# repository(no such field is present in SPDX)

sbomasm rm --field repository --scope document   samples/test/remove/complete-sbom.cdx.json -o remove-metadata-repo.sbom.cdx.json

# supplier
sbomasm rm --field supplier --scope document   samples/test/remove/complete-sbom.spdx.json -o remove-author-organization.sbom.spdx.json

sbomasm rm --field supplier --scope document   samples/test/remove/complete-sbom.cdx.json -o remove-metadata-supplier.sbom.cdx.json

# tools
sbomasm rm --field tool --scope document   samples/test/remove/complete-sbom.spdx.json -o remove-tool.sbom.spdx.json

sbomasm rm --field tool --scope document   samples/test/remove/complete-sbom.cdx.json -o remove-metadata-tool.sbom.cdx.json
```

### 1.2 Based on the fields and it's values

- Remove `author` having email `hello@interlynk.io`

```bash
sbomasm rm --field author --value "hello@interlynk.io" --scope document   samples/test/remove/complete-sbom.spdx.json -o remove-author-having-value.sbom.spdx.json
```

- SPDX: remove `author` of `Person` type having value `hello@interlynk.io`

```bash
sbomasm rm --field author --value "hello@interlynk.io" --scope document   samples/test/remove/complete-sbom.cdx.json -o remove-metadata-author-having-value.sbom.cdx.json
```

- CDX: remove `author` from `metadata.authors` having value `hello@interlynk.io`

Similarly, you can remove other fields too:

```bash
# license
sbomasm rm --field license --value "CC0-1.0" --scope document   samples/test/remove/complete-sbom.spdx.json -o remove-license-having-value.sbom.spdx.json

sbomasm rm --field license --key "Acme Customer Data License" --scope document   samples/test/remove/complete-sbom.cdx.json -o remove-metadata-license-and-value.sbom.cdx.json

# lifecycle
sbomasm rm --field lifecycle --value "source" --scope document   samples/test/remove/complete-sbom.spdx.json -o remove-lifecycle-with-value.sbom.spdx.json

sbomasm rm --field lifecycle --value "design" --scope document   samples/test/remove/complete-sbom.cdx.json -o remove-metadata-lifecycle-with-value.sbom.cdx.json

# repository(SPDX don't have this field)

sbomasm rm --field repository --value "https://kyverno.io/" --scope document   samples/test/remove/complete-sbom.cdx.json -o remove-metadata-repo-with-value.sbom.cdx.json

# supplier
sbomasm rm --field supplier --value "Acme, Inc (https://github.com/acme)" --scope document   samples/test/remove/complete-sbom.spdx.json -o remove-supplier-with-value.sbom.spdx.json

## TODO: testing
sbomasm rm --field supplier --key "Acme, Inc (https://github.com/acme)" --scope document   samples/test/remove/complete-sbom.cdx.json -o remove-metadata-supplier-with-value.sbom.cdx.json

# tool
sbomasm rm --field tool --value "sbomasm-devel" --scope document   samples/test/remove/complete-sbom.spdx.json -o remove-tool-with-value.sbom.spdx.json

sbomasm rm --field tool --value "cyclonedx-gomod" --scope document   samples/test/remove/complete-sbom.cdx.json -o remove-metadata-tool-with-value.sbom.cdx.json```

```

## 2. Field Removal for Particular Component

### 2.1 Based on Field

- Remove `author`

```bash
sbomasm rm --field author --scope component --name "github.com/kyverno/kyverno" --version "v1.14.0"  samples/test/remove/complete-sbom.spdx.json -o remove-component-author.sbom.spdx.json
```

- SPDX: will remove `originator` from component

```bash
sbomasm rm --field author --scope component --name "github.com/kyverno/kyverno" --version "v1.14.0"  samples/test/remove/complete-sbom.cdx.json -o remove-component-author.sbom.cdx.json
```

- CDX: will remove `authors` section from component

Similarly, let's look for other fields.

```bash
# copyright
sbomasm rm --field copyright --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.spdx.json -o remove-component-copyright.sbom.spdx.json

sbomasm rm --field copyright --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.cdx.json -o remove-component-copyright.sbom.cdx.json

# cpe
sbomasm rm --field cpe --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.spdx.json -o remove-component-cpe.sbom.spdx.json

sbomasm rm --field cpe --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.cdx.json -o remove-component-cpe.sbom.cdx.json

# purl
sbomasm rm --field purl --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.spdx.json -o remove-component-purl.sbom.spdx.json

sbomasm rm --field purl --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.cdx.json -o remove-component-purl.sbom.cdx.json

# description
sbomasm rm --field description --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.spdx.json -o remove-component-description.sbom.spdx.json

sbomasm rm --field description --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.cdx.json -o remove-component-description.sbom.cdx.json

# hash
sbomasm rm --field hash --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.spdx.json -o remove-component-hash.sbom.spdx.json

sbomasm rm --field hash --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.cdx.json -o remove-component-hash.sbom.cdx.json

# license
sbomasm rm --field license --scope component --name "github.com/kyverno/kyverno" --version "v1.14.0"  samples/test/remove/complete-sbom.spdx.json -o remove-component-license.sbom.spdx.json

sbomasm rm --field license --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.cdx.json -o remove-component-license.sbom.cdx.json

# repository
sbomasm rm --field repository --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.spdx.json -o remove-component-repository.sbom.spdx.json

sbomasm rm --field repository --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.cdx.json -o remove-component-repository.sbom.cdx.json


# supplier
sbomasm rm --field supplier --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.spdx.json -o remove-component-supplier.sbom.spdx.json

sbomasm rm --field supplier --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.cdx.json -o remove-component-supplier.sbom.cdx.json

# type
sbomasm rm --field type --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.spdx.json -o remove-component-type.sbom.spdx.json

sbomasm rm --field type --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.cdx.json -o remove-component-type.sbom.cdx.json

```

### 2.2 Based on fields and it's values

- Remove `author` with it's value

```bash
# value `Stefan (stefan@fluxcd.io)`
sbomasm rm --field author --value "Stefan (stefan@fluxcd.io)" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"   samples/test/remove/complete-sbom.spdx.json -o remove-component-author-with-value.sbom.spdx.json

sbomasm rm --field author --value "Stefan" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"   samples/test/remove/complete-sbom.cdx.json -o remove-component-author-with-value.sbom.cdx.json


# value `Stefan`
sbomasm rm --field author --value "Stefan" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"   samples/test/remove/complete-sbom.spdx.json -o remove-component-author-with-value.sbom.spdx.json

sbomasm rm --field author --value "Stefan Prodan" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"   samples/test/remove/complete-sbom.cdx.json -o remove-component-author-with-value.sbom.cdx.json

# value `stefan@fluxcd.io`
sbomasm rm --field author --value "stefan@fluxcd.io" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"   samples/test/remove/complete-sbom.spdx.json -o remove-component-author-with-value.sbom.spdx.json

sbomasm rm --field author --value "stefan@fluxcd.io" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"   samples/test/remove/complete-sbom.cdx.json -o remove-component-author-with-value.sbom.cdx.json
```

Similarly for other fields along with their values

```bash
# copyright
sbomasm rm --field copyright --value "Copyright 2025, the FluxCD project" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx.json -o remove-component-copyright-with-value.sbom.spdx.json

sbomasm rm --field copyright --value "Copyright 2025, the FluxCD project" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.cdx.json -o remove-component-copyright-with-value.sbom.cdx.json

# cpe
sbomasm rm --field cpe --value "cpe:2.3:a:fluxcd:oci:v0.45.0:*:*:*:*:*:*:*" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx.json -o remove-component-cpe-with-value.sbom.spdx.json

sbomasm rm --field cpe --value "cpe:2.3:a:fluxcd:oci:v0.45.0:*:*:*:*:*:*:*" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.cdx.json -o remove-component-cpe-with-value.sbom.cdx.json

# purl
sbomasm rm --field purl --value "pkg:golang/github.com/fluxcd/pkg/oci@v0.45.0?type=module&goos=linux&goarch=arm64" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx.json -o remove-component-purl-with-value.sbom.spdx.json

sbomasm rm --field purl --value "pkg:golang/github.com/fluxcd/pkg/oci@v0.45.0?type=module" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.cdx.json -o remove-component-purl-with-value.sbom.cdx.json

# description
sbomasm rm --field description --value "The OCI package provides utilities for working with OCI images and registries." --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx.json -o remove-component-description-with-value.sbom.spdx.json

sbomasm rm --field description --value "The OCI package provides utilities for working with OCI images and registries." --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.cdx.json -o remove-component-description-with-value.sbom.cdx.json

# hash
sbomasm rm --field hash --value "94fb71aaacc3385dd3018c7e63dd6750b1622f382613c5c31edfee67006ac78e" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.spdx.json -o remove-component-hash-with-value.sbom.spdx.json

sbomasm rm --field hash --value "94fb71aaacc3385dd3018c7e63dd6750b1622f382613c5c31edfee67006ac78e" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.cdx.json -o remove-component-hash-with-value.sbom.cdx.json

# license
sbomasm rm --field license --value "Apache-2.0" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"  samples/test/remove/complete-sbom.spdx.json -o remove-component-license-with-value.sbom.spdx.json

sbomasm rm --field license --value "Apache-2.0" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"  samples/test/remove/complete-sbom.cdx.json -o remove-component-license-with-value.sbom.cdx.json

# repository
sbomasm rm --field repository --value "https://github.com/fluxcd/pkg/oci" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx.json -o remove-component-repository-with-value.sbom.spdx.json

sbomasm rm --field repository --value "https://github.com/fluxcd/pkg/oci" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.cdx.json -o remove-component-repository-with-value.sbom.cdx.json

# supplier
## - value 'Flux'
sbomasm rm --field supplier --value "Flux"  --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.spdx.json -o remove-component-supplier-with-value.sbom.spdx.json

sbomasm rm --field supplier --value "Flux"  --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.cdx.json -o remove-component-supplier-with-value.sbom.cdx.json

## - value 'https://fluxcd.io'
sbomasm rm --field supplier --value "https://fluxcd.io"  --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.spdx.json -o remove-component-supplier-with-value.sbom.spdx.json

## -value 'Flux (https://fluxcd.io)'
sbomasm rm --field supplier --value "Flux (https://fluxcd.io)"  --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0"    samples/test/remove/complete-sbom.spdx.json -o remove-component-supplier-with-value.sbom.spdx.json

# type
sbomasm rm --field type --value "LIBRARY"  --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx.json -o remove-component-type-with-value.sbom.spdx.json

sbomasm rm --field type --value "LIBRARY"  --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.cdx.json -o remove-component-type-with-value.sbom.cdx.json
```

## 3. Field Removal for all component

- Same as "Field Removal for Particular component", but remove particular component `name` and `version`, and add a flag `-a`

Example: Remove `purl` field from all components

```bash
sbomasm rm --field purl --scope component samples/test/remove/complete-sbom.spdx.json -o remove-purl-from-all-components.sbom.spdx.json -a

sbomasm rm --field purl --scope component samples/test/remove/complete-sbom.cdx.json -o remove-purl-from-all-components.sbom.cdx.json -a
```

Whereas, `-a` flag represents **all components**. his is useful when you have to remove specific field from all components.

## 4. Component Removal

### 4.1 Remove all component if field is present

```bash
# author
sbomasm rm --components --field author  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-author-field.sbom.spdx.json

sbomasm rm --components --field author  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-author-field.sbom.cdx.json

# copyright
sbomasm rm --components --field copyright  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-copyright-field.sbom.spdx.json

sbomasm rm --components --field copyright  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-copyright-field.sbom.cdx.json

# cpe
sbomasm rm --components --field cpe  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-cpe-field.sbom.spdx.json

sbomasm rm --components --field cpe  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-cpe-field.sbom.cdx.json

# purl
sbomasm rm --components --field purl  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-purl-field.sbom.spdx.json

sbomasm rm --components --field purl  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-purl-field.sbom.cdx.json

# description
sbomasm rm --components --field description  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-description-field.sbom.spdx.json

sbomasm rm --components --field description  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-description-field.sbom.cdx.json

# hash
sbomasm rm --components --field hash  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-hash-field.sbom.spdx.json

sbomasm rm --components --field hash  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-hash-field.sbom.cdx.json

# license
sbomasm rm --components --field license  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-license-field.sbom.cdx.json

sbomasm rm --components --field license  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-license-field.sbom.spdx.json

# repository
sbomasm rm --components --field repository  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-repo-field.sbom.spdx.json

sbomasm rm --components --field repository  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-repository-field.sbom.cdx.json

# supplier
sbomasm rm --components --field supplier  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-supplier-field.sbom.spdx.json 

sbomasm rm --components --field supplier  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-supplier-field.sbom.cdx.json

# type
sbomasm rm --components --field type  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-type-field.sbom.spdx.json

sbomasm rm --components --field type  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-type-field.sbom.cdx.json

# group (CDX only)
sbomasm rm --components --field group  samples/test/remove/complete-sbom.cdx.json -o remove-all-components-with-group.cdx.json

# publisher (CDX only)
sbomasm rm --components --field publisher  samples/test/remove/complete-sbom.cdx.json -o remove-all-components-with-publisher.cdx.json
```

### 4.2 Remove all component if field and value is present

```bash
# author
sbomasm rm --components --field author --value "dan@sigstore.dev"  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-author-field-with-value.sbom.spdx.json

sbomasm rm --components --field author --value "dan"  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-author-field-with-value.sbom.spdx.json

sbomasm rm --components --field author --value "Dan"  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-author-field-with-value.sbom.cdx.json

sbomasm rm --components --field author --value "dan@sigstore.dev"  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-author-field-with-value.sbom.cdx.json

# copyright
sbomasm rm --components --field copyright --value "Copyright 2025, the Kyverno project"  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-copyright-field-and-value.sbom.spdx.json

sbomasm rm --components --field copyright --value "Copyright 2025, the Kyverno project"  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-copyright-field-and-value.sbom.cdx.json

# cpe
sbomasm rm --components --field cpe --value "cpe:2.3:a:fluxcd:oci:v0.45.0:*:*:*:*:*:*:*"  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-cpe-field-and-value.sbom.spdx.json

sbomasm rm --components --field cpe --value "cpe:2.3:a:fluxcd:oci:v0.45.0:*:*:*:*:*:*:*"  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-cpe-field-and-value.sbom.cdx.json

# purl
sbomasm rm --components --field purl --value "pkg:golang/github.com/sigstore/rekor@v1.3.9?type=module&goos=linux&goarch=amd64"  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-purl-field-and-value.sbom.spdx.json

sbomasm rm --components --field purl --value "pkg:golang/github.com/sigstore/rekor@v1.3.9?type=module&goos=linux&goarch=amd64"  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-purl-field-and-value.sbom.cdx.json

# description
sbomasm rm --components --field description --value "Rekor is a transparency log for software artifacts."  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-description-field-and-value.sbom.spdx.json

sbomasm rm --components --field description --value "Rekor is a transparency log for software artifacts."  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-description-field-and-value.sbom.cdx.json

# hash
sbomasm rm --components --field hash --value "b148d1a4a561fe1860a8632cd2df93b9b818b24b00ad9ea9a0b102dccb060335" samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-hash-field-with-value.sbom.spdx.json

sbomasm rm --components --field hash --value "b148d1a4a561fe1860a8632cd2df93b9b818b24b00ad9ea9a0b102dccb060335" samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-hash-field-with-value.sbom.cdx.json

# license
sbomasm rm --components --field license --value "Apache-2.0"  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-license-field-with-value.sbom.spdx.json

sbomasm rm --components --field license --value "Apache-2.0"  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-license-field-with-value.sbom.cdx.json

# repository
sbomasm rm --components --field repository --value "https://github.com/sigstore/rekor"  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-repo-field-with-value.sbom.spdx.json

sbomasm rm --components --field repository --value "https://github.com/sigstore/rekor"  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-repo-field-with-value.sbom.cdx.json

# supplier
sbomasm rm --components --field supplier --value "Sigstore (https://sigstore.dev)"  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-supplier-field-with-value.sbom.spdx.json

sbomasm rm --components --field supplier --value "Sigstore"  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-supplier-field-with-value.sbom.spdx.json

sbomasm rm --components --field supplier --value "https://sigstore.dev"  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-supplier-field-with-value.sbom.spdx.json

sbomasm rm --components --field supplier --value "https://sigstore.dev"  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-supplier-field-with-value.sbom.cdx.json

sbomasm rm --components --field supplier --value "Sigstore"  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-supplier-field-with-value.sbom.cdx.json

# type
sbomasm rm --components --field type --value "library"  samples/test/remove/complete-sbom.spdx.json -o remove-comp-with-type-field-with-value.sbom.spdx.json

sbomasm rm --components --field type --value "library"  samples/test/remove/complete-sbom.cdx.json -o remove-comp-with-type-field-with-value.sbom.cdx.json

# group (CDX only)
sbomasm rm --components --field group --value "github.com/fluxcd"  samples/test/remove/complete-sbom.cdx.json -o remove-fluxcd-group-components.cdx.json

# publisher (CDX only)
sbomasm rm --components --field publisher --value "cel.dev"  samples/test/remove/complete-sbom.cdx.json -o remove-cel.dev-group-components.cdx.json
```

---

## 5. SPDX 3.0 (JSON-LD) Examples

The `complete-sbom.spdx3.json` sample is an SPDX 3.0 JSON-LD document with the same content as the SPDX 2.3 and CDX samples. Commands follow the same pattern.

### 5.1 Document-Level Field Removal

```bash
# author (removes Person entries from CreationInfo.createdBy)
sbomasm rm --field author --scope document samples/test/remove/complete-sbom.spdx3.json -o remove-author-person.sbom.spdx3.json

# supplier (removes Organization entries from CreationInfo.createdBy)
sbomasm rm --field supplier --scope document samples/test/remove/complete-sbom.spdx3.json -o remove-supplier-org.sbom.spdx3.json

# tool (removes Tool entries from CreationInfo.createdUsing)
sbomasm rm --field tool --scope document samples/test/remove/complete-sbom.spdx3.json -o remove-tool.sbom.spdx3.json

# timestamp (clears CreationInfo.created)
sbomasm rm --field timestamp --scope document samples/test/remove/complete-sbom.spdx3.json -o remove-timestamp.sbom.spdx3.json

# lifecycle (clears Sbom.sbomType)
sbomasm rm --field lifecycle --scope document samples/test/remove/complete-sbom.spdx3.json -o remove-lifecycle.sbom.spdx3.json

# repository (clears SpdxDocument.externalRef of type vcs)
sbomasm rm --field repository --scope document samples/test/remove/complete-sbom.spdx3.json -o remove-repo.sbom.spdx3.json
```

### 5.2 Document-Level Field Removal with Value Filter

```bash
# Remove author with specific email value
sbomasm rm --field author --value "hello@interlynk.io" --scope document samples/test/remove/complete-sbom.spdx3.json -o remove-author-with-value.sbom.spdx3.json

# Remove license by value (matches resolved license name)
sbomasm rm --field license --value "CC0-1.0" --scope document samples/test/remove/complete-sbom.spdx3.json -o remove-license-with-value.sbom.spdx3.json

# Remove supplier by name
sbomasm rm --field supplier --value "Acme, Inc" --scope document samples/test/remove/complete-sbom.spdx3.json -o remove-supplier-with-value.sbom.spdx3.json

# Remove supplier by SpdxID substring
sbomasm rm --field supplier --value "acme.com" --scope document samples/test/remove/complete-sbom.spdx3.json -o remove-supplier-url.sbom.spdx3.json
```

### 5.3 Component-Level Field Removal (Single Component)

```bash
# Remove hash from a specific component
sbomasm rm --field hash --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-hash.sbom.spdx3.json

# Remove purl from a specific component
sbomasm rm --field purl --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-purl.sbom.spdx3.json

# Remove type (primaryPurpose + additionalPurpose)
sbomasm rm --field type --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-type.sbom.spdx3.json

# Remove description
sbomasm rm --field description --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-description.sbom.spdx3.json

# Remove copyright
sbomasm rm --field copyright --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-copyright.sbom.spdx3.json

# Remove author (originatedBy)
sbomasm rm --field author --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-author.sbom.spdx3.json

# Remove supplier (suppliedBy)
sbomasm rm --field supplier --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-supplier.sbom.spdx3.json

# Remove repository (externalRef of type vcs)
sbomasm rm --field repository --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-repository.sbom.spdx3.json

# Remove license (hasConcludedLicense relationship)
sbomasm rm --field license --scope component --name "github.com/kyverno/kyverno" --version "v1.14.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-license.sbom.spdx3.json
```

### 5.4 Component-Level Field Removal with Value Filter

```bash
# Remove hash by specific value
sbomasm rm --field hash --value "94fb71aaacc3385dd3018c7e63dd6750b1622f382613c5c31edfee67006ac78e" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-hash-with-value.sbom.spdx3.json

# Remove purl by specific value
sbomasm rm --field purl --value "pkg:golang/github.com/fluxcd/pkg/oci@v0.45.0?type=module&goos=linux&goarch=amd64" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-purl-with-value.sbom.spdx3.json

# Remove type by value (matches primaryPurpose)
sbomasm rm --field type --value "library" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-type-with-value.sbom.spdx3.json

# Remove description by value (substring match)
sbomasm rm --field description --value "OCI package" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-desc-with-value.sbom.spdx3.json

# Remove copyright by value
sbomasm rm --field copyright --value "Copyright 2025, the FluxCD project" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-copyright-with-value.sbom.spdx3.json

# Remove author by name
sbomasm rm --field author --value "Stefan" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-author-with-name.sbom.spdx3.json

# Remove author by email
sbomasm rm --field author --value "stefan@fluxcd.io" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-author-with-email.sbom.spdx3.json

# Remove supplier by name
sbomasm rm --field supplier --value "Flux" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-supplier-with-value.sbom.spdx3.json

# Remove license by name (matches resolved license name)
sbomasm rm --field license --value "Apache-2.0" --scope component --name "github.com/kyverno/kyverno" --version "v1.14.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component-license-with-value.sbom.spdx3.json
```

### 5.5 Component-Level Field Removal (All Components)

Add `-a` / `--all` to apply to all components:

```bash
# Remove hash from all components
sbomasm rm --field hash --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-all-component-hashes.sbom.spdx3.json

# Remove purl from all components
sbomasm rm --field purl --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-purl-from-all-components.sbom.spdx3.json

# Remove type from all components
sbomasm rm --field type --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-type-from-all-components.sbom.spdx3.json

# Remove supplier from all components
sbomasm rm --field supplier --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-supplier-from-all-components.sbom.spdx3.json

# Remove author from all components
sbomasm rm --field author --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-author-from-all-components.sbom.spdx3.json

# Remove license from all components
sbomasm rm --field license --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-license-from-all-components.sbom.spdx3.json

# Remove repository from all components
sbomasm rm --field repository --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-repository-from-all-components.sbom.spdx3.json
```

### 5.6 Component-Level Field Removal — All Components with Value Filter

```bash
# Remove only components with type "application" (library components preserved)
sbomasm rm --field type --value "application" --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-all-components-type-application.sbom.spdx3.json

# Remove only components with supplier "Azure"
sbomasm rm --field supplier --value "Azure" --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-all-components-supplier-azure.sbom.spdx3.json

# Remove only components authored by "Jim"
sbomasm rm --field author --value "Jim" --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-all-components-author-jim.sbom.spdx3.json

# Remove only components with specific hash value
sbomasm rm --field hash --value "94fb71aaacc3385dd3018c7e63dd6750b1622f382613c5c31edfee67006ac78e" --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-all-components-hash-oci.sbom.spdx3.json

# Remove only components with specific purl value
sbomasm rm --field purl --value "pkg:golang/github.com/fluxcd/pkg/oci@v0.45.0?type=module&goos=linux&goarch=amd64" --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-all-components-purl-oci.sbom.spdx3.json

# Remove only components with specific license value
sbomasm rm --field license --value "Apache-2.0" --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-all-components-license-apache20.sbom.spdx3.json

# Wrong value — no components matched
sbomasm rm --field type --value "firmware" --scope component -a samples/test/remove/complete-sbom.spdx3.json -o remove-all-components-type-firmware.sbom.spdx3.json
# Expected: Error: no matching entries found.
```

### 5.7 Full Component Removal

```bash
# Remove a specific component (also cleans up dependency relationships)
sbomasm rm --components --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" samples/test/remove/complete-sbom.spdx3.json -o remove-component.sbom.spdx3.json

# Remove all components that have a specific field (orphan cleanup included)
sbomasm rm --components --field purl samples/test/remove/complete-sbom.spdx3.json -o remove-components-with-purl.sbom.spdx3.json

sbomasm rm --components --field author samples/test/remove/complete-sbom.spdx3.json -o remove-components-with-author.sbom.spdx3.json

sbomasm rm --components --field supplier samples/test/remove/complete-sbom.spdx3.json -o remove-components-with-supplier.sbom.spdx3.json

sbomasm rm --components --field license samples/test/remove/complete-sbom.spdx3.json -o remove-components-with-license.sbom.spdx3.json

sbomasm rm --components --field hash samples/test/remove/complete-sbom.spdx3.json -o remove-components-with-hash.sbom.spdx3.json

sbomasm rm --components --field description samples/test/remove/complete-sbom.spdx3.json -o remove-components-with-description.sbom.spdx3.json

sbomasm rm --components --field copyright samples/test/remove/complete-sbom.spdx3.json -o remove-components-with-copyright.sbom.spdx3.json

sbomasm rm --components --field repository samples/test/remove/complete-sbom.spdx3.json -o remove-components-with-repository.sbom.spdx3.json

sbomasm rm --components --field type samples/test/remove/complete-sbom.spdx3.json -o remove-components-with-type.sbom.spdx3.json

sbomasm rm --components --field cpe samples/test/remove/complete-sbom.spdx3.json -o remove-components-with-cpe.sbom.spdx3.json
```

### 5.8 Full Component Removal with Value Filter

```bash
# Remove components with license "Apache-2.0" (4 components); azcore (MIT) preserved
sbomasm rm --components --field license --value "Apache-2.0" samples/test/remove/complete-sbom.spdx3.json -o remove-comp-license-apache20.sbom.spdx3.json

# Remove component with license "MIT" (azcore only); others preserved
sbomasm rm --components --field license --value "MIT" samples/test/remove/complete-sbom.spdx3.json -o remove-comp-license-mit.sbom.spdx3.json

# Remove component with specific hash value
sbomasm rm --components --field hash --value "94fb71aaacc3385dd3018c7e63dd6750b1622f382613c5c31edfee67006ac78e" samples/test/remove/complete-sbom.spdx3.json -o remove-comp-hash-oci.sbom.spdx3.json

# Remove component with specific purl value
sbomasm rm --components --field purl --value "pkg:golang/github.com/fluxcd/pkg/oci@v0.45.0?type=module&goos=linux&goarch=amd64" samples/test/remove/complete-sbom.spdx3.json -o remove-comp-purl-oci.sbom.spdx3.json

# Remove component with specific description value
sbomasm rm --components --field description --value "The OCI package provides utilities for working with OCI images and registries." samples/test/remove/complete-sbom.spdx3.json -o remove-comp-desc-oci.sbom.spdx3.json

# Remove component with specific copyright value
sbomasm rm --components --field copyright --value "Copyright 2025, the FluxCD project" samples/test/remove/complete-sbom.spdx3.json -o remove-comp-copyright-oci.sbom.spdx3.json

# Remove component with specific repository value
sbomasm rm --components --field repository --value "https://github.com/fluxcd/pkg/oci" samples/test/remove/complete-sbom.spdx3.json -o remove-comp-repo-oci.sbom.spdx3.json

# Remove component with specific cpe value
sbomasm rm --components --field cpe --value "cpe:2.3:a:fluxcd:oci:v0.45.0:*:*:*:*:*:*:*" samples/test/remove/complete-sbom.spdx3.json -o remove-comp-cpe-oci.sbom.spdx3.json

# Wrong value — no components matched
sbomasm rm --components --field license --value "BSD-3-Clause" samples/test/remove/complete-sbom.spdx3.json -o remove-comp-license-bsd.sbom.spdx3.json
# Expected: Error: error selecting components: no components matched the selection criteria
```

### 5.9 SPDX 3.0 JSON-LD Specific Behavior

- **Orphan cleanup:** When removing components, orphaned Person, Organization, Tool, License, and Relationship elements are automatically cleaned from `@graph`.
- **Root element cleanup:** `SpdxDocument.rootElement` and `Sbom.rootElement` references to deleted packages are automatically removed.
- **Relationship cleanup:** All `hasConcludedLicense`, `dependsOn`, `describes`, and other relationships referencing deleted packages are automatically removed.
- **License as relationships:** Unlike SPDX 2.3 (which stores `licenseDeclared` inline), SPDX 3.0 stores licenses as `Relationship` elements (`hasConcludedLicense`, `hasDeclaredLicense`) pointing to standalone license elements in `@graph`.
- **Author/Supplier as elements:** Unlike SPDX 2.3 (which stores `originator` / `packageSupplier` as strings), SPDX 3.0 stores them as references to standalone `Person` / `Organization` elements in `@graph` via `originatedBy` / `suppliedBy`.
