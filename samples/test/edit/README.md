# Testing Editing Feature

- This is simply to test all the features related to edit command.
- It allows edit on the basis of subject. It support 3 kinds of subjects: Document, Primary COmponent, and Cmponent with name and version.

## Examples

### 1. Edit Document

1. Append author to the document

```bash
sbomasm edit --subject document --author "Interlynk (hello@interlynk.io)"  samples/test/edit/in-complete-sbom.spdx.json -o append-author-sbom.spdx.json --append

sbomasm edit --subject document --author "Interlynk (hello@interlynk.io)"  samples/test/edit/in-complete-sbom.cdx.json -o append-author-sbom.cdx.json --append
```

- Similarly for other fields:

```bash
# supplier(SPDX doesn't support)
sbomasm edit --subject document --supplier "Interlynk (https://interlynk.io)"  samples/test/edit/in-complete-sbom.cdx.json -o append-supplier-sbom.cdx.json --append

# lifecycle
sbomasm edit --subject document --lifecycle "source" samples/test/edit/in-complete-sbom.spdx.json -o append-lifecycle-sbom.spdx.json --append

sbomasm edit --subject document --lifecycle "source" samples/test/edit/in-complete-sbom.cdx.json -o append-lifecycle-sbom.cdx.json --append

# license
sbomasm edit --subject document --license "CC0-1.1" samples/test/edit/in-complete-sbom.spdx.json -o append-license-sbom.spdx.json

sbomasm edit --subject document --license "Acme Customer Data License" samples/test/edit/in-complete-sbom.cdx.json -o append-license-sbom.cdx.json 

# repository(SPDX doesn't support)
sbomasm edit --subject document --repository "https://kyverno.io/" samples/test/edit/in-complete-sbom.cdx.json -o append-repo-sbom.cdx.json --append
```

### 2. Edit Primary Component

```bash
sbomasm edit --subject primary-component --author "Jim (jim@nirmata.com)" samples/test/edit/in-complete-sbom.spdx.json -o append-pc-author-sbom.spdx.json --append

sbomasm edit --subject primary-component --author "Interlynk (hello@interlynk.io)"  samples/test/edit/in-complete-sbom.cdx.json -o append-author-sbom.cdx.json --append
```

- Similarly for other fields:

```bash
# supplier
sbomasm edit --subject primary-component --supplier "Kyverno (https://kyverno.io)"  samples/test/edit/in-complete-sbom.spdx.json -o append-pc-supplier-sbom.spdx.json --append

sbomasm edit --subject primary-component --supplier "Kyverno (https://kyverno.io)"  samples/test/edit/in-complete-sbom.cdx.json -o append-pc-supplier-sbom.cdx.json --append

# license
sbomasm edit --subject primary-component --license "Apache-2.0" samples/test/edit/in-complete-sbom.spdx.json -o append-pc-license-sbom.spdx.json

sbomasm edit --subject primary-component --license "Apache-2.0" samples/test/edit/in-complete-sbom.cdx.json -o append-pc-license-sbom.cdx.json

# copyright
sbomasm edit --subject primary-component --copyright "Copyright 2025, the Kyverno project" samples/test/edit/in-complete-sbom.spdx.json -o append-pc-copyright-sbom.spdx.json

sbomasm edit --subject primary-component --copyright "Copyright 2025, the Kyverno project" samples/test/edit/in-complete-sbom.cdx.json -o append-pc-copyright-sbom.cdx.json

# description
sbomasm edit --subject primary-component --description "Kyverno is a policy engine designed for Kubernetes." samples/test/edit/in-complete-sbom.spdx.json -o append-pc-description-sbom.spdx.json

sbomasm edit --subject primary-component --description "Kyverno is a policy engine designed for Kubernetes." samples/test/edit/in-complete-sbom.cdx.json -o append-pc-description-sbom.cdx.json

# repository
sbomasm edit --subject primary-component --repository "https://github.com/kyverno/kyverno/releases" samples/test/edit/in-complete-sbom.spdx.json -o append-pc-repository-sbom.spdx.json


sbomasm edit --subject primary-component --repository "https://github.com/kyverno/kyverno/releases" samples/test/edit/in-complete-sbom.cdx.json -o append-pc-repository-sbom.cdx.json

# type
sbomasm edit --subject primary-component --type "APPLICATION" samples/test/edit/in-complete-sbom.spdx.json -o append-pc-type-sbom.spdx.json

sbomasm edit --subject primary-component --type "APPLICATION" samples/test/edit/in-complete-sbom.cdx.json -o append-pc-type-sbom.cdx.json

```

### 3. Edit Specific Component

In whole examples, we will take a component `github.com/fluxcd/pkg/oci` and version `v0.45.0`

```bash
sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --author "Stefan Prodan (stefan@fluxcd.io)" samples/test/edit/in-complete-sbom.spdx.json -o append-comp-author-sbom.spdx.json --append

sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --author "Stefan Prodan (stefan@fluxcd.io)"  samples/test/edit/in-complete-sbom.cdx.json -o append-comp-author-sbom.cdx.json --append
```

- Similarly for other fields:

```bash
# supplier
sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --supplier "Flux (https://fluxcd.io)"  samples/test/edit/in-complete-sbom.spdx.json -o append-comp-supplier-sbom.spdx.json --append

sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --supplier "Flux (https://fluxcd.io)"  samples/test/edit/in-complete-sbom.cdx.json -o append-comp-supplier-sbom.cdx.json --append

# license
sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --license "Apache-2.0" samples/test/edit/in-complete-sbom.spdx.json -o append-comp-license-sbom.spdx.json

sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --license "Apache-2.0" samples/test/edit/in-complete-sbom.cdx.json -o append-comp-license-sbom.cdx.json

# copyright
sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --copyright "Copyright 2025, the FluxCD project" samples/test/edit/in-complete-sbom.spdx.json -o append-comp-copyright-sbom.spdx.json

sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --copyright "Copyright 2025, the FluxCD project" samples/test/edit/in-complete-sbom.cdx.json -o append-comp-copyright-sbom.cdx.json

# description
sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --description "The OCI package provides utilities for working with OCI images and registries." samples/test/edit/in-complete-sbom.spdx.json -o append-comp-description-sbom.spdx.json

sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --description "The OCI package provides utilities for working with OCI images and registries." samples/test/edit/in-complete-sbom.cdx.json -o append-comp-description-sbom.cdx.json

# repository
sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --repository "https://github.com/fluxcd/pkg/oci" samples/test/edit/in-complete-sbom.spdx.json -o append-comp-repository-sbom.spdx.json

sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --repository "https://github.com/fluxcd/pkg/oci" samples/test/edit/in-complete-sbom.cdx.json -o append-comp-repository-sbom.cdx.json

# type
sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --type "library" samples/test/edit/in-complete-sbom.spdx.json -o append-comp-type-sbom.spdx.json

sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --type "library" samples/test/edit/in-complete-sbom.cdx.json -o append-comp-type-sbom.cdx.json
```

## SPDX 3.0 Examples

### 1. Edit Document (SPDX 3.0)

```bash
# Append author to the document
sbomasm edit --subject document --author "Interlynk (hello@interlynk.io)" samples/test/edit/in-complete-sbom.spdx3.json -o append-author-sbom.spdx3.json --append

# Add lifecycle
sbomasm edit --subject document --lifecycle "build" samples/test/edit/in-complete-sbom.spdx3.json -o append-lifecycle-sbom.spdx3.json

# Add tools and timestamp
sbomasm edit --subject document --tool "sbomasm-test (v1.0.0)" --timestamp samples/test/edit/in-complete-sbom.spdx3.json -o append-tool-sbom.spdx3.json
```

### 2. Edit Primary Component (SPDX 3.0)

```bash
# Update name, version, and description
sbomasm edit --subject primary-component --name "kyverno-renamed" --version "v2.0.0" --description "Test description" samples/test/edit/in-complete-sbom.spdx3.json -o edit-pc-sbom.spdx3.json

# Update supplier (creates new Organization, preserves old one)
sbomasm edit --subject primary-component --supplier "Kyverno (https://kyverno.io)" samples/test/edit/in-complete-sbom.spdx3.json -o edit-pc-supplier-sbom.spdx3.json

# Update license (creates hasConcludedLicense relationship + LicenseExpression)
sbomasm edit --subject primary-component --license "Apache-2.0" samples/test/edit/in-complete-sbom.spdx3.json -o edit-pc-license-sbom.spdx3.json

# Append hash
sbomasm edit --subject primary-component --hash "MD5 (d41d8cd98f00b204e9800998ecf8427e)" samples/test/edit/in-complete-sbom.spdx3.json -o append-pc-hash-sbom.spdx3.json --append
```

### 3. Edit Specific Component (SPDX 3.0)

```bash
# Update name and supplier
sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --name "fluxcd-renamed" --supplier "Flux (https://fluxcd.io)" samples/test/edit/in-complete-sbom.spdx3.json -o edit-comp-sbom.spdx3.json

# Update repository and type
sbomasm edit --subject component-name-version --search "github.com/fluxcd/pkg/oci (v0.45.0)" --repository "https://github.com/fluxcd/pkg/oci" --type "library" samples/test/edit/in-complete-sbom.spdx3.json -o edit-comp-repo-sbom.spdx3.json
```
