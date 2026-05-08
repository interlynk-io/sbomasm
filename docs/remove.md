# sbomasm remove command

This command is designed to support the following primary use cases:

- **Field Removal**: removal of specific fields from document metadata or components
- **Component Removal**: removal of entire components and their associated dependency links
- **Dependency Removal**: removal of dependency relationships *(not yet supported)*

## Why Common Field Method?

We initially considered two approaches for field removal:

- **Schema-Based Removal**: where users specify exact schema paths (e.g., `CreationInfo->Creator->Person` for SPDX).
- **Common Fields-Based Removal**: where users simply target common fields (e.g., `author`, `license`, `repository`, `purl`, `cpe`, `supplier`, etc).

We decided to proceed with the **common field-based** method for the following reasons:

- No need to know full JSON paths of fields located in SPDX and CycloneDX.
- Compatible across SPDX and CycloneDX.
- Focuses on high-level user intent instead of internal SBOM layout.

## sbomasm implementation

### 1. Field Removal

Removes specific fields from the document metadata or from components.

#### Common fields supported for document scope

| Field         | SPDX                                    | CycloneDX                          |
|---------------|-----------------------------------------|------------------------------------|
| `author`      | `creationInfo.creators` (Person type)   | `metadata.authors`                 |
| `supplier`    | `creationInfo.creators` (Organization)  | `metadata.supplier`                |
| `tool`        | `creationInfo.creators` (Tool type)     | `metadata.tools`                   |
| `lifecycle`   | *(custom extension)*                    | `metadata.lifecycles`              |
| `license`     | `dataLicense`                           | `metadata.licenses`                |
| `repository`  | *(not applicable)*                      | `metadata.component.externalRefs`  |
| `timestamp`   | `creationInfo.created`                  | `metadata.timestamp`               |

#### Common fields supported for component scope

| Field         | SPDX                    | CycloneDX              |
|---------------|-------------------------|------------------------|
| `author`      | `originator`            | `authors`              |
| `copyright`   | `copyrightText`         | `copyright`            |
| `cpe`         | `externalRefs` (cpe23)  | `cpe`                  |
| `group`       | *(not applicable)*      | `group`                |
| `hash`        | `packageChecksums` / checksums | `hashes`  |
| `license`     | `licenseDeclared`       | `licenses`             |
| `publisher`   | *(not applicable)*      | `publisher`            |
| `purl`        | `externalRefs` (purl)   | `purl`                 |
| `repository`  | `externalRefs` (vcs)    | `externalReferences`   |
| `supplier`    | `packageSupplier`       | `supplier`             |
| `type`        | `primaryPackagePurpose` | `type`                 |

#### Syntax

```bash
sbomasm rm --field <field> --scope <document|component> [--value <value>] [--name <component-name>] [--version <component-version>] [--all] [input-sbom] [-o output-sbom]
```

#### Examples on "Field Removal from document"

Remove all authors from the document:

```bash
sbomasm rm --field author --scope document input.spdx.json -o output.spdx.json
sbomasm rm --field author --scope document input.cdx.json -o output.cdx.json
```

Remove only the author entry containing `hello@interlynk.io`:

```bash
sbomasm rm --field author --value "hello@interlynk.io" --scope document input.spdx.json -o output.spdx.json
sbomasm rm --field author --value "hello@interlynk.io" --scope document input.cdx.json -o output.cdx.json
```

Remove license from the document:

```bash
sbomasm rm --field license --scope document input.spdx.json -o output.spdx.json
sbomasm rm --field license --scope document input.cdx.json -o output.cdx.json
```

Remove a specific license by value:

```bash
sbomasm rm --field license --value "CC0-1.0" --scope document input.spdx.json -o output.spdx.json
```

Remove lifecycle from the document:

```bash
sbomasm rm --field lifecycle --scope document input.spdx.json -o output.spdx.json
sbomasm rm --field lifecycle --value "design" --scope document input.cdx.json -o output.cdx.json
```

Remove tool from the document:

```bash
sbomasm rm --field tool --scope document input.spdx.json -o output.spdx.json
sbomasm rm --field tool --value "cyclonedx-gomod" --scope document input.cdx.json -o output.cdx.json
```

Remove supplier from the document:

```bash
sbomasm rm --field supplier --scope document input.spdx.json -o output.spdx.json
sbomasm rm --field supplier --value "Acme, Inc (https://github.com/acme)" --scope document input.spdx.json -o output.spdx.json
```

Remove repository from the document *(CycloneDX only; SPDX does not have this field)*:

```bash
sbomasm rm --field repository --scope document input.cdx.json -o output.cdx.json
sbomasm rm --field repository --value "https://kyverno.io/" --scope document input.cdx.json -o output.cdx.json
```

**NOTE**: Currently, `--key` is accepted but filtering by key name alone is not supported for key-value pair fields. Only `--value` filtering is effective. For example, given:

```json
"authors": [
  { "name": "Interlynk", "email": "hello@interlynk.io" },
  { "name": "VulnCon",   "email": "vulncon@sbom.dev"   }
]
```

Using `--value "Interlynk"` (a key name, not a value) will not match. Use the actual value: `--value "hello@interlynk.io"`.

#### Example on "Field Removal from a specific component"

Requires both `--name` and `--version` to identify the target component.

Remove `purl` from a specific component:

```bash
sbomasm rm --field purl --scope component --name "nginx" --version "v1.21.0" input.spdx.json -o output.spdx.json
sbomasm rm --field purl --scope component --name "nginx" --version "v1.21.0" input.cdx.json -o output.cdx.json
```

Remove `license` from a specific component:

```bash
sbomasm rm --field license --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" input.spdx.json -o output.spdx.json
sbomasm rm --field license --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" input.cdx.json -o output.cdx.json
```

Remove a specific `license` value from a component:

```bash
sbomasm rm --field license --value "Apache-2.0" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" input.spdx.json -o output.spdx.json
```

Remove `cpe` from a specific component:

```bash
sbomasm rm --field cpe --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" input.spdx.json -o output.spdx.json
```

Remove `hash` from a specific component:

```bash
sbomasm rm --field hash --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" input.spdx.json -o output.spdx.json
```

Remove a specific `hash` value from a component:

```bash
sbomasm rm --field hash --value "94fb71aaacc3385dd3018c7e63dd6750b1622f382613c5c31edfee67006ac78e" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" input.spdx.json -o output.spdx.json
```

Remove `supplier` from a specific component:

```bash
sbomasm rm --field supplier --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" input.spdx.json -o output.spdx.json
```

Remove supplier by partial value (substring match):

```bash
sbomasm rm --field supplier --value "Flux" --scope component --name "github.com/fluxcd/pkg/oci" --version "v0.45.0" input.spdx.json -o output.spdx.json
```

#### Example on "Field Removal from all components"

Use `-a` (or `--all`) instead of `--name` and `--version` to apply to every component.

Remove `purl` from all components:

```bash
sbomasm rm --field purl --scope component -a input.spdx.json -o output.spdx.json
sbomasm rm --field purl --scope component -a input.cdx.json -o output.cdx.json
```

Remove a specific `license` value from all components:

```bash
sbomasm rm --field license --value "Apache-2.0" --scope component -a input.spdx.json -o output.spdx.json
```

Remove `supplier` having a specific value from all components:

```bash
sbomasm rm --field supplier --value "Azure (https://azure.microsoft.com)" --scope component -a input.cdx.json -o output.cdx.json
```

Remove a specific `purl` value from all components:

```bash
sbomasm rm --field purl --value "pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.17.0" --scope component -a input.spdx.json -o output.spdx.json
```

### 2. Component Removal

Removes entire components and their associated dependency links.

#### Syntax

```bash
sbomasm rm --components [--name <component-name> --version <component-version>] [--field <field>] [--value <value>] [input-sbom] [-o output-sbom]
```

#### Remove a specific component by name and version

```bash
sbomasm rm --components --name "nginx" --version "v1.21.0" input.spdx.json -o output.spdx.json
sbomasm rm --components --name "nginx" --version "v1.21.0" input.cdx.json -o output.cdx.json
```

This also removes all dependency relationships linked to the removed component.

#### Remove all components where a field is present

Removes every component that has the specified field set (non-empty):

```bash
# Remove all components that have an author field
sbomasm rm --components --field author input.spdx.json -o output.spdx.json
sbomasm rm --components --field author input.cdx.json -o output.cdx.json

# Remove all components that have a purl
sbomasm rm --components --field purl input.spdx.json -o output.spdx.json

# Remove all components that have a cpe
sbomasm rm --components --field cpe input.cdx.json -o output.cdx.json

# Remove all components that have a license
sbomasm rm --components --field license input.spdx.json -o output.spdx.json

# Remove all components that have a supplier
sbomasm rm --components --field supplier input.spdx.json -o output.spdx.json

# Remove all components that have a hash
sbomasm rm --components --field hash input.cdx.json -o output.cdx.json

# Remove all components that have a repository
sbomasm rm --components --field repository input.spdx.json -o output.spdx.json
```

#### Remove all components where a field matches a specific value

Removes every component whose specified field contains the given value (substring match):

```bash
# Remove all components with license "Apache-2.0"
sbomasm rm --components --field license --value "Apache-2.0" input.spdx.json -o output.spdx.json
sbomasm rm --components --field license --value "Apache-2.0" input.cdx.json -o output.cdx.json

# Remove all components with a specific purl
sbomasm rm --components --field purl --value "pkg:golang/github.com/sigstore/rekor@v1.3.9?type=module" input.spdx.json -o output.spdx.json

# Remove all components authored by a specific person (partial name match)
sbomasm rm --components --field author --value "dan@sigstore.dev" input.spdx.json -o output.spdx.json
sbomasm rm --components --field author --value "Dan" input.cdx.json -o output.cdx.json

# Remove all components with a specific copyright
sbomasm rm --components --field copyright --value "Copyright 2025, the Kyverno project" input.spdx.json -o output.spdx.json

# Remove all components with a specific supplier
sbomasm rm --components --field supplier --value "Sigstore (https://sigstore.dev)" input.spdx.json -o output.spdx.json
sbomasm rm --components --field supplier --value "Sigstore" input.cdx.json -o output.cdx.json

# Remove all components with a specific hash value
sbomasm rm --components --field hash --value "b148d1a4a561fe1860a8632cd2df93b9b818b24b00ad9ea9a0b102dccb060335" input.spdx.json -o output.spdx.json

# Remove all components with a specific repository
sbomasm rm --components --field repository --value "https://github.com/sigstore/rekor" input.spdx.json -o output.spdx.json

# Remove all components of type "library"
sbomasm rm --components --field type --value "library" input.spdx.json -o output.spdx.json
sbomasm rm --components --field type --value "library" input.cdx.json -o output.cdx.json
```

### 3. Dependency Removal (Not yet supported)

Remove a dependency edge and optionally the target component.

#### Syntax

```bash
sbomasm rm --dependency --id <purl>
```

#### Example

```bash
sbomasm rm --dependency --id "pkg:golang/sigs.k8s.io/structured-merge-diff/v4@v4.6.0?type=module"
```

## Optional Flags

| Flag          | Short | Purpose                                              |
|---------------|-------|------------------------------------------------------|
| `--dry-run`   |       | Preview what would be removed without making changes |
| `--summary`   |       | Print a list of matched entries instead of removing  |
| `--output`    | `-o`  | Write the modified SBOM to the specified file        |
| `--all`       | `-a`  | Apply field removal to all components                |
| `--debug`     |       | Enable verbose debug logging                         |

## Pattern Matching

Value filtering uses **substring matching** via `strings.Contains()`. This means:

- `--value "Apache"` matches `"Apache-2.0"`, `"Apache-1.1"`, `"LicenseRef-Apache"`, etc.
- `--value "dan@sigstore.dev"` matches any field value that contains that string.
- `--value "pkg:golang/github.com/fluxcd/pkg/oci@v0.45.0"` matches PURLs containing that substring.

Name and version matching (for `--name` / `--version`) uses **case-insensitive exact matching** via `strings.EqualFold()`.

**There is no wildcard or regex support.** Patterns like `test-*` or `internal-[0-9]+` will be treated as literal strings.

Field values of `NOASSERTION` are treated as empty and will not match any `--value` filter.

## Safety Features

### Dry Run

Preview which entries would be removed without modifying the SBOM:

```bash
sbomasm rm --dry-run --field license --scope component -a input.spdx.json
sbomasm rm --dry-run --components --field purl --value "pkg:golang/..." input.cdx.json
```

### Summary Mode

Print a summary of matched entries without applying the removal:

```bash
sbomasm rm --summary --field purl --scope component -a input.spdx.json
sbomasm rm --summary --components --field license --value "Apache-2.0" input.cdx.json
```

Use `--dry-run` and `--summary` together to inspect the scope of changes before committing them.

## Batch Processing

### Remove a field from multiple SBOMs

```bash
#!/bin/bash
for sbom in sboms/*.json; do
  output="cleaned/$(basename "$sbom")"
  sbomasm rm --field purl --scope component -a "$sbom" -o "$output"
  echo "Cleaned: $output"
done
```

### Chain multiple removal operations

Since each invocation writes to a file, chain them using intermediate outputs:

```bash
# Step 1: Remove all author fields from document metadata
sbomasm rm --field author --scope document input.cdx.json -o step1.cdx.json

# Step 2: Remove all supplier fields from components
sbomasm rm --field supplier --scope component -a step1.cdx.json -o step2.cdx.json

# Step 3: Remove all components with a specific license
sbomasm rm --components --field license --value "GPL-3.0" step2.cdx.json -o final.cdx.json
```

### CI/CD pipeline integration

```bash
#!/bin/bash
# ci-clean.sh — strip internal metadata before publishing the SBOM

# Remove internal author info
sbomasm rm --field author --scope document "$INPUT_SBOM" -o step1.json

# Remove repository references from all components
sbomasm rm --field repository --scope component -a step1.json -o step2.json

# Remove components matching an internal supplier
sbomasm rm --components --field supplier --value "Internal Team" step2.json -o "$OUTPUT_SBOM"

echo "Published SBOM written to $OUTPUT_SBOM"
```

## Best Practices

1. **Use `--dry-run` first**: Always preview removals before applying them, especially with broad `--all` or field-only component removals.
2. **Use `--summary` for auditing**: Confirm which components or fields will be affected before modifying the SBOM.
3. **Keep originals**: Back up your SBOM files before running bulk removals.
4. **Be precise with values**: Since matching is substring-based, overly short values (e.g., `"lib"`) may match more than intended.
5. **Validate after removal**: Check that the resulting SBOM is still valid using a tool like `sbomqs`.

## Field Reference

### Field availability by scope

| Field         | Document scope | Component scope |
|---------------|:--------------:|:---------------:|
| `author`      | ✓              | ✓               |
| `copyright`   |                | ✓               |
| `cpe`         |                | ✓               |
| `group`       |                | ✓ (CDX only)    |
| `hash`        |                | ✓               |
| `license`     | ✓              | ✓               |
| `lifecycle`   | ✓              |                 |
| `publisher`   |                | ✓ (CDX only)    |
| `purl`        |                | ✓               |
| `repository`  | ✓ (CDX only)   | ✓               |
| `supplier`    | ✓              | ✓               |
| `timestamp`   | ✓              |                 |
| `tool`        | ✓              |                 |
| `type`        |                | ✓               |

### Format-specific behavior

| Format    | Author removal                                   | Supplier removal                    |
|-----------|--------------------------------------------------|-------------------------------------|
| SPDX      | Removes `Person:` entries from `creationInfo.creators` | Removes `Organization:` entries from `creationInfo.creators` |
| CycloneDX | Removes entries from `metadata.authors`          | Removes `metadata.supplier`         |

| Format    | Component removal                                    |
|-----------|------------------------------------------------------|
| SPDX      | Removes packages and updates the relationships array |
| CycloneDX | Removes from `components` array and updates `dependencies` |

### Flags quick reference

| Flag          | Short | Type     | Description                                      |
|---------------|-------|----------|--------------------------------------------------|
| `--field`     | `-f`  | string   | Field to remove                                  |
| `--scope`     | `-s`  | string   | Scope: `document` or `component`                 |
| `--value`     | `-v`  | string   | Filter by value (substring match)                |
| `--key`       | `-k`  | string   | Filter by key *(limited support)*                |
| `--all`       | `-a`  | bool     | Apply to all components (field removal)          |
| `--components`| `-c`  | bool     | Enable component removal mode                    |
| `--name`      | `-n`  | string   | Component name (exact, case-insensitive)         |
| `--version`   |       | string   | Component version (exact, case-insensitive)      |
| `--dependency`|       | bool     | Enable dependency removal *(not yet supported)*  |
| `--id`        |       | string   | Dependency PURL to remove *(not yet supported)*  |
| `--dry-run`   |       | bool     | Preview changes without applying them            |
| `--summary`   |       | bool     | Print matched entries without removing           |
| `--output`    | `-o`  | string   | Output file path                                 |
| `--debug`     |       | bool     | Enable debug logging                             |

## See Also

[Test samples and full worked examples](../samples/test/remove/README.md), complete set of test cases covering every supported removal scenario with real SBOM files.