# Edit Command

The `edit` command modifies existing SBOMs by adding, updating, or filling in missing metadata. This is essential for compliance, completeness, and maintaining accurate software supply chain information.

## Overview

`sbomasm edit` allows you to:

- Add missing metadata required for compliance
- Update incorrect or outdated information
- Append additional authors, tools, or licenses
- Search and modify specific components
- Batch process multiple SBOMs

Supported formats: **SPDX 2.3**, **SPDX 3.0** (JSON-LD), and **CycloneDX**.
See [Field Mapping](#field-mapping) below for the exact SPDX 3.0 and CycloneDX fields that each option modifies.

## Basic Usage

```bash
sbomasm edit --subject <target> [options] <input-sbom>
```

## Command Options

### Subject Selection (Required)

- `--subject <target>`: What to edit
  - `document`: Edit SBOM document metadata
  - `primary-component`: Edit the main component described by the SBOM
  - `component-name-version`: Search and edit a specific component

### Search Options

- `--search "<name> (<version>)"`: Find component by name and version (required for `component-name-version` subject)

### Operation Modes

- `--append`: Add to existing values (e.g., add another author)
- `--missing`: Only add if the field is currently empty
- (default): Overwrite existing values

### Output Options

- `--output <path>`: Output file path (default: prints to stdout)
- `-o <path>`: Short form of --output

### Metadata Fields

#### Common Fields

- `--name <string>`: Component/document name
- `--version <string>`: Version identifier
- `--type <string>`: Component type (application, library, framework, etc.)
- `--description <string>`: Detailed description
- `--supplier "<name> (<url>)"`: Supplier information
- `--timestamp`: Add current timestamp
- `--copyright <string>`: Copyright text

#### Multiple Values (can be repeated)

- `--author "<name> (<email>)"`: Author information
- `--tool "<name> (<version>)"`: Tool that created/modified the SBOM
- `--license "<id> (<url>)"`: License information
- `--hash "<algorithm> (<value>)"`: Checksum/hash values
- `--lifecycle <phase>`: Lifecycle phase (build, deploy, runtime, etc.)

#### Component Identifiers

- `--purl <string>`: Package URL (purl)
- `--cpe <string>`: Common Platform Enumeration identifier
- `--repository <url>`: Source repository URL

#### SPDX 3.0 Specific Notes

When editing **SPDX 3.0** JSON-LD SBOMs, the command automatically manages the
flat `@graph` element structure:

- **Author / Supplier / Tool**: Creates separate `Person`, `Organization`, or
  `Tool` elements in the `@graph` and links them via `CreationInfo.createdBy`
  or `createdUsing`. Email addresses are stored as `externalIdentifier[type=email]`;
  URLs as `externalRef[type=other]` (SPDX 3.0 `Organization` has no direct URL field).
- **License**: Creates a `simplelicensing_LicenseExpression` element and links
  it via a `hasConcludedLicense` relationship. Overwriting a license removes
  the orphaned expression from the `@graph`.
- **Type**: Maps CLI-friendly names (`application`, `library`, `container`, …)
  to SPDX 3.0 `SoftwarePurpose` enum values (e.g., `operatingSystem`).
- **Hash**: Stored in `verifiedUsing[]` as typed `Hash` elements with lowercase
  algorithm names (`sha256`, `md5`, …). Append mode deduplicates by
  algorithm + hash value.
- **Repository**: Both document-level and component-level repository URLs are
  stored as `externalRef[type=vcs]`, not `downloadLocation`. This aligns with
  SPDX 3.0 semantics and allows multiple repository URLs per component via
  `--append`.

## Edit Targets

### Document Metadata

Edit top-level SBOM metadata:

```bash
# Add missing document metadata
sbomasm edit \
  --subject document \
  --missing \
  --supplier "ACME Corp (acme.com)" \
  --author "Security Team (security@acme.com)" \
  --timestamp \
  input.json -o output.json

# Overwrite document info
sbomasm edit \
  --subject document \
  --tool "sbomasm (v0.1.0)" \
  --license "Apache-2.0 (apache.org/licenses/)" \
  input.json -o output.json
```

### Primary Component

Edit the main component described by the SBOM:

```bash
# Update primary component version
sbomasm edit \
  --subject primary-component \
  --version "2.1.0" \
  --type "application" \
  input.json -o output.json

# Add identifiers to primary component
sbomasm edit \
  --subject primary-component \
  --purl "pkg:generic/my-app@2.1.0" \
  --cpe "cpe:2.3:a:company:my-app:2.1.0:*:*:*:*:*:*:*" \
  input.json -o output.json
```

### Specific Components

Search and edit components by name and version:

```bash
# Update a specific component's license
sbomasm edit \
  --subject component-name-version \
  --search "lodash (4.17.21)" \
  --license "MIT (mit-license.org)" \
  input.json -o output.json

# Add missing purl to a component
sbomasm edit \
  --subject component-name-version \
  --search "spring-boot (2.7.0)" \
  --missing \
  --purl "pkg:maven/org.springframework.boot/spring-boot@2.7.0" \
  input.json -o output.json
```

## Operation Modes

### Overwrite Mode (Default)

Replaces existing values:

```bash
# Replace existing supplier
sbomasm edit \
  --subject document \
  --supplier "New Corp (newcorp.com)" \
  input.json -o output.json
```

### Append Mode

Adds to existing values. Only fields that are natively multi-valued in a format
support `--append`; using `--append` on a single-value field prints a warning
and skips the mutation so existing data is preserved.

#### Appendable Fields by Format

| Field | SPDX 2.3 | SPDX 3.0 | CycloneDX | Notes |
|-------|----------|----------|-----------|-------|
| `--author` | ✅ Append | ✅ Append | ✅ Append | Multi-value in all formats |
| `--tool` | ✅ Append | ✅ Append | ✅ Append | Multi-value in all formats |
| `--hash` | ✅ Append | ✅ Append | ✅ Append | Deduplicated by algorithm+value |
| `--lifecycle` | ✅ Append | ✅ Append | ✅ Append | Multi-value in all formats |
| `--license` | ❌ Overwrite | ❌ Overwrite | ✅ Append | SPDX: single concluded license |
| `--purl` | ✅ Append | ✅ Append | ❌ Overwrite | CDX: single purl per component |
| `--cpe` | ✅ Append | ✅ Append | ❌ Overwrite | CDX: single cpe per component |
| `--repository` | ❌ Overwrite | ✅ Append | ✅ Append | SPDX 2.3: single downloadLocation |
| `--name` | ❌ Overwrite | ❌ Overwrite | ❌ Overwrite | Single-value field |
| `--version` | ❌ Overwrite | ❌ Overwrite | ❌ Overwrite | Single-value field |
| `--type` | ❌ Overwrite | ❌ Overwrite | ❌ Overwrite | Single-value field |
| `--description` | ❌ Overwrite | ❌ Overwrite | ❌ Overwrite | Single-value field |
| `--copyright` | ❌ Overwrite | ❌ Overwrite | ❌ Overwrite | Single-value field |
| `--supplier` | ❌ Overwrite | ❌ Overwrite | ❌ Overwrite | Single-value field |
| `--timestamp` | ❌ Overwrite | ❌ Overwrite | ❌ Overwrite | Single-value field |

**Key:**
- **Append** — `--append` adds the new value alongside existing values
- **Overwrite** — `--append` is ignored; a warning is printed and the field is left unchanged. Use overwrite (default) or `--missing` instead.

```bash
# Add another author without removing existing ones
sbomasm edit \
  --append \
  --subject document \
  --author "Jane Doe (jane@company.com)" \
  input.json -o output.json

# Add additional tool
sbomasm edit \
  --append \
  --subject document \
  --tool "scanner (v2.0.0)" \
  input.json -o output.json
```

### Missing Mode

Only adds values if the field is currently empty:

```bash
# Add supplier only if missing
sbomasm edit \
  --missing \
  --subject document \
  --supplier "Default Corp (default.com)" \
  input.json -o output.json

# Add multiple missing fields
sbomasm edit \
  --missing \
  --subject primary-component \
  --version "1.0.0" \
  --type "application" \
  --purl "pkg:generic/app@1.0.0" \
  input.json -o output.json
```

## Field Format Reference

### Author Format

```bash
--author "Name (email@domain.com)"
--author "John Doe (john@example.com)"
```

### Supplier Format

```bash
--supplier "Company Name (website.com)"
--supplier "ACME Corp (https://acme.com)"
```

### Tool Format

```bash
--tool "Tool Name (version)"
--tool "syft (0.98.0)"
```

### License Format

```bash
--license "License-ID (optional-url)"
--license "Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)"
--license "MIT"
```

### Hash Format

```bash
--hash "Algorithm (value)"
--hash "SHA256 (abc123...)"
--hash "MD5 (def456...)"
```

## Examples

### Compliance Preparation

Prepare SBOM for regulatory submission:

```bash
# Add all required FDA fields
sbomasm edit \
  --subject document \
  --supplier "MedDevice Inc (meddevice.com)" \
  --author "Regulatory Team (regulatory@meddevice.com)" \
  --tool "sbomasm (v0.1.0)" \
  --timestamp \
  device-sbom.json -o fda-compliant.json

# Update primary component with device info
sbomasm edit \
  --subject primary-component \
  --name "MRI-Controller" \
  --version "3.2.0-FDA" \
  --type "device" \
  --description "MRI Scanner Control Software" \
  fda-compliant.json -o final-submission.json
```

### SPDX 3.0 Compliance Enrichment

SPDX 3.0 SBOMs use a flat JSON-LD `@graph` structure. The edit command
automatically creates and links the required element types:

```bash
# Add document metadata (creates Person + Tool elements in @graph)
sbomasm edit \
  --subject document \
  --author "Security Team (security@example.com)" \
  --tool "sbomasm (v0.1.0)" \
  --license "Apache-2.0" \
  --timestamp \
  in.spdx3.json -o enriched.spdx3.json

# Add component identifiers (stored as externalIdentifier + verifiedUsing)
sbomasm edit \
  --subject primary-component \
  --purl "pkg:golang/github.com/example/app@v1.0.0" \
  --hash "SHA256 (e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)" \
  enriched.spdx3.json -o final.spdx3.json
```

### Batch Processing

Process multiple SBOMs with consistent metadata:

```bash
#!/bin/bash
# batch-edit.sh

SUPPLIER="GlobalCorp (globalcorp.com)"
AUTHOR="Security Team (security@globalcorp.com)"

for sbom in input/*.json; do
  filename=$(basename "$sbom")
  sbomasm edit \
    --missing \
    --subject document \
    --supplier "$SUPPLIER" \
    --author "$AUTHOR" \
    --timestamp \
    "$sbom" \
    -o "output/$filename"
done
```

### Component License Updates

Fix missing or incorrect license information:

```bash
# Update all Apache components
components=("commons-io (2.11.0)" "commons-lang3 (3.12.0)" "log4j (2.17.1)")

for comp in "${components[@]}"; do
  sbomasm edit \
    --subject component-name-version \
    --search "$comp" \
    --license "Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)" \
    input.json -o input.json
done
```

### CI/CD Integration

Automated SBOM enrichment in pipeline:

```bash
#!/bin/bash
# ci-edit.sh

# Get build information
VERSION="${CI_COMMIT_TAG:-${CI_COMMIT_SHA:0:7}}"
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Edit SBOM with CI information
sbomasm edit \
  --subject primary-component \
  --version "$VERSION" \
  --repository "$CI_PROJECT_URL" \
  input-sbom.json -o enriched-sbom.json

# Add build metadata
sbomasm edit \
  --subject document \
  --tool "GitLab CI ($CI_PIPELINE_ID)" \
  --author "$CI_COMMIT_AUTHOR" \
  --timestamp \
  enriched-sbom.json -o final-sbom.json
```

## Field Mapping

### CycloneDX Field Mapping

| Parameter | CycloneDX Location |
|-----------|-------------------|
| Document author | metadata.authors |
| Document supplier | metadata.supplier |
| Document tool | metadata.tools |
| Document license | metadata.licenses |
| Component name | component.name |
| Component version | component.version |
| Component type | component.type |
| Component purl | component.purl |
| Component cpe | component.cpe |
| Component licenses | component.licenses |

> See [Append Mode](#append-mode) for which fields support `--append` in CycloneDX.

### SPDX 2.3 Field Mapping

| Parameter | SPDX 2.3 Location |
|-----------|-------------------|
| Document author | creationInfo.creators |
| Document supplier | creationInfo.comment |
| Document tool | creationInfo.creators |
| Document license | dataLicense |
| Component name | package.name |
| Component version | package.versionInfo |
| Component type | package.primaryPackagePurpose |
| Component purl | package.externalRefs[packageManager] |
| Component cpe | package.externalRefs[security] |
| Component licenses | package.licenseConcluded |

> See [Append Mode](#append-mode) for which fields support `--append` in SPDX 2.3.

### SPDX 3.0 Field Mapping

SPDX 3.0 uses a JSON-LD flat `@graph` structure where metadata is stored as
separate typed elements linked by reference. The edit command creates or
reuses these elements automatically.

| Parameter | SPDX 3.0 Target | Notes |
|-----------|-----------------|-------|
| **Document-level** | | |
| `--author` | `CreationInfo.createdBy` (adds `Person` element) | Person created with `externalIdentifier[type=email]` |
| `--supplier` | `CreationInfo.createdBy` (adds `Organization` element) | Organization created with `externalIdentifier[type=email]` and/or `externalRef[type=other]` |
| `--tool` | `CreationInfo.createdUsing` (adds `Tool` element) | Tool element created or reused |
| `--license` | `SpdxDocument.dataLicense` (adds `LicenseExpression` element) | Creates `simplelicensing_LicenseExpression` |
| `--timestamp` | `CreationInfo.created` | ISO-8601 timestamp |
| `--repository` | `SpdxDocument.externalRef[type=vcs]` | VCS URL stored as external reference |
| `--lifecycle` | `CreationInfo.comment` (appends `lifecycle: …`) | Preserves existing comment content |
| **Component-level** | | |
| `--name` | `software_Package.name` | |
| `--version` | `software_Package.software_packageVersion` | |
| `--type` | `software_Package.software_primaryPurpose` | Maps CLI value to SPDX 3.0 `SoftwarePurpose` enum |
| `--description` | `software_Package.description` | |
| `--supplier` | `software_Package.software_suppliedBy` (refs `Organization`) | Creates Organization element; URL via `externalRef[type=other]` |
| `--copyright` | `software_Package.software_copyrightText` | |
| `--purl` | `software_Package.externalIdentifier[type=packageUrl]` | |
| `--cpe` | `software_Package.externalIdentifier[type=cpe23]` | |
| `--hash` | `software_Package.verifiedUsing[]` (`Hash` elements) | Algorithm normalised to lowercase (`sha256`, `md5`, etc.) |
| `--repository` | `software_Package.externalRef[type=vcs]` | VCS URL stored as external reference; supports multiple repos via `--append` |
| `--license` | `hasConcludedLicense` relationship → `LicenseExpression` | Creates `simplelicensing_LicenseExpression` element; replaces existing relationship |

> **Note:** In SPDX 3.0, document-level author and supplier both go into
> `CreationInfo.createdBy`. The edit command creates new `Person` or
> `Organization` elements in the `@graph` and adds their SpdxIDs to
> `createdBy`. Similarly, `--tool` creates or reuses `Tool` elements and
> adds them to `createdUsing`.
>
> When overwriting a component license, the old `LicenseExpression`
> element is automatically removed from the `@graph` if it is no longer
> referenced. Append mode deduplicates hashes by algorithm+value.
>
> See [Append Mode](#append-mode) for a complete table of which fields
> support `--append` in each format.

## Best Practices

1. **Use Missing Mode for Defaults**: When adding default values, use `--missing` to avoid overwriting existing data
2. **Validate After Editing**: Always validate edited SBOMs with tools like `sbomqs`
3. **Maintain Edit History**: Use `--append` with `--tool` to track edit history
4. **Batch Similar Edits**: Group similar edits together for efficiency
5. **Test Search Patterns**: Verify component searches return expected results before editing

## Troubleshooting

### Component Not Found

```bash
# List all components first
sbomasm edit --subject document input.json | jq '.components[].name'

# Use exact name and version
sbomasm edit \
  --subject component-name-version \
  --search "exact-name (exact-version)" \
  --license "MIT" \
  input.json
```

### Format Issues

```bash
# Ensure proper format for compound fields
# Correct:
--author "John Doe (john@example.com)"

# Incorrect:
--author "John Doe" --email "john@example.com"
```

### SPDX 3.0 Specifics

```bash
# SPDX 3.0 uses a flat @graph — components are linked by SpdxID references.
# To inspect the @graph after editing:
jq '."@graph"[] | select(.type == "software_Package") | {name, spdxId}' output.spdx3.json

# Or view document-level metadata (CreationInfo, SpdxDocument):
jq '."@graph"[] | select(.type == "SpdxDocument")' output.spdx3.json
```

### Multiple Edits

```bash
# Chain multiple edits
sbomasm edit --subject document --supplier "Corp A" input.json -o temp.json
sbomasm edit --subject primary-component --version "2.0" temp.json -o final.json
```

## See Also

- [Assemble Command](assemble.md) - Merge multiple SBOMs
- [Remove Command](remove.md) - Remove components or fields
- [Generate Command](generate.md) - Create configuration templates