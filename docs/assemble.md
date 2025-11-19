# Assemble Command

The `assemble` command merges multiple SBOMs into a single comprehensive SBOM document. This is essential for creating unified views of complex software systems composed of multiple components.

## Overview

`sbomasm assemble` combines SBOMs from different sources while:
- Preserving component relationships
- Managing duplicate components (based on merge algorithm)
- Creating proper metadata for the assembled SBOM
- Supporting both SPDX and CycloneDX formats

## Basic Usage

```bash
sbomasm assemble -n <name> -v <version> -t <type> -o <output> <input-files...>
```

## Command Options

### Required Options

- `-n, --name <string>`: Name of the assembled SBOM's primary component
- `-v, --version <string>`: Version of the assembled SBOM's primary component
- `-o, --output <path>`: Output file path for the assembled SBOM

### Optional Options

- `-t, --type <string>`: Type of the primary component (default: "application")
  - Valid values: `application`, `framework`, `library`, `container`, `operating-system`, `device`, `firmware`, `file`
- `-c, --config <path>`: Path to configuration file (YAML format)
- `--xml`: Output in XML format (default is JSON)
- `-e, --export-version <version>`: Specify output spec version (e.g., "1.4" for CycloneDX)

### Merge Algorithms

- `--flat-merge`: Create a flat list of all components (removes duplicates in CycloneDX)
- `--hierarchical-merge`: Maintain component relationships (default)
- `--assembly-merge`: Similar to hierarchical but treats each SBOM independently
- `--augmentMerge`: Enrich a primary SBOM with additional data from secondary SBOMs

### Debug Options

- `-d, --debug`: Enable debug output for troubleshooting

## Merge Algorithm Details

### Hierarchical Merge (Default)

Maintains the relationship structure between components:
- Each input SBOM's primary component becomes a dependency of the new primary component
- Preserves all component relationships
- Does not remove duplicates in SPDX format

```bash
sbomasm assemble --hierarchical-merge \
  -n "platform" -v "1.0.0" \
  -o platform.json \
  service1.json service2.json
```

### Flat Merge

Creates a flat list of all components:
- Removes all relationships except "describes"
- Removes duplicate components (CycloneDX only)
- Useful for simple component inventories

```bash
sbomasm assemble --flat-merge \
  -n "inventory" -v "2024.01" \
  -o inventory.json \
  component1.json component2.json
```

### Assembly Merge

Treats each SBOM as an independent assembly:
- Similar to hierarchical but doesn't create relationships with the primary component
- Useful when combining independent products

```bash
sbomasm assemble --assembly-merge \
  -n "product-suite" -v "3.0" \
  -o suite.json \
  product1.json product2.json
```

### Augment Merge

Enriches an existing primary SBOM with additional information from secondary SBOMs:
- Does not create a new root component
- Merges matching components based on name, version, purl and CPE
- Adds new components that don't exist in the primary SBOM
- Only includes relationships/dependencies for added or merged components
- Validates all references to ensure data integrity

#### Required Options for Augment Merge

- `--augmentMerge`: Enable augment merge mode
- `--primary <path>`: Path to the primary SBOM to be enriched

#### Optional Options

- `--merge-mode <mode>`: How to merge matching components
  - `if-missing-or-empty` (default): Only fill empty fields in primary components
  - `overwrite`: Replace primary component fields with secondary values

#### Fields Merged by Specification

##### SPDX Package Fields

When components match, the following SPDX package fields are merged:

**Basic Information Fields:**
- `PackageDescription`: Package description text
- `PackageDownloadLocation`: Where the package can be downloaded
- `PackageHomePage`: Package home page URL
- `PackageSourceInfo`: Information about package source
- `PackageCopyrightText`: Copyright text
- `PackageLicenseConcluded`: License concluded by the reviewer
- `PackageLicenseDeclared`: License declared by the package author
- `PackageLicenseComments`: Additional license comments
- `PrimaryPackagePurpose`: Primary purpose of the package
- `PackageSupplier`: Supplier information (Person/Organization)
- `PackageOriginator`: Originator information (Person/Organization)
- `PackageChecksums`: List of checksums (SHA1, SHA256, etc.)
- `PackageExternalReferences`: External references

**Merge Behavior:**
- `if-missing-or-empty` mode: Only fills fields that are empty or missing in the primary
- `overwrite` mode: Replaces primary fields with secondary values if secondary has data
- External references are merged to avoid duplicates when in `if-missing-or-empty` mode

##### CycloneDX Component Fields

When components match, the following CycloneDX component fields are merged:

**Basic Information Fields:**
- `Description`: Component description
- `Author`: Component author
- `Publisher`: Component publisher  
- `Group`: Component group/namespace
- `Scope`: Component scope (required, optional, excluded)
- `Copyright`: Copyright information
- `PackageURL`: Package URL (purl)
- `CPE`: CPE identifier
- `SWID`: Software identification tag
- `Supplier`: Supplier organization details
- `Licenses`: License information list
- `Hashes`: Cryptographic hashes
- `ExternalReferences`: External reference links
- `Properties`: Custom properties

**Merge Behavior:**
- `if-missing-or-empty` mode: Only fills empty fields or empty lists
- `overwrite` mode: Replaces all fields with secondary values if present
- Lists are replaced entirely, not merged item-by-item

##### CycloneDX Sections Merged

When performing augment merge with CycloneDX SBOMs, the following sections are processed and merged:

**1. Components**
- All components from secondary SBOMs are evaluated against primary SBOM components
- Matching components have their fields merged based on merge mode
- New components (not in primary) are added to the primary SBOM
- Component matching uses name, version, purl, and CPE
- All components receive validated BOM-refs

**2. Dependencies**
- Only dependencies involving processed (added or merged) components are included
- Dependency references are resolved and validated against primary SBOM
- Invalid dependencies (referencing non-existent components) are filtered out
- Dependencies are deduplicated to avoid redundant relationships
- All dependency refs are updated to use primary SBOM component refs

**3. Vulnerabilities**
- Only vulnerabilities affecting processed components are included
- Vulnerabilities are deduplicated based on ID and source name
- Affects arrays are merged to consolidate all affected components
- Merge mode behavior:
  - `if-missing-or-empty`: Keeps primary's analysis, merges affects only
  - `overwrite`: Updates description, detail, recommendation, workaround, analysis, and ratings from secondary
- All vulnerability refs are validated and updated to primary SBOM component refs

**4. Metadata**
- Primary SBOM's metadata is preserved and updated with:
  - New timestamp (current UTC time)
  - Tool information (includes sbomasm and original tools)
  - Serial number (regenerated for the new SBOM)
  - Supplier, author, and license information from primary
- Tools from all SBOMs are collected and deduplicated

**5. Services**
- Similar handling to components (if present)
- Service dependencies follow the same validation rules

**Sections NOT Merged:**
- Compositions
- Annotations
- Formulation
- Declarations
- Definitions

#### Relationship and Dependency Handling

**SPDX Relationships:**
- Only relationships involving added or merged packages are included
- Both sides of a relationship must exist in the primary SBOM
- Invalid relationships (referencing non-existent packages) are filtered out
- Files are NOT merged (removed from secondary SBOMs)

**CycloneDX Dependencies:**
- Only dependencies involving added or merged components are included
- All dependency references are validated against the primary SBOM
- Invalid dependency references are automatically filtered out
- Services and their dependencies follow the same rules as components

#### Examples

```bash
# Basic augment merge - enrich with additional scan results
sbomasm assemble --augmentMerge \
  --primary base-sbom.json \
  scan-results.json \
  -o enriched-sbom.json

# Merge multiple enhancement SBOMs
sbomasm assemble --augmentMerge \
  --primary application.json \
  vulnerability-scan.json license-scan.json quality-scan.json \
  -o complete-sbom.json

# Overwrite mode - update with vendor-provided data
sbomasm assemble --augmentMerge \
  --primary internal-sbom.json \
  --merge-mode overwrite \
  vendor-sbom.json \
  -o updated-sbom.json
```

#### Use Cases

1. **Enriching CI/CD Generated SBOMs**: Add vulnerability, license, or quality data from various scanning tools
2. **Vendor SBOM Integration**: Merge vendor-provided SBOMs with internally generated ones
3. **Progressive Enhancement**: Build comprehensive SBOMs by incrementally adding data from different sources
4. **Supply Chain Updates**: Update component information as new data becomes available

#### Merge Behavior Example

Given a primary SBOM with:
```json
{
  "name": "log4j",
  "version": "2.17.1",
  "description": "",
  "licenses": []
}
```

And a secondary SBOM with:
```json
{
  "name": "log4j",
  "version": "2.17.1",
  "description": "Apache Log4j 2 logging library",
  "licenses": ["Apache-2.0"],
  "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
}
```

**Result with `if-missing-or-empty` mode:**
```json
{
  "name": "log4j",
  "version": "2.17.1",
  "description": "Apache Log4j 2 logging library",
  "licenses": ["Apache-2.0"],
  "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
}
```

**Result with `overwrite` mode:**
Same as above (since primary had empty fields)

If the primary had existing data:
```json
{
  "name": "log4j",
  "version": "2.17.1",
  "description": "Internal logging lib",
  "licenses": ["MIT"]
}
```

- `if-missing-or-empty` mode would keep the existing description and licenses
- `overwrite` mode would replace them with the secondary values

#### Important Notes

- The augment merge validates all component references to ensure consistency
- Only relationships/dependencies involving processed components are included
- Invalid references are automatically filtered out to maintain SBOM integrity
- The primary SBOM's metadata is preserved and updated with tool information
- Component matching is based on name, version, and other identifying attributes

## Configuration Files

For complex assemblies, use a configuration file:

```yaml
# config.yml
app:
  name: 'my-application'
  version: '1.0.0'
  type: 'application'
  description: 'Assembled application SBOM'
  author:
  - name: 'Security Team'
    email: 'security@company.com'
  supplier:
    name: 'My Company'
    email: 'sbom@company.com'
  licenses:
  - id: 'Apache-2.0'
  purl: 'pkg:generic/my-app@1.0.0'
  cpe: 'cpe:2.3:a:company:my-app:1.0.0:*:*:*:*:*:*:*'

output:
  spec: cyclonedx  # or spdx
  file_format: json  # or xml
  file: 'output.json'

assemble:
  flat_merge: false
  hierarchical_merge: true
  include_components: true
  include_dependency_graph: true
```

#### Configuration for Augment Merge

```yaml
# augment-config.yml
assemble:
  augment_merge: true
  primary_file: 'base-sbom.json'
  merge_mode: 'if-missing-or-empty'  # or 'overwrite'

output:
  spec: spdx  # or cyclonedx
  file_format: json
  file: 'enriched-sbom.json'
```

Use the configuration:

```bash
# For standard merge strategies
sbomasm assemble -c config.yml input1.json input2.json input3.json

# For augment merge
sbomasm assemble -c augment-config.yml enhancement1.json enhancement2.json
```

## Format Compatibility

### Input Formats

| Format | Supported Extensions |
|--------|---------------------|
| SPDX | .spdx, .spdx.json, .spdx.yaml, .spdx.yml, .spdx.rdf, .spdx.xml |
| CycloneDX | .cdx, .cdx.json, .cdx.xml |

### Output Formats

| Spec | Output Formats | Default Version |
|------|---------------|-----------------|
| SPDX | JSON, XML | 2.3 |
| CycloneDX | JSON, XML | 1.6 |

## Examples

### Microservices Assembly

Combine multiple microservice SBOMs:

```bash
# Assemble all services in a directory
sbomasm assemble \
  -n "microservices-platform" \
  -v "$(git describe --tags)" \
  -t "application" \
  -o platform-sbom.json \
  services/*.json
```

### Container Assembly

Merge base image with application layers:

```bash
# Combine base image and app SBOMs
sbomasm assemble \
  -n "containerized-app" \
  -v "latest" \
  -t "container" \
  --flat-merge \
  -o container.cdx.json \
  base-image.cdx.json \
  app-layer.cdx.json \
  runtime-deps.cdx.json
```

### Multi-Format Assembly

Assemble SBOMs in different formats:

```bash
# Mix SPDX and CycloneDX inputs (auto-detected)
sbomasm assemble \
  -n "mixed-sources" \
  -v "1.0.0" \
  -o output.spdx.json \
  component1.spdx.json \
  component2.cdx.json
```

### CI/CD Pipeline Integration

```bash
#!/bin/bash
# ci-assemble.sh

# Generate timestamp version
VERSION="$(date +%Y%m%d)-$(git rev-parse --short HEAD)"

# Collect all component SBOMs
SBOMS=$(find build/sboms -name "*.json" | tr '\n' ' ')

# Assemble with metadata
sbomasm assemble \
  -n "$CI_PROJECT_NAME" \
  -v "$VERSION" \
  -t "application" \
  -o "final-sbom.json" \
  $SBOMS

# Validate assembled SBOM
sbomqs score final-sbom.json
```

## Dependency Track Integration

Assemble SBOMs directly from Dependency Track:

```bash
# Fetch, assemble, and upload back
sbomasm assemble dt \
  -u "https://dtrack.example.com" \
  -k "$DEPENDENCY_TRACK_API_KEY" \
  -n "quarterly-report" \
  -v "2024-Q1" \
  --flat-merge \
  -o output-project-uuid \
  project-uuid-1 project-uuid-2 project-uuid-3
```

Options:
- `-u, --url`: Dependency Track server URL
- `-k, --api-key`: API key for authentication
- `-o`: Output project UUID (creates/updates project) or local file path

## Best Practices

1. **Use Configuration Files**: For production assemblies, maintain configuration files in version control
2. **Version Consistently**: Use semantic versioning or timestamps for assembled SBOMs
3. **Choose Appropriate Algorithm**: 
   - Hierarchical for maintaining relationships
   - Flat for simple inventories
   - Assembly for independent products
4. **Validate Output**: Always validate assembled SBOMs with tools like `sbomqs`
5. **Document Sources**: Include source information in the configuration

## Troubleshooting

### Common Issues

**Format Detection Failed**
```bash
# Explicitly specify format in filename
mv ambiguous.json component.spdx.json
```

**Memory Issues with Large SBOMs**
```bash
# Process in batches
sbomasm assemble -n "batch1" -v "1.0" -o batch1.json sboms1/*.json
sbomasm assemble -n "batch2" -v "1.0" -o batch2.json sboms2/*.json
sbomasm assemble -n "final" -v "1.0" -o final.json batch1.json batch2.json
```

**Duplicate Component Handling**
```bash
# Use flat-merge to remove duplicates (CycloneDX only)
sbomasm assemble --flat-merge -n "app" -v "1.0" -o deduped.json inputs/*.json
```

### Debug Mode

Enable debug output for troubleshooting:

```bash
sbomasm assemble -d \
  -n "debug-test" \
  -v "1.0.0" \
  -o output.json \
  input1.json input2.json 2>debug.log
```

## See Also

- [Edit Command](edit.md) - Modify assembled SBOM metadata
- [Remove Command](remove.md) - Remove components from assembled SBOMs
- [Generate Command](generate.md) - Create configuration templates
