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

Use the configuration:

```bash
sbomasm assemble -c config.yml input1.json input2.json input3.json
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