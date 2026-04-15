# Generate SBOM Command

The `generate sbom` command creates an SBOM from component metadata files. It reads one or more component manifests (JSON or CSV format) and produces a complete CycloneDX or SPDX SBOM.

## Overview

```bash
sbomasm generate sbom [flags]
```

## Prerequisites

Before running this command, you need:

1. **Artifact metadata file** (`.artifact-metadata.yaml`) - Created by `sbomasm generate config`
2. **Component manifest files** (`.components.json` or `.components.csv`) - Listing your dependencies

## Basic Usage

### Recursive Discovery (Recommended)

Discover all component files recursively:

```bash
sbomasm generate sbom -r . -o device-firmware-2.1.0.cdx.json
```

### Explicit Input Files

Specify component files directly:

```bash
sbomasm generate sbom \
  -i .components.json \
  -i libs/libmqtt/.components.json \
  -i src/cjson/.components.json \
  -o device-firmware-2.1.0.cdx.json
```

### Generate SPDX

```bash
sbomasm generate sbom -r . -o device-firmware.spdx.json --format spdx
```

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | `-c` | `.artifact-metadata.yaml` | Path to artifact metadata config |
| `--input` | `-i` | - | Component files (can specify multiple) |
| `--output` | `-o` | stdout | Output SBOM file path |
| `--format` | | `cyclonedx` | Output format: `cyclonedx` or `spdx` |
| `--tags` | `-t` | - | Include components with any of these tags |
| `--exclude-tags` | | - | Exclude components with these tags |
| `--recurse` | `-r` | - | Recursively discover component files |
| `--filename` | | `.components.json` | Filename to discover (with `--recurse`) |
| `--debug` | | false | Enable debug logging |

## Component Manifest Format

### JSON Format

File: `.components.json`

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "libmqtt",
      "version": "4.3.0",
      "type": "library",
      "supplier": {
        "name": "Eclipse Foundation"
      },
      "license": "EPL-2.0",
      "purl": "pkg:generic/eclipse/libmqtt@4.3.0",
      "hashes": [
        {
          "algorithm": "SHA-256",
          "value": "9f86d08..."
        }
      ],
      "dependency-of": ["device-firmware@2.1.0"],
      "tags": ["core", "networking"]
    }
  ]
}
```

### CSV Format

File: `.components.csv`

```csv
#interlynk/component-manifest/v1
name,version,type,supplier_name,supplier_email,license,purl,cpe,hash_algorithm,hash_value,dependency_of,tags
libmqtt,4.3.0,library,Eclipse Foundation,,EPL-2.0,pkg:generic/eclipse/libmqtt@4.3.0,,SHA-256,9f86d08...,,core,networking
libtls,3.9.0,library,OpenBSD,,ISC,pkg:generic/openbsd/libtls@3.9.0,,SHA-256,e3b0c44...,libmqtt@4.3.0,core,networking
```

### Field Reference

| Field | JSON | CSV | Required | Description |
|-------|------|-----|----------|-------------|
| `name` | ✓ | ✓ | Yes | Component name |
| `version` | ✓ | ✓ | Yes | Component version |
| `type` | ✓ | ✓ | No | Type: library, framework, application, container, firmware, device, file |
| `supplier` / `supplier_name` | ✓ | ✓ | No | Supplier organization |
| `license` | ✓ | ✓ | No | SPDX license ID or expression |
| `purl` | ✓ | ✓ | No | Package URL |
| `cpe` | ✓ | ✓ | No | CPE identifier |
| `hashes` / `hash_*` | ✓ | ✓ | No | Cryptographic hashes |
| `dependency-of` | ✓ | ✓ | No | Parent component(s) in `name@version` format |
| `tags` | ✓ | ✓ | No | Filter tags (comma-separated in CSV) |

## Dependency Resolution

Dependencies are defined using `dependency-of` to reference parent components:

```json
{
  "name": "libtls",
  "version": "3.9.0",
  "dependency-of": ["libmqtt@4.3.0"]
}
```

This creates a dependency: `libmqtt@4.3.0` → `libtls@3.9.0`

Components without `dependency-of` become top-level dependencies of the primary application.

### Cross-File References

References work across all input files:

```
root/.components.json          → defines libmqtt@4.3.0
libs/libmqtt/.components.json  → defines libtls@3.9.0 with dependency-of: ["libmqtt@4.3.0"]
```

The reference from libtls to libmqtt is resolved even though they're in different files.

## Tag Filtering

Use tags to generate different SBOM variants from the same component set:

### Include Filter

Include only components with specific tags:

```bash
# Only core components
sbomasm generate sbom -r . --tags core -o base.cdx.json

# Core OR networking
sbomasm generate sbom -r . --tags core,networking -o extended.cdx.json
```

### Exclude Filter

Exclude components with specific tags:

```bash
# Exclude debug components
sbomasm generate sbom -r . --exclude-tags debug -o release.cdx.json
```

### Combined Filtering

```bash
# Core only, no debug
sbomasm generate sbom -r . --tags core --exclude-tags debug -o production.cdx.json
```

## Real-World Examples

### Embedded Firmware Project

```
device-firmware/
├── .artifact-metadata.yaml      # Application metadata
├── .components.json             # External OSS components
├── src/
│   ├── main.c
│   ├── cjson/
│   │   └── .components.json     # Vendored JSON parser
│   └── miniz/
│       └── .components.json     # Vendored compression library
└── libs/
    └── libmqtt/
        └── .components.json     # Internal submodule
```

```bash
sbomasm generate sbom -r . -o device-firmware-2.1.0.cdx.json
```

### Multi-Variant Firmware

Build different firmware variants:

```bash
# Base firmware (core only)
sbomasm generate sbom -r . --tags core \
  -o device-firmware-base-2.1.0.cdx.json

# Display variant (core + display)
sbomasm generate sbom -r . --tags core,display \
  -o device-firmware-display-2.1.0.cdx.json

# Premium variant (all features)
sbomasm generate sbom -r . \
  -o device-firmware-premium-2.1.0.cdx.json
```

## Output Formats

### CycloneDX (Default)

- Spec version: 1.6
- Includes: metadata, components, dependencies
- Tools metadata includes sbomasm

### SPDX

- Spec version: 2.3
- Includes: document, packages, relationships
- Creation info includes sbomasm as tool

## Validation

### Input Validation

- JSON files must have `schema: "interlynk/component-manifest/v1"`
- CSV files must have `#interlynk/component-manifest/v1` header
- Required fields: `name`, `version`, `primary_purpose`

## Troubleshooting

### No Component Files Found

```bash
Error: no component files found in input paths
```

**Fix:** Create `.components.json` files or check `--filename`:
```bash
# Check what files exist
find . -name ".components.json"

# Use correct filename
sbomasm generate sbom -r . --filename my-components.json
```

### Invalid Schema

```bash
Error: invalid schema: expected interlynk/component-manifest/v1, got ...
```

**Fix:** Ensure the schema marker is present:
```json
{
  "schema": "interlynk/component-manifest/v1",
  ...
}
```

### No Components After Filtering

```bash
Error: no components left after applying tag filters
```

**Fix:** Check your tag filters match actual tags:
```bash
# List all available tags
grep -r "tags" .components.json
```

### Missing Config File

```bash
Error: artifact metadata file not found: .artifact-metadata.yaml
run 'sbomasm generate config > .artifact-metadata.yaml'
```

**Fix:** Generate and edit the config:
```bash
sbomasm generate config > .artifact-metadata.yaml
# Edit and fill required fields
```

## See Also

- [generate config](generate_config.md) - Artifact metadata configuration
- [generate](generate.md) - Generate command overview
- [assemble](assemble.md) - Merge existing SBOMs
