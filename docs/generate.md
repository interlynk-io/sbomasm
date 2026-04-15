# Generate Command

The `generate` command provides tools for creating SBOMs and configuration files. It has two subcommands:

- **`generate config`**: Create artifact metadata configuration files
- **`generate sbom`**: Generate SBOMs from component metadata

## Overview

```bash
# Generate artifact metadata template
sbomasm generate config > .artifact-metadata.yaml

# Generate SBOM from component files
sbomasm generate sbom -r . -o output.cdx.json
```

## Subcommands

| Subcommand | Description |
|------------|-------------|
| [`config`](generate_config.md) | Generate artifact metadata configuration template |
| [`sbom`](generate_sbom.md) | Generate SBOM from component metadata files |

## Quick Start

### 1. Create Artifact Metadata

First, generate a configuration file for your application:

```bash
sbomasm generate config > .artifact-metadata.yaml
```

Edit the file to describe your application:

```yaml
app:
  name: my-application
  version: 1.0.0
  description: My application description
  primary_purpose: application
  supplier:
    name: My Organization
    email: engineering@example.com
```

### 2. Create Component Manifests

Create `.components.json` files listing your third-party dependencies:

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "lodash",
      "version": "4.17.21",
      "type": "library",
      "license": "MIT",
      "purl": "pkg:npm/lodash@4.17.21"
    }
  ]
}
```

### 3. Generate the SBOM

```bash
sbomasm generate sbom -r . -o sbom.cdx.json
```

## Legacy Behavior

Running `sbomasm generate` without a subcommand prints a legacy assembly configuration template:

```bash
sbomasm generate > config.yml
```

This is deprecated in favor of the `config` and `sbom` subcommands.

## Workflow Comparison

| Workflow | Command |
|----------|---------|
| Create artifact metadata | `sbomasm generate config > .artifact-metadata.yaml` |
| Generate SBOM | `sbomasm generate sbom -r . -o output.cdx.json` |
| Legacy: Assembly config | `sbomasm generate > config.yml` |

## Use Cases

### Embedded Firmware

For C/C++ embedded projects without package managers:

```bash
# Create metadata
sbomasm generate config > .artifact-metadata.yaml
# Edit: Set primary_purpose: firmware

# Create component lists manually
# Vendored libraries in src/
cat > src/cjson/.components.json << 'EOF'
{
  "schema": "interlynk/component-manifest/v1",
  "components": [{
    "name": "cjson",
    "version": "1.7.17",
    "license": "MIT",
    "purl": "pkg:github/DaveGamble/cJSON@1.7.17"
  }]
}
EOF

# Generate SBOM
sbomasm generate sbom -r . -o firmware-1.0.0.cdx.json
```

### Multi-Variant Builds

Generate different SBOMs for different build targets:

```bash
# Base variant (core only)
sbomasm generate sbom -r . --tags core -o base.cdx.json

# Full variant (all components)
sbomasm generate sbom -r . -o full.cdx.json

# Release variant (exclude debug)
sbomasm generate sbom -r . --exclude-tags debug -o release.cdx.json
```

## See Also

- [generate config](generate_config.md) - Artifact metadata configuration
- [generate sbom](generate_sbom.md) - SBOM generation from components
- [assemble](assemble.md) - Merge existing SBOMs
- [edit](edit.md) - Modify SBOMs
