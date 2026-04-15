# Generate Config Command

The `generate config` command creates a template for the artifact metadata configuration file (`.artifact-metadata.yaml`). This file describes the primary application or product that the SBOM represents.

## Overview

```bash
sbomasm generate config [flags]
```

## Basic Usage

```bash
# Generate template to stdout
sbomasm generate config

# Save to file
sbomasm generate config > .artifact-metadata.yaml

# Save to custom location
sbomasm generate config > config/.artifact-metadata.yaml
```

## Generated Configuration

The default template includes placeholder values that you must replace:

```yaml
app:
  name: "[REQUIRED]"           # Application name
  version: "[REQUIRED]"        # Application version
  description: "[OPTIONAL]"    # Description
  primary_purpose: "[REQUIRED]" # Component type
  supplier:
    name: "[OPTIONAL]"         # Supplier organization
    email: "[OPTIONAL]"        # Contact email
  author:
    - name: "[OPTIONAL]"
      email: "[OPTIONAL]"
  license:
    id: "[OPTIONAL]"           # SPDX license ID
  purl: "[OPTIONAL]"           # Package URL
  cpe: "[OPTIONAL]"            # CPE identifier
  copyright: "[OPTIONAL]"      # Copyright text
```

## Configuration Fields

### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| `name` | Application name | `device-firmware` |
| `version` | Application version | `2.1.0` |
| `primary_purpose` | Component type | `firmware`, `application`, `library` |

### Optional Fields

| Field | Description | Example |
|-------|-------------|---------|
| `description` | Detailed description | `IoT gateway firmware` |
| `supplier.name` | Organization name | `Acme Corp` |
| `supplier.email` | Contact email | `engineering@acme.com` |
| `author` | List of authors | `[{name: "Jane Doe", email: "jane@acme.com"}]` |
| `license.id` | SPDX license ID | `MIT`, `Apache-2.0` |
| `purl` | Package URL | `pkg:generic/acme/app@1.0.0` |
| `cpe` | CPE identifier | `cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*` |
| `copyright` | Copyright statement | `Copyright 2026 Acme Corp` |

### Primary Purpose Values

| Value | Description |
|-------|-------------|
| `application` | Standalone application |
| `framework` | Development framework |
| `library` | Code library |
| `container` | Container image |
| `platform` | Hardware/software platform |
| `firmware` | Device firmware |
| `operating-system` | Operating system |
| `device` | Physical device |
| `file` | Single file |

## Examples

### Embedded Firmware

```yaml
app:
  name: device-firmware
  version: 2.1.0
  description: Main firmware for Acme IoT gateway
  primary_purpose: firmware
  supplier:
    name: Acme Corp
    email: engineering@acme.com
  author:
    - name: Jane Doe
      email: jane@acme.com
  license:
    id: MIT
  purl: pkg:generic/acme/device-firmware@2.1.0
  cpe: cpe:2.3:a:acme:device-firmware:2.1.0:*:*:*:*:*:*:*
  copyright: Copyright 2026 Acme Corp
```

### Enterprise Application

```yaml
app:
  name: enterprise-suite
  version: 2024.1.0
  description: Enterprise Resource Planning Suite
  primary_purpose: application
  supplier:
    name: Enterprise Software Inc
    email: support@enterprise.com
  author:
    - name: Development Team
      email: dev@enterprise.com
    - name: Security Team
      email: security@enterprise.com
  license:
    id: Commercial
  purl: pkg:generic/enterprise-suite@2024.1.0
  copyright: © 2024 Enterprise Software Inc
```

### Container Image

```yaml
app:
  name: web-service-container
  version: latest
  description: Containerized web service
  primary_purpose: container
  supplier:
    name: Container Corp
    email: containers@company.com
  license:
    id: Apache-2.0
  purl: pkg:docker/container-corp/web-service@latest
```

### Open Source Library

```yaml
app:
  name: my-library
  version: 3.2.1
  description: A useful library for developers
  primary_purpose: library
  author:
    - name: Open Source Contributors
  license:
    id: MIT
  purl: pkg:npm/my-library@3.2.1
  copyright: Copyright 2026 Contributors
```

## Validation

The configuration is validated when used:

### Required Field Checks

```bash
# Missing name
$ sbomasm generate sbom
Error: artifact name is required

# Missing version
Error: artifact version is required

# Missing primary_purpose
Error: artifact primary_purpose is required
```

### Value Validation

```bash
# Invalid primary_purpose
Error: invalid primary_purpose: widget
allowed values are: application, framework, library, container, platform, firmware, operating-system, device, file
```

### Sanitization

Placeholders are automatically converted:

- `"[OPTIONAL]"` → empty string
- `"[REQUIRED]"` → treated as missing (error)

## Best Practices

### 1. Version Control

Commit `.artifact-metadata.yaml` to your repository:

```bash
git add .artifact-metadata.yaml
git commit -m "Add SBOM artifact metadata"
```

### 2. Environment-Specific Values

Keep environment-specific data minimal:

```yaml
app:
  name: my-app                    # Constant
  version: "[REQUIRED]"           # Set by CI
  primary_purpose: application      # Constant
```

### 3. Supplier Information

Always include supplier for compliance:

```yaml
app:
  supplier:
    name: My Organization
    email: legal@example.com
```

### 4. License Identification

Use SPDX identifiers:

```yaml
license:
  id: Apache-2.0  # ✓ SPDX identifier
# Not: Apache License 2.0
```

## Troubleshooting

### File Not Found

```bash
$ sbomasm generate sbom
Error: artifact metadata file not found: .artifact-metadata.yaml
run 'sbomasm generate config > .artifact-metadata.yaml'
```

**Fix:** Generate the file first:

```bash
sbomasm generate config > .artifact-metadata.yaml
```

### Invalid YAML

```bash
Error: failed to parse yaml: ...
```

**Fix:** Check YAML syntax with a validator:

```bash
yamllint .artifact-metadata.yaml
```

### Placeholder Not Replaced

```bash
Error: artifact name is required
```

**Fix:** Replace `[REQUIRED]` with actual value:

```yaml
app:
  name: my-application  # Not: "[REQUIRED]"
```

## See Also

- [generate sbom](generate_sbom.md) - Generate SBOM using this configuration
- [generate](generate.md) - Generate command overview
