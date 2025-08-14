# Generate Command

The `generate` command creates configuration file templates for the `assemble` command. This simplifies complex assembly operations by providing a structured YAML configuration that can be customized and reused.

## Overview

`sbomasm generate` creates a template configuration file that includes:
- Application metadata fields
- Output format specifications
- Assembly algorithm settings
- All available configuration options with descriptions

## Basic Usage

```bash
# Generate template to stdout
sbomasm generate

# Save template to file
sbomasm generate > config.yml

# Generate and edit
sbomasm generate > my-config.yml && vi my-config.yml
```

## Generated Configuration Structure

The generated configuration file contains three main sections:

### 1. Application Section

Defines metadata for the assembled SBOM's primary component:

```yaml
app:
  name: '[REQUIRED]'              # Name of the assembled application
  version: '[REQUIRED]'           # Version of the assembled application
  description: '[OPTIONAL]'       # Detailed description
  author:                         # Authors (can be multiple)
  - name: '[OPTIONAL]'
    email: '[OPTIONAL]'
  primary_purpose: '[OPTIONAL]'   # Type: application, library, framework, etc.
  purl: '[OPTIONAL]'              # Package URL
  cpe: '[OPTIONAL]'               # CPE identifier
  license:
    id: '[OPTIONAL]'              # License identifier
  supplier:
    name: '[OPTIONAL]'            # Supplier organization
    email: '[OPTIONAL]'           # Supplier contact
  checksum:
  - algorithm: '[OPTIONAL]'       # Hash algorithm: SHA256, SHA512, etc.
    value: '[OPTIONAL]'           # Hash value
  copyright: '[OPTIONAL]'         # Copyright statement
```

### 2. Output Section

Specifies the output format and file:

```yaml
output:
  spec: '[REQUIRED]'              # Format: spdx or cyclonedx
  file_format: '[REQUIRED]'      # Output format: json or xml
  file: '[OPTIONAL]'              # Output filename (overrides CLI -o flag)
```

### 3. Assembly Section

Controls how SBOMs are merged:

```yaml
assemble:
  include_dependency_graph: true  # Include component relationships
  include_components: true        # Include all components
  flat_merge: false              # Use flat merge algorithm
  hierarchical_merge: true       # Use hierarchical merge (default)
  assembly_merge: false          # Use assembly merge algorithm
```

## Configuration Examples

### Basic Application Assembly

Simple configuration for assembling microservices:

```yaml
app:
  name: 'microservices-platform'
  version: '1.0.0'
  description: 'E-commerce platform microservices'
  primary_purpose: 'application'
  supplier:
    name: 'ACME Corp'
    email: 'engineering@acme.com'

output:
  spec: cyclonedx
  file_format: json

assemble:
  hierarchical_merge: true
  include_components: true
  include_dependency_graph: true
```

### Enterprise Configuration

Comprehensive configuration with all metadata:

```yaml
app:
  name: 'enterprise-suite'
  version: '2024.1.0'
  description: 'Enterprise Resource Planning Suite'
  author:
  - name: 'Development Team'
    email: 'dev@enterprise.com'
  - name: 'Security Team'
    email: 'security@enterprise.com'
  primary_purpose: 'application'
  purl: 'pkg:generic/enterprise-suite@2024.1.0'
  cpe: 'cpe:2.3:a:enterprise:suite:2024.1.0:*:*:*:*:*:*:*'
  license:
    id: 'Commercial'
  supplier:
    name: 'Enterprise Software Inc'
    email: 'support@enterprise.com'
  checksum:
  - algorithm: 'SHA256'
    value: 'abc123def456...'
  copyright: '© 2024 Enterprise Software Inc. All rights reserved.'

output:
  spec: spdx
  file_format: json
  file: 'enterprise-suite-2024.1.0.spdx.json'

assemble:
  hierarchical_merge: true
  include_components: true
  include_dependency_graph: true
```

### Container Assembly Configuration

Configuration for container image SBOMs:

```yaml
app:
  name: 'web-service-container'
  version: 'latest'
  description: 'Containerized web service with dependencies'
  primary_purpose: 'container'
  author:
  - name: 'DevOps Team'
    email: 'devops@company.com'
  supplier:
    name: 'Container Corp'
    email: 'containers@company.com'

output:
  spec: cyclonedx
  file_format: json

assemble:
  flat_merge: true  # Flatten for container inventory
  include_components: true
  include_dependency_graph: false
```

### Medical Device Configuration

FDA-compliant medical device SBOM:

```yaml
app:
  name: 'cardiac-monitor-software'
  version: '3.2.0-FDA'
  description: 'Cardiac Monitoring System Software - FDA Submission'
  primary_purpose: 'device'
  author:
  - name: 'Medical Device Engineering'
    email: 'engineering@medtech.com'
  - name: 'Regulatory Affairs'
    email: 'regulatory@medtech.com'
  purl: 'pkg:generic/cardiac-monitor@3.2.0'
  cpe: 'cpe:2.3:a:medtech:cardiac_monitor:3.2.0:*:*:*:*:*:*:*'
  license:
    id: 'Proprietary'
  supplier:
    name: 'MedTech Devices Inc'
    email: 'regulatory@medtech.com'
  copyright: '© 2024 MedTech Devices Inc. Medical Device Software'

output:
  spec: spdx
  file_format: json
  file: 'cardiac-monitor-fda-submission.spdx.json'

assemble:
  hierarchical_merge: true
  include_components: true
  include_dependency_graph: true
```

## Workflow Examples

### Development to Production

Generate and customize configuration for different environments:

```bash
# Generate base configuration
sbomasm generate > base-config.yml

# Create environment-specific configs
cp base-config.yml dev-config.yml
cp base-config.yml prod-config.yml

# Edit for development
sed -i 's/\[REQUIRED\]/development/g' dev-config.yml
sed -i 's/version: .*/version: dev-latest/' dev-config.yml

# Edit for production
sed -i 's/\[REQUIRED\]/production/g' prod-config.yml
sed -i 's/version: .*/version: 1.0.0/' prod-config.yml

# Use in assembly
sbomasm assemble -c dev-config.yml dev-components/*.json
sbomasm assemble -c prod-config.yml prod-components/*.json
```

### CI/CD Pipeline Integration

Dynamically generate configuration in CI:

```bash
#!/bin/bash
# ci-generate-config.sh

cat > assembly-config.yml << EOF
app:
  name: '${CI_PROJECT_NAME}'
  version: '${CI_COMMIT_TAG:-${CI_COMMIT_SHA:0:7}}'
  description: 'Built by CI Pipeline ${CI_PIPELINE_ID}'
  author:
  - name: '${CI_COMMIT_AUTHOR}'
    email: '${CI_COMMIT_AUTHOR_EMAIL}'
  primary_purpose: 'application'
  supplier:
    name: '${CI_PROJECT_NAMESPACE}'
    email: 'ci@company.com'

output:
  spec: cyclonedx
  file_format: json
  file: '${CI_PROJECT_NAME}-${CI_COMMIT_TAG}.cdx.json'

assemble:
  hierarchical_merge: true
  include_components: true
  include_dependency_graph: true
EOF

# Use generated config
sbomasm assemble -c assembly-config.yml build/sboms/*.json
```

### Template Repository

Create reusable templates for your organization:

```bash
# Create templates directory
mkdir sbom-templates

# Generate templates for different use cases
sbomasm generate > sbom-templates/default.yml
sbomasm generate > sbom-templates/container.yml
sbomasm generate > sbom-templates/library.yml
sbomasm generate > sbom-templates/firmware.yml

# Customize each template
vi sbom-templates/container.yml
# Set primary_purpose: 'container'
# Set flat_merge: true

vi sbom-templates/library.yml
# Set primary_purpose: 'library'
# Set include_dependency_graph: true

# Use templates
sbomasm assemble -c sbom-templates/container.yml docker-sboms/*.json
```

## Configuration Validation

### Required Fields

The configuration must have these minimum fields:

```yaml
app:
  name: 'my-app'        # Required
  version: '1.0.0'      # Required

output:
  spec: cyclonedx       # Required: cyclonedx or spdx
  file_format: json     # Required: json or xml
```

### Valid Values

#### Primary Purpose Values
- `application`
- `framework`
- `library`
- `container`
- `operating-system`
- `device`
- `firmware`
- `file`

#### Output Spec Values
- `spdx`
- `cyclonedx`

#### File Format Values
- `json`
- `xml`

#### Merge Algorithm (only one can be true)
- `flat_merge`
- `hierarchical_merge`
- `assembly_merge`

## Advanced Configuration

### Multi-Stage Assembly

Use multiple configurations for complex assemblies:

```bash
# Stage 1: Assemble services
sbomasm generate > stage1.yml
# Edit stage1.yml for services
sbomasm assemble -c stage1.yml services/*.json -o services-merged.json

# Stage 2: Assemble libraries
sbomasm generate > stage2.yml
# Edit stage2.yml for libraries
sbomasm assemble -c stage2.yml libraries/*.json -o libraries-merged.json

# Stage 3: Final assembly
sbomasm generate > final.yml
# Edit final.yml for complete system
sbomasm assemble -c final.yml services-merged.json libraries-merged.json -o final-system.json
```

### Dynamic Field Population

Use environment variables and scripts:

```bash
#!/bin/bash
# generate-dynamic-config.sh

# Get version from git
VERSION=$(git describe --tags --always)

# Get author from git
AUTHOR=$(git config user.name)
EMAIL=$(git config user.email)

# Generate config with substitutions
sbomasm generate | sed \
  -e "s/name: '\[REQUIRED\]'/name: '${PROJECT_NAME}'/" \
  -e "s/version: '\[REQUIRED\]'/version: '${VERSION}'/" \
  -e "s/name: '\[OPTIONAL\]'/name: '${AUTHOR}'/" \
  -e "s/email: '\[OPTIONAL\]'/email: '${EMAIL}'/" \
  > config.yml

# Use the generated config
sbomasm assemble -c config.yml inputs/*.json
```

## Best Practices

1. **Version Control Templates**: Keep configuration templates in version control
2. **Environment-Specific Configs**: Maintain separate configs for dev, staging, and production
3. **Document Fields**: Add comments to explain custom fields
4. **Validate Early**: Test configurations with small SBOMs first
5. **Reuse Common Settings**: Create base templates for common scenarios

## Troubleshooting

### Missing Required Fields

```bash
# Error: app.name is required
# Fix: Ensure all [REQUIRED] fields are filled
sed -i "s/name: '\[REQUIRED\]'/name: 'my-app'/" config.yml
```

### Invalid Spec Values

```bash
# Error: Invalid spec 'sbom'
# Fix: Use 'spdx' or 'cyclonedx'
sed -i "s/spec: 'sbom'/spec: 'spdx'/" config.yml
```

### Conflicting Merge Algorithms

```bash
# Error: Multiple merge algorithms specified
# Fix: Set only one to true
cat > merge-fix.yml << EOF
assemble:
  flat_merge: false
  hierarchical_merge: true  # Only this one true
  assembly_merge: false
EOF
```

## Template Customization

### Adding Custom Metadata

Extend generated templates with additional fields:

```yaml
# After generating, add custom fields
app:
  name: 'my-app'
  version: '1.0.0'
  # Add custom metadata
  custom_fields:
    team: 'Platform Team'
    environment: 'production'
    build_date: '2024-01-15'
```

### Conditional Configuration

Use different configs based on conditions:

```bash
#!/bin/bash
if [ "$BUILD_TYPE" = "release" ]; then
  CONFIG="release-config.yml"
else
  CONFIG="dev-config.yml"
fi

sbomasm assemble -c "$CONFIG" inputs/*.json
```

## See Also

- [Assemble Command](assemble.md) - Use generated configurations for assembly
- [Edit Command](edit.md) - Modify assembled SBOMs
- [Remove Command](remove.md) - Clean up assembled SBOMs