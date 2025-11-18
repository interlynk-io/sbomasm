# sbomasm view - SBOM Visualization

The `view` command displays CycloneDX SBOMs in a unified, hierarchical tree format that consolidates information from various SBOM sections (components, dependencies, vulnerabilities, compositions, annotations) into an intuitive view.

## Table of Contents

- [Quick Start](#quick-start)
- [Command Syntax](#command-syntax)
- [Display Modes](#display-modes)
- [Output Formats](#output-formats)
- [Filtering Options](#filtering-options)
- [Vulnerability Filtering](#vulnerability-filtering)
- [Common Use Cases](#common-use-cases)
- [Configuration Flags Reference](#configuration-flags-reference)

## Quick Start

```bash
# Basic view with default settings
sbomasm view sbom.cdx.json

# Detailed view with all information
sbomasm view sbom.cdx.json --verbose

# Focus on high-severity vulnerabilities
sbomasm view sbom.cdx.json --min-severity high --only-unresolved

# License-only view
sbomasm view sbom.cdx.json --only-licenses

# Save output to file
sbomasm view sbom.cdx.json -o report.txt
```

## Command Syntax

```
sbomasm view <sbom-file> [flags]
```

**Arguments:**
- `<sbom-file>` - Path to a CycloneDX SBOM file (JSON format)

## Display Modes

### Default Mode

Shows component hierarchy with dependencies and vulnerabilities enabled:

```bash
sbomasm view samples/cdx/sbom-with-assemblies.json
```

**Output:**
```
SBOM: CycloneDX 1.6
Generated: 2025-11-11 16:17:24 (7 days ago)
Serial: urn:uuid:75e19ea1-cb02-40f0-bc3a-390ab80a2b89
Tools: Dependency-Track 4.13.5, Dependency-Track 4.13.5

┌─ Final product@1.2.3 [PRIMARY] (application)
│   Type: application
│   Vulnerabilities (56):
│     - CVE-2025-26519 [HIGH] (false_positive) Score: 8.1 Source: NVD
│     - CVE-2017-7507 [HIGH] (false_positive) Score: 7.5 Source: NVD
│     - CVE-2025-59375 [HIGH] Score: 7.5 Source: NVD
│     - ALPINE-CVE-2025-26519 [HIGH] (false_positive) Source: OSV
│     - ALPINE-CVE-2017-7507 [HIGH] (false_positive) Source: OSV
│     ... and 51 more
│
│ ├─ foo@1.0.0 (container)
│ │   Type: container
│ │
│ │ Assemblies (6):
│ │ ├─ gnutls@3.8.8-r0 (library)
│ │ │   Type: library
│ │ │   Dependencies (1):
│ │ │     - musl@1.2.5-r10 (library)
│ │ │
│ │ ├─ libcrypto3@3.5.1-r0 (library)
│ │ │   Type: library
│ │ │   Dependencies (1):
│ │ │     - musl@1.2.5-r10 (library)
...

Statistics:
  Total Components: 22
  Total Dependencies: 25
  Vulnerabilities: 56 (4C, 27H, 21M, 3L, 1U)
  Components by type:
    library: 19
    application: 1
    container: 2
```

### Verbose Mode

Shows all available fields including PURLs, licenses, hashes, properties, and compositions:

```bash
sbomasm view samples/cdx/sbom-with-assemblies.json --verbose
```

**Output:**
```
SBOM: CycloneDX 1.6
Generated: 2025-11-11 16:17:24 (7 days ago)
Serial: urn:uuid:75e19ea1-cb02-40f0-bc3a-390ab80a2b89
Tools: OWASP/Dependency-Track 4.13.5, OWASP/Dependency-Track 4.13.5

┌─ Final product@1.2.3 [PRIMARY] (application)
│   Type: application
│   Vulnerabilities (56):
│     - CVE-2025-26519 (false_positive) (HIGH) (NVD) (8.1)
│     - CVE-2017-7507 (false_positive) (HIGH) (NVD) (7.5)
│     - CVE-2025-59375 (HIGH) (NVD) (7.5)
│     - ALPINE-CVE-2025-26519 (false_positive) (HIGH) (OSV)
│     - ALPINE-CVE-2017-7507 (false_positive) (HIGH) (OSV)
│     - ALPINE-CVE-2025-9230 (HIGH) (OSV)
│     - CVE-2025-9230 (HIGH) (NVD) (7.5)
│     ... and 49 more
│
│ ├─ foo@1.0.0 (container)
│ │   Type: container
│ │   Description: Docker image for foo
│ │
│ │ Assemblies (6):
│ │ ├─ gnutls@3.8.8-r0 (library)
│ │ │   Type: library
│ │ │   PURL: pkg:apk/alpine/gnutls@3.8.8-r0?arch=x86_64&distro=3.22.1
│ │ │   Licenses (1):
│ │ │     - LGPL-2.1-or-later
│ │ │   Hashes (1):
│ │ │     - SHA-1: 730ae0e4abacd127c131d9b5aeccaeaa8178512a
│ │ │   Dependencies (1):
│ │ │     - musl@1.2.5-r10 (library) (pkg:apk/alpine/musl@1.2.5-r10?...) (MIT)
│ │ │   Properties (5):
│ │ │     - aquasecurity:trivy:LayerDiffID: sha256:c2d2b55d55c7e06865715b4e1e79699cc7b95a30...
│ │ │     - aquasecurity:trivy:PkgID: gnutls@3.8.8-r0
│ │ │     - aquasecurity:trivy:PkgType: alpine
│ │ │     - aquasecurity:trivy:SrcName: gnutls
│ │ │     - aquasecurity:trivy:SrcVersion: 3.8.8-r0
...
```

### License-Only Mode

Shows only license information with minimal component details:

```bash
sbomasm view samples/cdx/sbom-with-assemblies.json --only-licenses
```

**Output:**
```
SBOM: CycloneDX 1.6
Generated: 2025-11-11 16:17:24 (7 days ago)
Serial: urn:uuid:75e19ea1-cb02-40f0-bc3a-390ab80a2b89
Tools: Dependency-Track 4.13.5, Dependency-Track 4.13.5

┌─ Final product@1.2.3 [PRIMARY] (application)
│   No license information

Statistics:
  Total Components: 22
  Total Dependencies: 25
  Vulnerabilities: 56 (4C, 27H, 21M, 3L, 1U)
  Components by type:
    library: 19
    application: 1
    container: 2
```

## Output Formats

### Tree Format (Default)

Displays components in a hierarchical tree structure showing parent-child relationships and assemblies:

```bash
sbomasm view sbom.cdx.json --format tree
```

This is the default format and shows:
- Component hierarchies with visual tree structure
- Assembly relationships
- Dependencies for each component
- Vulnerabilities aggregated by component
- Nested structures with proper indentation

### Flat Format

Displays all components as a flat list without hierarchy:

```bash
sbomasm view samples/cdx/sbom-with-assemblies.json --format flat
```

**Output:**
```
SBOM: CycloneDX 1.6
Generated: 2025-11-11 16:17:24 (7 days ago)
Serial: urn:uuid:75e19ea1-cb02-40f0-bc3a-390ab80a2b89
Tools: Dependency-Track 4.13.5, Dependency-Track 4.13.5

─── Component 1/22:
  Name: libexpat
  Version: 2.7.1-r0
  Type: library
  Parent: foo@1.0.0
  PURL: pkg:apk/alpine/libexpat@2.7.1-r0?arch=x86_64&distro=3.22.1
  Dependencies: 1

─── Component 2/22:
  Name: libssl3
  Version: 3.5.1-r0
  Type: library
  Parent: activemq-artemis@2.42.0-stable-0014-b05effa
  PURL: pkg:apk/alpine/libssl3@3.5.1-r0?arch=x86_64&distro=3.22.1
  Dependencies: 2

─── Component 3/22:
  Name: libxml2
  Version: 2.13.8-r0
  Type: library
  Parent: activemq-artemis@2.42.0-stable-0014-b05effa
  PURL: pkg:apk/alpine/libxml2@2.13.8-r0?arch=x86_64&distro=3.22.1
  Dependencies: 1
...
```

### JSON Format

Outputs the component graph as structured JSON for programmatic processing:

```bash
sbomasm view sbom.cdx.json --format json -o analysis.json
```

This format is useful for:
- Integration with other tools and pipelines
- Custom processing and analysis
- Storing enriched SBOM data
- API integrations

## Filtering Options

### Depth Limiting

Control how deep the tree structure is displayed:

```bash
# Limit to 2 levels deep
sbomasm view samples/cdx/sbom-with-assemblies.json --max-depth 2
```

**Output:**
```
SBOM: CycloneDX 1.6
Generated: 2025-11-11 16:17:24 (7 days ago)
Serial: urn:uuid:75e19ea1-cb02-40f0-bc3a-390ab80a2b89
Tools: Dependency-Track 4.13.5, Dependency-Track 4.13.5

┌─ Final product@1.2.3 [PRIMARY] (application)
│   Type: application
│   Vulnerabilities (56):
│     - CVE-2025-26519 [HIGH] (false_positive) Score: 8.1 Source: NVD
│     - CVE-2017-7507 [HIGH] (false_positive) Score: 7.5 Source: NVD
│     ... and 54 more
│
│ ├─ foo@1.0.0 (container)
│ │   Type: container
│ │
│ │ └─ (... 6 nested components - use --max-depth to expand)
│ └─ activemq-artemis@2.42.0-stable-0014-b05effa (container)
│     Type: container
│     Dependencies (6):
│       - javax.json@1.0.4 (library)
│       - netty-codec@4.1.121.Final (library)
│       ... and 4 more
│
│   └─ (... 13 nested components - use --max-depth to expand)
```

### Component Type Filtering

Filter components by type (library, container, operating-system, application, etc.):

```bash
# Show only library components
sbomasm view sbom.cdx.json --filter-type library

# Show multiple types
sbomasm view sbom.cdx.json --filter-type "library,container"

# Show containers and operating systems
sbomasm view sbom.cdx.json --filter-type "container,operating-system"
```

Valid component types:
- `application`
- `library`
- `framework`
- `container`
- `operating-system`
- `device`
- `firmware`
- `file`

### Island Management

Control how disconnected component graphs (islands) are displayed:

```bash
# Hide disconnected components (islands)
sbomasm view sbom.cdx.json --hide-islands

# Show only the primary component tree
sbomasm view sbom.cdx.json --only-primary
```

**What are islands?**
Islands are groups of components that are not connected to the primary component tree through dependency relationships. They often represent:
- Metadata-only components
- Disconnected dependency graphs
- Components referenced in compositions but not in dependencies

## Vulnerability Filtering

### Severity Filtering

Filter vulnerabilities by minimum severity level:

```bash
# Show only high and critical severity vulnerabilities
sbomasm view sbom.cdx.json --min-severity high

# Show critical vulnerabilities only
sbomasm view sbom.cdx.json --min-severity critical

# Show medium and above
sbomasm view sbom.cdx.json --min-severity medium
```

**Output:**
```
┌─ Final product@1.2.3 [PRIMARY] (application)
│   Type: application
│   Dependencies (2):
│     - foo@1.0.0 (container)
│     - activemq-artemis@2.42.0-stable-0014-b05effa (container)
│   Vulnerabilities (22):
│     - CVE-2025-59375 [HIGH] Score: 7.5 Source: NVD
│     - ALPINE-CVE-2025-9230 [HIGH] Source: OSV
│     - CVE-2025-9230 [HIGH] Score: 7.5 Source: NVD
│     - CVE-2025-58056 [HIGH] Score: 7.5 Source: NVD
│     - CVE-2025-58057 [HIGH] Score: 7.5 Source: NVD
│     ... and 17 more
```

Severity levels (from highest to lowest):
- `critical` - Critical vulnerabilities (CVSS 9.0-10.0)
- `high` - High severity (CVSS 7.0-8.9)
- `medium` - Medium severity (CVSS 4.0-6.9)
- `low` - Low severity (CVSS 0.1-3.9)

### Unresolved Vulnerabilities Only

Show only vulnerabilities that require action (excludes false positives, not affected, and resolved):

```bash
sbomasm view sbom.cdx.json --only-unresolved

# Combine with severity filtering
sbomasm view sbom.cdx.json --min-severity high --only-unresolved
```

This filters out vulnerabilities with these analysis states:
- `false_positive` - Confirmed false positive
- `not_affected` - Component not affected
- `resolved` - Vulnerability resolved
- `resolved_with_patchable_fix` - Resolved with patch

And shows vulnerabilities in these states:
- `exploitable` - Confirmed exploitable
- `in_triage` - Under investigation
- `requires_response` - Requires action
- (empty/unknown states are considered unresolved)

## Common Use Cases

### 1. Security Audit

Identify all critical and high severity unresolved vulnerabilities:

```bash
sbomasm view sbom.cdx.json \
  --min-severity high \
  --only-unresolved \
  --verbose \
  -o security-audit.txt
```

### 2. License Compliance Review

Extract all license information for compliance review:

```bash
sbomasm view sbom.cdx.json \
  --only-licenses \
  -o license-report.txt
```

### 3. Dependency Analysis

Understand component dependencies without vulnerability noise:

```bash
sbomasm view sbom.cdx.json \
  --dependencies \
  --vulnerabilities=false \
  --annotations=false \
  --max-depth 3
```

### 4. Quick Summary

Get a high-level overview of the SBOM:

```bash
sbomasm view sbom.cdx.json \
  --max-depth 2 \
  --hide-islands \
  --dependencies=false
```

### 5. Container Analysis

Focus on container and OS components:

```bash
sbomasm view sbom.cdx.json \
  --filter-type "container,operating-system" \
  --verbose \
  --licenses
```

### 6. Full Detailed Report

Generate a comprehensive report with all available information:

```bash
sbomasm view sbom.cdx.json \
  --verbose \
  -o full-report.txt
```

### 7. JSON Export for CI/CD

Export SBOM analysis as JSON for automated processing:

```bash
sbomasm view sbom.cdx.json \
  --format json \
  -o sbom-analysis.json

# Suppress warnings for cleaner CI/CD output
sbomasm view sbom.cdx.json \
  --format json \
  --quiet \
  -o sbom-analysis.json
```

### 8. Compact View for Large SBOMs

View large SBOMs efficiently:

```bash
sbomasm view large-sbom.cdx.json \
  --max-depth 3 \
  --hide-islands \
  --only-unresolved \
  --min-severity medium
```

## Configuration Flags Reference

### Detail Level Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--verbose` | `-V` | false | Show all available fields (overrides individual flags) |
| `--dependencies` | | true | Show dependencies section |
| `--vulnerabilities` | `-v` | true | Show vulnerabilities section |
| `--annotations` | `-a` | true | Show annotations section |
| `--compositions` | `-c` | false | Show compositions section |
| `--properties` | `-p` | false | Show custom properties |
| `--hashes` | | false | Show component hashes (SHA-1, SHA-256, etc.) |
| `--licenses` | `-l` | false | Show license information |
| `--only-licenses` | | false | Show only licenses (minimal component details) |

### Filtering Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--max-depth <int>` | 0 | Maximum tree depth to display (0 = unlimited) |
| `--filter-type <types>` | "" | Filter by component type (comma-separated) |
| `--hide-islands` | false | Don't show disconnected components |
| `--only-primary` | false | Only show primary component tree |

### Vulnerability Filtering Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--min-severity <level>` | "" | Minimum vulnerability severity (low\|medium\|high\|critical) |
| `--only-unresolved` | false | Only show unresolved vulnerabilities |

### Output Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format <format>` | | tree | Output format: tree, flat, json |
| `--output <file>` | `-o` | stdout | Write output to file instead of stdout |
| `--no-color` | | false | Disable colored output |
| `--quiet` | `-q` | false | Suppress all warnings |

### Flag Precedence

When multiple flags are used, the following precedence applies:

1. `--only-licenses` - Overrides all other detail flags
2. `--verbose` - Enables all detail flags (except only-licenses)
3. Individual flags - Applied when neither only-licenses nor verbose is set

**Examples:**

```bash
# verbose is ignored, only-licenses takes precedence
sbomasm view sbom.cdx.json --verbose --only-licenses

# verbose enables all flags, individual flag values are ignored
sbomasm view sbom.cdx.json --verbose --dependencies=false
# (dependencies will still be shown because verbose overrides)

# Individual flags work when neither verbose nor only-licenses is set
sbomasm view sbom.cdx.json --licenses --hashes --properties
```

## Output Color Support

The view command automatically detects terminal color support and adjusts output accordingly.

```bash
# Explicitly disable colors (useful for file output or non-color terminals)
sbomasm view sbom.cdx.json --no-color

# Colors are auto-disabled when outputting to file
sbomasm view sbom.cdx.json -o report.txt
```

Color coding in terminal output:
- **Green** - Component names and versions
- **Yellow** - Warnings and important metadata
- **Red** - Critical and high severity vulnerabilities
- **Blue** - Links, PURLs, and references
- **Cyan** - Section headers

## Performance Tips

For large SBOMs, consider these options to improve performance and readability:

```bash
# Use max-depth to limit tree traversal
sbomasm view large-sbom.cdx.json --max-depth 3

# Hide islands to reduce clutter
sbomasm view large-sbom.cdx.json --hide-islands

# Filter to specific component types
sbomasm view large-sbom.cdx.json --filter-type library

# Disable verbose output for faster rendering
sbomasm view large-sbom.cdx.json --verbose=false

# Use flat format for simpler processing
sbomasm view large-sbom.cdx.json --format flat
```

## Troubleshooting

### Graph Validation Warnings

The viewer may show warnings about graph structure issues:

```
Warning: Graph validation found issues:
  - dangling dependency reference: Final product@1.2.3 -> foo@1.0.0:672de6c2...
```

These warnings indicate:
- **Dangling dependency references**: Dependencies that reference components not in the SBOM
- **Missing components**: Components referenced but not defined
- **Circular dependencies**: Components that form dependency cycles

These are informational and don't prevent viewing, but may indicate SBOM quality issues.

To suppress these warnings, use the `--quiet` or `-q` flag:

```bash
sbomasm view sbom.cdx.json --quiet
```

### Empty Output

If the view shows no components after filtering:

```bash
# Check what component types exist
sbomasm view sbom.cdx.json --format json | jq '.components[].type' | sort -u

# Remove filters to see all components
sbomasm view sbom.cdx.json --filter-type ""

# Check if only-primary is hiding islands
sbomasm view sbom.cdx.json --only-primary=false
```

## See Also

- [assemble](assemble.md) - Merge multiple SBOMs
- [edit](edit.md) - Modify SBOM metadata
- [enrich](enrich.md) - Enrich SBOMs with missing information
- [Package Documentation](../pkg/view/README.md) - For developers using the view package as a library

## Examples Repository

More examples are available in the `samples/` directory:

```bash
# View various sample SBOMs
sbomasm view samples/cdx/sbom-with-assemblies.json
sbomasm view samples/cdx/product.json
```
