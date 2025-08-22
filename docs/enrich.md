# Enrich Command

The `enrich` command augments SBOMs with missing information by fetching data from external sources. Currently, it supports enriching license information using the ClearlyDefined database.

## Overview

`sbomasm enrich` helps you:
- Fill missing license information in automatically generated SBOMs
- Standardize license expressions across components
- Ensure compliance with regulatory requirements
- Improve SBOM completeness for procurement and legal review
- Update existing license data with more accurate information

## Basic Usage

```bash
sbomasm enrich --fields license -o <output> <input-sbom>
```

## Command Options

### Field Selection

- `--fields <list>`: Fields to enrich (comma-separated)
  - Currently supported: `license`
  - Future support planned for: `copyright`, `security`, `metadata`

### Output Options

- `-o, --output <path>`: Output file path for the enriched SBOM
  - If not specified, overwrites the input file

### Enrichment Control

- `-f, --force`: Force replacement of existing field values
  - Default: false (only fills missing values)
  - Use this to update potentially incorrect or incomplete data

### License-Specific Options

- `-j, --license-exp-join <operator>`: Join operator for license expressions
  - Default: `OR`
  - Options: `AND`, `OR`, `WITH`, `+`
  - Used when combining multiple licenses for a component

### Network Options

- `-r, --max-retries <number>`: Maximum retry attempts for failed requests
  - Default: 2
  - Range: 0-10
  - Useful for handling temporary network issues

- `-w, --max-wait <seconds>`: Maximum wait time per request
  - Default: 5 seconds
  - Range: 1-60
  - Adjust based on network conditions

### Debug Options

- `-d, --debug`: Enable debug logging for troubleshooting

## Data Source: ClearlyDefined

The enrich command uses [ClearlyDefined](https://clearlydefined.io) as its primary data source. ClearlyDefined is a community-driven project that:
- Aggregates license information from multiple sources
- Provides curated and reviewed license data
- Covers millions of open-source components
- Supports multiple package ecosystems (npm, Maven, PyPI, NuGet, etc.)

## How It Works

1. **Component Analysis**: Scans the SBOM for components with missing or incomplete license information
2. **Coordinate Mapping**: Maps components to ClearlyDefined coordinates using:
   - Package URLs (purls)
   - Component names and versions
   - Package ecosystem information
3. **Data Retrieval**: Fetches license data from ClearlyDefined API
4. **Enrichment**: Updates the SBOM with retrieved license information
5. **Output Generation**: Saves the enriched SBOM in the specified format

## Examples

### Basic License Enrichment

Fill missing licenses only:

```bash
# Enrich SBOM with missing license information
sbomasm enrich \
  --fields license \
  --output enriched-sbom.json \
  original-sbom.json
```

### Force Update All Licenses

Replace all license information with ClearlyDefined data:

```bash
# Force update all licenses
sbomasm enrich \
  --fields license \
  --force \
  --output updated-sbom.json \
  input-sbom.json
```

### Custom License Expression Joining

Use AND operator for dual-licensed components:

```bash
# Join multiple licenses with AND
sbomasm enrich \
  --fields license \
  --license-exp-join "AND" \
  --output dual-licensed.json \
  input.json
```

### Robust Network Handling

Configure for unreliable network conditions:

```bash
# Increase retries and timeout for slow networks
sbomasm enrich \
  --fields license \
  --max-retries 5 \
  --max-wait 30 \
  --output enriched.json \
  input.json
```

### Debug Mode

Troubleshoot enrichment issues:

```bash
# Enable debug logging
sbomasm enrich \
  --fields license \
  --debug \
  --output debug-enriched.json \
  input.json
```

## Use Cases

### Compliance Preparation

Ensure all components have license information before legal review:

```bash
# Prepare SBOM for compliance audit
sbomasm enrich \
  --fields license \
  --force \
  --output compliance-ready.json \
  generated-sbom.json
```

### CI/CD Pipeline Integration

Automatically enrich SBOMs in your build pipeline:

```bash
#!/bin/bash
# ci-enrich.sh

# Generate SBOM
syft . -o spdx-json=raw-sbom.json

# Enrich with licenses
sbomasm enrich \
  --fields license \
  --output enriched-sbom.json \
  raw-sbom.json

# Validate enriched SBOM
sbomasm validate enriched-sbom.json
```

### Batch Processing

Process multiple SBOMs:

```bash
#!/bin/bash
# batch-enrich.sh

for sbom in sboms/*.json; do
  echo "Enriching $sbom..."
  sbomasm enrich \
    --fields license \
    --output "enriched/$(basename $sbom)" \
    "$sbom"
done
```

### Supply Chain Documentation

Prepare SBOMs for vendor delivery:

```bash
# Enrich and clean SBOM for external sharing
sbomasm enrich \
  --fields license \
  --force \
  --output temp-enriched.json \
  internal-sbom.json

# Remove internal components
sbomasm rm \
  --subject component-name \
  --search "internal-" \
  --output vendor-sbom.json \
  temp-enriched.json
```

## Output Summary

After enrichment, the command provides a summary:

```
Total: 150        # Total components in SBOM
Selected: 45      # Components missing license info
Enriched: 42      # Successfully enriched components
Skipped: 3        # Components skipped (no data available)
Failed: 0         # Components that failed to enrich
```

## Supported Formats

### Input Formats

| Format | Extensions |
|--------|------------|
| SPDX | .spdx, .spdx.json, .spdx.yaml |
| CycloneDX | .cdx, .cdx.json, .cdx.xml |

### Output Formats

The enriched SBOM maintains the same format as the input file.

## Limitations

- Currently only supports license enrichment
- Requires internet connectivity to access ClearlyDefined
- Rate limits may apply for large SBOMs
- Some proprietary or internal components may not have data available
- License data quality depends on ClearlyDefined community curation

## Best Practices

1. **Verify Results**: Always review enriched license information for accuracy
2. **Use Force Carefully**: Only use `--force` when you trust the external data source
3. **Network Configuration**: Adjust retry and timeout settings based on your environment
4. **Pipeline Integration**: Run enrichment after SBOM generation but before validation
5. **Backup Original**: Keep a copy of the original SBOM before enrichment
6. **Legal Review**: Have legal team verify license compatibility after enrichment

## Troubleshooting

### No License Data Found

If components aren't being enriched:
- Verify components have valid Package URLs (purls)
- Check if components exist in ClearlyDefined database
- Enable debug mode to see API requests and responses

### Network Errors

For connection issues:
- Increase `--max-retries` value
- Extend `--max-wait` timeout
- Check proxy settings if behind corporate firewall
- Verify internet connectivity to api.clearlydefined.io

### Incorrect License Information

If enriched licenses seem wrong:
- Report issues to ClearlyDefined project
- Use `--force` flag to update existing values
- Manually edit specific components using `sbomasm edit`

## Future Enhancements

Planned features for the enrich command:
- Additional data sources beyond ClearlyDefined
- Copyright information enrichment
- Security vulnerability data integration
- Custom enrichment rules and mappings
- Offline mode with cached data
- Batch API requests for better performance