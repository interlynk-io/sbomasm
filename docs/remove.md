# Remove Command

The `rm` (remove) command strips components, fields, or sensitive information from SBOMs. This is essential for sharing SBOMs externally, protecting intellectual property, and reducing SBOM size.

## Overview

`sbomasm rm` allows you to:
- Remove entire components by name or pattern
- Strip specific fields from components or metadata
- Clean sensitive information before external sharing
- Reduce SBOM size by removing unnecessary data
- Filter components based on various criteria

## Basic Usage

```bash
sbomasm rm --subject <target> --search <pattern> [options] <input-sbom>
```

## Command Options

### Subject Selection (Required)

- `--subject <target>`: What to remove
  - `component-name`: Remove components by name
  - `component-data`: Remove specific component fields
  - `component-from-dependency`: Remove component from dependency graph
  - `primary-dependency`: Remove primary component dependencies
  - `author`: Remove author information
  - `supplier`: Remove supplier information
  - `repository`: Remove repository references
  - `primary-component-dependency`: Remove primary component from dependencies

### Search Options

- `--search <pattern>`: Pattern to match for removal
  - For components: exact name or pattern
  - For fields: field identifier
  - Can be repeated for multiple patterns

### Output Options

- `--output <path>`: Output file path (default: modifies in place with backup)
- `-o <path>`: Short form of --output
- `--force`: Skip confirmation prompts

### Filter Options

- `--type <type>`: Filter by component type
- `--version <version>`: Filter by version
- `--purl-type <type>`: Filter by package URL type
- `--license <license>`: Filter by license

## Remove Targets

### Remove Components by Name

Remove specific components from the SBOM:

```bash
# Remove a single component
sbomasm rm \
  --subject component-name \
  --search "internal-debug-tool" \
  input.json -o output.json

# Remove multiple components
sbomasm rm \
  --subject component-name \
  --search "test-framework" \
  --search "mock-server" \
  --search "debug-console" \
  input.json -o output.json
```

### Remove Component Fields

Strip specific fields from components:

```bash
# Remove all repository URLs
sbomasm rm \
  --subject repository \
  input.json -o output.json

# Remove supplier information
sbomasm rm \
  --subject supplier \
  input.json -o output.json

# Remove internal hashes
sbomasm rm \
  --subject component-data \
  --search "internal-hash" \
  input.json -o output.json
```

### Remove from Dependencies

Clean up dependency relationships:

```bash
# Remove component from dependency graph
sbomasm rm \
  --subject component-from-dependency \
  --search "deprecated-lib" \
  input.json -o output.json

# Remove all primary component dependencies
sbomasm rm \
  --subject primary-dependency \
  input.json -o output.json
```

## Filtering Options

### By Component Type

Remove components of specific types:

```bash
# Remove all test libraries
sbomasm rm \
  --subject component-name \
  --type "test" \
  input.json -o output.json

# Remove development dependencies
sbomasm rm \
  --subject component-name \
  --type "development" \
  input.json -o output.json
```

### By Package Type

Filter by package URL type:

```bash
# Remove all npm packages
sbomasm rm \
  --subject component-name \
  --purl-type "npm" \
  input.json -o output.json

# Remove internal packages
sbomasm rm \
  --subject component-name \
  --purl-type "generic" \
  --search "internal-*" \
  input.json -o output.json
```

### By License

Remove components with specific licenses:

```bash
# Remove GPL licensed components
sbomasm rm \
  --subject component-name \
  --license "GPL-3.0" \
  input.json -o output.json

# Remove components with unknown licenses
sbomasm rm \
  --subject component-name \
  --license "UNKNOWN" \
  input.json -o output.json
```

## Examples

### Prepare SBOM for External Sharing

Remove internal components and sensitive data:

```bash
#!/bin/bash
# prepare-external.sh

# Step 1: Remove internal components
sbomasm rm \
  --subject component-name \
  --search "internal-*" \
  --search "debug-*" \
  --search "test-*" \
  original.json -o step1.json

# Step 2: Remove repository URLs
sbomasm rm \
  --subject repository \
  step1.json -o step2.json

# Step 3: Remove internal supplier info
sbomasm rm \
  --subject supplier \
  --search "Internal Team" \
  step2.json -o external-ready.json

echo "SBOM prepared for external sharing: external-ready.json"
```

### Clean Development Dependencies

Remove non-production components:

```bash
# Remove dev dependencies from Node.js project
sbomasm rm \
  --subject component-name \
  --purl-type "npm" \
  --search "*-dev" \
  --search "*-test" \
  --search "eslint*" \
  --search "jest*" \
  input.json -o production.json
```

### Automotive Industry Compliance

Remove non-safety-critical components:

```bash
# Keep only safety-critical components
sbomasm rm \
  --subject component-name \
  --type "development" \
  input.json -o step1.json

sbomasm rm \
  --subject component-name \
  --search "logging-*" \
  --search "metrics-*" \
  step1.json -o safety-critical.json
```

### Remove Deprecated Components

Clean up legacy dependencies:

```bash
# List of deprecated components
deprecated=(
  "old-auth-lib"
  "legacy-parser"
  "deprecated-util"
)

output="input.json"
for comp in "${deprecated[@]}"; do
  sbomasm rm \
    --subject component-name \
    --search "$comp" \
    "$output" -o "$output"
  
  sbomasm rm \
    --subject component-from-dependency \
    --search "$comp" \
    "$output" -o "$output"
done
```

### GDPR Compliance

Remove personal information:

```bash
# Remove all author information for GDPR
sbomasm rm \
  --subject author \
  input.json -o step1.json

# Remove email addresses from suppliers
sbomasm edit \
  --subject document \
  --supplier "Company Name (website.com)" \
  step1.json -o gdpr-compliant.json
```

## Batch Processing

### Remove from Multiple SBOMs

```bash
#!/bin/bash
# batch-remove.sh

REMOVE_PATTERNS=(
  "test-*"
  "mock-*"
  "debug-*"
  "*-dev"
)

for sbom in sboms/*.json; do
  output="cleaned/$(basename $sbom)"
  cp "$sbom" "$output"
  
  for pattern in "${REMOVE_PATTERNS[@]}"; do
    sbomasm rm \
      --subject component-name \
      --search "$pattern" \
      "$output" -o "$output"
  done
  
  echo "Cleaned: $output"
done
```

### Pipeline Integration

```bash
#!/bin/bash
# ci-clean.sh

# Remove based on environment
if [ "$ENVIRONMENT" = "production" ]; then
  # Remove all non-production components
  sbomasm rm \
    --subject component-name \
    --type "development" \
    input.json -o temp.json
  
  sbomasm rm \
    --subject component-name \
    --type "test" \
    temp.json -o production.json
else
  cp input.json production.json
fi

# Always remove internal components for external
if [ "$DISTRIBUTION" = "external" ]; then
  sbomasm rm \
    --subject component-name \
    --search "internal-*" \
    production.json -o external.json
fi
```

## Pattern Matching

### Wildcard Patterns

Use wildcards for flexible matching:

```bash
# Remove all components starting with "test-"
sbomasm rm --subject component-name --search "test-*" input.json

# Remove all components ending with "-dev"
sbomasm rm --subject component-name --search "*-dev" input.json

# Remove all components containing "debug"
sbomasm rm --subject component-name --search "*debug*" input.json
```

### Regular Expressions

Some patterns support regex:

```bash
# Remove versioned test components
sbomasm rm --subject component-name --search "test-v[0-9]+" input.json

# Remove numbered internal components
sbomasm rm --subject component-name --search "internal-[0-9]{3}" input.json
```

## Safety Features

### Backup Creation

By default, creates backups before modification:

```bash
# Original file backed up as input.json.bak
sbomasm rm --subject component-name --search "component" input.json

# Skip backup with --force
sbomasm rm --force --subject component-name --search "component" input.json
```

### Dry Run

Preview what will be removed:

```bash
# Show what would be removed without making changes
sbomasm rm --dry-run \
  --subject component-name \
  --search "test-*" \
  input.json
```

### Confirmation Prompts

Interactive confirmation for destructive operations:

```bash
# Will prompt: "Remove 15 components matching 'test-*'? [y/N]"
sbomasm rm --subject component-name --search "test-*" input.json

# Skip prompt with --force
sbomasm rm --force --subject component-name --search "test-*" input.json
```

## Best Practices

1. **Always Backup**: Keep original SBOMs before bulk removals
2. **Test Patterns**: Use `--dry-run` to verify patterns before removal
3. **Document Removals**: Keep a log of what was removed and why
4. **Validate After**: Check SBOM validity after removals
5. **Use Specific Patterns**: Avoid overly broad patterns that might remove too much

## Troubleshooting

### Nothing Removed

```bash
# Check if pattern matches anything
sbomasm rm --dry-run --subject component-name --search "pattern" input.json

# List all component names to verify
jq '.components[].name' input.json | sort | uniq
```

### Too Much Removed

```bash
# Restore from backup
cp input.json.bak input.json

# Use more specific pattern
sbomasm rm --subject component-name --search "test-utils-*" input.json
```

### Dependency Issues

```bash
# After removing components, fix broken dependencies
sbomasm rm --subject component-from-dependency --search "removed-component" input.json
```

## Field Reference

### Removable Fields by Subject

| Subject | What Gets Removed |
|---------|------------------|
| component-name | Entire component and its data |
| component-data | Specific fields within components |
| author | All author information |
| supplier | All supplier information |
| repository | Repository URLs and references |
| component-from-dependency | Component from dependency graph |
| primary-dependency | Dependencies of primary component |

### Format-Specific Behavior

| Format | Removal Behavior |
|--------|-----------------|
| SPDX | Removes packages and updates relationships |
| CycloneDX | Removes components and updates dependency graph |

## See Also

- [Edit Command](edit.md) - Modify SBOM metadata
- [Assemble Command](assemble.md) - Merge multiple SBOMs
- [Generate Command](generate.md) - Create configuration templates