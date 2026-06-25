# Flat Merge with `--primary` Flag - Design Document

**Issue:** [#312](https://github.com/interlynk-io/sbomasm/issues/312)  
**Phase:** 2  
**Date:** 2026-06-22

## Overview

Extend the `--primary` flag to work with `flatMerge` strategy. This allows users to use an existing SBOM's primary component as the document root instead of creating a synthetic primary.

## Motivation

From GitHub issue #312, users need to merge SBOMs where:
- One SBOM represents the base (e.g., Python wheel)
- Other SBOMs represent dependencies or bundled components (e.g., JavaScript bundle)
- The result should preserve the base SBOM's identity (serial number, metadata)

## Design

### CLI Interface

```bash
sbomasm assemble \
  --flatMerge \
  --primary <primary-sbom> \
  <secondary-sbom-1> [<secondary-sbom-2> ...] \
  -o <output>
```

### Examples

```bash
# Merge Python wheel (primary) with JS bundle (secondary)
sbomasm assemble --flatMerge --primary python.json js.json -o merged.json

# Multiple secondaries
sbomasm assemble --flatMerge --primary python.json js.json css.json -o merged.json
```

### Behavior

| Aspect | Without `--primary` | With `--primary` |
|--------|--------------------|------------------|
| Document root | Synthetic primary from CLI flags | Primary SBOM's `metadata.component` |
| Serial number | New UUID | Preserved from primary |
| Metadata (supplier, licenses, authors) | From CLI flags | Preserved from primary |
| Timestamp | Current time | Current time (updated) |
| Components | Flat list from all SBOMs | Flat list from all SBOMs |
| `isExternal` | Preserved as-is | Preserved as-is |
| Dependencies | All linked to synthetic primary | All linked to primary's dependencies |
| Tools | Combined from all SBOMs | Primary SBOM's tools + sbomasm |

### Key Differences from Assembly Merge

| Feature | Assembly + `--primary` | Flat + `--primary` |
|--------|------------------------|-------------------|
| Structure | Hierarchical (sub-components) | Flat (all in `components[]`) |
| Secondary primaries | Nested under `metadata.component.components` | Added to flat `components[]` |
| Use case | Nesting SBOMs as assemblies | Combining SBOMs flat with preserved identity |

## Implementation

### Files to Modify

1. `cmd/assemble.go` - Add validation for `--primary` with `flatMerge`
2. `pkg/assemble/config.go` - Add `IsFlatMergeWithPrimary` flag
3. `pkg/assemble/cdx/merge.go` - Implement `flatMergeWithPrimary()` function
4. `pkg/assemble/combiner.go` - Pass flag to CDX merge settings

### Validation Rules

1. `--primary` is **required** when using flat merge with primary
2. At least **1 secondary SBOM** required in input arguments
3. Primary file **must NOT** appear in input arguments
4. All files must exist and be valid CycloneDX

### Algorithm

```
1. Validate: --primary file not in input args
2. Load primary SBOM
3. Load secondary SBOMs from input arguments
4. Prepend primary to internal input list
5. Build component lists (priCompList, compList, depList, toolsList)
6. Initialize output BOM from primary:
   - Serial number = primary.SerialNumber
   - Metadata = primary.Metadata (with updated timestamp)
   - Primary component = primary.Metadata.Component
7. Flat merge:
   - m.out.Components = priCompList + compList
   - Update dependencies to link all to primary
   - m.out.Metadata.Tools = buildToolListWithPrimary(primary)
     (Preserves primary's tools, adds sbomasm tool)
8. Write output
```

**Note on Tools Handling:** Unlike regular flat merge which combines tools from all SBOMs, flat merge with `--primary` preserves only the primary SBOM's tools and appends the sbomasm tool. This maintains consistency with assembly merge behavior where the primary SBOM is considered the "owner" of the merged document.

## Testing

### Test Cases

1. **Basic**: Primary + 1 secondary
2. **Multiple**: Primary + 2+ secondaries
3. **Metadata preservation**: Serial number, supplier, licenses preserved
4. **isExternal preservation**: Values from source SBOMs kept
5. **Tools preservation**: Only primary's tools + sbomasm (not combined from all)
6. **Error**: Primary file in input args
7. **Error**: No secondary SBOMs

### Example Test

```go
func TestFlatMergeWithPrimary_Basic(t *testing.T) {
    // Primary SBOM with metadata
    // Secondary SBOM with components
    // Merge and verify:
    // - Primary's serial number preserved
    // - Primary's metadata preserved
    // - All components flat in output
    // - Dependencies linked to primary
}
```

## Acceptance Criteria

- [x] `--primary` flag works with `--flatMerge`
- [x] Primary SBOM's serial number preserved
- [x] Primary SBOM's metadata preserved
- [x] All components merged flat
- [x] `isExternal` values preserved from source
- [x] Primary SBOM's tools preserved (not combined from all SBOMs)
- [x] Validation: primary not in input args
- [x] Validation: at least 1 secondary required
- [x] Test coverage > 80%
- [x] Documentation updated

## Related

- Phase 1: [Assembly Merge with `--primary`](assembly-merge-primary-flag-design.md)
- Issue: [#312](https://github.com/interlynk-io/sbomasm/issues/312)
