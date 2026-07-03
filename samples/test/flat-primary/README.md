# Flat Merge with `--primary` Test Files

This directory contains test files for the flat merge with `--primary` flag feature (Phase 2).

## Files

| File | Description |
|------|-------------|
| `primary.cdx.json` | Python wheel SBOM (primary) - contains components with `isExternal: true` |
| `secondary.cdx.json` | JavaScript bundle SBOM - contains components without `isExternal` (implicitly bundled) |

## Test Command

```bash
sbomasm assemble \
  --flatMerge \
  --primary primary.cdx.json \
  secondary.cdx.json \
  -o merged.json
```

## Expected Output

The merged SBOM will have:

1. **Document root**: `python-wheel` from primary (no `isExternal`)
2. **Serial number**: Preserved from primary (`urn:uuid:11111111-1111-1111-1111-111111111111`)
3. **Metadata**: Supplier and licenses preserved from primary, and sbomasm tool is appended.
4. **Components** (flat list):
   - `numpy` - with `isExternal: true` (from primary)
   - `requests` - with `isExternal: true` (from primary)
   - `react` - no `isExternal` (from secondary, bundled)
   - `lodash` - no `isExternal` (from secondary, bundled)
5. **Dependencies**: All linked to primary's dependency tree

## Key Features Tested

- ✅ Primary SBOM's identity preserved (serial, metadata)
- ✅ Flat component structure (no nesting)
- ✅ `isExternal` values preserved from source SBOMs
- ✅ Secondary SBOM's primary becomes regular component
- ✅ All components linked to primary's dependencies

## Validation

```bash
# Check output is valid CycloneDX
cat merged.json | jq '.metadata.component.name'  # Should be "python-wheel"
cat merged.json | jq '.serialNumber'              # Should match primary
```
