# Implementation Plan: SBOM Augmentation Feature (Issue #219)

## Issue Summary
GitHub Issue: https://github.com/interlynk-io/sbomasm/issues/219

The user needs to augment existing SBOMs with additional components and dependency relationships **without** introducing a new root package. Current implementation always requires creating a new root package when assembling SBOMs, which causes duplicate or unwanted root components when trying to simply add delta information to an existing SBOM.

## Problem Analysis

### Current Behavior
1. **Forced Root Package Creation**: The `assemble` command always requires app name/version parameters (`-n`, `-v`, `-t`) and creates a new root package, even when the user wants to preserve the existing primary component.

2. **Configuration Validation**: In `pkg/assemble/config.go:276-285`, the configuration validation enforces that app name and version are required, making it impossible to skip root package creation.

3. **Merge Strategies**: Current merge strategies (flat, hierarchical, assembly) all assume creating a new primary component that wraps the input SBOMs:
   - **Flat merge**: Creates new root with all components flattened
   - **Hierarchical merge**: Creates new root with input primary components as children
   - **Assembly merge**: Creates new root but keeps relationships independent

4. **Component Deduplication**: The `uniqueComponentService` deduplicates components based on `type-name-version` but doesn't handle the case where the primary component should be preserved from one of the inputs.

### Root Cause
The architecture assumes all assembly operations are combining multiple independent SBOMs into a new product, rather than augmenting an existing SBOM with additional information. There's no concept of a "primary SBOM" that should retain its structure while incorporating delta changes.

## Proposed Solution

### 1. New Augmentation Mode
Introduce a new **augmentation mode** that allows merging delta SBOMs into a primary SBOM without creating a new root package.

### 2. Command Line Interface Changes

#### Option A: Primary SBOM Flag (Recommended)
```bash
sbomasm assemble --primary-sbom sbom-1.json --augment sbom-2.json -o sbom-3.json
```

#### Option B: Component Linking via Identifiers
```bash
sbomasm assemble --primary-sbom sbom-1.json --method purl --id 'pkg:npm/component@1.0.0' sbom-2.json -o sbom-3.json
```

#### Option C: Configuration File Approach
```yaml
augment:
  primary_sbom: sbom-1.json
  method: purl  # or cpe, or name-version
  mappings:
    - target: 'pkg:npm/c1@1.0.0'
      delta: sbom-2.json
    - target: 'pkg:npm/c3@1.0.0'  
      delta: sbom-3.json
```

### 3. Required Code Changes

#### 3.1 Command Structure (`cmd/assemble.go`)
- Add new flags: `--primary-sbom`, `--augment`, `--method`, `--id`
- Make `-n`, `-v`, `-t` optional when using augmentation mode
- Add validation for augmentation-specific parameters

#### 3.2 Configuration Updates (`pkg/assemble/config.go`)
- Add `AugmentMode` struct:
  ```go
  type augmentMode struct {
      Enabled      bool
      PrimarySBOM  string
      Method       string // "purl", "cpe", "name-version"
      Mappings     []ComponentMapping
  }
  ```
- Update validation to skip app name/version requirements in augment mode
- Add primary SBOM validation

#### 3.3 New Augmentation Logic (`pkg/assemble/augment.go`)
Create new file with augmentation-specific logic:
- `loadPrimarySBOM()`: Load and preserve primary SBOM structure
- `findTargetComponent()`: Locate component to augment using specified method
- `mergeComponents()`: Add new components without duplicating existing ones
- `mergeDependencies()`: Add new dependency relationships
- `mergeMetadata()`: Optionally merge/override metadata fields

#### 3.4 Combiner Updates (`pkg/assemble/combiner.go`)
- Add augmentation path in `combine()` method
- Route to augmentation logic when mode is enabled

#### 3.5 CDX Implementation (`pkg/assemble/cdx/augment.go`)
- Implement CycloneDX-specific augmentation:
  - Preserve primary component from base SBOM
  - Match components using BOMRef, PURL, or CPE
  - Merge component trees at specified attachment points
  - Handle dependency graph updates

#### 3.6 SPDX Implementation (`pkg/assemble/spdx/augment.go`)
- Implement SPDX-specific augmentation:
  - Preserve primary package
  - Match packages using SPDX identifiers or external refs
  - Update relationships without duplicating

## Implementation Steps

### Phase 1: Core Infrastructure (Week 1)
1. Add command-line flags and parameters
2. Update configuration structures
3. Implement validation logic for augmentation mode
4. Create base augmentation interfaces

### Phase 2: Augmentation Logic (Week 2)
1. Implement primary SBOM loading and preservation
2. Create component matching algorithms (PURL, CPE, name-version)
3. Implement component and dependency merging
4. Handle metadata merging/override options

### Phase 3: Format-Specific Implementation (Week 3)
1. Complete CycloneDX augmentation
2. Complete SPDX augmentation
3. Handle format-specific edge cases
4. Ensure proper ID mapping and resolution

### Phase 4: Testing & Documentation (Week 4)
1. Unit tests for augmentation logic
2. Integration tests with sample SBOMs
3. Update documentation and examples
4. Performance testing with large SBOMs

## Test Cases

### Basic Augmentation
1. **Single Component Addition**: Add C4 to SBOM with C1, C2, C3
2. **Dependency Addition**: Add relationships C1→C4, C4→C3
3. **Metadata Override**: Update component metadata (version, licenses, etc.)

### Complex Scenarios
1. **Multiple Delta SBOMs**: Apply multiple augmentations in sequence
2. **Nested Components**: Augment components within component trees
3. **Circular Dependencies**: Handle circular dependency detection
4. **Large SBOMs**: Performance with 10,000+ components

### Error Cases
1. **Missing Target Component**: Handle when specified component not found
2. **Conflicting Information**: Resolve conflicts between base and delta
3. **Invalid Relationships**: Prevent invalid dependency relationships

## Backwards Compatibility

1. **Existing Commands**: All existing assemble modes remain unchanged
2. **Configuration Files**: Old configs continue to work
3. **Default Behavior**: Without augmentation flags, behavior is identical

## Performance Considerations

1. **Component Lookup**: Use hash maps for O(1) component lookup
2. **Memory Usage**: Stream processing for large SBOMs
3. **Deduplication**: Efficient duplicate detection algorithms

## Security Implications

1. **Input Validation**: Validate all external references (PURLs, CPEs)
2. **Cycle Prevention**: Prevent circular dependencies
3. **Data Integrity**: Preserve cryptographic hashes and signatures

## Documentation Updates

1. **User Guide**: Add augmentation examples and use cases
2. **API Documentation**: Document new interfaces and methods
3. **Migration Guide**: Help users transition from workarounds

## Future Enhancements

1. **Batch Operations**: Support multiple augmentations in single command
2. **Conflict Resolution**: Advanced strategies for handling conflicts
3. **Validation Rules**: Custom validation for augmented SBOMs
4. **Rollback Support**: Undo augmentation operations

## Success Metrics

1. **Functionality**: Successfully augment SBOMs without new root packages
2. **Performance**: < 2 second processing for 1000-component SBOMs
3. **Compatibility**: 100% backward compatibility with existing features
4. **User Experience**: Intuitive CLI interface and clear error messages

## Related Issues
- Issue #128: Discussion about primary component selection
- Issue #134: Primary component file specification

## References
- Original Issue: https://github.com/interlynk-io/sbomasm/issues/219
- CycloneDX Specification: https://cyclonedx.org/specification/
- SPDX Specification: https://spdx.github.io/spdx-spec/