# Implementation Plan: Add Augment and Attach Merge Capabilities to sbomasm

## Issue Summary
GitHub Issue #219: [Add components and dependency relationships to an existing SBOM](https://github.com/interlynk-io/sbomasm/issues/219)

The user wants to augment existing SBOMs by adding missing components and dependencies without creating a new root package. Currently, sbomasm's assemble command always creates a new root package, which is undesirable when the goal is to enhance an existing SBOM with additional information.

## Problem Analysis

### Current Behavior
1. **Forced Root Package Creation**: The current `assemble` command requires a root package configuration in `config.yaml`. If not provided, it errors; if provided, it creates a new root package that wraps the existing SBOMs.

2. **Three Merge Modes**:
   - **Flat Merge**: Creates a new root with all components at the same level
   - **Hierarchical Merge**: Creates a new root with original root packages as children
   - **Assembly Merge**: Creates a new root with components organized under their original roots

3. **Component Deduplication**: Uses `uniqueComponentService` that matches components by `Type-Name-Version` (case-insensitive) and assigns new BOMRefs to prevent duplicates.

4. **No Component Matching by Identifiers**: Current implementation doesn't support matching components by purl, CPE, or name-version for selective updates.

### Root Cause
The fundamental issue is architectural: the current design assumes all merge operations create a new SBOM with a new root package. There's no mechanism to:
1. Designate one SBOM as primary (keeping its root)
2. Match components across SBOMs using identifiers (purl, CPE, name-version)
3. Merge/update component fields selectively
4. Attach sub-SBOMs to specific components

## Proposed Solution

### Two New Merge Modes

#### 1. Augment Merge
- **Purpose**: Merge components and dependencies from secondary SBOMs into a primary SBOM
- **Key Features**:
  - Primary SBOM's root package is preserved
  - Components matched by purl/CPE/name-version
  - Two merge strategies: `if-missing-or-empty` (default) and `overwrite`
  - Supports both SPDX and CycloneDX formats

#### 2. Attach Merge
- **Purpose**: Attach a component SBOM to a specific component in the primary SBOM
- **Key Features**:
  - Targets a specific component using its identifier
  - Useful for adding third-party supplied SBOMs
  - Creates proper hierarchical relationships

## Implementation Details

### 1. Command Line Interface Changes

**File**: `cmd/assemble.go`

Add new flags:
```go
// Augment merge flags
assembleCmd.Flags().BoolP("augmentMerge", "", false, "augment merge mode")
assembleCmd.Flags().StringP("primary", "p", "", "primary SBOM file")
assembleCmd.Flags().StringP("match", "", "purl", "matching strategy: purl, cpe, name-version")
assembleCmd.Flags().StringP("merge-mode", "", "if-missing-or-empty", "merge mode: if-missing-or-empty, overwrite")

// Attach merge flags
assembleCmd.Flags().BoolP("attachMerge", "", false, "attach merge mode")
assembleCmd.Flags().StringP("id", "", "", "component identifier for attach merge")

// Mutual exclusivity
assembleCmd.MarkFlagsMutuallyExclusive("flatMerge", "hierMerge", "assemblyMerge", "augmentMerge", "attachMerge")
```

### 2. Configuration Structure Updates

**File**: `pkg/assemble/config.go`

```go
type assemble struct {
    // Existing fields...
    AugmentMerge      bool   `yaml:"augment_merge"`
    AttachMerge       bool   `yaml:"attach_merge"`
    PrimaryFile       string `yaml:"primary_file"`
    MatchStrategy     string `yaml:"match_strategy"`     // purl, cpe, name-version
    MergeMode         string `yaml:"merge_mode"`         // if-missing-or-empty, overwrite
    ComponentID       string `yaml:"component_id"`       // for attach merge
}
```

### 3. Component Matching Service

**New File**: `pkg/assemble/matcher.go`

```go
type ComponentMatcher interface {
    Match(primary, secondary Component) bool
}

type PurlMatcher struct{}
type CPEMatcher struct{}
type NameVersionMatcher struct{}

type MatcherFactory struct {
    strategy string
}

func (f *MatcherFactory) GetMatcher() ComponentMatcher {
    switch f.strategy {
    case "purl":
        return &PurlMatcher{}
    case "cpe":
        return &CPEMatcher{}
    case "name-version":
        return &NameVersionMatcher{}
    default:
        return &PurlMatcher{}
    }
}
```

### 4. Augment Merge Implementation

**New File**: `pkg/assemble/cdx/augment.go`

```go
type augmentMerge struct {
    primary   *cydx.BOM
    secondary []*cydx.BOM
    settings  *MergeSettings
    matcher   ComponentMatcher
}

func (a *augmentMerge) merge() error {
    // 1. Load primary SBOM
    // 2. For each secondary SBOM:
    //    a. Match components using matcher
    //    b. Apply merge strategy (if-missing-or-empty or overwrite)
    //    c. Update dependencies
    // 3. Write merged SBOM
}

func (a *augmentMerge) mergeComponent(primary, secondary *cydx.Component) {
    if a.settings.MergeMode == "overwrite" {
        a.overwriteFields(primary, secondary)
    } else {
        a.fillMissingFields(primary, secondary)
    }
}

func (a *augmentMerge) fillMissingFields(primary, secondary *cydx.Component) {
    // Only update empty/nil fields in primary
    if primary.Description == "" && secondary.Description != "" {
        primary.Description = secondary.Description
    }
    // ... similar for other fields
}
```

**File**: `pkg/assemble/spdx/augment.go` (Similar structure for SPDX)

### 5. Attach Merge Implementation

**New File**: `pkg/assemble/cdx/attach.go`

```go
type attachMerge struct {
    primary   *cydx.BOM
    secondary *cydx.BOM
    settings  *MergeSettings
    targetID  string
}

func (a *attachMerge) merge() error {
    // 1. Find target component in primary SBOM
    // 2. Add secondary SBOM components as children
    // 3. Update dependency relationships
    // 4. Write merged SBOM
}
```

### 6. Modified Merge Flow

**File**: `pkg/assemble/combiner.go`

```go
func (c *combiner) combine() error {
    log := logger.FromContext(*c.c.ctx)
    
    // New logic for augment/attach modes
    if c.c.Assemble.AugmentMerge {
        return c.augmentCombine()
    }
    
    if c.c.Assemble.AttachMerge {
        return c.attachCombine()
    }
    
    // Existing merge logic...
}

func (c *combiner) augmentCombine() error {
    // Dispatch to format-specific augment merge
}

func (c *combiner) attachCombine() error {
    // Dispatch to format-specific attach merge
}
```

### 7. Validation Updates

**File**: `pkg/assemble/config.go`

Add validation for new modes:
```go
func (c *config) validate() error {
    // Existing validation...
    
    if c.Assemble.AugmentMerge || c.Assemble.AttachMerge {
        if c.Assemble.PrimaryFile == "" {
            return fmt.Errorf("primary SBOM file required for augment/attach merge")
        }
        
        // Skip root package validation for augment/attach
        c.skipRootPackageValidation = true
    }
    
    if c.Assemble.AttachMerge && c.Assemble.ComponentID == "" {
        return fmt.Errorf("component ID required for attach merge")
    }
    
    // Validate match strategy
    validStrategies := []string{"purl", "cpe", "name-version"}
    if !lo.Contains(validStrategies, c.Assemble.MatchStrategy) {
        return fmt.Errorf("invalid match strategy: %s", c.Assemble.MatchStrategy)
    }
}
```

## Testing Strategy

### Unit Tests
1. **Component Matching**: Test purl, CPE, and name-version matching
2. **Field Merging**: Test if-missing-or-empty and overwrite modes
3. **Dependency Resolution**: Test dependency graph updates
4. **Format Support**: Test both CycloneDX and SPDX formats

### Integration Tests
1. **Augment Merge Scenarios**:
   - Single component update
   - Multiple component updates
   - Adding new components
   - Updating dependencies
   
2. **Attach Merge Scenarios**:
   - Attaching to root component
   - Attaching to nested component
   - Multiple attachments

### Test Files
- Create test SBOMs matching the user's examples (sbom-1.json, sbom-2.json)
- Validate output matches expected sbom-3.json

## Documentation Updates

### README.md
Add new examples:
```bash
# Augment merge
sbomasm assemble --augmentMerge --primary sbom-1.json sbom-2.json -o merged.json

# Augment with overwrite
sbomasm assemble --augmentMerge --merge-mode overwrite --match cpe --primary sbom-1.json sbom-2.json -o merged.json

# Attach merge
sbomasm assemble --attachMerge --primary sbom-1.json --match purl --id "pkg:maven/org.apache.commons/commons-lang3@3.12.0" commons-lang3.json -o merged.json
```

### Command Help Text
Update `assembleCmd.Long` to include augment and attach examples

## Performance Considerations

1. **Component Matching Performance**:
   - Build indices for fast lookups (O(1) instead of O(n))
   - Cache matched components to avoid repeated comparisons

2. **Memory Usage**:
   - Stream processing for large SBOMs
   - Avoid loading all SBOMs into memory simultaneously

## Security Implications

1. **Input Validation**:
   - Validate component identifiers to prevent injection
   - Sanitize purl/CPE strings
   
2. **File Access**:
   - Validate file paths
   - Check file permissions

## Backwards Compatibility

- All existing merge modes remain unchanged
- New flags are additive and don't affect existing workflows
- Config file format is backwards compatible (new fields are optional)

## Migration Path

For users currently working around the limitation:
1. Document how to migrate from workaround solutions
2. Provide conversion scripts if needed
3. Clear deprecation timeline if any features change

## Edge Cases

1. **Circular Dependencies**: Detect and prevent circular dependency creation
2. **Conflicting Information**: Clear precedence rules for overwrites
3. **Missing Components**: Handle references to non-existent components
4. **Format Mismatches**: Clear error messages for SPDX-CDX mixing

## Timeline Estimate

Based on the discussion, targeting September 25th release:
- Week 1: Core implementation (augment merge)
- Week 2: Attach merge and testing
- Week 3: Documentation and edge cases

## Follow-up Enhancements

Future iterations could add:
1. Batch configuration file support for multiple augmentations
2. Conflict resolution strategies
3. Validation rules for augmented SBOMs
4. Merge operation logging/audit trail

## References

- Original Issue: https://github.com/interlynk-io/sbomasm/issues/219
- Related Issues: #128, #134 (primary component selection)
- CycloneDX Specification: Component relationships
- SPDX Specification: Package relationships