# Design Draft: `--primary` Flag for Assembly Merge

**Issue:** [#312](https://github.com/interlynk-io/sbomasm/issues/312)  
**Status:** ✅ **IMPLEMENTED**  
**Author:** Claude  
**Date:** 2026-06-22

---

## 1. Overview

### Problem Statement
Current `--assemblyMerge` creates a **new synthetic primary component** and nests all input SBOM primaries as its sub-components. Users need a way to merge SBOM A into SBOM B while:
- **Preserving B's primary** as the document root
- **Nesting A's primary** as a sub-component of B's primary
- **Linking A's primary** as a direct dependency of B's primary

### Use Case
Python wheels shipping JavaScript bundles:
- SBOM A = JavaScript bundle (from webpack plugin)
- SBOM B = Python wheel package
- Result = JS bundle nested inside Python package's primary component

---

## 2. Current vs Proposed Behavior

### Current: `assemblyMerge A.json B.json`

```json
{
  "metadata": {
    "component": {
      "name": "sbomasm-assembly",      // ← Synthetic primary (NEW)
      "version": "1.0.0",
      "bom-ref": "urn:uuid:...",
      "components": [                   // ← A and B primaries here
        {"name": "cs-template", "bom-ref": "pkg:npm/cs-template@0.0.1"},
        {"name": "cs.template", "bom-ref": "cs.template==2026.2.3.0.dev16"}
      ]
    }
  },
  "components": [                      // ← A and B components (no primaries)
    {"name": "lodash", "purl": "..."},
    {"name": "numpy", "purl": "..."}
  ],
  "dependencies": [
    {"ref": "pkg:npm/cs-template@0.0.1", "dependsOn": [...]},
    {"ref": "cs.template==2026.2.3.0.dev16", "dependsOn": [...]}
  ]
}
```

**Issues:**
- Original B identity (`cs.template`) is lost
- No dependency link from synthetic primary to input primaries

---

### Proposed: `assemblyMerge --primary B.json A.json`

```json
{
  "metadata": {
    "component": {
      "name": "cs.template",          // ← B's primary preserved
      "version": "2026.2.3.0.dev16",
      "bom-ref": "cs.template==2026.2.3.0.dev16",
      "author": "CONTACT Software GmbH",
      "components": [                   // ← A's primary nested here
        {
          "type": "application",
          "name": "cs-template",
          "version": "0.0.1",
          "bom-ref": "pkg:npm/cs-template@0.0.1",
          "author": "CONTACT Software GmbH",
          "purl": "pkg:npm/cs-template@0.0.1"
        }
      ]
    }
  },
  "components": [
    {"name": "numpy", ...},            // ← B's components only
    {"name": "pyinotify", ...}
    // Note: A's primary is NOT in components[] - only in metadata.component.components
  ],
  "dependencies": [
    {
      "ref": "cs.template==2026.2.3.0.dev16",
      "dependsOn": [                   // ← UPDATED: includes A-primary
        "numpy==2.4.2",
        "pyinotify==0.9.6",
        "pkg:npm/cs-template@0.0.1"   // ← Reference to sub-component
      ]
    },
    {"ref": "pkg:npm/cs-template@0.0.1", "dependsOn": [...]},  // A's deps
    {"ref": "numpy==2.4.2"},
    {"ref": "pyinotify==0.9.6"}
  ]
}
```

**Benefits:**
- B's identity preserved
- A nested as sub-component (assembly)
- A's primary (sub-component) referenced as direct dependency of B's primary
- All original dependency relationships maintained
- Clean structure: sub-component defined once, referenced via `bom-ref`

### Clarification: Sub-Component vs Dependency

Per [Steve Springett's clarification](https://cyclonedx.slack.com/archives/CVA0G10FN/p1781767159810579) on the CycloneDX specification:

> A sub-component **CAN also be a dependency** - they are not mutually exclusive. The static linking example illustrates it perfectly: a library embedded in a binary is both contained (sub-component) and depended upon.

This means:
- The JS component (`cs-template`) is a **sub-component** of the Python primary (`cs.template`) via `metadata.component.components`
- The JS component is also a **direct dependency** of the Python primary via `dependencies[].dependsOn`
- The `bom-ref` is defined once in the sub-component array and referenced in dependencies

---

## 3. Command-Line Interface

### New Flag

```go
// In cmd/assemble.go
--primary string   // Path to the SBOM whose primary becomes the document root
```

### Usage

```bash
# Merge A into B (B's primary becomes root, A nested as sub-component)
sbomasm assemble \
  --assemblyMerge \
  --primary B.json \
  A.json \
  -o output.json

# Multiple SBOMs into B
sbomasm assemble \
  --assemblyMerge \
  --primary B.json \
  A1.json A2.json A3.json \
  -o output.json
```

### Validation Rules

| Rule | Behavior |
|------|----------|
| `--primary` requires `--assemblyMerge` or `--flatMerge` | Error if used with other merge types |
| `--primary` must be one of the input files (assembly) | Error if path not in input list |
| `--primary` must NOT be in input files (flat) | Error if primary in input list |
| Exactly one primary file | Error if multiple `--primary` values |
| Only one input file | Error (need at least 2: primary + one to merge) |

### Flag Interactions

| Flag Combination | Behavior |
|------------------|----------|
| `--assemblyMerge` only | Current behavior (synthetic primary) |
| `--assemblyMerge --primary B.json` | **New**: B's primary as root |
| `--flatMerge --primary B.json` | **Phase 2**: B's primary as document root, flat structure |
| `--augmentMerge --primary ...` | Error: not supported |
| `--hierMerge --primary ...` | Error: hierMerge is default assembly behavior |

---

## 4. Implementation Details

### 4.1 Configuration Changes

```go
// pkg/assemble/config.go

type AssembleConfig struct {
    // ... existing fields ...

    // NEW: Primary file for assembly merge with primary
    PrimaryFile string `yaml:"primary_file"`

    // NEW: Derived field - which SBOM is the primary
    IsAssemblyMergeWithPrimary bool
}

func (ac *AssembleConfig) Validate() error {
    // ... existing validation ...

    // NEW: Validate primary file
    if ac.AssemblyMerge && ac.PrimaryFile != "" {
        // Must be one of the input files
        found := false
        for _, f := range ac.Input.Files {
            if f == ac.PrimaryFile {
                found = true
                break
            }
        }
        if !found {
            return fmt.Errorf("--primary file must be one of the input SBOMs")
        }
        ac.IsAssemblyMergeWithPrimary = true
    }

    return nil
}
```

### 4.2 Merge Logic Changes

```go
// pkg/assemble/cdx/merge.go

func (m *merge) combinedMerge() error {
    // ... existing setup ...

    if m.settings.Assemble.IsAssemblyMergeWithPrimary {
        // Identify primary and secondary SBOMs
        primaryIdx := findPrimaryIndex(m.in, m.settings.Assemble.PrimaryFile)
        secondaryIdxs := allOtherIndices(len(m.in), primaryIdx)

        // Build output with primary's metadata
        m.initOutBomWithPrimary(m.in[primaryIdx])

        // Setup primary component from primary SBOM
        m.out.Metadata.Component = m.setupPrimaryFromExisting(m.in[primaryIdx])

        // Add secondary primaries as sub-components of primary
        var subComponents []cydx.Component
        for _, idx := range secondaryIdxs {
            subComp := extractPrimaryComponent(m.in[idx])
            subComponents = append(subComponents, subComp)
        }
        m.out.Metadata.Component.Components = &subComponents

        // Add sbomasm tool to metadata (preserve primary's existing tools)
        m.out.Metadata.Tools = m.buildToolListWithPrimary(m.in[primaryIdx])

        // Build component list (secondary primaries NOT included - only in sub-components)
        compList := buildComponentListExcludingPrimary(m.in, cs, secondaryIdxs)
        m.out.Components = &compList

        // Build dependencies (update primary's deps to include secondary primaries)
        depList := buildDependencyListWithPrimaryLinks(m.in, cs, primaryIdx)
        m.out.Dependencies = &depList

    } else if m.settings.Assemble.AssemblyMerge {
        // EXISTING: assembly merge with synthetic primary
        // ... current code ...
    }
    // ...
}
```

### 4.3 Key Functions to Add

```go
// Find which input SBOM is the primary
func findPrimaryIndex(boms []*cydx.BOM, primaryPath string) int

// Extract primary component from a BOM
func extractPrimaryComponent(bom *cydx.BOM) cydx.Component

// Build component list excluding secondary primaries (they're in sub-components)
func buildComponentListExcludingPrimary(boms []*cydx.BOM, cs *uniqueComponentService, excludeIdxs []int) []cydx.Component

// Build dependencies and add link from primary to secondary primaries
func buildDependencyListWithPrimaryLinks(
    boms []*cydx.BOM,
    cs *uniqueComponentService,
    primaryIdx int,
) []cydx.Dependency

// Initialize output BOM from primary SBOM metadata
func (m *merge) initOutBomWithPrimary(primaryBom *cydx.BOM)

// Setup primary component from existing SBOM (preserve all fields)
func (m *merge) setupPrimaryFromExisting(bom *cydx.BOM) *cydx.Component

// Build tools list preserving primary's tools and adding sbomasm
func (m *merge) buildToolListWithPrimary(primaryBom *cydx.BOM) *cydx.ToolsChoice
```

### 4.4 Dependency Linking Logic

**Critical:** When `--primary` is used, the primary SBOM's primary component gets additional dependencies on all secondary SBOMs' primary components.

```go
func buildDependencyListWithPrimaryLinks(boms []*cydx.BOM, cs *uniqueComponentService, primaryIdx int) []cydx.Dependency {
    var deps []cydx.Dependency

    // Collect all dependency entries from all SBOMs
    for _, bom := range boms {
        deps = append(deps, extractDependencies(bom)...)
    }

    // Find primary's bom-ref
    primaryRef := getPrimaryBomRef(boms[primaryIdx])

    // Collect secondary primary refs
    var secondaryRefs []string
    for i, bom := range boms {
        if i != primaryIdx {
            ref := getPrimaryBomRef(bom)
            secondaryRefs = append(secondaryRefs, ref)
        }
    }

    // Find or create primary's dependency entry
    primaryDepIdx := findDependencyRef(deps, primaryRef)
    if primaryDepIdx == -1 {
        // Create new dependency entry for primary
        deps = append(deps, cydx.Dependency{
            Ref: primaryRef,
            Dependencies: &secondaryRefs,
        })
    } else {
        // Append to existing dependencies
        *deps[primaryDepIdx].Dependencies = append(
            *deps[primaryDepIdx].Dependencies,
            secondaryRefs...,
        )
    }

    return deps
}
```

### 4.5 Tools Handling

When using `--primary`, preserve the primary SBOM's existing tools and add sbomasm:

```go
func (m *merge) buildToolListWithPrimary(primaryBom *cydx.BOM) *cydx.ToolsChoice {
    tools := cydx.ToolsChoice{
        Components: &[]cydx.Component{},
        Services:   &[]cydx.Service{},
    }

    // 1. Preserve primary's existing tools
    if primaryBom.Metadata != nil && primaryBom.Metadata.Tools != nil {
        // Copy old-format tools
        if primaryBom.Metadata.Tools.Tools != nil {
            for _, tool := range *primaryBom.Metadata.Tools.Tools {
                *tools.Components = append(*tools.Components, cydx.Component{
                    Type:    cydx.ComponentTypeApplication,
                    Name:    tool.Name,
                    Version: tool.Version,
                    Supplier: &cydx.OrganizationalEntity{
                        Name: tool.Vendor,
                    },
                })
            }
        }
        // Copy component-format tools
        if primaryBom.Metadata.Tools.Components != nil {
            for _, tool := range *primaryBom.Metadata.Tools.Components {
                comp, _ := cloneComp(&tool)
                *tools.Components = append(*tools.Components, *comp)
            }
        }
        // Copy services
        if primaryBom.Metadata.Tools.Services != nil {
            for _, service := range *primaryBom.Metadata.Tools.Services {
                serv, _ := cloneService(&service)
                *tools.Services = append(*tools.Services, *serv)
            }
        }
    }

    // 2. Add sbomasm tool (marking this merge operation)
    sbomasmTool := cydx.Component{
        Type:        cydx.ComponentTypeApplication,
        Name:        "sbomasm",
        Version:     version.GetVersionInfo().GitVersion,
        Description: "Assembler & Editor for your sboms",
        Supplier: &cydx.OrganizationalEntity{
            Name: "Interlynk",
            URL:  &[]string{"https://interlynk.io"},
            Contact: &[]cydx.OrganizationalContact{
                {Email: "support@interlynk.io"},
            },
        },
        Licenses: &cydx.Licenses{
            {License: &cydx.License{ID: "Apache-2.0"}},
        },
    }
    *tools.Components = append(*tools.Components, sbomasmTool)

    // 3. Deduplicate
    uniqTools := lo.UniqBy(*tools.Components, func(c cydx.Component) string {
        return fmt.Sprintf("%s-%s", c.Name, c.Version)
    })
    uniqServices := lo.UniqBy(*tools.Services, func(s cydx.Service) string {
        return fmt.Sprintf("%s-%s", s.Name, s.Version)
    })

    tools.Components = &uniqTools
    tools.Services = &uniqServices

    return &tools
}
```

---

## 5. Component Placement Rules

| Source | Placement | Rationale |
|--------|-----------|-----------|
| Primary SBOM's primary | `metadata.component` | Document root |
| Secondary SBOMs' primaries | `metadata.component.components[]` | Assemblies/sub-components |
| Secondary SBOMs' non-primary components | `components[]` (flat) | Standard flattening |
| Primary SBOM's non-primary components | `components[]` (flat) | Standard flattening |

**Note:** Per CycloneDX specification, a **sub-component can also be a dependency**. The secondary primary is defined once in `metadata.component.components[]` and can be referenced anywhere in `dependencies[]` via its `bom-ref`. No duplication in `components[]` is needed.

---

## 5.1 Metadata Preservation (Assembly Merge with Primary)

When using `--primary` with `--assemblyMerge`, the primary SBOM's metadata is preserved to maintain document identity:

| Property | Behavior | Rationale |
|----------|----------|-----------|
| **Serial Number** | Preserved from primary SBOM | Maintains document identity |
| **Timestamp** | Updated to current UTC time | Reflects modification |
| **Supplier** | Preserved from primary SBOM | Maintains provenance |
| **Licenses** | Preserved from primary SBOM | Maintains licensing info |
| **Authors** | Preserved from primary SBOM | Maintains attribution |
| **Tools** | Primary's tools + sbomasm tool added | Audit trail |

This matches the behavior of **augment merge** - preserving the primary SBOM's identity while enriching it with secondary content.

---

## 6. BOM-Ref Handling

BOM-refs must remain unique across the merged SBOM. The existing `uniqueComponentService` handles this.

```go
// If secondary primary's bom-ref conflicts with existing component,
// it gets a new unique ref. The dependency graph must be updated
// to use the new ref.
```

---

## 7. Edge Cases

### 7.1 Secondary SBOM Has No Primary

**Behavior:** Error or skip (with warning)
```
Error: Secondary SBOM A.json has no primary component
```

### 7.2 Primary SBOM Has No Primary

**Behavior:** Error
```
Error: Primary SBOM B.json must have a primary component
```

### 7.3 Duplicate BOM-Refs

**Behavior:** Use existing deduplication logic
- Generate new unique bom-ref for conflicting component
- Update all references in dependency graph

### 7.4 Cyclic Dependencies

**Behavior:** No special handling needed - CycloneDX allows cyclic refs

### 7.5 Spec Version Mismatch

**Behavior:**
- Upgrade all components to target spec version
- Handle fields that don't exist in older versions

---

## 8. Testing Scenarios

### 8.1 Happy Path

- Valid primary SBOM (B) with components
- Valid secondary SBOM (A) with components
- Output has B as root, A as sub-component
- Dependencies correctly linked

### 8.2 Multiple Secondaries

- Primary + 3 secondary SBOMs
- All 3 secondaries nested under primary
- All 3 appear in primary's dependencies

### 8.3 Empty Secondary

- Secondary has primary but no other components
- Should still work, only primary nested

### 8.4 Missing Primary Component

- Error handled gracefully

### 8.5 BOM-Ref Collisions

- Secondary primary has same bom-ref as existing component
- Should deduplicate and update refs

---

## 9. Documentation Updates

### README.md

Add new section:

```markdown
### Assembly Merge with Primary

Merge SBOMs into an existing SBOM's primary component:

```bash
sbomasm assemble \
  --assemblyMerge \
  --primary existing-sbom.json \
  new-component.json \
  -o merged.json
```

This nests `new-component.json`'s primary as a sub-component of 
`existing-sbom.json`'s primary, and adds the necessary dependency links.
```

### CLI Help

Update `--help` output:

```
--primary string   Path to SBOM whose primary becomes the document root.
                   Only valid with --assemblyMerge. The primary SBOM's 
                   primary component becomes the root, and other input 
                   SBOMs' primaries are nested as sub-components.
```

---

## 10. Future Considerations

### 10.1 Phase 2: `flatMerge --primary` ✅ COMPLETED

See [Flat Merge with Primary Design](flatmerge-primary-design.md). The `--primary` flag has been extended to work with `flatMerge` strategy, allowing users to preserve an existing SBOM's primary as the document root in a flat structure.

### 10.2 Phase 3: `isExternal` Flag (Future)

For the Python wheel use case, add `--is-external` flag to `flatMerge`:

```bash
sbomasm assemble \
  --flatMerge \
  --primary B.json \
  --mark-secondary-external \
  A.json \
  -o output.json
```

Marks components from secondary SBOMs as `isExternal: true` (runtime deps), 
primary's components as `isExternal: false` (bundled).

### 10.2 Extending to SPDX

Similar logic applies to SPDX:
- Primary SBOM's `DESCRIBES` relationship preserved
- Secondary primaries become `CONTAINS` relationships

---

## 11. Open Questions

1. **Should `--primary` support multiple primary SBOMs?**  
   → No, single primary only for clear semantics.

2. **Should this be a separate merge strategy instead of a flag?**  
   → Flag is preferred to extend existing `assemblyMerge` semantics.

3. **How to handle `metadata.tools`?**  
   → Preserve only primary SBOM's tools + append sbomasm tool. This maintains consistency with assembly merge semantics where the primary SBOM is the "owner" of the merged document.

4. **How to handle `metadata.authors`?**  
   → Preserve primary SBOM's authors, optionally append others.

---

## 12. Acceptance Criteria

- [x] `--primary` flag added to CLI
- [x] Validation rules implemented
- [x] Primary SBOM's primary becomes document root
- [x] Secondary primaries nested as sub-components
- [x] Secondary primaries added to primary's dependencies
- [x] All original dependency relationships preserved
- [x] BOM-refs remain unique
- [x] Primary SBOM's tools preserved and sbomasm tool added
- [x] Test coverage > 80%
- [x] Documentation updated
- [x] Example provided in repo

---

**Status:** Fully implemented and tested. See [Flat Merge with Primary Design](flatmerge-primary-design.md) for Phase 2.
