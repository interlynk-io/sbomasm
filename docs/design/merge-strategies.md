# Merge Strategies Reference

This document describes the four merge strategies available in `sbomasm assemble`, how each is implemented for CycloneDX (CDX) and SPDX, and the implementation behind the design.

## Table of Contents

1. [Overview](#1-overview)
2. [Key Differences Between CDX and SPDX Models](#2-key-differences-between-cdx-and-spdx-models)
3. [Merge Strategies](#3-merge-strategies)
   - 3.1 [Hierarchical Merge](#31-hierarchical-merge-default)
   - 3.2 [Flat Merge](#32-flat-merge)
   - 3.3 [Assembly Merge](#33-assembly-merge)
   - 3.4 [Augment Merge](#34-augment-merge)
4. [Open Question](#4-open-question)

## 1. Overview

`sbomasm assemble` supports four merge strategies for combining multiple SBOMs into one:

| Strategy | Flag | Purpose |
|----------|------|---------|
| **Hierarchical** | `--hierMerge` (default) | Preserves original SBOM structure under a new root |
| **Flat** | `--flatMerge` | Flattens all components to a single level |
| **Assembly** | `--assemblyMerge` | Combines as independent assemblies under a new root |
| **Augment** | `--augmentMerge` | Enriches a primary SBOM with data from secondary SBOMs |

The behavior differs between **CycloneDX** and **SPDX** because the two formats model components and relationships differently.

## 2. Key Differences Between CDX and SPDX Models

### CycloneDX

CDX has **two parallel structures**:

1. **Component tree** (`metadata.component` + `components[]` + nested `.components[]`)
   - Expresses **structural hierarchy**: "who contains what"
   - A component can be a sub-component of another component

2. **Dependency graph** (`dependencies[].dependsOn[]`)
   - Expresses **runtime relationships**: "who depends on what"
   - Independent of the component tree

A component can be both:

- A **sub-component** in the tree (`components[].components[]`)
- AND a **node** in the dependency graph (`dependencies[]`)

### SPDX

SPDX has **one flat structure**:

- All elements live in `packages[]`
- Relationships in `relationships[]` carry all semantics

| Relationship Type | Meaning |
|-------------------|---------|
| `CONTAINS` | Physical/logical containment — "A has B inside it" |
| `DEPENDS_ON` | Runtime dependency — "A needs B" |
| `DESCRIBES` | Document describes this element |

Because SPDX is flat, there is **no native nesting**. Hierarchy must be expressed entirely through relationships.

## 3. Merge Strategies

### 3.1 Hierarchical Merge (default)

**Flag:** `--hierMerge` (or no flag)

**Purpose:** Maintains the original SBOM structure. Each input SBOM's primary component becomes a top-level entry under the new root, and all original components remain nested under their respective primary.

#### CDX Implementation

**Structure:**

- New synthetic root in `metadata.component`
- Input primaries are **top-level peers** in `components[]`
- Each primary's original components are **nested** under it via `.components[]`
- Root has a **dependency** (`dependsOn`) on all input primaries
- Original component dependencies are **preserved**

**Example:**

Input SBOM 1 (Kyverno):

- Primary: `kyverno`
- Components: `oci`, `azcore`
- Dependencies: `kyverno → oci`, `oci → azcore`

Input SBOM 2 (Cosign):

- Primary: `cosign`
- Components: `httpsnoop`, `fulcio`, `rekor`
- Dependencies: `cosign → fulcio/rekor`, `fulcio → httpsnoop`

Output:

```json
{
  "metadata": {
    "component": { "name": "my app", "version": "1.0.0" }
  },
  "components": [
    {
      "name": "kyverno",
      "components": [
        { "name": "oci" },
        { "name": "azcore" }
      ]
    },
    {
      "name": "cosign",
      "components": [
        { "name": "httpsnoop" },
        { "name": "fulcio" },
        { "name": "rekor" }
      ]
    }
  ],
  "dependencies": [
    { "ref": "my app", "dependsOn": ["kyverno", "cosign"] },
    { "ref": "kyverno", "dependsOn": ["oci"] },
    { "ref": "oci", "dependsOn": ["azcore"] },
    { "ref": "cosign", "dependsOn": ["fulcio", "rekor"] },
    { "ref": "fulcio", "dependsOn": ["httpsnoop"] }
  ]
}
```

**Key point:** The root **depends on** the input primaries (not contains them). The nesting is structural via `components[].components[]`.

#### SPDX Implementation

**Structure:**

- New synthetic root Package
- All packages (primaries + originals) are **flat** in `packages[]`
- Root has a **dependency** (`DEPENDS_ON`) on all input primaries
- Original component dependencies are **preserved**

**Example:**

```json
{
  "packages": [
    { "name": "my app", "SPDXID": "SPDXRef-RootPackage" },
    { "name": "kyverno", "SPDXID": "SPDXRef-Package-Kyverno" },
    { "name": "oci", "SPDXID": "SPDXRef-Package-OCI" },
    { "name": "azcore", "SPDXID": "SPDXRef-Package-AzCore" },
    { "name": "cosign", "SPDXID": "SPDXRef-Package-Cosign" },
    { "name": "httpsnoop", "SPDXID": "SPDXRef-Package-Httpsnoop" },
    { "name": "fulcio", "SPDXID": "SPDXRef-Package-Fulcio" },
    { "name": "rekor", "SPDXID": "SPDXRef-Package-Rekor" }
  ],
  "relationships": [
    { "spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-RootPackage", "relationshipType": "DESCRIBES" },
    { "spdxElementId": "SPDXRef-RootPackage", "relatedSpdxElement": "SPDXRef-Package-Kyverno", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-RootPackage", "relatedSpdxElement": "SPDXRef-Package-Cosign", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-Kyverno", "relatedSpdxElement": "SPDXRef-Package-OCI", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-OCI", "relatedSpdxElement": "SPDXRef-Package-AzCore", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-Cosign", "relatedSpdxElement": "SPDXRef-Package-Fulcio", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-Cosign", "relatedSpdxElement": "SPDXRef-Package-Rekor", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-Fulcio", "relatedSpdxElement": "SPDXRef-Package-Httpsnoop", "relationshipType": "DEPENDS_ON" }
  ]
}
```

**Key point:** `DEPENDS_ON` is used from root to primaries because CDX hierarchical merge treats them as **dependencies**, not as bundled sub-assemblies.

### 3.2 Flat Merge

**Flag:** `--flatMerge`

**Purpose:** Flattens everything to a single level. Duplicates are removed (CDX only). Useful for simple component inventories.

#### CDX Implementation

**Structure:**

- New synthetic root in `metadata.component`
- All components (primaries + originals) are **flattened** to top-level `components[]`
- Root has a **dependency** (`dependsOn`) on all input primaries
- Original component dependencies are **preserved**

**Example:**

```json
{
  "metadata": {
    "component": { "name": "my app", "version": "1.0.0" }
  },
  "components": [
    { "name": "kyverno" },
    { "name": "cosign" },
    { "name": "oci" },
    { "name": "azcore" },
    { "name": "httpsnoop" },
    { "name": "fulcio" },
    { "name": "rekor" }
  ],
  "dependencies": [
    { "ref": "my app", "dependsOn": ["kyverno", "cosign"] },
    { "ref": "kyverno", "dependsOn": ["oci"] },
    { "ref": "oci", "dependsOn": ["azcore"] },
    { "ref": "cosign", "dependsOn": ["fulcio", "rekor"] },
    { "ref": "fulcio", "dependsOn": ["httpsnoop"] }
  ]
}
```

**Key point:** Everything is flat, but the **dependency graph is preserved**.

#### SPDX Implementation

**Structure:**

- New synthetic root Package
- All packages (primaries + originals) are **flat** in `packages[]`
- Root has a **dependency** (`DEPENDS_ON`) on all input primaries
- Original component dependencies are **preserved**

**Example:**

```json
{
  "packages": [
    { "name": "my app", "SPDXID": "SPDXRef-RootPackage" },
    { "name": "kyverno", "SPDXID": "SPDXRef-Package-Kyverno" },
    { "name": "cosign", "SPDXID": "SPDXRef-Package-Cosign" },
    { "name": "oci", "SPDXID": "SPDXRef-Package-OCI" },
    { "name": "azcore", "SPDXID": "SPDXRef-Package-AzCore" },
    { "name": "httpsnoop", "SPDXID": "SPDXRef-Package-Httpsnoop" },
    { "name": "fulcio", "SPDXID": "SPDXRef-Package-Fulcio" },
    { "name": "rekor", "SPDXID": "SPDXRef-Package-Rekor" }
  ],
  "relationships": [
    { "spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-RootPackage", "relationshipType": "DESCRIBES" },
    { "spdxElementId": "SPDXRef-RootPackage", "relatedSpdxElement": "SPDXRef-Package-Kyverno", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-RootPackage", "relatedSpdxElement": "SPDXRef-Package-Cosign", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-Kyverno", "relatedSpdxElement": "SPDXRef-Package-OCI", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-OCI", "relatedSpdxElement": "SPDXRef-Package-AzCore", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-Cosign", "relatedSpdxElement": "SPDXRef-Package-Fulcio", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-Cosign", "relatedSpdxElement": "SPDXRef-Package-Rekor", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-Fulcio", "relatedSpdxElement": "SPDXRef-Package-Httpsnoop", "relationshipType": "DEPENDS_ON" }
  ]
}
```

**Key point:** Same as hierarchical in SPDX — all packages flat, all dependencies preserved. The difference from hierarchical is that there is no structural nesting in CDX (and SPDX has no nesting anyway).

### 3.3 Assembly Merge

**Flag:** `--assemblyMerge`

**Purpose:** Treats each input SBOM as an independent assembly. Input primaries become sub-components of the new root, but all other components stay at the top level.

#### CDX Implementation

**Structure:**

- New synthetic root in `metadata.component`
- Input primaries become **sub-components** of the root: `metadata.component.components[]`
- All original components are **flat** in `components[]` (not nested under primaries)
- Original component dependencies are **preserved**
- **No dependency** from root to primaries (they are structural, not runtime dependencies)

**Example:**

```json
{
  "metadata": {
    "component": {
      "name": "my app",
      "version": "1.0.0",
      "components": [
        { "name": "kyverno" },
        { "name": "cosign" }
      ]
    }
  },
  "components": [
    { "name": "oci" },
    { "name": "azcore" },
    { "name": "httpsnoop" },
    { "name": "fulcio" },
    { "name": "rekor" }
  ],
  "dependencies": [
    { "ref": "kyverno", "dependsOn": ["oci"] },
    { "ref": "oci", "dependsOn": ["azcore"] },
    { "ref": "cosign", "dependsOn": ["fulcio", "rekor"] },
    { "ref": "fulcio", "dependsOn": ["httpsnoop"] }
  ]
}
```

**Key point:**

- Primaries are **sub-components** of the root (`metadata.component.components[]`)
- Original components are **flat** in `components[]`
- Root does **not** `dependsOn` primaries

#### SPDX Implementation

**Structure:**

- New synthetic root Package
- All packages (primaries + originals) are **flat** in `packages[]`
- Root **contains** (`CONTAINS`) all input primaries
- Original component dependencies are **preserved**
- **No dependency** from root to primaries

**Example:**

```json
{
  "packages": [
    { "name": "my app", "SPDXID": "SPDXRef-RootPackage" },
    { "name": "kyverno", "SPDXID": "SPDXRef-Package-Kyverno" },
    { "name": "cosign", "SPDXID": "SPDXRef-Package-Cosign" },
    { "name": "oci", "SPDXID": "SPDXRef-Package-OCI" },
    { "name": "azcore", "SPDXID": "SPDXRef-Package-AzCore" },
    { "name": "httpsnoop", "SPDXID": "SPDXRef-Package-Httpsnoop" },
    { "name": "fulcio", "SPDXID": "SPDXRef-Package-Fulcio" },
    { "name": "rekor", "SPDXID": "SPDXRef-Package-Rekor" }
  ],
  "relationships": [
    { "spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-RootPackage", "relationshipType": "DESCRIBES" },
    { "spdxElementId": "SPDXRef-RootPackage", "relatedSpdxElement": "SPDXRef-Package-Kyverno", "relationshipType": "CONTAINS" },
    { "spdxElementId": "SPDXRef-RootPackage", "relatedSpdxElement": "SPDXRef-Package-Cosign", "relationshipType": "CONTAINS" },
    { "spdxElementId": "SPDXRef-Package-Kyverno", "relatedSpdxElement": "SPDXRef-Package-OCI", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-OCI", "relatedSpdxElement": "SPDXRef-Package-AzCore", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-Cosign", "relatedSpdxElement": "SPDXRef-Package-Fulcio", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-Cosign", "relatedSpdxElement": "SPDXRef-Package-Rekor", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-Fulcio", "relatedSpdxElement": "SPDXRef-Package-Httpsnoop", "relationshipType": "DEPENDS_ON" }
  ]
}
```

**Key point:** `CONTAINS` is used from root to primaries because CDX assembly merge places them as **sub-components** of the root (`metadata.component.components[]`), not as runtime dependencies.

### 3.4 Augment Merge

**Flag:** `--augmentMerge --primary <file>`

**Purpose:** Enriches an existing primary SBOM with data from secondary SBOMs. Does not create a new root.

#### CDX Implementation

**Structure:**

- Primary SBOM's root is preserved as document root
- Components from secondary SBOMs are merged into primary
- Matching components (by name/version/purl/CPE) have fields merged
- New components are added
- Only dependencies involving added or merged components are included

**Behavior:**

- No new synthetic root
- Primary's metadata (serial number, timestamp, tools) preserved
- Secondary tools added
- Component matching uses name, version, purl, CPE
- Merge modes: `if-missing-or-empty` (default), `overwrite`

#### SPDX Implementation

**Structure:**

- Primary SBOM's document is preserved
- Packages from secondary SBOMs are merged
- Matching packages (by name/version/purl) have fields merged
- New packages are added
- Only relationships involving added or merged packages are included

**Behavior:**

- Same as CDX: no new root, preserve primary identity
- Package matching uses name, version, purl
- Merge modes: `if-missing-or-empty` (default), `overwrite`

## 4. Open Question

### Differentiating Hierarchical and Flat Merge in SPDX

### Current State

Today, **Hierarchical Merge** and **Flat Merge** for SPDX produce structurally identical output. Both emit:

- All packages flat in `packages[]`
- Root → primaries via `DEPENDS_ON`
- Original component dependencies preserved via `DEPENDS_ON`

This means a consumer cannot tell from the SPDX alone which strategy was used.

### Why This Matters

In CDX, the distinction is visually obvious:

- **Hierarchical**: Original components are **nested** under their primaries via `.components[]`
- **Flat**: Everything is a single flat `components[]` list with no nesting

SPDX has no native nesting mechanism, so the current implementation loses this semantic difference.

### Proposal: Use `CONTAINS` for Structural Nesting

Hierarchical merge should represent the *structural* relationship between a primary and its original components using `CONTAINS`, while still preserving the original runtime dependencies via `DEPENDS_ON`.

Both relationship types would coexist for the same element pairs:

| Relationship | Represents |
|-------------|-----------|
| **`CONTAINS`** | Structural nesting: "Primary X has component Y inside it" (the hierarchical aspect) |
| **`DEPENDS_ON`** | Runtime dependency: "X needs Y" (the original dependency graph) |

### Example: Hierarchical Merge Output (Proposed)

For an input SBOM where `kyverno → oci → azcore`:

```json
{
  "relationships": [
    { "spdxElementId": "SPDXRef-RootPackage", "relatedSpdxElement": "SPDXRef-Package-Kyverno", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-RootPackage", "relatedSpdxElement": "SPDXRef-Package-Cosign", "relationshipType": "DEPENDS_ON" },

    // Structural nesting (hierarchical aspect)
    { "spdxElementId": "SPDXRef-Package-Kyverno", "relatedSpdxElement": "SPDXRef-Package-OCI", "relationshipType": "CONTAINS" },
    { "spdxElementId": "SPDXRef-Package-OCI", "relatedSpdxElement": "SPDXRef-Package-AzCore", "relationshipType": "CONTAINS" },

    // Preserved original dependencies
    { "spdxElementId": "SPDXRef-Package-Kyverno", "relatedSpdxElement": "SPDXRef-Package-OCI", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-OCI", "relatedSpdxElement": "SPDXRef-Package-AzCore", "relationshipType": "DEPENDS_ON" }
  ]
}
```

### Flat Merge Output (for comparison)

Flat merge would **omit** the `CONTAINS` relationships, using only `DEPENDS_ON`:

```json
{
  "relationships": [
    { "spdxElementId": "SPDXRef-RootPackage", "relatedSpdxElement": "SPDXRef-Package-Kyverno", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-RootPackage", "relatedSpdxElement": "SPDXRef-Package-Cosign", "relationshipType": "DEPENDS_ON" },

    // No CONTAINS — everything is flat
    { "spdxElementId": "SPDXRef-Package-Kyverno", "relatedSpdxElement": "SPDXRef-Package-OCI", "relationshipType": "DEPENDS_ON" },
    { "spdxElementId": "SPDXRef-Package-OCI", "relatedSpdxElement": "SPDXRef-Package-AzCore", "relationshipType": "DEPENDS_ON" }
  ]
}
```
