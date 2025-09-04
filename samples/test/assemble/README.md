# Testing Editing Feature

- This is for testing of assemble command. And below commands are the examples of the same.
- Assembly supported 3 ways of assembling SBOMs:
  - Flag merge
  - Assembly Merge
  - Hierarchical Merge

- Flat Merge means:

  - Does not reference input SBOM primary components.
  - In this, all the all the primary components as well as components of all SBOMs are placed under components section.
  - Primary components of input SBOMs are dependencies.

- Assembly Merge:
  - References input SBOM primary components as subcomponents of primary component of final SBOM.
  - Excludes primary components of input SBOMs
  - No dependencies listed

- Hierarchical Merge
  - Does not reference input SBOM primary components under metadata.component
  - Hierarchically organizes components under respective primary components
  - Lists primary components of input SBOMs as dependencies

## 1. Flag Merge

```bash
sbomasm assemble -n "foo" -t "library" -v "v1.0.1" --flatMerge sbomex-cdx.json sbomgr-cdx.json -o flat-flag-merge-sbom.spdx.json
```

## 2. Assemble Merge

```bash
sbomasm assemble -n "foo" -t "library" -v "v1.0.1" --assemblyMerge sbomex-cdx.json sbomgr-cdx.json -o assemble-flag-merge-sbom.spdx.json
```

## 3. Hierarchical Merge (Default)

```bash
sbomasm assemble -n "foo" -t "library" -v "v1.0.1" sbomex-cdx.json sbomgr-cdx.json -o hierar-flag-merge-sbom.spdx.json
```
