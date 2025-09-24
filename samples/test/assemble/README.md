# Testing Editing Feature

- This is for testing of assemble command. And below commands are the examples of the same.
- Assembly supported 3 ways of assembling SBOMs:
  - Flag merge
  - Assembly Merge
  - Hierarchical Merge

- Flat Merge means:

  - All input SBOM components, including their primary components, are merged into the components section of the final SBOM.
  - Each input SBOM’s primary component becomes a direct dependency of the final SBOM.
  - The remaining dependencies from the input SBOMs are preserved as-is in the dependencies section of the final SBOM.

- Assembly Merge:
  - All input SBOM primary components are added as sub-components under the final SBOM’s primary component.
  - All input SBOM components are placed under the components section of the final SBOM.
  - The dependencies from the input SBOMs remain unchanged in the dependencies section of the final SBOM.

- Hierarchical Merge
  - The components section of the final SBOM contains one entry for each input SBOM.
  - Each input SBOM’s components are nested under the sub-components of its respective primary component.
  - Each input SBOM’s primary component becomes a direct dependency of the final SBOM.
  - The dependencies from the input SBOMs are preserved as-is in the dependencies section of the final SBOM.

## SBOMs Example

This example uses two SBOMs, each containing 2–3 components. A small number of components is chosen to make the merging strategies easier to visualize.

SBOM FIles:

- `lite-sbom1-cdx.json`
- `lite-sbom2-cdx.json`

1. `lite-sbom1-cdx.json` has:

- Total 2 components:
  - `github.com/fluxcd/pkg/oci`
  - `github.com/Azure/azure-sdk-for-go/sdk/azcore`
- Primary Component as `github.com/kyverno/kyverno`
- The dependencies of `github.com/kyverno/kyverno`
  - `github.com/fluxcd/pkg/oci`
- Similarly the  dependencies of `github.com/fluxcd/pkg/oci`
  - `github.com/Azure/azure-sdk-for-go/sdk/azcore`

2. `lite-sbom2-cdx.json` has:

- Total 3 components:
  - `github.com/felixge/httpsnoop`
  - `github.com/sigstore/fulcio`
  - `github.com/sigstore/rekor`
- Primary component as `github.com/sigstore/cosign`
- The dependenies of `github.com/sigstore/cosign`
  - `github.com/sigstore/fulcio`
  - `github.com/sigstore/rekor`
- Similalrly, the dependencies of:
  - `github.com/sigstore/fulcio` is `github.com/felixge/httpsnoop`

## 1. Flag Merge

```bash
sbomasm assemble -n "final-in-complete" -t "aplication" -v "v1.0.0" --flatMerge samples/test/assemble/lite-sbom1-cdx.json samples/test/assemble/lite-sbom2-cdx.json -o flatmerge-lite-sbom.cdx.json
```

## 2. Assemble Merge

```bash
sbomasm assemble -n "final-in-complete" -t "application" -v "v1.0.0" --assemblyMerge samples/test/assemble/lite-sbom1-cdx.json samples/test/assemble/lite-sbom2-cdx.json -o assemblemerge-lite-sbom.cdx.json
```

## 3. Hierarchical Merge (Default)

```bash
sbomasm assemble -n "final-in-complete" -t "application" -v "v1.0.0" --hierMerge samples/test/assemble/lite-sbom1-cdx.json samples/test/assemble/lite-sbom2-cdx.json -o hiermerge-lite-sbom.cdx.json
```

or

```bash
sbomasm assemble -n "final-in-complete" -t "application" -v "v1.0.0" samples/test/assemble/lite-sbom1-cdx.json samples/test/assemble/lite-sbom2-cdx.json -o hiermerge-lite-sbom.cdx.json
```
