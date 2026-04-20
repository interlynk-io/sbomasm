# `sbomasm generate sbom` — Integration Test Report

Branch: `test/generate-sbom-integration`
Based on: PR #291 (`viveksahu26:feat/support_sbom_generation`), HEAD `abfcad0`
Spec: `docs/spec/generate-sbom.md`
Suite: `e2e/testdata/generate_sbom/*.txt` (26 scenarios, driven by
`e2e/generate_sbom_test.go`)
Runner: `go test ./e2e/ -run TestSbomasmGenerateSBOM -count=1 -v`
Prereqs: `go`, `jq`, `sbomqs` on `PATH`

## Status

All 26 scenarios **pass** — but that is intentional: every spec gap is captured
via negated / inverted assertions, so the suite documents both the present
correct behaviour and the current divergence from spec. When a gap is fixed,
the affected negation in the corresponding scenario flips, and the test starts
failing until it is rewritten for the spec-correct behaviour. This makes the
suite useful as both a regression harness and a TODO list.

NTIA minimum-elements scores (sbomqs `--profile ntia`) against a well-formed
input manifest:

| Format | Score | Grade |
|--------|-------|-------|
| CycloneDX 1.6 | 8.8 / 10 | B |
| SPDX 2.3 | 7.6 / 10 | C |

The CDX/SPDX delta is driven by the SPDX-side gaps called out in §Gaps below.

## Scenario → spec section map

| Scenario | Spec section | Passes with… |
|----------|---------------|--------------|
| 01_cdx_basic | §Proposal, §Artifact Metadata, §Input: JSON Format | Happy path assertions only |
| 02_cdx_spec_versions | §Spec Version Pinning | Happy path |
| 03_spdx_basic | §Output (SPDX) | Happy path |
| 04_lifecycles | §Artifact Metadata (lifecycles) | Happy path |
| 05_output_config_precedence | §output block, §Precedence | **Gap 1** |
| 06_recurse_discovery | §Recursive Discovery | Happy path |
| 07_discovery_silent_skip | §Recursive Discovery error handling | **Gap 2** |
| 08_dedup_identity | §Composition Rules | Happy path |
| 09_hashes_file_and_path | §File-based hashes | Happy path |
| 10_hashes_errors | §File-based hashes error rules | **Gap 3** |
| 11_pedigree | §Pedigree | Happy path |
| 12_pedigree_purl_collision | §Purl on patched components | **Gap 4** |
| 13_determinism | §Determinism and bom-refs | **Gaps 5, 6, 7** |
| 14_tag_filtering | §Per-Build Filtering | **Gap 8** |
| 15_depends_on | §Depends-on | Happy path |
| 16_component_types | §Input: JSON Format (type) | **Gap 9** |
| 17_license_forms | §License forms | **Gap 10** |
| 18_strict_mode | §Strict mode checks | Happy path |
| 19_strict_library_supplier_bug | §Strict mode checks | **Gap 11** |
| 20_generate_components_scaffold | §`generate components` Command | Happy path |
| 21_csv_input | §Input: CSV Format | **Gap 12** |
| 22_spdx_gaps | §Output (SPDX) | **Gaps 13, 14** |
| 23_external_ref_types | §external_references types | Happy path |
| 24_sbomqs_ntia | §Validation | Happy path |
| 25_generate_config | §Command Structure | Happy path |
| 26_structural_validation | §Output | Happy path |

## Spec gaps

Each gap is reproducible via the scenario listed. Flipping the negated
assertion in the scenario is the definition of "fixed."

### 1. Config `output:` block ignored
**Scenario:** `05_output_config_precedence`
**File:** `pkg/generate/gsbom/loader.go::LoadArtifactConfig`
`.artifact-metadata.yaml`'s `output.spec` / `output.spec_version` /
`output.file_format` are parsed into `app.Output` but never read back in
`gsbom.Generate`. CLI flags always win because they are the only source.
Spec §Precedence says the order is CLI → config → built-in.

### 2. Discovery error-handling is "warn and skip" for everything
**Scenario:** `07_discovery_silent_skip`
**File:** `pkg/generate/gsbom/parser.go`, `pkg/generate/gsbom/gsbom.go:57-67`
Spec prescribes two distinct outcomes:
  - no `schema` marker → **silent skip** (no warning; "the file isn't ours")
  - malformed / unknown version → **hard error**
Current behaviour is uniform: `parseJSONComponents` returns an `error`,
`ParseComponentFiles` appends it to a `warnings` slice, and `gsbom.Generate`
prints the warning and continues. So both rules are wrong:
  - silent-skip is not silent (warning is printed)
  - hard-error is not an error (exit 0 produced)

### 3. Hash-source errors are soft warnings
**Scenario:** `10_hashes_errors`
**File:** `pkg/generate/gsbom/gsbom.go:76-82`
`ComputeHashes` returns errors that the top-level generator appends to
`warnings`. Spec §File-based hashes says a missing `file` target, a
pointing-at-a-directory, and an empty-match directory hash are **hard errors**.

### 4. Pedigree purl-vs-ancestor collision is a warning
**Scenario:** `12_pedigree_purl_collision`
**File:** `pkg/generate/gsbom/gsbom.go:94-101`
`ProcessPedigrees` correctly returns an error when a component's `purl` equals
any `pedigree.ancestors[].purl`, but the caller appends it to `warnings`
instead of aborting. Spec explicitly calls this out: "The generator
**hard-errors** if it detects a component whose `purl` equals any entry in its
own `pedigree.ancestors[].purl` list. This check fires even without `--strict`
mode because it's a correctness bug, not a quality warning."

### 5. Bom-ref fallback format diverges
**Scenario:** `13_determinism`
**File:** `pkg/generate/gsbom/serializer_cdx.go:238-243`
Spec §Determinism: "each component's bom-ref is its `purl` if present, else
`pkg:generic/{sanitized-name}@{version}`." Current: fallback is plain
`name@version`. No collision-detection between multiple components resolving to
the same bom-ref either.

### 6. `SOURCE_DATE_EPOCH` not honored
**Scenario:** `13_determinism`
**File:** `pkg/generate/gsbom/serializer_cdx.go:73`, `serializer_spdx.go:504`
`metadata.timestamp` is always `UTCNowTime()`; `serialNumber` is always random.
Spec §Determinism clauses 3-4 require both to be derived from
`SOURCE_DATE_EPOCH` when set.

### 7. Stable ordering missing
**Scenario:** `13_determinism`
**File:** `pkg/generate/gsbom/serializer_cdx.go`
Components emitted in merge order; dependency arrays iterated via Go map
(non-deterministic); `hashes`, `external_references`, `tags` not sorted. Two
runs with identical inputs produce non-byte-identical output even if
`SOURCE_DATE_EPOCH` is fixed.

### 8. `scope: excluded` is not dropped
**Scenario:** `14_tag_filtering`
**File:** `pkg/generate/gsbom/filter.go::FilterComponents`
Spec §Per-Build Filtering: "Components with `scope: excluded` are always
dropped before any tag filtering." Current `FilterComponents` only consults
`Tags` / `ExcludeTags` — `scope` is ignored, and excluded build-time
dependencies leak into the SBOM.

### 9. Component types silently downgraded
**Scenario:** `16_component_types`
**File:** `pkg/generate/gsbom/serializer_cdx.go::mapComponentType`
Spec allows `library, application, framework, container, operating-system,
device, firmware, file, platform, device-driver, machine-learning-model,
data`. `mapComponentType` handles the first 8; `platform`, `device-driver`,
`machine-learning-model`, `data` fall through to `ComponentDataTypeOther` and
the type information is lost.

### 10. License object forms reject the whole file
**Scenario:** `17_license_forms`
**File:** `pkg/generate/gsbom/parser.go::Component`
`Component.License` is a plain `string`. Spec §License forms requires four
forms: `"MIT"`, `{id}`, `{id,text}`, `{id,file}`. The three object forms cause
`json.Unmarshal` to fail, so the entire manifest is rejected (reported as
"no components found" after warning accumulation). No `file`-form license
loading happens either.

### 11. Strict `library`-supplier check has operator precedence bug
**Scenario:** `19_strict_library_supplier_bug`
**File:** `pkg/generate/gsbom/strict.go:118`
```go
c.Type == "library" && strings.TrimSpace(c.Supplier.Name) == "" || strings.TrimSpace(c.Supplier.Email) == ""
```
Go parses this as `(c.Type == "library" && name == "") || email == ""`, so any
component (library or not) missing a supplier email is flagged. Needs
parentheses; spec scopes the check to `type: library` and should treat
"supplier present" as either name-or-email sufficient.

### 12. CSV `hash_file` column ignored
**Scenario:** `21_csv_input`
**File:** `pkg/generate/gsbom/parser.go::parseHashesFromCSV`
The function only reads `hash_value`. Spec's CSV scaffold example uses
`hash_file=./src/cjson/cJSON.c` for the vendored cjson entry; today that
produces an empty `hashes[]` array. Parity with the JSON `file:` form is
missing.

### 13. SPDX pedigree mapping missing
**Scenario:** `22_spdx_gaps`
**File:** `pkg/generate/gsbom/serializer_spdx.go`
Spec §Output (SPDX): "Pedigree information is best-effort mapped to
`Annotations` and `SourceInfo` fields." The SPDX serializer emits no
Annotations and no PackageSourceInfo; ancestor purls, patch diff text, patch
CVE references and pedigree notes all disappear in SPDX output.

### 14. SPDX loses scope (and CycloneDX `scope` drops unmapped)
**Scenario:** `22_spdx_gaps`
**File:** `pkg/generate/gsbom/serializer_spdx.go::buildSPDXPackage`
Scope is not mapped to any SPDX field. This isn't a spec requirement per se
(SPDX has no direct scope equivalent), but combined with Gap 8, `scope:
excluded` components appear in the SPDX output as regular packages with no
indication they shouldn't ship.

## Reproducing

```bash
cd interlynk-io/sbomasm
git checkout test/generate-sbom-integration
go test ./e2e/ -run TestSbomasmGenerateSBOM -count=1 -v
```

Single scenario:

```bash
go test ./e2e/ -run TestSbomasmGenerateSBOM/12_pedigree_purl_collision -v
```

## What's not covered

These items from the spec are either too big for pure testscript or require
decisions that belong to the maintainer. Flagged here for future rounds:

- **Byte-equality with `SOURCE_DATE_EPOCH`** — tested via inequality today
  (Gap 6/7); once those are fixed, flip `13_determinism` to use `cmp
  run1.json run2.json` directly.
- **Per-platform tag variants** (spec §Per-platform variants) — covered
  implicitly by 14_tag_filtering; no dedicated scenario.
- **`generate components --schema`-based manifest linting via `jsonschema
  validate`** — the spec suggests piping the embedded schema into a validator.
  Requires a Go-side validator or installing `python-jsonschema` on CI.
- **Release/CI workflow** (spec §CI Integration) — out of scope for unit-level
  tests.
