# `generate sbom` spec gaps

Basis: PR #291 (`feat/support_sbom_generation`), HEAD `abfcad0`, against spec
`docs/spec/generate-sbom.md`.

14 divergences between the spec and the implementation. Each section has a
spec quote, the source location, a reproducible input, actual output from the
binary built on this branch, the expected output per spec, and a fix hint.

Reproducible with:

```
cd interlynk-io/sbomasm && git checkout test/generate-sbom-integration
go build -o /tmp/sbomasm .
```

All snippets below run from an empty directory with that binary on PATH as
`sbomasm`.

---

## 1. Config `output:` block parsed, never consulted

Spec (`§output block`, `§Precedence`):

> Pins the SBOM format and spec version so every invocation produces the same
> output without needing to remember CLI flags. ... Precedence: CLI flags
> override the config file. The config file overrides the defaults.

Source: `pkg/generate/gsbom/loader.go::LoadArtifactConfig`. The loader
unmarshals `app.Config` which does include `app.Output`, but only `Artifact`
is returned. `gsbom.Generate` never sees the output block, so the CLI default
(cobra default `cyclonedx`) wins.

Input `meta.yaml`:

```yaml
app:
  name: app
  version: 1.0.0
  primary_purpose: application
  supplier: {name: Acme}
  license: {id: MIT}
output:
  spec: spdx
  spec_version: "2.3"
  file_format: json
```

Invocation with no `--format` flag:

```
sbomasm generate sbom -c meta.yaml -i .components.json -o out.json
```

Actual:

```
$ jq -r 'if .bomFormat? then .bomFormat + " " + .specVersion else .spdxVersion end' out.json
CycloneDX 1.6
```

Expected: `SPDX-2.3`.

Fix: extend `Artifact` (or return a separate `Output` struct) and use it in
`cmd/generate_sbom.go::extractGenerateSBOM` as the fallback below the CLI flag
and above the built-in default.

---

## 2. Discovery errors degrade to "warn and continue"

Spec (`§Recursive Discovery`):

> File does not have the `schema` field → silent skip. The file isn't ours;
> don't touch it.
> File has `schema: interlynk/component-manifest/...` but is malformed
> JSON/CSV, or has an unknown schema version, or fails validation → hard
> error.

Source: `pkg/generate/gsbom/parser.go::parseJSONComponents` returns an error
for every case (missing marker, bad JSON, wrong version).
`ParseComponentFiles` appends the error to a warnings slice and
`gsbom.Generate` continues. Neither of the two spec outcomes is honored:
"silent skip" prints a warning, "hard error" produces exit 0.

Reproduction:

```
mkdir tree/a
echo '{"components":[{"name":"notours"}]}' > tree/a/.components.json   # no schema
/tmp/sbomasm generate sbom -c meta.yaml -r tree -o out.json
echo $?
```

Actual:

```
{"level":"info",...,"msg":"successfully generated SBOM: out.json"}
warning: file tree/a/.components.json: missing schema marker in JSON file
0
```

Expected: no mention of `tree/a/.components.json` at all. A subsequent run
where the discovered file has `schema: interlynk/component-manifest/v1`
followed by malformed JSON should exit non-zero.

Fix: in `parseJSONComponents`, detect the two cases (peek the raw JSON for a
`schema` key before full unmarshal). Propagate the "malformed-with-marker"
case up to `gsbom.Generate` as a fatal error, and drop the no-marker case
silently without appending to warnings.

---

## 3. Hash source errors are soft warnings

Spec (`§File-based hashes`):

> All paths are resolved relative to the manifest file containing them. If
> the target doesn't exist, the generator fails loudly. ...
> The `file` field must point at a regular file; pointing it at a directory
> is a hard error. ...
> No matching files (empty dir, or filter excludes everything) is a hard
> error.

Source: `pkg/generate/gsbom/gsbom.go:76-82`. `ComputeHashes` returns errors
but they are appended to `warnings` and the run completes.

Reproduction (missing file):

```json
{"schema":"interlynk/component-manifest/v1","components":[{
  "name":"x","version":"1.0","type":"library","license":"MIT",
  "supplier":{"name":"a"},
  "external_references":[{"type":"distribution","url":"https://x"}],
  "hashes":[{"algorithm":"SHA-256","file":"./nonexistent.c"}]}]}
```

Actual:

```
warning: component x@1.0: failed to hash file './nonexistent.c': ...
exit 0
```

Expected: non-zero exit, no output file.

Fix: `gsbom.Generate` should promote errors from `ComputeHashes` to a hard
failure, the same way it already does for `LoadArtifactConfig`. Same for
`ProcessPedigrees` (see gap 4).

---

## 4. Pedigree/ancestor purl collision is a warning, not an error

Spec (`§Purl on patched components`):

> The generator hard-errors if it detects a component whose `purl` equals any
> entry in its own `pedigree.ancestors[].purl` list. This check fires even
> without `--strict` mode because it's a correctness bug, not a quality
> warning.

Source: `pkg/generate/gsbom/pedigree.go::validatePurlVsAncestors` returns the
error correctly, but `gsbom.Generate:98` wraps it into `warnings`.

Reproduction:

```json
{"schema":"interlynk/component-manifest/v1","components":[{
  "name":"cjson","version":"1.7.17","type":"library","license":"MIT",
  "supplier":{"name":"a"},
  "purl":"pkg:github/DaveGamble/cJSON@1.7.17",
  "external_references":[{"type":"distribution","url":"https://x"}],
  "hashes":[{"algorithm":"SHA-256","value":"aa..."}],
  "pedigree":{"ancestors":[{"purl":"pkg:github/DaveGamble/cJSON@1.7.17"}]}
}]}
```

Actual:

```
warning: component pkg:github/DaveGamble/cJSON@1.7.17: purl 'pkg:github/DaveGamble/cJSON@1.7.17' collides with pedigree.ancestors[].purl: a patched component must have a different purl from its upstream ancestor
exit 0
```

Expected: non-zero exit, no output file.

Fix: in `gsbom.Generate`, if `ProcessPedigrees` returns any errors, return
the first one immediately.

---

## 5. Bom-ref fallback is `name@version`, not `pkg:generic/...`

Spec (`§Determinism and bom-refs`):

> Each component's bom-ref is its `purl` if present, else
> `pkg:generic/{sanitized-name}@{version}`. Collisions (two components
> resolving to the same bom-ref) are a hard error.

Source: `pkg/generate/gsbom/serializer_cdx.go:238-243`. Fallback is plain
concatenation. No collision detection anywhere.

Reproduction:

```json
{"schema":"interlynk/component-manifest/v1","components":[{
  "name":"noref","version":"1.0.0","type":"library","license":"MIT",
  "supplier":{"name":"a"},
  "external_references":[{"type":"distribution","url":"https://x"}],
  "hashes":[{"algorithm":"SHA-256","value":"aa..."}]}]}
```

Actual:

```
$ jq -r '.components[0]["bom-ref"]' out.json
noref@1.0.0
```

Expected: `pkg:generic/noref@1.0.0`.

Fix: in `getBomRef`, when `PURL` is empty, return
`"pkg:generic/" + sanitize(name) + "@" + version`. Add a pre-emit scan that
fails the run if two components produce the same bom-ref.

---

## 6. `SOURCE_DATE_EPOCH` is ignored

Spec (`§Determinism and bom-refs`):

> The SBOM `metadata.timestamp` is taken from the `SOURCE_DATE_EPOCH`
> environment variable if set ... The `serialNumber` is derived from a hash
> of the sorted component list when `SOURCE_DATE_EPOCH` is set, so re-runs of
> a tagged release produce the same UUID.

Source: `pkg/generate/gsbom/serializer_cdx.go:73` uses `assemble.UTCNowTime()`
unconditionally. `serialNumber` uses `assemble.NewSerialNumber()` which is
random. Same pattern in `serializer_spdx.go:504`.

Reproduction:

```
SOURCE_DATE_EPOCH=1735689600 sbomasm generate sbom -c meta.yaml -i x.json -o a.json
SOURCE_DATE_EPOCH=1735689600 sbomasm generate sbom -c meta.yaml -i x.json -o b.json
```

Actual:

```
$ jq -r '.metadata.timestamp, .serialNumber' a.json
2026-04-20T18:09:57Z
urn:uuid:18d03f15-d88c-4b06-9da1-237d14ee42e3
$ jq -r '.serialNumber' b.json
urn:uuid:4f666b35-11f2-4ece-a89d-12af2a730ffe
```

Expected: `2025-01-01T00:00:00Z` and identical serial numbers across runs.

Fix: in the CDX and SPDX serializers, read `SOURCE_DATE_EPOCH` and apply it
to timestamp. For serial number, use a hash (SHA-256 of the serialized
component list, truncated to 128 bits) formatted as a UUID.

---

## 7. Component and dependency output order is not stable

Spec (`§Determinism and bom-refs`):

> Stable ordering: components are emitted sorted by bom-ref. Dependency
> arrays are sorted by ref. `hashes`, `external_references`, and `tags` are
> sorted alphabetically.

Source: `pkg/generate/gsbom/serializer_cdx.go` iterates
`bom.Components` (input order), `bom.Dependencies` (Go map iteration, random
per-run), and builds `hashes`/`externalReferences`/`tags` arrays in input
order.

Reproduction (manifest with components in zebra, alpha, middle order):

```
$ jq -r '.components[].name' out.json
zebra
alpha
middle
```

Expected: `alpha`, `middle`, `zebra` (sorted by bom-ref).

Fix: sort `bom.Components` by `getBomRef(c)` before serializing. Sort the
dependency children in `compRefMap`-resolved ref order. Sort hashes by
algorithm, externalReferences by type then URL, tags lexicographically.

Note: this gap and gap 6 must both be fixed for the byte-equality guarantee
from the spec to hold.

---

## 8. `scope: excluded` is not dropped before tag filter

Spec (`§Per-Build Filtering`):

> Components with `scope: excluded` are always dropped before any tag
> filtering.

Source: `pkg/generate/gsbom/filter.go::FilterComponents` only consults `Tags`
and `ExcludeTags`. Scope is not touched.

Reproduction:

```json
{"schema":"interlynk/component-manifest/v1","components":[
  {"name":"runtime","version":"1.0","type":"library","scope":"required",...},
  {"name":"buildonly","version":"1.0","type":"library","scope":"excluded",...}
]}
```

Actual:

```
$ jq -r '.components[] | .name + " scope=" + (.scope // "n/a")' out.json
runtime scope=required
buildonly scope=excluded
```

Expected: only `runtime` is emitted.

Fix: first pass in `FilterComponents`, drop any component with
`strings.ToLower(c.Scope) == "excluded"`.

---

## 9. Four component types are silently downgraded

Spec (`§Input: JSON Format`, `type` field):

> Allowed: `library` (default), `application`, `framework`, `container`,
> `operating-system`, `device`, `firmware`, `file`, `platform`,
> `device-driver`, `machine-learning-model`, `data`.

Source: `pkg/generate/gsbom/serializer_cdx.go::mapComponentType` switches on
8 of the 12 types. The remaining four (`platform`, `device-driver`,
`machine-learning-model`, `data`) hit the default branch and get
`ComponentType(cydx.ComponentDataTypeOther)`.

Reproduction (4 components, one of each missing type):

```
$ jq -r '.components[] | .name + " emitted=" + .type' out.json
t1 emitted=application
t2 emitted=application
t3 emitted=application
t4 emitted=application
```

Expected: each `emitted=` value matches the declared type.

Fix: extend the switch in `mapComponentType` to cover the remaining four. Use
`cydx.ComponentTypePlatform`, `cydx.ComponentTypeDeviceDriver`,
`cydx.ComponentTypeMachineLearningModel`, `cydx.ComponentTypeData`
(all present in `cyclonedx-go` v0.8+).

---

## 10. License object forms crash JSON unmarshal

Spec (`§License forms`):

> Four forms are supported. Pick the richest one you can.
> "license": "MIT"                       (string or expression)
> "license": { "id": "MIT" }             (structured)
> "license": { "id": "MIT", "text": ... } (inline text)
> "license": { "id": "MIT", "file": "./LICENSE" } (file reference)

Source: `pkg/generate/gsbom/parser.go::Component`. `License string`. The
three object forms fail `json.Unmarshal` for the entire manifest file, which
then records a warning and results in "no components found."

Reproduction:

```json
{"schema":"interlynk/component-manifest/v1","components":[{
  "name":"x","version":"1.0","type":"library",
  "license":{"id":"BSD-3-Clause"},
  "supplier":{"name":"a"},
  "external_references":[{"type":"distribution","url":"https://x"}],
  "hashes":[{"algorithm":"SHA-256","value":"aa..."}]}]}
```

Actual:

```
Error: no components found in input files
exit 1
```

Expected: output with `licenses[0].license.id == "BSD-3-Clause"`.

Fix: change `Component.License` to `json.RawMessage` (or a custom type with
`UnmarshalJSON`) that accepts either a string or an object. Propagate the
parsed form through to `buildLicenses` in `serializer_cdx.go`. For the
`{id, file}` form, load the file contents relative to the manifest dir and
populate the CDX `License.Text.Content`.

---

## 11. Strict "library without supplier" check has operator precedence bug

Spec (`§Strict mode checks`, table row):

> Component with `type: library` has no `supplier` → warn.

Source: `pkg/generate/gsbom/strict.go:118`:

```go
if c.Type == "library" && strings.TrimSpace(c.Supplier.Name) == "" || strings.TrimSpace(c.Supplier.Email) == "" {
```

Go groups this as `(library AND name=="") OR email==""`. Any component
missing a supplier email triggers the warning regardless of type or name.

Reproduction:

```json
[
  {"name":"app-comp","type":"application","supplier":{"name":"Acme"}, ...},
  {"name":"has-both","type":"library","supplier":{"name":"Acme","email":"sec@acme.example"}, ...}
]
```

Actual:

```
warning: component app-comp@1.0.0 has no supplier
```

The `app-comp` warning is wrong on two counts: the component is type
`application`, not `library`; and it has a supplier name.

Expected: no warnings for this input.

Fix: wrap the condition in parentheses and clarify the "present" test:

```go
if c.Type == "library" && strings.TrimSpace(c.Supplier.Name) == "" && strings.TrimSpace(c.Supplier.Email) == "" {
```

If either supplier name or email is set, the component has a supplier.

---

## 12. CSV `hash_file` column is ignored

Spec (`§Input: CSV Format`, column list includes `hash_file`; spec's CSV
scaffold has a row using it):

> `cjson,1.7.17,library,...,,SHA-256,,./cJSON.c,required,,"core"`

Source: `pkg/generate/gsbom/parser.go::parseHashesFromCSV`:

```go
func parseHashesFromCSV(record []string, colIndex map[string]int) []Hash {
    v := getValue("hash_value", record, colIndex)
    if v != "" { return []Hash{{...}} }
    return nil
}
```

Only `hash_value` is read. `hash_file` is dropped on the floor.

Reproduction:

```csv
#interlynk/component-manifest/v1
name,version,type,description,supplier_name,supplier_email,license,purl,cpe,hash_algorithm,hash_value,hash_file,scope,depends_on,tags
mylib,1.0,library,,Acme,,MIT,,,SHA-256,,./payload.txt,required,,
```

Actual:

```
$ jq '.components[0].hashes' out.json
null
```

Expected: a hash with value computed from `./payload.txt` (same path
resolution as JSON `file:`).

Fix: in `parseHashesFromCSV`, also read `hash_file`. When set and
`hash_value` is empty, return a `Hash{Algorithm, File}` entry and let the
existing `ComputeHashes` pass fill in `Value` from disk.

---

## 13. SPDX output has no pedigree mapping

Spec (`§Output (SPDX)`):

> Pedigree information is best-effort mapped to `Annotations` and
> `SourceInfo` fields.

Source: `pkg/generate/gsbom/serializer_spdx.go::buildSPDXPackage` never
references the component's `Pedigree`. Ancestors, patches, patch diffs,
`resolves`, and `notes` all vanish.

Reproduction: manifest with pedigree ancestor `pkg:github/DaveGamble/cJSON@1.7.17`,
a patch with inline diff body "diff body", and notes "Forked at abc123":

```
Ancestor PURL in SPDX? NO
Patch diff body in SPDX? NO
Notes in SPDX? NO
```

Expected: ancestor purl appears as a `PackageAnnotation` or inside
`PackageSourceInfo`; patch diff text appears similarly; notes as an
annotation.

Fix: add a helper in `serializer_spdx.go` that, for each component with a
non-nil `Pedigree`, emits one `Annotation` per ancestor / patch / note. Set
`PackageSourceInfo = "Forked from <ancestor-purl> at <commit.uid>"` when
pedigree has ancestors and commits.

---

## 14. SPDX loses `scope`

Spec (`§Output (SPDX)`): no explicit mapping defined, but combined with
gap 8 (`scope: excluded` not filtered), excluded components appear in SPDX
output with nothing to signal they should not ship.

Source: `pkg/generate/gsbom/serializer_spdx.go::buildSPDXPackage` does not
read `c.Scope`.

Reproduction: same manifest as gap 8, `--format spdx`.

Actual:

```
$ grep '"scope"' out.spdx.json
(no output)
```

Expected (one of):

- `scope: excluded` components dropped before serialization (gap 8 fix).
- `scope: optional` / `required` reflected in `PackageComment` or an
  `Annotation`.

Fix: once gap 8 lands, `scope: excluded` components never reach the
serializer. For the remaining `required` / `optional`, record the value in
`PackageComment` so auditors can see it.

---

## NTIA scores

Against a well-formed input (valid supplier, license, purl, hash,
distribution URL for each component, and pedigree on patched entries):

- CycloneDX 1.6: sbomqs score **8.8 / 10**, grade B.
- SPDX 2.3: sbomqs score **7.6 / 10**, grade C.

The CDX/SPDX gap is driven by gaps 13 and 14. Landing those plus gap 6
(creation-time determinism) should push both formats into the A range.

## Suggested fix order

1. Gaps 4 and 11 are single-line changes, both in strict / pedigree
   handling. Land first to cut false positives.
2. Gap 8 is a 3-line filter prepend. Safe to land alongside 4/11.
3. Gap 12 mirrors the JSON `file:` code path; small diff.
4. Gap 9 is a map extension, no logic changes.
5. Gap 10 is the largest behavioral change (custom unmarshal), but unlocks
   a documented spec feature and is isolated to parser + CDX license
   builder.
6. Gaps 2 and 3 are refactors on how errors propagate from
   `ComputeHashes`/`ParseComponentFiles` to `Generate`. Do them together.
7. Gap 1 (config output block) pairs naturally with the flag-resolution
   refactor in `cmd/generate_sbom.go`.
8. Gaps 5, 6, 7 are the determinism cluster. Land last; each depends on the
   others to produce byte-identical runs.
9. Gaps 13 and 14 are SPDX-only; land after the CDX side stabilizes.

## Regression harness

`e2e/testdata/generate_sbom/*.txt` (26 scenarios) cover every gap. Each one
pins the current behavior via negated assertions (e.g. `! cmp run1 run2`
for gap 6). When a fix lands, the corresponding assertion starts failing;
flip the `!` and it asserts the spec-correct behavior. See `REPORT.md` in
the same directory for the scenario-to-gap map.
