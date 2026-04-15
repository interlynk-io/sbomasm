# Spec: Generate SBOM from Component Metadata

> **At a glance**
>
> This spec describes `sbomasm generate sbom`, a subcommand that generates CycloneDX/SPDX SBOMs from hand-curated `.components.json` component manifests. The design is shaped by feedback from reviewing real-world hand-authored SBOMs in C/C++, embedded, legacy codebases, and hybrid projects that mix multiple ecosystems with vendored, patched, and partially-optional native dependencies — the projects where traditional SCA tools fall down.
>
> Everything the spec covers:
>
> 1. **Pedigree / patches** — vendored code can declare upstream ancestors and local patches via `pedigree.ancestors[]` and `pedigree.patches[]`.
> 2. **Hashes computed from files or directories** — `{ "file": "./x.c" }` or `{ "path": "./src/cjson/", "extensions": ["c", "h"] }` is resolved at generate time instead of being pasted by hand. Directory hashes use a sorted-manifest scheme (hash each file, sort by relative path, hash the manifest) so the digest is deterministic across filesystems.
> 3. **Rich component fields** — `description`, `external_references`, `scope`, and a documented list of allowed `type` values.
> 4. **`depends-on` dependency direction** — components declare what they depend on in the natural "parent lists children" style.
> 5. **Uniqueness by `purl`** — when present, `purl` is the identity; `name@version` is the fallback.
> 6. **Deterministic bom-refs and stable ordering** — the spec says *how* determinism is achieved, and `SOURCE_DATE_EPOCH` pins the timestamp.
> 7. **Strict recurse error handling** — missing schema marker is a silent skip; malformed JSON with the marker present is a hard error.
> 8. **`--spec-version` flag** — pin CycloneDX/SPDX spec version for reproducible output across sbomasm upgrades.
> 9. **`generate components` scaffold command** — a subcommand that writes a starter `.components.json` (or `.components.csv` with `--csv`) with one filled-in example component.
> 10. **Scope decision rule and patched-purl rule** — spells out when to use `required` / `optional` / `excluded`, and requires that a patched component's `purl` differ from its upstream ancestor. Directly preempts the most common catches in hand-written SBOM reviews.
> 11. **Richer license forms, `metadata.lifecycles`, and a `--strict` lint mode** — structured `license` with `file` references, default `lifecycles: [{ phase: "build" }]`, and a lint mode that fails on missing NTIA minimum elements.
> 12. **Validation via sbomqs and a CI integration reference** — `sbomqs score --profile ntia` is the compliance measurement; full NTIA Minimum Elements compliance is the goal. Plus a reference GitHub Actions workflow.
>
> The manifest schema marker is `interlynk/component-manifest/v1`.

## Problem

In many development environments — especially embedded (C/C++), legacy, and mixed ecosystems — existing SCA tools are unreliable. They produce false positives, miss components, and don't support per-build SBOMs. A practical workflow is for developers to manually maintain a component metadata file listing third-party components, and use a tool to generate a proper SBOM from it.

sbomasm can merge, edit, enrich, and convert existing SBOMs, but it **cannot generate an SBOM from a raw component list**. This is a common need for teams that:

- Work in ecosystems where SCA tools don't work well (C, C++, embedded, legacy)
- Need per-build SBOMs for different firmware/build targets from the same codebase
- Want to manually curate their component list with full control over metadata accuracy for compliance reporting (NTIA, CRA, BSI)
- Have stable projects where dependencies rarely change, and want a **deterministic** way to generate SBOMs without recomputing dependencies each time
- Ship **vendored** copies of upstream libraries, sometimes with **local patches**, and need to declare both the ancestry and the diff for compliance

## End-to-End Workflow

Two worked examples demonstrate the workflow on real-world project shapes. Read whichever matches your stack; each is self-contained and walks from empty repo to CI-wired SBOM release:

### 📘 [generate-sbom-example.md](./generate-sbom-example.md) — Pure C (Acme IoT firmware)

Hand-curate `.components.json` manifests for internal submodules, external OSS libs, and vendored code. Generate the SBOM directly with `sbomasm generate sbom`. Walks through the scaffold command, per-build variants via tags, validation with sbomqs, and CI wiring. Use this example if your project is a native-code binary (firmware, C/C++ executable, embedded).

### 📘 [generate-sbom-example-python-lxml.md](./generate-sbom-example-python-lxml.md) — Hybrid Python + native (Acme xml-validator using lxml)

Generate the Python-side SBOM with [`cyclonedx-py`](https://github.com/CycloneDX/cyclonedx-python), generate the native-side SBOM with `sbomasm generate sbom` from hand-curated `.components.json` manifests, then merge them into a unified SBOM using **`sbomasm assemble --flatMerge`**. Uses real lxml wheel data (libxml2, libxslt, libexslt, zlib with versions extracted by grepping the headers that ship inside the installed wheel), plus a vendored + patched local C module (`acme-schema-cache`) demonstrating `pedigree`, the patched-purl rule, and the new directory-based `path` + `extensions` hash form. Read this example if your project is a Python app that ships wheels with bundled C libraries — or any project that needs to union an ecosystem-specific SBOM with a hand-curated native one.

The rest of this document is the **feature specification** — read it for flags, schema details, composition rules, strict-mode checks, determinism, validation, and CI integration references. Read the example documents for narrative walkthroughs.

<details>
<summary>Quick-reference project layouts (from the examples)</summary>

**Pure C — Acme IoT firmware:**

```
device-firmware/
  src/
    main.c
    cjson/                       <-- vendored JSON parser (locally patched)
    miniz/                       <-- vendored compression library
  libs/
    libmqtt/                     <-- internal submodule (ships .components.json)
    libtls/                      <-- external OSS submodule (no .components.json)
    libgui/                      <-- external OSS submodule (no .components.json)
```

**Hybrid Python + native — Acme xml-validator (lxml):**

```
xml-validator/
  pyproject.toml                 <-- Python deps (lxml + click)
  .artifact-metadata.yaml
  .components.json               <-- 4 bundled native libs (libxml2, libxslt, libexslt, zlib)
  src/
    xml_validator/               <-- click CLI
    acme_schema_cache/           <-- vendored C module (forked + locally patched)
      .components.json
  schemas/
    invoice.xsd
```

</details>

## Proposal

Add a `sbomasm generate sbom` subcommand that reads one or more component metadata input files (JSON or CSV) and produces a CycloneDX or SPDX SBOM.

### Command

```
sbomasm generate sbom \
  -r . \
  --output device-firmware-2.1.0.cdx.json \
  --tags core \
  --format cyclonedx \
  --spec-version 1.6
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config`, `-c` | string | `.artifact-metadata.yaml` | Path to artifact metadata config (required, generated by `generate config`) |
| `--input`, `-i` | string list | - | Paths to component metadata files (JSON or CSV). Can be specified multiple times. |
| `--output`, `-o` | string | stdout | Output SBOM file path |
| `--tags`, `-t` | string list | (all) | Include only components with any of these tags |
| `--exclude-tags` | string list | (none) | Exclude components with any of these tags |
| `--format` | string | `output.spec` in config, else `cyclonedx` | Output SBOM spec: `cyclonedx` or `spdx`. Overrides `output.spec` in `.artifact-metadata.yaml`. |
| `--spec-version` | string | `output.spec_version` in config, else latest | Pin output spec version (e.g. `1.6` for CycloneDX, `2.3` for SPDX). Overrides `output.spec_version` in `.artifact-metadata.yaml`. See [Spec Version Pinning](#spec-version-pinning). |
| `--recurse`, `-r` | string | - | Recursively discover component manifest files under the given directory |
| `--filename` | string | `.components.json` | Filename to look for during recursive discovery (e.g. `my-deps.json`) |
| `--strict` | bool | `false` | Fail the build on common omissions instead of just warning. See [Strict mode checks](#strict-mode-checks). |

Default output format is CycloneDX. Resolution order for format and spec version is: **CLI flag → `output:` block in `.artifact-metadata.yaml` → built-in default** (CycloneDX 1.6, SPDX 2.3).

### Command Structure

The existing `generate` command is restructured into subcommands:

- `sbomasm generate config` — generates the application/artifact metadata config file (`.artifact-metadata.yaml` by default). This file describes the primary application (name, version, supplier, author, etc.) and is **required** before generating an SBOM.
- `sbomasm generate components` — scaffolds a starter component manifest file (`.components.json` by default, `.components.csv` with `--csv`). Optional — for users who prefer editing a template over writing from scratch.
- `sbomasm generate sbom` — reads `.artifact-metadata.yaml` for application metadata and `.components.json`/`.components.csv` for component data, then generates the SBOM.

### Artifact Metadata

The `sbomasm generate config` command produces `.artifact-metadata.yaml`, which contains the application-level metadata for the SBOM (name, version, supplier, authors, license, external references, etc.) **and** the output-format pinning for reproducible builds. This file must exist when running `sbomasm generate sbom`.

By default, `generate sbom` looks for `.artifact-metadata.yaml` in the current directory. Use `--config` to specify a different path.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config`, `-c` | string | `.artifact-metadata.yaml` | Path to the artifact metadata config file |

The config has two top-level blocks: `app:` (primary component identity) and `output:` (SBOM format / spec version). A minimal example:

```yaml
app:
  name: xml-validator
  version: 1.0.0
  primary_purpose: application
  supplier:
    name: Acme Corp
  license:
    id: Apache-2.0
  # ... (full field list below)

output:
  spec: cyclonedx
  spec_version: "1.6"
  file_format: json
```

#### `app` block

Describes the primary component the SBOM is about.

| Field | Description |
|-------|-------------|
| `name`, `version`, `description` | Basic identity |
| `primary_purpose` | e.g. `firmware`, `application`, `library` |
| `supplier` | `{ name, email, url }` |
| `author` | list of `{ name, email }` |
| `license` | SPDX ID or expression |
| `purl`, `cpe` | Package URL / CPE identifier |
| `copyright` | Copyright string |
| `external_references` | list of `{ type, url, comment? }`. Types follow CycloneDX: `website`, `vcs`, `documentation`, `issue-tracker`, `distribution`, `support`, `release-notes`, `advisories`, `other`. |
| `lifecycles` | list of `{ phase }`. Allowed phases: `design`, `pre-build`, `build`, `post-build`, `operations`, `discovery`, `decommission`. Defaults to `[{ phase: "build" }]` if omitted. Controls `metadata.lifecycles` in the generated SBOM. |

#### `output` block

Pins the SBOM format and spec version so every invocation produces the same output without needing to remember CLI flags. Committing this block to version control is the recommended pattern for reproducible builds.

| Field | Description |
|-------|-------------|
| `spec` | Output SBOM spec. `cyclonedx` (default) or `spdx`. |
| `spec_version` | Spec version string (e.g. `"1.6"` for CycloneDX, `"2.3"` for SPDX). See [Spec Version Pinning](#spec-version-pinning) for the supported matrix. If omitted, the latest supported version is used. |
| `file_format` | Serialization format. `json` (default). CycloneDX also supports `xml`; SPDX only supports `json` in this spec. |

**Precedence:** CLI flags (`--format`, `--spec-version`) override the config file. The config file overrides the defaults. This lets committed-to-repo config values drive every normal build while leaving CLI flags free for ad-hoc overrides in release workflows.

## `generate components` Command

Scaffolds a starter component manifest file so users don't have to copy-paste the schema from this document. The output is a working file that parses as-is; users edit the example in place.

### Usage

```
sbomasm generate components [path] [flags]
```

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | (see path rules) | Explicit output file path. Overrides the positional `path` argument if both are given. Also applies to `--schema` when writing the schema to a file instead of stdout. |
| `--csv` | | `false` | Emit `.components.csv` instead of `.components.json`. |
| `--force` | `-f` | `false` | Overwrite target file if it already exists. Without `--force`, the command errors rather than clobbering. |
| `--describe` | | `false` | Print a human-readable list of every field the component manifest supports (name, type, required/optional, description) and exit. Useful for "I forgot what the field was called" discovery. See [Schema discovery](#schema-discovery). |
| `--schema` | | `false` | Print the canonical JSON Schema (draft 2020-12) for the component manifest to stdout (or to `-o <file>`) and exit. Machine-readable; feeds editor tooling, CI validators, and `jq`. See [Schema discovery](#schema-discovery). |

### Path resolution

The target path is determined in this order:

1. If `--output` is set, use it verbatim.
2. Else, if a positional `path` is given:
   - If it's an existing directory → write `<path>/.components.json` (or `.components.csv`).
   - Otherwise → treat as a file path and write to it.
3. Else → write `.components.json` (or `.components.csv`) in the current working directory.

### Overwrite safety

If the resolved target already exists, the command fails with:

```
refusing to overwrite <path> (use --force to overwrite)
```

Pass `-f` / `--force` to overwrite. This matches the behavior of `sbomasm enrich --force`.

### Schema discovery

Once a manifest exists, the CLI needs a way to answer "what fields does this support?" without forcing the user to re-read this spec document. Two flags cover it — both work **fully offline**, because the schema is embedded into the sbomasm binary at compile time (`//go:embed`). No network fetch, no filesystem lookup, nothing to host, nothing to break in an air-gapped environment.

#### `--describe` — human-readable field reference

```bash
sbomasm generate components --describe
```

Prints a formatted list of every field the component manifest supports, grouped by required/optional, with short descriptions. The output is generated from the embedded JSON Schema, so it is always in sync with what the generator actually accepts — there is no hand-maintained parallel documentation.

Representative output:

```
Component manifest (schema: interlynk/component-manifest/v1)

Required:
  schema              string     "interlynk/component-manifest/v1"
  components[]        array      List of third-party components

Component fields:
  name                string     required   Component name
  version             string     required   Component version
  type                string     optional   library (default) | application | framework | file | firmware | ...
  description         string     optional   Human-readable description
  supplier            object     optional   { name, email, url }
  license             string|obj optional   "MIT" | { id } | { id, text } | { id, file }
  purl                string     optional   Package URL — for patched/vendored components must differ from any pedigree.ancestors[].purl
  cpe                 string     optional   CPE identifier
  external_references array      optional   [{ type, url, comment? }]
  hashes              array      optional   literal value | file | path with optional extensions filter (SHA-256, SHA-512)
  scope               string     optional   required (default) | optional | excluded
  pedigree            object     optional   ancestors, descendants, variants, commits, patches, notes
  depends-on          array      optional   ["name@version", ...]
  tags                array      optional   Per-build filtering via --tags / --exclude-tags

Run `sbomasm generate components --schema` for the full JSON Schema.
```

#### `--schema` — machine-readable JSON Schema

```bash
sbomasm generate components --schema > components.schema.json
# or
sbomasm generate components --schema -o .sbomasm/components.schema.json
```

Writes the canonical [JSON Schema (draft 2020-12)](https://json-schema.org/draft/2020-12/schema) for the component manifest to stdout, or to a file via `-o`. The schema is the **single source of truth** — `--describe` is a formatted view of it, `sbomasm generate sbom` parses manifests against it, and any downstream CI validator can consume it directly:

```bash
# Example: validate a manifest in CI using jsonschema (or any other JSON Schema validator)
sbomasm generate components --schema -o /tmp/components.schema.json
jsonschema validate --instancefile .components.json /tmp/components.schema.json
```

#### Air-gapped guarantee

Both `--describe` and `--schema` read from bytes compiled into the sbomasm binary. They never make a network call, never read from `~/.cache`, never touch the filesystem outside of `-o` when the user asks for a file. The schema file is committed alongside the sbomasm source tree at `schemas/component-manifest-v1.schema.json` — build reproducibility guarantees that every sbomasm release ships the same bytes its users get from `--schema`.

### Scaffold content (JSON)

`sbomasm generate components` writes the following to `.components.json`:

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "libexample",
      "version": "1.0.0",
      "type": "library",
      "description": "Example component — replace with a real entry or delete",
      "supplier": {
        "name": "Example Org",
        "email": "security@example.com"
      },
      "license": "MIT",
      "purl": "pkg:generic/example/libexample@1.0.0",
      "external_references": [
        { "type": "website", "url": "https://example.com/libexample" },
        { "type": "vcs", "url": "https://github.com/example/libexample" }
      ],
      "hashes": [
        { "algorithm": "SHA-256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }
      ],
      "scope": "required",
      "tags": ["core"]
    }
  ]
}
```

The scaffold deliberately omits `pedigree`, `cpe`, and `depends-on` — these are specialized fields and including them in the default template would clutter the common case. Users who need them copy from the [JSON Schema Details](#json-schema-details) section below.

### Scaffold content (CSV)

`sbomasm generate components --csv` writes the following to `.components.csv`:

```csv
#interlynk/component-manifest/v1
name,version,type,description,supplier_name,supplier_email,license,purl,cpe,hash_algorithm,hash_value,hash_file,scope,depends_on,tags
libexample,1.0.0,library,Example component,Example Org,security@example.com,MIT,pkg:generic/example/libexample@1.0.0,,SHA-256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,,required,,core
```

The first line is the required schema marker (a CSV comment, not a data row). The second line is the column header. The third line is the example component.

### Success output

On success, the command prints the resolved path to stdout:

```
wrote .components.json
```

Nothing else — keeps the command pipe-friendly and scriptable.

## Distributed Component Metadata

Component metadata files can live at various locations in a repo. This supports real-world patterns like:

- **Internal submodules**: Libraries you control ship their own `.components.json` — discovered automatically by `--recurse`
- **External OSS submodules**: Libraries you don't control won't have `.components.json` — list these in the project's root `.components.json`
- **Vendored code**: Source code copied into the repo gets a `.components.json` alongside it
- **Monorepos**: Different teams/modules own their own component lists

### Composition Rules

When multiple `--input` files are provided:

1. **All `components` arrays are merged** into a single flat list.
2. **Identity is `purl` when present, else `name@version`.** If two components share the same identity, emit a **warning** and keep the first occurrence. If two components share the same `name@version` but declare different `purl` values, treat them as **distinct** components and emit a warning (likely a collision between unrelated upstreams).
3. **`depends-on` is resolved across files** — `libmqtt` in `libs/libmqtt/.components.json` can reference `libtls@3.9.0` defined in the project's root `.components.json`.
4. Tag filtering applies to the merged component list.

### Recursive Discovery

With `--recurse`, the tool walks the given directory tree and automatically collects all files named `.components.json` (or `.components.csv`). If the default filename conflicts, use `--filename` to specify a different name (e.g. `--filename my-deps.json`).

Error handling during discovery:

- **File does not have the `schema` field** → **silent skip**. The file isn't ours; don't touch it.
- **File has `schema: interlynk/component-manifest/...` but is malformed JSON/CSV, or has an unknown schema version, or fails validation** → **hard error**. The file is declared as ours and broken; failing loudly prevents silently shipping an SBOM that's missing components.
- **File references a patch file or hash source file that doesn't exist** → **hard error** with the offending path.

```bash
sbomasm generate sbom -r . -o device-firmware-2.1.0.cdx.json
```

`--recurse` and `--input` can be combined — explicitly listed files are processed first, then discovered files are appended (duplicates still deduplicated by identity rules above).

### Single File Shorthand

For simple projects with all components in one file:

```bash
sbomasm generate sbom -i .components.json -o device-firmware-2.1.0.cdx.json
```

## Input: JSON Format

> **Ecosystems**: A single manifest can mix components from any ecosystem — `purl` disambiguates. Python (`pkg:pypi/...`), C/C++ (`pkg:generic/...` or `pkg:github/...`), Go (`pkg:golang/...`), Rust (`pkg:cargo/...`), and Java (`pkg:maven/...`) can all coexist in one `.components.json`. This matters for hybrid projects — e.g. a Python wheel that bundles C shared libraries, a Go binary with linked C libs, or a Rust crate with vendored Cargo dependencies. Use one manifest for the whole thing; don't split by language.

Developers maintain these files in their repo alongside the source code.

### JSON Schema Details

**`schema`** (required) — must be `"interlynk/component-manifest/v1"`. Files without this field are silently skipped; files with an unknown `interlynk/component-manifest/*` value are rejected.

**`components[]`** (required) — list of third-party components:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Component name |
| `version` | string | yes | Component version |
| `type` | string | no | Component type. Allowed: `library` (default), `application`, `framework`, `container`, `operating-system`, `device`, `firmware`, `file`, `platform`, `device-driver`, `machine-learning-model`, `data`. Mirrors CycloneDX `type`. |
| `description` | string | no | Human-readable description |
| `supplier` | object | no | `{ "name": "", "email": "", "url": "" }` |
| `license` | string or object | no | SPDX ID/expression (string form) or structured object with `id` / `text` / `file`. See [License forms](#license-forms). |
| `purl` | string | no | Package URL. For patched/vendored components, see [Purl on patched components](#purl-on-patched-components). |
| `cpe` | string | no | CPE identifier |
| `external_references` | array | no | `[{ "type": "website", "url": "...", "comment": "..." }]`. Types as in Artifact Metadata. |
| `hashes` | array | no | Literal `[{ "algorithm": "SHA-256", "value": "..." }]`, single-file `[{ "algorithm": "SHA-256", "file": "./cJSON.c" }]`, or directory `[{ "algorithm": "SHA-256", "path": "./src/cjson/", "extensions": ["c", "h"] }]`. See [File-based hashes](#file-based-hashes). |
| `scope` | string | no | `required` (default), `optional`, or `excluded`. See [When to use each scope value](#when-to-use-each-scope-value). |
| `pedigree` | object | no | Vendored code provenance. See [Pedigree](#pedigree). |
| `depends-on` | array | no | References to components this depends on, in `name@version` or `purl` format. If missing, the component is a top-level dependency of the primary application. |
| `tags` | array | no | String tags for per-build filtering |

#### When to use each `scope` value

Getting this wrong is the most common mistake in hand-written SBOMs. Use this decision rule:

- **`required`** — component ships in the runtime artifact AND is needed at runtime. Example: `libtls` linked into firmware.
- **`optional`** — component ships in the runtime artifact but may not be reached at runtime. Feature flags, plugins, platform-conditional libraries. Example: `libgui` included in the binary but only loaded when the display variant is built.
- **`excluded`** — component does **not** ship in the runtime artifact. Build-time only: compilers, codegen tools, test harnesses, header-only dev dependencies used during compilation but not present in the output. Example: `pybind11` for a project that only uses its headers, or a SWIG-generated stub.

Rule of thumb: if the component's bytes are inside the final artifact a user downloads, it's `required` or `optional`. If not, it's `excluded`. Build-time dependencies are **not** `optional` — they're `excluded`.

#### License forms

Four forms are supported. Pick the richest one you can:

| Form | When to use |
|------|-------------|
| `"license": "MIT"` | SPDX ID or expression, no extra detail needed |
| `"license": { "id": "MIT" }` | Structured but no extra detail |
| `"license": { "id": "MIT", "text": "..." }` | Inline license text |
| `"license": { "id": "MIT", "file": "./LICENSE" }` | License text read from a file at generate time. Relative paths resolve from the manifest file. |

The `file` form is the recommended pattern for vendored code: commit the upstream `LICENSE` file alongside the vendored source and reference it. This keeps license text out of your manifest, makes upstream license updates easy to track via git, and keeps each vendored library's license next to the code it applies to rather than in a central registry.

A license expression (e.g. `"Apache-2.0 OR MIT"`) is valid in the string form or in the `id` field. The generator does not attempt to parse or validate expressions — it passes them through.

#### File-based hashes

A hash entry has three forms. Pick whichever matches how the real source is laid out on disk:

```json
{ "algorithm": "SHA-256", "value": "e3b0c442..." }                          // 1. literal — pasted by hand, frozen
{ "algorithm": "SHA-256", "file": "./cJSON.c" }                             // 2. single file — hash of that one file
{ "algorithm": "SHA-256", "path": "./src/cjson/", "extensions": ["c","h"] } // 3. directory — hash of all matching files under the directory
```

All paths are resolved **relative to the manifest file containing them**. If the target doesn't exist, the generator fails loudly. Mixing all three forms in the same `hashes` array is allowed (e.g. a frozen upstream digest plus a live digest of a local file plus a live digest of a vendored directory).

**1. Literal** — `value` is the hex digest. Nothing is read; the value passes straight through to the output SBOM.

**2. Single file (`file`)** — the generator reads the file, computes the declared algorithm over its bytes, and emits the digest as `value` in the output SBOM. Supported algorithms: **`SHA-256`** and **`SHA-512`**. Weaker algorithms (`SHA-1`, `MD5`) and less common ones (`SHA-384`) are deliberately excluded — they're either broken for supply-chain integrity or add surface area without practical value. Literal `value` form accepts any algorithm CycloneDX allows; the file/path forms only compute the two listed. The `file` field must point at a regular file; pointing it at a directory is a hard error.

**3. Directory (`path`)** — the generator walks the directory recursively, hashes every matching file, and combines the per-file digests into a single directory digest. This is the right form for vendored code that spans multiple source files (e.g. a whole vendored library, not just `foo.c`). `path` can point at either a directory or a single file — pointing it at a file makes it behave identically to `file`, so `path` is the more general form.

When `path` points to a directory:

- **Recursive walk** from `path` — all files under the tree are candidates.
- **`extensions` filter** (optional) — array of extensions (e.g. `["c", "h"]` or `["*.c", ".h"]`; leading dot and leading `*.` are both accepted, case-insensitive). When specified, only files whose name ends in one of the listed extensions are included. When omitted, every regular file is included.
- **Symbolic links are skipped** with a warning, to avoid cycles and to avoid leaking digests outside the intended tree.
- **Hidden files and directories** (anything whose basename starts with `.`, e.g. `.DS_Store`, `.git/`, `.venv/`, `.gitignore`) are **excluded by default**. These are almost always editor scratch, VCS metadata, or local tooling artifacts — including them would make directory digests non-deterministic across machines. If you genuinely need a dotfile in the hash, rename it or list it under an explicit `file` entry instead.
- **No matching files** (empty dir, or filter excludes everything) is a **hard error** — computing an "empty hash" silently masks misconfiguration.

The directory digest is computed deterministically via a sorted manifest, so the result is byte-identical across filesystems, operating systems, and re-runs:

1. Compute each matching file's digest in the declared algorithm.
2. Build a manifest string: one line per file, sorted lexicographically by the file's **forward-slash relative path** from `path`. Each line is `<hex-digest>  <relative-path>\n` (two spaces, LF terminator, UTF-8).
3. Hash the manifest string in the declared algorithm.
4. Emit that digest as `value` in the output SBOM.

Example manifest (internal, never written to disk) for a directory with three files:

```
3a4b...  cJSON.c
7f9e...  cJSON.h
c1d2...  cJSON_Utils.c
```

The sorted-manifest approach matches the model git uses for tree objects. It's deterministic, explains cleanly to auditors ("we hashed these N files in this order"), and changes whenever any covered file is added, removed, or modified — so the digest drifts if and only if the vendored source drifts.

**Example — vendored library directory with only `.c` and `.h` files hashed:**

```json
{
  "name": "cjson",
  "version": "1.7.17",
  "hashes": [
    { "algorithm": "SHA-256", "path": "./src/cjson/", "extensions": ["c", "h"] }
  ]
}
```

This is the preferred form for vendored code — it covers every source file in the tree without forcing the user to pick one arbitrarily, and it ignores whatever LICENSE / README / tests / build-output files live alongside.

#### Pedigree

The `pedigree` block mirrors CycloneDX's pedigree model and is the compliance story for vendored and patched code:

```json
"pedigree": {
  "ancestors": [
    { "purl": "pkg:github/DaveGamble/cJSON@1.7.17" }
  ],
  "descendants": [ ],
  "variants": [ ],
  "commits": [
    { "uid": "abc123", "url": "https://github.com/..." }
  ],
  "patches": [
    {
      "type": "backport",
      "diff": {
        "text": "...inline unified diff...",
        "url": "./patches/cjson-fix-int-overflow.patch"
      },
      "resolves": [
        { "type": "security", "name": "CVE-2024-XXXXX", "url": "..." }
      ]
    }
  ],
  "notes": "Forked at commit abc123; local fix for int overflow in parser."
}
```

Patch `type` follows CycloneDX: `unofficial`, `monkey`, `backport`, `cherry-pick`.

A `diff.url` with a local relative path (e.g. `./patches/foo.patch`) is read at generate time and inlined as `diff.text`. A `diff.url` with an `http(s)://` URL is left as-is.

#### Purl on patched components

**If a component has a `pedigree` block, its top-level `purl` MUST NOT equal any `pedigree.ancestors[].purl`.** A patched copy of upstream cJSON 1.7.17 is no longer cJSON 1.7.17 — referencing it by the upstream purl misleads vulnerability scanners into matching (or missing) advisories against code you're not actually running.

Three acceptable patterns:

1. **Repo-local purl** (preferred for vendored code):
   ```json
   "purl": "pkg:github/acme/device-firmware/src/cjson@1.7.17",
   "pedigree": { "ancestors": [ { "purl": "pkg:github/DaveGamble/cJSON@1.7.17" } ] }
   ```
2. **Upstream purl with a qualifier**:
   ```json
   "purl": "pkg:github/DaveGamble/cJSON@1.7.17?vendored=true",
   "pedigree": { "ancestors": [ { "purl": "pkg:github/DaveGamble/cJSON@1.7.17" } ] }
   ```
3. **Omit `purl` entirely** and let identity fall back to `name@version`. The component is still discoverable; it just won't match upstream purl databases (which, for a patched fork, is the point).

The generator **hard-errors** if it detects a component whose `purl` equals any entry in its own `pedigree.ancestors[].purl` list. This check fires even without `--strict` mode because it's a correctness bug, not a quality warning.

#### Depends-on

Components declare their dependencies via `depends-on` — the parent lists its children:

```json
{
  "name": "libmqtt",
  "version": "4.3.0",
  "depends-on": ["libtls@3.9.0", "libssl@3.0.0"]
}
```

References can be `name@version` or a full `purl`. References are resolved across files, so a `depends-on` entry in `libs/libmqtt/.components.json` can point at a component defined in the project's root `.components.json`.

If a component has no `depends-on` field, it is treated as a **top-level dependency** of the primary application (i.e. depended on by the artifact described in `.artifact-metadata.yaml`).

> **Only one direction:** v1 drafts supported a `dependency-of` field pointing the opposite way. That has been removed before release — having two ways to express the same edge was confusing and invited mixed usage within the same project. `depends-on` is the sole form.

## Input: CSV Format

Alternative input for simpler use cases or teams maintaining component lists in spreadsheets.

```csv
#interlynk/component-manifest/v1
name,version,type,description,supplier_name,supplier_email,license,purl,cpe,hash_algorithm,hash_value,hash_file,scope,depends_on,tags
libmqtt,4.3.0,library,Acme MQTT client,Acme Corp,,EPL-2.0,pkg:generic/acme/libmqtt@4.3.0,,SHA-256,9f86d08...,,required,libtls@3.9.0,"core,networking"
libtls,3.9.0,library,OpenBSD TLS,OpenBSD,,ISC,pkg:generic/openbsd/libtls@3.9.0,,SHA-256,e3b0c44...,,required,,"core,networking"
cjson,1.7.17,library,JSON parser (vendored fork),Dave Gamble,,MIT,pkg:github/acme/device-firmware/src/cjson@1.7.17,,SHA-256,,./cJSON.c,required,,"core"
libgui,2.0.0,library,LVGL GUI,LVGL,,MIT,pkg:generic/lvgl/libgui@2.0.0,,SHA-256,abc123...,,optional,,display
```

The first line must be `#interlynk/component-manifest/v1`. Files without this marker are silently skipped.

CSV limitations vs JSON:
- Single hash per row (either `hash_value` or `hash_file`, not both)
- Multiple `depends_on` / `tags` entries are comma-separated within the field (quoted)
- No `pedigree` support — use JSON for vendored-with-patches components
- No `external_references` support — use JSON

## Behaviors

### Strict mode checks

Without `--strict`, `generate sbom` emits warnings for the following conditions but still produces an SBOM. With `--strict`, these become hard errors. The list is derived from real-world review catches on hand-written SBOMs and maps directly to common compliance gaps:

| Check | Warning | Why it matters |
|-------|---------|----------------|
| Component has no `license` | `component X@Y has no license field` | NTIA minimum element |
| Component lives under `vendor/`, `thirdparty/`, or `src/*/` **and** has no `pedigree` | `component X@Y looks vendored but has no pedigree` | Patched forks masquerading as upstream |
| Component has `pedigree` but its top-level `purl` equals an ancestor purl | `component X@Y purl collides with pedigree.ancestors[]` | **Always a hard error**, even without `--strict` (see [Purl on patched components](#purl-on-patched-components)) |
| Component has no `hashes` entry | `component X@Y has no hash` | NTIA minimum element; needed for supply-chain attestation |
| Component has no `external_references` of type `distribution` | `component X@Y has no distribution URL` | Auditors need "where did you fetch this from" |
| Component with `type: library` has no `supplier` | `component X@Y has no supplier` | NTIA minimum element |

Run `sbomasm generate sbom --strict` in CI to prevent regressions. Start with warnings-only in local development until your manifests are clean, then flip to `--strict` once they pass.

### Determinism and bom-refs

The spec commits to byte-identical output on re-runs with unchanged inputs. This is achieved by:

1. **Deterministic `bom-ref`**: each component's bom-ref is its `purl` if present, else `pkg:generic/{sanitized-name}@{version}`. Collisions (two components resolving to the same bom-ref) are a hard error.
2. **Stable ordering**: components are emitted sorted by bom-ref. Dependency arrays are sorted by ref. `hashes`, `external_references`, and `tags` are sorted alphabetically.
3. **Deterministic timestamp**: the SBOM `metadata.timestamp` is taken from the `SOURCE_DATE_EPOCH` environment variable if set (seconds since epoch, per [reproducible-builds.org](https://reproducible-builds.org/specs/source-date-epoch/)); otherwise the current time. The `serialNumber` is derived from a hash of the sorted component list when `SOURCE_DATE_EPOCH` is set, so re-runs of a tagged release produce the same UUID.
4. **Deterministic hash inputs**: file-based hashes are computed over the file as-is on disk. If you want a stable hash, check the file into version control unchanged.

### Spec Version Pinning

The output SBOM spec and spec version can be pinned in two equivalent ways: **committed to the config file** (recommended for reproducible builds) or **passed on the CLI** (for ad-hoc overrides). CLI flags take precedence when both are given.

**Config file form** — commit `output:` to `.artifact-metadata.yaml`:

```yaml
output:
  spec: cyclonedx
  spec_version: "1.6"
  file_format: json
```

Once committed, every invocation — local developer, CI, release workflow — produces the same spec version without anyone having to remember a CLI flag. This is the recommended pattern.

**CLI flag form** — override the config (or omit the config entry and use CLI only):

```bash
# Pin CycloneDX 1.6 for reproducibility across sbomasm upgrades
sbomasm generate sbom -r . --format cyclonedx --spec-version 1.6 -o out.cdx.json

# Pin SPDX 2.3
sbomasm generate sbom -r . --format spdx --spec-version 2.3 -o out.spdx.json
```

**Precedence (highest to lowest):**

1. CLI flag (`--format`, `--spec-version`)
2. `output:` block in `.artifact-metadata.yaml`
3. Built-in default (CycloneDX 1.6, JSON)

**Supported values:**

| Format | Supported `spec_version` | Default (latest) |
|--------|--------------------------|------------------|
| `cyclonedx` | `1.4`, `1.5`, `1.6` | `1.6` |
| `spdx` | `2.3` | `2.3` |

A pinned spec version older than the default may silently drop fields the older spec doesn't support (e.g. `pedigree.patches.resolves.type: security` exists in CycloneDX 1.5+). The generator emits a warning listing any dropped fields.

### Per-Build Filtering

Tags enable generating different SBOMs from the same component files for different build targets:

```bash
# Base variant -- core only (cjson + miniz + libmqtt + libtls)
sbomasm generate sbom -r . -o device-firmware-base-2.1.0.cdx.json --tags core

# Display variant -- core + display (cjson + miniz + libmqtt + libtls + libgui)
sbomasm generate sbom -r . -o device-firmware-display-2.1.0.cdx.json --tags core,display

# Exclude debug-only components from a release SBOM
sbomasm generate sbom -r . -o device-firmware-release-2.1.0.cdx.json --exclude-tags debug
```

- `--tags`: include components that have **at least one** matching tag. Empty means include all.
- `--exclude-tags`: remove components that have **any** matching tag. Applied after `--tags`.
- Components with no tags are included when `--tags` is empty, excluded when `--tags` is specified.
- Components with `scope: excluded` are always dropped before any tag filtering.

#### Per-platform variants

The same tag mechanism handles platform-specific component sets. Some components only ship on some platforms — e.g. optional native libraries that are built into manylinux wheels but disabled on iOS or Windows. Model this by tagging components with platform names and filtering per-build:

```json
{
  "name": "raqm",
  "version": "0.10.5",
  "tags": ["core", "linux", "macos", "windows"]
}
```

```bash
sbomasm generate sbom -r . --tags core,linux -o firmware-linux.cdx.json
sbomasm generate sbom -r . --tags core,macos -o firmware-macos.cdx.json
sbomasm generate sbom -r . --tags core,ios --exclude-tags desktop -o firmware-ios.cdx.json
```

Combine platform tags with feature tags freely — a component with `tags: ["core", "linux", "display"]` is included only when both `core|linux` and `display` filters match. If you ship the same binary on multiple platforms with different bundled native libs, **generate one SBOM per platform**; don't try to represent platform variance inside a single SBOM.

### Dependency Resolution

The dependency graph is computed from `depends-on`:

1. Merge all components from all input files into a single list, applying identity rules.
2. Build a lookup map from `name@version` **and** `purl` to `bom-ref`.
3. For each component with `depends-on`, resolve each reference and record an edge from the current component to each referenced component.
4. If a component has no `depends-on` field, it is a **top-level dependency** of the primary application.
5. If a reference doesn't resolve (filtered out, typo, or not in any input file), emit a **warning** and drop the edge — the referring component keeps its other edges, or becomes top-level if it has none left.
6. The resolved relationships are written as proper dependency relationships in the output SBOM.

### Input Format Detection

The input format is detected from the file extension:
- `.json` — JSON format
- `.csv` — CSV format

Multiple input files can mix formats (e.g., one JSON and one CSV).

## Output

The tool generates a complete, valid SBOM document:

- **CycloneDX**: Valid BOM with serial number, timestamp, metadata (primary component from `.artifact-metadata.yaml` including `externalReferences` and `lifecycles`), components list with `description`/`scope`/`pedigree`/`externalReferences` as declared, and dependency graph. `$schema` points at the pinned CycloneDX schema URL.
- **SPDX**: Valid document with creation info, `DESCRIBES` relationship, packages, and relationships. Pedigree information is best-effort mapped to `Annotations` and `SourceInfo` fields.

sbomasm is registered as a tool in the SBOM metadata.

Every generated CycloneDX SBOM includes `metadata.lifecycles`. The default is `[{ "phase": "build" }]`, indicating the SBOM was produced at build time from source manifests. Override via `app.lifecycles` in `.artifact-metadata.yaml` if the SBOM is being generated at a different lifecycle phase (e.g. `post-build` when running against an already-built artifact, or `operations` when generated by a runtime scanner).

## Validation

Generating an SBOM is only half the job — you also need to confirm it's **compliant** against whatever regulatory framework applies to you (NTIA Minimum Elements, BSI TR-03183, EU CRA, Executive Order 14028, etc.). Schema validity is not the same as compliance: a schema-valid CycloneDX document can still be missing required metadata fields that regulations mandate.

Use [**sbomqs**](https://github.com/interlynk-io/sbomqs) (Interlynk's SBOM quality and compliance tool) to score your generated SBOM against these frameworks. The minimum bar to aim for is **NTIA Minimum Elements** — it's the baseline every other framework builds on.

```bash
# Generate the SBOM
sbomasm generate sbom -r . -o device-firmware-2.1.0.cdx.json

# Score it against NTIA minimum elements
sbomqs score --profile ntia device-firmware-2.1.0.cdx.json

# Score against other frameworks (pick what applies to you)
sbomqs score --profile bsi   device-firmware-2.1.0.cdx.json
sbomqs score --profile fsct device-firmware-2.1.0.cdx.json
```

sbomqs flags missing suppliers, missing hashes, missing licenses, missing timestamps, missing tool metadata — the same set of fields `--strict` mode checks for, but rendered as a regulatory compliance report rather than a pass/fail. Run both: `--strict` in CI to prevent regressions, `sbomqs score` before a release to confirm the SBOM meets the bar.

**The goal is high compliance against the regulatory framework that applies to you, not a number on a tool's scoreboard.** sbomqs reports a score because that's a convenient way to measure the gap, but what you actually care about is whether every field the regulation mandates is present and meaningful:

- **NTIA Minimum Elements** — treat this as a non-negotiable baseline. Every field is mandatory by regulation; any gap sbomqs reports is a gap regulators will report. This is the floor for shipping software into markets where NTIA compliance is enforced.
- **Higher-tier frameworks** (BSI TR-03183, FSCT, EU CRA, Executive Order 14028) — aim for as close to full compliance as your data sources allow. Where a gap exists, document *why* in your release notes (e.g. "upstream `foo@1.2.3` ships without a declared supplier and we couldn't determine one"); don't silently ship an incomplete SBOM and hope nobody notices.

A useful mental model: `--strict` prevents the gap from widening, `sbomqs` measures the gap against specific regulatory frameworks. Neither tool is the compliance goal; compliance is the goal.

## CI Integration

A minimal release pipeline wires SBOM generation into the same workflow that builds and ships the artifact. The pattern:

1. **Dedicated job, not blocked on slow build jobs.** Generate the SBOM early so developers can inspect the result in PR review without waiting for a full wheel/firmware build to finish.
2. **Run on every PR and push**, not just tag pushes. Regressions (missing license, missing pedigree, broken manifest JSON) are cheaper to catch in review than on release day.
3. **On tag push, attach the SBOM to the GitHub release.** Use `gh release upload`.
4. **Archive as a workflow artifact on non-release runs.** Keeps a paper trail and lets reviewers download the generated file.
5. **Run `sbomqs score` in the same job.** Fail the build on any NTIA Minimum Elements regression — a new missing supplier, hash, or license on a component is a compliance hole, not a cosmetic diff.

Reference GitHub Actions workflow snippet:

```yaml
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive
      - name: Install sbomasm and sbomqs
        run: |
          go install github.com/interlynk-io/sbomasm@latest
          go install github.com/interlynk-io/sbomqs@latest
      - name: Generate SBOM
        run: sbomasm generate sbom -r . --strict -o ${{ github.event.repository.name }}.cdx.json
      - name: Score SBOM (NTIA minimum elements)
        run: sbomqs score --profile ntia ${{ github.event.repository.name }}.cdx.json
      - name: Upload workflow artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: ${{ github.event.repository.name }}.cdx.json
      - name: Attach to GitHub release
        if: startsWith(github.ref, 'refs/tags/')
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: gh release upload "$GITHUB_REF_NAME" ${{ github.event.repository.name }}.cdx.json
```

Run order matters: generate first, score second, upload third. If scoring fails, the upload step never runs — you never ship a non-compliant SBOM.

## Non-Goals

- No automatic component detection from source code or binaries
- No automatic PURL/CPE generation or lookup
- No nested/recursive component hierarchies — flat list with `depends-on` linkage
- No YAML input format for component manifests (YAML is only used for `.artifact-metadata.yaml`)
- No network fetches during hash computation — only local files under `file:` hash references are read
- No rewriting of existing SBOMs — use `sbomasm edit` / `sbomasm merge` for that

## Examples

### Recursive discovery (most common)
```bash
sbomasm generate sbom -r . -o device-firmware-2.1.0.cdx.json
```

### Explicit files
```bash
sbomasm generate sbom \
  -i .components.json \
  -i libs/libmqtt/.components.json \
  -i src/cjson/.components.json \
  -i src/miniz/.components.json \
  -o device-firmware-2.1.0.cdx.json
```

### Per-build variants
```bash
# Base variant (core only)
sbomasm generate sbom -r . -o device-firmware-base-2.1.0.cdx.json --tags core

# Display variant (core + display)
sbomasm generate sbom -r . -o device-firmware-display-2.1.0.cdx.json --tags core,display
```

### Reproducible build
```bash
SOURCE_DATE_EPOCH=1735689600 sbomasm generate sbom \
  -r . \
  --spec-version 1.6 \
  -o device-firmware-2.1.0.cdx.json
```

### Generate SPDX
```bash
sbomasm generate sbom -r . -o device-firmware-2.1.0.spdx.json --format spdx --spec-version 2.3
```

### Custom config path
```bash
sbomasm generate sbom -r . -c configs/.artifact-metadata.yaml -o device-firmware-2.1.0.cdx.json
```

### CSV input
```bash
sbomasm generate sbom -i .components.csv -o device-firmware-2.1.0.cdx.json
```

### Scaffold a component manifest
```bash
# JSON in the current directory
sbomasm generate components

# CSV template
sbomasm generate components --csv

# Into a vendored-code directory
sbomasm generate components src/cjson
```
