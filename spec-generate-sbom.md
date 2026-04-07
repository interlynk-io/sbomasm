# Spec: Generate SBOM from Component Metadata

## Problem

In many development environments -- especially embedded (C/C++), legacy, and mixed ecosystems -- existing SCA tools are unreliable. They produce false positives, miss components, and don't support per-build SBOMs. A practical workflow is for developers to manually maintain a component metadata file listing third-party components, and use a tool to generate a proper SBOM from it.

sbomasm can merge, edit, enrich, and convert existing SBOMs, but it **cannot generate an SBOM from a raw component list**. This is a common need for teams that:
- Work in ecosystems where SCA tools don't work well (C, C++, embedded, legacy)
- Need per-build SBOMs for different firmware/build targets from the same codebase
- Want to manually curate their component list with full control over metadata accuracy for compliance reporting (NTIA, CRA, BSI)
- Have stable projects where dependencies rarely change, and want a **deterministic** way to generate SBOMs without recomputing dependencies each time

## End-to-End Workflow

This example follows Acme Corp's IoT gateway firmware project. The firmware uses a mix of third-party dependencies:

- **Internal submodule**: `libmqtt` (Acme's own MQTT library, ships its own `.components.json`)
- **External OSS submodules**: `libtls` (OpenBSD, no `.components.json`) and `libgui` (LVGL, no `.components.json`)
- **Vendored code**: `cjson` and `miniz` (copied directly into `src/`)

Internal submodules are expected to ship `.components.json` in their repo. External OSS submodules won't have one, so their components are listed in the project's root `.components.json`.

### 0. Start with your project

```bash
git clone git@github.com:acme/device-firmware.git
cd device-firmware
git submodule init
git submodule update
```

The repo layout:

```
device-firmware/
  src/
    main.c
    cjson/                       <-- vendored JSON parser (copied into src)
    miniz/                       <-- vendored compression library (copied into src)
  libs/
    libmqtt/                     <-- internal submodule (Acme owns this, ships .components.json)
    libtls/                      <-- external OSS submodule (OpenBSD, no .components.json)
    libgui/                      <-- external OSS submodule (LVGL, no .components.json)
```

### 1. Generate the artifact metadata config

Every SBOM needs metadata about the primary application it describes -- the product name, version, supplier, authors, license, etc. This is separate from the list of third-party components. The `generate config` command scaffolds a `.artifact-metadata.yaml` template that you fill in once and commit to the repo. This file is read automatically by `generate sbom` to populate the SBOM's top-level metadata.

```bash
sbomasm generate config > .artifact-metadata.yaml
```

Edit `.artifact-metadata.yaml` to describe the firmware:

```yaml
app:
  name: device-firmware
  version: 2.1.0
  description: Main firmware for Acme IoT gateway
  primary_purpose: firmware
  supplier:
    name: Acme Corp
    email: engineering@acme.com
  author:
    - name: Jane Doe
      email: jane@acme.com
  license:
    id: MIT
  purl: pkg:generic/acme/device-firmware@2.1.0
  cpe: cpe:2.3:a:acme:device-firmware:2.1.0:*:*:*:*:*:*:*
  copyright: Copyright 2026 Acme Corp
```

### 2. Create component manifest files

There are three sources of third-party components, each handled differently:

- **Internal submodules** (you control the repo): the submodule ships its own `.components.json` -- discovered automatically by `--recurse`
- **External OSS submodules** (you don't control the repo): list these in the project's root `.components.json`
- **Vendored code** (copied into `src/`): create `.components.json` alongside the vendored directory

```
device-firmware/
  .artifact-metadata.yaml
  .components.json               <-- external OSS submodule components (libtls, libgui)
  src/
    cjson/
      .components.json           <-- vendored code
    miniz/
      .components.json           <-- vendored code
  libs/
    libmqtt/
      .components.json           <-- internal submodule (ships its own manifest)
    libtls/                      <-- external OSS (no .components.json here)
    libgui/                      <-- external OSS (no .components.json here)
```

**`.components.json`** (project root) -- external OSS submodules that don't ship their own manifest:

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "libtls",
      "version": "3.9.0",
      "type": "library",
      "supplier": { "name": "OpenBSD" },
      "license": "ISC",
      "purl": "pkg:generic/openbsd/libtls@3.9.0",
      "hashes": [
        { "algorithm": "SHA-256", "value": "e3b0c44..." }
      ],
      "dependency-of": ["libmqtt@4.3.0"],
      "tags": ["core", "networking"]
    },
    {
      "name": "libgui",
      "version": "2.0.0",
      "type": "library",
      "supplier": { "name": "LVGL" },
      "license": "MIT",
      "purl": "pkg:generic/lvgl/libgui@2.0.0",
      "hashes": [
        { "algorithm": "SHA-256", "value": "abc123..." }
      ],
      "tags": ["display"]
    }
  ]
}
```

**`libs/libmqtt/.components.json`** -- internal submodule, ships its own manifest:

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "libmqtt",
      "version": "4.3.0",
      "type": "library",
      "supplier": { "name": "Acme Corp" },
      "license": "EPL-2.0",
      "purl": "pkg:generic/acme/libmqtt@4.3.0",
      "hashes": [
        { "algorithm": "SHA-256", "value": "9f86d08..." }
      ],
      "tags": ["core", "networking"]
    }
  ]
}
```

**`src/cjson/.components.json`** -- vendored JSON parser:

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "cjson",
      "version": "1.7.17",
      "type": "library",
      "supplier": { "name": "Dave Gamble" },
      "license": "MIT",
      "purl": "pkg:github/DaveGamble/cJSON@1.7.17",
      "hashes": [
        { "algorithm": "SHA-256", "value": "d2735c2..." }
      ],
      "tags": ["core"]
    }
  ]
}
```

**`src/miniz/.components.json`** -- vendored compression library:

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "miniz",
      "version": "3.0.2",
      "type": "library",
      "supplier": { "name": "Rich Geldreich" },
      "license": "MIT",
      "purl": "pkg:github/richgel999/miniz@3.0.2",
      "hashes": [
        { "algorithm": "SHA-256", "value": "f81bc5a..." }
      ],
      "tags": ["core"]
    }
  ]
}
```

Commit all `.components.json` files to version control.

### 3. Generate the SBOM

```bash
# Recursively discover all component manifests and generate the full SBOM
sbomasm generate sbom -r . -o device-firmware-2.1.0.cdx.json

# Or list files explicitly
sbomasm generate sbom \
  -i .components.json \
  -i libs/libmqtt/.components.json \
  -i src/cjson/.components.json \
  -i src/miniz/.components.json \
  -o device-firmware-2.1.0.cdx.json
```

The generated SBOM contains:
- `device-firmware@2.1.0` as the primary component (from `.artifact-metadata.yaml`)
- `cjson@1.7.17`, `miniz@3.0.2`, `libmqtt@4.3.0`, and `libgui@2.0.0` as top-level dependencies
- `libtls@3.9.0` as a dependency of `libmqtt@4.3.0`

### 4. Per-build variants

The gateway ships two firmware variants from the same codebase: a headless base variant and a display variant with a GUI. Use tags to generate the right SBOM for each:

```bash
# Base variant -- core only (cjson + miniz + libmqtt + libtls)
sbomasm generate sbom -r . -o device-firmware-base-2.1.0.cdx.json --tags core

# Display variant -- core + display (cjson + miniz + libmqtt + libtls + libgui)
sbomasm generate sbom -r . -o device-firmware-display-2.1.0.cdx.json --tags core,display
```

### 5. Ongoing maintenance

Acme updates libmqtt from 4.3.0 to 4.4.0. The developer edits `libs/libmqtt/.components.json` (update version, hash, purl), updates the `dependency-of` for libtls in the root `.components.json` to `"libmqtt@4.4.0"`, and commits. Re-running `sbomasm generate sbom -r .` produces an updated SBOM deterministically -- no scanning, no false positives.

## Proposal

Add a `sbomasm generate sbom` subcommand that reads one or more component metadata input files (JSON or CSV) and produces a CycloneDX or SPDX SBOM.

### Command

```
sbomasm generate sbom \
  -r . \
  --output device-firmware-2.1.0.cdx.json \
  --tags core \
  --format cyclonedx
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config`, `-c` | string | `.artifact-metadata.yaml` | Path to artifact metadata config (required, generated by `generate config`) |
| `--input`, `-i` | string list | - | Paths to component metadata files (JSON or CSV). Can be specified multiple times. |
| `--output`, `-o` | string | stdout | Output SBOM file path |
| `--tags`, `-t` | string list | (all) | Include only components with any of these tags |
| `--exclude-tags` | string list | (none) | Exclude components with any of these tags |
| `--format` | string | `cyclonedx` | Output SBOM spec: `cyclonedx` or `spdx` |
| `--recurse`, `-r` | string | - | Recursively discover component manifest files under the given directory |
| `--filename` | string | `.components.json` | Filename to look for during recursive discovery (e.g. `my-deps.json`) |

Default output format is CycloneDX. Output always uses the latest supported spec version (currently CycloneDX 1.6, SPDX 2.3).

### Command Structure

The existing `generate` command is restructured into subcommands:

- `sbomasm generate config` -- generates the application/artifact metadata config file (`.artifact-metadata.yaml` by default). This file describes the primary application (name, version, supplier, author, etc.) and is **required** before generating an SBOM.
- `sbomasm generate sbom` -- reads `.artifact-metadata.yaml` for application metadata and `.components.json`/`.components.csv` for component data, then generates the SBOM.

### Artifact Metadata

The `sbomasm generate config` command produces `.artifact-metadata.yaml`, which contains the application-level metadata for the SBOM (name, version, supplier, authors, license, etc.). This file must exist when running `sbomasm generate sbom`.

By default, `generate sbom` looks for `.artifact-metadata.yaml` in the current directory. Use `--config` to specify a different path.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config`, `-c` | string | `.artifact-metadata.yaml` | Path to the artifact metadata config file |

## Distributed Component Metadata

Component metadata files can live at various locations in a repo. This supports real-world patterns like:

- **Internal submodules**: Libraries you control ship their own `.components.json` -- discovered automatically by `--recurse`
- **External OSS submodules**: Libraries you don't control won't have `.components.json` -- list these in the project's root `.components.json`
- **Vendored code**: Source code copied into the repo gets a `.components.json` alongside it
- **Monorepos**: Different teams/modules own their own component lists

### Directory Layout Example

```
device-firmware/
  .artifact-metadata.yaml       <-- app metadata (name, version, supplier)
  .components.json              <-- external OSS submodule components
  src/
    cjson/
      .components.json          <-- vendored code
    miniz/
      .components.json          <-- vendored code
  libs/
    libmqtt/
      .components.json          <-- internal submodule (ships its own)
    libtls/                     <-- external OSS (no manifest here)
    libgui/                     <-- external OSS (no manifest here)
```

### Composition Rules

When multiple `--input` files are provided:

1. **All `components` arrays are merged** into a single flat list.
2. **Duplicate detection**: Components are uniquely identified by `name@version`. If two files define a component with the same `name` and `version`, emit a **warning** and keep the first occurrence. This means the order of `--input` flags matters for resolving duplicates.
3. **`dependency-of` is resolved across files** -- `libtls` in the root `.components.json` can reference `libmqtt@4.3.0` defined in `libs/libmqtt/.components.json`.
4. Tag filtering applies to the merged component list.

### Recursive Discovery

With `--recurse`, the tool walks the given directory tree and automatically collects all files named `.components.json` (or `.components.csv`). If the default filename conflicts, use `--filename` to specify a different name (e.g. `--filename my-deps.json`). Only files with a valid Interlynk schema marker are processed; others are silently skipped.

```bash
sbomasm generate sbom -r . -o device-firmware-2.1.0.cdx.json
```

`--recurse` and `--input` can be combined -- explicitly listed files are processed first, then discovered files are appended (duplicates still deduplicated by `name@version`).

### Single File Shorthand

For simple projects with all components in one file:

```bash
sbomasm generate sbom -i .components.json -o device-firmware-2.1.0.cdx.json
```

## Input: JSON Format

Developers maintain these files in their repo alongside the source code.

### Example JSON file

Root `.components.json` -- external OSS components (libtls is a dependency of libmqtt):

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "libtls",
      "version": "3.9.0",
      "type": "library",
      "supplier": { "name": "OpenBSD" },
      "license": "ISC",
      "purl": "pkg:generic/openbsd/libtls@3.9.0",
      "hashes": [
        { "algorithm": "SHA-256", "value": "e3b0c44..." }
      ],
      "dependency-of": ["libmqtt@4.3.0"],
      "tags": ["core", "networking"]
    }
  ]
}
```

### JSON Schema Details

**`schema`** (required) -- must be `"interlynk/component-manifest/v1"`. Files without this field or with a different value are rejected. This ensures only Interlynk component manifest files are processed.

**`components[]`** (required) -- list of third-party components:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Component name |
| `version` | string | yes | Component version |
| `type` | string | no | Component type (default: `library`) |
| `supplier` | object | no | `{ "name": "", "email": "" }` |
| `license` | string | no | SPDX license ID or expression |
| `purl` | string | no | Package URL |
| `cpe` | string | no | CPE identifier |
| `hashes` | array | no | `[{ "algorithm": "SHA-256", "value": "..." }]` |
| `dependency-of` | array | no | References to components this is a dependency of, in `name@version` format (e.g. `"libfoo@3.2.1"`). If missing, the component is a top-level dependency of the primary application. |
| `tags` | array | no | String tags for per-build filtering |

## Input: CSV Format

Alternative input for simpler use cases or teams maintaining component lists in spreadsheets.

```csv
#interlynk/component-manifest/v1
name,version,type,supplier_name,supplier_email,license,purl,cpe,hash_algorithm,hash_value,dependency_of,tags
libmqtt,4.3.0,library,Eclipse Foundation,,EPL-2.0,pkg:generic/eclipse/libmqtt@4.3.0,,SHA-256,9f86d08...,,"core,networking"
libtls,3.9.0,library,OpenBSD,,ISC,pkg:generic/openbsd/libtls@3.9.0,,SHA-256,e3b0c44...,libmqtt@4.3.0,"core,networking"
libgui,2.0.0,library,LVGL,,MIT,pkg:generic/lvgl/libgui@2.0.0,,SHA-256,abc123...,,display
```

The first line must be `#interlynk/component-manifest/v1`. Files without this marker are rejected.

CSV limitations vs JSON:
- Single hash per row
- Multiple `dependency_of`/tags are comma-separated within the field (quoted)

Application metadata (name, version, supplier, etc.) is provided via `.artifact-metadata.yaml` (generated by `sbomasm generate config`), not in the component input files.

## Behaviors

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

### Dependency Resolution

The dependency graph is computed automatically from the `dependency-of` field:

1. Merge all components from all input files into a single list
2. Build a lookup map of `name@version -> bom-ref`
3. For each component, if `dependency-of` is present, resolve each `name@version` reference and make the component a dependency of those component(s)
4. If `dependency-of` is **missing or empty**, the component is a **top-level dependency** of the primary application
5. If a `dependency-of` reference doesn't exist (filtered out or not in any input file), emit a **warning** and treat the component as top-level
6. The resolved relationships are written as proper dependency relationships in the output SBOM

### Input Format Detection

The input format is detected from the file extension:
- `.json` -- JSON format
- `.csv` -- CSV format

Multiple input files can mix formats (e.g., one JSON and one CSV).

## Output

The tool generates a complete, valid SBOM document:

- **CycloneDX**: Valid BOM with serial number, timestamp, metadata (primary component from `.artifact-metadata.yaml`), components list, and dependency graph
- **SPDX**: Valid document with creation info, describes relationship, packages, and relationships

sbomasm is registered as a tool in the SBOM metadata.

## Non-Goals

- No automatic component detection from source code or binaries
- No automatic PURL/CPE generation or lookup
- No automatic hash computation from files
- No nested/recursive component hierarchies -- flat list with `dependency-of` linkage
- No YAML input format

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

### Generate SPDX
```bash
sbomasm generate sbom -r . -o device-firmware-2.1.0.spdx.json --format spdx
```

### Custom config path
```bash
sbomasm generate sbom -r . -c configs/.artifact-metadata.yaml -o device-firmware-2.1.0.cdx.json
```

### CSV input
```bash
sbomasm generate sbom -i .components.csv -o device-firmware-2.1.0.cdx.json
```
