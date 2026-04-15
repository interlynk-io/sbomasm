# Worked Example: Acme IoT Gateway Firmware

> This is the worked end-to-end example for [`generate-sbom.md`](./generate-sbom.md). It walks through every step a real C/embedded project takes to generate, validate, and ship a compliant CycloneDX SBOM from hand-curated component manifests. Read the spec first for the feature reference; read this document for the narrative.

This example follows **Acme Corp's IoT gateway firmware** project. The firmware uses a mix of third-party dependencies:

- **Internal submodule**: `libmqtt` (Acme's own MQTT library, ships its own `.components.json`)
- **External OSS submodules**: `libtls` (OpenBSD, no `.components.json`) and `libgui` (LVGL, no `.components.json`)
- **Vendored code**: `cjson` and `miniz` (copied directly into `src/`), with `cjson` carrying a local patch

Internal submodules are expected to ship `.components.json` in their repo. External OSS submodules won't have one, so their components are listed in the project's root `.components.json`.

## 0. Start with your project

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
    cjson/                       <-- vendored JSON parser (copied into src, locally patched)
    miniz/                       <-- vendored compression library (copied into src)
  libs/
    libmqtt/                     <-- internal submodule (Acme owns this, ships .components.json)
    libtls/                      <-- external OSS submodule (OpenBSD, no .components.json)
    libgui/                      <-- external OSS submodule (LVGL, no .components.json)
```

## 1. Generate the artifact metadata config

Every SBOM needs metadata about the primary application it describes — the product name, version, supplier, authors, license, external references, etc. The `generate config` command scaffolds a `.artifact-metadata.yaml` template that you fill in once and commit to the repo.

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
  external_references:
    - type: website
      url: https://acme.example.com/device-firmware
    - type: vcs
      url: https://github.com/acme/device-firmware
    - type: documentation
      url: https://docs.acme.example.com/device-firmware
```

## 1b. Scaffold a component manifest

Instead of hand-writing your first `.components.json`, scaffold one:

```bash
# Writes ./.components.json with one example component
sbomasm generate components

# Scaffold into a specific directory (writes src/cjson/.components.json)
sbomasm generate components src/cjson

# Scaffold a CSV template instead
sbomasm generate components --csv

# Overwrite an existing file
sbomasm generate components -f
```

The scaffold contains the `schema` marker and one complete example component with every commonly-used field populated (`name`, `version`, `type`, `description`, `supplier`, `license`, `purl`, `hashes`, `scope`, `tags`, `external_references`). Edit the example in place or replace it with your real components.

## 2. Create component manifest files

There are three sources of third-party components, each handled differently:

- **Internal submodules** (you control the repo): the submodule ships its own `.components.json` — discovered automatically by `--recurse`
- **External OSS submodules** (you don't control the repo): list these in the project's root `.components.json`
- **Vendored code** (copied into `src/`): create `.components.json` alongside the vendored directory

```
device-firmware/
  .artifact-metadata.yaml
  .components.json               <-- external OSS submodule components (libtls, libgui)
  src/
    cjson/
      .components.json           <-- vendored code (with pedigree + patches)
    miniz/
      .components.json           <-- vendored code
  libs/
    libmqtt/
      .components.json           <-- internal submodule (ships its own manifest)
    libtls/                      <-- external OSS (no .components.json here)
    libgui/                      <-- external OSS (no .components.json here)
```

**`.components.json`** (project root) — external OSS submodules that don't ship their own manifest:

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "libtls",
      "version": "3.9.0",
      "type": "library",
      "description": "OpenBSD portable TLS library",
      "supplier": { "name": "OpenBSD" },
      "license": "ISC",
      "purl": "pkg:generic/openbsd/libtls@3.9.0",
      "external_references": [
        { "type": "website", "url": "https://www.libressl.org/" },
        { "type": "vcs", "url": "https://github.com/libressl/portable" },
        { "type": "distribution", "url": "https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.9.0.tar.gz" }
      ],
      "hashes": [
        { "algorithm": "SHA-256", "value": "e3b0c44..." }
      ],
      "scope": "required",
      "tags": ["core", "networking"]
    },
    {
      "name": "libgui",
      "version": "2.0.0",
      "type": "library",
      "description": "LVGL embedded GUI toolkit",
      "supplier": { "name": "LVGL" },
      "license": "MIT",
      "purl": "pkg:generic/lvgl/libgui@2.0.0",
      "external_references": [
        { "type": "website", "url": "https://lvgl.io/" },
        { "type": "distribution", "url": "https://github.com/lvgl/lvgl/archive/refs/tags/v2.0.0.tar.gz" }
      ],
      "hashes": [
        { "algorithm": "SHA-256", "value": "abc123..." }
      ],
      "scope": "optional",
      "tags": ["display"]
    }
  ]
}
```

> For native and vendored components, a `distribution` external reference is **strongly recommended**. It's the "where did you fetch this from" answer auditors and supply-chain tools need. Omitting it is one of the things `--strict` mode flags.

**`libs/libmqtt/.components.json`** — internal submodule, ships its own manifest:

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "libmqtt",
      "version": "4.3.0",
      "type": "library",
      "description": "Acme MQTT client library",
      "supplier": { "name": "Acme Corp" },
      "license": "EPL-2.0",
      "purl": "pkg:generic/acme/libmqtt@4.3.0",
      "hashes": [
        { "algorithm": "SHA-256", "value": "9f86d08..." }
      ],
      "scope": "required",
      "depends-on": ["libtls@3.9.0"],
      "tags": ["core", "networking"]
    }
  ]
}
```

**`src/cjson/.components.json`** — vendored JSON parser with a local patch and file-based hash:

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "cjson",
      "version": "1.7.17",
      "type": "library",
      "description": "Ultralightweight JSON parser in ANSI C (vendored fork with local patches)",
      "supplier": { "name": "Dave Gamble" },
      "license": { "id": "MIT", "file": "./LICENSE" },
      "purl": "pkg:github/acme/device-firmware/src/cjson@1.7.17",
      "hashes": [
        { "algorithm": "SHA-256", "file": "./cJSON.c" }
      ],
      "pedigree": {
        "ancestors": [
          { "purl": "pkg:github/DaveGamble/cJSON@1.7.17" }
        ],
        "patches": [
          {
            "type": "backport",
            "diff": {
              "url": "./patches/cjson-fix-int-overflow.patch"
            },
            "resolves": [
              { "type": "security", "name": "CVE-2024-XXXXX" }
            ]
          }
        ]
      },
      "scope": "required",
      "tags": ["core"]
    }
  ]
}
```

**`src/miniz/.components.json`** — vendored compression library:

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
        { "algorithm": "SHA-256", "file": "./miniz.c" }
      ],
      "scope": "required",
      "tags": ["core"]
    }
  ]
}
```

Commit all `.components.json` files (and any patch files they reference) to version control.

## 3. Generate the SBOM

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
- `cjson@1.7.17` with a `pedigree` block describing its upstream ancestor and the local patch

## 4. Per-build variants

The gateway ships two firmware variants from the same codebase: a headless base variant and a display variant with a GUI. Use tags to generate the right SBOM for each:

```bash
# Base variant -- core only (cjson + miniz + libmqtt + libtls)
sbomasm generate sbom -r . -o device-firmware-base-2.1.0.cdx.json --tags core

# Display variant -- core + display (cjson + miniz + libmqtt + libtls + libgui)
sbomasm generate sbom -r . -o device-firmware-display-2.1.0.cdx.json --tags core,display
```

## 5. Validate with sbomqs

Generating an SBOM isn't enough — Acme needs to confirm it meets the compliance bar their customers and regulators (NTIA, CRA, BSI) expect. Run [sbomqs](https://github.com/interlynk-io/sbomqs) against the generated file:

```bash
# Score against NTIA Minimum Elements — the baseline every framework builds on
sbomqs score --profile ntia device-firmware-2.1.0.cdx.json
```

**The goal is full NTIA Minimum Elements compliance — not a particular tool score.** sbomqs surfaces the gap as a report; what matters is that every field the NTIA baseline mandates (supplier, name, version, hash, unique identifier, dependency relationships, author, timestamp) is present and accurate for every component. Anything sbomqs flags is a compliance hole: fix the `.components.json` that's missing the field and re-run `generate sbom`. The developer loop is generate → score → fix manifest → regenerate, all offline from source manifests, no scanning required.

For additional frameworks, score against their profiles too:

```bash
sbomqs score --profile bsi   device-firmware-2.1.0.cdx.json
sbomqs score --profile fsct device-firmware-2.1.0.cdx.json
```

See the [Validation section in the spec](./generate-sbom.md#validation) for target scores on higher-tier frameworks.

## 6. Wire it into CI

Acme puts the whole loop into a GitHub Actions job that runs on every PR and every tag push. The SBOM is generated in a dedicated fast job (not blocked on the long firmware build), checked for NTIA Minimum Elements compliance with sbomqs, archived as a workflow artifact, and — on tag pushes — attached to the GitHub release:

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
          go install github.com/interlynk-io/sbomasm/v2@latest
          go install github.com/interlynk-io/sbomqs@latest
      - name: Generate SBOM
        run: sbomasm generate sbom -r . --strict -o device-firmware-${{ github.ref_name }}.cdx.json
      - name: Score SBOM (NTIA minimum elements)
        run: sbomqs score --profile ntia device-firmware-${{ github.ref_name }}.cdx.json
      - name: Upload workflow artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: device-firmware-${{ github.ref_name }}.cdx.json
      - name: Attach to GitHub release
        if: startsWith(github.ref, 'refs/tags/')
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: gh release upload "$GITHUB_REF_NAME" device-firmware-${{ github.ref_name }}.cdx.json
```

Run order matters: **generate first, score second, upload third**. If sbomqs reports a new NTIA Minimum Elements gap, the upload step never runs — Acme never ships an SBOM that doesn't meet the regulatory baseline. Note the use of `--strict` on `generate sbom`: that promotes the quality warnings from [Strict mode checks](./generate-sbom.md#strict-mode-checks) to hard errors so a missing license or missing distribution URL fails the PR in review, not at release time. Between `--strict` catching omissions at generate time and `sbomqs` grading the result against NTIA, there are two independent gates before a release goes out — and the goal both gates serve is the same: ship something a regulator would accept.

See the [CI Integration section in the spec](./generate-sbom.md#ci-integration) for pattern details.

## 7. Ongoing maintenance

Acme updates libmqtt from 4.3.0 to 4.4.0. The developer edits `libs/libmqtt/.components.json` (update version, hash, purl) and commits. The `depends-on` entry for `libtls@3.9.0` doesn't need to change because libtls's version didn't move. Re-running `sbomasm generate sbom -r .` produces an updated SBOM deterministically — no scanning, no false positives. The CI job from step 6 runs on the PR, regenerates the SBOM, re-scores it, and fails the build if the update introduced a regression (e.g. the new libmqtt drops a required field).

Because cjson's hash is declared as `{ "file": "./cJSON.c" }`, the hash is recomputed on each generate run. If the vendored file silently changes, the new hash lands in the SBOM automatically; if a developer intends to freeze the hash, they can pin it with `"value"` instead.

---

## Further reading

- [`generate-sbom.md`](./generate-sbom.md) — feature specification: flags, schema details, composition rules, strict-mode checks, determinism, validation, CI integration.
- [`generate-sbom-example-python-lxml.md`](./generate-sbom-example-python-lxml.md) — the companion hybrid Python + native example using lxml. Demonstrates `cyclonedx-py` + `sbomasm assemble --flatMerge` for a mixed-ecosystem project, plus a vendored + patched local C module showing `pedigree` and the directory-based hash form.
