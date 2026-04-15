# Worked Example: Acme XML Validator (lxml + Bundled Native Libs + Vendored C Module)

> This is the hybrid Python + native worked example for [`generate-sbom.md`](./generate-sbom.md). It walks through the workflow where Python packages are discovered by an external tool ([`cyclonedx-py`](https://github.com/CycloneDX/cyclonedx-python)), native libraries bundled inside a wheel are hand-curated via `.components.json`, a locally-vendored C module with a patch is documented via `pedigree`, and everything is merged into a unified CycloneDX SBOM with **`sbomasm assemble --flatMerge`**. It doubles as the reference for the **wheel-inspection workflow** — how to pull real version numbers and license data out of an installed wheel when the producer hasn't adopted [PEP 770](https://peps.python.org/pep-0770/) yet.

This example follows **Acme Corp's XML validator** (`xml-validator`), a command-line tool that validates XML documents against an XSD schema. The service has four kinds of dependencies:

- **Python packages** declared in `pyproject.toml` — `lxml` for XML/XSD parsing and `click` for CLI wiring. Discovered by `cyclonedx-py` from the installed virtualenv.
- **Native libraries bundled inside lxml's wheel** — `libxml2`, `libxslt`, `libexslt`, `zlib`. **Invisible to Python SBOM tools.** Hand-curated via a root `.components.json` using the wheel's own headers and license files as the source of truth.
- **Vendored native code** — a small C module Acme maintains under `src/acme_schema_cache/` for caching compiled XSD schemas across validation runs. Forked from an upstream project (`fast-xsd-cache`), with a local patch fixing a cache-eviction integer overflow. Documented via a nested `.components.json` with a `pedigree` block.
- **No per-build variants** — unlike the C firmware example, `xml-validator` ships a single release; tags exist on components but aren't used for filtering.

The end result is a single `xml-validator.cdx.json` that describes every piece of the tool — Python deps, upstream native libs bundled in the wheel, and the locally-patched C module — **meets NTIA Minimum Elements compliance** (validated via sbomqs), and ships with every tagged release.

## 0. Start with your project

```bash
git clone git@github.com:acme/xml-validator.git
cd xml-validator
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

The repo layout:

```
xml-validator/
  pyproject.toml                 <-- Python deps (input to cyclonedx-py)
  .artifact-metadata.yaml        <-- sbomasm artifact metadata (primary component)
  .components.json               <-- native libs bundled inside lxml's wheel
  src/
    xml_validator/
      __init__.py
      cli.py                     <-- click entrypoint
      validate.py                <-- lxml-based XSD validation
      schema_cache_bridge.py     <-- ctypes wrapper around acme_schema_cache
    acme_schema_cache/           <-- vendored C module (forked + locally patched)
      .components.json           <-- vendored code manifest with pedigree
      schema_cache.c
      schema_cache.h
      LICENSE
      patches/
        fix-eviction-overflow.patch
  schemas/
    invoice.xsd                  <-- example XSD the tool ships with
  tests/
```

The four native libraries lxml's wheel statically links — libxml2, libxslt, libexslt, and zlib — live **inside** the installed `.pyd` / `.so` files. `pip`, `cyclonedx-py`, and every other Python-level tool can't see them; the Windows wheel doesn't even ship a separate `lxml.libs/` directory the way manylinux wheels sometimes do for other projects. Acme has to document the native side by hand.

The `src/acme_schema_cache/` directory is Acme's own: a small C module (a few `.c` / `.h` files) that caches compiled XSD schema objects across invocations so the tool isn't paying libxml2's schema-compilation cost on every run. Acme forked it from the upstream `fast-xsd-cache` project, applied a local patch fixing a cache-eviction integer overflow, and vendors the result inside this repo. Because the code is patched it can no longer claim the upstream identity — see [Purl on patched components](./generate-sbom.md#purl-on-patched-components).

## 1. Generate the artifact metadata config

```bash
sbomasm generate config > .artifact-metadata.yaml
```

Edit `.artifact-metadata.yaml` to describe the CLI:

```yaml
app:
  name: xml-validator
  version: 0.1.0
  description: Acme XML validator CLI — validates XML documents against an XSD schema
  primary_purpose: application
  supplier:
    name: Acme Corp
    email: engineering@acme.com
  author:
    - name: Sam Liu
      email: sam@acme.com
  license:
    id: Apache-2.0
  purl: pkg:generic/acme/xml-validator@0.1.0
  copyright: Copyright 2026 Acme Corp
  lifecycles:
    - phase: build
  external_references:
    - type: website
      url: https://acme.example.com/xml-validator
    - type: vcs
      url: https://github.com/acme/xml-validator
    - type: distribution
      url: https://registry.acme.example.com/xml-validator
```

## 2. Declare Python dependencies in `pyproject.toml`

A minimal PEP 621 `pyproject.toml` — just `lxml` for the parsing work and `click` for the CLI:

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "xml-validator"
version = "0.1.0"
description = "Acme XML validator CLI"
requires-python = ">=3.12"
dependencies = [
    "lxml>=6.0.0",
    "click>=8.1.0",
]

[project.scripts]
xml-validator = "xml_validator.cli:main"

[project.optional-dependencies]
dev = ["pytest>=8.0"]
```

## 3. Generate the Python-side SBOM with `cyclonedx-py`

Install `cyclonedx-py` into the same virtualenv (package name is `cyclonedx-bom`; executable is `cyclonedx-py`):

```bash
pip install cyclonedx-bom
cyclonedx-py environment --output-file python-sbom.cdx.json
```

The resulting `python-sbom.cdx.json` contains:

- `lxml@6.0.4` with `purl: pkg:pypi/lxml@6.0.4`
- `click@8.x` with its transitive deps
- Exactly **zero** native libraries — `cyclonedx-py` has no visibility into the compiled `.pyd` / `.so` binaries inside the lxml wheel

This is the **Python half** of the eventual unified SBOM.

## 4. Inspect the lxml wheel to find bundled native libs

Before writing `.components.json`, Acme has to figure out what's actually inside lxml's wheel. The inspection workflow below is reproducible — every wheel ships enough metadata to answer these questions without guessing.

> **Check for PEP 770 first.** If the installed wheel already ships SBOMs per [PEP 770](https://peps.python.org/pep-0770/), skip this entire step — just read the files:
>
> ```bash
> ls .venv/lib/python*/site-packages/lxml-*.dist-info/sboms/ 2>/dev/null
> ```
>
> If that directory exists and contains `.cdx.json` or `.spdx.json` files, you can consume them directly with `sbomasm assemble --flatMerge` and delete the rest of step 4 / step 5 entirely. For lxml 6.0.4 (the version this example is built against) the directory does **not** exist — lxml hasn't adopted PEP 770 yet, so the hand-curation below is still required. Re-check whenever you bump lxml; the day it ships an `sboms/` directory is the day you can delete most of this file.

**Find the wheel's license documents:**

```bash
ls .venv/lib/python*/site-packages/lxml-*.dist-info/licenses/
# LICENSE.txt          — lxml's own BSD-3-Clause license
# LICENSES.txt         — summary of bundled-license terms
```

The `METADATA` file at `.venv/lib/python*/site-packages/lxml-*.dist-info/METADATA` confirms the package license (`License: BSD-3-Clause`), the maintainer (`lxml dev team`), the home page (`https://lxml.de/`), and the VCS (`https://github.com/lxml/lxml`).

**Extract bundled native-lib versions from the headers lxml ships:**

lxml's Cython bindings ship C headers for every native library it links, and those headers carry version macros. A single grep pulls every version Acme needs:

```bash
LXML_INC=$(echo .venv/lib/python*/site-packages/lxml/includes)

grep LIBXML_DOTTED_VERSION   "$LXML_INC/libxml/xmlversion.h"
# #define LIBXML_DOTTED_VERSION "2.11.9"

grep LIBXSLT_DOTTED_VERSION  "$LXML_INC/libxslt/xsltconfig.h"
# #define LIBXSLT_DOTTED_VERSION "1.1.39"

grep LIBEXSLT_DOTTED_VERSION "$LXML_INC/libexslt/exsltconfig.h"
# #define LIBEXSLT_DOTTED_VERSION "0.8.21"

grep 'define ZLIB_VERSION'   "$LXML_INC/extlibs/zlib.h"
# #define ZLIB_VERSION "1.3.2"
```

Those four strings are the authoritative version numbers for the native libraries actually compiled into this particular lxml wheel. Don't guess from the lxml release notes; read the headers. If lxml rebuilds its wheel against a newer libxml2 without bumping its own version, the headers are the only ground truth.

**Fetch upstream release hashes** (one-time, per native-lib version):

```bash
# libxml2 — hosted on download.gnome.org
curl -LO https://download.gnome.org/sources/libxml2/2.11/libxml2-2.11.9.tar.xz
sha256sum libxml2-2.11.9.tar.xz

# libxslt (which also ships libexslt in the same tarball)
curl -LO https://download.gnome.org/sources/libxslt/1.1/libxslt-1.1.39.tar.xz
sha256sum libxslt-1.1.39.tar.xz

# zlib
curl -LO https://zlib.net/zlib-1.3.2.tar.gz
sha256sum zlib-1.3.2.tar.gz
```

Record the SHA-256 output into `.components.json` in step 5. These are the upstream release-archive digests — they're what a compliance scanner expects to see, not a hash of the `.pyd` file itself.

## 5. Write the native-side component manifests

Acme writes **two** `.components.json` manifests. The **root** one documents the upstream native libraries bundled inside lxml's wheel (the four versions from step 4). The **nested** one at `src/acme_schema_cache/.components.json` documents the locally-vendored C module. Splitting them this way means the vendored code's hash covers the files Acme actually maintains, not a sibling library they only consume.

### Root manifest — upstream native libs bundled inside lxml

Armed with the four versions and four upstream hashes from step 4, Acme writes the root `.components.json`:

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "libxml2",
      "version": "2.11.9",
      "type": "library",
      "description": "XML parser library — statically linked into lxml's wheel",
      "supplier": { "name": "GNOME Project (libxml2 maintainers)" },
      "license": "MIT",
      "purl": "pkg:generic/gnome/libxml2@2.11.9",
      "external_references": [
        { "type": "website", "url": "https://gitlab.gnome.org/GNOME/libxml2" },
        { "type": "vcs", "url": "https://gitlab.gnome.org/GNOME/libxml2" },
        { "type": "distribution", "url": "https://download.gnome.org/sources/libxml2/2.11/libxml2-2.11.9.tar.xz" }
      ],
      "hashes": [
        { "algorithm": "SHA-256", "value": "REPLACE_WITH_sha256sum_OUTPUT_FROM_STEP_4" }
      ],
      "scope": "required",
      "tags": ["lxml-native", "xml-parser"]
    },
    {
      "name": "libxslt",
      "version": "1.1.39",
      "type": "library",
      "description": "XSLT engine — statically linked into lxml's wheel",
      "supplier": { "name": "GNOME Project (libxslt maintainers)" },
      "license": "MIT",
      "purl": "pkg:generic/gnome/libxslt@1.1.39",
      "external_references": [
        { "type": "website", "url": "https://gitlab.gnome.org/GNOME/libxslt" },
        { "type": "vcs", "url": "https://gitlab.gnome.org/GNOME/libxslt" },
        { "type": "distribution", "url": "https://download.gnome.org/sources/libxslt/1.1/libxslt-1.1.39.tar.xz" }
      ],
      "hashes": [
        { "algorithm": "SHA-256", "value": "REPLACE_WITH_sha256sum_OUTPUT_FROM_STEP_4" }
      ],
      "scope": "required",
      "tags": ["lxml-native", "xslt"]
    },
    {
      "name": "libexslt",
      "version": "0.8.21",
      "type": "library",
      "description": "EXSLT extensions for libxslt. Ships inside the libxslt source tree rather than as its own release, so the distribution URL points at the libxslt tarball.",
      "supplier": { "name": "GNOME Project (libxslt maintainers)" },
      "license": "MIT",
      "purl": "pkg:generic/gnome/libexslt@0.8.21",
      "external_references": [
        { "type": "website", "url": "https://gitlab.gnome.org/GNOME/libxslt" },
        { "type": "distribution", "url": "https://download.gnome.org/sources/libxslt/1.1/libxslt-1.1.39.tar.xz" }
      ],
      "hashes": [
        { "algorithm": "SHA-256", "value": "REPLACE_WITH_sha256sum_OUTPUT_FROM_STEP_4" }
      ],
      "scope": "optional",
      "tags": ["lxml-native", "xslt"]
    },
    {
      "name": "zlib",
      "version": "1.3.2",
      "type": "library",
      "description": "Compression library — statically linked into lxml's wheel for XML decompression support",
      "supplier": { "name": "zlib project" },
      "license": "Zlib",
      "purl": "pkg:generic/madler/zlib@1.3.2",
      "external_references": [
        { "type": "website", "url": "https://zlib.net/" },
        { "type": "vcs", "url": "https://github.com/madler/zlib" },
        { "type": "distribution", "url": "https://zlib.net/zlib-1.3.2.tar.gz" }
      ],
      "hashes": [
        { "algorithm": "SHA-256", "value": "REPLACE_WITH_sha256sum_OUTPUT_FROM_STEP_4" }
      ],
      "scope": "required",
      "tags": ["lxml-native"]
    }
  ]
}
```

Two things to notice about the root manifest:

- **`libexslt` has no independent upstream release.** It's built from sources that ship inside the libxslt tarball, so its `distribution` URL points at the same tarball as libxslt. This is a common real-world nuance — not every bundled lib has a clean 1:1 release artifact. Declaring the parent tarball is the honest answer.
- **None of the four libs carry a `pedigree` block.** lxml statically links unmodified upstream releases. If Acme ever discovers that lxml's wheel ships a patched libxml2 (check via the upstream changelog or the wheel's build script in `lxml/buildlibxml.py`), add a `pedigree` block with the upstream `purl` under `ancestors` and the patch under `patches`, and switch the top-level `purl` to a repo-local form so it no longer collides with upstream — see [Purl on patched components](./generate-sbom.md#purl-on-patched-components). The vendored `acme-schema-cache` below is the reference for how that structure looks in practice.

### Nested manifest — vendored `acme-schema-cache` with pedigree

The vendored C module has its own manifest at `src/acme_schema_cache/.components.json`. It sits **next to** the source files it describes, so the hash is computed directly from the files on disk and the `LICENSE` / patch files are referenced by relative path that resolves naturally:

```json
{
  "schema": "interlynk/component-manifest/v1",
  "components": [
    {
      "name": "acme-schema-cache",
      "version": "0.2.0",
      "type": "library",
      "description": "Acme-vendored fork of fast-xsd-cache — in-process cache for compiled XSD schemas. Ships with a local patch fixing a cache-eviction integer overflow.",
      "supplier": { "name": "Acme Corp" },
      "license": { "id": "MIT", "file": "./LICENSE" },
      "purl": "pkg:github/acme/xml-validator/src/acme_schema_cache@0.2.0",
      "hashes": [
        { "algorithm": "SHA-256", "path": "./", "extensions": ["c", "h"] }
      ],
      "pedigree": {
        "ancestors": [
          { "purl": "pkg:github/fast-xsd/fast-xsd-cache@0.2.0" }
        ],
        "patches": [
          {
            "type": "backport",
            "diff": {
              "url": "./patches/fix-eviction-overflow.patch"
            },
            "resolves": [
              { "type": "security", "name": "CVE-2025-YYYYY" }
            ]
          }
        ]
      },
      "scope": "required",
      "tags": ["acme-native"]
    }
  ]
}
```

Four things to notice about the vendored manifest:

- **Repo-local purl.** The `purl` is `pkg:github/acme/xml-validator/src/acme_schema_cache@0.2.0`, not the upstream `pkg:github/fast-xsd/fast-xsd-cache@0.2.0`. The upstream identity lives in `pedigree.ancestors[]`. A patched fork is no longer upstream — claiming its purl would mislead vulnerability scanners into matching advisories against code Acme isn't actually running. The generator hard-errors if a component's top-level `purl` equals any ancestor purl, even without `--strict`.
- **Directory-based hash via `path` + `extensions`.** Instead of hashing a single file with `{ "file": "./schema_cache.c" }`, the manifest uses `{ "path": "./", "extensions": ["c", "h"] }`. The generator walks `src/acme_schema_cache/` (the manifest's own directory, since `./` is relative to the manifest), collects every `.c` and `.h` file, computes each one's SHA-256, and combines them via the sorted-manifest scheme described in [File-based hashes](./generate-sbom.md#file-based-hashes). The result is a single digest that covers every source file in the vendored module — so adding `schema_cache_impl.c` tomorrow changes the digest automatically, without anyone editing the manifest. Hidden files (`.gitignore`, editor dotfiles, `patches/`) are excluded because they start with `.` or don't match the extensions filter.
- **License via `{ id, file }`.** The upstream LICENSE file travels with the vendored source at `src/acme_schema_cache/LICENSE`, so the manifest references it with `{ "id": "MIT", "file": "./LICENSE" }`. The generator reads the file at generate time and embeds the text into the output SBOM. When upstream bumps their LICENSE (rare but it happens), git tracks the change and the next SBOM generation picks it up automatically.
- **Patch diff as a local file URL.** The `diff.url` is `./patches/fix-eviction-overflow.patch`, a relative path the generator reads at generate time and inlines as `diff.text`. Committing the `.patch` file to the repo means the exact patch content ships inside every generated SBOM — auditors can read what the fix actually does without leaving the SBOM.

## 6. Generate the native-side SBOM with `sbomasm generate sbom`

```bash
sbomasm generate sbom \
  -r . \
  --strict \
  -o native-sbom.cdx.json
```

`--recurse` discovers **both** manifests — the root `.components.json` and `src/acme_schema_cache/.components.json` — and merges them into a single native-side SBOM. `--strict` fails the command on any missing NTIA minimum element, including the strict-mode check that fires when a vendored component has a `pedigree` block but its top-level `purl` collides with an ancestor. Cheaper to catch gaps here than during the merge+score step later.

The resulting `native-sbom.cdx.json` contains:

- `xml-validator@0.1.0` as the primary component (from `.artifact-metadata.yaml`)
- All four upstream native libs from the root manifest (`libxml2`, `libxslt`, `libexslt`, `zlib`)
- `acme-schema-cache@0.2.0` with its `pedigree` block intact — ancestor purl, inlined patch diff, resolved CVE reference
- `metadata.lifecycles = [{ phase: "build" }]`

## 7. Merge with `sbomasm assemble --flatMerge`

Combine the Python-side and native-side SBOMs into one unified document:

```bash
sbomasm assemble -f \
  -n xml-validator -v 0.1.0 -t application \
  -o xml-validator.cdx.json \
  python-sbom.cdx.json \
  native-sbom.cdx.json
```

- `-f` / `--flatMerge` — flat merge mode
- `-n xml-validator -v 0.1.0 -t application` — declares the new root component of the merged SBOM (required together for non-augment merges)
- `-o xml-validator.cdx.json` — output path
- Positional args are the input SBOMs, auto-detected by extension

The merged file contains:

- A single root `xml-validator@0.1.0`
- `lxml@6.0.4` + `click@8.x` + their transitives (from the Python SBOM)
- `libxml2@2.11.9`, `libxslt@1.1.39`, `libexslt@0.8.21`, `zlib@1.3.2`, and `acme-schema-cache@0.2.0` with pedigree (from the native SBOM)
- `describes` relationships from the new root to every pooled component
- Deduplicated by `name@version`

### Flat merge vs hierarchical merge

`-f` / `--flatMerge` unions all components into a flat inventory under the new root and drops every dependency edge except `describes`. That's the right call for `xml-validator` — customers scanning the release just need to know what's in the box, not that lxml depends on libxml2 inside the wheel. If you need the dependency graph preserved across sources (e.g. you want `lxml → libxml2` edges to survive the merge so a downstream SCA tool can trace provenance), use `-m` / `--hierMerge` instead, which nests each input SBOM as a sub-component under the new root and preserves every dependency edge. Pick flat for inventory-style consumers; pick hierarchical for provenance-style consumers. See [`docs/assemble.md`](../assemble.md) for the full description of both modes.

## 8. Validate the merged SBOM with sbomqs

```bash
sbomqs score --profile ntia xml-validator.cdx.json
```

**Target: full NTIA Minimum Elements compliance.** sbomqs is the measurement tool, not the goal — what matters is that every field NTIA mandates (supplier, component name, version, hash, unique identifier, dependency relationship, author, timestamp) is present for every component. If sbomqs reports any missing fields, the merged SBOM has a compliance gap in one of its two input halves:

- **Python side** — `cyclonedx-py` is usually the weak link. Some PyPI packages ship without supplier or license metadata and that gap propagates into the merged SBOM. Re-run `cyclonedx-py` after fixing upstream, or fall back to `cyclonedx-py requirements -r requirements.txt` for more control.
- **Native side** — fix the `.components.json` that's missing the field. `sbomasm generate sbom --strict` should have caught this in step 6 — if something slipped through, tighten the strict-mode rules.

For other regulatory frameworks:

```bash
sbomqs score --profile bsi   xml-validator.cdx.json
sbomqs score --profile fsct  xml-validator.cdx.json
```

## 9. Wire it into CI

The full pipeline runs as a single GitHub Actions job. Three SBOM-producing steps (cyclonedx-py, sbomasm generate sbom, sbomasm assemble) feed a single score step:

```yaml
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install tools
        run: |
          pip install cyclonedx-bom
          go install github.com/interlynk-io/sbomasm@latest
          go install github.com/interlynk-io/sbomqs@latest
      - name: Install Python deps into venv
        run: pip install -e .
      - name: Generate Python-side SBOM
        run: cyclonedx-py environment --output-file python-sbom.cdx.json
      - name: Generate native-side SBOM
        run: sbomasm generate sbom -r . --strict -o native-sbom.cdx.json
      - name: Merge SBOMs (flat)
        run: |
          sbomasm assemble -f \
            -n xml-validator -v "${{ github.ref_name }}" -t application \
            -o xml-validator-${{ github.ref_name }}.cdx.json \
            python-sbom.cdx.json native-sbom.cdx.json
      - name: Score merged SBOM
        run: sbomqs score --profile ntia xml-validator-${{ github.ref_name }}.cdx.json
      - name: Upload workflow artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: xml-validator-${{ github.ref_name }}.cdx.json
      - name: Attach to GitHub release
        if: startsWith(github.ref, 'refs/tags/')
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: gh release upload "$GITHUB_REF_NAME" xml-validator-${{ github.ref_name }}.cdx.json
```

Generate Python → generate native → merge → check NTIA compliance → upload. If sbomqs reports a new NTIA Minimum Elements gap, the upload is skipped and the release ships without an SBOM attachment — safer than shipping one that wouldn't satisfy regulators. `--strict` on `generate sbom` is a second independent gate catching the same class of gap at manifest-author time; both gates exist to serve the same goal of shipping an SBOM a regulator would accept.

## 10. Ongoing maintenance

Acme's workflow splits into three parts — two automatic and two that need a human, depending on what upstream changed:

- **Python side (automatic)** — update `pyproject.toml` (or let dependabot/renovate do it), commit, CI regenerates `python-sbom.cdx.json` via `cyclonedx-py environment`. No manual work.

- **lxml bundled libs (manual for now)** — re-run the step 4 inspection commands against the newly-installed lxml:

  ```bash
  LXML_INC=$(echo .venv/lib/python*/site-packages/lxml/includes)
  grep LIBXML_DOTTED_VERSION   "$LXML_INC/libxml/xmlversion.h"
  grep LIBXSLT_DOTTED_VERSION  "$LXML_INC/libxslt/xsltconfig.h"
  grep LIBEXSLT_DOTTED_VERSION "$LXML_INC/libexslt/exsltconfig.h"
  grep 'define ZLIB_VERSION'   "$LXML_INC/extlibs/zlib.h"
  ```

  If any version changed, edit the root `.components.json`, re-fetch the upstream hash, commit. **This is the step that disappears the day lxml ships PEP 770 SBOMs** at `.dist-info/sboms/` — see the PEP 770 callout in step 4.

- **Vendored `acme-schema-cache` (manual, infrequent)** — if Acme rebases onto a newer upstream `fast-xsd-cache`, bump the `version` field in `src/acme_schema_cache/.components.json`, update the `pedigree.ancestors[].purl` to the new upstream release, replace the patch file under `./patches/` if the diff changed, and update `pedigree.patches[].resolves[]` if the set of fixed CVEs moved. **The hash does not need hand-editing** — the `{ "path": "./", "extensions": ["c", "h"] }` entry is recomputed over the actual source on every `sbomasm generate sbom` run, so any change to `schema_cache.c` / `schema_cache.h` lands in the SBOM automatically. That's the whole point of the directory hash form: the source is the source of truth, not a hand-pasted digest.

- **Regression check (automatic)** — the CI job from step 9 runs on every PR, regenerates the merged SBOM, re-scores it with sbomqs, and fails the build if the update introduced a compliance regression.

A practical tip for the "manual for now" pieces: script the step 4 grep into a `tools/inspect-lxml.sh` one-liner, run it in CI, and diff against the committed `.components.json`. If the diff is non-empty, the CI fails with a message telling the developer to update the manifest. That turns "manual for now" into "automated drift detection with a human in the loop for the edit" — and because the vendored module's hash is directory-based, the only thing that ever needs a human edit is a version-number bump on an upstream rebase.

---

## Further reading

- [`generate-sbom.md`](./generate-sbom.md) — feature specification: flags, schema details, composition rules, strict-mode checks, determinism, validation, CI integration.
- [`generate-sbom-example.md`](./generate-sbom-example.md) — the pure-C firmware example (Acme IoT gateway). Read this for the native-only workflow without any Python in the mix.
- [`../assemble.md`](../assemble.md) — full `sbomasm assemble` documentation, including all four merge modes (flat / hierarchical / assembly / augment).
- [`cyclonedx-py`](https://github.com/CycloneDX/cyclonedx-python) — the Python SBOM tool used in step 3.
- [lxml project](https://lxml.de/) and [lxml GitHub](https://github.com/lxml/lxml) — the upstream Python binding wrapping libxml2 / libxslt.
- [PEP 770](https://peps.python.org/pep-0770/) — the accepted (April 2025) Python packaging PEP for shipping SBOMs inside wheels. When lxml adopts it, step 4 of this walkthrough collapses into a single `ls .dist-info/sboms/`.
