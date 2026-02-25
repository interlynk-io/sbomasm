# Convert Command

The `convert` command convert an SBOM from its native format (SPDX or CycloneDX) into a CSV format, which is flat, human-readable output. This is useful for auditing, reporting, and importing SBOM data into spreadsheets or data pipelines.

## Overview

`sbomasm convert` allows you to:

- Export SBOM components into a flat CSV file
- Inspect all component fields in a tabular view
- Feed SBOM data into external tools (spreadsheets, databases, dashboards)
- Normalize SPDX and CycloneDX into a common schema

## Basic Usage

```bash
sbomasm convert [flags] <input-sbom-file>
```

## Command Options

- `-f, --format <string>`: Output format (default: `csv`)
  - Currently supported: `csv`

- `-o, --output <path>`: Path to the output file
  - If not specified, output is written to stdout

- `--debug`: Enable debug logging

## CSV Output Schema

The CSV output always includes a header row followed by one row per component. Both SPDX and CycloneDX inputs produce the same columns:

| Column | Description |
|--------|-------------|
| `Name` | Component or file name |
| `Version` | Version string |
| `Type` | Component type (e.g. `library`, `application`, `FILE`) |
| `Author` | Author name (Person or Organization) |
| `Supplier` | Supplier name |
| `Group` | Component group or namespace (CycloneDX only) |
| `Scope` | Component scope: `required`, `optional`, `excluded` (CycloneDX only) |
| `Purl` | Package URL |
| `Cpe` | CPE identifier |
| `LicenseExpressions` | Comma-separated license expressions |
| `LicenseNames` | Comma-separated license names or SPDX IDs |
| `Copyright` | Copyright text |
| `Description` | Component description |
| `MD5` | MD5 hash |
| `SHA-1` | SHA-1 hash |
| `SHA-256` | SHA-256 hash |
| `SHA-512` | SHA-512 hash |

### Format-specific notes

#### CycloneDX

- `Type` is the component's `type` field (e.g. `library`, `application`, `firmware`)
- `Author` maps to `component.author`
- `Group` and `Scope` are populated from CycloneDX fields; left blank for SPDX
- `LicenseExpressions` collects `expression` entries; `LicenseNames` collects `license.name` (falling back to `license.id`)
- The metadata component (if present) is written as the first row

#### SPDX

- `Type` is `primaryPackagePurpose` (e.g. `APPLICATION`, `LIBRARY`); blank if unset
- `Author` is extracted from `PackageOriginator` for both `Person` and `Organization` types
- `Group` and `Scope` have no SPDX equivalent and are always blank
- `LicenseExpressions` maps to `PackageLicenseDeclared`; `LicenseNames` maps to `PackageLicenseComments`
- SPDX files are emitted with `Type = FILE`, version blank, and fields without a file-level equivalent left blank

## Examples

### 1. Print to stdout/console/terminal

```bash
sbomasm convert --format csv samples/cdx/sbomqs-cdx.json
```

### 2. Write to a provided output file

```bash
sbomasm convert --format csv --output sbom.csv samples/cdx/sbomqs-cdx.json
```

### 3. Convert an SPDX SBOM

```bash
sbomasm convert --format csv --output sbom.csv samples/spdx/sbomqs-spdx.json
```

### 4. Check logs via debug

```bash
sbomasm convert --debug --format csv --output sbom.csv input.json
```

## Supported Input Formats

The command auto-detects the input format. No flag is needed to specify it.

| Format | Encodings |
|--------|-----------|
| CycloneDX | JSON, XML |
| SPDX | JSON, YAML, TV (tag-value) |

## Use Cases

### 1. Audit and compliance review

Export an SBOM to CSV and open it in a spreadsheet to review license and supplier information across all components:

```bash
sbomasm convert --format csv --output audit.csv project.cdx.json
```

### 2. Conversion multiple SBOMs in a directory

Convert multiple SBOMs in a directory:

```bash
for f in sboms/*.json; do
  sbomasm convert --format csv --output "csv/$(basename "$f" .json).csv" "$f"
done
```

## See Also

- [Edit Command](edit.md) — Add or update SBOM metadata
- [Enrich Command](enrich.md) — Fill missing license data from ClearlyDefined
- [Assemble Command](assemble.md) — Merge multiple SBOMs into one
