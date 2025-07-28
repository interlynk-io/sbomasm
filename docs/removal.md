# sbomasm removal command

This command is designed to supports following primary use cases:

- **Field Removal**(removal of fields from metadata, components and dependencies)
- **Component Removal**(removal of entire component and their respective assets like dependencies or files, etc)
- **Dependency Removal**(removal of entire dependency relationships and associated components)

## Example Scenarios

Below are more detailed and categorized examples to help users understand the command:

### Example of "Field Removal"

- Document Field Removal
  - Remove an entire author field from the SBOM document.
  - Remove a particulr author with value <hello@interlynk.io> from the SBOM document

- Components Field Removal
  - Remove a entire purl field from a particular component having name "foo" and version "v1.0.0"
  - Remove a specific purl from the component having a value "pkg:golang/cloud.google.com/go/auth@v0.15.0"
- Dependency Field Removal (Currently, NOT SUPPPORTED)
  - Remove a dependency from the dependencies with a key "pkg:golang/sigs.k8s.io/yaml@v1.4.0?type=module"

### Example of "Component Removal"

- Remove a component with a name and verion(be default it will also remove it's dependencies)
- Remove all components with a key "license" and value "Apache-2.0"(also their dependencies)
- Remove all components having field purl with value "pkg:golang/org/xyz/abc@v1.0.0"

### Example of "Dependency Removal"

- Remove a dependency with id "pkg:golang/sigs.k8s.io/structured-merge-diff/v4@v4.6.0?type=module" and corresponding components.

This command enables users to remove specific fields, components, or dependencies from an SBOM document. The design prioritizes clarity, safety, and interoperability across SPDX and CycloneDX formats.

## Why Common Field Method?

We initially considered two approaches for field removal:

- **Schema Based Removal** – where users specify exact schema paths (e.g., CreationInfo->Creator->Person for SPDX).

- **Common Fields-Based Removal** – where users simply target common fields (e.g., author, license, repository, purl, cpe, supplier, etc).

We decided to proceed with the **common field-based** method for the following reasons:

✅ No need to know full JSON paths of fields located in SPDX and CycloneDX.

✅ Compatible across SPDX and CycloneDX.

✅ Focuses on high-level user intent instead of internal SBOM layout

## sbomasm implementation

### 1. Field Removal

Removes metadata fields from the document or component scopes.

#### Common Fields supported for metadata

- `author`
- `supplier`
- `tool`
- `lifecycle`
- `license`
- `description`
- `repository`
- `timestamp`

### Common Fields supported for component

- `author`
- `copyright`
- `cpe`
- `description`
- `hash`
- `license`
- `purl`
- `repo`
- `supplier`
- `type`

#### Common Syntax

```bash
sbomasm rm --field <field> --scope <document|component> [--value <v>] [--name <component-name>] [--version <component-version>] [--all]
```

#### Examples on "Field Removal from document"

- Remove all authors from the document:

  ```bash
  sbomasm rm --field author --scope document
  ```

- Remove authors with value <hello@interlynk.io> from document:

  ```bash
  sbomasm rm --field author --scope document --value "hello@interlynk.io"
  ```

**NOTE**: Currently we don't support removal of fields based on the provided key, currntly we only accept values of that field. Basically `key` is present where key-value pairs are there.

For Example:

  ```json
  "authors": [
          {
              "name": "Interlynk",
              "email": "hello@interlynk.io"
          },
          {
              "name": "VulnCon",
              "email": "vulncon@sbom.dev"
          },
          {
              "name": "Interlynk",
              "email": "hi@interlynk.io"
          }
      ],
  ```

So, if you provide command the below way:

 ```bash
  sbomasm rm --field author --scope document --value "Interlynk"
  ```

Providing value as "key", i.e "Interlynk" or "VulnCon" instead of <hi@interlynk.io> or <hello@interlynk.io> or <vulncon@sbom.dev>, wouldnt work.

#### Example on "Field Removal" from a specific component

- Remove license from a specific component having name `github.com/fluxcd/pkg/oci` and version `v1.21.0`

  ```bash
  sbomasm rm --field license --scope component --name "nginx" --version "v1.21.0"
  ```

- Remove purl from a specific component having name `nginx` and version `v1.21.0`

  ```bash
  sbomasm rm --field purl --scope component --name "nginx" --version "v1.21.0"
  ```

- Remove supplier from a specific component having name `nginx` and version `v1.21.0`

  ```bash
  sbomasm rm --field supplier --scope component --name "nginx" --version "v1.21.0"
  ```

#### Example on "Field Removal" from all components

- Remove license from a all components

  ```bash
  sbomasm rm --field license --scope component -a
  ```

- Remove license having a value "Apache-2.0" from all components

  ```bash
  sbomasm rm --field license --value "Apache-2.0" --scope component -a
  ```

- Remove purl from a all components

  ```bash
  sbomasm rm --field purl --scope component -a
  ```

- Remove purl having a value `pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.17.0` from all components

  ```bash
  sbomasm rm --field purl --value "pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.17.0" --scope component -a
  ```

- Remove supplier from all components

  ```bash
  sbomasm rm --field supplier --scope component -a
  ```

- Remove supplier having a value `Azure (https://azure.microsoft.com)` from all components

  ```bash
  sbomasm rm --field supplier --value "Azure (https://azure.microsoft.com)" --scope component -a
  ```

### 2. Component Removal

Remove a entire component and its dependency or file links.

#### Syntax

```bash
sbomasm rm --components --name <component-name> --version <component-version> [--deep]
```

#### Example

- Remove a entire component with a name `nginx` and version `v2.0.5`. And by default it will also remove all it's dependencies and files.

```bash
sbomasm rm --components --name nginx --version "v2.0.5"
```

### 3. Dependency Removal(Not yet supported)

Remove a dependency edge, and optionally remove the target component as well.

#### Syntax:

```bash
sbomasm rm --dependency --id <purl>
```

#### Example:

```bash
sbomasm rm --dependency --id pkg:golang/sigs.k8s.io/structured-merge-diff/v4@v4.6.0
```

- Removes the dependency links to/from this PURL
- Removes the component associated with this PURL

### 4. Component Removal Based on Field Matching

Remove components whose field matches a specific value (e.g., by PURL).

#### Syntax:

```bash
sbomasm rm --component --field <field> --value <value>
```

#### Example:

```bash
sbomasm rm --component --field purl --value pkg:golang/org/xyz/abc@v1.0.0
```

- Finds all components with a matching PURL
- Removes them and their related dependency links

## Optional Flags and Enhancements

| Flag        | Purpose                                    |
| ----------- | ------------------------------------------ |
| `--dry-run` | Show changes without applying them         |
| `--summary` | Print list of removed components/fields    |
| `--output`  | Output the modified SBOM to a file         |
| `--deep`    | Recursively remove all linked dependencies |
