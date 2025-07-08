# sbomasm removal command

This command is designed to supports following primary use cases:

- **Field Removal**(removal of specific metadata fields)
- **Component Removal**(removal of specific components and their dependencies)
- **Dependency Removal**(removal of specific dependency relationships and associated components)

## Example Scenarios

Below are more detailed and categorized examples to help users understand the breadth of this command:

### Example of Field Removal

- Document Removal
  - Remove an author field from the SBOM document.
  - Remove an author field from the SBOM document with a key "Interlynk"
  - Remove an author field from the SBOM document with a key "Interlynk" and value <hello@interlynk.io>
  - Remove an author field from the SBOM document with a value <hello@interlynk.io>
- Component Subject
  - Remove a purl field from the component
  - Remove a purl field from the component with a key "PACKAGE_MANAGER"
  - Remove a purl field from the component with a key "PACKAGE_MANAGER" and value "pkg:golang/cloud.google.com/go/auth@v0.15.0"
  - Remove a purl field from the component with a value "pkg:golang/cloud.google.com/go/auth@v0.15.0"
- Dependency Subject
  - Remove a dependency from the dependencies with a key "pkg:golang/sigs.k8s.io/yaml@v1.4.0?type=module"

### Example of component Removal

- Remove a component with a name and verion(be default it will also remove it's dependencies)
- Remove all components with a key "license" and value "Apache-2.0"(also their dependencies)
- Remove all components having field purl with value "pkg:golang/org/xyz/abc@v1.0.0"

### Example of Dependency Removal:

- Remove a dependency with id "pkg:golang/sigs.k8s.io/structured-merge-diff/v4@v4.6.0?type=module" and corresponding components

This command enables users to remove specific fields, components, or dependencies from an SBOM document. The design prioritizes clarity, safety, and interoperability across SPDX and CycloneDX formats.

## Why Common Field Method?

We initially considered two approaches for field removal:

- **Schema-Aware Removal** – where users specify exact schema paths (e.g., CreationInfo->Creator->Person for SPDX).

- **Common Field-Based Removal** – where users simply target semantic fields (e.g., author, license, repository).

We chose the common field-based method for the following reasons:

✅ Easier to remember and use (no need to know full JSON paths)

✅ Compatible across SPDX and CycloneDX

✅ Focuses on high-level user intent instead of internal SBOM layout

## sbomasm implementation

### 1. Field Removal (Metadata Cleanup)

Removes metadata fields from the document or component scopes.

#### Common Fields:

- `author`
- `supplier`
- `tool`
- `lifecycle`
- `license`
- `description`
- `repository`
- `timestamp`

#### Common Syntax:

```bash
sbomasm rm --field <field> --scope <document|component> [--key <k>] [--value <v>] [--name <component-name>] [--version <component-version>] [--all]
```

#### Examples:

- Remove all authors from the document:

  ```bash
  sbomasm rm --field author --scope document
  ```

- Remove authors named "Messi":

  ```bash
  sbomasm rm --field author --scope document --key Messi
  ```

- Remove authors with specific value:

  ```bash
  sbomasm rm --field author --scope document --value messi.shah@gmail.com
  ```

- Remove license from a specific component:

  ```bash
  sbomasm rm --field license --scope component --name nginx --version 1.21.0
  ```

- Remove description from all components:

  ```bash
  sbomasm rm --field description --scope component --all
  ```

### ✅ 2. Component Removal

Remove a full component and its dependency links.

#### Syntax:

```bash
sbomasm rm --component --name <component-name> --version <component-version> [--deep]
```

#### Example:

```bash
sbomasm rm --component --name nginx --version 2.0.5
```

- Removes the `nginx@2.0.5` component
- Removes all references in `dependencies` or `relationships`

### 3. Dependency Removal

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
