// Copyright 2026 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package csv

import (
	"bytes"
	"context"
	"encoding/csv"
	"os"
	"sync"
	"testing"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

var initLoggerOnce sync.Once

// initTestLogger initializes the production logger exactly once across all tests.
// logger.InitProdLogger panics if called more than once in the same process.
func initTestLogger() {
	initLoggerOnce.Do(logger.InitProdLogger)
}

var cdxSBOM = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-01T00:00:00Z",
    "component": {
	  "bom-ref": "my-app@2.0.0",
      "type": "application",
      "name": "my-app",
      "version": "2.0.0",
      "supplier": { 
	    "name": "Acme Corp" 
	  },
      "description": "My application",
      "purl": "pkg:npm/my-app@2.0.0",
      "cpe": "cpe:2.3:a:acme:my-app:2.0.0:*:*:*:*:*:*:*",
      "licenses": [
	    { 
	      "expression": "Apache-2.0" 
		}
	  ],
      "copyright": "Copyright 2024 Acme Corp",
      "hashes": [
        { 
	      "alg": "MD5",
		  "content": "abc123" 
		},
        { 
		  "alg": "SHA-1",
		  "content": "def456"
		},
        {
		  "alg": "SHA-256",
		  "content": "ghi789"
		},
        {
		  "alg": "SHA-512",
		  "content": "jkl012"
		}
      ]
    }
  },
  "components": [
    {
      "bom-ref": "lib-a@1.0.0",
      "type": "library",
      "name": "lib-a",
      "version": "1.0.0",
      "author": "Alice",
      "group": "com.example",
      "scope": "required",
      "purl": "pkg:maven/com.example/lib-a@1.0.0",
      "licenses": [
	    {
	      "license": 
		    {
		      "id": "MIT"
			}
		}
	  ],
      "copyright": "Copyright 2024",
      "description": "Library A",
      "hashes": [
        {
	      "alg": "SHA-256",
		  "content": "sha256ofliба"
		}
	  ]
    },
    {
      "type": "library",
      "name": "lib-b",
      "version": "2.1.0",
      "bom-ref": "lib-b@2.1.0",
      "purl": "pkg:npm/lib-b@2.1.0"
    }
  ]
}
`)

var spdxSBOM = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-spdx-sbom",
  "documentNamespace": "https://example.com/my-spdx-sbom",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": ["Tool: syft-0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-root",
      "name": "my-app",
      "versionInfo": "2.0.0",
      "downloadLocation": "https://example.com/my-app",
      "primaryPackagePurpose": "APPLICATION",
      "supplier": "Organization: Acme Corp",
      "originator": "Person: Alice",
      "licenseDeclared": "Apache-2.0",
      "copyrightText": "Copyright 2024 Acme Corp",
      "description": "My application",
      "checksums": [
        {
	      "algorithm": "MD5",
		  "checksumValue": "abc123"
		},
        {
		  "algorithm": "SHA1",
		  "checksumValue": "def456"
		},
        {
		  "algorithm": "SHA256",
		  "checksumValue": "ghi789"
		},
        {
		  "algorithm": "SHA512",
		  "checksumValue": "jkl012"
		}
      ],
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/my-app@2.0.0"
        },
        {
          "referenceCategory": "SECURITY",
          "referenceType": "cpe23Type",
          "referenceLocator": "cpe:2.3:a:acme:my-app:2.0.0:*:*:*:*:*:*:*"
        }
      ]
    },
    {
      "SPDXID": "SPDXRef-lib-a",
      "name": "lib-a",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "licenseDeclared": "MIT",
      "copyrightText": "Copyright 2024",
      "checksums": [
        {
	      "algorithm": "SHA256",
		  "checksumValue": "sha256ofliba"
		}
      ]
    }
  ],
  "files": [
    {
      "SPDXID": "SPDXRef-file-main",
      "fileName": "/src/main.go",
      "licenseConcluded": "MIT",
      "copyrightText": "Copyright 2024",
      "checksums": [
        {
	      "algorithm": "SHA256",
		  "checksumValue": "filesha256"
		}
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-root"
    }
  ]
}
`)

// writeTempFile writes content to a temp file and returns its path.
// The caller is responsible for removing the file.
func writeTempFile(t *testing.T, content []byte, suffix string) string {
	t.Helper()
	f, err := os.CreateTemp("", "sbomasm-test-*"+suffix)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

// parseAndSerialize parses the SBOM at path and serializes it to CSV,
// returning all rows (including header).
func parseAndSerialize(t *testing.T, path string) [][]string {
	t.Helper()

	initTestLogger()
	ctx := logger.WithLogger(context.Background())

	doc, err := sbom.Parser(ctx, path)
	if err != nil {
		t.Fatalf("Parser() error: %v", err)
	}

	buf := &bytes.Buffer{}
	if err := Serialize(ctx, doc, buf); err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}

	rows, err := csv.NewReader(buf).ReadAll()
	if err != nil {
		t.Fatalf("failed to read CSV output: %v", err)
	}
	return rows
}

// columnIndex returns the index of a column name in the header row.
func columnIndex(t *testing.T, header []string, col string) int {
	t.Helper()
	for i, h := range header {
		if h == col {
			return i
		}
	}
	t.Fatalf("column %q not found in header", col)
	return -1
}

func Test_CDX_HeaderRow(t *testing.T) {
	path := writeTempFile(t, cdxSBOM, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)

	if len(rows) == 0 {
		t.Fatal("expected at least header row, got none")
	}

	got := rows[0]
	if len(got) != len(headers) {
		t.Fatalf("header has %d columns, want %d", len(got), len(headers))
	}

	for i, h := range headers {
		if got[i] != h {
			t.Errorf("header[%d] = %q, want %q", i, got[i], h)
		}
	}
}

func Test_CDX_RowCount(t *testing.T) {
	path := writeTempFile(t, cdxSBOM, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)

	// header + metadata component + lib-a + lib-b = 4 rows
	if len(rows) != 4 {
		t.Errorf("expected 4 rows (header + 3 components), got %d", len(rows))
	}
}

func Test_CDX_MetadataComponentFields(t *testing.T) {
	path := writeTempFile(t, cdxSBOM, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	header := rows[0]

	// metadata component is the first data row
	row := rows[1]

	tests := []struct {
		col  string
		want string
	}{
		{"Name", "my-app"},
		{"Version", "2.0.0"},
		{"Type", "application"},
		{"Supplier", "Acme Corp"},
		{"Purl", "pkg:npm/my-app@2.0.0"},
		{"Cpe", "cpe:2.3:a:acme:my-app:2.0.0:*:*:*:*:*:*:*"},
		{"LicenseExpressions", "Apache-2.0"},
		{"Copyright", "Copyright 2024 Acme Corp"},
		{"Description", "My application"},
		{"MD5", "abc123"},
		{"SHA-1", "def456"},
		{"SHA-256", "ghi789"},
		{"SHA-512", "jkl012"},
	}

	for _, tt := range tests {
		t.Run(tt.col, func(t *testing.T) {
			idx := columnIndex(t, header, tt.col)
			if row[idx] != tt.want {
				t.Errorf("column %q = %q, want %q", tt.col, row[idx], tt.want)
			}
		})
	}
}

func Test_CDX_ComponentLibA(t *testing.T) {
	path := writeTempFile(t, cdxSBOM, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	header := rows[0]

	// lib-a is the second data row
	row := rows[2]

	tests := []struct {
		col  string
		want string
	}{
		{"Name", "lib-a"},
		{"Version", "1.0.0"},
		{"Type", "library"},
		{"Author", "Alice"},
		{"Group", "com.example"},
		{"Scope", "required"},
		{"Purl", "pkg:maven/com.example/lib-a@1.0.0"},
		{"LicenseNames", "MIT"},
		{"Copyright", "Copyright 2024"},
		{"Description", "Library A"},
		{"SHA-256", "sha256ofliба"},
	}

	for _, tt := range tests {
		t.Run(tt.col, func(t *testing.T) {
			idx := columnIndex(t, header, tt.col)
			if row[idx] != tt.want {
				t.Errorf("column %q = %q, want %q", tt.col, row[idx], tt.want)
			}
		})
	}
}

func Test_CDX_ComponentLibB(t *testing.T) {
	path := writeTempFile(t, cdxSBOM, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	header := rows[0]

	// lib-a is the second data row
	row := rows[3]

	tests := []struct {
		col  string
		want string
	}{
		{"Name", "lib-b"},
		{"Version", "2.1.0"},
		{"Type", "library"},
		{"Purl", "pkg:npm/lib-b@2.1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.col, func(t *testing.T) {
			idx := columnIndex(t, header, tt.col)
			if row[idx] != tt.want {
				t.Errorf("column %q = %q, want %q", tt.col, row[idx], tt.want)
			}
		})
	}
}

func Test_SPDX_HeaderRow(t *testing.T) {
	path := writeTempFile(t, spdxSBOM, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)

	if len(rows) == 0 {
		t.Fatal("expected at least header row, got none")
	}

	got := rows[0]
	if len(got) != len(headers) {
		t.Fatalf("header has %d columns, want %d", len(got), len(headers))
	}

	for i, h := range headers {
		if got[i] != h {
			t.Errorf("header[%d] = %q, want %q", i, got[i], h)
		}
	}
}

func Test_SPDX_RowCount(t *testing.T) {
	path := writeTempFile(t, spdxSBOM, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)

	// header + 2 packages + 1 file = 4 rows
	if len(rows) != 4 {
		t.Errorf("expected 4 rows (header + 2 packages + 1 file), got %d", len(rows))
	}
}

func Test_SPDX_PackageMyApp_Fields(t *testing.T) {
	path := writeTempFile(t, spdxSBOM, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	header := rows[0]

	// my-app is the first data row
	row := rows[1]

	tests := []struct {
		col  string
		want string
	}{
		{"Name", "my-app"},
		{"Version", "2.0.0"},
		{"Type", "APPLICATION"},
		{"Author", "Alice"},
		{"Supplier", "Acme Corp"},
		{"Purl", "pkg:npm/my-app@2.0.0"},
		{"Cpe", "cpe:2.3:a:acme:my-app:2.0.0:*:*:*:*:*:*:*"},
		{"LicenseExpressions", "Apache-2.0"},
		{"Copyright", "Copyright 2024 Acme Corp"},
		{"Description", "My application"},
		{"MD5", "abc123"},
		{"SHA-1", "def456"},
		{"SHA-256", "ghi789"},
		{"SHA-512", "jkl012"},
	}

	for _, tt := range tests {
		t.Run(tt.col, func(t *testing.T) {
			idx := columnIndex(t, header, tt.col)
			if row[idx] != tt.want {
				t.Errorf("column %q = %q, want %q", tt.col, row[idx], tt.want)
			}
		})
	}
}

func Test_SPDX_PackageLibA_Fields(t *testing.T) {
	path := writeTempFile(t, spdxSBOM, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	header := rows[0]

	// my-app is the first data row
	row := rows[2]

	tests := []struct {
		col  string
		want string
	}{
		{"Name", "lib-a"},
		{"Version", "1.0.0"},
		{"LicenseExpressions", "MIT"},
		{"Copyright", "Copyright 2024"},
		{"SHA-256", "sha256ofliba"},
	}

	for _, tt := range tests {
		t.Run(tt.col, func(t *testing.T) {
			idx := columnIndex(t, header, tt.col)
			if row[idx] != tt.want {
				t.Errorf("column %q = %q, want %q", tt.col, row[idx], tt.want)
			}
		})
	}
}

func Test_SPDX_File_Fields(t *testing.T) {
	path := writeTempFile(t, spdxSBOM, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	header := rows[0]
	// file is the last row (after 2 packages)
	row := rows[3]

	tests := []struct {
		col  string
		want string
	}{
		{"Name", "/src/main.go"},
		{"Type", "FILE"},
		{"LicenseExpressions", "MIT"},
		{"Copyright", "Copyright 2024"},
		{"SHA-256", "filesha256"},
	}

	for _, tt := range tests {
		t.Run(tt.col, func(t *testing.T) {
			idx := columnIndex(t, header, tt.col)
			if row[idx] != tt.want {
				t.Errorf("column %q = %q, want %q", tt.col, row[idx], tt.want)
			}
		})
	}
}

// Not valid JSON at all.
var cdxMalformedJSON = []byte(`{this is not valid json`)

// Valid JSON but no bomFormat or SPDXID  Detect cannot identify the spec.
var cdxEmptyJSON = []byte(`{}`)

// CycloneDX JSON missing the required "bomFormat" field.
var cdxMissingBomFormat = []byte(`{
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:12345",
  "version": 1,
  "components": []
}`)

// bomFormat present but not the expected "CycloneDX" value.
var cdxWrongBomFormat = []byte(`{
  "bomFormat": "NotCycloneDX",
  "specVersion": "1.5",
  "version": 1
}`)

// "version" field is a string instead of the required integer.
var cdxWrongVersionType = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": "not-an-integer",
  "components": [
    {"type": "library", "name": "lib-a", "version": "1.0.0"}
  ]
}`)

// Valid CDX with metadata component but no "components" key at all.
var cdxNoComponents = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "root@1.0.0",
      "type": "application",
      "name": "root-app",
      "version": "1.0.0"
    }
  }
}`)

// Valid CDX with metadata component and an explicitly empty "components" array.
var cdxEmptyComponentsArray = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "root-app",
      "version": "1.0.0"
    }
  },
  "components": []
}`)

// CDX component with only name and type; all other optional fields are absent.
var cdxMinimalComponent = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
	  "name": "minimal-lib"
	}
  ]
}`)

// CDX component with a mix of license expressions and named licenses.
var cdxMultipleLicenses = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "multi-license-lib",
      "version": "1.0.0",
      "licenses": [
        {"expression": "Apache-2.0"},
        {"expression": "MIT"},
        {"license": {"id": "GPL-2.0"}},
        {"license": {"name": "Custom License"}}
      ]
    }
  ]
}`)

// CDX component with a nested sub-component; writeCDX does not recurse into sub-components.
var cdxNestedComponents = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "parent-lib",
      "version": "1.0.0",
      "components": [
        {"type": "library", "name": "nested-child-lib", "version": "0.1.0"}
      ]
    }
  ]
}`)

// Not valid JSON at all.
var spdxMalformedJSON = []byte(`{this is not valid json`)

// Valid JSON without an SPDXID field  Detect cannot identify it as SPDX.
var spdxMissingSPDXID = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "name": "no-id-sbom",
  "documentNamespace": "https://example.com/no-id"
}`)

// SPDXID present but does not start with "SPDX"  Detect skips it.
var spdxWrongSPDXID = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "not-a-valid-spdx-ref",
  "name": "wrong-id-sbom",
  "documentNamespace": "https://example.com/wrong-id"
}`)

// Minimal valid SPDX document with no packages or files.
var spdxNoPackages = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "empty-sbom",
  "documentNamespace": "https://example.com/empty-sbom",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  }
}`)

// SPDX document with two files and no packages.
var spdxFilesOnly = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "files-only-sbom",
  "documentNamespace": "https://example.com/files-sbom",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "files": [
    {
      "SPDXID": "SPDXRef-file-a",
      "fileName": "/src/main.go",
      "licenseConcluded": "MIT",
      "copyrightText": "Copyright 2024"
    },
    {
      "SPDXID": "SPDXRef-file-b",
      "fileName": "/src/util.go",
      "licenseConcluded": "Apache-2.0",
      "copyrightText": "Copyright 2024"
    }
  ]
}`)

// SPDX package whose originator is an Organization (not a Person).
// spdxOriginatorName only maps Person originators to the Author column.
var spdxOrganizationOriginator = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "org-originator-sbom",
  "documentNamespace": "https://example.com/org-originator",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg",
      "name": "my-pkg",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "originator": "Organization: Acme Corp",
      "supplier": "Organization: Supplier Corp",
      "licenseDeclared": "MIT",
      "copyrightText": "Copyright 2024"
    }
  ]
}`)

// SPDX package with a cpe22Type external reference (no PURL).
var spdxCPE22Type = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "cpe22-sbom",
  "documentNamespace": "https://example.com/cpe22",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg",
      "name": "my-pkg",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "licenseDeclared": "MIT",
      "copyrightText": "Copyright 2024",
      "externalRefs": [
        {
          "referenceCategory": "SECURITY",
          "referenceType": "cpe22Type",
          "referenceLocator": "cpe:/a:acme:my-pkg:1.0.0"
        }
      ]
    }
  ]
}`)

// SPDX package with no external references at all (no PURL, no CPE).
var spdxNoExternalRefs = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "no-ext-refs-sbom",
  "documentNamespace": "https://example.com/no-ext-refs",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg",
      "name": "plain-pkg",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "licenseDeclared": "MIT",
      "copyrightText": "Copyright 2024"
    }
  ]
}`)

// tryParseAndSerialize is like parseAndSerialize but returns (rows, error)
// instead of calling t.Fatalf on failure, allowing tests to assert on error paths.
func tryParseAndSerialize(t *testing.T, path string) ([][]string, error) {
	t.Helper()

	initTestLogger()
	ctx := logger.WithLogger(context.Background())

	doc, err := sbom.Parser(ctx, path)
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	if err := Serialize(ctx, doc, buf); err != nil {
		return nil, err
	}

	rows, err := csv.NewReader(buf).ReadAll()
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func Test_CDX_MalformedJSON_ReturnsError(t *testing.T) {
	path := writeTempFile(t, cdxMalformedJSON, ".cdx.json")
	defer os.Remove(path)

	_, err := tryParseAndSerialize(t, path)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func Test_CDX_EmptyJSON_ReturnsError(t *testing.T) {
	path := writeTempFile(t, cdxEmptyJSON, ".cdx.json")
	defer os.Remove(path)

	_, err := tryParseAndSerialize(t, path)
	if err == nil {
		t.Fatal("expected error for empty JSON object {}, got nil")
	}
}

func Test_CDX_MissingBomFormat_ReturnsError(t *testing.T) {
	path := writeTempFile(t, cdxMissingBomFormat, ".cdx.json")
	defer os.Remove(path)

	_, err := tryParseAndSerialize(t, path)
	if err == nil {
		t.Fatal("expected error when bomFormat field is absent, got nil")
	}
}

func Test_CDX_WrongBomFormat_ReturnsError(t *testing.T) {
	path := writeTempFile(t, cdxWrongBomFormat, ".cdx.json")
	defer os.Remove(path)

	_, err := tryParseAndSerialize(t, path)
	if err == nil {
		t.Fatal("expected error when bomFormat is not 'CycloneDX', got nil")
	}
}

func Test_CDX_WrongVersionType_ReturnsError(t *testing.T) {
	path := writeTempFile(t, cdxWrongVersionType, ".cdx.json")
	defer os.Remove(path)

	_, err := tryParseAndSerialize(t, path)
	if err == nil {
		t.Fatal("expected error when BOM 'version' field is a string instead of integer, got nil")
	}
}

func Test_CDX_NoComponents_RowCount(t *testing.T) {
	path := writeTempFile(t, cdxNoComponents, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	// header + metadata component only; no body components
	if len(rows) != 2 {
		t.Errorf("expected 2 rows (header + metadata component), got %d", len(rows))
	}
}

func Test_CDX_EmptyComponentsArray_RowCount(t *testing.T) {
	path := writeTempFile(t, cdxEmptyComponentsArray, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	// header + metadata component; empty components array contributes nothing
	if len(rows) != 2 {
		t.Errorf("expected 2 rows (header + metadata component), got %d", len(rows))
	}
}

func Test_CDX_MinimalComponent_EmptyOptionalFields(t *testing.T) {
	path := writeTempFile(t, cdxMinimalComponent, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + 1 component), got %d", len(rows))
	}
	header := rows[0]
	row := rows[1]

	nameIdx := columnIndex(t, header, "Name")
	if row[nameIdx] != "minimal-lib" {
		t.Errorf("Name = %q, want %q", row[nameIdx], "minimal-lib")
	}

	// Every optional column must be empty when absent from the JSON.
	optionalCols := []string{
		"Version", "Author", "Supplier", "Group", "Scope",
		"Purl", "Cpe", "LicenseExpressions", "LicenseNames",
		"Copyright", "Description", "MD5", "SHA-1", "SHA-256", "SHA-512",
	}
	for _, col := range optionalCols {
		idx := columnIndex(t, header, col)
		if row[idx] != "" {
			t.Errorf("optional column %q = %q, want empty string", col, row[idx])
		}
	}
}

func Test_CDX_MultipleLicenses_ExpressionsAndNames(t *testing.T) {
	path := writeTempFile(t, cdxMultipleLicenses, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + 1 component), got %d", len(rows))
	}
	header := rows[0]
	row := rows[1]

	exprIdx := columnIndex(t, header, "LicenseExpressions")
	if row[exprIdx] != "Apache-2.0, MIT" {
		t.Errorf("LicenseExpressions = %q, want %q", row[exprIdx], "Apache-2.0, MIT")
	}

	namesIdx := columnIndex(t, header, "LicenseNames")
	if row[namesIdx] != "GPL-2.0, Custom License" {
		t.Errorf("LicenseNames = %q, want %q", row[namesIdx], "GPL-2.0, Custom License")
	}
}

// Test_CDX_NestedComponents_OnlyTopLevelWritten documents that writeCDX does not
// recurse into sub-components; only the top-level components slice is serialized.
func Test_CDX_NestedComponents_OnlyTopLevelWritten(t *testing.T) {
	path := writeTempFile(t, cdxNestedComponents, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	// header + 1 top-level component; the nested child must NOT appear
	if len(rows) != 2 {
		t.Errorf("expected 2 rows (header + parent only), got %d  nested sub-components should not be written", len(rows))
	}
	if len(rows) >= 2 {
		header := rows[0]
		nameIdx := columnIndex(t, header, "Name")
		if rows[1][nameIdx] != "parent-lib" {
			t.Errorf("first data row Name = %q, want %q", rows[1][nameIdx], "parent-lib")
		}
	}
}

func Test_SPDX_MalformedJSON_ReturnsError(t *testing.T) {
	path := writeTempFile(t, spdxMalformedJSON, ".spdx.json")
	defer os.Remove(path)

	_, err := tryParseAndSerialize(t, path)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func Test_SPDX_MissingSPDXID_ReturnsError(t *testing.T) {
	path := writeTempFile(t, spdxMissingSPDXID, ".spdx.json")
	defer os.Remove(path)

	_, err := tryParseAndSerialize(t, path)
	if err == nil {
		t.Fatal("expected error when SPDXID field is absent, got nil")
	}
}

func Test_SPDX_WrongSPDXID_ReturnsError(t *testing.T) {
	path := writeTempFile(t, spdxWrongSPDXID, ".spdx.json")
	defer os.Remove(path)

	_, err := tryParseAndSerialize(t, path)
	if err == nil {
		t.Fatal("expected error when SPDXID does not start with 'SPDX', got nil")
	}
}

func Test_SPDX_NoPackages_HeaderOnly(t *testing.T) {
	path := writeTempFile(t, spdxNoPackages, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	if len(rows) != 1 {
		t.Errorf("expected 1 row (header only) for document with no packages or files, got %d", len(rows))
	}
}

func Test_SPDX_FilesOnly_RowCount(t *testing.T) {
	path := writeTempFile(t, spdxFilesOnly, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	// header + 2 file rows
	if len(rows) != 3 {
		t.Errorf("expected 3 rows (header + 2 files), got %d", len(rows))
	}
}

func Test_SPDX_FilesOnly_TypeColumn(t *testing.T) {
	path := writeTempFile(t, spdxFilesOnly, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	header := rows[0]
	typeIdx := columnIndex(t, header, "Type")

	for i, row := range rows[1:] {
		if row[typeIdx] != "FILE" {
			t.Errorf("data row %d Type = %q, want FILE", i+1, row[typeIdx])
		}
	}
}

func Test_SPDX_FilesOnly_Fields(t *testing.T) {
	path := writeTempFile(t, spdxFilesOnly, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	if len(rows) < 2 {
		t.Fatalf("expected at least 2 rows, got %d", len(rows))
	}
	header := rows[0]
	row := rows[1] // first file: /src/main.go

	tests := []struct {
		col  string
		want string
	}{
		{"Name", "/src/main.go"},
		{"Type", "FILE"},
		{"LicenseExpressions", "MIT"},
		{"Copyright", "Copyright 2024"},
		// Files have no version, author, supplier, group, scope, purl, cpe or description in SPDX.
		{"Version", ""},
		{"Author", ""},
		{"Supplier", ""},
		{"Group", ""},
		{"Scope", ""},
		{"Purl", ""},
		{"Cpe", ""},
		{"Description", ""},
	}

	for _, tt := range tests {
		t.Run(tt.col, func(t *testing.T) {
			idx := columnIndex(t, header, tt.col)
			if row[idx] != tt.want {
				t.Errorf("column %q = %q, want %q", tt.col, row[idx], tt.want)
			}
		})
	}
}

// Test_SPDX_OrganizationOriginator_AuthorField verifies that spdxOriginatorName
// maps Organization-type originators to the Author column (same as Person).
func Test_SPDX_OrganizationOriginator_AuthorField(t *testing.T) {
	path := writeTempFile(t, spdxOrganizationOriginator, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + 1 package), got %d", len(rows))
	}
	header := rows[0]
	row := rows[1]

	authorIdx := columnIndex(t, header, "Author")
	if row[authorIdx] != "Acme Corp" {
		t.Errorf("Author = %q, want %q Organization originators are mapped to Author", row[authorIdx], "Acme Corp")
	}

	supplierIdx := columnIndex(t, header, "Supplier")
	if row[supplierIdx] != "Supplier Corp" {
		t.Errorf("Supplier = %q, want %q", row[supplierIdx], "Supplier Corp")
	}
}

func Test_SPDX_CPE22Type_ExtractedCorrectly(t *testing.T) {
	path := writeTempFile(t, spdxCPE22Type, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + 1 package), got %d", len(rows))
	}
	header := rows[0]
	row := rows[1]

	cpeIdx := columnIndex(t, header, "Cpe")
	if row[cpeIdx] != "cpe:/a:acme:my-pkg:1.0.0" {
		t.Errorf("Cpe = %q, want %q", row[cpeIdx], "cpe:/a:acme:my-pkg:1.0.0")
	}

	purlIdx := columnIndex(t, header, "Purl")
	if row[purlIdx] != "" {
		t.Errorf("Purl = %q, want empty string (fixture has no PURL ref)", row[purlIdx])
	}
}

func Test_SPDX_NoExternalRefs_EmptyPURLAndCPE(t *testing.T) {
	path := writeTempFile(t, spdxNoExternalRefs, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + 1 package), got %d", len(rows))
	}
	header := rows[0]
	row := rows[1]

	purlIdx := columnIndex(t, header, "Purl")
	if row[purlIdx] != "" {
		t.Errorf("Purl = %q, want empty string for package with no external refs", row[purlIdx])
	}

	cpeIdx := columnIndex(t, header, "Cpe")
	if row[cpeIdx] != "" {
		t.Errorf("Cpe = %q, want empty string for package with no external refs", row[cpeIdx])
	}
}

// Component with no "type" field  cdxComponentToRow calls string(c.Type), producing "".
var cdxAbsentType = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {"name": "no-type-lib", "version": "1.0.0"}
  ]
}`)

func Test_CDX_AbsentType_EmptyTypeColumn(t *testing.T) {
	path := writeTempFile(t, cdxAbsentType, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + 1 component), got %d", len(rows))
	}
	header := rows[0]
	row := rows[1]

	typeIdx := columnIndex(t, header, "Type")
	if row[typeIdx] != "" {
		t.Errorf("Type = %q, want empty string when type field is absent", row[typeIdx])
	}
}

// cdxLicenseNames checks Name first; if non-empty it wins over ID.
var cdxLicenseNameAndID = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "dual-id-lib",
      "version": "1.0.0",
      "licenses": [
        {"license": {"id": "MIT", "name": "MIT License"}}
      ]
    }
  ]
}`)

func Test_CDX_LicenseName_TakesPrecedenceOverID(t *testing.T) {
	path := writeTempFile(t, cdxLicenseNameAndID, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + 1 component), got %d", len(rows))
	}
	header := rows[0]
	row := rows[1]

	namesIdx := columnIndex(t, header, "LicenseNames")
	if row[namesIdx] != "MIT License" {
		t.Errorf("LicenseNames = %q, want %q  Name should take precedence over ID", row[namesIdx], "MIT License")
	}
}

var spdxPackageNoType = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "no-type-sbom",
  "documentNamespace": "https://example.com/no-type",
  "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg",
      "name": "no-type-pkg",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "licenseDeclared": "MIT",
      "copyrightText": "Copyright 2024"
    }
  ]
}`)

func Test_SPDX_PackageNoType_EmptyTypeColumn(t *testing.T) {
	path := writeTempFile(t, spdxPackageNoType, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + 1 package), got %d", len(rows))
	}
	header := rows[0]
	row := rows[1]

	typeIdx := columnIndex(t, header, "Type")
	if row[typeIdx] != "" {
		t.Errorf("Type = %q, want empty string for package without primaryPackagePurpose", row[typeIdx])
	}
}

var spdxPackageLicenseComments = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "license-comments-sbom",
  "documentNamespace": "https://example.com/license-comments",
  "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg",
      "name": "commented-pkg",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "licenseDeclared": "MIT",
      "licenseComments": "Approved by legal on 2024-01-01",
      "copyrightText": "Copyright 2024"
    }
  ]
}`)

func Test_SPDX_LicenseColumns(t *testing.T) {
	path := writeTempFile(t, spdxPackageLicenseComments, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + 1 package), got %d", len(rows))
	}
	header := rows[0]
	row := rows[1]

	exprIdx := columnIndex(t, header, "LicenseExpressions")
	if row[exprIdx] != "MIT" {
		t.Errorf("LicenseExpressions = %q, want %q", row[exprIdx], "MIT")
	}

	namesIdx := columnIndex(t, header, "LicenseNames")
	if row[namesIdx] != "" {
		t.Errorf("LicenseNames = %q, want %q (SPDX has no named-license concept)", row[namesIdx], "")
	}
}

// spdxFileToRow uses the CORRECT column order: MD5(13), SHA-1(14), SHA-256(15), SHA-512(16).
var spdxFileAllChecksums = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "file-checksums-sbom",
  "documentNamespace": "https://example.com/file-checksums",
  "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
  "files": [
    {
      "SPDXID": "SPDXRef-file",
      "fileName": "/src/main.go",
      "licenseConcluded": "MIT",
      "copyrightText": "Copyright 2024",
      "checksums": [
        {"algorithm": "MD5",    "checksumValue": "filemd5val"},
        {"algorithm": "SHA1",   "checksumValue": "filesha1val"},
        {"algorithm": "SHA256", "checksumValue": "filesha256val"},
        {"algorithm": "SHA512", "checksumValue": "filesha512val"}
      ]
    }
  ]
}`)

func Test_SPDX_FileAllChecksums(t *testing.T) {
	path := writeTempFile(t, spdxFileAllChecksums, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + 1 file), got %d", len(rows))
	}
	header := rows[0]
	row := rows[1]

	// spdxFileToRow has the correct column order (unlike spdxPackageToRow).
	checks := []struct {
		col  string
		want string
	}{
		{"MD5", "filemd5val"},
		{"SHA-1", "filesha1val"},
		{"SHA-256", "filesha256val"},
		{"SHA-512", "filesha512val"},
	}
	for _, c := range checks {
		t.Run(c.col, func(t *testing.T) {
			idx := columnIndex(t, header, c.col)
			if row[idx] != c.want {
				t.Errorf("column %q = %q, want %q", c.col, row[idx], c.want)
			}
		})
	}
}

func Test_SPDX_Package_MD5AndSHA1_CorrectColumns(t *testing.T) {
	path := writeTempFile(t, spdxSBOM, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)
	// my-app is the first data row; fixture has MD5="abc123" and SHA1="def456"
	header := rows[0]
	row := rows[1]

	md5Idx := columnIndex(t, header, "MD5")
	if row[md5Idx] != "abc123" {
		t.Errorf("MD5 column = %q, want %q", row[md5Idx], "abc123")
	}

	sha1Idx := columnIndex(t, header, "SHA-1")
	if row[sha1Idx] != "def456" {
		t.Errorf("SHA-1 column = %q, want %q", row[sha1Idx], "def456")
	}
}
