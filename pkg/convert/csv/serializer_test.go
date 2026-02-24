// Copyright 2025 Interlynk.io
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
	"testing"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

// === Inline SBOM fixtures ===
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

	logger.InitProdLogger()
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

//  Tests

func TestIntegration_CDX_HeaderRow(t *testing.T) {
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

func TestIntegration_CDX_RowCount(t *testing.T) {
	path := writeTempFile(t, cdxSBOM, ".cdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)

	// header + metadata component + lib-a + lib-b = 4 rows
	if len(rows) != 4 {
		t.Errorf("expected 4 rows (header + 3 components), got %d", len(rows))
	}
}

func TestIntegration_CDX_MetadataComponentFields(t *testing.T) {
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

func TestIntegration_CDX_ComponentFields(t *testing.T) {
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

func TestIntegration_SPDX_HeaderRow(t *testing.T) {
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

func TestIntegration_SPDX_RowCount(t *testing.T) {
	path := writeTempFile(t, spdxSBOM, ".spdx.json")
	defer os.Remove(path)

	rows := parseAndSerialize(t, path)

	// header + 2 packages + 1 file = 4 rows
	if len(rows) != 4 {
		t.Errorf("expected 4 rows (header + 2 packages + 1 file), got %d", len(rows))
	}
}

func TestIntegration_SPDX_PackageFields(t *testing.T) {
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

func TestIntegration_SPDX_FileRow(t *testing.T) {
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
