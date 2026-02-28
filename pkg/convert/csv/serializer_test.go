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
	"sync"
	"testing"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdx23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
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

func TestCDXConversionToCSV(t *testing.T) {
	path := writeTempFile(t, cdxSBOM, ".cdx.json")
	defer os.Remove(path)

	initTestLogger()
	ctx := logger.WithLogger(context.Background())

	sbomDoc, err := sbom.Parser(ctx, path)
	if err != nil {
		t.Fatalf("Parser() error: %v", err)
	}

	bom, ok := sbomDoc.Document().(*cydx.BOM)
	if !ok {
		t.Fatalf("expected CycloneDX BOM, got %T", sbomDoc.Document())
	}

	buf := &bytes.Buffer{}
	if err := Serialize(ctx, sbomDoc, buf); err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}

	rows, err := csv.NewReader(buf).ReadAll()
	if err != nil {
		t.Fatalf("failed to read CSV output: %v", err)
	}

	// header + metadata component + lib-a + lib-b = 4 rows
	if len(rows) != 4 {
		t.Errorf("expected 4 rows (header + 3 components), got %d", len(rows))
	}

	gotHeader := rows[0]
	if len(gotHeader) != len(headers) {
		t.Fatalf("header has %d columns, want %d", len(gotHeader), len(headers))
	}

	for i, h := range headers {
		if gotHeader[i] != h {
			t.Errorf("header[%d] = %q, want %q", i, gotHeader[i], h)
		}
	}

	pc := bom.Metadata.Component
	components := *bom.Components
	la := &components[0] // lib-a
	lb := &components[1] // lib-b

	checkRow := func(t *testing.T, row []string, checks []struct{ col, want string }) {
		t.Helper()
		for _, tt := range checks {
			idx := columnIndex(t, gotHeader, tt.col)
			if row[idx] != tt.want {
				t.Errorf("column %q = %q, want %q", tt.col, row[idx], tt.want)
			}
		}
	}

	t.Run("primary-component", func(t *testing.T) {
		checkRow(t, rows[1], []struct{ col, want string }{
			{"Name", pc.Name},
			{"Version", pc.Version},
			{"Type", string(pc.Type)},
			{"Author", pc.Author},
			{"Supplier", cdxSupplierName(pc.Supplier)},
			{"Group", pc.Group},
			{"Scope", string(pc.Scope)},
			{"Purl", pc.PackageURL},
			{"Cpe", pc.CPE},
			{"LicenseExpressions", cdxLicenseExpressions(pc.Licenses)},
			{"LicenseNames", cdxLicenseNames(pc.Licenses)},
			{"Copyright", pc.Copyright},
			{"Description", pc.Description},
			{"MD5", cdxHashValue(pc.Hashes, cydx.HashAlgoMD5)},
			{"SHA-1", cdxHashValue(pc.Hashes, cydx.HashAlgoSHA1)},
			{"SHA-256", cdxHashValue(pc.Hashes, cydx.HashAlgoSHA256)},
			{"SHA-512", cdxHashValue(pc.Hashes, cydx.HashAlgoSHA512)},
		})
	})

	t.Run("lib-a", func(t *testing.T) {
		checkRow(t, rows[2], []struct{ col, want string }{
			{"Name", la.Name},
			{"Version", la.Version},
			{"Type", string(la.Type)},
			{"Author", la.Author},
			{"Supplier", cdxSupplierName(la.Supplier)},
			{"Group", la.Group},
			{"Scope", string(la.Scope)},
			{"Purl", la.PackageURL},
			{"Cpe", la.CPE},
			// lib-a has a named license (id: "MIT"), not an expression
			{"LicenseExpressions", cdxLicenseExpressions(la.Licenses)},
			{"LicenseNames", cdxLicenseNames(la.Licenses)},
			{"Copyright", la.Copyright},
			{"Description", la.Description},
			{"MD5", cdxHashValue(la.Hashes, cydx.HashAlgoMD5)},
			{"SHA-1", cdxHashValue(la.Hashes, cydx.HashAlgoSHA1)},
			{"SHA-256", cdxHashValue(la.Hashes, cydx.HashAlgoSHA256)},
			{"SHA-512", cdxHashValue(la.Hashes, cydx.HashAlgoSHA512)},
		})
	})

	t.Run("lib-b", func(t *testing.T) {
		checkRow(t, rows[3], []struct{ col, want string }{
			{"Name", lb.Name},
			{"Version", lb.Version},
			{"Type", string(lb.Type)},
			{"Author", lb.Author},
			{"Supplier", cdxSupplierName(lb.Supplier)},
			{"Group", lb.Group},
			{"Scope", string(lb.Scope)},
			{"Purl", lb.PackageURL},
			{"Cpe", lb.CPE},
			{"LicenseExpressions", cdxLicenseExpressions(lb.Licenses)},
			{"LicenseNames", cdxLicenseNames(lb.Licenses)},
			{"Copyright", lb.Copyright},
			{"Description", lb.Description},
			{"MD5", cdxHashValue(lb.Hashes, cydx.HashAlgoMD5)},
			{"SHA-1", cdxHashValue(lb.Hashes, cydx.HashAlgoSHA1)},
			{"SHA-256", cdxHashValue(lb.Hashes, cydx.HashAlgoSHA256)},
			{"SHA-512", cdxHashValue(lb.Hashes, cydx.HashAlgoSHA512)},
		})
	})
}

func TestSPDXConversion(t *testing.T) {
	path := writeTempFile(t, spdxSBOM, ".spdx.json")
	defer os.Remove(path)

	initTestLogger()
	ctx := logger.WithLogger(context.Background())

	sbomDoc, err := sbom.Parser(ctx, path)
	if err != nil {
		t.Fatalf("Parser() error: %v", err)
	}

	doc, ok := sbomDoc.Document().(*spdx23.Document)
	if !ok {
		t.Fatalf("expected SPDX document, got %T", sbomDoc.Document())
	}

	buf := &bytes.Buffer{}
	if err := Serialize(ctx, sbomDoc, buf); err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}

	rows, err := csv.NewReader(buf).ReadAll()
	if err != nil {
		t.Fatalf("failed to read CSV output: %v", err)
	}

	// header + 2 packages + 1 file = 4 rows
	if len(rows) != 4 {
		t.Errorf("expected 4 rows (header + 2 packages + 1 file), got %d", len(rows))
	}

	header := rows[0]
	if len(header) != len(headers) {
		t.Fatalf("header has %d columns, want %d", len(header), len(headers))
	}
	for i, h := range headers {
		if header[i] != h {
			t.Errorf("header[%d] = %q, want %q", i, header[i], h)
		}
	}

	myApp := doc.Packages[0]
	libA := doc.Packages[1]
	mainGo := doc.Files[0]

	checkRow := func(t *testing.T, row []string, checks []struct{ col, want string }) {
		t.Helper()
		for _, tt := range checks {
			idx := columnIndex(t, header, tt.col)
			if row[idx] != tt.want {
				t.Errorf("column %q = %q, want %q", tt.col, row[idx], tt.want)
			}
		}
	}

	t.Run("my-app", func(t *testing.T) {
		checkRow(t, rows[1], []struct{ col, want string }{
			{"Name", myApp.PackageName},
			{"Version", myApp.PackageVersion},
			{"Type", myApp.PrimaryPackagePurpose},
			{"Author", spdxOriginatorName(myApp.PackageOriginator)},
			{"Supplier", spdxSupplierName(myApp.PackageSupplier)},
			{"Group", ""},
			{"Scope", ""},
			{"Purl", spdxExtractPURL(myApp.PackageExternalReferences)},
			{"Cpe", spdxExtractCPE(myApp.PackageExternalReferences)},
			{"LicenseExpressions", myApp.PackageLicenseDeclared},
			{"LicenseNames", ""},
			{"Copyright", myApp.PackageCopyrightText},
			{"Description", myApp.PackageDescription},
			{"MD5", spdxChecksumValue(myApp.PackageChecksums, common.MD5)},
			{"SHA-1", spdxChecksumValue(myApp.PackageChecksums, common.SHA1)},
			{"SHA-256", spdxChecksumValue(myApp.PackageChecksums, common.SHA256)},
			{"SHA-512", spdxChecksumValue(myApp.PackageChecksums, common.SHA512)},
		})
	})

	t.Run("lib-a", func(t *testing.T) {
		checkRow(t, rows[2], []struct{ col, want string }{
			{"Name", libA.PackageName},
			{"Version", libA.PackageVersion},
			{"Type", libA.PrimaryPackagePurpose},
			{"Author", spdxOriginatorName(libA.PackageOriginator)},
			{"Supplier", spdxSupplierName(libA.PackageSupplier)},
			{"Group", ""},
			{"Scope", ""},
			{"Purl", spdxExtractPURL(libA.PackageExternalReferences)},
			{"Cpe", spdxExtractCPE(libA.PackageExternalReferences)},
			{"LicenseExpressions", libA.PackageLicenseDeclared},
			{"LicenseNames", ""},
			{"Copyright", libA.PackageCopyrightText},
			{"Description", libA.PackageDescription},
			{"MD5", spdxChecksumValue(libA.PackageChecksums, common.MD5)},
			{"SHA-1", spdxChecksumValue(libA.PackageChecksums, common.SHA1)},
			{"SHA-256", spdxChecksumValue(libA.PackageChecksums, common.SHA256)},
			{"SHA-512", spdxChecksumValue(libA.PackageChecksums, common.SHA512)},
		})
	})

	t.Run("main.go-file", func(t *testing.T) {
		checkRow(t, rows[3], []struct{ col, want string }{
			{"Name", mainGo.FileName},
			{"Version", ""},
			{"Type", "FILE"},
			{"Author", ""},
			{"Supplier", ""},
			{"Group", ""},
			{"Scope", ""},
			{"Purl", ""},
			{"Cpe", ""},
			{"LicenseExpressions", mainGo.LicenseConcluded},
			{"LicenseNames", mainGo.LicenseComments},
			{"Copyright", mainGo.FileCopyrightText},
			{"Description", ""},
			{"MD5", spdxChecksumValue(mainGo.Checksums, common.MD5)},
			{"SHA-1", spdxChecksumValue(mainGo.Checksums, common.SHA1)},
			{"SHA-256", spdxChecksumValue(mainGo.Checksums, common.SHA256)},
			{"SHA-512", spdxChecksumValue(mainGo.Checksums, common.SHA512)},
		})
	})
}

var cdxMalformedJSON = []byte(`
{
	this is not valid json
}
`)

var cdxEmptyJSON = []byte(`{}`)

var cdxMissingBomFormat = []byte(`
{
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:12345",
  "version": 1,
  "components": []
}
`)

var cdxWrongBomFormat = []byte(`
{
  "bomFormat": "NotCycloneDX",
  "specVersion": "1.5",
  "version": 1
}
`)

var cdxWrongVersionType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": "not-an-integer",
  "components": [
    {
      "type": "library",
	  "name": "lib-a",
	  "version": "1.0.0"
	}
  ]
}
`)

var cdxWithNoComponent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1
}
`)

var cdxWithEmptyComponentsArray = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": []
}
`)

var cdxWithNestedComponents = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "parent-lib",
      "version": "1.0.0",
      "components": [
        {
	      "type": "library",
		  "name": "nested-child-lib",
		  "version": "0.1.0"
		}
      ]
    }
  ]
}
`)

var cdxWithMinimalComponent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
	  "name": "minimal-lib"
	}
  ]
}
`)

var cdxCompWithMultipleLicenses = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "multi-license-lib",
      "version": "1.0.0",
      "licenses": [
        {
	      "expression": "Apache-2.0"
		},
        {
		  "expression": "MIT"
		},
        {
		  "license": {
		    "id": "GPL-2.0"
		  }
		},
        {
		  "license": {
		    "name": "Custom License"
		  }
		}
      ]
    }
  ]
}
`)

var cdxAbsentType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "name": "no-type-lib",
	  "version": "1.0.0"
	}
  ]
}
`)
var cdxWithScopeVariants = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
	  "name": "optional-lib",
	  "version": "1.0.0",
	  "scope": "optional"
	},
	{
      "type": "library",
	  "name": "excluded-lib",
	  "version": "2.0.0",
	  "scope": "excluded"
	}
  ]
}
`)

// cdxLicenseNames checks Name first; if non-empty it wins over ID.
var cdxCompWithLicenseNameAndID = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "dual-id-lib",
      "version": "1.0.0",
      "licenses": [
        {
	      "license": {
		    "id": "MIT",
			"name": "MIT License"
		  }
		}
      ]
    }
  ]
}`)

// cdxTypeVariants has one component per CycloneDX component type to verify
var cdxCompWithTypeVariants = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "application",
	  "name": "app-comp",
	  "version": "1.0.0"
	},
	{
      "type": "library",
	  "name": "lib-comp",
	  "version": "1.0.0"
	},
	{
      "type": "firmware",
	  "name": "fw-comp",
	  "version": "1.0.0"
	},
	{
      "type": "container",
	  "name": "ctr-comp",
	  "version": "1.0.0"
	},
	{
      "type": "device",
	  "name": "dev-comp",
	  "version": "1.0.0"
	},
	{
      "type": "operating-system",
	  "name": "os-comp",
	  "version": "1.0.0"
	},
	{
      "type": "framework",
	  "name": "fwk-comp",
	  "version": "1.0.0"
	},
	{
      "type": "file",
	  "name": "file-comp",
	  "version": "1.0.0"
	}
  ]
}
`)

// cdxBothPURLAndCPE has a component with both PURL and CPE fields set.
var cdxCompWithBothPURLAndCPE = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "full-id-lib",
      "version": "1.0.0",
      "purl": "pkg:npm/full-id-lib@1.0.0",
      "cpe": "cpe:2.3:a:acme:full-id-lib:1.0.0:*:*:*:*:*:*:*"
    }
  ]
}`)

// cdxSupplierNameEmpty has a component where the supplier object exists but
var cdxCompWithSupplierNameEmpty = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "empty-supplier-lib",
      "version": "1.0.0",
      "supplier": {"name": ""}
    }
  ]
}`)

// cdxAllHashAlgos has a component with all four supported hash algorithms.
var cdxCompWithAllHashAlgos = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "hashed-lib",
      "version": "1.0.0",
      "hashes": [
        {
	      "alg": "MD5",
		  "content": "md5val"
		},
        {
		  "alg": "SHA-1",
		  "content": "sha1val"
		},
        {
		  "alg": "SHA-256",
		  "content": "sha256val"
		},
        {
		  "alg": "SHA-512",
		  "content": "sha512val"
		}
      ]
    }
  ]
}
`)

func TestCDXAll(t *testing.T) {
	t.Run("cdxWithAllErrorCase", func(t *testing.T) {
		cases := []struct {
			name    string
			fixture []byte
		}{
			{"malformed-json", cdxMalformedJSON},
			{"empty-json-object", cdxEmptyJSON},
			{"missing-bomFormat", cdxMissingBomFormat},
			{"wrong-bomFormat-value", cdxWrongBomFormat},
			{"version-field-is-string", cdxWrongVersionType},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				path := writeTempFile(t, tc.fixture, ".cdx.json")
				defer os.Remove(path)
				_, err := tryParseAndSerialize(t, path)
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.name)
				}
			})
		}
	})

	t.Run("cdxWithNoComponent", func(t *testing.T) {
		path := writeTempFile(t, cdxWithNoComponent, ".cdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 1 {
			t.Errorf("got %d rows, want 2 (header + metadata component)", len(rows))
		}
	})

	t.Run("cdxWithEmptyComponentsArray", func(t *testing.T) {
		path := writeTempFile(t, cdxWithEmptyComponentsArray, ".cdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 1 {
			t.Errorf("got %d rows, want 2 (header + metadata component)", len(rows))
		}
	})

	t.Run("cdxWithNestedComponents", func(t *testing.T) {
		path := writeTempFile(t, cdxWithNestedComponents, ".cdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Errorf("got %d rows, want 2 (nested children must not appear)", len(rows))
		}

		if len(rows) >= 2 {
			header := rows[0]
			nameIdx := columnIndex(t, header, "Name")

			if rows[1][nameIdx] != "parent-lib" {
				t.Errorf("Name = %q, want %q", rows[1][nameIdx], "parent-lib")
			}
		}
	})

	t.Run("cdxWithMinimalComponent", func(t *testing.T) {
		path := writeTempFile(t, cdxWithMinimalComponent, ".cdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)

		// row == header + 1 component
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		if row[columnIndex(t, header, "Name")] != "minimal-lib" {
			t.Errorf("Name = %q, want %q", row[columnIndex(t, header, "Name")], "minimal-lib")
		}

		for _, col := range []string{
			"Version", "Author", "Supplier", "Group", "Scope",
			"Purl", "Cpe", "LicenseExpressions", "LicenseNames",
			"Copyright", "Description", "MD5", "SHA-1", "SHA-256", "SHA-512",
		} {
			if got := row[columnIndex(t, header, col)]; got != "" {
				t.Errorf("optional column %q = %q, want empty", col, got)
			}
		}
	})

	t.Run("cdxCompWithMultipleLicenses", func(t *testing.T) {
		path := writeTempFile(t, cdxCompWithMultipleLicenses, ".cdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		checks := []struct{ col, want string }{
			{"LicenseExpressions", "Apache-2.0, MIT"},
			{"LicenseNames", "GPL-2.0, Custom License"},
		}

		for _, c := range checks {
			if got := row[columnIndex(t, header, c.col)]; got != c.want {
				t.Errorf("%s = %q, want %q", c.col, got, c.want)
			}
		}
	})

	t.Run("cdxAbsentType", func(t *testing.T) {
		path := writeTempFile(t, cdxAbsentType, ".cdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		if got := row[columnIndex(t, header, "Type")]; got != "" {
			t.Errorf("Type = %q, want empty when type field absent", got)
		}
	})

	t.Run("cdxWithScopeVariants", func(t *testing.T) {
		path := writeTempFile(t, cdxWithScopeVariants, ".cdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 3 {
			t.Fatalf("got %d rows, want 3 (header + 2 components)", len(rows))
		}

		header := rows[0]
		scopeIdx := columnIndex(t, header, "Scope")
		checks := []struct {
			row  int
			want string
		}{
			{1, "optional"},
			{2, "excluded"},
		}

		for _, c := range checks {
			if got := rows[c.row][scopeIdx]; got != c.want {
				t.Errorf("row %d Scope = %q, want %q", c.row, got, c.want)
			}
		}
	})

	t.Run("cdxCompWithLicenseNameAndID", func(t *testing.T) {
		path := writeTempFile(t, cdxCompWithLicenseNameAndID, ".cdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		if got := row[columnIndex(t, header, "LicenseNames")]; got != "MIT License" {
			t.Errorf("LicenseNames = %q, want %q (Name beats ID)", got, "MIT License")
		}
	})

	t.Run("cdxCompWithTypeVariants", func(t *testing.T) {
		path := writeTempFile(t, cdxCompWithTypeVariants, ".cdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		// header + 8 type-variant components
		if len(rows) != 9 {
			t.Fatalf("got %d rows, want 9 (header + 8 type variants)", len(rows))
		}

		header := rows[0]
		typeIdx := columnIndex(t, header, "Type")
		nameIdx := columnIndex(t, header, "Name")

		want := []struct{ name, typ string }{
			{"app-comp", "application"},
			{"lib-comp", "library"},
			{"fw-comp", "firmware"},
			{"ctr-comp", "container"},
			{"dev-comp", "device"},
			{"os-comp", "operating-system"},
			{"fwk-comp", "framework"},
			{"file-comp", "file"},
		}

		for i, w := range want {
			row := rows[i+1]
			if got := row[nameIdx]; got != w.name {
				t.Errorf("row %d Name = %q, want %q", i+1, got, w.name)
			}
			if got := row[typeIdx]; got != w.typ {
				t.Errorf("row %d Type = %q, want %q", i+1, got, w.typ)
			}
		}
	})

	t.Run("cdxCompWithBothPURLAndCPE", func(t *testing.T) {
		path := writeTempFile(t, cdxCompWithBothPURLAndCPE, ".cdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		checks := []struct{ col, want string }{
			{"Purl", "pkg:npm/full-id-lib@1.0.0"},
			{"Cpe", "cpe:2.3:a:acme:full-id-lib:1.0.0:*:*:*:*:*:*:*"},
		}

		for _, c := range checks {
			if got := row[columnIndex(t, header, c.col)]; got != c.want {
				t.Errorf("%s = %q, want %q", c.col, got, c.want)
			}
		}
	})

	t.Run("cdxCompWithSupplierNameEmpty", func(t *testing.T) {
		path := writeTempFile(t, cdxCompWithSupplierNameEmpty, ".cdx.json")
		defer os.Remove(path)
		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}
		header, row := rows[0], rows[1]
		if got := row[columnIndex(t, header, "Supplier")]; got != "" {
			t.Errorf("Supplier = %q, want empty when supplier.name is empty string", got)
		}
	})

	t.Run("cdxCompWithAllHashAlgos", func(t *testing.T) {
		path := writeTempFile(t, cdxCompWithAllHashAlgos, ".cdx.json")
		defer os.Remove(path)
		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}
		header, row := rows[0], rows[1]
		checks := []struct{ col, want string }{
			{"MD5", "md5val"},
			{"SHA-1", "sha1val"},
			{"SHA-256", "sha256val"},
			{"SHA-512", "sha512val"},
		}
		for _, c := range checks {
			if got := row[columnIndex(t, header, c.col)]; got != c.want {
				t.Errorf("%s = %q, want %q", c.col, got, c.want)
			}
		}
	})
}

var spdxMalformedJSON = []byte(`{this is not valid json`)

var spdxMissingSPDXID = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "name": "no-id-sbom",
  "documentNamespace": "https://example.com/no-id"
}
`)

var spdxWrongSPDXID = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "not-a-valid-spdx-ref",
  "name": "wrong-id-sbom",
  "documentNamespace": "https://example.com/wrong-id"
}
`)

// Minimal valid SPDX document with no packages or files.
var spdxWithNoPackages = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "empty-sbom",
  "documentNamespace": "https://example.com/empty-sbom",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  }
}
`)

// SPDX document with two files and no packages.
var spdxWithFilesOnly = []byte(`{
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
}
`)

// SPDX package whose originator is an Organization (not a Person).
// spdxOriginatorName only maps Person originators to the Author column.
var spdxPkgWithOrganizationOriginator = []byte(`
{
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
}
`)

// SPDX package with a cpe22Type external reference (no PURL).
var spdxPkgWithCPE22Type = []byte(`
{
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
}
`)

// SPDX package with no external references at all (no PURL, no CPE).
var spdxPkgWithNoExternalRefs = []byte(`{
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

var spdxPkgWithNoType = []byte(`{
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

var spdxPkgWithLicenseComments = []byte(`{
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

// SPDX file with all four checksum algorithms present.
var spdxWithFileAllChecksums = []byte(`{
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
        {
	      "algorithm": "MD5",
		  "checksumValue": "filemd5val"
		},
        {
		  "algorithm": "SHA1",
		  "checksumValue": "filesha1val"
		},
        {
		  "algorithm": "SHA256",
		  "checksumValue": "filesha256val"
		},
        {
		  "algorithm": "SHA512",
		  "checksumValue": "filesha512val"
		}
      ]
    }
  ]
}`)

// spdxLicenseNoassertion has a package with licenseDeclared = "NOASSERTION".
var spdxPkgWithLicenseNoassertion = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "noassertion-license-sbom",
  "documentNamespace": "https://example.com/noassertion-license",
  "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg",
      "name": "noassertion-pkg",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "Copyright 2024"
    }
  ]
}`)

// spdxLicenseNone has a package with licenseDeclared = "NONE".
var spdxPkgWithLicenseNONE = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "none-license-sbom",
  "documentNamespace": "https://example.com/none-license",
  "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg",
      "name": "none-license-pkg",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "licenseDeclared": "NONE",
      "copyrightText": "Copyright 2024"
    }
  ]
}`)

// spdxCopyrightNoassertion has a package with copyrightText = "NOASSERTION".
var spdxPkgWithCopyrightNOASSERTION = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "noassertion-copyright-sbom",
  "documentNamespace": "https://example.com/noassertion-copyright",
  "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg",
      "name": "noassertion-copyright-pkg",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "licenseDeclared": "MIT",
      "copyrightText": "NOASSERTION"
    }
  ]
}`)

// spdxToolOriginator has a package with originator = "Tool: test-tool".
// spdxOriginatorName only maps Person/Organization originators to Author; Tool → "".
var spdxToolOriginator = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "tool-originator-sbom",
  "documentNamespace": "https://example.com/tool-originator",
  "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg",
      "name": "tool-pkg",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "originator": "Tool: test-tool",
      "licenseDeclared": "MIT",
      "copyrightText": "Copyright 2024"
    }
  ]
}`)

// spdxMultiplePURLRefs has a package with two PURL external references.
var spdxPkgWithMultiplePURLRefs = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "multi-purl-sbom",
  "documentNamespace": "https://example.com/multi-purl",
  "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg",
      "name": "multi-purl-pkg",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "licenseDeclared": "MIT",
      "copyrightText": "Copyright 2024",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/multi-purl-pkg@1.0.0"
        },
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:github/acme/multi-purl-pkg@1.0.0"
        }
      ]
    }
  ]
}`)

// spdxTypeVariants has packages with six different primaryPackagePurpose values.
var spdxPkgWithTypeVariants = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "type-variants-sbom",
  "documentNamespace": "https://example.com/type-variants",
  "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
  "packages": [
    {
      "SPDXID": "SPDXRef-app",
	  "name": "app-pkg",
	  "versionInfo": "1.0.0",
	  "downloadLocation": "NOASSERTION",
	  "primaryPackagePurpose": "APPLICATION",
	  "licenseDeclared": "MIT",
	  "copyrightText": "NOASSERTION"
	},
    {
	  "SPDXID": "SPDXRef-lib",
	  "name": "lib-pkg",
	  "versionInfo": "1.0.0",
	  "downloadLocation": "NOASSERTION",
	  "primaryPackagePurpose": "LIBRARY",
	  "licenseDeclared": "MIT",
	  "copyrightText": "NOASSERTION"
	},
    {
	  "SPDXID": "SPDXRef-os",
	  "name": "os-pkg",
	  "versionInfo": "1.0.0",
	  "downloadLocation": "NOASSERTION",
	  "primaryPackagePurpose": "OPERATING-SYSTEM",
	  "licenseDeclared": "MIT",
	  "copyrightText": "NOASSERTION"
	},
    {
	  "SPDXID": "SPDXRef-ctr",
	  "name": "container-pkg",
	  "versionInfo": "1.0.0",
	  "downloadLocation": "NOASSERTION",
	  "primaryPackagePurpose": "CONTAINER",
	  "licenseDeclared": "MIT",
	  "copyrightText": "NOASSERTION"
	},
    {
	  "SPDXID": "SPDXRef-dev",
	  "name": "device-pkg",
	  "versionInfo": "1.0.0",
	  "downloadLocation": "NOASSERTION",
	  "primaryPackagePurpose": "DEVICE",
	  "licenseDeclared": "MIT",
	  "copyrightText": "NOASSERTION"
	},
    {
	  "SPDXID": "SPDXRef-fw",
	  "name": "firmware-pkg",
	  "versionInfo": "1.0.0",
	  "downloadLocation": "NOASSERTION",
	  "primaryPackagePurpose": "FIRMWARE",
	  "licenseDeclared": "MIT",
	  "copyrightText": "NOASSERTION"
	}
  ]
}`)

// TestSPDXAll consolidates all SPDX error, edge-case, and field-coverage
// tests into a single table-driven function organised as subtests.
func TestSPDXAll(t *testing.T) {
	// --- Error / invalid-input cases ---
	t.Run("errors", func(t *testing.T) {
		cases := []struct {
			name    string
			fixture []byte
		}{
			{"spdxMalformedJSON", spdxMalformedJSON},
			{"spdxMissingSPDXID", spdxMissingSPDXID},
			{"spdxWrongSPDXID", spdxWrongSPDXID},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				path := writeTempFile(t, tc.fixture, ".spdx.json")
				defer os.Remove(path)
				_, err := tryParseAndSerialize(t, path)
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.name)
				}
			})
		}
	})

	t.Run("spdxWithNoPackages", func(t *testing.T) {
		path := writeTempFile(t, spdxWithNoPackages, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 1 {
			t.Errorf("got %d rows, want 1 (header only)", len(rows))
		}
	})

	t.Run("spdxWithFilesOnly", func(t *testing.T) {
		path := writeTempFile(t, spdxWithFilesOnly, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 3 {
			t.Fatalf("got %d rows, want 3 (header + 2 files)", len(rows))
		}

		header := rows[0]
		typeIdx := columnIndex(t, header, "Type")

		// every data row must have Type = "FILE"
		for i, row := range rows[1:] {
			if row[typeIdx] != "FILE" {
				t.Errorf("row %d Type = %q, want FILE", i+1, row[typeIdx])
			}
		}
		// first file: spot-check all 17 columns
		row := rows[1]
		checks := []struct{ col, want string }{
			{"Name", "/src/main.go"},
			{"Type", "FILE"},
			{"LicenseExpressions", "MIT"},
			{"Copyright", "Copyright 2024"},
			{"Version", ""}, {"Author", ""}, {"Supplier", ""},
			{"Group", ""}, {"Scope", ""}, {"Purl", ""}, {"Cpe", ""},
			{"LicenseNames", ""}, {"Description", ""},
			{"MD5", ""}, {"SHA-1", ""}, {"SHA-256", ""}, {"SHA-512", ""},
		}
		for _, c := range checks {
			t.Run(c.col, func(t *testing.T) {
				if got := row[columnIndex(t, header, c.col)]; got != c.want {
					t.Errorf("column %q = %q, want %q", c.col, got, c.want)
				}
			})
		}
	})

	// --- Field-coverage cases ---
	t.Run("spdxPkgWithOrganizationOriginator", func(t *testing.T) {
		path := writeTempFile(t, spdxPkgWithOrganizationOriginator, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		checks := []struct{ col, want string }{
			{"Author", "Acme Corp"},
			{"Supplier", "Supplier Corp"},
		}

		for _, c := range checks {
			if got := row[columnIndex(t, header, c.col)]; got != c.want {
				t.Errorf("%s = %q, want %q", c.col, got, c.want)
			}
		}
	})

	t.Run("spdxPkgWithCPE22Type", func(t *testing.T) {
		path := writeTempFile(t, spdxPkgWithCPE22Type, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]

		checks := []struct{ col, want string }{
			{"Cpe", "cpe:/a:acme:my-pkg:1.0.0"},
			{"Purl", ""},
		}

		for _, c := range checks {
			if got := row[columnIndex(t, header, c.col)]; got != c.want {
				t.Errorf("%s = %q, want %q", c.col, got, c.want)
			}
		}
	})

	t.Run("spdxPkgWithNoExternalRefs", func(t *testing.T) {
		path := writeTempFile(t, spdxPkgWithNoExternalRefs, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		for _, col := range []string{"Purl", "Cpe"} {
			if got := row[columnIndex(t, header, col)]; got != "" {
				t.Errorf("%s = %q, want empty (no external refs)", col, got)
			}
		}
	})

	t.Run("spdxPkgWithNoType", func(t *testing.T) {
		path := writeTempFile(t, spdxPkgWithNoType, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		if got := row[columnIndex(t, header, "Type")]; got != "" {
			t.Errorf("Type = %q, want empty when primaryPackagePurpose absent", got)
		}
	})

	t.Run("spdxPkgWithLicenseComments", func(t *testing.T) {
		path := writeTempFile(t, spdxPkgWithLicenseComments, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		checks := []struct{ col, want string }{
			{"LicenseExpressions", "MIT"},
			{"LicenseNames", ""},
		}

		for _, c := range checks {
			if got := row[columnIndex(t, header, c.col)]; got != c.want {
				t.Errorf("%s = %q, want %q", c.col, got, c.want)
			}
		}
	})

	t.Run("spdxWithFileAllChecksums", func(t *testing.T) {
		path := writeTempFile(t, spdxWithFileAllChecksums, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		checks := []struct{ col, want string }{
			{"MD5", "filemd5val"},
			{"SHA-1", "filesha1val"},
			{"SHA-256", "filesha256val"},
			{"SHA-512", "filesha512val"},
		}

		for _, c := range checks {
			t.Run(c.col, func(t *testing.T) {
				if got := row[columnIndex(t, header, c.col)]; got != c.want {
					t.Errorf("column %q = %q, want %q", c.col, got, c.want)
				}
			})
		}
	})

	t.Run("spdxSBOM", func(t *testing.T) {
		path := writeTempFile(t, spdxSBOM, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		header, row := rows[0], rows[1] // my-app is first data row

		checks := []struct{ col, want string }{
			{"MD5", "abc123"},
			{"SHA-1", "def456"},
		}

		for _, c := range checks {
			if got := row[columnIndex(t, header, c.col)]; got != c.want {
				t.Errorf("%s = %q, want %q", c.col, got, c.want)
			}
		}
	})

	t.Run("spdxPkgWithLicenseNoassertion", func(t *testing.T) {
		path := writeTempFile(t, spdxPkgWithLicenseNoassertion, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		if got := row[columnIndex(t, header, "LicenseExpressions")]; got != "NOASSERTION" {
			t.Errorf("LicenseExpressions = %q, want NOASSERTION", got)
		}
	})

	t.Run("spdxPkgWithLicenseNONE", func(t *testing.T) {
		path := writeTempFile(t, spdxPkgWithLicenseNONE, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		if got := row[columnIndex(t, header, "LicenseExpressions")]; got != "NONE" {
			t.Errorf("LicenseExpressions = %q, want NONE", got)
		}
	})

	t.Run("spdxPkgWithCopyrightNOASSERTION", func(t *testing.T) {
		path := writeTempFile(t, spdxPkgWithCopyrightNOASSERTION, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		if got := row[columnIndex(t, header, "Copyright")]; got != "NOASSERTION" {
			t.Errorf("Copyright = %q, want NOASSERTION", got)
		}
	})

	t.Run("spdxToolOriginator", func(t *testing.T) {
		path := writeTempFile(t, spdxToolOriginator, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		if got := row[columnIndex(t, header, "Author")]; got != "" {
			t.Errorf("Author = %q, want empty for Tool originator", got)
		}
	})

	t.Run("spdxPkgWithMultiplePURLRefs", func(t *testing.T) {
		path := writeTempFile(t, spdxPkgWithMultiplePURLRefs, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		header, row := rows[0], rows[1]
		if got := row[columnIndex(t, header, "Purl")]; got != "pkg:npm/multi-purl-pkg@1.0.0" {
			t.Errorf("Purl = %q, want first PURL when multiple present", got)
		}
	})

	t.Run("spdxPkgWithTypeVariants", func(t *testing.T) {
		path := writeTempFile(t, spdxPkgWithTypeVariants, ".spdx.json")
		defer os.Remove(path)

		rows := parseAndSerialize(t, path)
		// header + 6 packages
		if len(rows) != 7 {
			t.Fatalf("got %d rows, want 7 (header + 6 packages)", len(rows))
		}

		header := rows[0]
		typeIdx := columnIndex(t, header, "Type")

		wantTypes := []string{
			"APPLICATION", "LIBRARY", "OPERATING-SYSTEM",
			"CONTAINER", "DEVICE", "FIRMWARE",
		}

		for i, want := range wantTypes {
			if got := rows[i+1][typeIdx]; got != want {
				t.Errorf("row %d Type = %q, want %q", i+1, got, want)
			}
		}
	})
}
