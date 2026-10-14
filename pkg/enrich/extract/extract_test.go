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

package extract

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

var initLoggerOnce sync.Once

func initTestLogger() {
	initLoggerOnce.Do(logger.InitProdLogger)
}

// spdx3NoLicense is an SPDX 3.0 document with one package that has a PURL
// but no license relationships.
var spdx3NoLicense = []byte(`
{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "@id": "_:creationinfo",
      "type": "CreationInfo",
      "specVersion": "3.0.1",
      "createdBy": ["https://example.org/org1"],
      "createdUsing": ["https://example.org/tool1"],
      "created": "2024-01-01T00:00:00Z"
    },
    {
      "spdxId": "https://example.org/doc1",
      "type": "SpdxDocument",
      "name": "test-sbom",
      "creationInfo": "_:creationinfo",
      "rootElement": ["https://example.org/pkg1"],
      "profileConformance": ["core", "software"]
    },
    {
      "spdxId": "https://example.org/org1",
      "type": "Organization",
      "name": "Acme Corp",
      "creationInfo": "_:creationinfo"
    },
    {
      "spdxId": "https://example.org/tool1",
      "type": "Tool",
      "name": "test-tool",
      "creationInfo": "_:creationinfo"
    },
    {
      "spdxId": "https://example.org/pkg1",
      "type": "software_Package",
      "name": "my-app",
      "software_packageVersion": "1.0.0",
      "software_primaryPurpose": "application",
      "creationInfo": "_:creationinfo",
      "externalIdentifier": [
        {
          "externalIdentifierType": "packageUrl",
          "identifier": "pkg:npm/my-app@1.0.0"
        }
      ]
    }
  ]
}
`)

// spdx3WithLicense is an SPDX 3.0 document with one package that has a PURL
// and an existing hasConcludedLicense relationship.
var spdx3WithLicense = []byte(`
{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "@id": "_:creationinfo",
      "type": "CreationInfo",
      "specVersion": "3.0.1",
      "createdBy": ["https://example.org/org1"],
      "createdUsing": ["https://example.org/tool1"],
      "created": "2024-01-01T00:00:00Z"
    },
    {
      "spdxId": "https://example.org/doc1",
      "type": "SpdxDocument",
      "name": "test-sbom",
      "creationInfo": "_:creationinfo",
      "rootElement": ["https://example.org/pkg1"],
      "profileConformance": ["core", "software"]
    },
    {
      "spdxId": "https://example.org/org1",
      "type": "Organization",
      "name": "Acme Corp",
      "creationInfo": "_:creationinfo"
    },
    {
      "spdxId": "https://example.org/tool1",
      "type": "Tool",
      "name": "test-tool",
      "creationInfo": "_:creationinfo"
    },
    {
      "spdxId": "https://example.org/pkg1",
      "type": "software_Package",
      "name": "my-app",
      "software_packageVersion": "1.0.0",
      "software_primaryPurpose": "application",
      "creationInfo": "_:creationinfo",
      "externalIdentifier": [
        {
          "externalIdentifierType": "packageUrl",
          "identifier": "pkg:npm/my-app@1.0.0"
        }
      ]
    },
    {
      "spdxId": "https://example.org/lic-mit",
      "type": "SimpleLicensingText",
      "name": "MIT",
      "creationInfo": "_:creationinfo"
    },
    {
      "spdxId": "https://example.org/rel1",
      "type": "Relationship",
      "relationshipType": "hasConcludedLicense",
      "from": "https://example.org/pkg1",
      "to": ["https://example.org/lic-mit"],
      "creationInfo": "_:creationinfo"
    }
  ]
}
`)

// spdx3NoPurl is an SPDX 3.0 document with one package that has no PURL.
var spdx3NoPurl = []byte(`
{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "@id": "_:creationinfo",
      "type": "CreationInfo",
      "specVersion": "3.0.1",
      "createdBy": ["https://example.org/org1"],
      "createdUsing": ["https://example.org/tool1"],
      "created": "2024-01-01T00:00:00Z"
    },
    {
      "spdxId": "https://example.org/doc1",
      "type": "SpdxDocument",
      "name": "test-sbom",
      "creationInfo": "_:creationinfo",
      "rootElement": ["https://example.org/pkg1"],
      "profileConformance": ["core", "software"]
    },
    {
      "spdxId": "https://example.org/org1",
      "type": "Organization",
      "name": "Acme Corp",
      "creationInfo": "_:creationinfo"
    },
    {
      "spdxId": "https://example.org/pkg1",
      "type": "software_Package",
      "name": "my-app",
      "software_packageVersion": "1.0.0",
      "creationInfo": "_:creationinfo"
    }
  ]
}
`)

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

func TestSPDX3ExtractComponents(t *testing.T) {
	initTestLogger()
	ctx := logger.WithLogger(context.Background())

	t.Run("no-license-selects-for-enrichment", func(t *testing.T) {
		path := writeTempFile(t, spdx3NoLicense, ".spdx3.json")
		defer os.Remove(path)

		doc, err := sbom.Parser(ctx, path)
		if err != nil {
			t.Fatalf("Parser() error: %v", err)
		}

		params := &Params{
			Fields: []string{"license"},
			Force:  false,
		}
		components, total, selected, err := Components(ctx, doc, params)
		if err != nil {
			t.Fatalf("Components() error: %v", err)
		}

		if total != 1 {
			t.Errorf("total = %d, want 1", total)
		}
		if selected != 1 {
			t.Errorf("selected = %d, want 1", selected)
		}
		if len(components) != 1 {
			t.Errorf("components = %d, want 1", len(components))
		}
	})

	t.Run("with-license-skips-without-force", func(t *testing.T) {
		path := writeTempFile(t, spdx3WithLicense, ".spdx3.json")
		defer os.Remove(path)

		doc, err := sbom.Parser(ctx, path)
		if err != nil {
			t.Fatalf("Parser() error: %v", err)
		}

		params := &Params{
			Fields: []string{"license"},
			Force:  false,
		}
		components, total, selected, err := Components(ctx, doc, params)
		if err != nil {
			t.Fatalf("Components() error: %v", err)
		}

		if total != 1 {
			t.Errorf("total = %d, want 1", total)
		}
		if selected != 0 {
			t.Errorf("selected = %d, want 0 (has existing license)", selected)
		}
		if len(components) != 0 {
			t.Errorf("components = %d, want 0", len(components))
		}
	})

	t.Run("with-license-selects-with-force", func(t *testing.T) {
		path := writeTempFile(t, spdx3WithLicense, ".spdx3.json")
		defer os.Remove(path)

		doc, err := sbom.Parser(ctx, path)
		if err != nil {
			t.Fatalf("Parser() error: %v", err)
		}

		params := &Params{
			Fields: []string{"license"},
			Force:  true,
		}
		components, total, selected, err := Components(ctx, doc, params)
		if err != nil {
			t.Fatalf("Components() error: %v", err)
		}

		if total != 1 {
			t.Errorf("total = %d, want 1", total)
		}
		if selected != 1 {
			t.Errorf("selected = %d, want 1 (force=true)", selected)
		}
		if len(components) != 1 {
			t.Errorf("components = %d, want 1", len(components))
		}
	})

	t.Run("no-purl-skips", func(t *testing.T) {
		path := writeTempFile(t, spdx3NoPurl, ".spdx3.json")
		defer os.Remove(path)

		doc, err := sbom.Parser(ctx, path)
		if err != nil {
			t.Fatalf("Parser() error: %v", err)
		}

		params := &Params{
			Fields: []string{"license"},
			Force:  false,
		}
		components, total, selected, err := Components(ctx, doc, params)
		if err != nil {
			t.Fatalf("Components() error: %v", err)
		}

		if total != 1 {
			t.Errorf("total = %d, want 1", total)
		}
		if selected != 0 {
			t.Errorf("selected = %d, want 0 (no PURL)", selected)
		}
		if len(components) != 0 {
			t.Errorf("components = %d, want 0", len(components))
		}
	})
}
