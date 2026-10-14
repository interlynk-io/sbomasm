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

package rm

import (
	"testing"

	"github.com/interlynk-io/sbomasm/v2/pkg/rm/types"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SPDX 3.0 Inline Fixtures
// ═══════════════════════════════════════════════════════════════════════════════

// Fixture: Document with author (Person Alice), supplier (Organization ACME), tool (Tool1)
var spdx3DocWithAuthorSupplierTool = []byte(`{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "https://example.org/doc1",
      "creationInfo": "_:creationinfo",
      "rootElement": ["https://example.org/pkg1"]
    },
    {
      "type": "CreationInfo",
      "spdxId": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-01T00:00:00Z",
      "createdBy": ["https://example.org/person1", "https://example.org/org1"],
      "createdUsing": ["https://example.org/tool1"]
    },
    {
      "type": "Person",
      "spdxId": "https://example.org/person1",
      "name": "Alice"
    },
    {
      "type": "Organization",
      "spdxId": "https://example.org/org1",
      "name": "ACME Corp"
    },
    {
      "type": "Tool",
      "spdxId": "https://example.org/tool1",
      "name": "Tool1"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg1",
      "name": "app",
      "packageVersion": "1.0.0"
    }
  ]
}`)

// Fixture: Component with hash, purl, description, copyright, type, author, supplier
var spdx3DocWithComponentFields = []byte(`{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "https://example.org/doc1",
      "creationInfo": "_:creationinfo",
      "rootElement": ["https://example.org/pkg1"]
    },
    {
      "type": "CreationInfo",
      "spdxId": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-01T00:00:00Z",
      "createdBy": ["https://example.org/person1"]
    },
    {
      "type": "Person",
      "spdxId": "https://example.org/person1",
      "name": "Alice"
    },
    {
      "type": "Organization",
      "spdxId": "https://example.org/org1",
      "name": "ACME Corp"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg1",
      "name": "app",
      "packageVersion": "1.0.0",
      "description": "An application",
      "software_copyrightText": "Copyright 2024",
      "primaryPurpose": "application",
      "additionalPurpose": ["library"],
      "originatedBy": ["https://example.org/person1"],
      "suppliedBy": "https://example.org/org1",
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha256",
          "hashValue": "abc123"
        }
      ],
      "externalIdentifier": [
        {
          "type": "PackageUrl",
          "externalIdentifierType": "packageUrl",
          "identifier": "pkg:generic/app@1.0.0"
        }
      ]
    }
  ]
}`)

// Fixture: Component with license relationship
var spdx3DocWithComponentLicense = []byte(`{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "https://example.org/doc1",
      "creationInfo": "_:creationinfo",
      "rootElement": ["https://example.org/pkg1"]
    },
    {
      "type": "CreationInfo",
      "spdxId": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-01T00:00:00Z",
      "createdBy": ["https://example.org/person1"]
    },
    {
      "type": "Person",
      "spdxId": "https://example.org/person1",
      "name": "Alice"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg1",
      "name": "app",
      "packageVersion": "1.0.0"
    },
    {
      "type": "Relationship",
      "spdxId": "https://example.org/rel1",
      "relationshipType": "hasConcludedLicense",
      "from": "https://example.org/pkg1",
      "to": ["https://example.org/license1"]
    },
    {
      "type": "SimpleLicensingText",
      "spdxId": "https://example.org/license1",
      "name": "MIT",
      "licenseText": "MIT License text"
    }
  ]
}`)

// Fixture: Two packages with dependency relationship
var spdx3DocWithTwoPackages = []byte(`{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "https://example.org/doc1",
      "creationInfo": "_:creationinfo",
      "rootElement": ["https://example.org/pkg1"]
    },
    {
      "type": "CreationInfo",
      "spdxId": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-01T00:00:00Z",
      "createdBy": ["https://example.org/person1"]
    },
    {
      "type": "Person",
      "spdxId": "https://example.org/person1",
      "name": "Alice"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg1",
      "name": "app",
      "packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg2",
      "name": "lib",
      "packageVersion": "2.0.0"
    },
    {
      "type": "Relationship",
      "spdxId": "https://example.org/rel1",
      "relationshipType": "dependsOn",
      "from": "https://example.org/pkg1",
      "to": ["https://example.org/pkg2"]
    }
  ]
}`)

// ═══════════════════════════════════════════════════════════════════════════════
// Document-Level Removal Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestRmSpdx3_DocumentAuthorRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithAuthorSupplierTool)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "author"
	params.Scope = "document"
	params.IsFieldPresent = true
	params.All = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteDocumentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteDocumentFieldRemoval failed: %v", err)
	}

	if len(doc.CreationInfo.CreatedBy) != 1 {
		t.Fatalf("expected 1 CreatedBy entry after author removal, got %d", len(doc.CreationInfo.CreatedBy))
	}
	if doc.CreationInfo.CreatedBy[0].SpdxID != "https://example.org/org1" {
		t.Fatalf("expected remaining org SpdxID, got %s", doc.CreationInfo.CreatedBy[0].SpdxID)
	}
	if len(doc.Persons) != 0 {
		t.Fatalf("expected 0 Persons after orphan cleanup, got %d", len(doc.Persons))
	}
}

func TestRmSpdx3_DocumentSupplierRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithAuthorSupplierTool)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "supplier"
	params.Scope = "document"
	params.IsFieldPresent = true
	params.All = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteDocumentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteDocumentFieldRemoval failed: %v", err)
	}

	if len(doc.CreationInfo.CreatedBy) != 1 {
		t.Fatalf("expected 1 CreatedBy entry after supplier removal, got %d", len(doc.CreationInfo.CreatedBy))
	}
	if doc.CreationInfo.CreatedBy[0].SpdxID != "https://example.org/person1" {
		t.Fatalf("expected remaining person SpdxID, got %s", doc.CreationInfo.CreatedBy[0].SpdxID)
	}
	if len(doc.Organizations) != 0 {
		t.Fatalf("expected 0 Organizations after orphan cleanup, got %d", len(doc.Organizations))
	}
}

func TestRmSpdx3_DocumentToolRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithAuthorSupplierTool)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "tool"
	params.Scope = "document"
	params.IsFieldPresent = true
	params.All = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteDocumentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteDocumentFieldRemoval failed: %v", err)
	}

	if len(doc.CreationInfo.CreatedUsing) != 0 {
		t.Fatalf("expected 0 CreatedUsing entries after tool removal, got %d", len(doc.CreationInfo.CreatedUsing))
	}
	if len(doc.Tools) != 0 {
		t.Fatalf("expected 0 Tools after orphan cleanup, got %d", len(doc.Tools))
	}
}

func TestRmSpdx3_DocumentTimestampRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithAuthorSupplierTool)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "timestamp"
	params.Scope = "document"
	params.IsFieldPresent = true
	params.All = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteDocumentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteDocumentFieldRemoval failed: %v", err)
	}

	if !doc.CreationInfo.Created.IsZero() {
		t.Fatalf("expected timestamp to be zeroed, got %v", doc.CreationInfo.Created)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Component-Level Removal Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestRmSpdx3_ComponentHashRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithComponentFields)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "hash"
	params.Scope = "component"
	params.IsFieldPresent = true
	params.All = true
	params.AllComponents = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteComponentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteComponentFieldRemoval failed: %v", err)
	}

	if len(doc.Packages[0].VerifiedUsing) != 0 {
		t.Fatalf("expected 0 VerifiedUsing entries after hash removal, got %d", len(doc.Packages[0].VerifiedUsing))
	}
}

func TestRmSpdx3_ComponentPurlRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithComponentFields)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "purl"
	params.Scope = "component"
	params.IsFieldPresent = true
	params.All = true
	params.AllComponents = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteComponentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteComponentFieldRemoval failed: %v", err)
	}

	if len(doc.Packages[0].ExternalIdentifier) != 0 {
		t.Fatalf("expected 0 ExternalIdentifier entries after PURL removal, got %d", len(doc.Packages[0].ExternalIdentifier))
	}
}

func TestRmSpdx3_ComponentTypeRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithComponentFields)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "type"
	params.Scope = "component"
	params.IsFieldPresent = true
	params.All = true
	params.AllComponents = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteComponentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteComponentFieldRemoval failed: %v", err)
	}

	if doc.Packages[0].PrimaryPurpose != "" {
		t.Fatalf("expected PrimaryPurpose to be empty, got %s", doc.Packages[0].PrimaryPurpose)
	}
	if len(doc.Packages[0].AdditionalPurpose) != 0 {
		t.Fatalf("expected 0 AdditionalPurpose entries, got %d", len(doc.Packages[0].AdditionalPurpose))
	}
}

func TestRmSpdx3_ComponentDescriptionRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithComponentFields)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "description"
	params.Scope = "component"
	params.IsFieldPresent = true
	params.All = true
	params.AllComponents = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteComponentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteComponentFieldRemoval failed: %v", err)
	}

	if doc.Packages[0].Description != "" {
		t.Fatalf("expected Description to be empty, got %s", doc.Packages[0].Description)
	}
}

func TestRmSpdx3_ComponentCopyrightRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithComponentFields)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "copyright"
	params.Scope = "component"
	params.IsFieldPresent = true
	params.All = true
	params.AllComponents = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteComponentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteComponentFieldRemoval failed: %v", err)
	}

	if doc.Packages[0].CopyrightText != "" {
		t.Fatalf("expected CopyrightText to be empty, got %s", doc.Packages[0].CopyrightText)
	}
}

func TestRmSpdx3_ComponentAuthorRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithComponentFields)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "author"
	params.Scope = "component"
	params.IsFieldPresent = true
	params.All = true
	params.AllComponents = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteComponentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteComponentFieldRemoval failed: %v", err)
	}

	if len(doc.Packages[0].OriginatedBy) != 0 {
		t.Fatalf("expected 0 OriginatedBy entries after author removal, got %d", len(doc.Packages[0].OriginatedBy))
	}
	// Alice should still exist because she's referenced in CreationInfo.CreatedBy
	if len(doc.Persons) != 1 {
		t.Fatalf("expected 1 Person (Alice in CreationInfo), got %d", len(doc.Persons))
	}
}

func TestRmSpdx3_ComponentSupplierRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithComponentFields)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "supplier"
	params.Scope = "component"
	params.IsFieldPresent = true
	params.All = true
	params.AllComponents = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteComponentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteComponentFieldRemoval failed: %v", err)
	}

	if doc.Packages[0].SuppliedBy != nil {
		t.Fatalf("expected SuppliedBy to be nil after supplier removal")
	}
	// ACME should be removed (orphan cleanup — not referenced elsewhere)
	if len(doc.Organizations) != 0 {
		t.Fatalf("expected 0 Organizations after orphan cleanup, got %d", len(doc.Organizations))
	}
}

func TestRmSpdx3_ComponentLicenseRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithComponentLicense)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "license"
	params.Scope = "component"
	params.IsFieldPresent = true
	params.All = true
	params.AllComponents = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteComponentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteComponentFieldRemoval failed: %v", err)
	}

	if len(doc.Relationships) != 0 {
		t.Fatalf("expected 0 Relationships after license removal, got %d", len(doc.Relationships))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Full Component Removal Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestRmSpdx3_RemoveComponent(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithTwoPackages)

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Kind = types.ComponentRemoval
	params.IsComponent = true
	params.ComponentName = "app"
	params.ComponentVersion = "1.0.0"

	compEngine := &ComponentsOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := compEngine.Execute(*params.Ctx, params); err != nil {
		t.Fatalf("ComponentsOperationEngine.Execute failed: %v", err)
	}

	if len(doc.Packages) != 1 {
		t.Fatalf("expected 1 package after removal, got %d", len(doc.Packages))
	}
	if doc.Packages[0].Name != "lib" {
		t.Fatalf("expected remaining package 'lib', got %s", doc.Packages[0].Name)
	}
	if len(doc.Relationships) != 0 {
		t.Fatalf("expected 0 relationships after component removal, got %d", len(doc.Relationships))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Orphan Cleanup Verification
// ═══════════════════════════════════════════════════════════════════════════════

func TestRmSpdx3_OrphanCleanupAfterDocAuthorRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithAuthorSupplierTool)

	// Verify Alice exists before removal
	if len(doc.Persons) != 1 {
		t.Fatalf("expected 1 Person before removal, got %d", len(doc.Persons))
	}
	if doc.Persons[0].Name != "Alice" {
		t.Fatalf("expected Person 'Alice', got %s", doc.Persons[0].Name)
	}

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "author"
	params.Scope = "document"
	params.IsFieldPresent = true
	params.All = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteDocumentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteDocumentFieldRemoval failed: %v", err)
	}

	// Alice should be removed from CreationInfo
	for _, agent := range doc.CreationInfo.CreatedBy {
		if agent.SpdxID == "https://example.org/person1" {
			t.Fatalf("Alice should be removed from CreationInfo.CreatedBy")
		}
	}

	// Alice should be removed from doc.Persons (orphan cleanup)
	if len(doc.Persons) != 0 {
		t.Fatalf("expected 0 Persons after orphan cleanup, got %d", len(doc.Persons))
	}
}

func TestRmSpdx3_OrphanCleanupAfterDocSupplierRemoval(t *testing.T) {
	doc := parseSpdx3FromBytes(t, spdx3DocWithAuthorSupplierTool)

	// Verify ACME exists before removal
	if len(doc.Organizations) != 1 {
		t.Fatalf("expected 1 Organization before removal, got %d", len(doc.Organizations))
	}
	if doc.Organizations[0].Name != "ACME Corp" {
		t.Fatalf("expected Organization 'ACME Corp', got %s", doc.Organizations[0].Name)
	}

	RegisterSPDX3Handlers(doc)
	params := newRmParams(t)
	params.SpecKey = "spdx3"
	params.Field = "supplier"
	params.Scope = "document"
	params.IsFieldPresent = true
	params.All = true

	engine := &FieldOperationEngine{doc: &sbom.SPDX3Document{Doc: doc}}
	if err := engine.ExecuteDocumentFieldRemoval(*params.Ctx, params); err != nil {
		t.Fatalf("ExecuteDocumentFieldRemoval failed: %v", err)
	}

	// ACME should be removed from CreationInfo
	for _, agent := range doc.CreationInfo.CreatedBy {
		if agent.SpdxID == "https://example.org/org1" {
			t.Fatalf("ACME Corp should be removed from CreationInfo.CreatedBy")
		}
	}

	// ACME should be removed from doc.Organizations (orphan cleanup)
	if len(doc.Organizations) != 0 {
		t.Fatalf("expected 0 Organizations after orphan cleanup, got %d", len(doc.Organizations))
	}
}
