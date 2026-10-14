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

package edit

import (
	"testing"

	spdx3 "github.com/interlynk-io/spdx-zen/model/v3.0.1"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SPDX 3.0 Test Data — Package-Level Variables
// ═══════════════════════════════════════════════════════════════════════════════

// sbomSpdx3DocWithOneAuthorNamedAlice is a minimal SPDX 3.0 document containing:
//   - SpdxDocument with one rootElement
//   - CreationInfo with one createdBy (Person Alice)
//   - Person element named Alice
//   - software_Package element named "app"
var sbomSpdx3DocWithOneAuthorNamedAlice = []byte(`{
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
      "name": "app"
    }
  ]
}`)

// sbomSpdx3DocEmptyWithJustDocumentAndPackage is a bare-minimum SPDX 3.0 document
// with no authors, no supplier, no hashes — just a SpdxDocument and one Package.
var sbomSpdx3DocEmptyWithJustDocumentAndPackage = []byte(`{
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
      "created": "2024-01-01T00:00:00Z"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg1",
      "name": "app"
    }
  ]
}`)

// sbomSpdx3DocWithOnePackageOneSha256Hash contains a single package with one
// SHA-256 hash in its verifiedUsing array.
var sbomSpdx3DocWithOnePackageOneSha256Hash = []byte(`{
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
      "created": "2024-01-01T00:00:00Z"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg1",
      "name": "app",
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha256",
          "hashValue": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
      ]
    }
  ]
}`)

// sbomSpdx3DocWithTwoPackagesNamedAppAndLib contains two packages so we can
// test component-name-version search isolation.
var sbomSpdx3DocWithTwoPackagesNamedAppAndLib = []byte(`{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "https://example.org/doc1",
      "creationInfo": "_:creationinfo",
      "rootElement": ["https://example.org/pkg-app", "https://example.org/pkg-lib"]
    },
    {
      "type": "CreationInfo",
      "spdxId": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-01T00:00:00Z"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg-app",
      "name": "app",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg-lib",
      "name": "lib",
      "software_packageVersion": "2.0.0"
    }
  ]
}`)

// sbomSpdx3DocWithSupplierOrgAcmeAndAuthorAlice has both a supplier
// (Organization) and an author (Person) in CreationInfo.createdBy.
var sbomSpdx3DocWithSupplierOrgAcmeAndAuthorAlice = []byte(`{
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
      "createdBy": [
        "https://example.org/org-acme",
        "https://example.org/person1"
      ]
    },
    {
      "type": "Organization",
      "spdxId": "https://example.org/org-acme",
      "name": "ACME Corp"
    },
    {
      "type": "Person",
      "spdxId": "https://example.org/person1",
      "name": "Alice"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg1",
      "name": "app"
    }
  ]
}`)

// ═══════════════════════════════════════════════════════════════════════════════
// Document-Level Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx3Doc_AppendAuthor_AddsNewPersonPreservesExisting(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocWithOneAuthorNamedAlice)

	cfg := newConfig(t, "document", "append", withAuthor("Bob (bob@example.com)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Alice (original) + Bob (new) = 2 Persons total
	if len(doc.Persons) != 2 {
		t.Fatalf("expected 2 Persons, got %d", len(doc.Persons))
	}

	// CreatedBy should have both Alice and Bob
	// Note: mutations happen on SpdxDocument.CreationInfo (editor.ci)
	if len(doc.SpdxDocument.CreationInfo.CreatedBy) != 2 {
		t.Fatalf("expected 2 CreatedBy entries, got %d", len(doc.SpdxDocument.CreationInfo.CreatedBy))
	}

	// Verify Alice is still there
	assertAgentInCreatedBy(t, &doc.SpdxDocument.CreationInfo, "https://example.org/person1")

	// Verify Bob was added — find by checking doc.Persons for name "Bob"
	foundBob := false
	for _, p := range doc.Persons {
		if p.Name == "Bob" {
			foundBob = true
			// Verify Bob's SpdxID appears in CreatedBy
			assertAgentInCreatedBy(t, &doc.SpdxDocument.CreationInfo, p.SpdxID)
			break
		}
	}
	if !foundBob {
		t.Fatal("expected Bob to be added to Persons")
	}
}

func TestSpdx3Doc_AppendAuthor_DedupByName(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocWithOneAuthorNamedAlice)

	// Try adding Alice again with different email
	// findOrCreatePerson deduplicates by NAME, so existing Alice is returned
	// and isInCreatedBy skips because her SpdxID is already in CreatedBy.
	cfg := newConfig(t, "document", "append", withAuthor("Alice (different@example.com)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should still be just 1 Person (Alice) — name dedup prevents duplicate
	if len(doc.Persons) != 1 {
		t.Fatalf("expected 1 Person (name dedup), got %d", len(doc.Persons))
	}

	// CreatedBy should still be just 1 entry (Alice)
	if len(doc.SpdxDocument.CreationInfo.CreatedBy) != 1 {
		t.Fatalf("expected 1 CreatedBy entry after dedup, got %d", len(doc.SpdxDocument.CreationInfo.CreatedBy))
	}
}

func TestSpdx3Doc_OverwriteAuthor_ReplacesExisting(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocWithOneAuthorNamedAlice)

	cfg := newConfig(t, "document", "overwrite", withAuthor("Charlie (charlie@example.com)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have exactly 1 Person now (Charlie replaced Alice)
	if len(doc.Persons) != 1 {
		t.Fatalf("expected 1 Person after overwrite, got %d", len(doc.Persons))
	}

	// CreatedBy should have exactly 1 entry (Charlie)
	if len(doc.SpdxDocument.CreationInfo.CreatedBy) != 1 {
		t.Fatalf("expected 1 CreatedBy entry, got %d", len(doc.SpdxDocument.CreationInfo.CreatedBy))
	}

	// Verify Alice is gone
	for _, p := range doc.Persons {
		if p.Name == "Alice" {
			t.Fatal("Alice should have been removed after overwrite")
		}
	}
}

func TestSpdx3Doc_MissingAuthor_SkipsIfPresent(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocWithOneAuthorNamedAlice)

	cfg := newConfig(t, "document", "missing", withAuthor("Bob (bob@example.com)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should still be just 1 Person (Alice) — Bob was skipped
	if len(doc.Persons) != 1 {
		t.Fatalf("expected 1 Person (missing mode should skip), got %d", len(doc.Persons))
	}
	if len(doc.SpdxDocument.CreationInfo.CreatedBy) != 1 {
		t.Fatalf("expected 1 CreatedBy entry, got %d", len(doc.SpdxDocument.CreationInfo.CreatedBy))
	}

	// Verify Alice is Present
	for _, p := range doc.Persons {
		if p.Name != "Alice" {
			t.Fatal("Alice should have been replaced after missing")
		}
	}
}

func TestSpdx3Doc_MissingAuthor_AddsIfEmpty(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "document", "missing", withAuthor("Foo (foo@example.com)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should now have 1 Person
	if len(doc.Persons) != 1 {
		t.Fatalf("expected 1 Person added by missing mode, got %d", len(doc.Persons))
	}
	if len(doc.SpdxDocument.CreationInfo.CreatedBy) != 1 {
		t.Fatalf("expected 1 CreatedBy entry, got %d", len(doc.SpdxDocument.CreationInfo.CreatedBy))
	}

	// Verify Alice is Present
	for _, p := range doc.Persons {
		if p.Name != "Foo" {
			t.Fatal("Foo should have been added after missing")
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Primary Component Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx3PC_AppendHash_AddsNewHashPreservesExisting(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocWithOnePackageOneSha256Hash)

	cfg := newConfig(t, "primary-component", "append", withHash("MD5 (d41d8cd98f00b204e9800998ecf8427e)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have 2 hashes: original SHA-256 + new MD5
	pkg := doc.Packages[0]
	if len(pkg.VerifiedUsing) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(pkg.VerifiedUsing))
	}

	// Verify original SHA-256 is still there
	assertHasHash(t, &pkg.Element, "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	// Verify new MD5 was added
	assertHasHash(t, &pkg.Element, "md5", "d41d8cd98f00b204e9800998ecf8427e")
}

func TestSpdx3PC_AppendHash_DedupByAlgValue(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocWithOnePackageOneSha256Hash)

	// Try appending the same hash again
	cfg := newConfig(t, "primary-component", "append",
		withHash("SHA256 (e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should still be just 1 hash (dedup)
	pkg := doc.Packages[0]
	if len(pkg.VerifiedUsing) != 1 {
		t.Fatalf("expected 1 hash after dedup, got %d", len(pkg.VerifiedUsing))
	}
}

func TestSpdx3PC_OverwriteHash_ReplacesAllExisting(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocWithOnePackageOneSha256Hash)

	cfg := newConfig(t, "primary-component", "overwrite", withHash("MD5 (d41d8cd98f00b204e9800998ecf8427e)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have exactly 1 hash now (MD5 replaced SHA-256)
	pkg := doc.Packages[0]
	if len(pkg.VerifiedUsing) != 1 {
		t.Fatalf("expected 1 hash after overwrite, got %d", len(pkg.VerifiedUsing))
	}

	// Verify SHA-256 is gone
	found := false
	for _, v := range pkg.VerifiedUsing {
		switch h := v.(type) {
		case spdx3.Hash:
			if string(h.Algorithm) == "sha256" {
				found = true
			}
		}
	}
	if found {
		t.Fatal("sha256 hash should have been removed after overwrite")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Component-Name-Version Search Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx3CNV_AppendHash_IsolatesTargetComponent(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocWithTwoPackagesNamedAppAndLib)

	cfg := newConfig(t, "component-name-version", "append",
		withSearch("app", "1.0.0"),
		withHash("SHA256 (deadbeef)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Find app and lib packages
	var appPkg, libPkg *spdx3.Package
	for _, pkg := range doc.Packages {
		if pkg.Name == "app" {
			appPkg = pkg
		} else if pkg.Name == "lib" {
			libPkg = pkg
		}
	}

	if appPkg == nil {
		t.Fatal("app package not found")
	}
	if libPkg == nil {
		t.Fatal("lib package not found")
	}

	// App should have the new hash
	if len(appPkg.VerifiedUsing) != 1 {
		t.Fatalf("expected app to have 1 hash, got %d", len(appPkg.VerifiedUsing))
	}

	// Lib should have no hashes
	if len(libPkg.VerifiedUsing) != 0 {
		t.Fatalf("expected lib to have 0 hashes, got %d", len(libPkg.VerifiedUsing))
	}
}

func TestSpdx3CNV_NotFound_ReturnsError(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "component-name-version", "overwrite",
		withSearch("nonexistent", "9.9.9"),
		withName("whatever"))

	_, err := NewSpdx3EditDoc(doc, cfg)
	if err == nil {
		t.Fatal("expected error when component not found, got nil")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Supplier Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx3Doc_OverwriteSupplier_PreservesAuthor(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocWithSupplierOrgAcmeAndAuthorAlice)

	cfg := newConfig(t, "document", "overwrite", withSupplier("NewCorp (newcorp.com)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	if len(doc.SpdxDocument.CreationInfo.CreatedBy) != 2 {
		t.Fatalf("expected 2 CreatedBy entries (author + new supplier), got %d",
			len(doc.SpdxDocument.CreationInfo.CreatedBy))
	}

	// Alice (Person) should still be referenced
	assertAgentInCreatedBy(t, &doc.SpdxDocument.CreationInfo, "https://example.org/person1")

	// Verify NewCorp was added as an Organization
	foundNewCorp := false
	for _, org := range doc.Organizations {
		if org.Name == "NewCorp" {
			foundNewCorp = true
			assertAgentInCreatedBy(t, &doc.SpdxDocument.CreationInfo, org.SpdxID)
			break
		}
	}
	if !foundNewCorp {
		t.Fatal("expected NewCorp to be added to Organizations")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tool Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx3Doc_AppendTool_AddsNewTool(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "document", "append", withTool("syft (v1.0.0)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have 2 Tools: syft + sbomasm (auto-injected)
	if len(doc.Tools) != 2 {
		t.Fatalf("expected 2 Tools (syft + sbomasm), got %d", len(doc.Tools))
	}

	// createdUsing should reference both
	if len(doc.SpdxDocument.CreationInfo.CreatedUsing) != 2 {
		t.Fatalf("expected 2 CreatedUsing entries, got %d", len(doc.SpdxDocument.CreationInfo.CreatedUsing))
	}
}

func TestSpdx3Doc_OverwriteTool_ReplacesExisting(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	// First add a tool
	cfg1 := newConfig(t, "document", "append", withTool("oldtool (v1.0)"))
	editor1, _ := NewSpdx3EditDoc(doc, cfg1)
	editor1.update()

	// Now overwrite with a new tool
	cfg2 := newConfig(t, "document", "overwrite", withTool("newtool (v2.0)"))
	editor2, err := NewSpdx3EditDoc(doc, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// Tools slice accumulates; overwrite only replaces CreatedUsing references.
	// After two updates: oldtool + sbomasm + newtool = 3 (sbomasm deduped, oldtool stays)
	if len(doc.Tools) != 3 {
		t.Fatalf("expected 3 Tools (oldtool + sbomasm + newtool), got %d", len(doc.Tools))
	}

	// Verify oldtool still exists in document
	foundOldtool := false
	for _, tool := range doc.Tools {
		if tool.Name == "oldtool (v1.0)" {
			foundOldtool = true
			break
		}
	}
	if !foundOldtool {
		t.Fatal("expected oldtool to still exist in Tools")
	}

	// Verify newtool exists
	foundNewtool := false
	for _, tool := range doc.Tools {
		if tool.Name == "newtool (v2.0)" {
			foundNewtool = true
			break
		}
	}
	if !foundNewtool {
		t.Fatal("expected newtool to be in Tools")
	}

	// CreatedUsing should be [newtool, sbomasm] (overwrite replaced references)
	if len(doc.SpdxDocument.CreationInfo.CreatedUsing) != 2 {
		t.Fatalf("expected 2 CreatedUsing entries, got %d", len(doc.SpdxDocument.CreationInfo.CreatedUsing))
	}
}

func TestSpdx3Doc_MissingTool_SkipsIfPresent(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	// First add a tool
	cfg1 := newConfig(t, "document", "append", withTool("existing (v1.0)"))
	editor1, _ := NewSpdx3EditDoc(doc, cfg1)
	editor1.update()

	// Now try missing mode — should skip since tool exists
	cfg2 := newConfig(t, "document", "missing", withTool("newtool (v2.0)"))
	editor2, err := NewSpdx3EditDoc(doc, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// Tools: existing + sbomasm (from first update) + sbomasm (from second update, deduped)
	// Actually sbomasm is deduped by mergeTools, so still just [existing, sbomasm]
	if len(doc.Tools) != 2 {
		t.Fatalf("expected 2 Tools (missing mode should skip), got %d", len(doc.Tools))
	}

	// CreatedUsing should still be [existing, sbomasm] — newtool skipped
	if len(doc.SpdxDocument.CreationInfo.CreatedUsing) != 2 {
		t.Fatalf("expected 2 CreatedUsing entries, got %d", len(doc.SpdxDocument.CreationInfo.CreatedUsing))
	}
}

func TestSpdx3Doc_MissingTool_AddsIfEmpty(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "document", "missing", withTool("newtool (v1.0)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have 2 Tools: newtool + sbomasm
	if len(doc.Tools) != 2 {
		t.Fatalf("expected 2 Tools added by missing mode, got %d", len(doc.Tools))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Supplier Tests (Complete)
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx3Doc_AppendSupplier_AddsNewOrgPreservesAuthor(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocWithSupplierOrgAcmeAndAuthorAlice)

	cfg := newConfig(t, "document", "append", withSupplier("BetaCorp (betacorp.com)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// CreatedBy should have 3 entries: ACME + Alice + BetaCorp
	if len(doc.SpdxDocument.CreationInfo.CreatedBy) != 3 {
		t.Fatalf("expected 3 CreatedBy entries, got %d",
			len(doc.SpdxDocument.CreationInfo.CreatedBy))
	}

	// Alice (Person) should still be there
	assertAgentInCreatedBy(t, &doc.SpdxDocument.CreationInfo, "https://example.org/person1")

	// ACME should still be there
	assertAgentInCreatedBy(t, &doc.SpdxDocument.CreationInfo, "https://example.org/org-acme")
}

func TestSpdx3Doc_MissingSupplier_SkipsIfPresent(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocWithSupplierOrgAcmeAndAuthorAlice)

	cfg := newConfig(t, "document", "missing", withSupplier("BetaCorp (betacorp.com)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// CreatedBy should still be 2 (ACME + Alice) — BetaCorp skipped
	if len(doc.SpdxDocument.CreationInfo.CreatedBy) != 2 {
		t.Fatalf("expected 2 CreatedBy entries (missing should skip), got %d",
			len(doc.SpdxDocument.CreationInfo.CreatedBy))
	}
}

func TestSpdx3Doc_MissingSupplier_AddsIfEmpty(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "document", "missing", withSupplier("ACME (acme.com)"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// CreatedBy should have 1 entry (the new supplier)
	if len(doc.SpdxDocument.CreationInfo.CreatedBy) != 1 {
		t.Fatalf("expected 1 CreatedBy entry, got %d",
			len(doc.SpdxDocument.CreationInfo.CreatedBy))
	}

	// Verify ACME was added
	foundAcme := false
	for _, org := range doc.Organizations {
		if org.Name == "ACME" {
			foundAcme = true
			break
		}
	}
	if !foundAcme {
		t.Fatal("expected ACME to be added to Organizations")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Purl Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx3PC_AppendPurl_AddsNewIdentifierPreservesExisting(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "primary-component", "append", withPurl("pkg:golang/app@v1.0.0"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have 1 externalIdentifier
	pkg := doc.Packages[0]
	if len(pkg.ExternalIdentifier) != 1 {
		t.Fatalf("expected 1 externalIdentifier, got %d", len(pkg.ExternalIdentifier))
	}

	// Verify it's a packageUrl type
	assertHasExternalIdentifier(t, &pkg.Element, "packageUrl", "pkg:golang/app@v1.0.0")
}

func TestSpdx3PC_AppendPurl_DedupByValue(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	// First add a purl
	cfg1 := newConfig(t, "primary-component", "append", withPurl("pkg:golang/app@v1.0.0"))
	editor1, _ := NewSpdx3EditDoc(doc, cfg1)
	editor1.update()

	// Try adding the same purl again
	cfg2 := newConfig(t, "primary-component", "append", withPurl("pkg:golang/app@v1.0.0"))
	editor2, err := NewSpdx3EditDoc(doc, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// Should still be 1 externalIdentifier (dedup)
	pkg := doc.Packages[0]
	if len(pkg.ExternalIdentifier) != 1 {
		t.Fatalf("expected 1 externalIdentifier after dedup, got %d", len(pkg.ExternalIdentifier))
	}
}

func TestSpdx3PC_OverwritePurl_ReplacesExisting(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	// First add a purl
	cfg1 := newConfig(t, "primary-component", "append", withPurl("pkg:golang/old@v1.0.0"))
	editor1, _ := NewSpdx3EditDoc(doc, cfg1)
	editor1.update()

	// Now overwrite
	cfg2 := newConfig(t, "primary-component", "overwrite", withPurl("pkg:golang/new@v2.0.0"))
	editor2, err := NewSpdx3EditDoc(doc, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// Should have exactly 1 externalIdentifier with new value
	pkg := doc.Packages[0]
	if len(pkg.ExternalIdentifier) != 1 {
		t.Fatalf("expected 1 externalIdentifier, got %d", len(pkg.ExternalIdentifier))
	}
	if pkg.ExternalIdentifier[0].Identifier != "pkg:golang/new@v2.0.0" {
		t.Fatalf("expected new purl, got %q", pkg.ExternalIdentifier[0].Identifier)
	}
}

func TestSpdx3PC_MissingPurl_SkipsIfPresent(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	// First add a purl
	cfg1 := newConfig(t, "primary-component", "append", withPurl("pkg:golang/app@v1.0.0"))
	editor1, _ := NewSpdx3EditDoc(doc, cfg1)
	editor1.update()

	// Now try missing mode
	cfg2 := newConfig(t, "primary-component", "missing", withPurl("pkg:golang/new@v2.0.0"))
	editor2, err := NewSpdx3EditDoc(doc, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// Should still be the original purl
	pkg := doc.Packages[0]
	if len(pkg.ExternalIdentifier) != 1 {
		t.Fatalf("expected 1 externalIdentifier (missing should skip), got %d", len(pkg.ExternalIdentifier))
	}
	if pkg.ExternalIdentifier[0].Identifier != "pkg:golang/app@v1.0.0" {
		t.Fatalf("expected original purl, got %q", pkg.ExternalIdentifier[0].Identifier)
	}
}

func TestSpdx3PC_MissingPurl_AddsIfEmpty(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "primary-component", "missing", withPurl("pkg:golang/app@v1.0.0"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have 1 externalIdentifier
	pkg := doc.Packages[0]
	if len(pkg.ExternalIdentifier) != 1 {
		t.Fatalf("expected 1 externalIdentifier, got %d", len(pkg.ExternalIdentifier))
	}
}

func TestSpdx3CNV_OverwritePurl_IsolatesTargetComponent(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocWithTwoPackagesNamedAppAndLib)

	cfg := newConfig(t, "component-name-version", "overwrite",
		withSearch("app", "1.0.0"),
		withPurl("pkg:golang/app@v1.0.0"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// App should have the purl
	appPkg := doc.Packages[0]
	if len(appPkg.ExternalIdentifier) != 1 {
		t.Fatalf("expected app to have 1 externalIdentifier, got %d", len(appPkg.ExternalIdentifier))
	}

	// Lib should have no purl
	libPkg := doc.Packages[1]
	if len(libPkg.ExternalIdentifier) != 0 {
		t.Fatalf("expected lib to have 0 externalIdentifiers, got %d", len(libPkg.ExternalIdentifier))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Append Warning Tests (Single-Value Fields)
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx3Doc_AppendName_WarnsAndSkips(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "primary-component", "append", withName("newname"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}

	stderr := captureStderr(func() { editor.update() })

	// Should warn about append on single-value field
	assertWarningContains(t, stderr, "name")

	// Name should NOT have changed
	if doc.Packages[0].Name != "app" {
		t.Fatalf("expected name to remain 'app', got %q", doc.Packages[0].Name)
	}
}

func TestSpdx3Doc_AppendVersion_WarnsAndSkips(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "primary-component", "append", withVersion("9.9.9"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}

	stderr := captureStderr(func() { editor.update() })

	assertWarningContains(t, stderr, "version")
}

func TestSpdx3Doc_AppendLicense_WarnsAndSkips(t *testing.T) {
	doc := parseSpdx3FromBytes(t, sbomSpdx3DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "document", "append", withLicense("MIT"))

	editor, err := NewSpdx3EditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}

	stderr := captureStderr(func() { editor.update() })

	assertWarningContains(t, stderr, "license")
}
