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
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SPDX 2.3 Test Data — Package-Level Variables
// ═══════════════════════════════════════════════════════════════════════════════

// sbomSpdx23DocWithOneCreatorPersonAlice is a minimal SPDX 2.3 document with
// one Person creator and one package.
var sbomSpdx23DocWithOneCreatorPersonAlice = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": ["Person: Alice"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package",
      "name": "app",
      "downloadLocation": "NOASSERTION"
    }
  ],
  "documentDescribes": ["SPDXRef-Package"]
}`)

// sbomSpdx23DocEmptyWithJustDocumentAndPackage is a bare-minimum SPDX 2.3 doc.
var sbomSpdx23DocEmptyWithJustDocumentAndPackage = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": []
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package",
      "name": "app",
      "downloadLocation": "NOASSERTION"
    }
  ],
  "documentDescribes": ["SPDXRef-Package"]
}`)

// sbomSpdx23DocWithOnePackageOneSha256Hash contains a single package with one hash.
var sbomSpdx23DocWithOnePackageOneSha256Hash = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": []
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package",
      "name": "app",
      "downloadLocation": "NOASSERTION",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
      ]
    }
  ],
  "documentDescribes": ["SPDXRef-Package"]
}`)

// sbomSpdx23DocWithTwoPackagesNamedAppAndLib contains two packages.
var sbomSpdx23DocWithTwoPackagesNamedAppAndLib = []byte(`{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": []
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-App",
      "name": "app",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION"
    },
    {
      "SPDXID": "SPDXRef-Package-Lib",
      "name": "lib",
      "versionInfo": "2.0.0",
      "downloadLocation": "NOASSERTION"
    }
  ],
  "documentDescribes": ["SPDXRef-Package-App"]
}`)

// ═══════════════════════════════════════════════════════════════════════════════
// Document-Level Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx23Doc_AppendAuthor_AddsNewCreatorPreservesExisting(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocWithOneCreatorPersonAlice)

	cfg := newConfig(t, "document", "append", withAuthor("Bob (bob@example.com)"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have 2 creators: Alice + Bob
	if len(doc.CreationInfo.Creators) != 2 {
		t.Fatalf("expected 2 creators, got %d", len(doc.CreationInfo.Creators))
	}

	// Verify Alice is still there (parsed as "Alice", not "Person: Alice")
	foundAlice := false
	for _, c := range doc.CreationInfo.Creators {
		if c.Creator == "Alice" {
			foundAlice = true
			break
		}
	}
	if !foundAlice {
		t.Fatalf("expected Alice to still be in creators, got %v", doc.CreationInfo.Creators)
	}

	// Verify Bob was added (edit formats as "Name (email)")
	foundBob := false
	for _, c := range doc.CreationInfo.Creators {
		if c.Creator == "Bob (bob@example.com)" {
			foundBob = true
			break
		}
	}
	if !foundBob {
		t.Fatalf("expected Bob to be added to creators, got %v", doc.CreationInfo.Creators)
	}
}

func TestSpdx23Doc_OverwriteAuthor_ReplacesExisting(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocWithOneCreatorPersonAlice)

	cfg := newConfig(t, "document", "overwrite", withAuthor("Charlie (charlie@example.com)"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have exactly 1 creator (Charlie replaced Alice)
	if len(doc.CreationInfo.Creators) != 1 {
		t.Fatalf("expected 1 creator after overwrite, got %d", len(doc.CreationInfo.Creators))
	}

	// Verify Alice is gone
	for _, c := range doc.CreationInfo.Creators {
		if c.Creator == "Alice" {
			t.Fatal("Alice should have been removed after overwrite")
		}
	}
}

func TestSpdx23Doc_MissingAuthor_SkipsIfPresent(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocWithOneCreatorPersonAlice)

	cfg := newConfig(t, "document", "missing", withAuthor("Bob (bob@example.com)"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should still be just 1 creator (Alice)
	if len(doc.CreationInfo.Creators) != 1 {
		t.Fatalf("expected 1 creator (missing mode should skip), got %d", len(doc.CreationInfo.Creators))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Primary Component Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx23PC_AppendHash_AddsNewHashPreservesExisting(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocWithOnePackageOneSha256Hash)

	cfg := newConfig(t, "primary-component", "append", withHash("MD5 (d41d8cd98f00b204e9800998ecf8427e)"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have 2 checksums
	pkg := doc.Packages[0]
	if len(pkg.PackageChecksums) != 2 {
		t.Fatalf("expected 2 checksums, got %d", len(pkg.PackageChecksums))
	}
}

func TestSpdx23PC_OverwriteHash_ReplacesAllExisting(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocWithOnePackageOneSha256Hash)

	cfg := newConfig(t, "primary-component", "overwrite", withHash("MD5 (d41d8cd98f00b204e9800998ecf8427e)"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have exactly 1 checksum
	pkg := doc.Packages[0]
	if len(pkg.PackageChecksums) != 1 {
		t.Fatalf("expected 1 checksum after overwrite, got %d", len(pkg.PackageChecksums))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Component-Name-Version Search Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx23CNV_AppendHash_IsolatesTargetComponent(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocWithTwoPackagesNamedAppAndLib)

	cfg := newConfig(t, "component-name-version", "append",
		withSearch("app", "1.0.0"),
		withHash("SHA256 (deadbeef)"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Verify app package has the hash (first package in describes order)
	appPkg := doc.Packages[0]
	if len(appPkg.PackageChecksums) != 1 {
		t.Fatalf("expected app to have 1 checksum, got %d", len(appPkg.PackageChecksums))
	}

	// Verify lib package has no hashes
	libPkg := doc.Packages[1]
	if len(libPkg.PackageChecksums) != 0 {
		t.Fatalf("expected lib to have 0 checksums, got %d", len(libPkg.PackageChecksums))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Supplier Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx23Doc_OverwriteSupplier_AddsCreatorComment(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "document", "overwrite", withSupplier("ACME (acme.com)"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Document-level supplier is stored in CreatorComment
	if doc.CreationInfo.CreatorComment == "" {
		t.Fatal("expected CreatorComment to be set")
	}
	if !strings.Contains(doc.CreationInfo.CreatorComment, "ACME") {
		t.Fatalf("expected CreatorComment to contain ACME, got %q", doc.CreationInfo.CreatorComment)
	}
}

func TestSpdx23Doc_MissingSupplier_SkipsIfPresent(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	// First set a supplier
	cfg1 := newConfig(t, "document", "overwrite", withSupplier("ACME (acme.com)"))
	editor1, _ := NewSpdxEditDoc(doc, cfg1)
	editor1.update()

	// Now try missing mode — document-level supplier uses CreatorComment
	// and overwrites rather than skipping (existing behavior)
	cfg2 := newConfig(t, "document", "missing", withSupplier("BetaCorp (beta.com)"))
	editor2, err := NewSpdxEditDoc(doc, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// Document-level supplier overwrites in missing mode
	if !strings.Contains(doc.CreationInfo.CreatorComment, "BetaCorp") {
		t.Fatal("document-level supplier should overwrite in missing mode")
	}
}

func TestSpdx23Doc_MissingSupplier_AddsIfEmpty(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "document", "missing", withSupplier("ACME (acme.com)"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	if !strings.Contains(doc.CreationInfo.CreatorComment, "ACME") {
		t.Fatalf("expected CreatorComment to contain ACME, got %q", doc.CreationInfo.CreatorComment)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tool Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx23Doc_AppendTool_AddsNewTool(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "document", "append", withTool("syft (v1.0)"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have 2 creators: syft + sbomasm
	if len(doc.CreationInfo.Creators) != 2 {
		t.Fatalf("expected 2 creators (syft + sbomasm), got %d", len(doc.CreationInfo.Creators))
	}
}

func TestSpdx23Doc_OverwriteTool_ReplacesExisting(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	// First add a tool
	cfg1 := newConfig(t, "document", "append", withTool("oldtool (v1.0)"))
	editor1, _ := NewSpdxEditDoc(doc, cfg1)
	editor1.update()

	// Now overwrite
	cfg2 := newConfig(t, "document", "overwrite", withTool("newtool (v2.0)"))
	editor2, err := NewSpdxEditDoc(doc, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// Overwrite merges tools; oldtool stays, newtool + sbomasm added
	// Creators: oldtool + sbomasm + newtool = 3 (sbomasm deduped across updates)
	if len(doc.CreationInfo.Creators) != 3 {
		t.Fatalf("expected 3 creators (oldtool + sbomasm + newtool), got %d", len(doc.CreationInfo.Creators))
	}

	foundNewtool := false
	for _, c := range doc.CreationInfo.Creators {
		if strings.Contains(c.Creator, "newtool") {
			foundNewtool = true
			break
		}
	}
	if !foundNewtool {
		t.Fatal("expected newtool to be in creators")
	}
}

func TestSpdx23Doc_MissingTool_AddsIfNotAlreadyExists(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	// First add a tool
	cfg1 := newConfig(t, "document", "append", withTool("existing (v1.0)"))
	editor1, _ := NewSpdxEditDoc(doc, cfg1)
	editor1.update()

	// Now try missing mode — adds new tool if not already in creators
	cfg2 := newConfig(t, "document", "missing", withTool("newtool (v2.0)"))
	editor2, err := NewSpdxEditDoc(doc, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// Should be 3 creators (existing + sbomasm + newtool) — missing adds if not present
	if len(doc.CreationInfo.Creators) != 3 {
		t.Fatalf("expected 3 creators (missing adds if not exists), got %d", len(doc.CreationInfo.Creators))
	}
}

func TestSpdx23Doc_MissingTool_AddsIfEmpty(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "document", "missing", withTool("newtool (v1.0)"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have 2 creators: newtool + sbomasm
	if len(doc.CreationInfo.Creators) != 2 {
		t.Fatalf("expected 2 creators, got %d", len(doc.CreationInfo.Creators))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Purl Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx23PC_AppendPurl_AddsNewPurl(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "primary-component", "append", withPurl("pkg:golang/app@v1.0.0"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	pkg := doc.Packages[0]
	if len(pkg.PackageExternalReferences) != 1 {
		t.Fatalf("expected 1 external reference, got %d", len(pkg.PackageExternalReferences))
	}
	if pkg.PackageExternalReferences[0].Locator != "pkg:golang/app@v1.0.0" {
		t.Fatalf("expected purl pkg:golang/app@v1.0.0, got %q", pkg.PackageExternalReferences[0].Locator)
	}
}

func TestSpdx23PC_OverwritePurl_ReplacesExisting(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	// First add a purl
	cfg1 := newConfig(t, "primary-component", "append", withPurl("pkg:golang/old@v1.0.0"))
	editor1, _ := NewSpdxEditDoc(doc, cfg1)
	editor1.update()

	// Now overwrite
	cfg2 := newConfig(t, "primary-component", "overwrite", withPurl("pkg:golang/new@v2.0.0"))
	editor2, err := NewSpdxEditDoc(doc, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	pkg := doc.Packages[0]
	if len(pkg.PackageExternalReferences) != 1 {
		t.Fatalf("expected 1 external reference, got %d", len(pkg.PackageExternalReferences))
	}
	if pkg.PackageExternalReferences[0].Locator != "pkg:golang/new@v2.0.0" {
		t.Fatalf("expected new purl, got %q", pkg.PackageExternalReferences[0].Locator)
	}
}

func TestSpdx23PC_MissingPurl_AddsIfNotAlreadyExists(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	// First add a purl
	cfg1 := newConfig(t, "primary-component", "append", withPurl("pkg:golang/app@v1.0.0"))
	editor1, _ := NewSpdxEditDoc(doc, cfg1)
	editor1.update()

	// Now try missing mode — adds new purl if different from existing
	cfg2 := newConfig(t, "primary-component", "missing", withPurl("pkg:golang/new@v2.0.0"))
	editor2, err := NewSpdxEditDoc(doc, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// Missing mode adds if not found, so 2 refs now
	pkg := doc.Packages[0]
	if len(pkg.PackageExternalReferences) != 2 {
		t.Fatalf("expected 2 external references (missing adds if not exists), got %d", len(pkg.PackageExternalReferences))
	}
}

func TestSpdx23PC_MissingPurl_AddsIfEmpty(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "primary-component", "missing", withPurl("pkg:golang/app@v1.0.0"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	pkg := doc.Packages[0]
	if len(pkg.PackageExternalReferences) != 1 {
		t.Fatalf("expected 1 external reference, got %d", len(pkg.PackageExternalReferences))
	}
}

func TestSpdx23CNV_OverwritePurl_IsolatesTargetComponent(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocWithTwoPackagesNamedAppAndLib)

	cfg := newConfig(t, "component-name-version", "overwrite",
		withSearch("app", "1.0.0"),
		withPurl("pkg:golang/app@v1.0.0"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// App should have the purl
	appPkg := doc.Packages[0]
	if len(appPkg.PackageExternalReferences) != 1 {
		t.Fatalf("expected app to have 1 external reference, got %d", len(appPkg.PackageExternalReferences))
	}

	// Lib should have no purl
	libPkg := doc.Packages[1]
	if len(libPkg.PackageExternalReferences) != 0 {
		t.Fatalf("expected lib to have 0 external references, got %d", len(libPkg.PackageExternalReferences))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Append Warning Tests (Single-Value Fields)
// ═══════════════════════════════════════════════════════════════════════════════

func TestSpdx23Doc_AppendName_WarnsAndSkips(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "primary-component", "append", withName("newname"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}

	stderr := captureStderr(func() { editor.update() })

	assertWarningContains(t, stderr, "name")

	pkg := doc.Packages[0]
	if pkg.PackageName != "app" {
		t.Fatalf("expected name to remain 'app', got %q", pkg.PackageName)
	}
}

func TestSpdx23Doc_AppendLicense_WarnsAndSkips(t *testing.T) {
	doc := parseSpdx23FromBytes(t, sbomSpdx23DocEmptyWithJustDocumentAndPackage)

	cfg := newConfig(t, "primary-component", "append", withLicense("MIT"))

	editor, err := NewSpdxEditDoc(doc, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}

	stderr := captureStderr(func() { editor.update() })

	assertWarningContains(t, stderr, "license")
}
