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
)

// ═══════════════════════════════════════════════════════════════════════════════
// CycloneDX Test Data — Package-Level Variables
// ═══════════════════════════════════════════════════════════════════════════════

// sbomCdxBomWithOneAuthorAlice is a minimal CycloneDX BOM with one author.
var sbomCdxBomWithOneAuthorAlice = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": [
      {
        "name": "Alice",
        "email": "alice@example.com"
      }
    ]
  },
  "components": [
    {
      "type": "application",
      "name": "app",
      "version": "1.0.0"
    }
  ]
}`)

// sbomCdxBomEmptyWithJustOneComponent is a bare-minimum CycloneDX BOM.
var sbomCdxBomEmptyWithJustOneComponent = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "app",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "application",
      "name": "app",
      "version": "1.0.0"
    }
  ]
}`)

// sbomCdxBomWithOneComponentOneSha256Hash contains a component with one hash.
var sbomCdxBomWithOneComponentOneSha256Hash = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "app",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
      ]
    }
  },
  "components": [
    {
      "type": "application",
      "name": "app",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
      ]
    }
  ]
}`)

// sbomCdxBomWithTwoComponentsNamedAppAndLib contains two components.
var sbomCdxBomWithTwoComponentsNamedAppAndLib = []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "app",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "application",
      "name": "app",
      "version": "1.0.0"
    },
    {
      "type": "library",
      "name": "lib",
      "version": "2.0.0"
    }
  ]
}`)

// ═══════════════════════════════════════════════════════════════════════════════
// Document-Level Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestCdxDoc_AppendAuthor_AddsNewAuthorPreservesExisting(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomWithOneAuthorAlice)

	cfg := newConfig(t, "document", "append", withAuthor("Bob (bob@example.com)"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have 2 authors
	if len(*bom.Metadata.Authors) != 2 {
		t.Fatalf("expected 2 authors, got %d", len(*bom.Metadata.Authors))
	}

	// Verify Alice is still there
	foundAlice := false
	for _, a := range *bom.Metadata.Authors {
		if a.Name == "Alice" {
			foundAlice = true
			break
		}
	}
	if !foundAlice {
		t.Fatal("expected Alice to still be in authors")
	}

	// Verify Bob was added
	foundBob := false
	for _, a := range *bom.Metadata.Authors {
		if a.Name == "Bob" {
			foundBob = true
			break
		}
	}
	if !foundBob {
		t.Fatal("expected Bob to be added to authors")
	}
}

func TestCdxDoc_OverwriteAuthor_ReplacesExisting(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomWithOneAuthorAlice)

	cfg := newConfig(t, "document", "overwrite", withAuthor("Charlie (charlie@example.com)"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have exactly 1 author (Charlie replaced Alice)
	if len(*bom.Metadata.Authors) != 1 {
		t.Fatalf("expected 1 author after overwrite, got %d", len(*bom.Metadata.Authors))
	}

	// Verify Alice is gone
	for _, a := range *bom.Metadata.Authors {
		if a.Name == "Alice" {
			t.Fatal("Alice should have been removed after overwrite")
		}
	}
}

func TestCdxDoc_MissingAuthor_SkipsIfPresent(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomWithOneAuthorAlice)

	cfg := newConfig(t, "document", "missing", withAuthor("Bob (bob@example.com)"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should still be just 1 author (Alice)
	if len(*bom.Metadata.Authors) != 1 {
		t.Fatalf("expected 1 author (missing mode should skip), got %d", len(*bom.Metadata.Authors))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Primary Component Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestCdxPC_AppendHash_AddsNewHashPreservesExisting(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomWithOneComponentOneSha256Hash)

	cfg := newConfig(t, "primary-component", "append", withHash("MD5 (d41d8cd98f00b204e9800998ecf8427e)"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Primary component edit mutates metadata.component, not components[0]
	comp := bom.Metadata.Component
	if len(*comp.Hashes) != 2 {
		t.Fatalf("expected 2 hashes on metadata.component, got %d", len(*comp.Hashes))
	}
}

func TestCdxPC_OverwriteHash_ReplacesAllExisting(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomWithOneComponentOneSha256Hash)

	cfg := newConfig(t, "primary-component", "overwrite", withHash("MD5 (d41d8cd98f00b204e9800998ecf8427e)"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Primary component edit mutates metadata.component
	comp := bom.Metadata.Component
	if len(*comp.Hashes) != 1 {
		t.Fatalf("expected 1 hash after overwrite, got %d", len(*comp.Hashes))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Component-Name-Version Search Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestCdxCNV_AppendHash_IsolatesTargetComponent(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomWithTwoComponentsNamedAppAndLib)

	cfg := newConfig(t, "component-name-version", "append",
		withSearch("app", "1.0.0"),
		withHash("SHA256 (deadbeef)"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Verify app component has the hash
	appComp := (*bom.Components)[0]
	if len(*appComp.Hashes) != 1 {
		t.Fatalf("expected app to have 1 hash, got %d", len(*appComp.Hashes))
	}

	// Verify lib component has no hashes
	libComp := (*bom.Components)[1]
	if libComp.Hashes != nil && len(*libComp.Hashes) != 0 {
		t.Fatalf("expected lib to have 0 hashes, got %d", len(*libComp.Hashes))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Supplier Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestCdxDoc_OverwriteSupplier_AddsMetadataSupplier(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	cfg := newConfig(t, "document", "overwrite", withSupplier("ACME (acme.com)"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	if bom.Metadata.Supplier == nil {
		t.Fatal("expected Metadata.Supplier to be set")
	}
	if bom.Metadata.Supplier.Name != "ACME" {
		t.Fatalf("expected supplier name ACME, got %q", bom.Metadata.Supplier.Name)
	}
}

func TestCdxDoc_MissingSupplier_SkipsIfPresent(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	// First set supplier
	cfg1 := newConfig(t, "document", "overwrite", withSupplier("ACME (acme.com)"))
	editor1, _ := NewCdxEditDoc(bom, cfg1)
	editor1.update()

	// Now try missing mode
	cfg2 := newConfig(t, "document", "missing", withSupplier("BetaCorp (beta.com)"))
	editor2, err := NewCdxEditDoc(bom, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// Should still be ACME
	if bom.Metadata.Supplier.Name != "ACME" {
		t.Fatalf("expected ACME to remain, got %q", bom.Metadata.Supplier.Name)
	}
}

func TestCdxDoc_MissingSupplier_AddsIfEmpty(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	cfg := newConfig(t, "document", "missing", withSupplier("ACME (acme.com)"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	if bom.Metadata.Supplier == nil {
		t.Fatal("expected Metadata.Supplier to be set")
	}
	if bom.Metadata.Supplier.Name != "ACME" {
		t.Fatalf("expected supplier name ACME, got %q", bom.Metadata.Supplier.Name)
	}
}

func TestCdxPC_OverwriteSupplier_AddsComponentSupplier(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	cfg := newConfig(t, "primary-component", "overwrite", withSupplier("ACME (acme.com)"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	comp := bom.Metadata.Component
	if comp.Supplier == nil {
		t.Fatal("expected component Supplier to be set")
	}
	if comp.Supplier.Name != "ACME" {
		t.Fatalf("expected supplier name ACME, got %q", comp.Supplier.Name)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tool Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestCdxDoc_AppendTool_AddsNewTool(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	cfg := newConfig(t, "document", "append", withTool("syft (v1.0)"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have 2 tool components: syft + sbomasm
	if bom.Metadata.Tools == nil {
		t.Fatal("expected Metadata.Tools to be set")
	}
	if len(*bom.Metadata.Tools.Components) != 2 {
		t.Fatalf("expected 2 tool components (syft + sbomasm), got %d", len(*bom.Metadata.Tools.Components))
	}
}

func TestCdxDoc_OverwriteTool_ReplacesExisting(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	// First add a tool
	cfg1 := newConfig(t, "document", "append", withTool("oldtool (v1.0)"))
	editor1, _ := NewCdxEditDoc(bom, cfg1)
	editor1.update()

	// Now overwrite
	cfg2 := newConfig(t, "document", "overwrite", withTool("newtool (v2.0)"))
	editor2, err := NewCdxEditDoc(bom, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// Overwrite should replace the user's tools but keep sbomasm
	tools := *bom.Metadata.Tools.Components
	foundNewtool := false
	for _, tc := range tools {
		if tc.Name == "newtool" {
			foundNewtool = true
			break
		}
	}
	if !foundNewtool {
		t.Fatal("expected newtool to be in Tools.Components")
	}
}

func TestCdxDoc_MissingTool_AddsIfNotAlreadyExists(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	// First add a tool
	cfg1 := newConfig(t, "document", "append", withTool("existing (v1.0)"))
	editor1, _ := NewCdxEditDoc(bom, cfg1)
	editor1.update()

	// Now try missing mode — adds newtool if not already present
	cfg2 := newConfig(t, "document", "missing", withTool("newtool (v2.0)"))
	editor2, err := NewCdxEditDoc(bom, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// Should be 3 tool components: existing + sbomasm + newtool
	tools := *bom.Metadata.Tools.Components
	if len(tools) != 3 {
		t.Fatalf("expected 3 tool components (existing + sbomasm + newtool), got %d", len(tools))
	}
}

func TestCdxDoc_MissingTool_AddsIfEmpty(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	cfg := newConfig(t, "document", "missing", withTool("newtool (v1.0)"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// Should have 2 tool components: newtool + sbomasm
	if bom.Metadata.Tools == nil {
		t.Fatal("expected Metadata.Tools to be set")
	}
	if len(*bom.Metadata.Tools.Components) != 2 {
		t.Fatalf("expected 2 tool components (newtool + sbomasm), got %d", len(*bom.Metadata.Tools.Components))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Purl Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestCdxPC_OverwritePurl_ReplacesExisting(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	// First set a purl
	cfg1 := newConfig(t, "primary-component", "overwrite", withPurl("pkg:generic/old@1.0"))
	editor1, _ := NewCdxEditDoc(bom, cfg1)
	editor1.update()

	// Now overwrite
	cfg2 := newConfig(t, "primary-component", "overwrite", withPurl("pkg:generic/new@2.0"))
	editor2, err := NewCdxEditDoc(bom, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	comp := bom.Metadata.Component
	if comp.PackageURL != "pkg:generic/new@2.0" {
		t.Fatalf("expected new purl, got %q", comp.PackageURL)
	}
}

func TestCdxPC_MissingPurl_OverwritesWithNewValue(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	// First set a purl
	cfg1 := newConfig(t, "primary-component", "overwrite", withPurl("pkg:generic/old@1.0"))
	editor1, _ := NewCdxEditDoc(bom, cfg1)
	editor1.update()

	// Now try missing mode — CDX missing purl overwrites with new value
	cfg2 := newConfig(t, "primary-component", "missing", withPurl("pkg:generic/new@2.0"))
	editor2, err := NewCdxEditDoc(bom, cfg2)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor2.update()

	// CDX missing mode overwrites purl (existing behavior)
	comp := bom.Metadata.Component
	if comp.PackageURL != "pkg:generic/new@2.0" {
		t.Fatalf("expected new purl, got %q", comp.PackageURL)
	}
}

func TestCdxPC_MissingPurl_AddsIfEmpty(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	cfg := newConfig(t, "primary-component", "missing", withPurl("pkg:generic/app@1.0"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	comp := bom.Metadata.Component
	if comp.PackageURL != "pkg:generic/app@1.0" {
		t.Fatalf("expected purl to be set, got %q", comp.PackageURL)
	}
}

func TestCdxCNV_OverwritePurl_IsolatesTargetComponent(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomWithTwoComponentsNamedAppAndLib)

	cfg := newConfig(t, "component-name-version", "overwrite",
		withSearch("app", "1.0.0"),
		withPurl("pkg:generic/app@1.0"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}
	editor.update()

	// App should have the purl
	appComp := (*bom.Components)[0]
	if appComp.PackageURL != "pkg:generic/app@1.0" {
		t.Fatalf("expected app purl, got %q", appComp.PackageURL)
	}

	// Lib should have no purl
	libComp := (*bom.Components)[1]
	if libComp.PackageURL != "" {
		t.Fatalf("expected lib to have no purl, got %q", libComp.PackageURL)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Append Warning Tests (Single-Value Fields)
// ═══════════════════════════════════════════════════════════════════════════════

func TestCdxDoc_AppendName_WarnsAndSkips(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	cfg := newConfig(t, "primary-component", "append", withName("newname"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}

	stderr := captureStderr(func() { editor.update() })

	assertWarningContains(t, stderr, "name")

	comp := (*bom.Components)[0]
	if comp.Name != "app" {
		t.Fatalf("expected name to remain 'app', got %q", comp.Name)
	}
}

func TestCdxDoc_AppendPurl_WarnsAndSkips(t *testing.T) {
	bom := parseCdxFromBytes(t, sbomCdxBomEmptyWithJustOneComponent)

	cfg := newConfig(t, "primary-component", "append", withPurl("pkg:generic/new@1.0"))

	editor, err := NewCdxEditDoc(bom, cfg)
	if err != nil {
		t.Fatalf("failed to create editor: %v", err)
	}

	stderr := captureStderr(func() { editor.update() })

	assertWarningContains(t, stderr, "purl")
}
