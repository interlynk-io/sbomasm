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

package spdx3

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Test Helpers
// ═══════════════════════════════════════════════════════════════════════════════

// writeTestDoc writes an SPDX 3.0 JSON-LD document string to a temp file and
// returns the file path.
func writeTestDoc(t *testing.T, data string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "test.spdx3.json")
	if err := os.WriteFile(f, []byte(data), 0644); err != nil {
		t.Fatalf("failed to write test doc: %v", err)
	}
	return f
}

// findPkgByName finds a package by name in the output document.
func findPkgByName(t *testing.T, path string, name string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}

	graph, ok := doc["@graph"].([]interface{})
	if !ok {
		t.Fatal("no @graph in output")
	}

	for _, item := range graph {
		if m, ok := item.(map[string]interface{}); ok {
			if m["type"] == "software_Package" && m["name"] == name {
				return m
			}
		}
	}
	return nil
}

// findRelationshipsByType finds all relationships of a given type from a given source.
func findRelationshipsByType(t *testing.T, path string, fromType string, fromName string, relType string) []map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}

	graph, ok := doc["@graph"].([]interface{})
	if !ok {
		t.Fatal("no @graph in output")
	}

	// Find source ID
	var fromID string
	for _, item := range graph {
		if m, ok := item.(map[string]interface{}); ok {
			if m["type"] == fromType && m["name"] == fromName {
				fromID = m["spdxId"].(string)
				break
			}
		}
	}

	var results []map[string]interface{}
	for _, item := range graph {
		if m, ok := item.(map[string]interface{}); ok {
			if m["type"] == "Relationship" {
				if m["relationshipType"] == relType {
					if from, ok := m["from"].(string); ok && from == fromID {
						results = append(results, m)
					}
				}
			}
		}
	}
	return results
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test Data — Inline JSON Fixtures
// ═══════════════════════════════════════════════════════════════════════════════

// docFrontendReact is an SPDX 3.0 SBOM with Frontend as primary and React as child.
var docFrontendReact = []byte(`{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "https://example.org/doc1",
      "name": "doc1",
      "creationInfo": "_:creationinfo1",
      "rootElement": ["https://example.org/pkg/frontend"]
    },
    {
      "type": "CreationInfo",
      "spdxId": "_:creationinfo1",
      "specVersion": "3.0.1",
      "created": "2025-01-01T00:00:00Z",
      "createdBy": [{"type": "Tool", "spdxId": "https://interlynk.io/tool/test", "name": "test"}]
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg/frontend",
      "name": "Frontend",
      "software_packageVersion": "1.0.0",
      "creationInfo": "_:creationinfo1"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg/react",
      "name": "React",
      "software_packageVersion": "18.0.0",
      "creationInfo": "_:creationinfo1"
    },
    {
      "type": "Relationship",
      "spdxId": "https://example.org/rel/describes-frontend",
      "from": "https://example.org/doc1",
      "relationshipType": "describes",
      "to": ["https://example.org/pkg/frontend"],
      "creationInfo": "_:creationinfo1"
    },
    {
      "type": "Relationship",
      "spdxId": "https://example.org/rel/dependsOn-frontend-react",
      "from": "https://example.org/pkg/frontend",
      "relationshipType": "dependsOn",
      "to": ["https://example.org/pkg/react"],
      "creationInfo": "_:creationinfo1"
    }
  ]
}`)

// docBackendExpress is an SPDX 3.0 SBOM with Backend as primary and Express as child.
var docBackendExpress = []byte(`{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "https://example.org/doc2",
      "name": "doc2",
      "creationInfo": "_:creationinfo2",
      "rootElement": ["https://example.org/pkg/backend"]
    },
    {
      "type": "CreationInfo",
      "spdxId": "_:creationinfo2",
      "specVersion": "3.0.1",
      "created": "2025-01-01T00:00:00Z",
      "createdBy": [{"type": "Tool", "spdxId": "https://interlynk.io/tool/test2", "name": "test2"}]
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg/backend",
      "name": "Backend",
      "software_packageVersion": "1.0.0",
      "creationInfo": "_:creationinfo2"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg/express",
      "name": "Express",
      "software_packageVersion": "4.0.0",
      "creationInfo": "_:creationinfo2"
    },
    {
      "type": "Relationship",
      "spdxId": "https://example.org/rel/describes-backend",
      "from": "https://example.org/doc2",
      "relationshipType": "describes",
      "to": ["https://example.org/pkg/backend"],
      "creationInfo": "_:creationinfo2"
    },
    {
      "type": "Relationship",
      "spdxId": "https://example.org/rel/dependsOn-backend-express",
      "from": "https://example.org/pkg/backend",
      "relationshipType": "dependsOn",
      "to": ["https://example.org/pkg/express"],
      "creationInfo": "_:creationinfo2"
    }
  ]
}`)

// ═══════════════════════════════════════════════════════════════════════════════
// Flat Merge Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestFlatMerge_RootToPrimaryIsDependsOn(t *testing.T) {
	ctx := context.Background()

	file1 := writeTestDoc(t, string(docFrontendReact))
	file2 := writeTestDoc(t, string(docBackendExpress))
	outFile := filepath.Join(t.TempDir(), "out.spdx3.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file1, file2}},
		Output: output{
			FileFormat:  "json",
			Spec:        string(sbom.SBOMSpecSPDX),
			SpecVersion: "3.0.1",
			File:        outFile,
		},
		Assemble: assemble{FlatMerge: true},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Root (MyApp) -> Frontend should be DEPENDS_ON
	rels := findRelationshipsByType(t, outFile, "software_Package", "MyApp", "dependsOn")
	if len(rels) == 0 {
		t.Error("flat merge: expected root DEPENDS_ON to at least one primary")
	}

	// Root should NOT CONTAINS any primary
	containsRels := findRelationshipsByType(t, outFile, "software_Package", "MyApp", "contains")
	if len(containsRels) > 0 {
		t.Error("flat merge: root should not CONTAINS any primary")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hierarchical Merge Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestHierarchicalMerge_RootToPrimaryIsDependsOn(t *testing.T) {
	ctx := context.Background()

	file1 := writeTestDoc(t, string(docFrontendReact))
	file2 := writeTestDoc(t, string(docBackendExpress))
	outFile := filepath.Join(t.TempDir(), "out.spdx3.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file1, file2}},
		Output: output{
			FileFormat:  "json",
			Spec:        string(sbom.SBOMSpecSPDX),
			SpecVersion: "3.0.1",
			File:        outFile,
		},
		Assemble: assemble{},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Root -> Frontend should be DEPENDS_ON
	rels := findRelationshipsByType(t, outFile, "software_Package", "MyApp", "dependsOn")
	if len(rels) == 0 {
		t.Error("hierarchical merge: expected root DEPENDS_ON to at least one primary")
	}

	// Root should NOT CONTAINS any primary
	containsRels := findRelationshipsByType(t, outFile, "software_Package", "MyApp", "contains")
	if len(containsRels) > 0 {
		t.Error("hierarchical merge: root should not CONTAINS any primary")
	}
}

func TestHierarchicalMerge_GeneratesInternalContains(t *testing.T) {
	ctx := context.Background()

	file1 := writeTestDoc(t, string(docFrontendReact))
	outFile := filepath.Join(t.TempDir(), "out.spdx3.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file1}},
		Output: output{
			FileFormat:  "json",
			Spec:        string(sbom.SBOMSpecSPDX),
			SpecVersion: "3.0.1",
			File:        outFile,
		},
		Assemble: assemble{},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Frontend -> React should be CONTAINS (structural nesting)
	rels := findRelationshipsByType(t, outFile, "software_Package", "Frontend", "contains")
	if len(rels) == 0 {
		t.Error("hierarchical merge: expected CONTAINS from primary to child")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Assembly Merge Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestAssemblyMerge_RootToPrimaryIsContains(t *testing.T) {
	ctx := context.Background()

	file1 := writeTestDoc(t, string(docFrontendReact))
	file2 := writeTestDoc(t, string(docBackendExpress))
	outFile := filepath.Join(t.TempDir(), "out.spdx3.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file1, file2}},
		Output: output{
			FileFormat:  "json",
			Spec:        string(sbom.SBOMSpecSPDX),
			SpecVersion: "3.0.1",
			File:        outFile,
		},
		Assemble: assemble{AssemblyMerge: true},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Root -> Frontend should be CONTAINS
	rels := findRelationshipsByType(t, outFile, "software_Package", "MyApp", "contains")
	if len(rels) == 0 {
		t.Error("assembly merge: expected root CONTAINS to at least one primary")
	}

	// Root should NOT DEPENDS_ON any primary
	dependsRels := findRelationshipsByType(t, outFile, "software_Package", "MyApp", "dependsOn")
	if len(dependsRels) > 0 {
		t.Error("assembly merge: root should not DEPENDS_ON any primary")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Flat Merge with Primary Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestFlatMergeWithPrimary_RootIsPrimary(t *testing.T) {
	ctx := context.Background()

	file1 := writeTestDoc(t, string(docFrontendReact))
	file2 := writeTestDoc(t, string(docBackendExpress))
	outFile := filepath.Join(t.TempDir(), "out.spdx3.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file2}},
		Output: output{
			FileFormat:  "json",
			Spec:        string(sbom.SBOMSpecSPDX),
			SpecVersion: "3.0.1",
			File:        outFile,
		},
		Assemble: assemble{
			FlatMerge:              true,
			IsFlatMergeWithPrimary: true,
			PrimaryFile:            file1,
		},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// The root package should be "Frontend" (from primary SBOM), not "MyApp"
	rootPkg := findPkgByName(t, outFile, "Frontend")
	if rootPkg == nil {
		t.Fatal("flat merge with primary: expected root package to be 'Frontend' from primary SBOM")
	}

	// Root (Frontend) should have DEPENDS_ON to Backend
	rels := findRelationshipsByType(t, outFile, "software_Package", "Frontend", "dependsOn")
	foundBackend := false
	for _, rel := range rels {
		if toList, ok := rel["to"].([]interface{}); ok {
			for _, to := range toList {
				if toStr, ok := to.(string); ok {
					backendPkg := findPkgByName(t, outFile, "Backend")
					if backendPkg != nil && toStr == backendPkg["spdxId"] {
						foundBackend = true
					}
				}
			}
		}
	}
	if !foundBackend {
		t.Error("flat merge with primary: expected root (Frontend) to have DEPENDS_ON to Backend")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Assembly Merge with Primary Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestAssemblyMergeWithPrimary_RootIsPrimary(t *testing.T) {
	ctx := context.Background()

	file1 := writeTestDoc(t, string(docFrontendReact))
	file2 := writeTestDoc(t, string(docBackendExpress))
	outFile := filepath.Join(t.TempDir(), "out.spdx3.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file2}},
		Output: output{
			FileFormat:  "json",
			Spec:        string(sbom.SBOMSpecSPDX),
			SpecVersion: "3.0.1",
			File:        outFile,
		},
		Assemble: assemble{
			AssemblyMerge:              true,
			IsAssemblyMergeWithPrimary: true,
			PrimaryFile:                file1,
		},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// The root package should be "Frontend" (from primary SBOM)
	rootPkg := findPkgByName(t, outFile, "Frontend")
	if rootPkg == nil {
		t.Fatal("assembly merge with primary: expected root package to be 'Frontend' from primary SBOM")
	}

	// Root (Frontend) should have CONTAINS to Backend
	rels := findRelationshipsByType(t, outFile, "software_Package", "Frontend", "contains")
	foundBackend := false
	for _, rel := range rels {
		if toList, ok := rel["to"].([]interface{}); ok {
			for _, to := range toList {
				if toStr, ok := to.(string); ok {
					backendPkg := findPkgByName(t, outFile, "Backend")
					if backendPkg != nil && toStr == backendPkg["spdxId"] {
						foundBackend = true
					}
				}
			}
		}
	}
	if !foundBackend {
		t.Error("assembly merge with primary: expected root (Frontend) to have CONTAINS to Backend")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Augment Merge Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestAugmentMerge_MatchedPackageGetsFieldsFilled(t *testing.T) {
	ctx := context.Background()

	// Primary: React with no description
	primaryDoc := `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": [
			{"type": "SpdxDocument", "spdxId": "https://example.org/primary", "name": "primary", "creationInfo": "_:ci", "rootElement": ["https://example.org/pkg/react"]},
			{"type": "CreationInfo", "spdxId": "_:ci", "specVersion": "3.0.1", "created": "2025-01-01T00:00:00Z", "createdBy": [{"type": "Tool", "spdxId": "https://interlynk.io/tool/test", "name": "test"}]},
			{"type": "software_Package", "spdxId": "https://example.org/pkg/react", "name": "React", "software_packageVersion": "18.0.0", "creationInfo": "_:ci"}
		]
	}`

	// Secondary: React with description + new Axios package
	secondaryDoc := `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": [
			{"type": "SpdxDocument", "spdxId": "https://example.org/sec", "name": "secondary", "creationInfo": "_:ci2", "rootElement": ["https://example.org/pkg/react"]},
			{"type": "CreationInfo", "spdxId": "_:ci2", "specVersion": "3.0.1", "created": "2025-01-01T00:00:00Z", "createdBy": [{"type": "Tool", "spdxId": "https://interlynk.io/tool/test2", "name": "test2"}]},
			{"type": "software_Package", "spdxId": "https://example.org/pkg/react", "name": "React", "software_packageVersion": "18.0.0", "description": "A UI library", "creationInfo": "_:ci2"},
			{"type": "software_Package", "spdxId": "https://example.org/pkg/axios", "name": "axios", "software_packageVersion": "1.0.0", "creationInfo": "_:ci2"},
			{"type": "Relationship", "spdxId": "https://example.org/rel/r1", "from": "https://example.org/pkg/react", "relationshipType": "dependsOn", "to": ["https://example.org/pkg/axios"], "creationInfo": "_:ci2"}
		]
	}`

	primaryFile := writeTestDoc(t, primaryDoc)
	secondaryFile := writeTestDoc(t, secondaryDoc)
	outFile := filepath.Join(t.TempDir(), "out.spdx3.json")

	ms := &MergeSettings{
		Ctx:      &ctx,
		App:      app{Name: "MyApp", Version: "1.0.0", PrimaryPurpose: "application"},
		Input:    input{Files: []string{secondaryFile}},
		Output:   output{FileFormat: "json", Spec: string(sbom.SBOMSpecSPDX), SpecVersion: "3.0.1", File: outFile},
		Assemble: assemble{AugmentMerge: true, PrimaryFile: primaryFile},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// React should now have description from secondary
	reactPkg := findPkgByName(t, outFile, "React")
	if reactPkg == nil {
		t.Fatal("React package not found in output")
	}
	if desc, ok := reactPkg["description"].(string); !ok || desc != "A UI library" {
		t.Errorf("React description = %q, want %q", desc, "A UI library")
	}

	// Axios should be added as new
	axiosPkg := findPkgByName(t, outFile, "axios")
	if axiosPkg == nil {
		t.Error("axios package not found in output (should have been added)")
	}

	// React -> axios dependsOn should be preserved
	reactDeps := findRelationshipsByType(t, outFile, "software_Package", "React", "dependsOn")
	foundAxiosDep := false
	for _, rel := range reactDeps {
		if toList, ok := rel["to"].([]interface{}); ok {
			for _, to := range toList {
				if toStr, ok := to.(string); ok {
					if axiosPkg != nil && toStr == axiosPkg["spdxId"] {
						foundAxiosDep = true
					}
				}
			}
		}
	}
	if !foundAxiosDep {
		t.Error("expected React -> axios dependsOn to be preserved")
	}
}

func TestAugmentMerge_OverwriteMode(t *testing.T) {
	ctx := context.Background()

	// Primary: React with existing description
	primaryDoc := `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": [
			{"type": "SpdxDocument", "spdxId": "https://example.org/primary", "name": "primary", "creationInfo": "_:ci", "rootElement": ["https://example.org/pkg/react"]},
			{"type": "CreationInfo", "spdxId": "_:ci", "specVersion": "3.0.1", "created": "2025-01-01T00:00:00Z", "createdBy": [{"type": "Tool", "spdxId": "https://interlynk.io/tool/test", "name": "test"}]},
			{"type": "software_Package", "spdxId": "https://example.org/pkg/react", "name": "React", "software_packageVersion": "18.0.0", "description": "Old description", "creationInfo": "_:ci"}
		]
	}`

	// Secondary: React with new description
	secondaryDoc := `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": [
			{"type": "SpdxDocument", "spdxId": "https://example.org/sec", "name": "secondary", "creationInfo": "_:ci2", "rootElement": ["https://example.org/pkg/react"]},
			{"type": "CreationInfo", "spdxId": "_:ci2", "specVersion": "3.0.1", "created": "2025-01-01T00:00:00Z", "createdBy": [{"type": "Tool", "spdxId": "https://interlynk.io/tool/test2", "name": "test2"}]},
			{"type": "software_Package", "spdxId": "https://example.org/pkg/react", "name": "React", "software_packageVersion": "18.0.0", "description": "New description", "creationInfo": "_:ci2"}
		]
	}`

	primaryFile := writeTestDoc(t, primaryDoc)
	secondaryFile := writeTestDoc(t, secondaryDoc)
	outFile := filepath.Join(t.TempDir(), "out.spdx3.json")

	ms := &MergeSettings{
		Ctx:      &ctx,
		App:      app{Name: "MyApp", Version: "1.0.0", PrimaryPurpose: "application"},
		Input:    input{Files: []string{secondaryFile}},
		Output:   output{FileFormat: "json", Spec: string(sbom.SBOMSpecSPDX), SpecVersion: "3.0.1", File: outFile},
		Assemble: assemble{AugmentMerge: true, PrimaryFile: primaryFile, MergeMode: "overwrite"},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	reactPkg := findPkgByName(t, outFile, "React")
	if reactPkg == nil {
		t.Fatal("React package not found in output")
	}
	if desc, ok := reactPkg["description"].(string); !ok || desc != "New description" {
		t.Errorf("React description = %q, want %q (overwrite mode)", desc, "New description")
	}
}
