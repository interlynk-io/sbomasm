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

package spdx

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// createTestSpdxDoc builds a minimal SPDX document with one primary and two child packages.
func createTestSpdxDoc(name string, ns string, primaryName string, primaryID string, children []struct{ Name, ID string }) *spdx.Document {
	doc := &spdx.Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      name,
		DocumentNamespace: ns,
		CreationInfo: &spdx.CreationInfo{
			Created: "2025-01-01T00:00:00Z",
			Creators: []common.Creator{
				{Creator: "Tool: test", CreatorType: "Tool"},
			},
		},
		Packages: []*spdx.Package{
			{
				PackageName:             primaryName,
				PackageSPDXIdentifier:   common.ElementID(primaryID),
				PackageVersion:          "1.0.0",
				PackageDownloadLocation: "NOASSERTION",
			},
		},
		Relationships: []*spdx.Relationship{
			{
				RefA:         common.MakeDocElementID("", "DOCUMENT"),
				RefB:         common.MakeDocElementID("", primaryID),
				Relationship: common.TypeRelationshipDescribe,
			},
		},
	}

	for _, child := range children {
		doc.Packages = append(doc.Packages, &spdx.Package{
			PackageName:             child.Name,
			PackageSPDXIdentifier:   common.ElementID(child.ID),
			PackageVersion:          "1.0.0",
			PackageDownloadLocation: "NOASSERTION",
		})
	}

	return doc
}

// writeTestDoc writes an SPDX document to a temp file and returns the path.
func writeTestDoc(t *testing.T, doc *spdx.Document) string {
	t.Helper()
	data, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		t.Fatalf("failed to marshal test doc: %v", err)
	}
	f := filepath.Join(t.TempDir(), doc.DocumentName+".spdx.json")
	if err := os.WriteFile(f, data, 0644); err != nil {
		t.Fatalf("failed to write test doc: %v", err)
	}
	return f
}

// loadOutputDoc reads the generated SPDX document from disk.
func loadOutputDoc(t *testing.T, path string) *v2_3.Document {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	var doc v2_3.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to unmarshal output doc: %v", err)
	}
	return &doc
}

// findRelationship searches for a relationship matching the given criteria.
func findRelationship(doc *v2_3.Document, refA string, refB string, relType string) *v2_3.Relationship {
	for _, rel := range doc.Relationships {
		if string(rel.RefA.ElementRefID) == refA && string(rel.RefB.ElementRefID) == refB && rel.Relationship == relType {
			return rel
		}
	}
	return nil
}

// countRelationshipsOfType counts how many relationships of a given type exist from refA to refB.
func countRelationshipsOfType(doc *v2_3.Document, refA string, refB string, relType string) int {
	count := 0
	for _, rel := range doc.Relationships {
		if string(rel.RefA.ElementRefID) == refA && string(rel.RefB.ElementRefID) == refB && rel.Relationship == relType {
			count++
		}
	}
	return count
}

func TestHierarchicalMerge_RootToPrimaryIsDependsOn(t *testing.T) {
	ctx := context.Background()

	// Doc 1: Frontend
	doc1 := createTestSpdxDoc("doc1", "https://example.com/doc1", "Frontend", "SPDXRef-Frontend", []struct{ Name, ID string }{
		{Name: "React", ID: "SPDXRef-React"},
		{Name: "Axios", ID: "SPDXRef-Axios"},
	})

	// Doc 2: Backend
	doc2 := createTestSpdxDoc("doc2", "https://example.com/doc2", "Backend", "SPDXRef-Backend", []struct{ Name, ID string }{
		{Name: "Express", ID: "SPDXRef-Express"},
		{Name: "Mongoose", ID: "SPDXRef-Mongoose"},
	})

	file1 := writeTestDoc(t, doc1)
	file2 := writeTestDoc(t, doc2)
	outFile := filepath.Join(t.TempDir(), "out.spdx.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file1, file2}},
		Output: output{
			FileFormat: "json",
			Spec:       string(sbom.SBOMSpecSPDX),
			File:       outFile,
		},
		Assemble: assemble{},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	outDoc := loadOutputDoc(t, outFile)

	// Find the new root package ID (the generated primary package)
	var rootPkgID string
	for _, rel := range outDoc.Relationships {
		if rel.Relationship == common.TypeRelationshipDescribe && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	if rootPkgID == "" {
		t.Fatal("could not find DESCRIBES relationship for root package")
	}

	// Find remapped IDs for Frontend and Backend
	var frontendID, backendID string
	for _, pkg := range outDoc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "Backend" {
			backendID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if frontendID == "" || backendID == "" {
		t.Fatal("Frontend or Backend package not found in output")
	}

	// Assert root -> Frontend is DEPENDS_ON
	if r := findRelationship(outDoc, rootPkgID, frontendID, "DEPENDS_ON"); r == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s)", rootPkgID, frontendID)
	}

	// Assert root -> Backend is DEPENDS_ON
	if r := findRelationship(outDoc, rootPkgID, backendID, "DEPENDS_ON"); r == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s)", rootPkgID, backendID)
	}

	// Assert root -> Frontend is NOT CONTAINS
	if r := findRelationship(outDoc, rootPkgID, frontendID, "CONTAINS"); r != nil {
		t.Error("hierarchical merge: root should not CONTAINS any primary")
	}
}

func TestHierarchicalMerge_GeneratesInternalContains(t *testing.T) {
	ctx := context.Background()

	// Doc 1: Frontend with NO internal CONTAINS
	doc1 := createTestSpdxDoc("doc1", "https://example.com/doc1", "Frontend", "SPDXRef-Frontend", []struct{ Name, ID string }{
		{Name: "React", ID: "SPDXRef-React"},
	})

	file1 := writeTestDoc(t, doc1)
	outFile := filepath.Join(t.TempDir(), "out.spdx.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file1}},
		Output: output{
			FileFormat: "json",
			Spec:       string(sbom.SBOMSpecSPDX),
			File:       outFile,
		},
		Assemble: assemble{},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	outDoc := loadOutputDoc(t, outFile)

	// Find the remapped Frontend package ID
	var frontendID string
	for _, pkg := range outDoc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
			break
		}
	}
	if frontendID == "" {
		t.Fatal("Frontend package not found in output")
	}

	// Find the remapped React package ID
	var reactID string
	for _, pkg := range outDoc.Packages {
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
			break
		}
	}
	if reactID == "" {
		t.Fatal("React package not found in output")
	}

	// Assert CONTAINS(Frontend -> React) exists
	if r := findRelationship(outDoc, frontendID, reactID, "CONTAINS"); r == nil {
		t.Errorf("expected CONTAINS(%s -> %s) for hierarchical merge", frontendID, reactID)
	}
}

func TestHierarchicalMerge_PreservesExistingDependsOn(t *testing.T) {
	ctx := context.Background()

	// Doc 1: Frontend with existing DEPENDS_ON(Frontend -> React)
	doc1 := createTestSpdxDoc("doc1", "https://example.com/doc1", "Frontend", "SPDXRef-Frontend", []struct{ Name, ID string }{
		{Name: "React", ID: "SPDXRef-React"},
	})
	doc1.Relationships = append(doc1.Relationships, &spdx.Relationship{
		RefA:         common.MakeDocElementID("", "SPDXRef-Frontend"),
		RefB:         common.MakeDocElementID("", "SPDXRef-React"),
		Relationship: common.TypeRelationshipDependsOn,
	})

	file1 := writeTestDoc(t, doc1)
	outFile := filepath.Join(t.TempDir(), "out.spdx.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file1}},
		Output: output{
			FileFormat: "json",
			Spec:       string(sbom.SBOMSpecSPDX),
			File:       outFile,
		},
		Assemble: assemble{},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	outDoc := loadOutputDoc(t, outFile)

	var frontendID, reactID string
	for _, pkg := range outDoc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if frontendID == "" || reactID == "" {
		t.Fatal("Frontend or React package not found")
	}

	// Assert DEPENDS_ON(Frontend -> React) is preserved
	if r := findRelationship(outDoc, frontendID, reactID, "DEPENDS_ON"); r == nil {
		t.Errorf("expected preserved DEPENDS_ON(%s -> %s)", frontendID, reactID)
	}

	// Assert CONTAINS(Frontend -> React) is generated (hierarchy)
	if r := findRelationship(outDoc, frontendID, reactID, "CONTAINS"); r == nil {
		t.Errorf("expected generated CONTAINS(%s -> %s)", frontendID, reactID)
	}
}

func TestHierarchicalMerge_NoDuplicateContains(t *testing.T) {
	ctx := context.Background()

	// Doc 1: Frontend with existing CONTAINS(Frontend -> React)
	doc1 := createTestSpdxDoc("doc1", "https://example.com/doc1", "Frontend", "SPDXRef-Frontend", []struct{ Name, ID string }{
		{Name: "React", ID: "SPDXRef-React"},
	})
	doc1.Relationships = append(doc1.Relationships, &spdx.Relationship{
		RefA:         common.MakeDocElementID("", "SPDXRef-Frontend"),
		RefB:         common.MakeDocElementID("", "SPDXRef-React"),
		Relationship: common.TypeRelationshipContains,
	})

	file1 := writeTestDoc(t, doc1)
	outFile := filepath.Join(t.TempDir(), "out.spdx.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file1}},
		Output: output{
			FileFormat: "json",
			Spec:       string(sbom.SBOMSpecSPDX),
			File:       outFile,
		},
		Assemble: assemble{},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	outDoc := loadOutputDoc(t, outFile)

	var frontendID, reactID string
	for _, pkg := range outDoc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if frontendID == "" || reactID == "" {
		t.Fatal("Frontend or React package not found")
	}

	// Must be exactly ONE CONTAINS(Frontend -> React)
	count := countRelationshipsOfType(outDoc, frontendID, reactID, "CONTAINS")
	if count != 1 {
		t.Errorf("expected exactly 1 CONTAINS(%s -> %s), got %d", frontendID, reactID, count)
	}
}

func TestAssemblyMerge_RootToPrimaryIsContains(t *testing.T) {
	ctx := context.Background()

	doc1 := createTestSpdxDoc("doc1", "https://example.com/doc1", "Frontend", "SPDXRef-Frontend", []struct{ Name, ID string }{
		{Name: "React", ID: "SPDXRef-React"},
	})
	doc2 := createTestSpdxDoc("doc2", "https://example.com/doc2", "Backend", "SPDXRef-Backend", []struct{ Name, ID string }{
		{Name: "Express", ID: "SPDXRef-Express"},
	})

	file1 := writeTestDoc(t, doc1)
	file2 := writeTestDoc(t, doc2)
	outFile := filepath.Join(t.TempDir(), "out.spdx.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file1, file2}},
		Output: output{
			FileFormat: "json",
			Spec:       string(sbom.SBOMSpecSPDX),
			File:       outFile,
		},
		Assemble: assemble{
			AssemblyMerge: true,
		},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	outDoc := loadOutputDoc(t, outFile)

	var rootPkgID string
	for _, rel := range outDoc.Relationships {
		if rel.Relationship == common.TypeRelationshipDescribe && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	if rootPkgID == "" {
		t.Fatal("could not find root package")
	}

	// Assert root -> Frontend is CONTAINS
	foundRootContains := false
	for _, rel := range outDoc.Relationships {
		if string(rel.RefA.ElementRefID) == rootPkgID && rel.Relationship == common.TypeRelationshipContains {
			foundRootContains = true
			break
		}
	}
	if !foundRootContains {
		t.Error("assembly merge: expected root CONTAINS at least one primary")
	}

	// Assert root -> Frontend is NOT DEPENDS_ON
	for _, rel := range outDoc.Relationships {
		if string(rel.RefA.ElementRefID) == rootPkgID && rel.Relationship == common.TypeRelationshipDependsOn {
			t.Error("assembly merge: root should not have DEPENDS_ON to primary")
			break
		}
	}
}

func TestFlatMerge_RootToPrimaryIsDependsOn(t *testing.T) {
	ctx := context.Background()

	doc1 := createTestSpdxDoc("doc1", "https://example.com/doc1", "Frontend", "SPDXRef-Frontend", []struct{ Name, ID string }{
		{Name: "React", ID: "SPDXRef-React"},
	})
	doc2 := createTestSpdxDoc("doc2", "https://example.com/doc2", "Backend", "SPDXRef-Backend", []struct{ Name, ID string }{
		{Name: "Express", ID: "SPDXRef-Express"},
	})

	file1 := writeTestDoc(t, doc1)
	file2 := writeTestDoc(t, doc2)
	outFile := filepath.Join(t.TempDir(), "out.spdx.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file1, file2}},
		Output: output{
			FileFormat: "json",
			Spec:       string(sbom.SBOMSpecSPDX),
			File:       outFile,
		},
		Assemble: assemble{
			FlatMerge: true,
		},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	outDoc := loadOutputDoc(t, outFile)

	var rootPkgID string
	for _, rel := range outDoc.Relationships {
		if rel.Relationship == common.TypeRelationshipDescribe && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	if rootPkgID == "" {
		t.Fatal("could not find root package")
	}

	// Assert root -> Frontend is DEPENDS_ON
	foundRootDepends := false
	for _, rel := range outDoc.Relationships {
		if string(rel.RefA.ElementRefID) == rootPkgID && rel.Relationship == common.TypeRelationshipDependsOn {
			foundRootDepends = true
			break
		}
	}
	if !foundRootDepends {
		t.Error("flat merge: expected root DEPENDS_ON to at least one primary")
	}

	// Assert root -> Frontend is NOT CONTAINS
	for _, rel := range outDoc.Relationships {
		if string(rel.RefA.ElementRefID) == rootPkgID && rel.Relationship == common.TypeRelationshipContains {
			t.Error("flat merge: root should not CONTAINS any primary")
			break
		}
	}
}

func TestFlatMerge_PreservesAllClonedRelationships(t *testing.T) {
	ctx := context.Background()

	// Doc 1: Frontend with both CONTAINS and DEPENDS_ON
	doc1 := createTestSpdxDoc("doc1", "https://example.com/doc1", "Frontend", "SPDXRef-Frontend", []struct{ Name, ID string }{
		{Name: "React", ID: "SPDXRef-React"},
	})
	doc1.Relationships = append(doc1.Relationships,
		&spdx.Relationship{
			RefA:         common.MakeDocElementID("", "SPDXRef-Frontend"),
			RefB:         common.MakeDocElementID("", "SPDXRef-React"),
			Relationship: common.TypeRelationshipContains,
		},
		&spdx.Relationship{
			RefA:         common.MakeDocElementID("", "SPDXRef-Frontend"),
			RefB:         common.MakeDocElementID("", "SPDXRef-React"),
			Relationship: common.TypeRelationshipDependsOn,
		},
	)

	file1 := writeTestDoc(t, doc1)
	outFile := filepath.Join(t.TempDir(), "out.spdx.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:           "MyApp",
			Version:        "1.0.0",
			PrimaryPurpose: "application",
		},
		Input: input{Files: []string{file1}},
		Output: output{
			FileFormat: "json",
			Spec:       string(sbom.SBOMSpecSPDX),
			File:       outFile,
		},
		Assemble: assemble{
			FlatMerge: true,
		},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	outDoc := loadOutputDoc(t, outFile)

	var frontendID, reactID string
	for _, pkg := range outDoc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if frontendID == "" || reactID == "" {
		t.Fatal("Frontend or React package not found")
	}

	// Both CONTAINS and DEPENDS_ON must be preserved
	if r := findRelationship(outDoc, frontendID, reactID, "CONTAINS"); r == nil {
		t.Errorf("flat merge should preserve existing CONTAINS(%s -> %s)", frontendID, reactID)
	}
	if r := findRelationship(outDoc, frontendID, reactID, "DEPENDS_ON"); r == nil {
		t.Errorf("flat merge should preserve existing DEPENDS_ON(%s -> %s)", frontendID, reactID)
	}
}
