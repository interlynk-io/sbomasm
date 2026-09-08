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

package spdx

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

func TestAssemblyMergeWithPrimary_RootIsPrimary(t *testing.T) {
	ctx := context.Background()

	// Primary SBOM
	primaryDoc := createTestSpdxDoc("primary", "https://example.com/primary", "MyApp", "SPDXRef-MyApp", []struct{ Name, ID string }{
		{Name: "LibA", ID: "SPDXRef-LibA"},
	})
	primaryDoc.CreationInfo.Creators = append(primaryDoc.CreationInfo.Creators, common.Creator{
		CreatorType: "Person",
		Creator:     "Alice",
	})

	// Secondary SBOM 1
	sec1 := createTestSpdxDoc("sec1", "https://example.com/sec1", "Frontend", "SPDXRef-Frontend", []struct{ Name, ID string }{
		{Name: "React", ID: "SPDXRef-React"},
	})

	primaryFile := writeTestDoc(t, primaryDoc)
	sec1File := writeTestDoc(t, sec1)
	outFile := filepath.Join(t.TempDir(), "out.spdx.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:    "MyApp",
			Version: "1.0.0",
		},
		Input: input{Files: []string{sec1File}},
		Output: output{
			FileFormat: "json",
			Spec:       string(sbom.SBOMSpecSPDX),
			File:       outFile,
		},
		Assemble: assemble{
			AssemblyMerge:              true,
			IsAssemblyMergeWithPrimary: true,
			PrimaryFile:                primaryFile,
		},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	outDoc := loadOutputDoc(t, outFile)

	// Document name and namespace should be preserved from primary
	if outDoc.DocumentName != "primary" {
		t.Errorf("expected DocumentName 'primary', got %q", outDoc.DocumentName)
	}
	if outDoc.DocumentNamespace != "https://example.com/primary" {
		t.Errorf("expected DocumentNamespace 'https://example.com/primary', got %q", outDoc.DocumentNamespace)
	}

	// Find the root package (should be the primary's primary package)
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

	// Root package should be MyApp (primary's primary)
	var rootPkgName string
	for _, pkg := range outDoc.Packages {
		if string(pkg.PackageSPDXIdentifier) == rootPkgID {
			rootPkgName = pkg.PackageName
			break
		}
	}
	if rootPkgName != "MyApp" {
		t.Errorf("expected root package name 'MyApp', got %q", rootPkgName)
	}

	// Find secondary primary (Frontend) ID
	var frontendID string
	for _, pkg := range outDoc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
			break
		}
	}
	if frontendID == "" {
		t.Fatal("Frontend package not found")
	}

	// Assert root (MyApp) -> Frontend is CONTAINS
	if r := findRelationship(outDoc, rootPkgID, frontendID, "CONTAINS"); r == nil {
		t.Errorf("expected CONTAINS(%s -> %s) for assembly merge with primary", rootPkgID, frontendID)
	}

	// Assert root -> Frontend is NOT DEPENDS_ON
	if r := findRelationship(outDoc, rootPkgID, frontendID, "DEPENDS_ON"); r != nil {
		t.Error("assembly merge with primary: root should not DEPENDS_ON secondary primary")
	}
}

func TestFlatMergeWithPrimary_RootIsPrimary(t *testing.T) {
	ctx := context.Background()

	// Primary SBOM
	primaryDoc := createTestSpdxDoc("primary", "https://example.com/primary", "MyApp", "SPDXRef-MyApp", []struct{ Name, ID string }{
		{Name: "LibA", ID: "SPDXRef-LibA"},
	})

	// Secondary SBOM 1
	sec1 := createTestSpdxDoc("sec1", "https://example.com/sec1", "Frontend", "SPDXRef-Frontend", []struct{ Name, ID string }{
		{Name: "React", ID: "SPDXRef-React"},
	})

	// Secondary SBOM 2
	sec2 := createTestSpdxDoc("sec2", "https://example.com/sec2", "Backend", "SPDXRef-Backend", []struct{ Name, ID string }{
		{Name: "Express", ID: "SPDXRef-Express"},
	})

	primaryFile := writeTestDoc(t, primaryDoc)
	sec1File := writeTestDoc(t, sec1)
	sec2File := writeTestDoc(t, sec2)
	outFile := filepath.Join(t.TempDir(), "out.spdx.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:    "MyApp",
			Version: "1.0.0",
		},
		Input: input{Files: []string{sec1File, sec2File}},
		Output: output{
			FileFormat: "json",
			Spec:       string(sbom.SBOMSpecSPDX),
			File:       outFile,
		},
		Assemble: assemble{
			FlatMerge:              true,
			IsFlatMergeWithPrimary: true,
			PrimaryFile:            primaryFile,
		},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	outDoc := loadOutputDoc(t, outFile)

	// Document name and namespace should be preserved from primary
	if outDoc.DocumentName != "primary" {
		t.Errorf("expected DocumentName 'primary', got %q", outDoc.DocumentName)
	}

	// Find the root package
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

	// Root package should be MyApp
	var rootPkgName string
	for _, pkg := range outDoc.Packages {
		if string(pkg.PackageSPDXIdentifier) == rootPkgID {
			rootPkgName = pkg.PackageName
			break
		}
	}
	if rootPkgName != "MyApp" {
		t.Errorf("expected root package name 'MyApp', got %q", rootPkgName)
	}

	// Find secondary primaries
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
		t.Fatal("Frontend or Backend package not found")
	}

	// Assert root -> Frontend is DEPENDS_ON
	if r := findRelationship(outDoc, rootPkgID, frontendID, "DEPENDS_ON"); r == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s) for flat merge with primary", rootPkgID, frontendID)
	}

	// Assert root -> Backend is DEPENDS_ON
	if r := findRelationship(outDoc, rootPkgID, backendID, "DEPENDS_ON"); r == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s) for flat merge with primary", rootPkgID, backendID)
	}

	// Assert root -> Frontend is NOT CONTAINS
	if r := findRelationship(outDoc, rootPkgID, frontendID, "CONTAINS"); r != nil {
		t.Error("flat merge with primary: root should not CONTAINS secondary primary")
	}
}

func TestFlatMergeWithPrimary_DocLicenseOverride(t *testing.T) {
	ctx := context.Background()

	primaryDoc := createTestSpdxDoc("primary", "https://example.com/primary", "MyApp", "SPDXRef-MyApp", nil)
	primaryDoc.DataLicense = "CC0-1.0"

	sec1 := createTestSpdxDoc("sec1", "https://example.com/sec1", "Frontend", "SPDXRef-Frontend", nil)

	primaryFile := writeTestDoc(t, primaryDoc)
	sec1File := writeTestDoc(t, sec1)
	outFile := filepath.Join(t.TempDir(), "out.spdx.json")

	ms := &MergeSettings{
		Ctx: &ctx,
		App: app{
			Name:    "MyApp",
			Version: "1.0.0",
		},
		Input: input{Files: []string{sec1File}},
		Output: output{
			FileFormat: "json",
			Spec:       string(sbom.SBOMSpecSPDX),
			File:       outFile,
		},
		Assemble: assemble{
			FlatMerge:              true,
			IsFlatMergeWithPrimary: true,
			PrimaryFile:            primaryFile,
			DocLicense:             "MIT",
		},
	}

	if err := Merge(ms); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	outDoc := loadOutputDoc(t, outFile)
	if outDoc.DataLicense != "MIT" {
		t.Errorf("expected DataLicense 'MIT' to override primary's license, got %q", outDoc.DataLicense)
	}
}
