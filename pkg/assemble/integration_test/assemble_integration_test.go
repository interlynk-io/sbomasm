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

package integration_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/v2/pkg/assemble"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	spdx_json "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

var testLoggerOnce sync.Once

// TestMain initializes the logger before running tests
func TestMain(m *testing.M) {
	testLoggerOnce.Do(func() {
		logger.InitProdLogger()
	})
	m.Run()
}

// getTestDataDir returns the path to the testdata directory
func getTestDataDir() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "testdata")
}

// Test_FlatMergeWithPrimary_BomRefNormalization tests
// Verifies that flat merge with --primary normalizes the primary component's bom-ref
// to match the dependency refs, preventing dangling references.
func Test_FlatMergeWithPrimary_BomRefNormalization(t *testing.T) {
	// Create temp output file
	outputFile := filepath.Join(t.TempDir(), "issue330-flat-merge-output.cdx.json")

	// Get test data paths
	testDataDir := filepath.Join(getTestDataDir(), "issue330")
	primaryFile := filepath.Join(testDataDir, "primary.cdx.json")
	secondaryFile := filepath.Join(testDataDir, "secondary.cdx.json")

	// Setup context and params
	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{secondaryFile}
	params.Output = outputFile
	params.FlatMerge = true
	params.PrimaryFile = primaryFile
	params.Json = true
	params.OutputSpec = "cyclonedx"

	// Populate config and run assemble
	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	// Read and parse output
	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	bom := new(cydx.BOM)
	decoder := cydx.NewBOMDecoder(f, cydx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		t.Fatalf("Failed to parse output JSON: %v", err)
	}

	// Verify primary component bom-ref is normalized (myapp@1.0.0, not myapp==1.0.0)
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatal("metadata.component should be set")
	}
	primaryBomRef := bom.Metadata.Component.BOMRef
	if primaryBomRef == "" {
		t.Fatal("metadata.component.bom-ref should not be empty")
	}

	// The bom-ref should be normalized
	if contains := containsSubstring(primaryBomRef, "=="); contains {
		t.Errorf("Primary component bom-ref should be normalized (use @ not ==), got: %s", primaryBomRef)
	}

	expectedBomRef := "myapp@1.0.0"
	if primaryBomRef != expectedBomRef {
		t.Errorf("Primary component bom-ref should be normalized to %s, got %s", expectedBomRef, primaryBomRef)
	}

	// Verify that at least one dependency refs the primary component
	foundPrimaryRef := false
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if dep.Ref == primaryBomRef {
				foundPrimaryRef = true
				break
			}
		}
	}
	if !foundPrimaryRef {
		t.Errorf("No dependency refs found for primary component bom-ref %q", primaryBomRef)
	}

	t.Logf("✓ Primary component bom-ref normalized: %s", primaryBomRef)
	t.Logf("✓ Dependency refs match primary bom-ref")
}

// Test_AssemblyMergeWithPrimary_BomRefNormalization test
// Verifies that assembly merge with --primary normalizes the primary component's bom-ref
func Test_AssemblyMergeWithPrimary_BomRefNormalization(t *testing.T) {
	// Create temp output file
	outputFile := filepath.Join(t.TempDir(), "issue330-assembly-merge-output.cdx.json")

	// Get test data paths
	testDataDir := filepath.Join(getTestDataDir(), "issue330")
	primaryFile := filepath.Join(testDataDir, "primary.cdx.json")
	secondaryFile := filepath.Join(testDataDir, "secondary.cdx.json")

	// Setup context and params
	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{secondaryFile}
	params.Output = outputFile
	params.AssemblyMerge = true
	params.PrimaryFile = primaryFile
	params.Json = true
	params.OutputSpec = "cyclonedx"

	// Populate config and run assemble
	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	// Read and parse output
	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	bom := new(cydx.BOM)
	decoder := cydx.NewBOMDecoder(f, cydx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		t.Fatalf("Failed to parse output JSON: %v", err)
	}

	// Verify primary component bom-ref is normalized
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatal("metadata.component should be set")
	}
	primaryBomRef := bom.Metadata.Component.BOMRef
	if primaryBomRef == "" {
		t.Fatal("metadata.component.bom-ref should not be empty")
	}

	// The bom-ref should be normalized
	if contains := containsSubstring(primaryBomRef, "=="); contains {
		t.Errorf("Primary component bom-ref should be normalized (use @ not ==), got: %s", primaryBomRef)
	}

	expectedBomRef := "myapp@1.0.0"
	if primaryBomRef != expectedBomRef {
		t.Errorf("Primary component bom-ref should be normalized to %s, got %s", expectedBomRef, primaryBomRef)
	}

	// Verify that at least one dependency refs the primary component
	foundPrimaryRef := false
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if dep.Ref == primaryBomRef {
				foundPrimaryRef = true
				break
			}
		}
	}
	if !foundPrimaryRef {
		t.Errorf("No dependency refs found for primary component bom-ref %q", primaryBomRef)
	}

	t.Logf("✓ Primary component bom-ref normalized: %s", primaryBomRef)
	t.Logf("✓ Dependency refs match primary bom-ref")
}

// Test_AugmentMerge_OutputSpecVersion_SchemaURL tests that augment merge respects
// --outputSpecVersion and writes the correct $schema URL in the JSON output.
// Regression test for: https://github.com/interlynk-io/sbomasm/issues/328
func Test_AugmentMerge_OutputSpecVersion_SchemaURL(t *testing.T) {
	testCases := []struct {
		name           string
		outputSpecVer  string
		expectedSchema string
	}{
		{
			name:           "Downgrade 1.6 primary SBOM to 1.5 output",
			outputSpecVer:  "1.5",
			expectedSchema: "http://cyclonedx.org/schema/bom-1.5.schema.json",
		},
		{
			name:           "Downgrade 1.6 primary SBOM to 1.4 output",
			outputSpecVer:  "1.4",
			expectedSchema: "http://cyclonedx.org/schema/bom-1.4.schema.json",
		},
		{
			name:           "Upgrade 1.6 primary SBOM to 1.7 output",
			outputSpecVer:  "1.7",
			expectedSchema: "http://cyclonedx.org/schema/bom-1.7.schema.json",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outputFile := filepath.Join(t.TempDir(), "issue328-output.cdx.json")

			testDataDir := filepath.Join(getTestDataDir(), "issue328")
			primaryFile := filepath.Join(testDataDir, "primary.cdx.json")
			secondaryFile := filepath.Join(testDataDir, "secondary.cdx.json")

			ctx := logger.WithLogger(context.Background())
			params := assemble.NewParams()
			params.Ctx = &ctx
			params.Input = []string{secondaryFile}
			params.Output = outputFile
			params.AugmentMerge = true
			params.PrimaryFile = primaryFile
			params.Json = true
			params.OutputSpec = "cyclonedx"
			params.OutputSpecVersion = tc.outputSpecVer

			config, err := assemble.PopulateConfig(params)
			if err != nil {
				t.Fatalf("PopulateConfig failed: %v", err)
			}

			err = assemble.Assemble(config)
			if err != nil {
				t.Fatalf("Assemble failed: %v", err)
			}

			rawBytes, err := os.ReadFile(outputFile)
			if err != nil {
				t.Fatalf("Failed to read output file: %v", err)
			}

			// Parse as generic JSON to inspect $schema field
			var rawJSON map[string]interface{}
			if err := json.Unmarshal(rawBytes, &rawJSON); err != nil {
				t.Fatalf("Failed to parse output as generic JSON: %v", err)
			}

			schemaURL, ok := rawJSON["$schema"].(string)
			if !ok {
				t.Fatalf("$schema field missing or not a string in output")
			}

			if schemaURL != tc.expectedSchema {
				t.Errorf("$schema mismatch: expected %q, got %q", tc.expectedSchema, schemaURL)
			} else {
				t.Logf("✓ $schema correctly set to %s for --outputSpecVersion=%s", schemaURL, tc.outputSpecVer)
			}
		})
	}
}

// Test_AssemblyMergeWithPrimary_DocLicense tests that --doc-license is respected
// when using --assemblyMerge --primary. Regression test for:
// https://github.com/interlynk-io/sbomasm/issues/331
func Test_AssemblyMergeWithPrimary_DocLicense(t *testing.T) {
	testCases := []struct {
		name            string
		primaryFile     string
		docLicense      string
		expectLicense   string
		expectNoLicense bool
	}{
		{
			name:          "No-license primary + --doc-license Apache-2.0",
			primaryFile:   "primary-no-license.cdx.json",
			docLicense:    "Apache-2.0",
			expectLicense: "Apache-2.0",
		},
		{
			name:          "No-license primary + no --doc-license (default CC0-1.0)",
			primaryFile:   "primary-no-license.cdx.json",
			docLicense:    "",
			expectLicense: "CC0-1.0",
		},
		{
			name:            "No-license primary + --doc-license none",
			primaryFile:     "primary-no-license.cdx.json",
			docLicense:      "none",
			expectNoLicense: true,
		},
		{
			name:          "Licensed primary (MIT) + no --doc-license (preserve primary)",
			primaryFile:   "primary-with-license.cdx.json",
			docLicense:    "",
			expectLicense: "MIT",
		},
		{
			name:          "Licensed primary (MIT) + --doc-license Apache-2.0 (override)",
			primaryFile:   "primary-with-license.cdx.json",
			docLicense:    "Apache-2.0",
			expectLicense: "Apache-2.0",
		},
		{
			name:            "Licensed primary (MIT) + --doc-license none",
			primaryFile:     "primary-with-license.cdx.json",
			docLicense:      "none",
			expectNoLicense: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outputFile := filepath.Join(t.TempDir(), "issue331-output.cdx.json")

			testDataDir := filepath.Join(getTestDataDir(), "issue331")
			primaryPath := filepath.Join(testDataDir, tc.primaryFile)
			secondaryPath := filepath.Join(testDataDir, "secondary.cdx.json")

			ctx := logger.WithLogger(context.Background())
			params := assemble.NewParams()
			params.Ctx = &ctx
			params.Input = []string{secondaryPath}
			params.Output = outputFile
			params.AssemblyMerge = true
			params.PrimaryFile = primaryPath
			params.Json = true
			params.OutputSpec = "cyclonedx"
			params.DocLicense = tc.docLicense

			config, err := assemble.PopulateConfig(params)
			if err != nil {
				t.Fatalf("PopulateConfig failed: %v", err)
			}

			err = assemble.Assemble(config)
			if err != nil {
				t.Fatalf("Assemble failed: %v", err)
			}

			// Parse output
			f, err := os.Open(outputFile)
			if err != nil {
				t.Fatalf("Failed to open output file: %v", err)
			}
			defer f.Close()

			bom := new(cydx.BOM)
			decoder := cydx.NewBOMDecoder(f, cydx.BOMFileFormatJSON)
			if err := decoder.Decode(bom); err != nil {
				t.Fatalf("Failed to parse output JSON: %v", err)
			}

			if tc.expectNoLicense {
				if bom.Metadata != nil && bom.Metadata.Licenses != nil && len(*bom.Metadata.Licenses) > 0 {
					t.Errorf("Expected no licenses, but found %d license(s)", len(*bom.Metadata.Licenses))
				} else {
					t.Logf("✓ No license present as expected")
				}
				return
			}

			if bom.Metadata == nil || bom.Metadata.Licenses == nil || len(*bom.Metadata.Licenses) == 0 {
				t.Fatalf("Expected license %q, but no licenses found", tc.expectLicense)
			}

			actualLicense := (*bom.Metadata.Licenses)[0].License.ID
			if actualLicense != tc.expectLicense {
				t.Errorf("License mismatch: expected %q, got %q", tc.expectLicense, actualLicense)
			} else {
				t.Logf("✓ License correctly set to %s", actualLicense)
			}
		})
	}
}

// containsSubstring is a helper to check if a string contains a substring
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ---- SPDX Merge Strategy Integration Tests (Issue #344) ----

// spdxFindRel looks up for a relationship in an SPDX document.
func spdxFindRel(doc *v2_3.Document, refA, refB, relType string) *v2_3.Relationship {
	for _, rel := range doc.Relationships {
		if string(rel.RefA.ElementRefID) == refA && string(rel.RefB.ElementRefID) == refB && rel.Relationship == relType {
			return rel
		}
	}
	return nil
}

// spdxCountRels counts how many relationships of a given type exist from refA to refB.
func spdxCountRels(doc *v2_3.Document, refA, refB, relType string) int {
	count := 0
	for _, rel := range doc.Relationships {
		if string(rel.RefA.ElementRefID) == refA && string(rel.RefB.ElementRefID) == refB && rel.Relationship == relType {
			count++
		}
	}
	return count
}

// Test_SPDX_HierarchicalMerge_Relationships verifies that hierarchical merge
// produces DEPENDS_ON from root to primaries and generates CONTAINS for internal hierarchy.
func Test_SPDX_HierarchicalMerge_Relationships(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "issue344-hierarchical.spdx.json")

	testDataDir := filepath.Join(getTestDataDir(), "issue344")
	frontendFile := filepath.Join(testDataDir, "frontend.spdx.json")
	backendFile := filepath.Join(testDataDir, "backend.spdx.json")

	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{frontendFile, backendFile}
	params.Output = outputFile
	params.Json = true
	params.OutputSpec = "spdx"
	params.Name = "MyApp"
	params.Version = "1.0.0"
	params.Type = "application"

	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	// Parse output SPDX
	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	doc, err := spdx_json.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse output SPDX: %v", err)
	}

	// Find root package (the one DESCRIBED by DOCUMENT)
	var rootPkgID string
	for _, rel := range doc.Relationships {
		if rel.Relationship == "DESCRIBES" && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	if rootPkgID == "" {
		t.Fatal("could not find root package via DESCRIBES")
	}

	// Find remapped Frontend and Backend package IDs
	var frontendID, backendID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "Backend" {
			backendID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if frontendID == "" || backendID == "" {
		t.Fatalf("Frontend or Backend package not found in output")
	}

	// Assert root -> Frontend is DEPENDS_ON
	if spdxFindRel(doc, rootPkgID, frontendID, "DEPENDS_ON") == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s)", rootPkgID, frontendID)
	}

	// Assert root -> Backend is DEPENDS_ON
	if spdxFindRel(doc, rootPkgID, backendID, "DEPENDS_ON") == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s)", rootPkgID, backendID)
	}

	// Assert root -> Frontend is NOT CONTAINS
	if spdxFindRel(doc, rootPkgID, frontendID, "CONTAINS") != nil {
		t.Errorf("hierarchical merge: root should not CONTAINS primary %s", frontendID)
	}

	// Find React and Axios IDs
	var reactID, axiosID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "Axios" {
			axiosID = string(pkg.PackageSPDXIdentifier)
		}
	}

	// Assert CONTAINS(Frontend -> React) generated for hierarchy
	if reactID != "" && spdxFindRel(doc, frontendID, reactID, "CONTAINS") == nil {
		t.Errorf("expected generated CONTAINS(%s -> %s)", frontendID, reactID)
	}

	// Assert CONTAINS(Frontend -> Axios) generated for hierarchy
	if axiosID != "" && spdxFindRel(doc, frontendID, axiosID, "CONTAINS") == nil {
		t.Errorf("expected generated CONTAINS(%s -> %s)", frontendID, axiosID)
	}

	// Assert existing DEPENDS_ON(Frontend -> React) preserved
	if reactID != "" && spdxFindRel(doc, frontendID, reactID, "DEPENDS_ON") == nil {
		t.Errorf("expected preserved DEPENDS_ON(%s -> %s)", frontendID, reactID)
	}

	t.Logf("✓ Hierarchical merge relationships verified")
}

// Test_SPDX_AssemblyMerge_Relationships verifies that assembly merge
// produces CONTAINS from root to primaries.
func Test_SPDX_AssemblyMerge_Relationships(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "issue344-assembly.spdx.json")

	testDataDir := filepath.Join(getTestDataDir(), "issue344")
	frontendFile := filepath.Join(testDataDir, "frontend.spdx.json")
	backendFile := filepath.Join(testDataDir, "backend.spdx.json")

	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{frontendFile, backendFile}
	params.Output = outputFile
	params.AssemblyMerge = true
	params.Json = true
	params.OutputSpec = "spdx"
	params.Name = "MyApp"
	params.Version = "1.0.0"
	params.Type = "application"

	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	doc, err := spdx_json.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse output SPDX: %v", err)
	}

	var rootPkgID string
	for _, rel := range doc.Relationships {
		if rel.Relationship == "DESCRIBES" && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	if rootPkgID == "" {
		t.Fatal("could not find root package")
	}

	var frontendID, backendID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "Backend" {
			backendID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if frontendID == "" || backendID == "" {
		t.Fatalf("Frontend or Backend package not found")
	}

	// Assert root -> Frontend is CONTAINS
	if spdxFindRel(doc, rootPkgID, frontendID, "CONTAINS") == nil {
		t.Errorf("expected CONTAINS(%s -> %s) for assembly merge", rootPkgID, frontendID)
	}

	// Assert root -> Backend is CONTAINS
	if spdxFindRel(doc, rootPkgID, backendID, "CONTAINS") == nil {
		t.Errorf("expected CONTAINS(%s -> %s) for assembly merge", rootPkgID, backendID)
	}

	// Assert root -> Frontend is NOT DEPENDS_ON
	if spdxFindRel(doc, rootPkgID, frontendID, "DEPENDS_ON") != nil {
		t.Errorf("assembly merge: root should not DEPENDS_ON primary %s", frontendID)
	}

	// Assert existing internal DEPENDS_ON preserved
	var reactID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if reactID != "" && spdxFindRel(doc, frontendID, reactID, "DEPENDS_ON") == nil {
		t.Errorf("expected preserved DEPENDS_ON(%s -> %s)", frontendID, reactID)
	}

	t.Logf("✓ Assembly merge relationships verified")
}

// Test_SPDX_FlatMerge_Relationships verifies that flat merge
// produces DEPENDS_ON from root to primaries and preserves cloned relationships.
func Test_SPDX_FlatMerge_Relationships(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "issue344-flat.spdx.json")

	testDataDir := filepath.Join(getTestDataDir(), "issue344")
	frontendFile := filepath.Join(testDataDir, "frontend.spdx.json")
	backendFile := filepath.Join(testDataDir, "backend.spdx.json")

	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{frontendFile, backendFile}
	params.Output = outputFile
	params.FlatMerge = true
	params.Json = true
	params.OutputSpec = "spdx"
	params.Name = "MyApp"
	params.Version = "1.0.0"
	params.Type = "application"

	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	doc, err := spdx_json.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse output SPDX: %v", err)
	}

	var rootPkgID string
	for _, rel := range doc.Relationships {
		if rel.Relationship == "DESCRIBES" && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	if rootPkgID == "" {
		t.Fatal("could not find root package")
	}

	var frontendID, backendID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "Backend" {
			backendID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if frontendID == "" || backendID == "" {
		t.Fatalf("Frontend or Backend package not found")
	}

	// Assert root -> Frontend is DEPENDS_ON
	if spdxFindRel(doc, rootPkgID, frontendID, "DEPENDS_ON") == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s) for flat merge", rootPkgID, frontendID)
	}

	// Assert root -> Backend is DEPENDS_ON
	if spdxFindRel(doc, rootPkgID, backendID, "DEPENDS_ON") == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s) for flat merge", rootPkgID, backendID)
	}

	// Assert root -> Frontend is NOT CONTAINS
	if spdxFindRel(doc, rootPkgID, frontendID, "CONTAINS") != nil {
		t.Errorf("flat merge: root should not CONTAINS primary %s", frontendID)
	}

	// Assert existing internal relationships preserved
	var reactID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if reactID != "" && spdxFindRel(doc, frontendID, reactID, "DEPENDS_ON") == nil {
		t.Errorf("expected preserved DEPENDS_ON(%s -> %s) in flat merge", frontendID, reactID)
	}

	t.Logf("✓ Flat merge relationships verified")
}

// ---- SPDX Merge Strategy Variations: All CONTAINS, Mixed, Pre-existing CONTAINS ----

// Test_SPDX_HierarchicalMerge_AllContains verifies hierarchical merge when input
// SBOMs already use only CONTAINS relationships (no DEPENDS_ON). The merge should
// preserve all original CONTAINS relationships and generate additional CONTAINS for
// hierarchy from each primary to its non-primary packages.
func Test_SPDX_HierarchicalMerge_AllContains(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "issue344-all-contains-hierarchical.spdx.json")

	testDataDir := filepath.Join(getTestDataDir(), "issue344-all-contains")
	frontendFile := filepath.Join(testDataDir, "frontend.spdx.json")
	backendFile := filepath.Join(testDataDir, "backend.spdx.json")

	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{frontendFile, backendFile}
	params.Output = outputFile
	params.Json = true
	params.OutputSpec = "spdx"
	params.Name = "MyApp"
	params.Version = "1.0.0"
	params.Type = "application"

	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	doc, err := spdx_json.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse output SPDX: %v", err)
	}

	var rootPkgID string
	for _, rel := range doc.Relationships {
		if rel.Relationship == "DESCRIBES" && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	if rootPkgID == "" {
		t.Fatal("could not find root package")
	}

	var frontendID, backendID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "Backend" {
			backendID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if frontendID == "" || backendID == "" {
		t.Fatalf("Frontend or Backend package not found")
	}

	// Root -> primaries must be DEPENDS_ON
	if spdxFindRel(doc, rootPkgID, frontendID, "DEPENDS_ON") == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s)", rootPkgID, frontendID)
	}
	if spdxFindRel(doc, rootPkgID, backendID, "DEPENDS_ON") == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s)", rootPkgID, backendID)
	}

	// Original CONTAINS relationships must be preserved
	var reactID, axiosID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "Axios" {
			axiosID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if reactID != "" && spdxFindRel(doc, frontendID, reactID, "CONTAINS") == nil {
		t.Errorf("expected preserved CONTAINS(%s -> %s)", frontendID, reactID)
	}
	if reactID != "" && axiosID != "" && spdxFindRel(doc, reactID, axiosID, "CONTAINS") == nil {
		t.Errorf("expected preserved CONTAINS(%s -> %s)", reactID, axiosID)
	}

	// Generated hierarchy CONTAINS(Frontend -> Axios) must exist
	if axiosID != "" && spdxFindRel(doc, frontendID, axiosID, "CONTAINS") == nil {
		t.Errorf("expected generated CONTAINS(%s -> %s) for hierarchy", frontendID, axiosID)
	}

	t.Logf("✓ Hierarchical merge with all-CONTAINS input verified")
}

// Test_SPDX_AssemblyMerge_AllContains verifies assembly merge when input SBOMs
// use only CONTAINS relationships. Original CONTAINS must be preserved, and
// root -> primaries must be CONTAINS.
func Test_SPDX_AssemblyMerge_AllContains(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "issue344-all-contains-assembly.spdx.json")

	testDataDir := filepath.Join(getTestDataDir(), "issue344-all-contains")
	frontendFile := filepath.Join(testDataDir, "frontend.spdx.json")
	backendFile := filepath.Join(testDataDir, "backend.spdx.json")

	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{frontendFile, backendFile}
	params.Output = outputFile
	params.AssemblyMerge = true
	params.Json = true
	params.OutputSpec = "spdx"
	params.Name = "MyApp"
	params.Version = "1.0.0"
	params.Type = "application"

	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	doc, err := spdx_json.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse output SPDX: %v", err)
	}

	var rootPkgID string
	for _, rel := range doc.Relationships {
		if rel.Relationship == "DESCRIBES" && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	if rootPkgID == "" {
		t.Fatal("could not find root package")
	}

	var frontendID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if frontendID == "" {
		t.Fatal("Frontend package not found")
	}

	// Root -> Frontend must be CONTAINS
	if spdxFindRel(doc, rootPkgID, frontendID, "CONTAINS") == nil {
		t.Errorf("expected CONTAINS(%s -> %s) for assembly merge", rootPkgID, frontendID)
	}

	// Original CONTAINS preserved
	var reactID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if reactID != "" && spdxFindRel(doc, frontendID, reactID, "CONTAINS") == nil {
		t.Errorf("expected preserved CONTAINS(%s -> %s)", frontendID, reactID)
	}

	t.Logf("✓ Assembly merge with all-CONTAINS input verified")
}

// Test_SPDX_FlatMerge_AllContains verifies flat merge when input SBOMs use only
// CONTAINS relationships. Original CONTAINS must be preserved, and root -> primaries
// must be DEPENDS_ON.
func Test_SPDX_FlatMerge_AllContains(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "issue344-all-contains-flat.spdx.json")

	testDataDir := filepath.Join(getTestDataDir(), "issue344-all-contains")
	frontendFile := filepath.Join(testDataDir, "frontend.spdx.json")
	backendFile := filepath.Join(testDataDir, "backend.spdx.json")

	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{frontendFile, backendFile}
	params.Output = outputFile
	params.FlatMerge = true
	params.Json = true
	params.OutputSpec = "spdx"
	params.Name = "MyApp"
	params.Version = "1.0.0"
	params.Type = "application"

	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	doc, err := spdx_json.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse output SPDX: %v", err)
	}

	var rootPkgID string
	for _, rel := range doc.Relationships {
		if rel.Relationship == "DESCRIBES" && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	if rootPkgID == "" {
		t.Fatal("could not find root package")
	}

	var frontendID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if frontendID == "" {
		t.Fatal("Frontend package not found")
	}

	// Root -> Frontend must be DEPENDS_ON
	if spdxFindRel(doc, rootPkgID, frontendID, "DEPENDS_ON") == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s) for flat merge", rootPkgID, frontendID)
	}

	// Original CONTAINS preserved
	var reactID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if reactID != "" && spdxFindRel(doc, frontendID, reactID, "CONTAINS") == nil {
		t.Errorf("expected preserved CONTAINS(%s -> %s)", frontendID, reactID)
	}

	t.Logf("✓ Flat merge with all-CONTAINS input verified")
}

// Test_SPDX_HierarchicalMerge_Mixed verifies hierarchical merge when input SBOMs
// have a mix of CONTAINS and DEPENDS_ON. Both types must be preserved, and
// generated CONTAINS must be added for hierarchy without creating duplicates.
func Test_SPDX_HierarchicalMerge_Mixed(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "issue344-mixed-hierarchical.spdx.json")

	testDataDir := filepath.Join(getTestDataDir(), "issue344-mixed")
	frontendFile := filepath.Join(testDataDir, "frontend.spdx.json")
	backendFile := filepath.Join(testDataDir, "backend.spdx.json")

	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{frontendFile, backendFile}
	params.Output = outputFile
	params.Json = true
	params.OutputSpec = "spdx"
	params.Name = "MyApp"
	params.Version = "1.0.0"
	params.Type = "application"

	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	doc, err := spdx_json.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse output SPDX: %v", err)
	}

	var rootPkgID string
	for _, rel := range doc.Relationships {
		if rel.Relationship == "DESCRIBES" && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	if rootPkgID == "" {
		t.Fatal("could not find root package")
	}

	var frontendID, backendID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "Backend" {
			backendID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if frontendID == "" || backendID == "" {
		t.Fatalf("Frontend or Backend package not found")
	}

	// Root -> primaries must be DEPENDS_ON
	if spdxFindRel(doc, rootPkgID, frontendID, "DEPENDS_ON") == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s)", rootPkgID, frontendID)
	}
	if spdxFindRel(doc, rootPkgID, backendID, "DEPENDS_ON") == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s)", rootPkgID, backendID)
	}

	var reactID, axiosID, expressID, mongooseID string
	for _, pkg := range doc.Packages {
		switch pkg.PackageName {
		case "React":
			reactID = string(pkg.PackageSPDXIdentifier)
		case "Axios":
			axiosID = string(pkg.PackageSPDXIdentifier)
		case "Express":
			expressID = string(pkg.PackageSPDXIdentifier)
		case "Mongoose":
			mongooseID = string(pkg.PackageSPDXIdentifier)
		}
	}

	// Preserved: Frontend CONTAINS React (from input)
	if reactID != "" && spdxFindRel(doc, frontendID, reactID, "CONTAINS") == nil {
		t.Errorf("expected preserved CONTAINS(%s -> %s)", frontendID, reactID)
	}
	// Preserved: React DEPENDS_ON Axios (from input)
	if reactID != "" && axiosID != "" && spdxFindRel(doc, reactID, axiosID, "DEPENDS_ON") == nil {
		t.Errorf("expected preserved DEPENDS_ON(%s -> %s)", reactID, axiosID)
	}
	// Preserved: Backend DEPENDS_ON Express (from input)
	if expressID != "" && spdxFindRel(doc, backendID, expressID, "DEPENDS_ON") == nil {
		t.Errorf("expected preserved DEPENDS_ON(%s -> %s)", backendID, expressID)
	}
	// Preserved: Express CONTAINS Mongoose (from input)
	if expressID != "" && mongooseID != "" && spdxFindRel(doc, expressID, mongooseID, "CONTAINS") == nil {
		t.Errorf("expected preserved CONTAINS(%s -> %s)", expressID, mongooseID)
	}

	// Generated hierarchy: Frontend CONTAINS Axios (direct nesting)
	if axiosID != "" && spdxFindRel(doc, frontendID, axiosID, "CONTAINS") == nil {
		t.Errorf("expected generated CONTAINS(%s -> %s) for hierarchy", frontendID, axiosID)
	}
	// Generated hierarchy: Backend CONTAINS Mongoose (direct nesting)
	if mongooseID != "" && spdxFindRel(doc, backendID, mongooseID, "CONTAINS") == nil {
		t.Errorf("expected generated CONTAINS(%s -> %s) for hierarchy", backendID, mongooseID)
	}

	// No duplicates
	if c := spdxCountRels(doc, frontendID, reactID, "CONTAINS"); c != 1 {
		t.Errorf("expected exactly 1 CONTAINS(%s -> %s), got %d", frontendID, reactID, c)
	}

	t.Logf("✓ Hierarchical merge with mixed relationships verified")
}

// Test_SPDX_AssemblyMerge_Mixed verifies assembly merge with mixed CONTAINS and
// DEPENDS_ON input. All original relationships must be preserved.
func Test_SPDX_AssemblyMerge_Mixed(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "issue344-mixed-assembly.spdx.json")

	testDataDir := filepath.Join(getTestDataDir(), "issue344-mixed")
	frontendFile := filepath.Join(testDataDir, "frontend.spdx.json")
	backendFile := filepath.Join(testDataDir, "backend.spdx.json")

	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{frontendFile, backendFile}
	params.Output = outputFile
	params.AssemblyMerge = true
	params.Json = true
	params.OutputSpec = "spdx"
	params.Name = "MyApp"
	params.Version = "1.0.0"
	params.Type = "application"

	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	doc, err := spdx_json.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse output SPDX: %v", err)
	}

	var rootPkgID, frontendID string
	for _, rel := range doc.Relationships {
		if rel.Relationship == "DESCRIBES" && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if rootPkgID == "" || frontendID == "" {
		t.Fatal("root or Frontend package not found")
	}

	// Root -> Frontend must be CONTAINS
	if spdxFindRel(doc, rootPkgID, frontendID, "CONTAINS") == nil {
		t.Errorf("expected CONTAINS(%s -> %s)", rootPkgID, frontendID)
	}

	var reactID, axiosID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "Axios" {
			axiosID = string(pkg.PackageSPDXIdentifier)
		}
	}

	// Preserved: Frontend CONTAINS React
	if reactID != "" && spdxFindRel(doc, frontendID, reactID, "CONTAINS") == nil {
		t.Errorf("expected preserved CONTAINS(%s -> %s)", frontendID, reactID)
	}
	// Preserved: React DEPENDS_ON Axios
	if reactID != "" && axiosID != "" && spdxFindRel(doc, reactID, axiosID, "DEPENDS_ON") == nil {
		t.Errorf("expected preserved DEPENDS_ON(%s -> %s)", reactID, axiosID)
	}

	t.Logf("✓ Assembly merge with mixed relationships verified")
}

// Test_SPDX_FlatMerge_Mixed verifies flat merge with mixed CONTAINS and
// DEPENDS_ON input. All original relationships must be preserved.
func Test_SPDX_FlatMerge_Mixed(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "issue344-mixed-flat.spdx.json")

	testDataDir := filepath.Join(getTestDataDir(), "issue344-mixed")
	frontendFile := filepath.Join(testDataDir, "frontend.spdx.json")
	backendFile := filepath.Join(testDataDir, "backend.spdx.json")

	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{frontendFile, backendFile}
	params.Output = outputFile
	params.FlatMerge = true
	params.Json = true
	params.OutputSpec = "spdx"
	params.Name = "MyApp"
	params.Version = "1.0.0"
	params.Type = "application"

	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	doc, err := spdx_json.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse output SPDX: %v", err)
	}

	var rootPkgID, frontendID string
	for _, rel := range doc.Relationships {
		if rel.Relationship == "DESCRIBES" && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if rootPkgID == "" || frontendID == "" {
		t.Fatal("root or Frontend package not found")
	}

	// Root -> Frontend must be DEPENDS_ON
	if spdxFindRel(doc, rootPkgID, frontendID, "DEPENDS_ON") == nil {
		t.Errorf("expected DEPENDS_ON(%s -> %s)", rootPkgID, frontendID)
	}

	var reactID, axiosID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "Axios" {
			axiosID = string(pkg.PackageSPDXIdentifier)
		}
	}

	// Preserved: Frontend CONTAINS React
	if reactID != "" && spdxFindRel(doc, frontendID, reactID, "CONTAINS") == nil {
		t.Errorf("expected preserved CONTAINS(%s -> %s)", frontendID, reactID)
	}
	// Preserved: React DEPENDS_ON Axios
	if reactID != "" && axiosID != "" && spdxFindRel(doc, reactID, axiosID, "DEPENDS_ON") == nil {
		t.Errorf("expected preserved DEPENDS_ON(%s -> %s)", reactID, axiosID)
	}

	t.Logf("✓ Flat merge with mixed relationships verified")
}

// Test_SPDX_HierarchicalMerge_PreContains_Dedup verifies that hierarchical merge
// does not generate duplicate CONTAINS relationships when the input SBOM already
// contains CONTAINS from primary to its packages. This is the deduplication case.
func Test_SPDX_HierarchicalMerge_PreContains_Dedup(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "issue344-precontains-hierarchical.spdx.json")

	testDataDir := filepath.Join(getTestDataDir(), "issue344-precontains")
	frontendFile := filepath.Join(testDataDir, "frontend.spdx.json")
	backendFile := filepath.Join(testDataDir, "backend.spdx.json")

	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{frontendFile, backendFile}
	params.Output = outputFile
	params.Json = true
	params.OutputSpec = "spdx"
	params.Name = "MyApp"
	params.Version = "1.0.0"
	params.Type = "application"

	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	doc, err := spdx_json.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse output SPDX: %v", err)
	}

	var rootPkgID, frontendID string
	for _, rel := range doc.Relationships {
		if rel.Relationship == "DESCRIBES" && string(rel.RefA.ElementRefID) == "DOCUMENT" {
			rootPkgID = string(rel.RefB.ElementRefID)
			break
		}
	}
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "Frontend" {
			frontendID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if rootPkgID == "" || frontendID == "" {
		t.Fatal("root or Frontend package not found")
	}

	var reactID, axiosID string
	for _, pkg := range doc.Packages {
		if pkg.PackageName == "React" {
			reactID = string(pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageName == "Axios" {
			axiosID = string(pkg.PackageSPDXIdentifier)
		}
	}

	// All original relationships must be present
	if reactID != "" && spdxFindRel(doc, frontendID, reactID, "DEPENDS_ON") == nil {
		t.Errorf("expected preserved DEPENDS_ON(%s -> %s)", frontendID, reactID)
	}
	if reactID != "" && spdxFindRel(doc, frontendID, reactID, "CONTAINS") == nil {
		t.Errorf("expected preserved CONTAINS(%s -> %s)", frontendID, reactID)
	}
	if axiosID != "" && spdxFindRel(doc, frontendID, axiosID, "CONTAINS") == nil {
		t.Errorf("expected preserved CONTAINS(%s -> %s)", frontendID, axiosID)
	}

	// Deduplication: exactly 1 CONTAINS(Frontend -> React)
	if c := spdxCountRels(doc, frontendID, reactID, "CONTAINS"); c != 1 {
		t.Errorf("expected exactly 1 CONTAINS(%s -> %s), got %d", frontendID, reactID, c)
	}
	// Deduplication: exactly 1 CONTAINS(Frontend -> Axios)
	if c := spdxCountRels(doc, frontendID, axiosID, "CONTAINS"); c != 1 {
		t.Errorf("expected exactly 1 CONTAINS(%s -> %s), got %d", frontendID, axiosID, c)
	}

	// For backend (no pre-existing CONTAINS), generated hierarchy should still work
	var backendID, expressID, mongooseID string
	for _, pkg := range doc.Packages {
		switch pkg.PackageName {
		case "Backend":
			backendID = string(pkg.PackageSPDXIdentifier)
		case "Express":
			expressID = string(pkg.PackageSPDXIdentifier)
		case "Mongoose":
			mongooseID = string(pkg.PackageSPDXIdentifier)
		}
	}
	if backendID != "" && expressID != "" && spdxFindRel(doc, backendID, expressID, "CONTAINS") == nil {
		t.Errorf("expected generated CONTAINS(%s -> %s) for backend hierarchy", backendID, expressID)
	}
	if backendID != "" && mongooseID != "" && spdxFindRel(doc, backendID, mongooseID, "CONTAINS") == nil {
		t.Errorf("expected generated CONTAINS(%s -> %s) for backend hierarchy", backendID, mongooseID)
	}

	t.Logf("✓ Hierarchical merge with pre-existing CONTAINS deduplication verified")
}

// Test_SPDX_AssemblyMerge_PreContains verifies assembly merge when input has
// pre-existing CONTAINS. All original relationships must be preserved without
// duplication.
func Test_SPDX_AssemblyMerge_PreContains(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "issue344-precontains-assembly.spdx.json")

	testDataDir := filepath.Join(getTestDataDir(), "issue344-precontains")
	frontendFile := filepath.Join(testDataDir, "frontend.spdx.json")
	backendFile := filepath.Join(testDataDir, "backend.spdx.json")

	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{frontendFile, backendFile}
	params.Output = outputFile
	params.AssemblyMerge = true
	params.Json = true
	params.OutputSpec = "spdx"
	params.Name = "MyApp"
	params.Version = "1.0.0"
	params.Type = "application"

	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	doc, err := spdx_json.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse output SPDX: %v", err)
	}

	var frontendID, reactID string
	for _, pkg := range doc.Packages {
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

	// Preserved original relationships
	if spdxFindRel(doc, frontendID, reactID, "DEPENDS_ON") == nil {
		t.Errorf("expected preserved DEPENDS_ON(%s -> %s)", frontendID, reactID)
	}
	if spdxFindRel(doc, frontendID, reactID, "CONTAINS") == nil {
		t.Errorf("expected preserved CONTAINS(%s -> %s)", frontendID, reactID)
	}
	if c := spdxCountRels(doc, frontendID, reactID, "CONTAINS"); c != 1 {
		t.Errorf("expected exactly 1 CONTAINS(%s -> %s), got %d", frontendID, reactID, c)
	}

	t.Logf("✓ Assembly merge with pre-existing CONTAINS verified")
}

// Test_SPDX_FlatMerge_PreContains verifies flat merge when input has pre-existing
// CONTAINS. All original relationships must be preserved without duplication.
func Test_SPDX_FlatMerge_PreContains(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "issue344-precontains-flat.spdx.json")

	testDataDir := filepath.Join(getTestDataDir(), "issue344-precontains")
	frontendFile := filepath.Join(testDataDir, "frontend.spdx.json")
	backendFile := filepath.Join(testDataDir, "backend.spdx.json")

	ctx := logger.WithLogger(context.Background())
	params := assemble.NewParams()
	params.Ctx = &ctx
	params.Input = []string{frontendFile, backendFile}
	params.Output = outputFile
	params.FlatMerge = true
	params.Json = true
	params.OutputSpec = "spdx"
	params.Name = "MyApp"
	params.Version = "1.0.0"
	params.Type = "application"

	config, err := assemble.PopulateConfig(params)
	if err != nil {
		t.Fatalf("PopulateConfig failed: %v", err)
	}

	err = assemble.Assemble(config)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	f, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer f.Close()

	doc, err := spdx_json.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse output SPDX: %v", err)
	}

	var frontendID, reactID string
	for _, pkg := range doc.Packages {
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

	// Preserved original relationships
	if spdxFindRel(doc, frontendID, reactID, "DEPENDS_ON") == nil {
		t.Errorf("expected preserved DEPENDS_ON(%s -> %s)", frontendID, reactID)
	}
	if spdxFindRel(doc, frontendID, reactID, "CONTAINS") == nil {
		t.Errorf("expected preserved CONTAINS(%s -> %s)", frontendID, reactID)
	}
	if c := spdxCountRels(doc, frontendID, reactID, "CONTAINS"); c != 1 {
		t.Errorf("expected exactly 1 CONTAINS(%s -> %s), got %d", frontendID, reactID, c)
	}

	t.Logf("✓ Flat merge with pre-existing CONTAINS verified")
}
