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
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/v2/pkg/assemble"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
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
