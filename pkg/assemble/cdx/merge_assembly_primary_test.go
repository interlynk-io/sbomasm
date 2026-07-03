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

package cdx

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
)

// Primary SBOM: Java app with 2 components
var primarySBOM = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "name": "primary-app",
      "version": "1.0.0",
      "bom-ref": "pkg:maven/primary-app@1.0.0"
    },
    "supplier": {
      "name": "Primary Supplier"
    },
    "licenses": [
      {
        "license": {
          "id": "MIT"
        }
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "lib1",
      "version": "1.0.0",
      "bom-ref": "pkg:maven/lib1@1.0.0"
    },
    {
      "type": "library",
      "name": "lib2",
      "version": "2.0.0",
      "bom-ref": "pkg:maven/lib2@2.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:maven/primary-app@1.0.0",
      "dependsOn": [
        "pkg:maven/lib1@1.0.0",
        "pkg:maven/lib2@2.0.0"
      ]
    }
  ]
}
`)

// Secondary SBOM: npm package with 2 components
var secondarySBOM = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "library",
      "name": "secondary-pkg",
      "version": "1.5.0",
      "bom-ref": "pkg:npm/secondary-pkg@1.5.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "dep-a",
      "version": "1.0.0",
      "bom-ref": "pkg:npm/dep-a@1.0.0"
    },
    {
      "type": "library",
      "name": "dep-b",
      "version": "2.0.0",
      "bom-ref": "pkg:npm/dep-b@2.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/secondary-pkg@1.5.0",
      "dependsOn": [
        "pkg:npm/dep-a@1.0.0",
        "pkg:npm/dep-b@2.0.0"
      ]
    }
  ]
}
`)

// Secondary 2 SBOM: Another secondary
var secondary2SBOM = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "name": "secondary2-pkg",
      "version": "2.0.0",
      "bom-ref": "pkg:maven/secondary2-pkg@2.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "dep2",
      "version": "2.0.0",
      "bom-ref": "pkg:maven/dep2@2.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:maven/secondary2-pkg@2.0.0",
      "dependsOn": [
        "pkg:maven/dep2@2.0.0"
      ]
    }
  ]
}
`)

// Primary with no components
var primaryNoComponents = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:no-components",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "name": "empty-primary",
      "version": "1.0.0",
      "bom-ref": "pkg:generic/empty-primary@1.0.0"
    }
  },
  "components": [],
  "dependencies": []
}
`)

// Secondary with no components
var secondaryNoComponents = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:secondary-no-components",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "library",
      "name": "empty-secondary",
      "version": "1.0.0",
      "bom-ref": "pkg:npm/empty-secondary@1.0.0"
    }
  },
  "components": [],
  "dependencies": []
}
`)

// Primary with no primary component
var primaryNoPrimary = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:no-primary",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z"
  },
  "components": []
}
`)

// parseCDXBytes parses CycloneDX JSON bytes into a BOM
func parseCDXBytes(data []byte) (*cydx.BOM, error) {
	bom := new(cydx.BOM)
	decoder := cydx.NewBOMDecoder(bytes.NewReader(data), cydx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, err
	}
	return bom, nil
}

// Edge Case 1: One primary + one secondary
func TestAssemblyMergeWithPrimary_OneSecondary(t *testing.T) {
	ctx := setupTestContext()

	primaryBOM, err := parseCDXBytes(primarySBOM)
	if err != nil {
		t.Fatalf("failed to parse primary SBOM: %v", err)
	}
	secondaryBOM, err := parseCDXBytes(secondarySBOM)
	if err != nil {
		t.Fatalf("failed to parse secondary SBOM: %v", err)
	}

	ms := &MergeSettings{
		Ctx:   &ctx,
		Input: input{Files: []string{"primary.cdx.json", "secondary.cdx.json"}},
		Assemble: assemble{
			IsAssemblyMergeWithPrimary: true,
			PrimaryFile:                "primary.cdx.json",
		},
	}

	m := newMerge(ms)
	m.in = []*cydx.BOM{primaryBOM, secondaryBOM}
	cs := newUniqueComponentService(ctx)

	compList := buildComponentList(m.in, cs)
	depList := buildDependencyList(m.in, cs)

	if err := m.assemblyMergeWithPrimary(cs, compList, depList); err != nil {
		t.Fatalf("assemblyMergeWithPrimary failed: %v", err)
	}

	t.Run("serial number preserved", func(t *testing.T) {
		if m.out.SerialNumber != "urn:uuid:11111111-1111-1111-1111-111111111111" {
			t.Errorf("expected serial number preserved, got %s", m.out.SerialNumber)
		}
	})

	t.Run("primary is document root", func(t *testing.T) {
		if m.out.Metadata.Component == nil {
			t.Fatal("expected metadata.component to be set")
		}
		if m.out.Metadata.Component.Name != "primary-app" {
			t.Errorf("expected primary-app as root, got %s", m.out.Metadata.Component.Name)
		}
	})

	t.Run("secondary is sub-component", func(t *testing.T) {
		if m.out.Metadata.Component.Components == nil {
			t.Fatal("expected sub-components to be set")
		}
		if len(*m.out.Metadata.Component.Components) != 1 {
			t.Fatalf("expected 1 sub-component, got %d", len(*m.out.Metadata.Component.Components))
		}
		subComp := (*m.out.Metadata.Component.Components)[0]
		if subComp.Name != "secondary-pkg" {
			t.Errorf("expected secondary-pkg, got %s", subComp.Name)
		}
	})

	t.Run("all non-primary components in flat list", func(t *testing.T) {
		if m.out.Components == nil {
			t.Fatal("expected components to be set")
		}
		// Should have lib1, lib2, dep-a, dep-b (4 components)
		if len(*m.out.Components) != 4 {
			t.Errorf("expected 4 components, got %d", len(*m.out.Components))
		}
	})

	t.Run("secondary not in flat components", func(t *testing.T) {
		for _, comp := range *m.out.Components {
			if comp.Name == "secondary-pkg" {
				t.Error("secondary primary should not be in flat components")
			}
		}
	})

	t.Run("metadata preserved", func(t *testing.T) {
		if m.out.Metadata.Supplier == nil || m.out.Metadata.Supplier.Name != "Primary Supplier" {
			t.Error("expected supplier metadata preserved")
		}
		if m.out.Metadata.Licenses == nil || len(*m.out.Metadata.Licenses) != 1 {
			t.Error("expected licenses metadata preserved")
		}
	})
}

// Edge Case 2: One primary + two secondaries
func TestAssemblyMergeWithPrimary_TwoSecondaries(t *testing.T) {
	ctx := setupTestContext()

	primaryBOM, _ := parseCDXBytes(primarySBOM)
	secondaryBOM1, _ := parseCDXBytes(secondarySBOM)
	secondaryBOM2, _ := parseCDXBytes(secondary2SBOM)

	ms := &MergeSettings{
		Ctx:   &ctx,
		Input: input{Files: []string{"primary.cdx.json", "secondary1.cdx.json", "secondary2.cdx.json"}},
		Assemble: assemble{
			IsAssemblyMergeWithPrimary: true,
			PrimaryFile:                "primary.cdx.json",
		},
	}

	m := newMerge(ms)
	m.in = []*cydx.BOM{primaryBOM, secondaryBOM1, secondaryBOM2}
	cs := newUniqueComponentService(ctx)

	compList := buildComponentList(m.in, cs)
	depList := buildDependencyList(m.in, cs)

	if err := m.assemblyMergeWithPrimary(cs, compList, depList); err != nil {
		t.Fatalf("assemblyMergeWithPrimary failed: %v", err)
	}

	t.Run("two sub-components", func(t *testing.T) {
		if m.out.Metadata.Component.Components == nil {
			t.Fatal("expected sub-components to be set")
		}
		if len(*m.out.Metadata.Component.Components) != 2 {
			t.Errorf("expected 2 sub-components, got %d", len(*m.out.Metadata.Component.Components))
		}
	})

	t.Run("dependencies exist", func(t *testing.T) {
		if m.out.Dependencies == nil || len(*m.out.Dependencies) == 0 {
			t.Error("expected dependencies to be set")
		}
	})
}

// Edge Case 3: Primary SBOM with no components
func TestAssemblyMergeWithPrimary_NoPrimaryComponents(t *testing.T) {
	ctx := setupTestContext()

	primaryBOM, _ := parseCDXBytes(primaryNoComponents)
	secondaryBOM, _ := parseCDXBytes(secondarySBOM)

	ms := &MergeSettings{
		Ctx:   &ctx,
		Input: input{Files: []string{"primary.cdx.json", "secondary.cdx.json"}},
		Assemble: assemble{
			IsAssemblyMergeWithPrimary: true,
			PrimaryFile:                "primary.cdx.json",
		},
	}

	m := newMerge(ms)
	m.in = []*cydx.BOM{primaryBOM, secondaryBOM}
	cs := newUniqueComponentService(ctx)

	compList := buildComponentList(m.in, cs)
	depList := buildDependencyList(m.in, cs)

	if err := m.assemblyMergeWithPrimary(cs, compList, depList); err != nil {
		t.Fatalf("assemblyMergeWithPrimary failed: %v", err)
	}

	t.Run("secondary components only", func(t *testing.T) {
		if m.out.Components == nil {
			t.Fatal("expected components to be set")
		}
		if len(*m.out.Components) != 2 { // dep-a, dep-b from secondary
			t.Errorf("expected 2 components, got %d", len(*m.out.Components))
		}
	})

	t.Run("secondary is sub-component", func(t *testing.T) {
		if m.out.Metadata.Component.Components == nil {
			t.Fatal("expected sub-components to be set")
		}
		if len(*m.out.Metadata.Component.Components) != 1 {
			t.Errorf("expected 1 sub-component, got %d", len(*m.out.Metadata.Component.Components))
		}
	})
}

// Edge Case 4: Secondary SBOM with no components
func TestAssemblyMergeWithPrimary_NoSecondaryComponents(t *testing.T) {
	ctx := setupTestContext()

	primaryBOM, _ := parseCDXBytes(primarySBOM)
	secondaryBOM, _ := parseCDXBytes(secondaryNoComponents)

	ms := &MergeSettings{
		Ctx:   &ctx,
		Input: input{Files: []string{"primary.cdx.json", "secondary.cdx.json"}},
		Assemble: assemble{
			IsAssemblyMergeWithPrimary: true,
			PrimaryFile:                "primary.cdx.json",
		},
	}

	m := newMerge(ms)
	m.in = []*cydx.BOM{primaryBOM, secondaryBOM}
	cs := newUniqueComponentService(ctx)

	compList := buildComponentList(m.in, cs)
	depList := buildDependencyList(m.in, cs)

	if err := m.assemblyMergeWithPrimary(cs, compList, depList); err != nil {
		t.Fatalf("assemblyMergeWithPrimary failed: %v", err)
	}

	t.Run("secondary is sub-component", func(t *testing.T) {
		if m.out.Metadata.Component.Components == nil {
			t.Fatal("expected sub-components to be set")
		}
		if len(*m.out.Metadata.Component.Components) != 1 {
			t.Errorf("expected 1 sub-component, got %d", len(*m.out.Metadata.Component.Components))
		}
		subComp := (*m.out.Metadata.Component.Components)[0]
		if subComp.Name != "empty-secondary" {
			t.Errorf("expected empty-secondary, got %s", subComp.Name)
		}
	})
}

// Edge Case 5: Error - Primary SBOM with no primary component
func TestAssemblyMergeWithPrimary_ErrorNoPrimaryComponent(t *testing.T) {
	ctx := setupTestContext()

	primaryBOM, _ := parseCDXBytes(primaryNoPrimary)
	secondaryBOM, _ := parseCDXBytes(secondarySBOM)

	ms := &MergeSettings{
		Ctx:   &ctx,
		Input: input{Files: []string{"primary.cdx.json", "secondary.cdx.json"}},
		Assemble: assemble{
			IsAssemblyMergeWithPrimary: true,
			PrimaryFile:                "primary.cdx.json",
		},
	}

	m := newMerge(ms)
	m.in = []*cydx.BOM{primaryBOM, secondaryBOM}
	cs := newUniqueComponentService(ctx)

	compList := buildComponentList(m.in, cs)
	depList := buildDependencyList(m.in, cs)

	err := m.assemblyMergeWithPrimary(cs, compList, depList)
	if err == nil {
		t.Fatal("expected error for primary with no primary component")
	}
	if !strings.Contains(err.Error(), "no primary component") {
		t.Errorf("expected error message to contain 'no primary component', got: %v", err)
	}
}

// Helper functions

var testLoggerOnce sync.Once

func setupTestContext() context.Context {
	testLoggerOnce.Do(func() {
		logger.InitProdLogger()
	})
	return logger.WithLogger(context.Background())
}
