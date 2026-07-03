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
	"testing"

	cydx "github.com/CycloneDX/cyclonedx-go"
)

// Test SBOMs as JSON byte slices for flat merge with primary

// Primary SBOM: Python wheel with 2 components
var flatPrimarySBOM = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "name": "python-wheel",
      "version": "1.0.0",
      "bom-ref": "pkg:pypi/python-wheel@1.0.0"
    },
    "supplier": {
      "name": "Python Supplier"
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
      "name": "numpy",
      "version": "1.24.0",
      "bom-ref": "pkg:pypi/numpy@1.24.0",
      "purl": "pkg:pypi/numpy@1.24.0",
      "isExternal": true
    },
    {
      "type": "library",
      "name": "requests",
      "version": "2.28.0",
      "bom-ref": "pkg:pypi/requests@2.28.0",
      "purl": "pkg:pypi/requests@2.28.0",
      "isExternal": true
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:pypi/python-wheel@1.0.0",
      "dependsOn": [
        "pkg:pypi/numpy@1.24.0",
        "pkg:pypi/requests@2.28.0"
      ]
    }
  ]
}
`)

// Secondary SBOM: JavaScript bundle
var flatSecondarySBOM = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "name": "js-bundle",
      "version": "0.0.1",
      "bom-ref": "pkg:npm/js-bundle@0.0.1"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "react",
      "version": "18.2.0",
      "bom-ref": "pkg:npm/react@18.2.0",
      "purl": "pkg:npm/react@18.2.0"
    },
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      "purl": "pkg:npm/lodash@4.17.21"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/js-bundle@0.0.1",
      "dependsOn": [
        "pkg:npm/react@18.2.0",
        "pkg:npm/lodash@4.17.21"
      ]
    }
  ]
}
`)

// Secondary SBOM 2: CSS assets
var flatSecondary2SBOM = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "name": "css-assets",
      "version": "1.0.0",
      "bom-ref": "pkg:generic/css-assets@1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "bootstrap",
      "version": "5.3.0",
      "bom-ref": "pkg:npm/bootstrap@5.3.0",
      "purl": "pkg:npm/bootstrap@5.3.0"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:generic/css-assets@1.0.0",
      "dependsOn": [
        "pkg:npm/bootstrap@5.3.0"
      ]
    }
  ]
}
`)

// parseCDXBytesForFlat parses CycloneDX JSON bytes into a BOM (for flat merge tests)
func parseCDXBytesForFlat(data []byte) (*cydx.BOM, error) {
	bom := new(cydx.BOM)
	decoder := cydx.NewBOMDecoder(bytes.NewReader(data), cydx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, err
	}
	return bom, nil
}

// Test: Basic flat merge with primary - 1 secondary
func TestFlatMergeWithPrimary_OneSecondary(t *testing.T) {
	ctx := setupTestContext()

	primary, err := parseCDXBytesForFlat(flatPrimarySBOM)
	if err != nil {
		t.Fatalf("failed to parse primary SBOM: %v", err)
	}
	secondary, err := parseCDXBytesForFlat(flatSecondarySBOM)
	if err != nil {
		t.Fatalf("failed to parse secondary SBOM: %v", err)
	}

	ms := &MergeSettings{
		Ctx:   &ctx,
		Input: input{Files: []string{"secondary.cdx.json"}},
		Assemble: assemble{
			FlatMerge:              true,
			IsFlatMergeWithPrimary: true,
			PrimaryFile:            "primary.cdx.json",
		},
	}

	m := newMerge(ms)
	m.in = []*cydx.BOM{primary, secondary}
	cs := newUniqueComponentService(ctx)

	priCompList := buildPrimaryComponentList(m.in, cs)
	compList := buildComponentList(m.in, cs)
	_ = buildDependencyList(m.in, cs) // Not used in this test

	// Initialize from primary
	m.initOutBomFromPrimary(primary)
	m.out.Metadata.Component = m.extractPrimaryComponent(primary)

	// Flat merge - filter out primary component (it's the document root)
	// Filter by name+version since StoreAndCloneWithNewID generates new BOMRefs
	primaryName := m.out.Metadata.Component.Name
	primaryVersion := m.out.Metadata.Component.Version
	filteredPriCompList := make([]cydx.Component, 0)
	for _, c := range priCompList {
		if !(c.Name == primaryName && c.Version == primaryVersion) {
			filteredPriCompList = append(filteredPriCompList, c)
		}
	}
	finalCompList := append(filteredPriCompList, compList...)
	m.out.Components = &finalCompList

	// Assertions
	t.Run("serial number preserved from primary", func(t *testing.T) {
		if m.out.SerialNumber != "urn:uuid:11111111-1111-1111-1111-111111111111" {
			t.Errorf("expected primary serial number, got %s", m.out.SerialNumber)
		}
	})

	t.Run("primary component is document root", func(t *testing.T) {
		if m.out.Metadata.Component == nil {
			t.Fatal("expected metadata.component to be set")
		}
		if m.out.Metadata.Component.Name != "python-wheel" {
			t.Errorf("expected python-wheel as root, got %s", m.out.Metadata.Component.Name)
		}
	})

	t.Run("primary component not marked isExternal", func(t *testing.T) {
		if m.out.Metadata.Component.IsExternal != nil && *m.out.Metadata.Component.IsExternal {
			t.Error("primary component should not have isExternal=true")
		}
	})

	t.Run("all components in flat list", func(t *testing.T) {
		if m.out.Components == nil {
			t.Fatal("expected components to be set")
		}
		// Should have 5 components: js-bundle (secondary primary) + numpy, requests, react, lodash
		// Primary component (python-wheel) is NOT in flat list - it's the document root
		if len(*m.out.Components) != 5 {
			t.Errorf("expected 5 components, got %d", len(*m.out.Components))
		}
	})

	t.Run("isExternal preserved from source", func(t *testing.T) {
		externalCount := 0
		for _, comp := range *m.out.Components {
			if comp.IsExternal != nil && *comp.IsExternal {
				externalCount++
			}
		}
		// numpy and requests have isExternal=true
		if externalCount != 2 {
			t.Errorf("expected 2 components with isExternal=true, got %d", externalCount)
		}
	})

	t.Run("metadata preserved from primary", func(t *testing.T) {
		if m.out.Metadata.Supplier == nil || m.out.Metadata.Supplier.Name != "Python Supplier" {
			t.Error("expected supplier metadata preserved")
		}
		if m.out.Metadata.Licenses == nil || len(*m.out.Metadata.Licenses) != 1 {
			t.Error("expected licenses metadata preserved")
		}
	})
}

// Test: Flat merge with primary - 2 secondaries
func TestFlatMergeWithPrimary_TwoSecondaries(t *testing.T) {
	ctx := setupTestContext()

	primary, _ := parseCDXBytes(flatPrimarySBOM)
	secondary1, _ := parseCDXBytes(flatSecondarySBOM)
	secondary2, _ := parseCDXBytesForFlat(flatSecondary2SBOM)

	ms := &MergeSettings{
		Ctx:   &ctx,
		Input: input{Files: []string{"secondary1.cdx.json", "secondary2.cdx.json"}},
		Assemble: assemble{
			FlatMerge:              true,
			IsFlatMergeWithPrimary: true,
			PrimaryFile:            "primary.cdx.json",
		},
	}

	m := newMerge(ms)
	m.in = []*cydx.BOM{primary, secondary1, secondary2}
	cs := newUniqueComponentService(ctx)

	priCompList := buildPrimaryComponentList(m.in, cs)
	compList := buildComponentList(m.in, cs)
	depList := buildDependencyList(m.in, cs)

	m.initOutBomFromPrimary(primary)
	m.out.Metadata.Component = m.extractPrimaryComponent(primary)

	// Filter out primary component from flat list (it's the document root)
	// Filter by name+version since StoreAndCloneWithNewID generates new BOMRefs
	primaryName := m.out.Metadata.Component.Name
	primaryVersion := m.out.Metadata.Component.Version
	filteredPriCompList := make([]cydx.Component, 0)
	for _, c := range priCompList {
		if !(c.Name == primaryName && c.Version == primaryVersion) {
			filteredPriCompList = append(filteredPriCompList, c)
		}
	}
	finalCompList := append(filteredPriCompList, compList...)
	m.out.Components = &finalCompList

	t.Run("all 7 components in flat list", func(t *testing.T) {
		// Should have 7 components: js-bundle, css-assets (secondary primaries) + numpy, requests, react, lodash, bootstrap
		// Primary component (python-wheel) is NOT in flat list - it's the document root
		if len(*m.out.Components) != 7 {
			t.Errorf("expected 7 components, got %d", len(*m.out.Components))
		}
	})

	t.Run("dependencies exist", func(t *testing.T) {
		if len(depList) == 0 {
			t.Error("expected dependencies to be set")
		}
	})
}

// Test: Components without isExternal are treated as bundled
func TestFlatMergeWithPrimary_NoIsExternalComponents(t *testing.T) {
	ctx := setupTestContext()

	primary, _ := parseCDXBytes(flatSecondarySBOM) // Use JS as primary
	secondary, _ := parseCDXBytes(flatSecondary2SBOM)

	ms := &MergeSettings{
		Ctx:   &ctx,
		Input: input{Files: []string{"secondary.cdx.json"}},
		Assemble: assemble{
			FlatMerge:              true,
			IsFlatMergeWithPrimary: true,
			PrimaryFile:            "primary.cdx.json",
		},
	}

	m := newMerge(ms)
	m.in = []*cydx.BOM{primary, secondary}
	cs := newUniqueComponentService(ctx)

	priCompList := buildPrimaryComponentList(m.in, cs)
	compList := buildComponentList(m.in, cs)
	_ = buildDependencyList(m.in, cs) // Not used in this test

	m.initOutBomFromPrimary(primary)
	m.out.Metadata.Component = m.extractPrimaryComponent(primary)

	finalCompList := append(priCompList, compList...)
	m.out.Components = &finalCompList

	t.Run("no components have isExternal set", func(t *testing.T) {
		for _, comp := range *m.out.Components {
			if comp.IsExternal != nil {
				t.Errorf("component %s should not have isExternal", comp.Name)
			}
		}
	})
}
