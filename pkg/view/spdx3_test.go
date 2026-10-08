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

package view

import (
	"strings"
	"testing"

	"github.com/interlynk-io/spdx-zen/parse"
)

func TestSPDX3Viewer_ParseAndEnrich(t *testing.T) {
	viewer := NewSPDX3Viewer()
	input := strings.NewReader(spdx3TestDoc)

	graph, err := viewer.ParseAndEnrich(input)
	if err != nil {
		t.Fatalf("ParseAndEnrich failed: %v", err)
	}

	// Check metadata
	if graph.Metadata.Format != "SPDX-3.0" {
		t.Errorf("Metadata.Format = %q, want SPDX-3.0", graph.Metadata.Format)
	}
	if graph.Metadata.SpecVersion != "3.0.1" {
		t.Errorf("Metadata.SpecVersion = %q, want 3.0.1", graph.Metadata.SpecVersion)
	}

	// Check all components are present
	if len(graph.AllNodes) != 3 {
		t.Errorf("AllNodes count = %d, want 3", len(graph.AllNodes))
	}

	// Check primary component
	if graph.Primary == nil {
		t.Fatal("Primary component is nil")
	}
	if graph.Primary.Name != "dropwizard-core" {
		t.Errorf("Primary.Name = %q, want dropwizard-core", graph.Primary.Name)
	}
	if !graph.Primary.IsPrimary {
		t.Error("Primary.IsPrimary = false, want true")
	}

	// Check assembly tree
	if len(graph.Primary.Children) != 2 {
		t.Errorf("Primary.Children count = %d, want 2", len(graph.Primary.Children))
	}

	// Check dependency graph
	assetsDeps := graph.DepGraph["https://example.org/pkg/dropwizard-assets"]
	if len(assetsDeps) != 1 || assetsDeps[0] != "https://example.org/pkg/dropwizard-auth" {
		t.Errorf("assets deps = %v, want [https://example.org/pkg/dropwizard-auth]", assetsDeps)
	}

	// Check license
	coreComp := graph.AllNodes["https://example.org/pkg/dropwizard-core"]
	if len(coreComp.Licenses) != 1 {
		t.Errorf("core licenses = %d, want 1", len(coreComp.Licenses))
	} else if coreComp.Licenses[0].Name != "Apache-2.0" {
		t.Errorf("core license name = %q, want Apache-2.0", coreComp.Licenses[0].Name)
	}

	// Check supplier
	if coreComp.Supplier != "Dropwizard Project" {
		t.Errorf("core supplier = %q, want Dropwizard Project", coreComp.Supplier)
	}

	// Check hashes
	if len(coreComp.Hashes) != 1 {
		t.Errorf("core hashes = %d, want 1", len(coreComp.Hashes))
	} else if coreComp.Hashes[0].Algorithm != "sha256" {
		t.Errorf("core hash algo = %q, want sha256", coreComp.Hashes[0].Algorithm)
	}
}

func TestBuildSPDX3Graph_Licenses(t *testing.T) {
	reader := parse.NewReader()
	doc, err := reader.FromReader(strings.NewReader(spdx3TestDoc))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	graph, err := buildSPDX3Graph(doc)
	if err != nil {
		t.Fatalf("buildSPDX3Graph failed: %v", err)
	}

	core := graph.AllNodes["https://example.org/pkg/dropwizard-core"]
	if core == nil {
		t.Fatal("core component not found")
	}

	if len(core.Licenses) != 1 {
		t.Fatalf("licenses count = %d, want 1", len(core.Licenses))
	}

	lic := core.Licenses[0]
	if lic.Name != "Apache-2.0" {
		t.Errorf("license.Name = %q, want Apache-2.0", lic.Name)
	}
	if lic.ID != "https://example.org/lic/apache20" {
		t.Errorf("license.ID = %q, want https://example.org/lic/apache20", lic.ID)
	}
}

func TestBuildSPDX3Graph_AssemblyTree(t *testing.T) {
	reader := parse.NewReader()
	doc, err := reader.FromReader(strings.NewReader(spdx3TestDoc))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	graph, err := buildSPDX3Graph(doc)
	if err != nil {
		t.Fatalf("buildSPDX3Graph failed: %v", err)
	}

	// Primary should have 2 children via contains relationships
	if len(graph.Primary.Children) != 2 {
		t.Errorf("primary children = %d, want 2", len(graph.Primary.Children))
	}

	// Check parent links
	assets := graph.AllNodes["https://example.org/pkg/dropwizard-assets"]
	if assets == nil {
		t.Fatal("assets component not found")
	}
	if assets.Parent == nil {
		t.Fatal("assets.Parent is nil")
	}
	if assets.Parent.Name != "dropwizard-core" {
		t.Errorf("assets.Parent.Name = %q, want dropwizard-core", assets.Parent.Name)
	}
}

func TestBuildSPDX3Graph_Dependencies(t *testing.T) {
	reader := parse.NewReader()
	doc, err := reader.FromReader(strings.NewReader(spdx3TestDoc))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	graph, err := buildSPDX3Graph(doc)
	if err != nil {
		t.Fatalf("buildSPDX3Graph failed: %v", err)
	}

	// dropwizard-assets dependsOn dropwizard-auth
	assets := graph.AllNodes["https://example.org/pkg/dropwizard-assets"]
	if assets == nil {
		t.Fatal("assets component not found")
	}
	if assets.DependencyCount != 1 {
		t.Errorf("assets.DependencyCount = %d, want 1", assets.DependencyCount)
	}

	// Verify DepGraph
	deps := graph.DepGraph["https://example.org/pkg/dropwizard-assets"]
	if len(deps) != 1 || deps[0] != "https://example.org/pkg/dropwizard-auth" {
		t.Errorf("depgraph[assets] = %v, want [https://example.org/pkg/dropwizard-auth]", deps)
	}
}

const spdx3TestDoc = `{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "https://example.org/doc/test",
      "creationInfo": "_:creationinfo",
      "name": "Test Document",
      "profileConformance": ["core", "software"],
      "rootElement": ["https://example.org/pkg/dropwizard-core"]
    },
    {
      "type": "CreationInfo",
      "spdxId": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2025-01-15T10:00:00Z",
      "createdBy": ["https://example.org/tool/sbomasm"]
    },
    {
      "type": "Tool",
      "spdxId": "https://example.org/tool/sbomasm",
      "creationInfo": "_:creationinfo",
      "name": "sbomasm"
    },
    {
      "type": "Organization",
      "spdxId": "https://example.org/org/dropwizard",
      "creationInfo": "_:creationinfo",
      "name": "Dropwizard Project"
    },
    {
      "type": "Person",
      "spdxId": "https://example.org/person/author1",
      "creationInfo": "_:creationinfo",
      "name": "John Doe"
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg/dropwizard-core",
      "creationInfo": "_:creationinfo",
      "name": "dropwizard-core",
      "software_packageVersion": "2.0.31",
      "software_primaryPurpose": "application",
      "description": "Dropwizard is a Java framework.",
      "software_copyrightText": "Copyright 2025",
      "externalIdentifier": [
        {
          "type": "ExternalIdentifier",
          "externalIdentifierType": "packageUrl",
          "identifier": "pkg:maven/io.dropwizard/dropwizard-core@2.0.31"
        }
      ],
      "suppliedBy": "https://example.org/org/dropwizard",
      "originatedBy": ["https://example.org/person/author1"],
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha256",
          "hashValue": "abc123def456"
        }
      ]
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg/dropwizard-assets",
      "creationInfo": "_:creationinfo",
      "name": "dropwizard-assets",
      "software_packageVersion": "2.0.31",
      "software_primaryPurpose": "library",
      "externalIdentifier": [
        {
          "type": "ExternalIdentifier",
          "externalIdentifierType": "packageUrl",
          "identifier": "pkg:maven/io.dropwizard/dropwizard-assets@2.0.31"
        }
      ]
    },
    {
      "type": "software_Package",
      "spdxId": "https://example.org/pkg/dropwizard-auth",
      "creationInfo": "_:creationinfo",
      "name": "dropwizard-auth",
      "software_packageVersion": "2.0.31",
      "software_primaryPurpose": "library",
      "externalIdentifier": [
        {
          "type": "ExternalIdentifier",
          "externalIdentifierType": "packageUrl",
          "identifier": "pkg:maven/io.dropwizard/dropwizard-auth@2.0.31"
        }
      ]
    },
    {
      "type": "Relationship",
      "spdxId": "https://example.org/rel/contains-assets",
      "creationInfo": "_:creationinfo",
      "relationshipType": "contains",
      "from": "https://example.org/pkg/dropwizard-core",
      "to": ["https://example.org/pkg/dropwizard-assets"]
    },
    {
      "type": "Relationship",
      "spdxId": "https://example.org/rel/contains-auth",
      "creationInfo": "_:creationinfo",
      "relationshipType": "contains",
      "from": "https://example.org/pkg/dropwizard-core",
      "to": ["https://example.org/pkg/dropwizard-auth"]
    },
    {
      "type": "Relationship",
      "spdxId": "https://example.org/rel/depends-auth",
      "creationInfo": "_:creationinfo",
      "relationshipType": "dependsOn",
      "from": "https://example.org/pkg/dropwizard-assets",
      "to": ["https://example.org/pkg/dropwizard-auth"]
    },
    {
      "type": "SimpleLicensingText",
      "spdxId": "https://example.org/lic/apache20",
      "creationInfo": "_:creationinfo",
      "name": "Apache-2.0"
    },
    {
      "type": "Relationship",
      "spdxId": "https://example.org/rel/core-license",
      "creationInfo": "_:creationinfo",
      "relationshipType": "hasConcludedLicense",
      "from": "https://example.org/pkg/dropwizard-core",
      "to": ["https://example.org/lic/apache20"]
    }
  ]
}`
