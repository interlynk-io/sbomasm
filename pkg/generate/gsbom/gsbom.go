// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gsbom

import (
	"fmt"
	"os"

	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

// Generate is the main entry point for generating an SBOM. It does the following steps:
// - Load artifact metadata from config file and map to internal model
// - Collect input component files (explicit or recursive)
// - Parse component files into internal component model
// - Merge all components into a single list
// - Deduplicate components and collect warnings for duplicates
// - Prepare final component list by Filtering components by tags
// - Build dependency graph based on "dependency-of" references
// - Build BOM model from artifact, components, and dependency graph
// - Serialize BOM to output file in specified format (CycloneDX or SPDX)
func Generate(params *GenerateSBOMParams) error {
	var errors []error

	// Load config: `.artifact-metadata.yaml`
	// artifact refers to the primary component information
	artifact, err := LoadArtifactConfig(params.ConfigPath)
	if err != nil {
		return err
	}

	// Collect input files: `.components.json` (explicit/recursive)
	// `.components.json` files contain component information
	files, warn := CollectInputFiles(params)
	errors = append(errors, warn...)

	// Parse component files into intrnal component model
	// it returns list of components of each files
	groups, warn := ParseComponentFiles(files)
	errors = append(errors, warn...)

	// Merge all components into a single list
	merged := MergeAll(groups)

	// Dedup components and collect warnings for duplicates
	components, warn := DeduplicateComponents(merged)
	errors = append(errors, warn...)

	// Filter components by tags
	components = FilterComponents(components, params.Tags, params.ExcludeTags)

	// Lookup map for components by name@version for easy reference
	compMap := BuildComponentMap(components)

	// Dependency graph to build parent-child relationships
	// based on "dependency-of" references
	graph, warn := BuildDependencyGraph(components, compMap)
	errors = append(errors, warn...)

	// Build BOM model from artifact, components, and dependency graph
	bom := BuildBOM(artifact, components, graph)

	// Serialize: default to CycloneDX, but support SPDX
	switch params.Format {
	case string(sbom.SBOMSpecSPDX):
		err = SerializeSPDX(bom, params.Output)
	default:
		err = SerializeCycloneDX(bom, params.Output)
	}

	if err != nil {
		return err
	}

	// Print warnings
	for _, w := range errors {
		fmt.Fprintf(os.Stderr, "warning: %v\n", w)
	}

	return nil
}
