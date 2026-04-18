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
	"path/filepath"
)

// Generate is the main entry point for generating an SBOM. It does the following steps:
// - Load artifact metadata from config file and map to internal model
// - Collect input component files (explicit or recursive)
// - Parse component files into internal component model
// - Merge all components into a single list
// - Deduplicate components and collect warnings for duplicates
// - Prepare final component list by Filtering components by tags
// - Compute file/directory hashes for each component list (done per-file so relative paths resolve correctly)
// - Build dependency graph based on "dependency-of" references
// - Build BOM model from artifact, components, and dependency graph
// - Serialize BOM to output file in specified format (CycloneDX or SPDX)
func Generate(params *GenerateSBOMParams) error {
	var warnings []error

	// 1. Load artifact from config: `.artifact-metadata.yaml`
	artifact, err := LoadArtifactConfig(params.ConfigPath)
	if err != nil {
		return err
	}

	// Collect input files: `.components.json` (explicit/recursive)
	// `.components.json` files contain component information
	files, warn := CollectInputFiles(params)
	warnings = append(warnings, warn...)

	if len(files) == 0 {
		return fmt.Errorf("no component files found in input paths")
	}

	// Parse component files into internal component model
	// it returns list of components present in each files
	componentLists, warn := ParseComponentFiles(files)
	warnings = append(warnings, warn...)

	// Compute file/directory hashes for each component list
	// Hash computation is done per-file so relative paths resolve correctly
	for i, file := range files {
		if i < len(componentLists) {
			manifestDir := filepath.Dir(file)
			hashErrs := ComputeHashes(componentLists[i], manifestDir)
			warnings = append(warnings, hashErrs...)
		}
	}

	// Merge all components into a single list
	componentMergedLists := MergeAll(componentLists)
	if len(componentMergedLists) == 0 {
		return fmt.Errorf("no components found in input files")
	}

	// Process pedigree information for all components
	// This loads patch files and validates purl vs ancestor purl
	for i, file := range files {
		if i < len(componentLists) {
			manifestDir := filepath.Dir(file)
			pedigreeErrs := ProcessPedigrees(componentLists[i], manifestDir)
			warnings = append(warnings, pedigreeErrs...)
		}
	}

	// Dedup components and collect warnings for duplicates
	componentUniqueLists, warn := DeduplicateComponents(componentMergedLists)
	warnings = append(warnings, warn...)

	// 2. Final component list(post filtering components by tags)
	componentFileteredLists := FilterComponents(componentUniqueLists, params.Tags, params.ExcludeTags)
	if len(componentFileteredLists) == 0 && len(componentUniqueLists) > 0 {
		return fmt.Errorf("no components left after applying tag filters")
	}

	// Lookup map for components by name@version for easy reference
	compMap := BuildComponentMap(componentFileteredLists)

	// 3. Dependency graph to build parent-child relationships
	graph, warn := BuildDependencyGraph(componentFileteredLists, compMap, artifact)
	warnings = append(warnings, warn...)

	// Build BOM model from artifact, components, and dependency graph
	bom := BuildBOM(artifact, componentFileteredLists, graph)

	// Serialize BOM to output file in specified format (CycloneDX or SPDX)
	err = Serialize(params.Format, bom, params.Output)

	// Print warnings
	defer func() {
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "warning: %v\n", w)
		}
	}()

	if err != nil {
		return err
	}

	return nil
}
