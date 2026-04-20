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

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
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

	log := logger.FromContext(*params.Ctx)
	log.Debugf("starting SBOM generation: format=%s, output=%s", params.Format, params.Output)

	// 1. Load artifact from config: `.artifact-metadata.yaml`
	log.Debugf("loading artifact metadata from: %s", params.ConfigPath)
	artifact, err := LoadArtifactConfig(params.ConfigPath)
	if err != nil {
		log.Debugf("failed to load artifact config: %v", err)
		return err
	}
	log.Debugf("loaded artifact: %s@%s", artifact.Name, artifact.Version)

	// Collect input files: `.components.json` (explicit/recursive)
	// `.components.json` files contain component information
	log.Debugf("collecting input files: input=%v, recurse=%s", params.InputFiles, params.RecursePath)
	files, warn := CollectInputFiles(params)
	warnings = append(warnings, warn...)
	log.Debugf("found %d component files", len(files))

	if len(files) == 0 {
		return fmt.Errorf("no component files found in input paths")
	}

	// Parse component files into internal component model
	// it returns list of components present in each files
	log.Debugf("parsing %d component files", len(files))
	componentLists, warn := ParseComponentFiles(files)
	warnings = append(warnings, warn...)
	totalComponents := 0
	for _, list := range componentLists {
		totalComponents += len(list)
	}
	log.Debugf("parsed %d components from %d files", totalComponents, len(componentLists))

	// Compute file/directory hashes for each component list
	// Hash computation is done per-file so relative paths resolve correctly
	log.Debugf("computing hashes for components")
	for i, file := range files {
		if i < len(componentLists) {
			manifestDir := filepath.Dir(file)
			hashErrs := ComputeHashes(componentLists[i], manifestDir)
			warnings = append(warnings, hashErrs...)
		}
	}

	// Merge all components into a single list
	log.Debugf("merging %d component lists", len(componentLists))
	componentMergedLists := MergeAll(componentLists)
	log.Debugf("merged into %d total components", len(componentMergedLists))
	if len(componentMergedLists) == 0 {
		return fmt.Errorf("no components found in input files")
	}

	// Process pedigree information for all components
	// This loads patch files and validates purl vs ancestor purl
	log.Debugf("processing pedigree information")
	for i, file := range files {
		if i < len(componentLists) {
			manifestDir := filepath.Dir(file)
			pedigreeErrs := ProcessPedigrees(componentLists[i], manifestDir)
			warnings = append(warnings, pedigreeErrs...)
		}
	}

	// Dedup components and collect warnings for duplicates
	log.Debugf("deduplicating components")
	componentUniqueLists, warn := DeduplicateComponents(componentMergedLists)
	warnings = append(warnings, warn...)
	log.Debugf("deduplicated to %d unique components", len(componentUniqueLists))

	// 2. Final component list(post filtering components by tags)
	log.Debugf("filtering components: tags=%v, exclude-tags=%v", params.Tags, params.ExcludeTags)
	componentFileteredLists := FilterComponents(componentUniqueLists, params.Tags, params.ExcludeTags)
	log.Debugf("filtered to %d components", len(componentFileteredLists))
	if len(componentFileteredLists) == 0 && len(componentUniqueLists) > 0 {
		return fmt.Errorf("no components left after applying tag filters")
	}

	// Lookup map for components by name@version for easy reference
	log.Debugf("building component lookup map")
	compMap := BuildComponentMap(componentFileteredLists)
	log.Debugf("built map with %d entries", len(compMap))

	// 3. Dependency graph to build parent-child relationships
	log.Debugf("building dependency graph")
	graph, warn := BuildDependencyGraph(componentFileteredLists, compMap, artifact)
	warnings = append(warnings, warn...)
	log.Debugf("built dependency graph: %d dependencies", len(graph.Edges))

	// Build BOM model from artifact, components, and dependency graph
	log.Debugf("building BOM model")
	bom := BuildBOM(artifact, componentFileteredLists, graph)
	log.Debugf("built BOM: %d components, format=%s", len(bom.Components), params.Format)

	// Run strict checks on all components (warnings in default mode, errors in strict mode)
	// These include: missing license, vendored without pedigree, missing hashes,
	// missing distribution URL, library without supplier
	log.Debugf("running strict checks: strict=%v", params.Strict)
	strictWarnings, err := ValidateStrictChecks(params.Ctx, componentFileteredLists, params.Strict)
	if err != nil {
		// Strict mode: return error
		log.Infof("strict mode validation failed with %d warnings", len(strictWarnings))
		return fmt.Errorf("strict mode validation failed: %v", err)
	}
	log.Debugf("strict checks completed: %d warnings", len(strictWarnings))
	warnings = append(warnings, strictWarnings...)

	// Serialize BOM to output file in specified format (CycloneDX or SPDX)
	log.Debugf("serializing BOM: format=%s, output=%s, specVersion=%s", params.Format, params.Output, params.SpecVersion)
	err = Serialize(*params.Ctx, params.Format, bom, params.Output, params.SpecVersion)

	// Print warnings
	defer func() {
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "warning: %v\n", w)
		}
	}()

	if err != nil {
		log.Debugf("serialization failed: %v", err)
		return err
	}
	log.Infof("successfully generated SBOM: %s", params.Output)

	return nil
}
