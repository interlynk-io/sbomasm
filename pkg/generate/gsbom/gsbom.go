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
	var errors []error

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

	// Apply artifact output config if CLI flags weren't explicitly set
	if !params.FormatSet && artifact.OutputConfig.Spec != "" {
		params.Format = artifact.OutputConfig.Spec
		log.Debugf("using format from artifact config: %s", params.Format)
	}

	if !params.SpecVersionSet && artifact.OutputConfig.SpecVersion != "" {
		params.SpecVersion = artifact.OutputConfig.SpecVersion
		log.Debugf("using spec version from artifact config: %s", params.SpecVersion)
	}

	// Collect input files: `.components.json` (explicit/recursive)
	// `.components.json` files contain component information
	log.Debugf("collecting input files: input=%v, recurse=%s", params.InputFiles, params.RecursePath)

	explicitFiles, discoveredFiles, fErr := CollectInputFiles(params)
	// Check for errors from collection (e.g., explicit file without schema)
	if len(fErr) > 0 {
		return fmt.Errorf("error during file collection: %v", fErr[0])
	}

	allFiles := append(explicitFiles, discoveredFiles...)
	log.Debugf("found %d component files (%d explicit, %d discovered)", len(allFiles), len(explicitFiles), len(discoveredFiles))

	if len(allFiles) == 0 {
		return fmt.Errorf("no component files found in input paths")
	}

	log.Debugf("parsing %d component files", len(allFiles))

	// Parse component files into internal component model
	componentLists, parseErrs := ParseComponentFiles(allFiles)
	if len(parseErrs) > 0 {
		return fmt.Errorf("component validation failed: %v", parseErrs[0])
	}

	totalComponents := 0
	for _, list := range componentLists {
		totalComponents += len(list)
	}
	log.Debugf("parsed %d components from %d files", totalComponents, len(componentLists))

	// Compute file/directory hashes for each component list
	// Hash errors are hard failures per spec
	log.Debugf("computing hashes for components")

	for i, list := range componentLists {
		if len(list) > 0 && list[0].SourcePath != "" {
			manifestDir := filepath.Dir(list[0].SourcePath)

			hashErrs := ComputeHashes(componentLists[i], manifestDir)
			if len(hashErrs) > 0 {
				return fmt.Errorf("hash computation failed: %v", hashErrs[0])
			}
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
	// Pedigree errors are hard failures
	log.Debugf("processing pedigree information")

	for i, list := range componentLists {
		if len(list) > 0 && list[0].SourcePath != "" {
			manifestDir := filepath.Dir(list[0].SourcePath)

			pedigreeErrs := ProcessPedigrees(componentLists[i], manifestDir)
			if len(pedigreeErrs) > 0 {
				return fmt.Errorf("pedigree processing failed: %v", pedigreeErrs[0])
			}
		}
	}

	// Dedup components and collect warnings for duplicates
	componentUniqueLists, warn := DeduplicateComponents(componentMergedLists)
	errors = append(errors, warn...)

	log.Debugf("deduplicated to %d unique components", len(componentUniqueLists))

	// 2. Final component list(post filtering components by tags)
	log.Debugf("filtering components: tags=%v, exclude-tags=%v", params.Tags, params.ExcludeTags)

	componentFileteredLists := FilterComponents(componentUniqueLists, params.Tags, params.ExcludeTags)
	log.Debugf("filtered to %d components", len(componentFileteredLists))

	if len(componentFileteredLists) == 0 && len(componentUniqueLists) > 0 {
		return fmt.Errorf("no components left after applying tag filters")
	}

	// Lookup map for components by name@version for easy reference
	compMap := BuildComponentMap(componentFileteredLists)

	// 3. Dependency graph to build parent-child relationships
	graph, warn := BuildDependencyGraph(componentFileteredLists, compMap, artifact)
	errors = append(errors, warn...)

	log.Debugf("built dependency graph: %d dependencies", len(graph.Edges))

	// Build BOM model from artifact, components, and dependency graph
	bom := BuildBOM(artifact, componentFileteredLists, graph)
	log.Debugf("built BOM: %d components, format=%s", len(bom.Components), params.Format)

	log.Debugf("running strict checks: strict=%v", params.Strict)

	strictWarnings, err := ValidateStrictChecks(params.Ctx, componentFileteredLists, params.Strict)
	if err != nil {
		// Strict mode: return error
		log.Infof("strict mode validation failed with %d warnings", len(strictWarnings))
		return fmt.Errorf("strict mode validation failed: %v", err)
	}

	log.Debugf("strict checks completed: %d warnings", len(strictWarnings))
	errors = append(errors, strictWarnings...)

	// Serialize BOM to output file in specified format (CycloneDX or SPDX)
	log.Debugf("serializing BOM: format=%s, output=%s, specVersion=%s", params.Format, params.Output, params.SpecVersion)
	err = Serialize(*params.Ctx, params.Format, bom, params.Output, params.SpecVersion)

	// Print warnings
	defer func() {
		for _, w := range errors {
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
