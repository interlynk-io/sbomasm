package gsbom

import (
	"fmt"
	"os"
)

func Generate(params *GenerateSBOMParams) error {
	var errors []error

	// STEP 3: Load config
	artifact, err := LoadArtifactConfig(params.ConfigPath)
	if err != nil {
		return err
	}

	// STEP 4: Collect input files
	files, warn := CollectInputFiles(params)
	errors = append(errors, warn...)

	// STEP 5: Parse
	groups, warn := ParseComponentFiles(files)
	errors = append(errors, warn...)

	// STEP 6: Merge
	merged := MergeAll(groups)

	// STEP 7: Dedup
	components, warn := DeduplicateComponents(merged)
	errors = append(errors, warn...)

	// STEP 8: Filter
	components = FilterComponents(components, params.Tags, params.ExcludeTags)

	// STEP 9: Lookup map
	compMap := BuildComponentMap(components)

	// STEP 10: Dependency graph
	graph, warn := BuildDependencyGraph(components, compMap)
	errors = append(errors, warn...)

	// STEP 11: Build BOM
	bom := BuildBOM(artifact, components, graph)

	// STEP 12: Serialize
	switch params.Format {
	case "spdx":
		err = SerializeSPDX(bom, params.Output)
	default:
		err = SerializeCycloneDX(bom, params.Output)
	}

	if err != nil {
		return err
	}

	// STEP 14: Print warnings
	for _, w := range errors {
		fmt.Fprintf(os.Stderr, "warning: %v\n", w)
	}

	return nil
}
