// Copyright 2025 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/interlynk-io/sbomasm/pkg/assemble"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/spf13/cobra"
)

// assembleCmd represents the assemble command
var assembleCmd = &cobra.Command{
	Use:   "assemble",
	Short: "Combine multiple SBOMs into a single SBOM",
	Long: `The assemble command combines multiple SBOMs into a single SBOM using various merge strategies.

Merge Strategies:
  • Hierarchical (default): Preserves SBOM structure, nests components under new root
  • Flat: Flattens all components to same level under new root
  • Assembly: Combines as assembly with shared dependencies
  • Augment: Enriches primary SBOM without creating new root

Examples:

Hierarchical Merge (default):
  $ sbomasm assemble -n "my-app" -v "1.0.0" -t "application" service1.json service2.json -o final.json

Flat Merge:
  $ sbomasm assemble -f -n "my-app" -v "1.0.0" -t "application" lib1.json lib2.json -o flat.json

Assembly Merge:
  $ sbomasm assemble -a -n "my-app" -v "1.0.0" -t "application" module1.json module2.json -o assembly.json

Augment Merge (enrich existing SBOM):
  $ sbomasm assemble --augmentMerge --primary base.json delta.json -o enriched.json
  $ sbomasm assemble --augmentMerge --primary base.json --merge-mode overwrite vendor-sbom.json

Config File:
  $ sbomasm generate > config.yaml
  $ sbomasm assemble -c config.yaml sbom1.json sbom2.json sbom3.json -o final.json
	`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		augmentMerge, _ := cmd.Flags().GetBool("augmentMerge")

		// For augment merge, args are secondary SBOMs (primary is specified via flag)
		// For other modes, args are all input SBOMs
		if !augmentMerge && len(args) == 0 {
			return fmt.Errorf("please provide at least one sbom file to assemble")
		}

		if augmentMerge {
			primaryFile, _ := cmd.Flags().GetString("primary")
			if primaryFile == "" {
				return fmt.Errorf("primary SBOM file is required for augment merge (use --primary flag)")
			}
			if len(args) == 0 {
				return fmt.Errorf("please provide at least one secondary sbom file for augment merge")
			}
		}

		debug, _ := cmd.Flags().GetBool("debug")
		if debug {
			logger.InitDebugLogger()
		} else {
			logger.InitProdLogger()
		}

		ctx := logger.WithLogger(context.Background())

		assembleParams, err := extractArgs(cmd, args)
		if err != nil {
			return err
		}

		assembleParams.Ctx = &ctx

		// Populate the config object
		config, err := assemble.PopulateConfig(assembleParams)
		if err != nil {
			fmt.Println("Error populating config:", err)
		}
		return assemble.Assemble(config)
	},
}

func init() {
	rootCmd.AddCommand(assembleCmd)
	// Output flags
	assembleCmd.Flags().StringP("output", "o", "", "path to assembled sbom, defaults to stdout")
	assembleCmd.Flags().StringP("configPath", "c", "", "path to config file")

	// Component metadata flags (for non-augment merges)
	assembleCmd.Flags().StringP("name", "n", "", "name of the assembled sbom (required for non-augment merges)")
	assembleCmd.Flags().StringP("version", "v", "", "version of the assembled sbom (required for non-augment merges)")
	assembleCmd.Flags().StringP("type", "t", "", "product type of the assembled sbom (application, framework, library, container, device, firmware)")
	assembleCmd.MarkFlagsRequiredTogether("name", "version", "type")

	// Merge strategy flags
	assembleCmd.Flags().BoolP("flatMerge", "f", false, "flat merge - combine all components at same level under new root")
	assembleCmd.Flags().BoolP("hierMerge", "m", false, "hierarchical merge - preserve original SBOM structures under new root")
	assembleCmd.Flags().BoolP("assemblyMerge", "a", false, "assembly merge - combine as assembly with shared dependencies")

	// Augment merge flags
	assembleCmd.Flags().BoolP("augmentMerge", "", false, "augment merge - merge components into primary SBOM without creating new root")
	assembleCmd.Flags().StringP("primary", "p", "", "primary SBOM file for augment merge (required for augment merge)")
	assembleCmd.Flags().StringP("merge-mode", "", "if-missing-or-empty", "merge mode for augment merge: if-missing-or-empty, overwrite")

	assembleCmd.MarkFlagsMutuallyExclusive("flatMerge", "hierMerge", "assemblyMerge", "augmentMerge")

	// Output format flags
	assembleCmd.Flags().BoolP("outputSpecCdx", "g", true, "output in CycloneDX format")
	assembleCmd.Flags().BoolP("outputSpecSpdx", "s", false, "output in SPDX format")
	assembleCmd.MarkFlagsMutuallyExclusive("outputSpecCdx", "outputSpecSpdx")

	assembleCmd.Flags().StringP("outputSpecVersion", "e", "", "spec version of the output sbom (e.g., 1.5, 1.6 for CycloneDX)")

	assembleCmd.Flags().BoolP("xml", "x", false, "output in XML format")
	assembleCmd.Flags().BoolP("json", "j", true, "output in JSON format")
	assembleCmd.MarkFlagsMutuallyExclusive("xml", "json")
}

func validatePath(path string) error {
	stat, err := os.Stat(path)
	if err != nil {
		return err
	}

	if stat.IsDir() {
		return fmt.Errorf("path %s is a directory include only files", path)
	}

	return nil
}

func extractArgs(cmd *cobra.Command, args []string) (*assemble.Params, error) {
	aParams := assemble.NewParams()

	configPath, err := cmd.Flags().GetString("configPath")
	if err != nil {
		return nil, err
	}

	if configPath != "" {
		if err := validatePath(configPath); err != nil {
			return nil, err
		}
		aParams.ConfigPath = configPath
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return nil, err
	}
	aParams.Output = output

	name, _ := cmd.Flags().GetString("name")
	version, _ := cmd.Flags().GetString("version")
	typeValue, _ := cmd.Flags().GetString("type")

	aParams.Name = name
	aParams.Version = version
	aParams.Type = typeValue

	flatMerge, _ := cmd.Flags().GetBool("flatMerge")
	hierMerge, _ := cmd.Flags().GetBool("hierMerge")
	assemblyMerge, _ := cmd.Flags().GetBool("assemblyMerge")
	augmentMerge, _ := cmd.Flags().GetBool("augmentMerge")

	aParams.FlatMerge = flatMerge
	aParams.HierMerge = hierMerge
	aParams.AssemblyMerge = assemblyMerge
	aParams.AugmentMerge = augmentMerge

	// Get augment merge specific flags
	primaryFile, _ := cmd.Flags().GetString("primary")
	mergeMode, _ := cmd.Flags().GetString("merge-mode")

	aParams.PrimaryFile = primaryFile
	aParams.MergeMode = mergeMode

	xml, _ := cmd.Flags().GetBool("xml")
	json, _ := cmd.Flags().GetBool("json")

	aParams.Xml = xml
	aParams.Json = json

	if aParams.Xml {
		aParams.Json = false
	}

	specVersion, _ := cmd.Flags().GetString("outputSpecVersion")
	aParams.OutputSpecVersion = specVersion

	cdx, _ := cmd.Flags().GetBool("outputSpecCdx")

	if cdx {
		aParams.OutputSpec = "cyclonedx"
	} else {
		aParams.OutputSpec = "spdx"
	}

	for _, arg := range args {
		if err := validatePath(arg); err != nil {
			return nil, err
		}
		aParams.Input = append(aParams.Input, arg)
	}
	return aParams, nil
}
