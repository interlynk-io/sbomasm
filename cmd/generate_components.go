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

package cmd

import (
	"context"
	"fmt"

	"github.com/interlynk-io/sbomasm/v2/pkg/generate/gcomps"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/spf13/cobra"
)

// generateComponentsCmd represents the generate components command
var generateComponentsCmd = &cobra.Command{
	Use:   "components [path]",
	Short: "Generate a component manifest scaffold file",
	Long: `Generate a component manifest scaffold file in JSON or CSV format.

Examples:
  # Generate .components.json in current directory
  $ sbomasm generate components

  # Generate in a specific directory
  $ sbomasm generate components ./my-project

  # Generate with explicit output path
  $ sbomasm generate components -o ./output/my-components.json

  # Generate CSV format
  $ sbomasm generate components --csv

  # Print field descriptions
  $ sbomasm generate components --describe

  # Print JSON Schema
  $ sbomasm generate components --schema
  $ sbomasm generate components --schema -o schema.json`,
	SilenceUsage: true,
	Args:         cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Logger setup
		debug, _ := cmd.Flags().GetBool("debug")
		if debug {
			logger.InitDebugLogger()
		} else {
			logger.InitProdLogger()
		}

		ctx := logger.WithLogger(context.Background())

		// Step 1: Extract parameters from flags
		params, err := extractGenerateComponents(cmd, args)
		if err != nil {
			return err
		}

		// Step 2: Validate parameters
		if err := validateGenerateComponentsParams(params); err != nil {
			return err
		}

		log := logger.FromContext(ctx)
		log.Debugf("executing generate components command with args: %v", args)
		log.Debugf("params: output=%s, csv=%v, force=%v, describe=%v, schema=%v",
			params.Output, params.CSV, params.Force, params.Describe, params.Schema)

		// Step 3: Handle mode flags

		if params.Describe {
			log.Debugf("printing field descriptions")
			fmt.Print(gcomps.DescribeSchema())
			return nil
		}

		if params.Schema {
			log.Debugf("writing JSON schema to: %s", params.Output)
			return gcomps.WriteSchema(ctx, params.Output, params.Force)
		}

		params.Ctx = &ctx

		// Step 4: Generate scaffold
		log.Debugf("generating component scaffold")
		return gcomps.Generate(params)
	},
}

// extractGenerateComponents extracts parameters from command flags and arguments
func extractGenerateComponents(cmd *cobra.Command, args []string) (*gcomps.GenerateComponentsParams, error) {
	params := gcomps.NewGenerateComponentsParams()

	// Get flags
	params.Output, _ = cmd.Flags().GetString("output")
	params.CSV, _ = cmd.Flags().GetBool("csv")
	params.Force, _ = cmd.Flags().GetBool("force")
	params.Describe, _ = cmd.Flags().GetBool("describe")
	params.Schema, _ = cmd.Flags().GetBool("schema")

	if len(args) > 0 {
		// if --output is not set, use the positional arg as output
		if params.Output == "" {
			params.Output = args[0]
		}
	}

	return params, nil
}

// validateGenerateComponentsParams validates the parameters
func validateGenerateComponentsParams(params *gcomps.GenerateComponentsParams) error {
	// Check for mutually exclusive flags
	if params.Describe && params.Schema {
		return fmt.Errorf("flags --describe and --schema are mutually exclusive")
	}

	return nil
}

func init() {
	// Flags
	generateComponentsCmd.Flags().StringP("output", "o", "", "Explicit output file path. If omitted, writes to .components.json (or .components.csv with --csv) in the current directory or specified path.")
	generateComponentsCmd.Flags().Bool("csv", false, "Emit .components.csv instead of .components.json. CSV has limitations (no pedigree, no external_references).")
	generateComponentsCmd.Flags().BoolP("force", "f", false, "Overwrite target file if it already exists. Without --force, the command errors rather than clobbering.")
	generateComponentsCmd.Flags().Bool("describe", false, "Print a human-readable list of every field the component manifest supports, grouped by required/optional. Useful for field discovery.")
	generateComponentsCmd.Flags().Bool("schema", false, "Print the canonical JSON Schema (draft 2020-12) for the component manifest to stdout (or to -o <file>). Machine-readable for CI validators.")
}
