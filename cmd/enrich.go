// Copyright 2025 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
//
// http://opensource.org/licenses/Apache-2.0
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

package cmd

import (
	"fmt"
	"os"

	"github.com/interlynk-io/sbomasm/pkg/enrich"
	"github.com/interlynk-io/sbomasm/pkg/enrich/types"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/spf13/cobra"
)

var enrichCmd = &cobra.Command{
	Use:   "enrich [flags] <input-file>",
	Short: "Enrich SBOM licenses using ClearlyDefined API",
	Long: `Enrich missing or incorrect licenses in an SBOM file using the ClearlyDefined API.

	`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		if _, err := os.Stat(args[0]); err != nil {
			return fmt.Errorf("invalid input file: %v", err)
		}
		return nil
	},
	RunE: runEnrich,
}

func init() {
	rootCmd.AddCommand(enrichCmd)

	// Define flags for the enrich command
	enrichCmd.Flags().StringSlice("fields", []string{}, "Fields to enrich in the SBOM (e.g., author, license)")
	enrichCmd.Flags().String("output", "", "Output file to save the enriched SBOM")
	enrichCmd.Flags().Bool("debug", false, "Enable debug logging")
	enrichCmd.Flags().Bool("force", false, "Force overwrite of output file if it exists")
	enrichCmd.Flags().Bool("verbose", false, "Enable verbose output")
}

func runEnrich(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	log := logger.FromContext(ctx)

	log.Debugf("Executing enrich command with args: %v", args)

	debug, _ := cmd.Flags().GetBool("debug")
	if debug {
		logger.InitDebugLogger()
	} else {
		logger.InitProdLogger()
	}

	enrichParams, err := extractEnrichParams(cmd)
	if err != nil {
		return fmt.Errorf("failed to extract enrich parameters: %w", err)
	}
	enrichParams.SBOMFile = args[0]

	log.Debugf("Enrich parameters: %+v", enrichParams)

	if err := enrichParams.Validate(); err != nil {
		return fmt.Errorf("invalid enrich parameters: %w", err)
	}

	summary, err := enrich.Engine(ctx, args, enrichParams)
	if err != nil {
		return fmt.Errorf("failed to run enrich engine: %w", err)
	}

	if enrichParams.Verbose {
		fmt.Printf("Enriched: %d, Skipped: %d, Failed: %d\n", summary.Enriched, summary.Skipped, summary.Failed)
		for _, err := range summary.Errors {
			fmt.Println("Error: " + err.Error())
		}
	}

	return nil
}

func extractEnrichParams(cmd *cobra.Command) (*types.EnrichConfig, error) {
	fields, _ := cmd.Flags().GetStringSlice("fields")
	outputFile, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")
	force, _ := cmd.Flags().GetBool("force")

	params := &types.EnrichConfig{
		Fields:  fields,
		Output:  outputFile,
		Verbose: verbose,
		Force:   force,
	}
	return params, nil
}
