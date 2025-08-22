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
	"context"
	"fmt"
	"os"
	"time"

	"github.com/interlynk-io/sbomasm/pkg/enrich"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/spf13/cobra"
)

var enrichCmd = &cobra.Command{
	Use:   "enrich [flags] <input-file>",
	Short: "Enrich SBOM licenses using ClearlyDefined",
	Long: `Enrich missing licenses in an SBOM file using the ClearlyDefined.

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

	enrichCmd.Flags().StringSlice("fields", []string{}, "Fields to enrich in the SBOM (e.g. license)")
	enrichCmd.Flags().StringP("output", "o", "", "Output path of file to save the enriched SBOM")
	enrichCmd.Flags().BoolP("debug", "d", false, "Enable debug logging")
	enrichCmd.Flags().BoolP("force", "f", false, "Forcefully replace the existing fields with new one.")
	enrichCmd.Flags().IntP("max-retries", "r", 2, "Maximum number of retries for failed requests(default: 2)")
	enrichCmd.Flags().IntP("max-wait", "w", 5, "Maximum wait time for requests(default: 5sec)")
}

func runEnrich(cmd *cobra.Command, args []string) error {
	debug, _ := cmd.Flags().GetBool("debug")
	if debug {
		logger.InitDebugLogger()
	} else {
		logger.InitProdLogger()
	}

	ctx := logger.WithLogger(context.Background())
	log := logger.FromContext(ctx)

	log.Debugf("executing enrich command with args: %v", args)

	// extract the enrich configuration
	enrichConfig, err := extractEnrichConfig(cmd, args)
	if err != nil {
		return fmt.Errorf("failed to extract enrich configuration: %w", err)
	}

	log.Debugf("enrich configuration: %+v", enrichConfig)

	if err := enrichConfig.Validate(); err != nil {
		return fmt.Errorf("invalid enrich configuration: %w", err)
	}

	summary, err := enrich.Engine(ctx, enrichConfig)
	if err != nil {
		return fmt.Errorf("failed to run enrich engine: %w", err)
	}

	fmt.Printf("\nTotal: %d, Selected: %d, Enriched: %d, Skipped: %d, Failed: %d\n", summary.TotalComponents, summary.SelectedComponents, summary.Enriched, summary.Skipped, summary.Failed)

	for _, err := range summary.Errors {
		fmt.Printf("Error: %v\n", err)
	}

	return nil
}

func extractEnrichConfig(cmd *cobra.Command, args []string) (*enrich.Config, error) {
	enrichConfig := enrich.NewConfig()

	enrichConfig.SBOMFile = args[0]

	fields, _ := cmd.Flags().GetStringSlice("fields")
	enrichConfig.Fields = fields

	outputFile, _ := cmd.Flags().GetString("output")
	enrichConfig.Output = outputFile

	maxRetries, _ := cmd.Flags().GetInt("max-retries")
	enrichConfig.MaxRetries = maxRetries

	maxWait, _ := cmd.Flags().GetInt("max-wait")
	enrichConfig.MaxWait = time.Duration(maxWait) * time.Second

	force, _ := cmd.Flags().GetBool("force")
	enrichConfig.Force = force

	debug, _ := cmd.Flags().GetBool("debug")
	enrichConfig.Debug = debug

	return enrichConfig, nil
}
