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

	"github.com/interlynk-io/sbomasm/v2/pkg/generate/gsbom"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/spf13/cobra"
)

// generateSbomCmd represents the generate sbom command
var generateSbomCmd = &cobra.Command{
	Use:          "sbom",
	Short:        "Generate SBOM from component metadata",
	Long:         "Generate an SBOM from component manifests and artifact metadata",
	SilenceUsage: true,
	Args:         cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		// Logger setup
		debug, _ := cmd.Flags().GetBool("debug")
		if debug {
			logger.InitDebugLogger()
		} else {
			logger.InitProdLogger()
		}

		ctx := logger.WithLogger(context.Background())

		// extract generate sbom Params` from flags
		params, err := extractGenerateSBOM(cmd)
		if err != nil {
			return err
		}

		params.Ctx = &ctx
		return gsbom.Generate(params)
	},
}

// extractGenerateSBOM extracts the parameters for the
// generate sbom command from the command flags
func extractGenerateSBOM(cmd *cobra.Command) (*gsbom.GenerateSBOMParams, error) {
	params := gsbom.NewGenerateSBOMParams()

	params.ConfigPath, _ = cmd.Flags().GetString("config")
	params.InputFiles, _ = cmd.Flags().GetStringSlice("input")
	params.Output, _ = cmd.Flags().GetString("output")
	params.Tags, _ = cmd.Flags().GetStringSlice("tags")
	params.ExcludeTags, _ = cmd.Flags().GetStringSlice("exclude-tags")
	params.Format, _ = cmd.Flags().GetString("format")
	params.RecursePath, _ = cmd.Flags().GetString("recurse")
	params.Filename, _ = cmd.Flags().GetString("filename")

	return params, nil
}

func init() {
	// Flags
	generateSbomCmd.Flags().StringP("config", "c", ".artifact-metadata.yaml", "artifact metadata config file")
	generateSbomCmd.Flags().StringSliceP("input", "i", []string{}, "component input files")
	generateSbomCmd.Flags().StringP("output", "o", "", "output SBOM file (default stdout)")
	generateSbomCmd.Flags().StringSliceP("tags", "t", []string{}, "include components with these tags")
	generateSbomCmd.Flags().StringSlice("exclude-tags", []string{}, "exclude components with these tags")
	generateSbomCmd.Flags().String("format", "cyclonedx(default)", "output format (cyclonedx|spdx)")
	generateSbomCmd.Flags().StringP("recurse", "r", "", "recursively discover component files")
	generateSbomCmd.Flags().String("filename", ".components.json", "filename for recursive discovery")
	generateSbomCmd.Flags().Bool("debug", false, "enable debug logging")
}
