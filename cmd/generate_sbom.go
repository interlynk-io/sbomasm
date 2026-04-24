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
	"strings"

	"github.com/interlynk-io/sbomasm/v2/pkg/generate/gsbom"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/spf13/cobra"
)

// generateSbomCmd represents the generate sbom command
var generateSbomCmd = &cobra.Command{
	Use:          "sbom",
	Short: "Generate SBOM from component metadata",
	Long: `Generate an SBOM from component manifests and artifact metadata.

Examples:
  # Basic: generate SBOM using explicit artifact config and components file
  $ sbomasm generate sbom -c .artifact-metadata.yaml -i .components.json -o sbom.cdx.json

  # Config is optional: sbomasm automatically uses .artifact-metadata.yaml if present
  $ sbomasm generate sbom -i .components.json -o sbom.cdx.json

  # Discover components recursively: finds all .components.json files under current directory
  $ sbomasm generate sbom -r . -o sbom.cdx.json

  # Use specific SBOM format and version (both flags required together)
  $ sbomasm generate sbom -r . -o sbom.cdx.json --format cyclonedx --spec-version 1.5
  $ sbomasm generate sbom -r . -o sbom.spdx.json --format spdx --spec-version 2.3

  # Discover with custom filename pattern
  $ sbomasm generate sbom -r . --filename my-components.json -o sbom.cdx.json

  # Include only components with specific tags
  $ sbomasm generate sbom -r . -o sbom.cdx.json -t runtime -t required

  # Exclude components with specific tags
  $ sbomasm generate sbom -r . -o sbom.cdx.json --exclude-tags test

  # Enable strict NTIA compliance validation
  $ sbomasm generate sbom -r . -o sbom.cdx.json --strict

  # Validate component files against JSON schema
  $ sbomasm generate sbom -r . -o sbom.cdx.json --validate`,
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

		if err := validateGenerateSBOMParams(params); err != nil {
			return err
		}

		params.Ctx = &ctx
		return gsbom.Generate(params)
	},
}

// extractGenerateSBOM extracts the parameters for the
// generate sbom command from the command flags
func extractGenerateSBOM(cmd *cobra.Command) (*gsbom.GenerateSBOMParams, error) {
	params := new(gsbom.GenerateSBOMParams)

	params.ConfigPath, _ = cmd.Flags().GetString("config")
	params.InputFiles, _ = cmd.Flags().GetStringSlice("input")
	params.Output, _ = cmd.Flags().GetString("output")
	params.Tags = normalizeTags(getStringSliceFlag(cmd, "tags"))
	params.ExcludeTags = normalizeTags(getStringSliceFlag(cmd, "exclude-tags"))
	params.Format, _ = cmd.Flags().GetString("format")
	params.RecursePath, _ = cmd.Flags().GetString("recurse")
	params.Filename, _ = cmd.Flags().GetString("filename")
	params.Strict, _ = cmd.Flags().GetBool("strict")
	params.SpecVersion, _ = cmd.Flags().GetString("spec-version")
	params.FormatSet = cmd.Flags().Changed("format")
	params.SpecVersionSet = cmd.Flags().Changed("spec-version")
	params.ValidateSchema, _ = cmd.Flags().GetBool("validate")

	return params, nil
}
func validateGenerateSBOMParams(params *gsbom.GenerateSBOMParams) error {
	if hasOverlap(params.Tags, params.ExcludeTags) {
		return fmt.Errorf("conflicting tags: same tag in include and exclude")
	}

	// If either format or spec-version is provided, both must be provided
	if params.FormatSet && !params.SpecVersionSet {
		return fmt.Errorf("--format requires --spec-version: when specifying format, you must also specify spec-version (e.g., --format cyclonedx --spec-version 1.5)")
	}
	if params.SpecVersionSet && !params.FormatSet {
		return fmt.Errorf("--spec-version requires --format: when specifying spec-version, you must also specify format (e.g., --format cyclonedx --spec-version 1.5)")
	}

	// Normalize format to lowercase
	params.Format = strings.ToLower(params.Format)

	if params.Format != "cdx" && params.Format != "spdx" && params.Format != "cyclonedx" {
		return fmt.Errorf("invalid format: must be 'cyclonedx', 'cdx', or 'spdx'")
	}

	// Validate spec version
	if params.SpecVersion != "" {
		if params.Format == "spdx" {
			if params.SpecVersion != "2.2" && params.SpecVersion != "2.3" {
				return fmt.Errorf("invalid spec-version for SPDX: must be '2.2' or '2.3'")
			}
		} else if params.Format == "cdx" || params.Format == "cyclonedx" {
			if params.SpecVersion != "1.4" && params.SpecVersion != "1.5" && params.SpecVersion != "1.6" {
				return fmt.Errorf("invalid spec-version for CycloneDX: must be '1.4', '1.5', or '1.6'")
			}
		}
	}

	return nil
}

func normalizeTags(tags []string) []string {
	var normalized []string
	for _, tag := range tags {
		ttag := strings.TrimSpace(tag)
		if ttag != "" {
			normalized = append(normalized, strings.ToLower(ttag))
		}
	}
	return normalized
}

// getStringSliceFlag safely gets a string slice flag, ignoring the error.
func getStringSliceFlag(cmd *cobra.Command, name string) []string {
	val, _ := cmd.Flags().GetStringSlice(name)
	return val
}

func init() {
	// Flags
	generateSbomCmd.Flags().StringP("config", "c", ".artifact-metadata.yaml", "Path to artifact metadata config file. Run 'sbomasm generate config' to create one. Describes the primary application (name, version, supplier, etc.) and output format pinning.")
	generateSbomCmd.Flags().StringSliceP("input", "i", []string{}, "Paths to component manifest files (.components.json or .components.csv). Can be specified multiple times. Mixing formats is allowed.")
	generateSbomCmd.Flags().StringP("output", "o", "", "Output SBOM file path. If not specified, writes to stdout.")
	generateSbomCmd.Flags().StringSliceP("tags", "t", []string{}, "Include only components with any of these tags (default: all). Can be specified multiple times for OR matching.")
	generateSbomCmd.Flags().StringSlice("exclude-tags", []string{}, "Exclude components with any of these tags (default: none). Applied after --tags.")
	generateSbomCmd.Flags().String("format", "cyclonedx", "Output SBOM format. Must be used with --spec-version. Valid values: cyclonedx, cdx, spdx. Case-insensitive.")
	generateSbomCmd.Flags().StringP("recurse", "r", "", "Recursively discover component manifest files under the given directory. Discovers .components.json and .components.csv files.")
	generateSbomCmd.Flags().String("filename", ".components.json", "Filename to look for during recursive discovery (e.g., my-deps.json). Also discovers .components.csv.")
	generateSbomCmd.Flags().Bool("debug", false, "Enable debug logging for detailed output.")
	generateSbomCmd.Flags().Bool("strict", false, "Fail on common omissions (missing license, hash, supplier, etc.) instead of just warning. Recommended for CI.")
	generateSbomCmd.Flags().String("spec-version", "", "Pin output spec version. Must be used with --format. CycloneDX: 1.4, 1.5, 1.6. SPDX: 2.2, 2.3.")
	generateSbomCmd.Flags().Bool("validate", false, "Validate component manifest files against the JSON Schema before processing. Detects malformed manifests early.")
}

func hasOverlap(include, exclude []string) bool {
	set := make(map[string]bool)
	for _, v := range include {
		set[strings.ToLower(v)] = true
	}
	for _, v := range exclude {
		if set[strings.ToLower(v)] {
			return true
		}
	}
	return false
}
