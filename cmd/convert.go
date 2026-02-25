// Copyright 2026 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
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

	"github.com/interlynk-io/sbomasm/v2/pkg/convert"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/spf13/cobra"
)

// convertCmd represents the convert command
var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "converts SBOM to a different format",
	Long: `The sbomasm convert command allows you to convert a SBOM
from its original format (SPDX or CycloneDX) into a different output format.

Usage:
  sbomasm convert [flags] <input-sbom-file>

Examples:
  # Convert a CycloneDX SBOM to CSV and print to stdout
  $ sbomasm convert --format csv samples/cdx/sbomqs-cdx.json

  # Convert an SPDX SBOM to CSV and write to a file
  $ sbomasm convert --format csv --output sbomqs-cdx.csv samples/cdx/sbomqs-cdx.json
`,
	SilenceUsage: true,
	Args:         cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		debug, _ := cmd.Flags().GetBool("debug")
		if debug {
			logger.InitDebugLogger()
		} else {
			logger.InitProdLogger()
		}

		ctx := logger.WithLogger(context.Background())

		convertParams, err := extractConvertArgs(cmd, args)
		if err != nil {
			return err
		}

		convertParams.Ctx = &ctx
		return convert.Convert(convertParams)
	},
}

func init() {
	rootCmd.AddCommand(convertCmd)
	convertCmd.Flags().StringP("output", "o", "", "path to output file, defaults to stdout")
	convertCmd.Flags().StringP("format", "f", "csv", "output format (csv)")
}

func extractConvertArgs(cmd *cobra.Command, args []string) (*convert.ConvertParams, error) {
	convertParams := convert.NewConvertParams()

	convertParams.Input = args[0]

	output, _ := cmd.Flags().GetString("output")
	convertParams.Output = output

	format, _ := cmd.Flags().GetString("format")
	convertParams.Format = format

	if convertParams.Input == "" {
		return nil, fmt.Errorf("input sbom file is required")
	}

	if convertParams.Format == "" {
		return nil, fmt.Errorf("output format is required")
	}

	return convertParams, nil
}
