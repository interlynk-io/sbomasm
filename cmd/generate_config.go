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
	"fmt"
	"os"

	"github.com/interlynk-io/sbomasm/v2/pkg/generate/app"
	"github.com/spf13/cobra"
)

var generateConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Generate artifact metadata config",
	RunE: func(cmd *cobra.Command, args []string) error {
		outputPath, _ := cmd.Flags().GetString("output")

		content := app.DefaultAppYaml()

		if err := os.WriteFile(outputPath, content, 0644); err != nil {
			return fmt.Errorf("failed to write config file: %w", err)
		}

		fmt.Printf("artifact config written to %s\n", outputPath)
		return nil
	},
}

func init() {
	generateConfigCmd.Flags().StringP("output", "o", ".artifact-metadata.yaml", "Output file path for the generated artifact metadata config. Contains app metadata (name, version, supplier) and output format pinning.")
}
