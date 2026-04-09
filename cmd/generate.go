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
	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a sample config file for assembling sboms",
	Long: `The generate command will generate a sample config file for assembling sboms.
Example:
	$ sbomasm generate config
	$ sbomasm generate sbom -r . -o device-firmware-2.1.0.cdx.json
	$ sbomasm generate sbom \
	  -i .components.json \
	  -i libs/libmqtt/.components.json \
	  -i src/cjson/.components.json \
	  -i src/miniz/.components.json \
	  -o device-firmware-2.1.0.cdx.json
`,
	// Args:         cobra.NoArgs,
	// SilenceUsage: true,
	// Run: func(cmd *cobra.Command, args []string) {
	// 	fmt.Printf("%s", assemble.DefaultConfigYaml())
	// },
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.AddCommand(generateConfigCmd)
	generateCmd.AddCommand(generateSbomCmd)
}
