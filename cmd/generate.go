// Copyright 2023 Interlynk.io
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
	"github.com/interlynk-io/sbomasm/pkg/assemble"
	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a sample config file for assembling sboms",
	Long: `The generate command will generate a sample config file for assembling sboms.
Example:
	$ sbomasm generate > config.yaml

Please fill in all the fields that are known. Unknown fields can be left blank.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	Run: func(cmd *cobra.Command, args []string) {
		assemble.DefaultConfig()
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
}
