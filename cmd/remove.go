// Copyright 2025 Interlynk.io
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
	"os"

	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/rm"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/spf13/cobra"
)

var rmCmd = &cobra.Command{
	Use:   "rm [flags] <input-file>",
	Short: "Remove fields, components, or dependencies from an SBOM",
	Long: `Remove fields, components, or dependencies from an SBOM.

This command supports high-level removal operations, such as:
- Removing metadata fields (e.g., author, license)
- Removing entire components
- Removing specific dependency relationships

The command follows a structured pattern:
  WHAT to remove → WHERE to remove it → HOW to match/filter

Examples:

  sbomasm rm --field author --scope document sbom.spdx.json
  sbomasm rm --field license --scope component --value "MIT" sbom.spdx.json
  sbomasm rm --component --name nginx --version 1.0.0 sbom.spdx.json
  sbomasm rm --component --field license --value "MIT" --all sbom.cdx.json
  sbomasm rm --dependency --id "pkg:deb/debian/nginx@1.0.0" sbom.cdx.json
`,
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
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			fmt.Println("Error: missing required input file (e.g. sbom.spdx.json)")

			_ = cmd.Help()
			return nil
		}

		debug, _ := cmd.Flags().GetBool("debug")
		if debug {
			logger.InitDebugLogger()
		} else {
			logger.InitProdLogger()
		}

		ctx := logger.WithLogger(context.Background())

		removalParams, err := extractRemoveParams(cmd)
		if err != nil {
			return err
		}

		if err := removalParams.Validate(); err != nil {
			return err
		}

		return rm.Run(ctx, args, removalParams)
	},
}

func init() {
	rootCmd.AddCommand(rmCmd)

	// Field Removal Flags
	rmCmd.Flags().StringP("field", "f", "", "Field to remove (e.g., author, license, purl)")
	rmCmd.Flags().StringP("scope", "s", "", "Scope to remove field from (document, component, dependency)")
	rmCmd.Flags().StringP("key", "k", "", "Optional key to filter field entries")
	rmCmd.Flags().StringP("value", "v", "", "Optional value to filter field entries")
	rmCmd.Flags().BoolP("all", "a", false, "Apply field removal to all matching items (e.g. all components)")

	// Component Removal Flags
	rmCmd.Flags().BoolP("component", "c", false, "Operate at component level (e.g., remove whole component or match by field)")
	rmCmd.Flags().StringP("name", "n", "", "Component name for removal or matching")
	rmCmd.Flags().String("version", "", "Component version for removal or matching")

	// Dependency Removal Flags
	rmCmd.Flags().Bool("dependency", false, "Operate at dependency level")
	rmCmd.Flags().String("id", "", "Dependency ID or PURL to remove (e.g. pkg:...@version)")

	rmCmd.Flags().Bool("dry-run", false, "Perform a dry run without making changes")
	rmCmd.Flags().Bool("summary", false, "Print a summary of the changes instead of applying them")
	rmCmd.Flags().StringP("output", "o", "", "Output file to write the modified SBOM (default: overwrite input file)")

	// Custom help template: moves "Usage:" to the top
	rmCmd.SetHelpTemplate(`Usage:
  {{.UseLine}}

{{.Long}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}
`)
}

// extractRemoveParams extracts parameters from the command flags for the removal operation.
func extractRemoveParams(cmd *cobra.Command) (*types.RmParams, error) {
	// Extract Field Removal Parameters
	field, _ := cmd.Flags().GetString("field")
	scope, _ := cmd.Flags().GetString("scope")
	key, _ := cmd.Flags().GetString("key")
	value, _ := cmd.Flags().GetString("value")
	all, _ := cmd.Flags().GetBool("all")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	summary, _ := cmd.Flags().GetBool("summary")

	// Extract Component Removal Parameters
	name, _ := cmd.Flags().GetString("name")
	version, _ := cmd.Flags().GetString("version")

	// Extract Dependency Removal Parameters
	dependencyID, _ := cmd.Flags().GetString("id")

	isComponent, _ := cmd.Flags().GetBool("component")

	isDependency, _ := cmd.Flags().GetBool("dependency")

	isKeyPresent := key != ""
	isValuePresent := value != ""
	isKeyAndValuePresent := isKeyPresent && isValuePresent

	params := &types.RmParams{
		Field:                field,
		Scope:                scope,
		Key:                  key,
		Value:                value,
		All:                  all,
		ComponentName:        name,
		ComponentVersion:     version,
		DependencyID:         dependencyID,
		IsComponent:          isComponent,
		IsDependency:         isDependency,
		IsKeyPresent:         isKeyPresent,
		IsValuePresent:       isValuePresent,
		IsKeyAndValuePresent: isKeyAndValuePresent,
		DryRun:               dryRun,  // Default to false, can be set via global flag
		Summary:              summary, // Default to false, can be set via global flag
	}

	switch {
	case field != "":
		params.Kind = types.FieldRemoval
	case isComponent:
		params.Kind = types.ComponentRemoval
	case isDependency:
		params.Kind = types.DependencyRemoval
	}

	return params, nil
}
