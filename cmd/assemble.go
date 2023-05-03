// Copyright 2023 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

	"github.com/interlynk-io/sbomasm/pkg/assemble"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/spf13/cobra"
)

// assembleCmd represents the assemble command
var assembleCmd = &cobra.Command{
	Use:   "assemble",
	Short: "helps assembling sboms into a final sbom",
	Long: `The assemble command will help assembling sboms into a final sbom. 

Basic Example:
    $ sbomasm assemble -n "mega-app" -v "1.0.0" in-sbom1.json in-sbom2.json 
    $ sbomasm assemble -n "mega-app" -v "1.0.0" -f -o "mega_app_flat.sbom.json" in-sbom1.json in-sbom2.json 

Advanced Example:
	$ sbomasm generate > config.yaml (edit the config file to add your settings)
	$ sbomasm assemble -c config.yaml -o final_sbom_cdx.json in-sbom1.json in-sbom2.json
	`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("please provide at least one sbom file to assemble")
		}

		debug, _ := cmd.Flags().GetBool("debug")
		if debug {
			logger.InitDebugLogger()
		} else {
			logger.InitProdLogger()
		}

		ctx := logger.WithLogger(context.Background())

		assembleParams, err := extractArgs(cmd, args)
		if err != nil {
			return err
		}
		assembleParams.Ctx = &ctx
		return assemble.Assemble(assembleParams)
	},
}

func init() {
	rootCmd.AddCommand(assembleCmd)
	assembleCmd.Flags().StringP("output", "o", "", "path to assembled sbom, defaults to stdout")
	assembleCmd.Flags().StringP("configPath", "c", "", "path to config file")

	assembleCmd.Flags().StringP("name", "n", "", "name of the assembled sbom")
	assembleCmd.Flags().StringP("version", "v", "", "version of the assembled sbom")
	assembleCmd.MarkFlagsRequiredTogether("name", "version")

	assembleCmd.Flags().BoolP("flatMerge", "f", false, "flat merge")
	assembleCmd.Flags().BoolP("hierMerge", "m", true, "hierarchical merge")

	assembleCmd.Flags().BoolP("xml", "x", false, "output in xml format")
	assembleCmd.Flags().BoolP("json", "j", true, "output in json format")

	assembleCmd.PersistentFlags().BoolP("debug", "d", false, "debug output")
}

func validatePath(path string) error {
	stat, err := os.Stat(path)

	if err != nil {
		return err
	}

	if stat.IsDir() {
		return fmt.Errorf("path %s is a directory include only files", path)
	}

	return nil
}

func extractArgs(cmd *cobra.Command, args []string) (*assemble.Params, error) {
	aParams := assemble.NewParams()

	configPath, err := cmd.Flags().GetString("configPath")
	if err != nil {
		return nil, err
	}

	if configPath != "" {
		if err := validatePath(configPath); err != nil {
			return nil, err
		}
		aParams.ConfigPath = configPath
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return nil, err
	}
	aParams.Output = output

	name, _ := cmd.Flags().GetString("name")
	version, _ := cmd.Flags().GetString("version")

	aParams.Name = name
	aParams.Version = version

	flatMerge, _ := cmd.Flags().GetBool("flatMerge")
	hierMerge, _ := cmd.Flags().GetBool("hierMerge")

	if flatMerge {
		hierMerge = false
	}

	aParams.FlatMerge = flatMerge
	aParams.HierMerge = hierMerge

	xml, _ := cmd.Flags().GetBool("xml")
	json, _ := cmd.Flags().GetBool("json")

	aParams.Xml = xml
	aParams.Json = json

	if aParams.Xml {
		aParams.Json = false
	}

	for _, arg := range args {
		if err := validatePath(arg); err != nil {
			return nil, err
		}
		aParams.Input = append(aParams.Input, arg)
	}
	return aParams, nil
}
