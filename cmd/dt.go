// Copyright 2023 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
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

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/pkg/assemble"
	"github.com/interlynk-io/sbomasm/pkg/dt"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/spf13/cobra"
)

// assembleCmd represents the assemble command
var dtCmd = &cobra.Command{
	Use:   "dt",
	Short: "helps assembling multiple DT project sboms into a final sbom",
	Long: `The dt command will help assembling sboms into a final sbom.

Basic Example:
    $ sbomasm dt -u "http://localhost:8080/" -k "odt_gwiwooi29i1N5Hewkkddkkeiwi3ii" -n "mega-app" -v "1.0.0" -t "application" -o finalsbom.json 11903ba9-a585-4dfb-9a0c-f348345a5473 34103ba2-rt63-2fga-3a8b-t625261g6262
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

		dtParams, err := extractDtArgs(cmd, args)
		if err != nil {
			return err
		}

		dtParams.Ctx = &ctx

		// retrieve Input Files
		dt.PopulateInputField(ctx, dtParams)
		fmt.Println("dtAssembleParams.Input: ", dtParams.Input)

		assembleParams, err := extractArgsFromDTtoAssemble(dtParams)
		if err != nil {
			return err
		}
		assembleParams.Ctx = &ctx

		config, err := assemble.PopulateConfig(assembleParams)
		if err != nil {
			fmt.Println("Error populating config:", err)
		}
		return assemble.Assemble(config)
	},
}

func extractArgsFromDTtoAssemble(dtParams *dt.Params) (*assemble.Params, error) {
	aParams := assemble.NewParams()

	aParams.Output = dtParams.Output

	aParams.Name = dtParams.Name
	aParams.Version = dtParams.Version
	aParams.Type = dtParams.Type

	aParams.FlatMerge = dtParams.FlatMerge
	aParams.HierMerge = dtParams.HierMerge
	aParams.AssemblyMerge = dtParams.AssemblyMerge

	aParams.Xml = dtParams.Xml
	aParams.Json = dtParams.Json

	aParams.OutputSpecVersion = dtParams.OutputSpecVersion

	aParams.OutputSpec = dtParams.OutputSpec

	aParams.Input = dtParams.Input

	return aParams, nil
}

func extractDtArgs(cmd *cobra.Command, args []string) (*dt.Params, error) {
	aParams := dt.NewParams()

	url, err := cmd.Flags().GetString("url")
	if err != nil {
		return nil, err
	}

	apiKey, err := cmd.Flags().GetString("api-key")
	if err != nil {
		return nil, err
	}
	aParams.Url = url
	aParams.ApiKey = apiKey

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return nil, err
	}
	aParams.Output = output

	name, _ := cmd.Flags().GetString("name")
	version, _ := cmd.Flags().GetString("version")
	typeValue, _ := cmd.Flags().GetString("type")

	aParams.Name = name
	aParams.Version = version
	aParams.Type = typeValue

	flatMerge, _ := cmd.Flags().GetBool("flatMerge")
	hierMerge, _ := cmd.Flags().GetBool("hierMerge")
	assemblyMerge, _ := cmd.Flags().GetBool("assemblyMerge")

	aParams.FlatMerge = flatMerge
	aParams.HierMerge = hierMerge
	aParams.AssemblyMerge = assemblyMerge

	xml, _ := cmd.Flags().GetBool("xml")
	json, _ := cmd.Flags().GetBool("json")

	aParams.Xml = xml
	aParams.Json = json

	if aParams.Xml {
		aParams.Json = false
	}

	specVersion, _ := cmd.Flags().GetString("outputSpecVersion")
	aParams.OutputSpecVersion = specVersion

	cdx, _ := cmd.Flags().GetBool("outputSpecCdx")

	if cdx {
		aParams.OutputSpec = "cyclonedx"
	} else {
		aParams.OutputSpec = "spdx"
	}

	fmt.Println("args: ", args)
	for _, arg := range args {
		fmt.Println("arg: ", arg)
		argID, err := uuid.Parse(arg)
		fmt.Println("argID: ", argID)

		if err != nil {
			return nil, err
		}
		aParams.ProjectIds = append(aParams.ProjectIds, argID)
	}
	return aParams, nil
}
