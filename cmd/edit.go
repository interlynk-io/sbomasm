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

	"github.com/interlynk-io/sbomasm/pkg/edit"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/spf13/cobra"
)

// editCmd represents the edit command
var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "helps editing an sbom",
	Long: `The edit command allows you to modify an existing Software Bill of Materials (SBOM) by filling in gaps or adding information that may have been missed during the generation process. This command operates by first locating the entity to edit and then adding the required information. The goal of edit is not to provide a full editing experience but to help fill in filling in missing information useful for compliance and security purposes.

Usage
	sbomasm edit [flags] <input-sbom-file>
	
Basic Example:
	# Edit's an sbom to add app-name and version to the primary component 
	$ sbomasm edit --subject primary-component  --name "my-cool-app" --version "1.0.0"  in-sbom-2.json

    # Edit's an sbom with an exiting created-at timestamp and supplier information only for missing fields
	$ sbomasm edit --missing --subject document --timestamp --supplier "interlynk (support@interlynk.io)" in-sbom-1.json

	# Edit's an sbom add a new author to the primary component preserving the existing authors in the doc 
	# if append is not provided the default behavior is to replace. 
	$ sbomasm edit --append --subject primary-component --author "abc (abc@gmail.com)" in-sbom-2.json

Advanced Example:
	# Edit's an sbom to add purl to a component by search it by name and version
	$ sbomasm edit --subject component-name-version --search "abc (v1.0.0)" --purl "pkg:deb/debian/abc@1.0.0" in-sbom-3.json

	# Edit's an sbom to add multiple authors to the document
	$ sbomasm edit --subject document --author "abc (abc@gmail.com)" --author "def (def@gmail.com)" in-sbom-4.json

	# Edit's an sbom to add multiple hashes to the primary component
	$ sbomasm edit --subject primary-component --hash "MD5 (hash1)" --hash "SHA256 (hash2)" in-sbom-5.json
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

		editParams, err := extractEditArgs(cmd, args)
		if err != nil {
			return err
		}

		editParams.Ctx = &ctx
		return edit.Edit(editParams)
	},
}

func init() {
	rootCmd.AddCommand(editCmd)
	// Output controls
	editCmd.Flags().StringP("output", "o", "", "path to edited sbom, defaults to stdout")

	// Edit locations
	editCmd.Flags().String("subject", "document", "subject to edit (document, primary-component, component-name-version)")
	editCmd.MarkFlagRequired("subject")
	editCmd.Flags().String("search", "", "search string to find the entity")

	// Edit controls
	editCmd.Flags().BoolP("missing", "m", false, "edit only missing fields")
	editCmd.Flags().BoolP("append", "a", false, "append to field instead of replacing")
	editCmd.Flags().BoolP("remove", "r", false, "remove field instead of replacing")

	// Edit fields
	editCmd.Flags().String("name", "", "name of the entity")
	editCmd.Flags().String("version", "", "version of the entity")
	editCmd.Flags().String("supplier", "", "supplier to add e.g 'name (email)'")
	editCmd.Flags().StringSlice("author", []string{}, "author to add e.g 'name (email)'")
	editCmd.Flags().String("purl", "", "purl to add e.g 'pkg:deb/debian/abc@1.0.0'")
	editCmd.Flags().String("cpe", "", "cpe to add e.g 'cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*'")
	editCmd.Flags().StringSlice("license", []string{}, "license to add e.g 'MIT'")
	editCmd.Flags().StringSlice("hash", []string{}, "checksum to add e.g 'MD5 (hash'")
	editCmd.Flags().StringSlice("tool", []string{}, "tool to add e.g 'sbomasm (v1.0.0)'")
	editCmd.Flags().String("copyright", "", "copyright to add e.g 'Copyright © 2024'")
	editCmd.Flags().StringSlice("lifecycle", []string{}, "lifecycle to add e.g 'build'")
	editCmd.Flags().String("description", "", "description to add e.g 'this is a cool app'")
	editCmd.Flags().String("repository", "", "repository to add e.g 'github.com/interlynk-io/sbomasm'")
	editCmd.Flags().String("type", "", "type to add e.g 'application'")

	editCmd.Flags().Bool("timestamp", false, "add created-at timestamp")
}

func extractEditArgs(cmd *cobra.Command, args []string) (*edit.EditParams, error) {
	editParams := edit.NewEditParams()

	editParams.Input = args[0]
	editParams.Output, _ = cmd.Flags().GetString("output")

	subject, _ := cmd.Flags().GetString("subject")
	editParams.Subject = subject

	search, _ := cmd.Flags().GetString("search")
	editParams.Search = search

	missing, _ := cmd.Flags().GetBool("missing")
	editParams.Missing = missing

	append, _ := cmd.Flags().GetBool("append")
	editParams.Append = append

	remove, _ := cmd.Flags().GetBool("remove")
	editParams.Remove = remove

	name, _ := cmd.Flags().GetString("name")
	editParams.Name = name

	version, _ := cmd.Flags().GetString("version")
	editParams.Version = version

	supplier, _ := cmd.Flags().GetString("supplier")
	editParams.Supplier = supplier

	authors, _ := cmd.Flags().GetStringSlice("author")
	editParams.Authors = authors

	purl, _ := cmd.Flags().GetString("purl")
	editParams.Purl = purl

	cpe, _ := cmd.Flags().GetString("cpe")
	editParams.Cpe = cpe

	licenses, _ := cmd.Flags().GetStringSlice("license")
	editParams.Licenses = licenses

	hashes, _ := cmd.Flags().GetStringSlice("hash")
	editParams.Hashes = hashes

	tools, _ := cmd.Flags().GetStringSlice("tool")
	editParams.Tools = tools

	copyright, _ := cmd.Flags().GetString("copyright")
	editParams.CopyRight = copyright

	lifecycles, _ := cmd.Flags().GetStringSlice("lifecycle")
	editParams.Lifecycles = lifecycles

	description, _ := cmd.Flags().GetString("description")
	editParams.Description = description

	repository, _ := cmd.Flags().GetString("repository")
	editParams.Repository = repository

	typ, _ := cmd.Flags().GetString("type")
	editParams.Type = typ

	timestamp, _ := cmd.Flags().GetBool("timestamp")
	editParams.Timestamp = timestamp

	return editParams, nil
}
