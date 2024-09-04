package cmd

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/pkg/dt"
	"github.com/interlynk-io/sbomasm/pkg/edit"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/spf13/cobra"
)

// editDtCmd represents the dt command under edit
var editDtCmd = &cobra.Command{
	Use:   "dt",
	Short: "helps editing an sbom using dependency track",
	Long: `The dt command allows you to modify an existing Software Bill of Materials (SBOM) using data from Dependency Track.

Usage
    sbomasm edit dt [flags] <project-ids>
    
Basic Example:
    # Edit an sbom to add app-name and version to the primary component 
    $ sbomasm edit dt -u "http://localhost:8080/" -k "odt_gwiwooi29i1N5Hewkkiddkkeiwi3ii" --subject primary-component --name "my-cool-app" --version "1.0.0" 11903ba9-a585-4dfb-9a0c-f348345a5473 34103ba2-rt63-2fga-3a8b-t625261g6262
	$ sbomasm edit dt -u "http://localhost:8080/" -k "odt_gEB8881Nhhhkkk5HewiZkkkUUhsgk7"   --subject document --author "fred (fred@c.com)" --author "jane (jane@c.com)" --supplier "interlynk.io (https://interlynk.io)" --tool "sbomasm edit (v1.0.0)" --license "CC0-1.0" --repository "github.com/interlynk/cool-app" --timestamp  --output  dt-new-final-product.spdx.json 11903ba9-a585-4dfb-9a0c-f348345a5473

    # Edit an sbom to add created-at timestamp and supplier information only for missing fields
    $ sbomasm edit dt  -u "http://localhost:8080/" -k "odt_gwiwooi29i1N5Hewkkddkkueiwi3ii"--missing --subject document --timestamp --supplier "interlynk (support@interlynk.io)" 11903ba9-a585-4dfb-9a0c-f348345a5473 34103ba2-rt63-2fga-3a8b-t625261g6262
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

		dtEditParams, err := extractEditDtArgs(cmd, args)
		if err != nil {
			return err
		}

		dtEditParams.Ctx = &ctx

		// retrieve Input Files
		dtEditParams.PopulateInputField(ctx)

		editParams, err := extractArgsFromDTtoEdit(dtEditParams)
		if err != nil {
			return err
		}
		editParams.Ctx = &ctx

		return edit.Edit(editParams)
	},
}

func init() {
	editCmd.AddCommand(editDtCmd)
	editDtCmd.Flags().StringP("url", "u", "", "dependency track url https://localhost:8080/")
	editDtCmd.Flags().StringP("api-key", "k", "", "dependency track api key, requires VIEW_PORTFOLIO for scoring and PORTFOLIO_MANAGEMENT for tagging")
	editDtCmd.MarkFlagsRequiredTogether("url", "api-key")

	// Output controls
	editDtCmd.Flags().StringP("output", "o", "", "path to edited sbom, defaults to stdout")

	// Edit locations
	editDtCmd.Flags().String("subject", "document", "subject to edit (document, primary-component, component-name-version)")
	editDtCmd.MarkFlagRequired("subject")
	editDtCmd.Flags().String("search", "", "search string to find the entity")

	// Edit controls
	editDtCmd.Flags().BoolP("missing", "m", false, "edit only missing fields")
	editDtCmd.Flags().BoolP("append", "a", false, "append to field instead of replacing")

	// Edit fields
	editDtCmd.Flags().String("name", "", "name of the entity")
	editDtCmd.Flags().String("version", "", "version of the entity")
	editDtCmd.Flags().String("supplier", "", "supplier to add e.g 'name (email)'")
	editDtCmd.Flags().StringSlice("author", []string{}, "author to add e.g 'name (email)'")
	editDtCmd.Flags().String("purl", "", "purl to add e.g 'pkg:deb/debian/abc@1.0.0'")
	editDtCmd.Flags().String("cpe", "", "cpe to add e.g 'cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*'")
	editDtCmd.Flags().StringSlice("license", []string{}, "license to add e.g 'MIT'")
	editDtCmd.Flags().StringSlice("hash", []string{}, "checksum to add e.g 'MD5 (hash'")
	editDtCmd.Flags().StringSlice("tool", []string{}, "tool to add e.g 'sbomasm (v1.0.0)'")
	editDtCmd.Flags().String("copyright", "", "copyright to add e.g 'Copyright © 2024'")
	editDtCmd.Flags().StringSlice("lifecycle", []string{}, "lifecycle to add e.g 'build'")
	editDtCmd.Flags().String("description", "", "description to add e.g 'this is a cool app'")
	editDtCmd.Flags().String("repository", "", "repository to add e.g 'github.com/interlynk-io/sbomasm'")
	editDtCmd.Flags().String("type", "", "type to add e.g 'application'")

	editDtCmd.Flags().Bool("timestamp", false, "add created-at timestamp")
}

func extractEditDtArgs(cmd *cobra.Command, args []string) (*dt.EditParams, error) {
	dtEditParams := dt.NewEditParams()

	url, err := cmd.Flags().GetString("url")
	if err != nil {
		return nil, err
	}

	apiKey, err := cmd.Flags().GetString("api-key")
	if err != nil {
		return nil, err
	}
	dtEditParams.Url = url
	dtEditParams.ApiKey = apiKey

	dtEditParams.Output, _ = cmd.Flags().GetString("output")

	subject, _ := cmd.Flags().GetString("subject")
	dtEditParams.Subject = subject

	search, _ := cmd.Flags().GetString("search")
	dtEditParams.Search = search

	missing, _ := cmd.Flags().GetBool("missing")
	dtEditParams.Missing = missing

	append, _ := cmd.Flags().GetBool("append")
	dtEditParams.Append = append

	name, _ := cmd.Flags().GetString("name")
	dtEditParams.Name = name

	version, _ := cmd.Flags().GetString("version")
	dtEditParams.Version = version

	supplier, _ := cmd.Flags().GetString("supplier")
	dtEditParams.Supplier = supplier

	authors, _ := cmd.Flags().GetStringSlice("author")
	dtEditParams.Authors = authors

	purl, _ := cmd.Flags().GetString("purl")
	dtEditParams.Purl = purl

	cpe, _ := cmd.Flags().GetString("cpe")
	dtEditParams.Cpe = cpe

	licenses, _ := cmd.Flags().GetStringSlice("license")
	dtEditParams.Licenses = licenses

	hashes, _ := cmd.Flags().GetStringSlice("hash")
	dtEditParams.Hashes = hashes

	tools, _ := cmd.Flags().GetStringSlice("tool")
	dtEditParams.Tools = tools

	copyright, _ := cmd.Flags().GetString("copyright")
	dtEditParams.CopyRight = copyright

	lifecycles, _ := cmd.Flags().GetStringSlice("lifecycle")
	dtEditParams.Lifecycles = lifecycles

	description, _ := cmd.Flags().GetString("description")
	dtEditParams.Description = description

	repository, _ := cmd.Flags().GetString("repository")
	dtEditParams.Repository = repository

	typ, _ := cmd.Flags().GetString("type")
	dtEditParams.Type = typ

	timestamp, _ := cmd.Flags().GetBool("timestamp")
	dtEditParams.Timestamp = timestamp

	fmt.Println("args: ", args[0])

	argID, err := uuid.Parse(args[0])
	fmt.Println("argID: ", argID)

	if err != nil {
		return nil, err
	}
	dtEditParams.ProjectIds = argID
	return dtEditParams, nil
}

func extractArgsFromDTtoEdit(dtEditParams *dt.EditParams) (*edit.EditParams, error) {
	editParams := edit.NewEditParams()

	editParams.Output = dtEditParams.Output
	editParams.Subject = dtEditParams.Subject
	editParams.Search = dtEditParams.Search
	editParams.Missing = dtEditParams.Missing
	editParams.Append = dtEditParams.Append
	editParams.Name = dtEditParams.Name
	editParams.Version = dtEditParams.Version
	editParams.Supplier = dtEditParams.Supplier
	editParams.Authors = dtEditParams.Authors
	editParams.Purl = dtEditParams.Purl
	editParams.Cpe = dtEditParams.Cpe
	editParams.Licenses = dtEditParams.Licenses
	editParams.Hashes = dtEditParams.Hashes
	editParams.Tools = dtEditParams.Tools
	editParams.CopyRight = dtEditParams.CopyRight
	editParams.Lifecycles = dtEditParams.Lifecycles
	editParams.Description = dtEditParams.Description
	editParams.Repository = dtEditParams.Repository
	editParams.Type = dtEditParams.Type
	editParams.Timestamp = dtEditParams.Timestamp
	editParams.Input = dtEditParams.Input

	return editParams, nil
}
