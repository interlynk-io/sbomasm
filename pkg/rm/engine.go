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

package rm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	cdxcomp "github.com/interlynk-io/sbomasm/v2/pkg/rm/field/cdx"
	spdxcomp "github.com/interlynk-io/sbomasm/v2/pkg/rm/field/spdx"
	"github.com/interlynk-io/sbomasm/v2/pkg/rm/types"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

func Engine(ctx context.Context, args []string, params *types.RmParams) error {
	log := logger.FromContext(ctx)

	log.Debugf("Executing engine")

	inputFile := args[0]
	if inputFile == "" {
		return errors.New("input file path not provided")
	}

	// open sbom file
	f, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open file %q: %w", inputFile, err)
	}
	defer f.Close()

	// detect sbom format
	spec, format, err := sbom.Detect(f)
	if err != nil {
		return fmt.Errorf("failed to detect SBOM format: %w", err)
	}

	log.Debugf("Detected SBOM format: %s, spec: %s", format, spec)

	// rewind before parsing
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to rewind file: %w", err)
	}

	// parse into SBOM object
	sbomDoc, err := sbom.ParseSBOM(f, spec, format)
	if err != nil {
		return err
	}

	switch spec {
	case sbom.SBOMSpecCDX:
		bom, ok := sbomDoc.Document().(*cydx.BOM)
		if !ok {
			return fmt.Errorf("expected CycloneDX BOM, got %T", sbomDoc.Document())
		}
		log.Debugf("CycloneDX BOM detected, registering handlers")

		RegisterHandlers(bom, nil)
	case sbom.SBOMSpecSPDX:
		doc, ok := sbomDoc.Document().(*spdx.Document)
		if !ok {
			return fmt.Errorf("expected SPDX doc, got %T", sbomDoc.Document())
		}
		log.Debugf("SPDX Doc detected, registering handlers")
		RegisterHandlers(nil, doc)
	default:
		return fmt.Errorf("unsupported spec: %s", spec)
	}

	err = Remove(ctx, sbomDoc, params)
	if err != nil {
		return err
	}

	// Skip writing output in dry-run mode
	if params.DryRun {
		return nil
	}

	fmt.Println("successfully removed...")

	if params.OutputFile != "" {

		f, err := os.Create(params.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()

		if err := sbom.WriteSBOM(f, sbomDoc); err != nil {
			return fmt.Errorf("failed to write SBOM to file: %w", err)
		}

		fmt.Printf("updated SBOM written to file: %s", params.OutputFile)
	} else {

		if err := sbom.WriteSBOM(os.Stdout, sbomDoc); err != nil {
			return fmt.Errorf("failed to write SBOM to stdout: %w", err)
		}
		fmt.Printf("no output file specified, writing to stdout")

	}

	return nil
}

func (f *FieldOperationEngine) ExecuteDocumentFieldRemoval(ctx context.Context, params *types.RmParams) error {
	log := logger.FromContext(ctx)
	log.Debugf("Initializing field removal process for document metadata")

	spec, scope, field := f.doc.SpecType(), strings.ToLower(params.Scope), strings.ToLower(params.Field)
	key := fmt.Sprintf("%s:%s:%s", strings.ToLower(spec), scope, field)

	log.Debugf("Handler key: %s", key)

	handler, ok := handlerRegistry[key]
	if !ok {
		return fmt.Errorf("no handler registered for key: %s", key)
	}

	selected, err := handler.Select(params)
	if err != nil {
		return err
	}

	if len(selected) == 0 {
		log.Debugf("No matching entries found.")
		return nil
	}

	targets, err := handler.Filter(selected, params)
	if err != nil {
		return err
	}

	if len(targets) == 0 {
		log.Debugf("No matching entries found.")
		return nil
	}

	if params.Summary {
		handler.Summary(selected)
		return nil
	}
	if params.DryRun {
		fmt.Printf("Dry-run: matched entries:\n")
		for _, entry := range targets {
			switch e := entry.(type) {
			case common.Creator:
				fmt.Printf("  - Creator: %s (%s)\n", e.Creator, e.CreatorType)
			case spdx.Originator:
				fmt.Printf("  - Author: %s (%s)\n", e.Originator, e.OriginatorType)
			case spdx.Supplier:
				fmt.Printf("  - Supplier: %s (%s)\n", e.Supplier, e.SupplierType)
			case cydx.OrganizationalContact:
				fmt.Printf("  - Author: %s (%s)\n", e.Name, e.Email)
			case cydx.OrganizationalEntity:
				fmt.Printf("  - Supplier: %s\n", e.Name)
			case cydx.LicenseChoice:
				if e.License != nil {
					if e.License.ID != "" {
						fmt.Printf("  - License: %s\n", e.License.ID)
					} else if e.License.Name != "" {
						fmt.Printf("  - License: %s\n", e.License.Name)
					}
				} else if e.Expression != "" {
					fmt.Printf("  - License Expression: %s\n", e.Expression)
				}
			case cydx.Lifecycle:
				fmt.Printf("  - Lifecycle: %s\n", e.Phase)
			case cydx.Tool:
				fmt.Printf("  - Tool: %s@%s\n", e.Name, e.Version)
			case cydx.Component:
				fmt.Printf("  - Tool: %s@%s\n", e.Name, e.Version)
			case []cydx.Component:
				for _, c := range e {
					fmt.Printf("  - Tool: %s@%s\n", c.Name, c.Version)
				}
			case []cydx.Tool:
				for _, t := range e {
					fmt.Printf("  - Tool: %s@%s\n", t.Name, t.Version)
				}
			case []cydx.OrganizationalContact:
				for _, a := range e {
					fmt.Printf("  - Author: %s (%s)\n", a.Name, a.Email)
				}
			case string:
				// timestamp, repository URL, etc.
				fmt.Printf("  - %s\n", e)
			default:
				fmt.Printf("  - %v\n", entry)
			}
		}
		return nil
	}

	return handler.Remove(targets, params)
}

func (f *FieldOperationEngine) ExecuteComponentFieldRemoval(ctx context.Context, params *types.RmParams) error {
	log := logger.FromContext(ctx)
	log.Debugf("Initializing field removal process for components")

	compEngine := &FieldOperationComponentEngine{doc: f.doc}
	selectedComponents, err := compEngine.SelectComponents(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to select components: %w", err)
	}
	if len(selectedComponents) == 0 {
		log.Debugf("No matching components found.")
		return nil
	}

	// Step 2: For each selected component, operate on field
	spec, field := f.doc.SpecType(), strings.ToLower(params.Field)
	key := fmt.Sprintf("%s:%s:%s", strings.ToLower(spec), "component", field)

	log.Debugf("Handler key for field removal: %s", key)

	handler, ok := handlerRegistry[key]
	if !ok {
		return fmt.Errorf("no handler registered for key: %s", key)
	}

	params.SelectedComponents = selectedComponents

	// Step 3: Select field entries from components
	selected, err := handler.Select(params)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		log.Debugf("No matching fields found in selected components.")
		return nil
	}

	// Step 4: Filter fields
	targets, err := handler.Filter(selected, params)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		log.Debugf("No matching field entries after filtering.")
		return nil
	}

	if params.Summary {
		handler.Summary(selected)
		return nil
	}
	if params.DryRun {
		fmt.Printf("Dry-run: matched field entries:\n")
		for _, entry := range targets {
			switch e := entry.(type) {
			case spdxcomp.AuthorEntry:
				author := ""
				if e.Originator != nil {
					author = e.Originator.Originator
				}
				fmt.Printf("  - %s@%s: %s\n", e.Package.PackageName, e.Package.PackageVersion, author)
			case spdxcomp.SupplierEntry:
				supplier := ""
				if e.Supplier != nil {
					supplier = e.Supplier.Supplier
				}
				fmt.Printf("  - %s@%s: %s\n", e.Package.PackageName, e.Package.PackageVersion, supplier)
			case spdxcomp.DescriptionEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Package.PackageName, e.Package.PackageVersion, e.Value)
			case spdxcomp.CopyrightEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Package.PackageName, e.Package.PackageVersion, e.Value)
			case spdxcomp.RepositoryEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Package.PackageName, e.Package.PackageVersion, e.Value)
			case spdxcomp.LicenseEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Package.PackageName, e.Package.PackageVersion, e.Value)
			case spdxcomp.TypeEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Package.PackageName, e.Package.PackageVersion, e.Value)
			case spdxcomp.CpeEntry:
				cpe := ""
				if e.Ref != nil {
					cpe = e.Ref.Locator
				}
				fmt.Printf("  - %s@%s: %s\n", e.Package.PackageName, e.Package.PackageVersion, cpe)
			case spdxcomp.HashEntry:
				hash := ""
				if e.Checksum != nil {
					hash = e.Checksum.Value
				}
				fmt.Printf("  - %s@%s: %s\n", e.Package.PackageName, e.Package.PackageVersion, hash)
			case spdxcomp.PurlEntry:
				purl := ""
				if e.Ref != nil {
					purl = e.Ref.Locator
				}
				fmt.Printf("  - %s@%s: %s\n", e.Package.PackageName, e.Package.PackageVersion, purl)
			case cdxcomp.AuthorEntry:
				author := ""
				if e.Author != nil {
					author = fmt.Sprintf("%s (%s)", e.Author.Name, e.Author.Email)
				}
				fmt.Printf("  - %s@%s: %s\n", e.Component.Name, e.Component.Version, author)
			case cdxcomp.SupplierEntry:
				supplier := ""
				if e.Value != nil {
					supplier = e.Value.Name
				}
				fmt.Printf("  - %s@%s: %s\n", e.Component.Name, e.Component.Version, supplier)
			case cdxcomp.DescriptionEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Component.Name, e.Component.Version, e.Value)
			case cdxcomp.CopyrightEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Component.Name, e.Component.Version, e.Value)
			case cdxcomp.RepositoryEntry:
				url := ""
				if e.Ref != nil {
					url = e.Ref.URL
				}
				fmt.Printf("  - %s@%s: %s\n", e.Component.Name, e.Component.Version, url)
			case cdxcomp.LicenseEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Component.Name, e.Component.Version, e.Value)
			case cdxcomp.TypeEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Component.Name, e.Component.Version, e.Value)
			case cdxcomp.CpeEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Component.Name, e.Component.Version, e.Ref)
			case cdxcomp.HashEntry:
				hash := ""
				if e.Hash != nil {
					hash = e.Hash.Value
				}
				fmt.Printf("  - %s@%s: %s\n", e.Component.Name, e.Component.Version, hash)
			case cdxcomp.PurlEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Component.Name, e.Component.Version, e.Value)
			case cdxcomp.GroupEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Component.Name, e.Component.Version, e.Value)
			case cdxcomp.PublisherEntry:
				fmt.Printf("  - %s@%s: %s\n", e.Component.Name, e.Component.Version, e.Value)
			default:
				fmt.Printf("  - %v\n", entry)
			}
		}
		return nil
	}

	// Step 5: Remove matched fields from components
	return handler.Remove(targets, params)
}
