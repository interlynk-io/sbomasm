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
	"log"
	"os"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
)

func Engine(ctx context.Context, args []string, params *types.RmParams) error {
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

	fmt.Println("Detected SBOM format:", format)
	fmt.Println("Detected SBOM spec:", spec)

	// rewind before parsing
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to rewind file: %w", err)
	}

	// parse into SBOM object
	sbomDoc, err := sbom.ParseSBOM(f, spec, format)
	if err != nil {
		return err
	}

	// Cast the underlying raw doc to correct type for registration
	switch spec {
	case sbom.SBOMSpecCDX:
		RegisterHandlers(sbomDoc.Raw().(*cydx.BOM), nil)
	case sbom.SBOMSpecSPDX:
		doc, ok := sbomDoc.Raw().(*spdx.Document)
		if !ok {
			// handle error, maybe return or panic, depending on your use case
			log.Println("Could not assert SPDX document")
		}
		RegisterHandlers(nil, doc)
	default:
		return fmt.Errorf("unsupported spec: %s", spec)
	}

	err = Remove(ctx, sbomDoc, params)
	if err != nil {
		return err
	}

	// 🧾 Step: Output the modified SBOM
	if params.OutputFile != "" {
		fmt.Println("Writing updated SBOM to file:", params.OutputFile)
		// Write to file
		f, err := os.Create(params.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()

		if err := sbom.WriteSBOM(f, sbomDoc); err != nil {
			return fmt.Errorf("failed to write SBOM to file: %w", err)
		}
		fmt.Printf("✅ Updated SBOM written to file: %s\n", params.OutputFile)
	} else {
		// Write to stdout
		if err := sbom.WriteSBOM(os.Stdout, sbomDoc); err != nil {
			return fmt.Errorf("failed to write SBOM to stdout: %w", err)
		}
	}

	return fmt.Errorf("unsupported SBOM spec type: %s", spec)
}

func (f *FieldOperationEngine) ExecuteDocumentFieldRemoval(ctx context.Context, params *types.RmParams) error {
	spec, scope, field := f.doc.SpecType(), strings.ToLower(params.Scope), strings.ToLower(params.Field)
	key := fmt.Sprintf("%s:%s:%s", strings.ToLower(spec), scope, field)

	handler, ok := handlerRegistry[key]
	if !ok {
		return fmt.Errorf("no handler registered for key: %s", key)
	}

	selected, err := handler.Select(params)
	if err != nil {
		return err
	}

	if len(selected) == 0 {
		fmt.Println("No matching entries found.")
		return nil
	}

	targets, err := handler.Filter(selected, params)
	if err != nil {
		return err
	}

	if len(targets) == 0 {
		fmt.Println("No matching entries found.")
		return nil
	}

	if params.Summary {
		handler.Summary(selected)
		return nil
	}
	if params.DryRun {
		fmt.Println("Dry-run: matched entries:")
		for _, entry := range targets {
			fmt.Printf("  - %v\n", entry)
		}
		return nil
	}

	return handler.Remove(targets, params)
}

func (f *FieldOperationEngine) ExecuteComponentFieldRemoval(ctx context.Context, params *types.RmParams) error {
	// Step 1: Select relevant components
	compEngine := &FieldOperationComponentEngine{doc: f.doc}
	selectedComponents, err := compEngine.SelectComponents(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to select components: %w", err)
	}
	if len(selectedComponents) == 0 {
		fmt.Println("No matching components found.")
		return nil
	}

	fmt.Println("Total selected components for field removal:", len(selectedComponents))
	// fmt.Println("Selected components:", selectedComponents)

	// Step 2: For each selected component, operate on field
	spec, field := f.doc.SpecType(), strings.ToLower(params.Field)
	key := fmt.Sprintf("%s:%s:%s", strings.ToLower(spec), "component", field)

	handler, ok := handlerRegistry[key]
	if !ok {
		return fmt.Errorf("no handler registered for key: %s", key)
	}

	// Set selected components for field handler to operate on
	params.SelectedComponents = selectedComponents

	// Step 3: Select field entries from components
	selected, err := handler.Select(params)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		fmt.Println("No matching fields found in selected components.")
		return nil
	}

	// Step 4: Filter fields
	targets, err := handler.Filter(selected, params)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("No matching field entries after filtering.")
		return nil
	}

	if params.Summary {
		handler.Summary(selected)
		return nil
	}
	if params.DryRun {
		fmt.Println("Dry-run: matched field entries:")
		for _, entry := range targets {
			fmt.Printf("  - %v\n", entry)
		}
		return nil
	}

	// Step 5: Remove matched fields from components
	return handler.Remove(targets, params)
}
