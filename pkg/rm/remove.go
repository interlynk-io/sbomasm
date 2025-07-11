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
	"fmt"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type SCOPE string

const (
	DOCUMENT   SCOPE = "document"
	COMPONENT  SCOPE = "component"
	DEPENDENCY SCOPE = "dependency"
)

func rmCycloneDX(ctx context.Context, bom *cydx.BOM, params *types.RmParams) error {
	switch params.Kind {
	case types.FieldRemoval:
		return handleCDXFieldRemoval(ctx, bom, params)
	case types.ComponentRemoval:
		// TODO: Implement
		return fmt.Errorf("component removal not implemented yet")
	case types.DependencyRemoval:
		// TODO: Implement
		return fmt.Errorf("dependency removal not implemented yet")
	default:
		// return sbom.ErrInvalidRemovalKind
		return fmt.Errorf("invalid removal kind: %s", params.Kind)
	}
}

func handleCDXFieldRemoval(ctx context.Context, bom *cydx.BOM, params *types.RmParams) error {
	switch SCOPE(params.Scope) {
	case DOCUMENT:
		return handleFieldFromCDXDocument(ctx, bom, params)
	case COMPONENT:
		// return removeFieldFromCDXComponents(ctx, bom, params)
	case DEPENDENCY:
		// return removeFieldFromCDXDependencies(ctx, bom, params)
	default:
		return fmt.Errorf("invalid scope for field removal: %s", params.Scope)
	}
	return fmt.Errorf("field removal for scope %q not implemented", params.Scope)
}

func handleFieldFromCDXDocument(ctx context.Context, bom *cydx.BOM, params *types.RmParams) error {
	// no metadata, nothing to remove
	if bom.Metadata == nil {
		return nil
	}

	// first select field
	selected, err := selectFieldFromCDXDocument(bom, params)
	if err != nil {
		return err
	}

	// Filter target entries
	targets, err := filterFieldFromCDXDocument(selected, params)
	if err != nil {
		return fmt.Errorf("failed to filter target entries: %w", err)
	}

	if len(targets) == 0 {
		fmt.Println("No matching fields found.")
		return nil
	}

	// log it or summarize about it
	if params.DryRun {
		fmt.Println("Dry-run mode: matched entries that would be removed:")
		for _, entry := range selected {
			fmt.Printf("  - %v\n", entry)
		}
		return nil
	}

	if params.Summary {
		renderFieldSummary(params.Field, selected)
		return nil
	}

	// and finally remove that field from the document
	return removeTargetFieldFromCDXDocument(bom, targets, params)
}

func selectFieldFromCDXDocument(bom *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	field := strings.ToLower(params.Field)

	switch DOCFIELD(field) {
	case AUTHOR:
		return cdx.SelectAuthorFromMetadata(bom)
	case SUPPLIER:
		return cdx.SelectSupplierFromMetadata(bom)
	case TIMESTAMP:
		return cdx.SelectTimestampFromMetadata(bom)
	case TOOL:
		return cdx.SelectToolFromMetadata(bom)
	case LICENSE:
		return cdx.SelectLicenseFromMetadata(bom)
	case LIFECYCLE:
		return cdx.SelectLifecycleFromMetadata(bom)
	case DESCRIPTION:
		// return selectDescriptionFromMetadata(bom, params)
	case REPOSITORY:
		return cdx.SelectRepositoryFromMetadata(bom)

	}
	return nil, fmt.Errorf("unsupported document field for CycloneDX: %s", field)
}

func filterFieldFromCDXDocument(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	field := strings.ToLower(params.Field)

	switch DOCFIELD(field) {
	case AUTHOR:
		return cdx.FilterAuthorFromMetadata(selected, params)
	case SUPPLIER:
		return cdx.FilterSupplierFromMetadata(selected, params)
	case TIMESTAMP:
		// return filterTimestampFromMetadata(selected, params)
	case TOOL:
		// return filterToolFromMetadata(selected, params)
	case LICENSE:
		return cdx.FilterLicenseFromMetadata(selected, params)
	case DESCRIPTION:
		// return filterDescriptionFromMetadata(bom, params)
	case REPOSITORY:
		// return filterRepositoryFromMetadata(bom, params)

	}
	return nil, fmt.Errorf("unsupported document field for CycloneDX: %s", field)
}

func renderFieldSummary(field string, selected []interface{}) {
	switch DOCFIELD(field) {
	case AUTHOR:
		cdx.RenderSummaryAuthor(selected)
	case SUPPLIER:
		cdx.RenderSummarySupplier(selected)
	case TOOL:
		cdx.RenderSummaryTool(selected)
	case LICENSE:
		cdx.RenderSummaryLicense(selected)
	// Add more as needed
	default:
		fmt.Println("📋 Summary of removed entries:")
		for _, entry := range selected {
			fmt.Printf("  - %v\n", entry)
		}
	}
}

func removeTargetFieldFromCDXDocument(bom *cydx.BOM, targets []interface{}, params *types.RmParams) error {
	switch strings.ToLower(params.Field) {
	case "author":
		return cdx.RemoveAuthorFromMetadata(bom, targets)
	case "supplier":
		return cdx.RemoveSupplierFromMetadata(bom, targets)
	case "timestamp":
		// return removeTimestampFromMetadata(bom, targets)
	case "tool":
		// return removeToolFromMetadata(bom, targets)
	case "license":
		return cdx.RemoveLicenseFromMetadata(bom, targets)
	case "description":
		// return removeDescriptionFromMetadata(bom, targets)
	}

	return fmt.Errorf("removal for field %q not implemented", params.Field)
}
