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

package extract

import (
	"context"
	"fmt"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/enrich/types"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
)

// type EnrichmentTarget struct {
// 	Component sbom.GetComponent
// 	Field     string
// }

// // extract all the components with missing or NOASSERTION licenses
// func Extractor(sbom sbom.Document, fields []string, force bool) []types.EnrichmentTarget {
// 	targets := []types.EnrichmentTarget{}
// 	for _, comp := range sbom.Components() {
// 		for _, field := range fields {
// 			if field == "license" {
// 				if force || comp.GetPackageLicenseConcluded() == "" || comp.GetPackageLicenseConcluded() == "NOASSERTION" {
// 					targets = append(targets, types.EnrichmentTarget{Component: comp, Field: field})
// 				}
// 			}
// 			// Future: Add for supplier, downloadLocation
// 		}
// 	}
// 	return targets
// }

// Components selects components needing license enrichment
func Components(ctx context.Context, sbomDoc sbom.SBOMDocument, params *types.EnrichConfig) ([]interface{}, error) {
	log := logger.FromContext(ctx)

	var selectedComponents []interface{}
	var totalComponents int
	var totalSelectedComponents int

	switch doc := sbomDoc.Document().(type) {
	case *spdx.Document:
		for _, p := range doc.Packages {
			totalComponents++
			if shouldSelectSPDXComponent(*p, params) {
				selectedComponents = append(selectedComponents, p)
				totalSelectedComponents++
			}
		}

	case *cydx.BOM:
		if doc.Components != nil {
			for _, component := range *doc.Components {
				totalComponents++
				if shouldSelectCDXComponent(&component, params) {
					selectedComponents = append(selectedComponents, component)
					totalSelectedComponents++
				}
			}
		}
		// Check metadata.component
		if doc.Metadata != nil && doc.Metadata.Component != nil {
			totalComponents++
			if shouldSelectCDXComponent(doc.Metadata.Component, params) {
				totalSelectedComponents++
				selectedComponents = append(selectedComponents, *doc.Metadata.Component)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported SBOM format")
	}

	if len(selectedComponents) == 0 {
		return nil, fmt.Errorf("no components matched the selection criteria")
	}

	if params.Verbose {
		log.Infof("Total components: %d, Total selected components: %d", totalComponents, totalSelectedComponents)
	}

	return selectedComponents, nil
}

// shouldSelectSPDXComponent checks if an SPDX package needs license enrichment
func shouldSelectSPDXComponent(pkg spdx.Package, params *types.EnrichConfig) bool {
	for _, field := range params.Fields {
		if field == "license" {
			if params.Force || pkg.PackageLicenseConcluded == "" || pkg.PackageLicenseConcluded == "NOASSERTION" {
				return true
			}
		}
	}
	return false
}

// shouldSelectCDXComponent checks if a CycloneDX component needs license enrichment
func shouldSelectCDXComponent(comp *cydx.Component, params *types.EnrichConfig) bool {
	for _, field := range params.Fields {
		if field == "license" {
			license := ""
			if comp.Licenses != nil && len(*comp.Licenses) > 0 {
				if (*comp.Licenses)[0].License != nil {
					license = (*comp.Licenses)[0].License.ID
				}
			}
			if params.Force || license == "" || license == "NOASSERTION" {
				return true
			}
		}
	}
	return false
}
