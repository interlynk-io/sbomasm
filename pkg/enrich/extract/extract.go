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
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
)

// Extract Params
type Params struct {
	Fields  []string
	Force   bool
	Verbose bool
}

// Components selects components requiring license enrichment
func Components(ctx context.Context, sbomDoc sbom.SBOMDocument, params *Params) ([]interface{}, int, int, error) {
	log := logger.FromContext(ctx)
	log.Debugf("extracting components for enrichment")

	var selectedComponents []interface{}
	var totalComponents int
	var totalSelectedComponents int

	switch doc := sbomDoc.Document().(type) {

	case *spdx.Document:
		for _, pkg := range doc.Packages {
			totalComponents++
			if shouldSelectSPDXComponent(*pkg, params) {
				selectedComponents = append(selectedComponents, pkg)
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

		// check primary component too - metadata.component
		if doc.Metadata != nil && doc.Metadata.Component != nil {
			totalComponents++
			if shouldSelectCDXComponent(doc.Metadata.Component, params) {
				totalSelectedComponents++
				selectedComponents = append(selectedComponents, *doc.Metadata.Component)
			}
		}

	default:
		return nil, totalComponents, totalSelectedComponents, fmt.Errorf("unsupported SBOM format")
	}

	if len(selectedComponents) == 0 {
		return nil, totalComponents, totalSelectedComponents, fmt.Errorf("no components matched the selection criteria")
	}

	fmt.Printf("\nTotal Components: %d\t Selected For Enrichment: %d\n", totalComponents, totalSelectedComponents)

	log.Debugf("extracted %d components out of %d for enrichment", totalSelectedComponents, totalComponents)

	return selectedComponents, totalComponents, totalSelectedComponents, nil
}

// shouldSelectSPDXComponent checks if an SPDX package needs license enrichment
func shouldSelectSPDXComponent(pkg spdx.Package, params *Params) bool {
	for _, field := range params.Fields {
		// when field is license
		if field == "license" {
			if params.Force || pkg.PackageLicenseConcluded == "" || pkg.PackageLicenseConcluded == "NOASSERTION" || pkg.PackageLicenseDeclared == "" || pkg.PackageLicenseDeclared == "NOASSERTION" {
				return true
			}
		}

		// future work: Add checks for other fields
	}
	return false
}

// shouldSelectCDXComponent checks if a CycloneDX component needs license enrichment
func shouldSelectCDXComponent(comp *cydx.Component, params *Params) bool {
	for _, field := range params.Fields {
		// when field is license
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

		// future work: Add checks for other fields
	}
	return false
}
