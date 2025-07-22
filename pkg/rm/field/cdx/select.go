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

package cdx

import (
	"fmt"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

// func selectFromCDXDependency(bom *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
// 	return nil, fmt.Errorf("CDX dependency selection not implemented yet")
// }

func SelectAuthorFromMetadata(bom *cydx.BOM) ([]interface{}, error) {
	if bom.Metadata.Authors == nil || len(*bom.Metadata.Authors) == 0 {
		return nil, nil
	}
	fmt.Println("Selecting authors from metadata: ", bom.Metadata.Authors)

	return []interface{}{*bom.Metadata.Authors}, nil
}

func SelectAuthorFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var finalComponents []interface{}

	for _, originalComp := range *doc.Components {
		for _, sel := range params.SelectedComponents {
			selectedComp, ok := sel.(*cydx.Component)
			if !ok {
				continue
			}

			if *selectedComp == originalComp && originalComp.Authors != nil && len(*originalComp.Authors) > 0 {
				fmt.Println("Selecting authors from component: ", *originalComp.Authors)
				finalComponents = append(finalComponents, originalComp)
			}
		}
	}
	if len(finalComponents) == 0 {
		return nil, nil
	}
	fmt.Println("Selecting authors from component: ", finalComponents)
	return finalComponents, nil
}

func SelectCopyrightFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var finalComponents []interface{}

	for _, originalComp := range *doc.Components {
		for _, sel := range params.SelectedComponents {
			selectedComp, ok := sel.(*cydx.Component)
			if !ok {
				continue
			}

			if *selectedComp == originalComp && originalComp.Copyright != "" {
				fmt.Println("Selecting copyright from component: ", originalComp.Copyright)
				finalComponents = append(finalComponents, originalComp)
			}
		}
	}
	if len(finalComponents) == 0 {
		return nil, nil
	}
	fmt.Println("Selecting copyright from component: ", finalComponents)
	return finalComponents, nil
}

func SelectCpeFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var finalComponents []interface{}

	for _, originalComp := range *doc.Components {
		for _, sel := range params.SelectedComponents {
			selectedComp, ok := sel.(*cydx.Component)
			if !ok {
				continue
			}

			if *selectedComp == originalComp && originalComp.CPE != "" {
				fmt.Println("Selecting CPE from component: ", originalComp.CPE)
				finalComponents = append(finalComponents, originalComp)
			}
		}
	}

	if len(finalComponents) == 0 {
		return nil, nil
	}
	fmt.Println("Selecting CPE from component: ", finalComponents)
	return finalComponents, nil
}

func SelectDescriptionFromComponent(bom *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var finalComponents []interface{}

	for _, originalComp := range *bom.Components {
		for _, sel := range params.SelectedComponents {
			selectedComp, ok := sel.(*cydx.Component)
			if !ok {
				continue
			}

			if *selectedComp == originalComp && originalComp.Description != "" {
				fmt.Println("Selecting description from component: ", originalComp.Description)
				finalComponents = append(finalComponents, originalComp)
			}
		}
	}

	if len(finalComponents) == 0 {
		return nil, nil
	}
	fmt.Println("Selecting description from component: ", finalComponents)
	return finalComponents, nil
}

func SelectLicenseFromComponent(bom *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var finalComponents []interface{}

	for _, originalComp := range *bom.Components {
		for _, sel := range params.SelectedComponents {
			selectedComp, ok := sel.(*cydx.Component)
			if !ok {
				continue
			}

			if *selectedComp == originalComp && originalComp.Licenses != nil && len(*originalComp.Licenses) > 0 {
				fmt.Println("Selecting licenses from component: ", originalComp.Licenses)
				finalComponents = append(finalComponents, originalComp)
			}
		}
	}
	if len(finalComponents) == 0 {
		return nil, nil
	}

	fmt.Println("Selecting licenses from component: ", finalComponents)
	return finalComponents, nil
}

func SelectHashFromComponent(bom *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var finalComponents []interface{}

	for _, originalComp := range *bom.Components {
		for _, sel := range params.SelectedComponents {
			selectedComp, ok := sel.(*cydx.Component)
			if !ok {
				continue
			}

			if *selectedComp == originalComp && originalComp.Hashes != nil && len(*originalComp.Hashes) > 0 {
				fmt.Println("Selecting hashes from component: ", originalComp.Hashes)
				finalComponents = append(finalComponents, originalComp)
			}
		}
	}

	if len(finalComponents) == 0 {
		return nil, nil
	}

	return finalComponents, nil
}

func SelectPurlFromComponent(bom *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var finalComponents []interface{}

	for _, originalComp := range *bom.Components {
		for _, sel := range params.SelectedComponents {
			selectedComp, ok := sel.(*cydx.Component)
			if !ok {
				continue
			}

			if *selectedComp == originalComp && originalComp.PackageURL != "" {
				fmt.Println("Selecting PURL from component: ", originalComp.PackageURL)
				finalComponents = append(finalComponents, originalComp)
			}
		}
	}

	if len(finalComponents) == 0 {
		return nil, nil
	}
	fmt.Println("Selecting PURL from component: ", finalComponents)
	return finalComponents, nil
}

func SelectSupplierFromComponent(bom *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var finalComponents []interface{}

	for _, originalComp := range *bom.Components {
		for _, sel := range params.SelectedComponents {
			selectedComp, ok := sel.(*cydx.Component)
			if !ok {
				continue
			}

			if *selectedComp == originalComp && originalComp.Supplier != nil {
				fmt.Println("Selecting supplier from component: ", originalComp.Supplier)
				finalComponents = append(finalComponents, originalComp)
			}
		}
	}

	if len(finalComponents) == 0 {
		return nil, nil
	}

	fmt.Println("Selecting supplier from component: ", finalComponents)
	return finalComponents, nil
}

func SelectRepoFromComponent(bom *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var finalComponents []interface{}

	for _, originalComp := range *bom.Components {
		for _, sel := range params.SelectedComponents {
			selectedComp, ok := sel.(*cydx.Component)
			if !ok {
				continue
			}

			if *selectedComp == originalComp && originalComp.ExternalReferences != nil && len(*originalComp.ExternalReferences) > 0 {
				for _, ref := range *originalComp.ExternalReferences {
					if ref.Type == "vcs" || ref.Type == "distribution" {
						fmt.Println("Selecting repository from component: ", ref)
						finalComponents = append(finalComponents, originalComp)
						break
					}
				}
			}
		}
	}

	if len(finalComponents) == 0 {
		return nil, nil
	}

	fmt.Println("Selecting repositories from component: ", finalComponents)
	return finalComponents, nil
}

func SelectTypeFromComponent(bom *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var finalComponents []interface{}

	for _, originalComp := range *bom.Components {
		for _, sel := range params.SelectedComponents {
			selectedComp, ok := sel.(*cydx.Component)
			if !ok {
				continue
			}

			if *selectedComp == originalComp && originalComp.Type != "" {
				fmt.Println("Selecting type from component: ", originalComp.Type)
				finalComponents = append(finalComponents, originalComp)
			}
		}
	}

	if len(finalComponents) == 0 {
		return nil, nil
	}

	return finalComponents, nil
}

func SelectSupplierFromMetadata(bom *cydx.BOM) ([]interface{}, error) {
	if bom.Metadata.Supplier == nil {
		return nil, nil
	}
	return []interface{}{*bom.Metadata.Supplier}, nil
}

func SelectTimestampFromMetadata(bom *cydx.BOM) ([]interface{}, error) {
	if bom.Metadata.Timestamp == "" {
		return nil, nil
	}

	fmt.Println("Selecting timestamp from metadata: ", bom.Metadata.Timestamp)
	return []interface{}{bom.Metadata.Timestamp}, nil
}

func SelectToolFromMetadata(bom *cydx.BOM) ([]interface{}, error) {
	if bom.Metadata.Tools == nil {
		return nil, nil
	}

	if bom.SpecVersion > cydx.SpecVersion1_4 {
		if bom.Metadata.Tools.Components == nil {
			return nil, nil
		}
		return []interface{}{*bom.Metadata.Tools.Components}, nil
	}

	if *bom.Metadata.Tools.Tools == nil {
		return nil, nil
	}
	fmt.Println("Selecting tools from metadata: ", bom.Metadata.Tools.Tools)
	return []interface{}{*bom.Metadata.Tools.Tools}, nil
}

func SelectLicenseFromMetadata(bom *cydx.BOM) ([]interface{}, error) {
	if bom.Metadata.Licenses == nil {
		return nil, nil
	}

	var selected []interface{}
	for _, licenseChoice := range *bom.Metadata.Licenses {
		selected = append(selected, licenseChoice)
	}

	fmt.Println("Selecting licenses from metadata:", selected)
	return selected, nil
}

func SelectLifecycleFromMetadata(bom *cydx.BOM) ([]interface{}, error) {
	if bom.Metadata.Lifecycles == nil {
		return nil, nil
	}
	return []interface{}{*bom.Metadata.Lifecycles}, nil
}

func SelectRepositoryFromMetadata(bom *cydx.BOM) ([]interface{}, error) {
	if bom.ExternalReferences == nil || len(*bom.ExternalReferences) == 0 {
		return nil, nil
	}

	fmt.Println("Selecting repositories from metadata: ", bom.ExternalReferences)
	return []interface{}{*bom.ExternalReferences}, nil
}
