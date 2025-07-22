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

func SelectAuthorFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Authors != nil {
			for _, author := range *c.Authors {
				fmt.Printf("Selecting author from component: %s@%s, Author: %s (%s)\n", c.Name, c.Version, author.Name, author.Email)
				selected = append(selected, AuthorEntry{Component: c, Author: &author})
			}
		}
	}
	if len(selected) == 0 {
		fmt.Println("No author entries found in selected components")
	}
	return selected, nil
}

func SelectSupplierFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Supplier != nil && c.Supplier.Name != "" {
			fmt.Printf("Selecting supplier from component: %s@%s, Supplier: %s\n", c.Name, c.Version, c.Supplier.Name)
			selected = append(selected, SupplierEntry{Component: c, Value: c.Supplier.Name})
		}
	}
	if len(selected) == 0 {
		fmt.Println("No supplier entries found in selected components")
	}
	return selected, nil
}

func SelectCopyrightFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Copyright != "" {
			fmt.Printf("Selecting copyright from component: %s@%s, Copyright: %s\n", c.Name, c.Version, c.Copyright)
			selected = append(selected, CopyrightEntry{Component: c, Value: c.Copyright})
		}
	}
	if len(selected) == 0 {
		fmt.Println("No copyright entries found in selected components")
	}
	return selected, nil
}

func SelectCpeFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.ExternalReferences != nil {
			for _, ref := range *c.ExternalReferences {
				if ref.Type == cydx.ERTypeSecurityContact {
					fmt.Printf("Selecting CPE from component: %s@%s, CPE: %s\n", c.Name, c.Version, ref.URL)
					selected = append(selected, CpeEntry{Component: c, Ref: &ref})
				}
			}
		}
		// Fallback to Component.CPE (deprecated but supported)
		if c.CPE != "" {
			fmt.Printf("Selecting CPE from component: %s@%s, CPE: %s\n", c.Name, c.Version, c.CPE)
			selected = append(selected, CpeEntry{Component: c, Ref: &cydx.ExternalReference{Type: cydx.ERTypeSecurityContact, URL: c.CPE}})
		}
	}
	if len(selected) == 0 {
		fmt.Println("No CPE entries found in selected components")
	}
	return selected, nil
}

func SelectDescriptionFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Description != "" {
			fmt.Printf("Selecting description from component: %s@%s, Description: %s\n", c.Name, c.Version, c.Description)
			selected = append(selected, DescriptionEntry{Component: c, Value: c.Description})
		}
	}
	if len(selected) == 0 {
		fmt.Println("No description entries found in selected components")
	}
	return selected, nil
}

func SelectHashFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Hashes != nil {
			for _, hash := range *c.Hashes {
				fmt.Printf("Selecting hash from component: %s@%s, Hash: %s (%s)\n", c.Name, c.Version, hash.Value, hash.Algorithm)
				selected = append(selected, HashEntry{Component: c, Hash: &hash})
			}
		}
	}
	if len(selected) == 0 {
		fmt.Println("No hash entries found in selected components")
	}
	return selected, nil
}

func SelectLicenseFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Licenses != nil {
			for _, license := range *c.Licenses {
				var licenseValue string
				if license.License.ID != "" {
					licenseValue = license.License.ID
				} else if license.License.Name != "" {
					licenseValue = license.License.Name
				} else if license.Expression != "" {
					licenseValue = license.Expression
				}
				if licenseValue != "" {
					fmt.Printf("Selecting license from component: %s@%s, License: %s\n", c.Name, c.Version, licenseValue)
					selected = append(selected, LicenseEntry{Component: c, Value: licenseValue})
				}
			}
		}
	}
	if len(selected) == 0 {
		fmt.Println("No license entries found in selected components")
	}
	return selected, nil
}

func SelectPurlFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.PackageURL != "" {
			fmt.Printf("Selecting PURL from component: %s@%s, PURL: %s\n", c.Name, c.Version, c.PackageURL)
			selected = append(selected, PurlEntry{Component: c, Value: c.PackageURL})
		}
		// Check ExternalReferences for purl
		if c.ExternalReferences != nil {
			for _, ref := range *c.ExternalReferences {
				if ref.Type == "purl" {
					fmt.Printf("Selecting PURL from component: %s@%s, PURL: %s\n", c.Name, c.Version, ref.URL)
					selected = append(selected, PurlEntry{Component: c, Value: ref.URL})
				}
			}
		}
	}
	if len(selected) == 0 {
		fmt.Println("No PURL entries found in selected components")
	}
	return selected, nil
}

func SelectRepoFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.ExternalReferences != nil {
			for _, ref := range *c.ExternalReferences {
				if ref.Type == cydx.ERTypeVCS || ref.Type == cydx.ERTypeDistribution {
					fmt.Printf("Selecting repository from component: %s@%s, Repository: %s\n", c.Name, c.Version, ref.URL)
					selected = append(selected, RepositoryEntry{Component: c, Ref: &ref})
				}
			}
		}
	}
	if len(selected) == 0 {
		fmt.Println("No repository entries found in selected components")
	}
	return selected, nil
}

func SelectTypeFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Type != "" {
			fmt.Printf("Selecting type from component: %s@%s, Type: %s\n", c.Name, c.Version, c.Type)
			selected = append(selected, TypeEntry{Component: c, Value: c.Type})
		}
	}
	if len(selected) == 0 {
		fmt.Println("No type entries found in selected components")
	}
	return selected, nil
}
