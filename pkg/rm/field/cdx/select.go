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

func SelectAuthorFromComponents(component *cydx.Component) ([]interface{}, error) {
	if component.Authors == nil || len(*component.Authors) == 0 {
		return nil, nil
	}

	fmt.Println("Selecting authors from component: ", component.Authors)
	return []interface{}{*component.Authors}, nil
}

func SelectCopyrightFromComponents(component *cydx.Component) ([]interface{}, error) {
	if component.Copyright == "" {
		return nil, nil
	}

	fmt.Println("Selecting copyright from component: ", component.Copyright)
	return []interface{}{component.Copyright}, nil
}

func SelectCPEFromComponent(component *cydx.Component) ([]interface{}, error) {
	if component.CPE == "" {
		return nil, nil
	}

	fmt.Println("Selecting CPE from component: ", component.CPE)
	return []interface{}{component.CPE}, nil
}

func SelectDescriptionFromComponent(component *cydx.Component) ([]interface{}, error) {
	if component.Description == "" {
		return nil, nil
	}

	fmt.Println("Selecting description from component: ", component.Description)
	return []interface{}{component.Description}, nil
}

func SelectLicenseFromComponent(component *cydx.Component) ([]interface{}, error) {
	if component.Licenses == nil || len(*component.Licenses) == 0 {
		return nil, nil
	}

	var selected []interface{}
	for _, licenseChoice := range *component.Licenses {
		selected = append(selected, licenseChoice)
	}

	fmt.Println("Selecting licenses from component: ", selected)
	return selected, nil
}

func SelectHashFromComponent(component *cydx.Component) ([]interface{}, error) {
	if component.Hashes == nil || len(*component.Hashes) == 0 {
		return nil, nil
	}

	var selected []interface{}
	for _, hash := range *component.Hashes {
		selected = append(selected, hash)
	}

	fmt.Println("Selecting hashes from component: ", selected)
	return selected, nil
}

func SelectPurlFromComponent(component *cydx.Component) ([]interface{}, error) {
	if component.PackageURL == "" {
		return nil, nil
	}

	fmt.Println("Selecting PURL from component: ", component.PackageURL)
	return []interface{}{component.PackageURL}, nil
}

func SelectSupplierFromComponent(component *cydx.Component) ([]interface{}, error) {
	if component.Supplier == nil {
		return nil, nil
	}

	fmt.Println("Selecting supplier from component: ", component.Supplier)
	return []interface{}{*component.Supplier}, nil
}

func SelectRepoFromComponent(component *cydx.Component) ([]interface{}, error) {
	if component.ExternalReferences == nil || len(*component.ExternalReferences) == 0 {
		return nil, nil
	}

	fmt.Println("Selecting repositories from component: ", component.ExternalReferences)
	return []interface{}{*component.ExternalReferences}, nil
}

func SelectTypeFromComponent(component *cydx.Component) ([]interface{}, error) {
	if component.Type == "" {
		return nil, nil
	}

	fmt.Println("Selecting type from component: ", component.Type)
	return []interface{}{component.Type}, nil
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
