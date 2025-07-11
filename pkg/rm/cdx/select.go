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

import cydx "github.com/CycloneDX/cyclonedx-go"

func SelectAuthorFromMetadata(bom *cydx.BOM) ([]interface{}, error) {
	if bom.Metadata.Authors == nil || len(*bom.Metadata.Authors) == 0 {
		return nil, nil
	}

	// var selected []interface{}
	// if bom.Metadata.Authors != nil {
	// 	for _, author := range *bom.Metadata.Authors {
	// 		selected = append(selected, author)
	// 	}
	// }
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
	return []interface{}{bom.Metadata.Timestamp}, nil
}

func SelectToolFromMetadata(bom *cydx.BOM) ([]interface{}, error) {
	if bom.Metadata.Tools == nil {
		return nil, nil
	}
	var selected []interface{}

	if bom.SpecVersion > cydx.SpecVersion1_4 {
		if bom.Metadata.Tools.Components == nil {
			return nil, nil
		}
		return []interface{}{*bom.Metadata.Tools.Components}, nil
		// for _, tool := range *bom.Metadata.Tools.Components {
		// 	selected = append(selected, tool)
		// }
		// return selected, nil
	}

	for _, tool := range *bom.Metadata.Tools.Tools {
		selected = append(selected, tool)
	}

	if *bom.Metadata.Tools.Tools == nil {
		return nil, nil
	}
	return []interface{}{*bom.Metadata.Tools.Tools}, nil
}

func SelectLicenseFromMetadata(bom *cydx.BOM) ([]interface{}, error) {
	if bom.Metadata.Licenses == nil {
		return nil, nil
	}
	// var selected []interface{}
	// for _, lic := range *bom.Metadata.Licenses {
	// 	selected = append(selected, lic)
	// }
	return []interface{}{*bom.Metadata.Licenses}, nil
}

func SelectLifecycleFromMetadata(bom *cydx.BOM) ([]interface{}, error) {
	if bom.Metadata.Lifecycles == nil {
		return nil, nil
	}
	// var selected []interface{}
	// for _, lifecycle := range *bom.Metadata.Lifecycles {
	// 	selected = append(selected, lifecycle)
	// }
	return []interface{}{*bom.Metadata.Lifecycles}, nil
}

func SelectRepositoryFromMetadata(bom *cydx.BOM) ([]interface{}, error) {
	if bom.ExternalReferences == nil || len(*bom.ExternalReferences) == 0 {
		return nil, nil
	}

	// var selected []interface{}
	// for _, repo := range *bom.ExternalReferences {
	// 	selected = append(selected, repo)
	// }

	return []interface{}{*bom.ExternalReferences}, nil
}
