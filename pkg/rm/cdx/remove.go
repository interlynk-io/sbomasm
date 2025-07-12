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
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

func RemoveCDXField(bom *cydx.BOM, targets []interface{}, params *types.RmParams) error {
	switch params.Field {
	case "author":
		return RemoveAuthorFromMetadata(bom, targets)
	case "supplier":
		return RemoveSupplierFromMetadata(bom, targets)
	case "license":
		return RemoveLicenseFromMetadata(bom, targets)
	// case "tool":
	// 	return removeToolFromMetadata(bom, targets)
	default:
		// return types.ErrUnsupportedField
	}
	return nil
}

func RemoveSupplierFromMetadata(bom *cydx.BOM, targets []interface{}) error {
	if bom.Metadata.Supplier == nil {
		return nil
	}
	for _, tar := range targets {
		supplier, ok := tar.(cydx.OrganizationalEntity)
		if ok && matchSupplier(*bom.Metadata.Supplier, supplier) {
			bom.Metadata.Supplier = nil
			break
		}
	}
	return nil
}

func matchSupplier(a, b cydx.OrganizationalEntity) bool {
	return a.Name == b.Name
}

func RemoveLicenseFromMetadata(bom *cydx.BOM, targets []interface{}) error {
	if bom.Metadata.Licenses == nil {
		return nil
	}
	var filtered cydx.Licenses
	for _, lic := range *bom.Metadata.Licenses {
		match := false
		for _, tar := range targets {
			if matchLicense(tar, lic) {
				match = true
				break
			}
		}
		if !match {
			filtered = append(filtered, lic)
		}
	}
	bom.Metadata.Licenses = &filtered
	return nil
}

func matchLicense(tar interface{}, lic cydx.LicenseChoice) bool {
	candidate, ok := tar.(cydx.LicenseChoice)
	if !ok {
		return false
	}
	return candidate.Expression == lic.Expression
}

// func removeToolFromMetadata(bom *cydx.BOM, targets []interface{}) error {
// 	if bom.Metadata.Tools == nil {
// 		return nil
// 	}
// 	var filtered []cydx.Tool
// 	for _, tool := range *bom.Metadata.Tools.Components {
// 		match := false
// 		for _, tar := range targets {
// 			if matchTool(tar, tool) {
// 				match = true
// 				break
// 			}
// 		}
// 		if !match {
// 			filtered = append(filtered, tool)
// 		}
// 	}
// 	bom.Metadata.Tools = &filtered
// 	return nil
// }

func RemoveAuthorFromMetadata(bom *cydx.BOM, targets []interface{}) error {
	if bom.Metadata == nil || bom.Metadata.Authors == nil {
		return nil
	}

	var filtered []cydx.OrganizationalContact
	for _, author := range *bom.Metadata.Authors {
		match := false
		for _, tar := range targets {
			if matchAuthor(tar, author) {
				match = true
				break
			}
		}
		if !match {
			filtered = append(filtered, author)
		}
	}
	bom.Metadata.Authors = &filtered
	return nil
}

func matchAuthor(tar interface{}, author cydx.OrganizationalContact) bool {
	candidate, ok := tar.(cydx.OrganizationalContact)
	if !ok {
		return false
	}
	return candidate.Name == author.Name && candidate.Email == author.Email
}
