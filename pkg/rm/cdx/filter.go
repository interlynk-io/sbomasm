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

func FilterCDXField(bom *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	switch params.Field {
	case "author":
		return FilterAuthorFromMetadata(selected, params)
	case "supplier":
		return FilterSupplierFromMetadata(selected, params)
	case "timestamp":
		// return FilterTimestampFromMetadata(selected, params)
	case "tool":
		// return FilterToolFromMetadata(selected, params)
	case "license":
		return FilterLicenseFromMetadata(selected, params)
	case "lifecycle":
		// return FilterLifecycleFromMetadata(selected, params)
	case "repository":
		// return FilterRepositoryFromMetadata(selected, params)
	default:
		// return nil, types.ErrUnsupportedField
	}
	return nil, nil
}

func FilterAuthorFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filtered []interface{}
	for _, s := range selected {
		author, ok := s.(cydx.OrganizationalContact)
		if !ok {
			continue
		}
		// for _, author := range *bom.Metadata.Authors {
		if params.IsKeyAndValuePresent {
			// match both key and value
			if author.Name == params.Key && author.Email == params.Value {
				filtered = append(filtered, author)
			}
		} else if params.IsKeyPresent {
			// match only key
			if author.Name == params.Key {
				filtered = append(filtered, author)
			}
		} else if params.IsValuePresent {
			// match only value
			if author.Email == params.Value {
				filtered = append(filtered, author)
			}
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
			filtered = append(filtered, author)
		}
	}
	return filtered, nil
}

func FilterSupplierFromMetadata(supplier []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filtered []interface{}
	for _, sup := range supplier {
		supplier, ok := sup.(cydx.OrganizationalEntity)
		if !ok {
			continue
		}
		if params.All ||
			(params.IsKeyAndValuePresent && supplier.Name == params.Key && containsEmail(supplier.Contact, params.Value)) ||
			(params.IsKeyPresent && supplier.Name == params.Key) ||
			(params.IsValuePresent && containsEmail(supplier.Contact, params.Value)) {
			filtered = append(filtered, supplier)
		}
	}
	return filtered, nil
}

func containsEmail(contacts *[]cydx.OrganizationalContact, email string) bool {
	if contacts == nil {
		return false
	}
	for _, c := range *contacts {
		if c.Email == email {
			return true
		}
	}
	return false
}

func FilterLicenseFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filtered []interface{}
	for _, entry := range selected {
		lic, ok := entry.(cydx.LicenseChoice)
		if !ok {
			continue
		}
		if params.All ||
			(params.IsKeyPresent && lic.Expression == params.Key) {
			filtered = append(filtered, lic)
		}
	}
	return filtered, nil
}
