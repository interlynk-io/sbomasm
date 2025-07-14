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
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

func FilterAuthorFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filtered []interface{}
	for _, s := range selected {
		author, ok := s.(cydx.OrganizationalContact)
		if !ok {
			continue
		}
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

func FilterSupplierFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filtered []interface{}
	for _, entry := range selected {
		supplier, ok := entry.(cydx.OrganizationalEntity)
		if !ok {
			continue
		}
		if params.IsKeyAndValuePresent && supplier.Name == params.Key && containsEmail(supplier.Contact, params.Value) {
			filtered = append(filtered, supplier)
		} else if params.IsKeyPresent && supplier.Name == params.Key {
			filtered = append(filtered, supplier)
		} else if params.IsValuePresent && containsEmail(supplier.Contact, params.Value) {
			filtered = append(filtered, supplier)
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
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
		license, ok := entry.(cydx.LicenseChoice)
		if !ok {
			continue
		}
		if params.IsKeyPresent && license.Expression == params.Key {
			filtered = append(filtered, license)
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
			filtered = append(filtered, license)
		}
	}
	fmt.Println("Filtered licenses:", filtered)
	return filtered, nil
}

func FilterLifecycleFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filtered []interface{}
	for _, s := range selected {
		lifecycle, ok := s.(string)
		if !ok {
			continue
		}
		if params.IsKeyPresent && lifecycle == params.Key {
			filtered = append(filtered, lifecycle)
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
			filtered = append(filtered, lifecycle)
		}
	}
	return filtered, nil
}

func FilterRepositoryFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filtered []interface{}
	for _, entry := range selected {
		ref, ok := entry.(cydx.ExternalReference)
		if !ok || strings.ToLower(string(ref.Type)) != "vcs" {
			continue
		}

		if params.IsKeyAndValuePresent && ref.Comment == params.Key && ref.URL == params.Value {
			filtered = append(filtered, ref)
		} else if params.IsKeyPresent && ref.Comment == params.Key {
			filtered = append(filtered, ref)
		} else if params.IsValuePresent && ref.URL == params.Value {
			filtered = append(filtered, ref)
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
			filtered = append(filtered, ref)
		}
	}
	return filtered, nil
}

func FilterTimestampFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	if len(selected) == 0 {
		return nil, nil
	}
	if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
		return selected, nil
	}
	return nil, nil
}

func FilterToolFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filtered []interface{}

	for _, s := range selected {
		switch tool := s.(type) {
		case cydx.Tool:
			// v1.4 style tool object
			if params.All ||
				(params.IsKeyAndValuePresent && tool.Name == params.Key && tool.Version == params.Value) ||
				(params.IsKeyPresent && tool.Name == params.Key) ||
				(params.IsValuePresent && tool.Version == params.Value) {
				filtered = append(filtered, tool)
			}

		case cydx.Component:
			// v1.5+ tool-as-component
			if tool.Type == cydx.ComponentTypeApplication || tool.Type == cydx.ComponentTypeFramework {
				if params.All ||
					(params.IsKeyAndValuePresent && tool.Name == params.Key && tool.Version == params.Value) ||
					(params.IsKeyPresent && tool.Name == params.Key) ||
					(params.IsValuePresent && tool.Version == params.Value) {
					filtered = append(filtered, tool)
				}
			}
		}
	}

	return filtered, nil
}
