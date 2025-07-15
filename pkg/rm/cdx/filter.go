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
		fmt.Println("Processing author entry:", s)
		authors, ok := s.([]cydx.OrganizationalContact)
		if !ok {
			fmt.Println("Skipping non-author entry:", s)
			continue
		}

		for _, author := range authors {
			if params.IsKeyAndValuePresent {
				fmt.Println("Checking author:", author.Name, "with email:", author.Email)
				// match both key and value
				if author.Name == params.Key && author.Email == params.Value {
					filtered = append(filtered, author)
				}
			} else if params.IsKeyPresent {
				fmt.Println("Checking author name:", author.Name, "against key:", params.Key)
				// match only key
				if author.Name == params.Key {
					filtered = append(filtered, author)
				}
			} else if params.IsValuePresent {
				fmt.Println("Checking author email:", author.Email, "against value:", params.Value)
				// match only value
				if author.Email == params.Value {
					filtered = append(filtered, author)
				}
			} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
				fmt.Println("Adding author without specific filters:", author)
				filtered = append(filtered, author)
			}
		}
		// }
	}
	fmt.Println("Filtered authors:", filtered)
	return filtered, nil
}

func FilterSupplierFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filtered []interface{}
	for _, entry := range selected {
		fmt.Println("Processing supplier entry:", entry)
		supplier, ok := entry.(cydx.OrganizationalEntity)
		if !ok {
			continue
		}
		fmt.Println("Processing supplier:", supplier.Name, "with URL:", *supplier.URL)
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
		fmt.Println("Processing lifecycle entry:", s)

		lifecycles, ok := s.([]cydx.Lifecycle)
		if !ok {
			fmt.Println("Skipping non-lifecycle entry:", s)
			continue
		}

		for _, lc := range lifecycles {
			phase := string(lc.Phase) // convert to string for comparison
			fmt.Println("Lifecycle phase:", phase)

			if params.IsKeyAndValuePresent || params.IsKeyPresent || params.IsValuePresent {
				if phase == params.Key || phase == params.Value {
					filtered = append(filtered, phase)
				}
			} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
				filtered = append(filtered, phase)
			}
		}
	}

	fmt.Println("Filtered lifecycles:", filtered)
	return filtered, nil
}

func FilterRepositoryFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filtered []interface{}
	for _, entry := range selected {
		fmt.Println("Processing repository entry:", entry)
		extRefs, ok := entry.([]cydx.ExternalReference)
		if !ok || strings.ToLower(string(extRefs[0].Type)) != "vcs" {
			continue
		}

		for _, ref := range extRefs {
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
	}
	fmt.Println("Filtered repositories:", filtered)
	return filtered, nil
}

func FilterTimestampFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filtered []interface{}

	timestamp, ok := selected[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid timestamp format")
	}
	if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
		filtered = append(filtered, timestamp)
	}
	fmt.Println("Filtered timestamps:", filtered)
	return filtered, nil
}

func FilterToolFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filtered []interface{}

	for _, s := range selected {
		switch tools := s.(type) {

		case []cydx.Tool: // CycloneDX v1.4 style
			for _, tool := range tools {
				if matchTool(tool.Name, tool.Version, params) {
					filtered = append(filtered, tool)
				}
			}
		case []cydx.ToolsChoice: // CycloneDX v1.5+ style
			for _, toolChoice := range tools {
				if toolChoice.Components == nil {
					continue
				}
				for _, comp := range *toolChoice.Components {
					if matchTool(comp.Name, comp.Version, params) {
						filtered = append(filtered, comp)
					}
				}
			}
		default:
			continue
		}
	}

	return filtered, nil
}

func matchTool(name, version string, params *types.RmParams) bool {
	switch {
	case params.IsKeyAndValuePresent:
		return name == params.Key && version == params.Value
	case params.IsKeyPresent:
		return name == params.Key
	case params.IsValuePresent:
		return version == params.Value
	case params.All || (!params.IsKeyPresent && !params.IsValuePresent):
		return true
	default:
		return false
	}
}
