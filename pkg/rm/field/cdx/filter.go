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

func FilterAuthorFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(AuthorEntry)
		if !ok || entry.Author == nil {
			fmt.Println("Skipping invalid author entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Author.Name, params.Value) || strings.EqualFold(entry.Author.Email, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for author field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Printf("Filtered %d author entries\n", len(filtered))
	return filtered, nil
}

func FilterSupplierFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(SupplierEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid supplier entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Printf("Matched NOASSERTION for supplier in component: %s@%s\n", entry.Component.Name, entry.Component.Version)
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Printf("Filtered %d supplier entries\n", len(filtered))
	return filtered, nil
}

func FilterCopyrightFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(CopyrightEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid copyright entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Printf("Matched NOASSERTION for copyright in component: %s@%s\n", entry.Component.Name, entry.Component.Version)
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Printf("Filtered %d copyright entries\n", len(filtered))
	return filtered, nil
}

func FilterCpeFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(CpeEntry)
		if !ok || entry.Ref == nil || entry.Ref.Type != cydx.ERTypeSecurityContact {
			fmt.Println("Skipping invalid CPE entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Ref.URL, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for CPE field")
			}
		case params.IsKeyPresent:
			if entry.Ref.Type == cydx.ExternalReferenceType(params.Key) && params.Key == string(cydx.ERTypeSecurityContact) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Printf("Filtered %d CPE entries\n", len(filtered))
	return filtered, nil
}

func FilterDescriptionFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(DescriptionEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid description entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for description field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Printf("Filtered %d description entries\n", len(filtered))
	return filtered, nil
}

func FilterHashFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(HashEntry)
		if !ok || entry.Hash == nil {
			fmt.Println("Skipping invalid hash entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Hash.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for hash field")
			}
		case params.IsKeyPresent:
			if strings.EqualFold(string(entry.Hash.Algorithm), params.Key) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Printf("Filtered %d hash entries\n", len(filtered))
	return filtered, nil
}

func FilterLicenseFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(LicenseEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid license entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Printf("Matched NOASSERTION for license in component: %s@%s\n", entry.Component.Name, entry.Component.Version)
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Printf("Filtered %d license entries\n", len(filtered))
	return filtered, nil
}

func FilterPurlFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(PurlEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid PURL entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for PURL field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Printf("Filtered %d PURL entries\n", len(filtered))
	return filtered, nil
}

func FilterRepoFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(RepositoryEntry)
		if !ok || entry.Ref == nil || (entry.Ref.Type != cydx.ERTypeVCS && entry.Ref.Type != cydx.ERTypeDistribution) {
			fmt.Println("Skipping invalid repository entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Ref.URL, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for repository field")
			}
		case params.IsKeyPresent:
			if entry.Ref.Type == cydx.ExternalReferenceType(params.Key) && (params.Key == string(cydx.ERTypeVCS) || params.Key == string(cydx.ERTypeDistribution)) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Printf("Filtered %d repository entries\n", len(filtered))
	return filtered, nil
}

func FilterTypeFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(TypeEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid type entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(string(entry.Value), params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for type field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Printf("Filtered %d type entries\n", len(filtered))
	return filtered, nil
}
