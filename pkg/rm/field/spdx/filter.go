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

package spdx

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/spdx/tools-golang/spdx"
)

func FilterAuthorFromMetadata(allAuthors []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filteredAuthors []interface{}

	for _, s := range allAuthors {
		fmt.Println("Processing author entry:", s)
		author, ok := s.(spdx.Creator)
		if !ok || author.CreatorType != "Person" {
			fmt.Println("Skipping non-author entry:", s)
			continue
		}

		match := false
		switch {
		case params.IsKeyAndValuePresent:
			match = strings.Contains(strings.ToLower(author.Creator), strings.ToLower(params.Key)) &&
				strings.Contains(strings.ToLower(author.Creator), strings.ToLower(params.Value))
		case params.IsKeyPresent:
			match = strings.Contains(strings.ToLower(author.Creator), strings.ToLower(params.Key))
		case params.IsValuePresent:
			match = strings.Contains(strings.ToLower(author.Creator), strings.ToLower(params.Value))
		case params.All || (!params.IsKeyPresent && !params.IsValuePresent):
			match = true
		}

		if match {
			filteredAuthors = append(filteredAuthors, author)
		}
	}

	fmt.Println("Filtered SPDX authors:", filteredAuthors)
	return filteredAuthors, nil
}

func FilterLicenseFromMetadata(allLicenses []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filteredLicenses []interface{}

	for _, s := range allLicenses {
		licenseStr, ok := s.(string)
		if !ok {
			continue
		}
		if params.IsKeyAndValuePresent {
			if strings.Contains(licenseStr, params.Key) && strings.Contains(licenseStr, params.Value) {
				filteredLicenses = append(filteredLicenses, licenseStr)
			}
		} else if params.IsKeyPresent {
			if strings.Contains(licenseStr, params.Key) {
				filteredLicenses = append(filteredLicenses, licenseStr)
			}
		} else if params.IsValuePresent {
			if strings.Contains(licenseStr, params.Value) {
				filteredLicenses = append(filteredLicenses, licenseStr)
			}
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
			filteredLicenses = append(filteredLicenses, licenseStr)
		}
	}
	return filteredLicenses, nil
}

func FilterLifecycleFromMetadata(allLifecycles []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filteredLifecycles []interface{}

	for _, s := range allLifecycles {
		lifecycle, ok := s.(string)
		if !ok {
			continue
		}
		if params.IsKeyAndValuePresent {
			if strings.Contains(lifecycle, params.Key) && strings.Contains(lifecycle, params.Value) {
				filteredLifecycles = append(filteredLifecycles, lifecycle)
			}
		} else if params.IsKeyPresent && strings.Contains(lifecycle, params.Key) {
			filteredLifecycles = append(filteredLifecycles, lifecycle)
		} else if params.IsValuePresent && strings.Contains(lifecycle, params.Value) {
			filteredLifecycles = append(filteredLifecycles, lifecycle)
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
			filteredLifecycles = append(filteredLifecycles, lifecycle)
		}
	}

	return filteredLifecycles, nil
}

func FilterSupplierFromMetadata(allSuppliers []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filteredSuppliers []interface{}

	for _, s := range allSuppliers {
		creator, ok := s.(spdx.Creator)
		if !ok {
			continue
		}

		name := creator.Creator

		if params.IsKeyAndValuePresent && name == params.Key && creator.CreatorType == params.Value {
			filteredSuppliers = append(filteredSuppliers, creator)
		} else if params.IsKeyPresent && name == params.Key {
			filteredSuppliers = append(filteredSuppliers, creator)
		} else if params.IsValuePresent && creator.CreatorType == params.Value {
			filteredSuppliers = append(filteredSuppliers, creator)
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
			filteredSuppliers = append(filteredSuppliers, creator)
		}
	}

	return filteredSuppliers, nil
}

func FilterToolFromMetadata(allTools []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filteredTools []interface{}

	for _, s := range allTools {
		creator, ok := s.(spdx.Creator)
		if !ok {
			continue
		}

		toolName := creator.Creator

		if params.IsKeyAndValuePresent && toolName == params.Key && creator.CreatorType == params.Value {
			filteredTools = append(filteredTools, creator)
		} else if params.IsKeyPresent && toolName == params.Key {
			filteredTools = append(filteredTools, creator)
		} else if params.IsValuePresent && creator.CreatorType == params.Value {
			filteredTools = append(filteredTools, creator)
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
			filteredTools = append(filteredTools, creator)
		}
	}

	fmt.Println("Filtered SPDX tools:", filteredTools)

	return filteredTools, nil
}

func FilterTimestampFromMetadata(allTimestamps []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filteredTimestamps []interface{}

	for _, entry := range allTimestamps {
		timestamp, ok := entry.(string)
		if !ok {
			continue
		}

		filteredTimestamps = append(filteredTimestamps, timestamp)

	}

	fmt.Println("Filtered SPDX timestamps:", filteredTimestamps)
	return filteredTimestamps, nil
}

func FilterPurlFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil // No filtering criteria, return all
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(PurlEntry)
		if !ok || entry.Ref.RefType != "purl" {
			// Log: "Skipping invalid PURL entry: %v", e
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Ref.Locator, params.Value) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}
	return filtered, nil
}

func FilterAuthorFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(AuthorEntry)
		if !ok || entry.Originator == nil {
			fmt.Println("Skipping invalid author entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			// Match against Originator or email
			if strings.EqualFold(entry.Originator.Originator, params.Value) {
				match = true
			} else {
				// Extract email (e.g., "Person: John Doe (john@example.com)")
				re := regexp.MustCompile(`\(([^)]+)\)`)
				if matches := re.FindStringSubmatch(entry.Originator.Originator); len(matches) > 1 {
					if strings.EqualFold(matches[1], params.Value) {
						match = true
					}
				}
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

	fmt.Println("Filtered SPDX author entries:", len(filtered))
	return filtered, nil
}

func FilterSupplierFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(SupplierEntry)
		if !ok || entry.Supplier == nil {
			fmt.Println("Skipping invalid supplier entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Supplier.Supplier, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Println("Matched NOASSERTION for supplier in component:", entry.Package.PackageName)
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Println("Filtered SPDX supplier entries:", len(filtered))
	return filtered, nil
}

func FilterCopyrightFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
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
				fmt.Println("Matched NOASSERTION for copyright in component:", entry.Package.PackageName)
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Println("Filtered SPDX copyright entries:", len(filtered))
	return filtered, nil
}

func FilterCpeFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(CpeEntry)
		if !ok || entry.Ref == nil || (entry.Ref.RefType != "cpe22Type" && entry.Ref.RefType != "cpe23Type") {
			fmt.Println("Skipping invalid CPE entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Ref.Locator, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for CPE field")
			}
		case params.IsKeyPresent:
			if entry.Ref.RefType == params.Key && (params.Key == "cpe22Type" || params.Key == "cpe23Type") {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Println("Filtered SPDX CPE entries:", len(filtered))
	return filtered, nil
}

func FilterDescriptionFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
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

	fmt.Println("Filtered SPDX description entries:", len(filtered))
	return filtered, nil
}

func FilterHashFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(HashEntry)
		if !ok || entry.Checksum == nil {
			fmt.Println("Skipping invalid hash entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Checksum.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for hash field")
			}
		case params.IsKeyPresent:
			if strings.EqualFold(string(entry.Checksum.Algorithm), params.Key) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Println("Filtered SPDX hash entries:", len(filtered))
	return filtered, nil
}

func FilterLicenseFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
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
				fmt.Println("Matched NOASSERTION for license in component:", entry.Package.PackageName)
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Println("Filtered SPDX license entries:", len(filtered))
	return filtered, nil
}

func FilterRepoFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(RepositoryEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid repository entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for repository field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	fmt.Println("Filtered SPDX repository entries:", len(filtered))
	return filtered, nil
}

func FilterTypeFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(TypeEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid type entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
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

	fmt.Println("Filtered SPDX type entries:", len(filtered))
	return filtered, nil
}
