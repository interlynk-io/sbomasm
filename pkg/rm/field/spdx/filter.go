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
	"strings"

	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/spdx/tools-golang/spdx"
)

func FilterAuthorFromMetadata(allAuthors []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var filteredAuthors []interface{}

	for _, s := range allAuthors {
		author, ok := s.(spdx.Creator)
		if !ok || author.CreatorType != "Person" {
			log.Debugf("Skipping non-author entry: %v", s)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
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

	log.Debugf("Filtered SPDX authors: %v", filteredAuthors)
	return filteredAuthors, nil
}

func FilterLicenseFromMetadata(allLicenses []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var filteredLicenses []interface{}

	for _, s := range allLicenses {
		licenseStr, ok := s.(string)
		if !ok {
			continue
		}
		if params.IsFieldAndKeyValuePresent {
			if strings.Contains(licenseStr, params.Key) && strings.Contains(licenseStr, params.Value) {
				filteredLicenses = append(filteredLicenses, licenseStr)
			}
		} else if params.IsFieldAndKeyPresent {
			if strings.Contains(licenseStr, params.Key) {
				filteredLicenses = append(filteredLicenses, licenseStr)
			}
		} else if params.IsFieldAndValuePresent {
			if strings.Contains(licenseStr, params.Value) {
				filteredLicenses = append(filteredLicenses, licenseStr)
			}
		} else if params.All || (!params.IsFieldAndKeyPresent && !params.IsFieldAndValuePresent) {
			filteredLicenses = append(filteredLicenses, licenseStr)
		}
	}
	log.Debugf("Filtered SPDX licenses: %v", filteredLicenses)
	return filteredLicenses, nil
}

func FilterLifecycleFromMetadata(allLifecycles []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var filteredLifecycles []interface{}

	for _, s := range allLifecycles {
		lifecycle, ok := s.(string)
		if !ok {
			continue
		}
		if params.IsFieldAndKeyValuePresent {
			if strings.Contains(lifecycle, params.Key) && strings.Contains(lifecycle, params.Value) {
				filteredLifecycles = append(filteredLifecycles, lifecycle)
			}
		} else if params.IsFieldAndKeyPresent && strings.Contains(lifecycle, params.Key) {
			filteredLifecycles = append(filteredLifecycles, lifecycle)
		} else if params.IsFieldAndValuePresent && strings.Contains(lifecycle, params.Value) {
			filteredLifecycles = append(filteredLifecycles, lifecycle)
		} else if params.All || (!params.IsFieldAndKeyPresent && !params.IsFieldAndValuePresent) {
			filteredLifecycles = append(filteredLifecycles, lifecycle)
		}
	}

	log.Debugf("Filtered SPDX lifecycles: %v", filteredLifecycles)
	return filteredLifecycles, nil
}

func FilterSupplierFromMetadata(allSuppliers []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var filteredSuppliers []interface{}

	for _, s := range allSuppliers {
		creator, ok := s.(spdx.Creator)
		if !ok {
			continue
		}

		name := creator.Creator

		if params.IsFieldAndKeyValuePresent && name == params.Value {
			filteredSuppliers = append(filteredSuppliers, creator)
		} else if params.IsFieldAndValuePresent {
			if strings.Contains(name, params.Value) {
				filteredSuppliers = append(filteredSuppliers, creator)
			}
		} else if params.All || (!params.IsFieldAndKeyPresent && !params.IsFieldAndValuePresent) {
			filteredSuppliers = append(filteredSuppliers, creator)
		}
	}

	log.Debugf("Filtered SPDX suppliers: %v", filteredSuppliers)
	return filteredSuppliers, nil
}

func FilterToolFromMetadata(allTools []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var filteredTools []interface{}

	for _, s := range allTools {
		creator, ok := s.(spdx.Creator)
		if !ok {
			continue
		}

		toolName := creator.Creator

		if params.IsFieldAndKeyValuePresent && toolName == params.Key && creator.CreatorType == params.Value {
			filteredTools = append(filteredTools, creator)
		} else if params.IsFieldAndKeyPresent && toolName == params.Key {
			filteredTools = append(filteredTools, creator)
		} else if params.IsFieldAndValuePresent {
			if strings.Contains(toolName, params.Value) {
				filteredTools = append(filteredTools, creator)
			}
		} else if params.All || (!params.IsFieldAndKeyPresent && !params.IsFieldAndValuePresent) {
			filteredTools = append(filteredTools, creator)
		}
	}

	log.Debugf("Filtered SPDX tools: %v", filteredTools)
	return filteredTools, nil
}

func FilterTimestampFromMetadata(allTimestamps []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var filteredTimestamps []interface{}

	for _, entry := range allTimestamps {
		timestamp, ok := entry.(string)
		if !ok {
			continue
		}

		filteredTimestamps = append(filteredTimestamps, timestamp)

	}

	log.Debugf("Filtered SPDX timestamp from metadata: %v", filteredTimestamps)
	return filteredTimestamps, nil
}

func FilterPurlFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(PurlEntry)
		if !ok || entry.Ref.RefType != "purl" {
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
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
	log.Debugf("Filtered SPDX PURL from Component: %v", filtered)
	return filtered, nil
}

func FilterAuthorFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering author from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(AuthorEntry)
		if !ok || entry.Originator == nil {
			log.Debugf("Skipping invalid author entry: %v", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.Contains(entry.Originator.Originator, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warnf("NOASSERTION is unlikely for author field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered SPDX author from component: %v", filtered)
	return filtered, nil
}

func FilterSupplierFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering supplier from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(SupplierEntry)
		if !ok || entry.Supplier == nil {
			log.Debugf("Skipping invalid supplier entry: %v", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.Contains(entry.Supplier.Supplier, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warnf("Matched NOASSERTION for supplier in component: %v", entry.Package.PackageName)
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered SPDX supplier from component: %v", filtered)
	return filtered, nil
}

func FilterCopyrightFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering copyright from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(CopyrightEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid copyright entry: %v", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warnf("Matched NOASSERTION for copyright in component: %v", entry.Package.PackageName)
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered SPDX copyright from component: %v", filtered)
	return filtered, nil
}

func FilterCpeFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering CPE from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(CpeEntry)
		if !ok || entry.Ref == nil || (entry.Ref.RefType != "cpe22Type" && entry.Ref.RefType != "cpe23Type") {
			log.Debugf("Skipping invalid CPE entry: %v", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Ref.Locator, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warnf("NOASSERTION is unlikely for CPE field")
			}
		case params.IsFieldAndKeyPresent:
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

	log.Debugf("Filtered SPDX CPE from component: %v", filtered)
	return filtered, nil
}

func FilterDescriptionFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering description from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(DescriptionEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid description entry: %v", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warnf("NOASSERTION is unlikely for description field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered SPDX description from component: %v", filtered)
	return filtered, nil
}

func FilterHashFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering hash from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(HashEntry)
		if !ok || entry.Checksum == nil {
			log.Debugf("Skipping invalid hash entry: %v", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Checksum.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warnf("NOASSERTION is unlikely for hash field")
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

	log.Debugf("Filtered SPDX hash from component: %v", filtered)
	return filtered, nil
}

func FilterLicenseFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering license from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(LicenseEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid license entry: %v", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warnf("NOASSERTION is unlikely for license in component: %v", entry.Package.PackageName)
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered SPDX license from component: %v", filtered)
	return filtered, nil
}

func FilterRepoFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering repository from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(RepositoryEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid repository entry: %v", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warnf("NOASSERTION is unlikely for repository field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered SPDX repository from component: %v", filtered)
	return filtered, nil
}

func FilterTypeFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering type from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(TypeEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid type entry: %v", e)
			continue
		}

		match := false
		switch {
		case params.IsValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warnf("NOASSERTION is unlikely for type field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered SPDX type from component: %v", filtered)
	return filtered, nil
}
