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
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

func FilterAuthorFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering authors from metadata")

	var filtered []interface{}
	for _, s := range selected {
		authors, ok := s.([]cydx.OrganizationalContact)
		if !ok {
			log.Warn("Skipping non-author entry:", s)
			continue
		}

		for _, author := range authors {
			if params.IsFieldAndKeyValuePresent {
				if author.Name == params.Key && author.Email == params.Value {
					filtered = append(filtered, author)
				}
			} else if params.IsFieldAndKeyPresent {
				if author.Name == params.Key {
					filtered = append(filtered, author)
				}
			} else if params.IsFieldAndValuePresent {
				if author.Name == params.Value || author.Email == params.Value {
					filtered = append(filtered, author)
				}
			} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
				filtered = append(filtered, author)
			}
		}
	}

	log.Debugf("Filtered authors from metadata: %v", filtered)
	return filtered, nil
}

func FilterSupplierFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering supplier from metadata")

	var filtered []interface{}
	for _, entry := range selected {
		supplier, ok := entry.(cydx.OrganizationalEntity)
		if !ok {
			continue
		}
		if params.IsFieldAndKeyValuePresent && supplier.Name == params.Key && containsEmail(supplier.Contact, params.Value) {
			filtered = append(filtered, supplier)
		} else if params.IsFieldAndValuePresent {
			if supplier.Name == params.Value || containsEmail(supplier.Contact, params.Value) || containsURL(supplier.URL, params.Value) {
				filtered = append(filtered, supplier)
			}
		} else if params.All || (!params.IsFieldAndKeyPresent && !params.IsFieldAndValuePresent) {
			filtered = append(filtered, supplier)
		}
	}

	log.Debugf("Filtered supplier from metadata: %v", filtered)
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

func containsURL(url *[]string, value string) bool {
	if url == nil {
		return false
	}

	for _, u := range *url {
		if u == value {
			return true
		}
	}
	return false
}

func FilterLicenseFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering license from metadata")

	var filtered []interface{}
	for _, entry := range selected {
		license, ok := entry.(cydx.LicenseChoice)
		if !ok {
			log.Debugf("skipping license filter for non-license entry: %v", entry)
			continue
		}
		if params.IsFieldAndValuePresent && license.License.Name == params.Value || license.License.ID == params.Value {
			filtered = append(filtered, license)
		} else if params.All || (!params.IsFieldAndKeyPresent && !params.IsFieldAndValuePresent) {
			filtered = append(filtered, license)
		}
	}

	log.Debugf("Filtered licenses from metadata: %v", filtered)
	return filtered, nil
}

func FilterLifecycleFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering lifecycle from metadata")

	var filtered []interface{}

	for _, s := range selected {

		lifecycles, ok := s.([]cydx.Lifecycle)
		if !ok {
			log.Warn("Skipping non-lifecycle entry:", s)
			continue
		}

		for _, lc := range lifecycles {
			phase := string(lc.Phase)

			if params.IsFieldAndValuePresent {
				if phase == params.Value {
					filtered = append(filtered, phase)
				}
			} else if params.All || (!params.IsFieldAndKeyPresent && !params.IsFieldAndValuePresent) {
				filtered = append(filtered, phase)
			}
		}
	}

	log.Debugf("Filtered lifecycle from metadata: %v", filtered)
	return filtered, nil
}

func FilterRepositoryFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering repository from metadata")

	var filtered []interface{}
	for _, entry := range selected {
		extRefs, ok := entry.([]cydx.ExternalReference)
		if !ok || strings.ToLower(string(extRefs[0].Type)) != "vcs" {
			continue
		}

		for _, ref := range extRefs {
			if params.IsFieldAndKeyValuePresent {
				if string(ref.Type) == params.Key && ref.URL == params.Value {
					filtered = append(filtered, ref)
				}
			} else if params.IsFieldAndValuePresent {
				if ref.URL == params.Value {
					filtered = append(filtered, ref)
				}
			} else if params.All || (!params.IsFieldAndKeyPresent && !params.IsFieldAndValuePresent) {
				filtered = append(filtered, ref)
			}
		}
	}

	log.Debugf("Filtered repositories from metadata: %v", filtered)
	return filtered, nil
}

func FilterTimestampFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering timestamp from metadata")

	var filtered []interface{}

	timestamp, ok := selected[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid timestamp format")
	}
	if params.All || (!params.IsFieldAndKeyPresent && !params.IsFieldAndValuePresent) {
		filtered = append(filtered, timestamp)
	}

	log.Debugf("Filtered timestamp from metadata: %v", filtered)
	return filtered, nil
}

func FilterToolFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering tool from metadata")

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

	log.Debugf("Filtered tools from metadata: %v", filtered)
	return filtered, nil
}

func matchTool(name, version string, params *types.RmParams) bool {
	var paramsToolName, paramsToolVersion string

	if strings.Contains(params.Value, "@") {
		parts := strings.Split(params.Value, "@")
		if len(parts) == 2 {
			paramsToolName = parts[0]
			paramsToolVersion = parts[1]
		}
	} else {
		paramsToolName = params.Value
	}

	if params.IsFieldAndValuePresent {
		if name == paramsToolName || version == paramsToolVersion {
			return true
		}
	} else if params.All || (!params.IsFieldAndKeyPresent && !params.IsFieldAndValuePresent) {
		return true
	}
	return false
}

func FilterAuthorFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering author from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(AuthorEntry)
		if !ok || entry.Author == nil {
			log.Warn("Skipping invalid author entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.Contains(entry.Author.Name, params.Value) || strings.Contains(entry.Author.Email, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warn("Warning: NOASSERTION is unlikely for author field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered author from component: %v", filtered)
	return filtered, nil
}

func FilterSupplierFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering supplier from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(SupplierEntry)
		if !ok || entry.Value == nil {
			log.Warn("Skipping invalid supplier entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.Contains(entry.Value.Name, params.Value) || containsURL(entry.Value.URL, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warnf("Matched NOASSERTION for supplier in component: %s@%s\n", entry.Component.Name, entry.Component.Version)
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered supplier from component: %v", filtered)
	return filtered, nil
}

func FilterCopyrightFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering copyright from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(CopyrightEntry)
		if !ok || entry.Value == "" {
			log.Warn("Skipping invalid copyright entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
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

	log.Debugf("Filtered copyright from component: %v", filtered)
	return filtered, nil
}

func FilterCpeFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering CPE from component")

	if params.Value == "" && !params.All && !params.IsFieldAndKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(CpeEntry)
		if !ok || entry.Ref == "" {
			log.Warn("Skipping invalid CPE entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Ref, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warn("Warning: NOASSERTION is unlikely for CPE field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered CPE from component: %v", filtered)
	return filtered, nil
}

func FilterDescriptionFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering description from component")

	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(DescriptionEntry)
		if !ok || entry.Value == "" {
			log.Warn("Skipping invalid description entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warn("Warning: NOASSERTION is unlikely for description field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered description from component: %v", filtered)
	return filtered, nil
}

func FilterHashFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering hash from component")

	if params.Value == "" && !params.All {
		log.Warn("No hash value provided, returning selected entries without filtering")
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(HashEntry)
		if !ok || entry.Hash == nil {
			log.Warn("Skipping invalid hash entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Hash.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warn("Warning: NOASSERTION is unlikely for hash field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered hash from component: %v", filtered)
	return filtered, nil
}

func FilterLicenseFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering license from component")

	if params.Value == "" && !params.All {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(LicenseEntry)
		if !ok || entry.Value == "" {
			log.Warn("Skipping invalid license entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warn("Warning: NOASSERTION is unlikely for license field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered license from component: %v", filtered)
	return filtered, nil
}

func FilterPurlFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering PURL from component")

	if params.Value == "" && !params.All && !params.IsFieldAndKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(PurlEntry)
		if !ok || entry.Value == "" {
			log.Warn("Skipping invalid PURL entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warn("Warning: NOASSERTION is unlikely for PURL field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered PURL from component: %v", filtered)
	return filtered, nil
}

func FilterRepoFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering repository from component")

	if params.Value == "" && !params.All && !params.IsFieldAndKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(RepositoryEntry)
		if !ok || entry.Ref == nil || (entry.Ref.Type != cydx.ERTypeVCS && entry.Ref.Type != cydx.ERTypeDistribution) {
			log.Warn("Skipping invalid repository entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Ref.URL, params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warn("Warning: NOASSERTION is unlikely for repository field")
			}
		case params.IsFieldAndKeyPresent:
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

	log.Debugf("Filtered repository from component: %v", filtered)
	return filtered, nil
}

func FilterTypeFromComponent(doc *cydx.BOM, selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Filtering type from component")

	if params.Value == "" && !params.All && !params.IsFieldAndKeyPresent {
		return selected, nil
	}

	var filtered []interface{}
	for _, e := range selected {
		entry, ok := e.(TypeEntry)
		if !ok || entry.Value == "" {
			log.Warn("Skipping invalid type entry:", e)
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(string(entry.Value), params.Value) {
				match = true
			}
			if params.Value == "NOASSERTION" {
				log.Warn("Warning: NOASSERTION is unlikely for type field")
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered type from component: %v", filtered)
	return filtered, nil
}
