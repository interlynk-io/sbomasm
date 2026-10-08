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

package spdx3

import (
	"strings"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/rm/types"
	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
)

// getPersonEmail returns the email identifier from a Person's ExternalIdentifier list.
func getPersonEmail(person *spdx.Person) string {
	for _, ei := range person.ExternalIdentifier {
		if ei.ExternalIdentifierType == spdx.ExternalIdentifierTypeEmail {
			return ei.Identifier
		}
	}
	return ""
}

// getOrgUrls returns all URL-like locators from an Organization's ExternalRef list.
func getOrgUrls(org *spdx.Organization) []string {
	var urls []string
	for _, ref := range org.ExternalRef {
		if ref.ExternalRefType == spdx.ExternalRefTypeAltWebPage {
			urls = append(urls, ref.Locator...)
		}
	}
	return urls
}

func FilterAuthorFromMetadata(allAuthors []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var filtered []interface{}

	for _, s := range allAuthors {
		entry, ok := s.(PersonEntry)
		if !ok || entry.Person == nil {
			continue
		}

		name := entry.Person.Name
		email := getPersonEmail(entry.Person)

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			match = strings.Contains(strings.ToLower(name), strings.ToLower(params.Value)) ||
				strings.Contains(strings.ToLower(email), strings.ToLower(params.Value))
		case params.IsKeyPresent:
			match = strings.Contains(strings.ToLower(name), strings.ToLower(params.Key)) ||
				strings.Contains(strings.ToLower(email), strings.ToLower(params.Key))
		case params.IsValuePresent:
			match = strings.Contains(strings.ToLower(name), strings.ToLower(params.Value)) ||
				strings.Contains(strings.ToLower(email), strings.ToLower(params.Value))
		case params.All || (!params.IsKeyPresent && !params.IsValuePresent):
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered SPDX 3.0 authors: %d", len(filtered))
	return filtered, nil
}

func FilterSupplierFromMetadata(allSuppliers []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var filtered []interface{}

	for _, s := range allSuppliers {
		entry, ok := s.(OrgEntry)
		if !ok || entry.Organization == nil {
			continue
		}

		name := entry.Organization.Name
		spdxID := entry.Organization.SpdxID
		urls := getOrgUrls(entry.Organization)

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			match = strings.Contains(strings.ToLower(name), strings.ToLower(params.Value)) ||
				strings.Contains(strings.ToLower(spdxID), strings.ToLower(params.Value))
			for _, u := range urls {
				if strings.Contains(strings.ToLower(u), strings.ToLower(params.Value)) {
					match = true
					break
				}
			}
		case params.IsKeyPresent:
			match = strings.Contains(strings.ToLower(name), strings.ToLower(params.Key)) ||
				strings.Contains(strings.ToLower(spdxID), strings.ToLower(params.Key))
			for _, u := range urls {
				if strings.Contains(strings.ToLower(u), strings.ToLower(params.Key)) {
					match = true
					break
				}
			}
		case params.IsValuePresent:
			match = strings.Contains(strings.ToLower(name), strings.ToLower(params.Value)) ||
				strings.Contains(strings.ToLower(spdxID), strings.ToLower(params.Value))
			for _, u := range urls {
				if strings.Contains(strings.ToLower(u), strings.ToLower(params.Value)) {
					match = true
					break
				}
			}
		case params.All || (!params.IsKeyPresent && !params.IsValuePresent):
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered SPDX 3.0 suppliers: %d", len(filtered))
	return filtered, nil
}

func FilterToolFromMetadata(allTools []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var filtered []interface{}

	for _, s := range allTools {
		entry, ok := s.(ToolEntry)
		if !ok || entry.Tool == nil {
			continue
		}

		name := entry.Tool.Name
		match := false
		switch {
		case params.IsFieldAndValuePresent:
			match = strings.Contains(strings.ToLower(name), strings.ToLower(params.Value))
		case params.IsKeyPresent:
			match = strings.Contains(strings.ToLower(name), strings.ToLower(params.Key))
		case params.IsValuePresent:
			match = strings.Contains(strings.ToLower(name), strings.ToLower(params.Value))
		case params.All || (!params.IsKeyPresent && !params.IsValuePresent):
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered SPDX 3.0 tools: %d", len(filtered))
	return filtered, nil
}

func FilterLicenseFromMetadata(allLicenses []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var filtered []interface{}

	for _, s := range allLicenses {
		entry, ok := s.(LicenseEntry)
		if !ok || entry.License == nil {
			continue
		}

		// Match against both resolved Name and SpdxID (reference URL)
		licID := entry.License.SpdxID
		licName := entry.License.Name
		match := false
		switch {
		case params.IsFieldAndValuePresent:
			match = strings.Contains(strings.ToLower(licID), strings.ToLower(params.Value)) ||
				strings.Contains(strings.ToLower(licName), strings.ToLower(params.Value))
		case params.All || (!params.IsKeyPresent && !params.IsValuePresent):
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}

	log.Debugf("Filtered SPDX 3.0 document licenses: %d", len(filtered))
	return filtered, nil
}
