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
)

func FilterAuthorFromMetadata(allAuthors []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var filtered []interface{}

	for _, s := range allAuthors {
		entry, ok := s.(PersonEntry)
		if !ok || entry.Person == nil {
			continue
		}

		name := entry.Person.Name
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

		// Use SpdxID as the license identifier (e.g., "https://spdx.org/licenses/CC0-1.0")
		licID := entry.License.SpdxID
		match := false
		switch {
		case params.IsFieldAndValuePresent:
			match = strings.Contains(strings.ToLower(licID), strings.ToLower(params.Value))
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
