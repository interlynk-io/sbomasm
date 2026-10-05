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

func FilterHashFromComponent(entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(ComponentHashEntry)
		if !ok || entry.Hash == nil {
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Hash.HashValue, params.Value) {
				match = true
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
	log.Debugf("Filtered SPDX 3.0 hash from component: %v", filtered)
	return filtered, nil
}

func FilterPurlFromComponent(entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(ComponentExternalIdentifierEntry)
		if !ok || entry.ExtId == nil {
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.ExtId.Identifier, params.Value) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}
	log.Debugf("Filtered SPDX 3.0 PURL from component: %v", filtered)
	return filtered, nil
}

func FilterCpeFromComponent(entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(ComponentExternalIdentifierEntry)
		if !ok || entry.ExtId == nil {
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.ExtId.Identifier, params.Value) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}
	log.Debugf("Filtered SPDX 3.0 CPE from component: %v", filtered)
	return filtered, nil
}

func FilterRepoFromComponent(entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(ComponentExternalRefEntry)
		if !ok || entry.ExtRef == nil {
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			for _, loc := range entry.ExtRef.Locator {
				if strings.EqualFold(loc, params.Value) {
					match = true
					break
				}
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}
	log.Debugf("Filtered SPDX 3.0 repository from component: %v", filtered)
	return filtered, nil
}

func FilterLicenseFromComponent(entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(ComponentLicenseEntry)
		if !ok {
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.LicenseExpr, params.Value) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}
	log.Debugf("Filtered SPDX 3.0 license from component: %v", filtered)
	return filtered, nil
}

func FilterTypeFromComponent(entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(ComponentTypeEntry)
		if !ok {
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}
	log.Debugf("Filtered SPDX 3.0 type from component: %v", filtered)
	return filtered, nil
}

func FilterDescriptionFromComponent(entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(ComponentDescriptionEntry)
		if !ok {
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}
	log.Debugf("Filtered SPDX 3.0 description from component: %v", filtered)
	return filtered, nil
}

func FilterCopyrightFromComponent(entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(ComponentCopyrightEntry)
		if !ok {
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.EqualFold(entry.Value, params.Value) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}
	log.Debugf("Filtered SPDX 3.0 copyright from component: %v", filtered)
	return filtered, nil
}

func FilterAuthorFromComponent(entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(ComponentAuthorEntry)
		if !ok || entry.Person == nil {
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.Contains(entry.Person.Name, params.Value) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}
	log.Debugf("Filtered SPDX 3.0 author from component: %v", filtered)
	return filtered, nil
}

func FilterSupplierFromComponent(entries []interface{}, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	if params.Value == "" && !params.All && !params.IsKeyPresent {
		return entries, nil
	}

	var filtered []interface{}
	for _, e := range entries {
		entry, ok := e.(ComponentSupplierEntry)
		if !ok || entry.Org == nil {
			continue
		}

		match := false
		switch {
		case params.IsFieldAndValuePresent:
			if strings.Contains(entry.Org.Name, params.Value) {
				match = true
			}
		default:
			match = true
		}

		if match {
			filtered = append(filtered, entry)
		}
	}
	log.Debugf("Filtered SPDX 3.0 supplier from component: %v", filtered)
	return filtered, nil
}
