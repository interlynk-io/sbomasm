// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gsbom

import (
	"strings"
)

// FilterComponents takes a list of components and applies include and exclude tag filters.
// - Components with scope: "excluded" are always dropped first (before tag filtering).
// - If includeTags is provided, only components that have at least one of the specified tags will be included.
// - If excludeTags is provided, any component that has at least one of the specified exclude tags will be excluded.
// And finally returns a list of components that match the filtering criteria.
func FilterComponents(components []Component, includeTags, excludeTags []string) []Component {
	var filteredComponentsList []Component

	for _, comp := range components {
		// Step 0: Always drop components with scope: "excluded"
		if strings.TrimSpace(strings.ToLower(comp.Scope)) == "excluded" {
			continue
		}

		// Step 1: include filter
		if len(includeTags) > 0 {
			if !hasAnyTag(comp.Tags, includeTags) {
				continue
			}
		}

		// Step 2: exclude filter
		if len(excludeTags) > 0 {
			if hasAnyTag(comp.Tags, excludeTags) {
				continue
			}
		}

		filteredComponentsList = append(filteredComponentsList, comp)
	}

	return filteredComponentsList
}

// hasAnyTag checks if there is any common tag between componentTags and filterTags.
func hasAnyTag(componentTags, filterTags []string) bool {

	for _, ct := range componentTags {
		t := strings.TrimSpace(ct)

		for _, ft := range filterTags {
			if strings.EqualFold(t, ft) {
				return true
			}
		}
	}
	return false
}
