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

func FilterComponents(components []Component, includeTags, excludeTags []string) []Component {
	var filteredComponentsList []Component

	for _, c := range components {
		// Step 1: include filter
		if len(includeTags) > 0 {
			if !hasAnyTag(c.Tags, includeTags) {
				continue
			}
		}

		// Step 2: exclude filter
		if len(excludeTags) > 0 {
			if hasAnyTag(c.Tags, excludeTags) {
				continue
			}
		}

		filteredComponentsList = append(filteredComponentsList, c)
	}

	return filteredComponentsList
}

func hasAnyTag(componentTags, filterTags []string) bool {
	for _, ct := range componentTags {
		for _, ft := range filterTags {
			if ct == ft {
				return true
			}
		}
	}
	return false
}
