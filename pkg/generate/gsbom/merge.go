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

import "fmt"

func componentKey(c Component) string {
	return c.Name + "@" + c.Version
}

func MergeAll(componentLists [][]Component) []Component {
	var merged []Component

	for _, group := range componentLists {
		merged = append(merged, group...)
	}

	return merged
}

func DeduplicateComponents(components []Component) ([]Component, []error) {
	var result []Component
	var warnings []error

	seen := make(map[string]bool)

	for _, c := range components {
		key := componentKey(c)

		if seen[key] {
			warnings = append(warnings, fmt.Errorf("duplicate component: %s", key))
			continue
		}

		seen[key] = true
		result = append(result, c)
	}

	return result, warnings
}
