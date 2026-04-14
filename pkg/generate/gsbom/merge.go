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

func componentKey(c Component) string {
	return c.Name + "@" + c.Version
}

// MergeAll takes a list of component lists and
// merges them into a single list.
func MergeAll(componentLists [][]Component) []Component {
	var mergedComponentList []Component

	for _, components := range componentLists {
		mergedComponentList = append(mergedComponentList, components...)
	}

	return mergedComponentList
}

// DeduplicateComponents takes a list of components:
// - removes duplicates based on name and version
// - and finally returns a list of unique components
func DeduplicateComponents(components []Component) ([]Component, []error) {
	var componentUniqueLists []Component
	var warnings []error

	seen := make(map[string]*Component)

	for _, c := range components {
		key := componentKey(c)

		if existing, ok := seen[key]; ok {
			mergeComponent(existing, c)
			continue
		}
		copy := c
		seen[key] = &copy
		componentUniqueLists = append(componentUniqueLists, copy)
	}

	return componentUniqueLists, warnings
}

func mergeComponent(dst *Component, src Component) {
	// --- dependency-of (CRITICAL FIX) ---
	dst.DependencyOf = unionStrings(dst.DependencyOf, src.DependencyOf)

	// --- tags ---
	dst.Tags = unionStrings(dst.Tags, src.Tags)
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]bool)
	var out []string

	for _, v := range a {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}

	return out
}
