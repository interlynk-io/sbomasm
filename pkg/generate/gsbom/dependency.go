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

func BuildComponentMap(components []Component) map[string]Component {
	m := make(map[string]Component)

	for _, c := range components {
		key := componentKey(c)

		// "libmqtt@4.3.0" -> Component{...}
		m[key] = c
	}

	return m
}

type DependencyGraph struct {
	// parent -> children
	Edges map[string][]string
}

func BuildDependencyGraph(components []Component, compMap map[string]Component) (*DependencyGraph, []error) {
	graph := &DependencyGraph{
		Edges: make(map[string][]string),
	}

	var warnings []error

	for _, c := range components {
		childKey := componentKey(c)

		// Case 1: has dependency-of
		if len(c.DependencyOf) > 0 {
			for _, parentRef := range c.DependencyOf {

				// Check if parent exists
				if _, ok := compMap[parentRef]; !ok {
					warnings = append(warnings,
						fmt.Errorf("missing dependency reference: %s → %s", childKey, parentRef))
					continue
				}

				// parent -> child
				graph.Edges[parentRef] = append(graph.Edges[parentRef], childKey)
			}
		} else {
			// Case 2: top-level (handled later in SBOM builder)
			continue
		}
	}

	return graph, warnings
}
