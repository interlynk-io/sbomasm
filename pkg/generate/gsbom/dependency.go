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
	"fmt"
	"strings"
)

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

// BuildDependencyGraph performs the following functionality:
// - takes a list of components and a component map (keyed by name@version) and
// - builds a dependency graph based on the "dependency-of" field in components.
func BuildDependencyGraph(components []Component, compMap map[string]Component, artifact *Artifact) (*DependencyGraph, []error) {
	graph := &DependencyGraph{
		Edges: make(map[string][]string),
	}

	var warnings []error

	for _, c := range components {
		childKey := componentKey(c)

		seen := make(map[string]bool)

		// Case 1: has dependency-of
		if len(c.DependencyOf) > 0 {
			for _, parentRef := range c.DependencyOf {
				parentRef = strings.TrimSpace(parentRef)

				if seen[parentRef] {
					continue // skip duplicate parent references
				}
				seen[parentRef] = true

				// Check for self-dependency
				if parentRef == childKey {
					warnings = append(warnings, fmt.Errorf("component %s cannot be a dependency of itself", childKey))
					continue
				}

				// Check if parent exists
				if _, ok := compMap[parentRef]; !ok {
					warnings = append(warnings, fmt.Errorf("missing dependency reference: %s -> %s", childKey, parentRef))
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

	// 2. Remove cycles
	warn1, edges := detectAndRemoveCycles(graph.Edges)
	graph.Edges = edges

	warnings = append(warnings, warn1...)

	// 3. Attach orphans to root (artifact)
	root := componentKey(Component{
		Name:    artifact.Name,
		Version: artifact.Version,
	})

	attachOrphansToRoot(graph.Edges, components, root)

	return graph, warnings
}

// detectAndRemoveCycles performs the following functionality:
// - detects cycles in the dependency graph and removes edges that cause cycles.
// - returns a list of warnings for detected cycles and the modified graph without cycles.
func detectAndRemoveCycles(graph map[string][]string) ([]error, map[string][]string) {
	var warnings []error

	visited := make(map[string]bool)
	stack := make(map[string]bool)

	var dfs func(node string) bool

	dfs = func(node string) bool {
		if stack[node] {
			return true // cycle detected
		}
		if visited[node] {
			return false
		}

		visited[node] = true
		stack[node] = true

		children := graph[node]
		fmt.Println("children: ", children)
		var newChildren []string

		for _, child := range children {
			if dfs(child) {
				// cycle edge -> drop it
				warnings = append(warnings, fmt.Errorf("cycle detected: %s -> %s (edge removed)", node, child))
				continue
			}
			newChildren = append(newChildren, child)
		}

		graph[node] = newChildren
		stack[node] = false
		return false
	}

	for node := range graph {
		fmt.Println("Node1: ", node)
		dfs(node)
	}

	return warnings, graph
}

func attachOrphansToRoot(graph map[string][]string, components []Component, root string) {
	// 1. compute in-degree
	inDegree := make(map[string]int)

	for parent, children := range graph {
		for _, child := range children {
			inDegree[child]++
		}
		// ensure parent exists in map
		if _, ok := inDegree[parent]; !ok {
			inDegree[parent] = inDegree[parent]
		}
	}

	// 2. attach only nodes with NO parent
	for _, c := range components {
		key := componentKey(c)

		if key == root {
			continue
		}

		if inDegree[key] == 0 {
			graph[root] = append(graph[root], key)
		}
	}
}
