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
