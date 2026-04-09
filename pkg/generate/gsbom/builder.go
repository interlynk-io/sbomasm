package gsbom

type BOM struct {
	Artifact     Artifact
	Components   []Component
	Dependencies map[string][]string
}

func BuildBOM(artifact *Artifact, components []Component, graph *DependencyGraph) *BOM {

	bom := &BOM{
		Artifact:     *artifact,
		Components:   components,
		Dependencies: make(map[string][]string),
	}

	// Copy dependency edges
	for parent, children := range graph.Edges {
		bom.Dependencies[parent] = children
	}

	return bom
}
