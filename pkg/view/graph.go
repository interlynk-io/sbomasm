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

package view

import (
	"fmt"
)

// BuildGraph enriches the component graph with dependency information and detects islands
func BuildGraph(graph *ComponentGraph) error {
	// Link dependency details
	linkDependencies(graph)

	// Detect islands (disconnected components)
	detectIslands(graph)

	// Set up root nodes
	setupRootNodes(graph)

	return nil
}

// linkDependencies fills in dependency details for each component
func linkDependencies(graph *ComponentGraph) {
	// We need to iterate through the DepGraph instead of AllNodes
	// because components might be keyed by name in DepGraph but by BOMRef (or name) in AllNodes
	for depGraphKey, depRefs := range graph.DepGraph {
		// Find the source component that has these dependencies
		sourceComp, found, _ := resolveComponent(depGraphKey, graph)
		if !found {
			// Source component not found, skip
			continue
		}

		// Look up each dependency and create DependencyInfo
		for _, depRef := range depRefs {
			depComp, found, fallbackMethod := resolveComponent(depRef, graph)
			if !found {
				// Dependency not found in components - create a placeholder
				sourceComp.Dependencies = append(sourceComp.Dependencies, DependencyInfo{
					BOMRef: depRef,
					Name:   depRef, // Use depRef as name if component not found
					Type:   "unknown",
				})
				continue
			}

			// Track fallback usage
			if fallbackMethod != "" {
				resolvedTo := depComp.BOMRef
				if resolvedTo == "" {
					// If component has no BOMRef, use the identifier used for resolution
					switch fallbackMethod {
					case "purl":
						resolvedTo = depComp.PURL
					case "cpe":
						resolvedTo = depComp.CPE
					case "name-version":
						resolvedTo = depComp.Name + "-" + depComp.Version
					case "name":
						resolvedTo = depComp.Name
					}
				}
				graph.FallbackResolutions = append(graph.FallbackResolutions, FallbackResolution{
					SourceRef:  depGraphKey,
					TargetRef:  depRef,
					ResolvedBy: fallbackMethod,
					ResolvedTo: resolvedTo,
				})
			}

			// Create dependency info from the component
			sourceComp.Dependencies = append(sourceComp.Dependencies, DependencyInfo{
				BOMRef:   depComp.BOMRef,
				Name:     depComp.Name,
				Version:  depComp.Version,
				Type:     depComp.Type,
				PURL:     depComp.PURL,
				Licenses: depComp.Licenses,
				Supplier: depComp.Supplier,
			})
		}
	}
}

// resolveComponent attempts to find a component using multiple strategies
// Returns: (component, found, fallbackMethod)
// fallbackMethod is empty string if found by BOMRef, otherwise indicates which fallback was used
func resolveComponent(ref string, graph *ComponentGraph) (*EnrichedComponent, bool, string) {
	// Try primary lookup by BOMRef first
	// Check if the component found has a proper BOMRef
	if comp, found := graph.AllNodes[ref]; found {
		// If the component has a BOMRef and it matches the ref, this is a proper resolution
		if comp.BOMRef != "" && comp.BOMRef == ref {
			return comp, true, ""
		}
		// If component has no BOMRef but was found in AllNodes, it was added by name
		// This means we're doing name-based resolution - track it as fallback
		if comp.BOMRef == "" {
			// Determine which fallback method this is
			if comp.PURL != "" && comp.PURL == ref {
				return comp, true, "purl"
			}
			if comp.CPE != "" && comp.CPE == ref {
				return comp, true, "cpe"
			}
			nameVersion := comp.Name
			if comp.Version != "" {
				nameVersion = comp.Name + "-" + comp.Version
			}
			if nameVersion == ref {
				return comp, true, "name-version"
			}
			if comp.Name == ref {
				return comp, true, "name"
			}
		}
	}

	// Try PURL lookup
	if comp, found := graph.ByPURL[ref]; found {
		return comp, true, "purl"
	}

	// Try CPE lookup
	if comp, found := graph.ByCPE[ref]; found {
		return comp, true, "cpe"
	}

	// Try name-version lookup
	if comp, found := graph.ByNameVersion[ref]; found {
		return comp, true, "name-version"
	}

	// Try name-only lookup (take first match if multiple exist)
	if comps, found := graph.ByName[ref]; found && len(comps) > 0 {
		return comps[0], true, "name"
	}

	// Not found
	return nil, false, ""
}

// detectIslands finds disconnected component subgraphs
// An island is any component (or group of components) that has no path to the primary component
func detectIslands(graph *ComponentGraph) {
	visited := make(map[string]bool)

	// Mark all components reachable from primary component
	if graph.Primary != nil {
		markReachable(graph.Primary, visited, graph)
	}

	// Find all unvisited components - these are all islands
	// We need to group them by their connected subgraphs
	islandID := 1
	for _, comp := range graph.AllNodes {
		// Use the component's identifier for tracking (prefer BOMRef, fallback to name)
		compID := comp.BOMRef
		if compID == "" {
			compID = comp.Name
		}

		if !visited[compID] {
			// This component is not reachable from primary - it's part of an island
			// Collect all components in this island subgraph
			island := make([]*EnrichedComponent, 0)
			// Use the global visited map to ensure we don't split connected island components
			collectIslandSubgraph(comp, &island, visited, graph, islandID)

			if len(island) > 0 {
				graph.Islands = append(graph.Islands, island)
				islandID++
			}
		}
	}
}

// markReachable marks all components reachable from the given component
func markReachable(comp *EnrichedComponent, visited map[string]bool, graph *ComponentGraph) {
	if comp == nil {
		return
	}

	// Use the component's identifier for tracking (prefer BOMRef, fallback to name)
	compID := comp.BOMRef
	if compID == "" {
		compID = comp.Name
	}
	if visited[compID] {
		return
	}

	visited[compID] = true

	// Visit children (assembly relationships)
	for _, child := range comp.Children {
		markReachable(child, visited, graph)
	}

	// Visit dependencies using fallback resolution
	depRefs := []string{}
	if comp.BOMRef != "" {
		if deps, ok := graph.DepGraph[comp.BOMRef]; ok {
			depRefs = deps
		}
	}
	// Also check if component is referenced by name in DepGraph
	if comp.BOMRef == "" && comp.Name != "" {
		if deps, ok := graph.DepGraph[comp.Name]; ok {
			depRefs = deps
		}
	}

	for _, depRef := range depRefs {
		if depComp, found, _ := resolveComponent(depRef, graph); found {
			markReachable(depComp, visited, graph)
		}
	}
}

// collectIslandSubgraph recursively collects all components in an island subgraph
// This follows both assembly (parent-child) and dependency relationships
func collectIslandSubgraph(comp *EnrichedComponent, island *[]*EnrichedComponent, visited map[string]bool, graph *ComponentGraph, islandID int) {
	if comp == nil {
		return
	}

	// Use the component's identifier for tracking (prefer BOMRef, fallback to name)
	compID := comp.BOMRef
	if compID == "" {
		compID = comp.Name
	}
	if visited[compID] {
		return
	}

	visited[compID] = true
	comp.IslandID = islandID
	*island = append(*island, comp)

	// Follow children (assembly relationships)
	for _, child := range comp.Children {
		collectIslandSubgraph(child, island, visited, graph, islandID)
	}

	// Follow dependencies within the island using fallback resolution
	depRefs := []string{}
	if comp.BOMRef != "" {
		if deps, ok := graph.DepGraph[comp.BOMRef]; ok {
			depRefs = deps
		}
	}
	// Also check if component is referenced by name in DepGraph
	if comp.BOMRef == "" && comp.Name != "" {
		if deps, ok := graph.DepGraph[comp.Name]; ok {
			depRefs = deps
		}
	}

	for _, depRef := range depRefs {
		if depComp, found, _ := resolveComponent(depRef, graph); found {
			collectIslandSubgraph(depComp, island, visited, graph, islandID)
		}
	}

	// Follow reverse dependencies (components that depend on this one)
	for bomRef, deps := range graph.DepGraph {
		for _, depRef := range deps {
			// Check if depRef resolves to our component
			if resolvedComp, found, _ := resolveComponent(depRef, graph); found {
				resolvedID := resolvedComp.BOMRef
				if resolvedID == "" {
					resolvedID = resolvedComp.Name
				}
				if resolvedID == compID {
					// This dependency points to our component, so follow back to the parent
					if parentComp, found, _ := resolveComponent(bomRef, graph); found {
						collectIslandSubgraph(parentComp, island, visited, graph, islandID)
					}
				}
			}
		}
	}
}

// setupRootNodes sets up the root nodes list
func setupRootNodes(graph *ComponentGraph) {
	graph.RootNodes = make([]*EnrichedComponent, 0)

	// Add primary if it exists
	if graph.Primary != nil {
		graph.RootNodes = append(graph.RootNodes, graph.Primary)
	}

	// Add island roots
	for _, island := range graph.Islands {
		if len(island) > 0 {
			graph.RootNodes = append(graph.RootNodes, island[0])
		}
	}
}

// CalculateStatistics computes overall statistics for the SBOM
func CalculateStatistics(graph *ComponentGraph) Statistics {
	stats := Statistics{
		TotalComponents:   len(graph.AllNodes),
		TotalAnnotations:  len(graph.Annotations),  // Keep for global annotations if any
		TotalCompositions: len(graph.Compositions), // Keep for global compositions if any
		IslandCount:       len(graph.Islands),
		ComponentsByType:  make(map[string]int),
	}

	// Count dependencies, vulnerabilities, annotations, and compositions from components
	annotationsSeen := make(map[string]bool) // Track unique annotations
	compositionsSeen := make(map[string]bool) // Track unique compositions

	for _, comp := range graph.AllNodes {
		// Count by type
		stats.ComponentsByType[comp.Type]++

		// Count dependencies
		stats.TotalDependencies += comp.DependencyCount

		// Count annotations (avoid duplicates)
		for _, ann := range comp.Annotations {
			// Create a unique key for the annotation
			key := fmt.Sprintf("%s|%s", ann.Text, ann.Annotator)
			if !annotationsSeen[key] {
				annotationsSeen[key] = true
				stats.TotalAnnotations++
			}
		}

		// Count compositions (avoid duplicates)
		for _, comp := range comp.Compositions {
			// Create a unique key for the composition
			key := fmt.Sprintf("%s|%v|%v", comp.Aggregate, comp.Assemblies, comp.Dependencies)
			if !compositionsSeen[key] {
				compositionsSeen[key] = true
				stats.TotalCompositions++
			}
		}

		// Aggregate vulnerabilities
		stats.TotalVulnerabilities.Total += comp.VulnCount.Total
		stats.TotalVulnerabilities.Critical += comp.VulnCount.Critical
		stats.TotalVulnerabilities.High += comp.VulnCount.High
		stats.TotalVulnerabilities.Medium += comp.VulnCount.Medium
		stats.TotalVulnerabilities.Low += comp.VulnCount.Low
		stats.TotalVulnerabilities.None += comp.VulnCount.None
		stats.TotalVulnerabilities.Unknown += comp.VulnCount.Unknown
	}

	// Calculate max depth from primary component only (not islands)
	// This represents the depth of the main component tree
	maxDepth := 0
	if graph.Primary != nil {
		visited := make(map[string]bool)    // Track visited components in current path
		depthCache := make(map[string]int)  // Cache computed depths for memoization
		maxDepth = calculateTreeDepth(graph.Primary, graph, 0, visited, depthCache)
	}

	stats.MaxDepth = maxDepth

	return stats
}

// calculateDepth calculates the depth of a component in the tree by counting parents (legacy method)
func calculateDepth(comp *EnrichedComponent) int {
	depth := 0
	current := comp
	for current.Parent != nil {
		depth++
		current = current.Parent
	}
	return depth
}

// calculateTreeDepth calculates the maximum depth from a component downward through the tree
// This includes both assembly children and expanded dependencies
// Uses a visited map to prevent infinite recursion and a cache for memoization
func calculateTreeDepth(comp *EnrichedComponent, graph *ComponentGraph, currentDepth int, visited map[string]bool, depthCache map[string]int) int {
	// Get component identifier
	compID := comp.BOMRef
	if compID == "" {
		compID = comp.Name
	}

	// Check if already visited in current path (cycle detection)
	if visited[compID] {
		return currentDepth
	}

	// Check cache for previously computed depth from this component
	if cachedDepth, found := depthCache[compID]; found {
		return currentDepth + cachedDepth
	}

	// Mark as visited in current path
	visited[compID] = true
	defer func() {
		// Unmark when done with this branch
		delete(visited, compID)
	}()

	maxDepthFromHere := 0

	// Check children (assemblies)
	for _, child := range comp.Children {
		childDepth := calculateTreeDepth(child, graph, 1, visited, depthCache)
		if childDepth > maxDepthFromHere {
			maxDepthFromHere = childDepth
		}
	}

	// Check dependencies - only count those that would be expanded in the tree view
	// (those with assemblies or other dependencies of their own)
	if comp.Dependencies != nil {
		for _, dep := range comp.Dependencies {
			if depComp, found := graph.AllNodes[dep.BOMRef]; found {
				// Only count dependencies that would be expanded in the tree view
				// This matches the renderer logic which only expands non-leaf dependencies
				if len(depComp.Children) > 0 || len(depComp.Dependencies) > 0 {
					depDepth := calculateTreeDepth(depComp, graph, 1, visited, depthCache)
					if depDepth > maxDepthFromHere {
						maxDepthFromHere = depDepth
					}
				}
			}
		}
	}

	// Cache the computed depth from this component
	depthCache[compID] = maxDepthFromHere

	return currentDepth + maxDepthFromHere
}

// ValidateGraph performs validation checks on the graph
func ValidateGraph(graph *ComponentGraph) []error {
	var errors []error

	// Check for circular dependencies
	if cycles := detectCircularDependencies(graph); len(cycles) > 0 {
		for _, cycle := range cycles {
			errors = append(errors, fmt.Errorf("circular dependency detected: %v", cycle))
		}
	}

	// Check for dangling references (components that couldn't be resolved even with fallbacks)
	for bomRef, deps := range graph.DepGraph {
		for _, depRef := range deps {
			if _, found, _ := resolveComponent(depRef, graph); !found {
				errors = append(errors, fmt.Errorf("dangling dependency reference: %s -> %s", bomRef, depRef))
			}
		}
	}

	// Report fallback resolutions as informational warnings
	// These occur when dependencies are resolved using fallback mechanisms (PURL, CPE, name-version, name)
	// instead of the standard bom-ref lookup
	if len(graph.FallbackResolutions) > 0 {
		for _, fb := range graph.FallbackResolutions {
			errors = append(errors, fmt.Errorf("used fallback resolution (%s): %s -> %s (resolved to component: %s)",
				fb.ResolvedBy, fb.SourceRef, fb.TargetRef, fb.ResolvedTo))
		}
	}

	return errors
}

// detectCircularDependencies detects circular dependencies using DFS
func detectCircularDependencies(graph *ComponentGraph) [][]string {
	var cycles [][]string
	visited := make(map[string]bool)
	recStack := make(map[string]bool)
	path := make([]string, 0)

	for bomRef := range graph.AllNodes {
		if !visited[bomRef] {
			if foundCycles := dfsDetectCycle(bomRef, graph, visited, recStack, path); len(foundCycles) > 0 {
				cycles = append(cycles, foundCycles...)
			}
		}
	}

	return cycles
}

// dfsDetectCycle performs DFS to detect cycles
func dfsDetectCycle(bomRef string, graph *ComponentGraph, visited, recStack map[string]bool, path []string) [][]string {
	visited[bomRef] = true
	recStack[bomRef] = true
	path = append(path, bomRef)

	var cycles [][]string

	if deps, ok := graph.DepGraph[bomRef]; ok {
		for _, depRef := range deps {
			if !visited[depRef] {
				if foundCycles := dfsDetectCycle(depRef, graph, visited, recStack, path); len(foundCycles) > 0 {
					cycles = append(cycles, foundCycles...)
				}
			} else if recStack[depRef] {
				// Found a cycle
				cycleStart := -1
				for i, ref := range path {
					if ref == depRef {
						cycleStart = i
						break
					}
				}
				if cycleStart != -1 {
					cycle := make([]string, 0)
					cycle = append(cycle, path[cycleStart:]...)
					cycle = append(cycle, depRef)
					cycles = append(cycles, cycle)
				}
			}
		}
	}

	recStack[bomRef] = false
	return cycles
}

// GetComponentPath returns the path from root to a given component
func GetComponentPath(comp *EnrichedComponent) []*EnrichedComponent {
	path := make([]*EnrichedComponent, 0)
	current := comp

	for current != nil {
		path = append([]*EnrichedComponent{current}, path...)
		current = current.Parent
	}

	return path
}

// FindComponentByBOMRef finds a component by its BOMRef
func FindComponentByBOMRef(graph *ComponentGraph, bomRef string) *EnrichedComponent {
	return graph.AllNodes[bomRef]
}

// FindComponentsByType finds all components of a given type
func FindComponentsByType(graph *ComponentGraph, compType string) []*EnrichedComponent {
	var result []*EnrichedComponent

	for _, comp := range graph.AllNodes {
		if comp.Type == compType {
			result = append(result, comp)
		}
	}

	return result
}

// FindComponentsWithVulnerabilities finds all components with vulnerabilities
func FindComponentsWithVulnerabilities(graph *ComponentGraph, minSeverity string) []*EnrichedComponent {
	var result []*EnrichedComponent

	for _, comp := range graph.AllNodes {
		if hasVulnerabilityOfSeverity(comp, minSeverity) {
			result = append(result, comp)
		}
	}

	return result
}

// hasVulnerabilityOfSeverity checks if component has vulnerabilities of given severity or higher
func hasVulnerabilityOfSeverity(comp *EnrichedComponent, minSeverity string) bool {
	if len(comp.Vulnerabilities) == 0 {
		return false
	}

	switch minSeverity {
	case "critical":
		return comp.VulnCount.Critical > 0
	case "high":
		return comp.VulnCount.Critical > 0 || comp.VulnCount.High > 0
	case "medium":
		return comp.VulnCount.Critical > 0 || comp.VulnCount.High > 0 || comp.VulnCount.Medium > 0
	case "low":
		return comp.VulnCount.Total > 0
	default:
		return false
	}
}
