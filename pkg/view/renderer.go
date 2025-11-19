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
	"io"
	"strings"
)

// TreeRenderer renders component graphs in tree format
type TreeRenderer struct {
	config          DisplayConfig
	scheme          *ColorScheme
	symbols         TreeSymbols
	graph           *ComponentGraph // Store graph for looking up dependency components
	visited         map[string]int  // Track components being rendered to detect cycles (BOMRef -> depth)
	maxDepth        int             // Maximum depth calculated in the tree
	maxRenderedDepth int             // Maximum depth actually rendered
	depthCache      map[string]int  // Cache for subtree depth calculations
}

// NewTreeRenderer creates a new tree renderer
func NewTreeRenderer(config DisplayConfig) *TreeRenderer {
	var scheme *ColorScheme
	if config.NoColor {
		scheme = NoColorScheme()
	} else {
		scheme = DefaultColorScheme()
	}

	return &TreeRenderer{
		config:     config,
		scheme:     scheme,
		symbols:    DefaultTreeSymbols(),
		visited:    make(map[string]int),
		depthCache: make(map[string]int),
	}
}

// Render renders the component graph to the output writer
func (r *TreeRenderer) Render(graph *ComponentGraph, output io.Writer) error {
	// Store graph for looking up dependency components
	r.graph = graph

	// Write SBOM header
	var header string
	if r.config.VerboseOutput {
		header = FormatSBOMHeaderVerbose(graph.Metadata, r.scheme)
	} else {
		header = FormatSBOMHeader(graph.Metadata, r.scheme)
	}
	fmt.Fprintln(output, header)

	// Calculate statistics to get total depth
	stats := CalculateStatistics(graph)
	r.maxDepth = stats.MaxDepth // Store for marking deepest components

	// Pre-calculate all component subtree depths for efficient lookups during rendering
	r.preCalculateSubtreeDepths(graph)

	// Display depth information
	if r.config.MaxDepth > 0 {
		fmt.Fprintf(output, "%s\n", r.scheme.FieldLabel.Sprintf("Showing up to depth %d, total depth is %d", r.config.MaxDepth, stats.MaxDepth))
	} else {
		fmt.Fprintf(output, "%s\n", r.scheme.FieldLabel.Sprintf("Total depth is %d", stats.MaxDepth))
	}
	fmt.Fprintln(output)

	// Render primary component tree
	if graph.Primary != nil {
		r.renderComponent(graph.Primary, output, "", true, 0)
	} else if len(graph.RootNodes) > 0 && !r.config.OnlyPrimary {
		// No primary, render first root
		r.renderComponent(graph.RootNodes[0], output, "", true, 0)
	}

	// Render islands if not collapsed
	if !r.config.CollapseIslands && !r.config.OnlyPrimary && len(graph.Islands) > 0 {
		fmt.Fprintln(output)
		r.renderIslands(graph.Islands, output)
	}

	// Render statistics
	fmt.Fprintln(output)
	fmt.Fprintln(output, FormatStatistics(stats, r.scheme))

	return nil
}

// preCalculateSubtreeDepths pre-calculates subtree depths for all components
// This is done once before rendering to avoid repeated calculations
func (r *TreeRenderer) preCalculateSubtreeDepths(graph *ComponentGraph) {
	visited := make(map[string]bool)

	// Calculate for all nodes in the graph
	for _, comp := range graph.AllNodes {
		compID := comp.BOMRef
		if compID == "" {
			compID = comp.Name
		}
		// Only calculate if not already in cache
		if _, found := r.depthCache[compID]; !found {
			calculateTreeDepth(comp, graph, 0, visited, r.depthCache)
		}
	}
}

// getSubtreeDepth retrieves the pre-calculated subtree depth for a component
func (r *TreeRenderer) getSubtreeDepth(comp *EnrichedComponent) int {
	compID := comp.BOMRef
	if compID == "" {
		compID = comp.Name
	}
	if depth, found := r.depthCache[compID]; found {
		return depth
	}
	return 0 // Default to 0 if not found (shouldn't happen with pre-calculation)
}

// showMaxDepthComponents displays a summary of components at maximum rendered depth
func (r *TreeRenderer) showMaxDepthComponents(graph *ComponentGraph, output io.Writer) {
	// Find all components at max rendered depth
	maxDepthComps := r.findComponentsAtDepth(graph.Primary, r.maxRenderedDepth, 0)

	// Also check islands
	for _, island := range graph.Islands {
		for _, root := range island {
			if root.Parent == nil {
				maxDepthComps = append(maxDepthComps, r.findComponentsAtDepth(root, r.maxRenderedDepth, 0)...)
			}
		}
	}

	if len(maxDepthComps) > 0 {
		// Deduplicate components by BOMRef
		seen := make(map[string]bool)
		uniqueComps := make([]*EnrichedComponent, 0)
		for _, comp := range maxDepthComps {
			compID := comp.BOMRef
			if compID == "" {
				compID = comp.Name
			}
			if !seen[compID] {
				seen[compID] = true
				uniqueComps = append(uniqueComps, comp)
			}
		}

		fmt.Fprintf(output, "%s\n", r.scheme.Critical.Sprint("━━━ Components at Maximum Depth ━━━"))
		fmt.Fprintf(output, "%s at depth %d:\n", r.scheme.FieldLabel.Sprint("The following components"), r.maxRenderedDepth)

		// Show up to 10 components
		maxShow := 10
		for i, comp := range uniqueComps {
			if i >= maxShow {
				remaining := len(uniqueComps) - maxShow
				fmt.Fprintf(output, "  %s\n", r.scheme.FieldLabel.Sprintf("... and %d more", remaining))
				break
			}
			nameVersion := comp.Name
			if comp.Version != "" {
				nameVersion += "@" + comp.Version
			}
			fmt.Fprintf(output, "  • %s %s\n", r.scheme.ComponentName.Sprint(nameVersion),
				r.scheme.FieldLabel.Sprintf("(%s)", comp.Type))
		}
	}
}

// findComponentsAtDepth recursively finds all components at a specific depth
func (r *TreeRenderer) findComponentsAtDepth(comp *EnrichedComponent, targetDepth int, currentDepth int) []*EnrichedComponent {
	var result []*EnrichedComponent

	if currentDepth == targetDepth {
		result = append(result, comp)
	}

	if currentDepth < targetDepth {
		// Check children
		for _, child := range comp.Children {
			result = append(result, r.findComponentsAtDepth(child, targetDepth, currentDepth+1)...)
		}

		// Check expanded dependencies
		if comp.Dependencies != nil {
			for _, dep := range comp.Dependencies {
				if depComp, found := r.graph.AllNodes[dep.BOMRef]; found {
					if len(depComp.Children) > 0 || len(depComp.Dependencies) > 0 {
						result = append(result, r.findComponentsAtDepth(depComp, targetDepth, currentDepth+1)...)
					}
				}
			}
		}
	}

	return result
}

// renderComponent renders a single component and its children
func (r *TreeRenderer) renderComponent(comp *EnrichedComponent, output io.Writer, prefix string, isLast bool, depth int) {
	if r.config.MaxDepth > 0 && depth >= r.config.MaxDepth {
		return
	}

	// Check for cycles using component identifier
	compID := comp.BOMRef
	if compID == "" {
		compID = comp.Name
	}

	// If we've already visited this component at the same or shallower depth, skip to avoid cycles
	if visitedDepth, seen := r.visited[compID]; seen && visitedDepth <= depth {
		// Component already being rendered - this is a cycle
		connector := r.symbols.Branch
		if isLast {
			connector = r.symbols.Last
		}
		if depth == 0 {
			connector = "┌─"
		}

		header := FormatComponentHeader(comp, r.scheme)
		depthIndicator := r.scheme.FieldLabel.Sprintf("[depth:%d]", depth)
		fmt.Fprintf(output, "%s%s %s %s %s\n", prefix, r.scheme.TreeStructure.Sprint(connector), header,
			depthIndicator, r.scheme.FieldLabel.Sprint("(circular reference - already shown above)"))
		return
	}

	// Mark this component as being visited at this depth
	r.visited[compID] = depth
	defer func() {
		// Remove from visited when we're done with this branch
		delete(r.visited, compID)
	}()

	// Component header
	connector := r.symbols.Branch
	if isLast {
		connector = r.symbols.Last
	}

	if depth == 0 {
		connector = "┌─"
	}

	// Track maximum rendered depth
	if depth > r.maxRenderedDepth {
		r.maxRenderedDepth = depth
	}

	header := FormatComponentHeader(comp, r.scheme)
	// Show current depth
	depthIndicator := r.scheme.FieldLabel.Sprintf("[depth:%d]", depth)
	fmt.Fprintf(output, "%s%s %s %s\n", prefix, r.scheme.TreeStructure.Sprint(connector), header, depthIndicator)

	// Build child prefix
	childPrefix := prefix
	if depth > 0 {
		if isLast {
			childPrefix += "  "
		} else {
			childPrefix += r.scheme.TreeStructure.Sprint(r.symbols.Vertical) + " "
		}
	} else {
		childPrefix += r.scheme.TreeStructure.Sprint(r.symbols.Vertical) + " "
	}

	// Render component details and get dependencies to expand (render as tree)
	depsToExpand := r.renderComponentDetails(comp, output, childPrefix, depth)

	// Render children (assemblies) - these come before expanded dependencies
	if len(comp.Children) > 0 {
		if r.config.MaxDepth > 0 && depth+1 >= r.config.MaxDepth {
			// Show truncated message
			fmt.Fprintf(output, "%s%s %s\n", childPrefix,
				r.scheme.TreeStructure.Sprint(r.symbols.Last),
				r.scheme.FieldLabel.Sprintf("(... %d nested components - use --max-depth to expand)", len(comp.Children)))
		} else {
			fmt.Fprintf(output, "%s%s\n", childPrefix,
				r.scheme.FieldLabel.Sprintf("Assemblies (%d):", len(comp.Children)))

			for i, child := range comp.Children {
				isChildLast := i == len(comp.Children)-1
				r.renderComponent(child, output, childPrefix, isChildLast, depth+1)
			}
		}
	}

	// Render expanded dependencies last (after all component details and assemblies)
	if len(depsToExpand) > 0 {
		for i, depComp := range depsToExpand {
			isLast := i == len(depsToExpand)-1 && len(comp.Children) == 0
			r.renderComponent(depComp, output, childPrefix, isLast, depth+1)
		}
	}
}

// renderComponentDetails renders detailed information about a component
// Returns a list of dependency components to expand (those with assemblies or dependencies)
func (r *TreeRenderer) renderComponentDetails(comp *EnrichedComponent, output io.Writer, prefix string, depth int) []*EnrichedComponent {
	// If showing only licenses, skip most details
	if r.config.ShowOnlyLicenses {
		// Only show licenses
		if len(comp.Licenses) > 0 {
			fmt.Fprintf(output, "%s  %s\n", prefix, FormatListHeader("Licenses", len(comp.Licenses), r.scheme))
			for _, lic := range comp.Licenses {
				fmt.Fprintf(output, "%s    - %s\n", prefix, FormatLicense(lic, r.scheme))
			}
		} else {
			fmt.Fprintf(output, "%s  %s\n", prefix, r.scheme.FieldLabel.Sprint("No license information"))
		}
		// Return empty list to skip dependency rendering
		return make([]*EnrichedComponent, 0)
	}

	// Type and description
	if comp.Type != "" {
		fmt.Fprintf(output, "%s  Type: %s\n", prefix, r.scheme.Info.Sprint(comp.Type))
	}

	if comp.Description != "" && r.config.VerboseOutput {
		desc := truncateString(comp.Description, 100)
		fmt.Fprintf(output, "%s  Description: %s\n", prefix, r.scheme.Info.Sprint(desc))
	}

	// Supplier
	if r.config.VerboseOutput && comp.Supplier != "" {
		fmt.Fprintf(output, "%s  Supplier: %s\n", prefix, r.scheme.Supplier.Sprint(comp.Supplier))
	}

	// PURL and CPE
	if r.config.VerboseOutput {
		if comp.PURL != "" {
			fmt.Fprintf(output, "%s  PURL: %s\n", prefix, FormatPURL(comp.PURL, r.scheme))
		}
		if comp.CPE != "" {
			fmt.Fprintf(output, "%s  CPE: %s\n", prefix, FormatCPE(comp.CPE, r.scheme))
		}
	}

	// Licenses
	if r.config.ShowLicenses && len(comp.Licenses) > 0 {
		fmt.Fprintf(output, "%s  %s\n", prefix, FormatListHeader("Licenses", len(comp.Licenses), r.scheme))
		for _, lic := range comp.Licenses {
			fmt.Fprintf(output, "%s    - %s\n", prefix, FormatLicense(lic, r.scheme))
		}
	}

	// Hashes
	if r.config.ShowHashes && len(comp.Hashes) > 0 {
		fmt.Fprintf(output, "%s  %s\n", prefix, FormatListHeader("Hashes", len(comp.Hashes), r.scheme))
		for _, hash := range comp.Hashes {
			if r.config.VerboseOutput {
				fmt.Fprintf(output, "%s    - %s\n", prefix, FormatHashVerbose(hash, r.scheme))
			} else {
				fmt.Fprintf(output, "%s    - %s\n", prefix, FormatHash(hash, r.scheme))
			}
		}
	}

	// Dependencies
	depsToExpand := make([]*EnrichedComponent, 0)
	if r.config.ShowDependencies && len(comp.Dependencies) > 0 {
		// Separate dependencies that should be expanded vs shown inline
		depsInline := make([]DependencyInfo, 0)

		for _, dep := range comp.Dependencies {
			if r.graph != nil {
				if depComp, found := r.graph.AllNodes[dep.BOMRef]; found {
					// Expand this dependency if it has assemblies OR other dependencies
					if len(depComp.Children) > 0 || len(depComp.Dependencies) > 0 {
						depsToExpand = append(depsToExpand, depComp)
					} else {
						// Leaf node, show as simple dependency
						depsInline = append(depsInline, dep)
					}
				} else {
					// Component not found, show as simple dependency
					depsInline = append(depsInline, dep)
				}
			} else {
				depsInline = append(depsInline, dep)
			}
		}

		// Show inline dependencies as a list (leaf nodes only)
		if len(depsInline) > 0 {
			fmt.Fprintf(output, "%s  %s\n", prefix, FormatListHeader("Dependencies", len(depsInline), r.scheme))

			if r.config.VerboseOutput {
				// In verbose mode, show all dependencies with full details
				for _, dep := range depsInline {
					fmt.Fprintf(output, "%s    - %s\n", prefix, FormatDependencyVerbose(dep, r.scheme))
				}
			} else {
				// In non-verbose mode, limit to 5 dependencies
				maxShow := 5
				for i, dep := range depsInline {
					if i >= maxShow {
						remaining := len(depsInline) - maxShow
						fmt.Fprintf(output, "%s    %s\n", prefix,
							r.scheme.FieldLabel.Sprintf("... and %d more", remaining))
						break
					}
					fmt.Fprintf(output, "%s    - %s\n", prefix, FormatDependency(dep, r.scheme))
				}
			}
		}
	} else if comp.DependencyCount > 0 {
		fmt.Fprintf(output, "%s  Dependencies: %d\n", prefix, comp.DependencyCount)
	}

	// Vulnerabilities
	if r.config.ShowVulnerabilities && len(comp.Vulnerabilities) > 0 {
		// Apply filters
		vulns := comp.Vulnerabilities
		if r.config.MinSeverity != "" || r.config.OnlyUnresolved {
			vulns = FilterVulnerabilities(vulns, r.config.MinSeverity, r.config.OnlyUnresolved)
		}

		if len(vulns) > 0 {
			fmt.Fprintf(output, "%s  %s\n", prefix, FormatListHeader("Vulnerabilities", len(vulns), r.scheme))

			if r.config.VerboseOutput {
				// Show all vulnerabilities with full details in compact format
				for _, vuln := range vulns {
					fmt.Fprintf(output, "%s    - %s\n", prefix, FormatVulnerabilityVerbose(vuln, r.scheme, prefix))
				}
			} else {
				// Show first few vulnerabilities in compact format
				maxShow := 5
				for i, vuln := range vulns {
					if i >= maxShow {
						remaining := len(vulns) - maxShow
						fmt.Fprintf(output, "%s    %s\n", prefix,
							r.scheme.FieldLabel.Sprintf("... and %d more", remaining))
						break
					}
					fmt.Fprintf(output, "%s    - %s\n", prefix, FormatVulnerability(vuln, r.scheme))
				}
			}
		}
	} else if comp.VulnCount.Total > 0 {
		fmt.Fprintf(output, "%s  %s\n", prefix, FormatVulnerabilitySummary(comp.VulnCount, r.scheme))
	}
	
	// Annotations
	if r.config.ShowAnnotations && len(comp.Annotations) > 0 {
		fmt.Fprintf(output, "%s  %s\n", prefix, FormatListHeader("Annotations", len(comp.Annotations), r.scheme))

		if r.config.VerboseOutput {
			// Show all annotations with full details
			for i, ann := range comp.Annotations {
				// Format annotation with full details
				annotatorStr := ""
				if ann.Annotator != "" {
					annotatorStr = ann.Annotator
				}

				fmt.Fprintf(output, "%s    - %s\n", prefix, r.scheme.Info.Sprint(ann.Text))

				if annotatorStr != "" {
					fmt.Fprintf(output, "%s      Annotator: %s\n", prefix, r.scheme.Annotations.Sprint(annotatorStr))
				}

				if !ann.Timestamp.IsZero() {
					fmt.Fprintf(output, "%s      Timestamp: %s\n", prefix, r.scheme.FieldLabel.Sprint(ann.Timestamp.Format("2006-01-02 15:04:05")))
				}

				// Add blank line between annotations except for the last one
				if i < len(comp.Annotations)-1 {
					fmt.Fprintf(output, "%s\n", prefix)
				}
			}
		} else {
			// Show first few annotations in compact format
			maxShow := 3
			for i, ann := range comp.Annotations {
				if i >= maxShow {
					remaining := len(comp.Annotations) - maxShow
					fmt.Fprintf(output, "%s    %s\n", prefix,
						r.scheme.FieldLabel.Sprintf("... and %d more", remaining))
					break
				}

				// Format annotation inline
				annotatorStr := ""
				if ann.Annotator != "" {
					annotatorStr = fmt.Sprintf("[%s] ", ann.Annotator)
				}
				fmt.Fprintf(output, "%s    - %s%s\n", prefix,
					r.scheme.Annotations.Sprint(annotatorStr),
					r.scheme.Info.Sprint(ann.Text))
			}
		}
	}
	
	// Compositions
	if r.config.ShowCompositions && len(comp.Compositions) > 0 {
		fmt.Fprintf(output, "%s  %s\n", prefix, FormatListHeader("Compositions", len(comp.Compositions), r.scheme))

		if r.config.VerboseOutput {
			// Show all compositions with full details
			for i, composition := range comp.Compositions {
				fmt.Fprintf(output, "%s    - Aggregate: %s\n", prefix,
					r.scheme.Info.Sprint(composition.Aggregate))

				// Show all assemblies
				if len(composition.Assemblies) > 0 {
					fmt.Fprintf(output, "%s      Assemblies (%d):\n", prefix, len(composition.Assemblies))
					for _, asm := range composition.Assemblies {
						fmt.Fprintf(output, "%s        - %s\n", prefix, r.scheme.Dependencies.Sprint(asm))
					}
				}

				// Show all dependencies
				if len(composition.Dependencies) > 0 {
					fmt.Fprintf(output, "%s      Dependencies (%d):\n", prefix, len(composition.Dependencies))
					for _, dep := range composition.Dependencies {
						fmt.Fprintf(output, "%s        - %s\n", prefix, r.scheme.Dependencies.Sprint(dep))
					}
				}

				// Add blank line between compositions except for the last one
				if i < len(comp.Compositions)-1 {
					fmt.Fprintf(output, "%s\n", prefix)
				}
			}
		} else {
			// Show first few compositions in compact format
			for i, composition := range comp.Compositions {
				if i >= 5 {
					remaining := len(comp.Compositions) - 5
					fmt.Fprintf(output, "%s    %s\n", prefix,
						r.scheme.FieldLabel.Sprintf("... and %d more", remaining))
					break
				}

				fmt.Fprintf(output, "%s    - %s\n", prefix,
					r.scheme.Info.Sprintf("Aggregate: %s", composition.Aggregate))

				// Show assemblies and dependencies in compact form
				if len(composition.Assemblies) > 0 {
					fmt.Fprintf(output, "%s      Assemblies: %s\n", prefix,
						r.scheme.Dependencies.Sprint(strings.Join(composition.Assemblies[:min(3, len(composition.Assemblies))], ", ")))
				}
			}
		}
	}

	// Properties
	if r.config.ShowProperties && len(comp.Properties) > 0 {
		fmt.Fprintf(output, "%s  %s\n", prefix, FormatListHeader("Properties", len(comp.Properties), r.scheme))

		if r.config.VerboseOutput {
			// Show all properties in verbose mode
			for _, prop := range comp.Properties {
				fmt.Fprintf(output, "%s    - %s\n", prefix, FormatProperty(prop, r.scheme))
			}
		} else {
			// Show first 5 properties in non-verbose mode
			maxShow := 5
			for i, prop := range comp.Properties {
				if i >= maxShow {
					remaining := len(comp.Properties) - maxShow
					fmt.Fprintf(output, "%s    %s\n", prefix,
						r.scheme.FieldLabel.Sprintf("... and %d more", remaining))
					break
				}
				fmt.Fprintf(output, "%s    - %s\n", prefix, FormatProperty(prop, r.scheme))
			}
		}
	}

	// Add spacing
	if r.config.VerboseOutput ||
		r.config.ShowDependencies ||
		r.config.ShowVulnerabilities ||
		r.config.ShowProperties {
		fmt.Fprintln(output, prefix)
	}

	// Return dependencies to expand (those with assemblies or dependencies) to be rendered after component details and assemblies
	return depsToExpand
}

// renderIslands renders disconnected component islands
func (r *TreeRenderer) renderIslands(islands [][]*EnrichedComponent, output io.Writer) {
	fmt.Fprintln(output, r.scheme.Islands.Sprint("Islands (disconnected components):"))

	for i, island := range islands {
		if len(island) == 0 {
			continue
		}

		fmt.Fprintf(output, "\n%s [Island %d] %d components\n",
			r.scheme.TreeStructure.Sprint("└─"),
			i+1,
			len(island))

		// For small islands (≤ 10 components), show all components
		// For larger islands, show based on verbose mode
		if len(island) <= 10 {
			for j, comp := range island {
				isLast := j == len(island)-1
				r.renderComponent(comp, output, "   ", isLast, 0)
			}
		} else if r.config.VerboseOutput {
			// Verbose mode - show all components in large islands
			for j, comp := range island {
				isLast := j == len(island)-1
				r.renderComponent(comp, output, "   ", isLast, 0)
			}
		} else {
			// Large island - show first few components with full details
			maxShow := 5
			for j := 0; j < maxShow && j < len(island); j++ {
				r.renderComponent(island[j], output, "   ", false, 0)
			}

			// Show remaining component names in a compact list
			if len(island) > maxShow {
				fmt.Fprintf(output, "   %s:\n",
					r.scheme.FieldLabel.Sprintf("... and %d more components", len(island)-maxShow))

				// Show up to 20 more component names in compact format
				remaining := island[maxShow:]
				compactShow := 20
				for j := 0; j < compactShow && j < len(remaining); j++ {
					comp := remaining[j]
					nameVersion := comp.Name
					if comp.Version != "" {
						nameVersion += "@" + comp.Version
					}
					fmt.Fprintf(output, "     - %s\n", nameVersion)
				}

				if len(remaining) > compactShow {
					fmt.Fprintf(output, "     %s\n",
						r.scheme.FieldLabel.Sprintf("... and %d more (use --verbose to show all)", len(remaining)-compactShow))
				}
			}
		}
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// renderGlobalAnnotations renders SBOM-level annotations - DEPRECATED (kept for compatibility)
func (r *TreeRenderer) renderGlobalAnnotations(annotations []AnnotationInfo, output io.Writer) {
	fmt.Fprintln(output, r.scheme.Annotations.Sprintf("Annotations (%d):", len(annotations)))

	for i, ann := range annotations {
		// Format annotation header
		annotatorStr := "Unknown"
		if ann.Annotator != "" {
			annotatorStr = ann.Annotator
		}

		// Format timestamp
		timestampStr := ""
		if !ann.Timestamp.IsZero() {
			timestampStr = ann.Timestamp.Format("2006-01-02 15:04:05")
		}

		fmt.Fprintf(output, "\n%s [Annotation %d]\n",
			r.scheme.TreeStructure.Sprint("├─"), i+1)

		if annotatorStr != "Unknown" {
			fmt.Fprintf(output, "│  %s: %s\n",
				r.scheme.FieldLabel.Sprint("Annotator"),
				r.scheme.Info.Sprint(annotatorStr))
		}

		if timestampStr != "" {
			fmt.Fprintf(output, "│  %s: %s\n",
				r.scheme.FieldLabel.Sprint("Timestamp"),
				r.scheme.Info.Sprint(timestampStr))
		}

		if len(ann.Subjects) > 0 {
			fmt.Fprintf(output, "│  %s:\n",
				r.scheme.FieldLabel.Sprint("Subjects"))
			for _, subject := range ann.Subjects {
				fmt.Fprintf(output, "│    - %s\n",
					r.scheme.Dependencies.Sprint(subject))
			}
		}

		fmt.Fprintf(output, "│  %s: %s\n",
			r.scheme.FieldLabel.Sprint("Text"),
			r.scheme.Info.Sprint(ann.Text))
	}
}

// renderGlobalCompositions renders SBOM-level compositions
func (r *TreeRenderer) renderGlobalCompositions(compositions []CompositionInfo, output io.Writer) {
	fmt.Fprintln(output, r.scheme.Annotations.Sprintf("Compositions (%d):", len(compositions)))

	for i, comp := range compositions {
		fmt.Fprintf(output, "\n%s [Composition %d] %s\n",
			r.scheme.TreeStructure.Sprint("├─"), i+1,
			r.scheme.Info.Sprintf("(%s)", comp.Aggregate))

		if len(comp.Assemblies) > 0 {
			fmt.Fprintf(output, "│  %s:\n",
				r.scheme.FieldLabel.Sprint("Assemblies"))
			for _, assembly := range comp.Assemblies {
				fmt.Fprintf(output, "│    - %s\n",
					r.scheme.Dependencies.Sprint(assembly))
			}
		}

		if len(comp.Dependencies) > 0 {
			fmt.Fprintf(output, "│  %s:\n",
				r.scheme.FieldLabel.Sprint("Dependencies"))
			for _, dep := range comp.Dependencies {
				fmt.Fprintf(output, "│    - %s\n",
					r.scheme.Dependencies.Sprint(dep))
			}
		}
	}
}

// FlatRenderer renders components in a flat list format
type FlatRenderer struct {
	config DisplayConfig
	scheme *ColorScheme
}

// NewFlatRenderer creates a new flat renderer
func NewFlatRenderer(config DisplayConfig) *FlatRenderer {
	var scheme *ColorScheme
	if config.NoColor {
		scheme = NoColorScheme()
	} else {
		scheme = DefaultColorScheme()
	}

	return &FlatRenderer{
		config: config,
		scheme: scheme,
	}
}

// Render renders components in flat list format
func (r *FlatRenderer) Render(graph *ComponentGraph, output io.Writer) error {
	// Write SBOM header
	header := FormatSBOMHeader(graph.Metadata, r.scheme)
	fmt.Fprintln(output, header)
	fmt.Fprintln(output)

	// Render all components
	i := 1
	for _, comp := range graph.AllNodes {
		fmt.Fprintf(output, "%s Component %d/%d:\n",
			r.scheme.ComponentName.Sprint("───"),
			i, len(graph.AllNodes))

		r.renderComponentFlat(comp, output)
		fmt.Fprintln(output)
		i++
	}

	// Render statistics
	stats := CalculateStatistics(graph)
	fmt.Fprintln(output, FormatStatistics(stats, r.scheme))

	return nil
}

// renderComponentFlat renders a component in flat format
func (r *FlatRenderer) renderComponentFlat(comp *EnrichedComponent, output io.Writer) {
	indent := "  "

	fmt.Fprintf(output, "%sName: %s\n", indent, r.scheme.ComponentName.Sprint(comp.Name))

	if comp.Version != "" {
		fmt.Fprintf(output, "%sVersion: %s\n", indent, r.scheme.Info.Sprint(comp.Version))
	}

	if comp.Type != "" {
		fmt.Fprintf(output, "%sType: %s\n", indent, r.scheme.Info.Sprint(comp.Type))
	}

	if comp.IsPrimary {
		fmt.Fprintf(output, "%sPrimary: %s\n", indent, r.scheme.Primary.Sprint("true"))
	}

	if comp.Parent != nil {
		parentName := comp.Parent.Name
		if comp.Parent.Version != "" {
			parentName += "@" + comp.Parent.Version
		}
		fmt.Fprintf(output, "%sParent: %s\n", indent, r.scheme.Info.Sprint(parentName))
	}

	if comp.PURL != "" {
		fmt.Fprintf(output, "%sPURL: %s\n", indent, FormatPURL(comp.PURL, r.scheme))
	}

	if comp.CPE != "" {
		fmt.Fprintf(output, "%sCPE: %s\n", indent, FormatCPE(comp.CPE, r.scheme))
	}

	if len(comp.Children) > 0 {
		fmt.Fprintf(output, "%sAssembly: %d components\n", indent, len(comp.Children))
	}

	if comp.DependencyCount > 0 {
		fmt.Fprintf(output, "%sDependencies: %d\n", indent, comp.DependencyCount)
	}

	if comp.VulnCount.Total > 0 {
		fmt.Fprintf(output, "%s%s\n", indent, FormatVulnerabilitySummary(comp.VulnCount, r.scheme))
	}

	if comp.IslandID > 0 {
		fmt.Fprintf(output, "%sIsland: %d\n", indent, comp.IslandID)
	}
}
