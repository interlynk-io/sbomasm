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
	"time"
)

// EnrichedComponent consolidates all component information from scattered SBOM sections
type EnrichedComponent struct {
	// Core component info
	BOMRef      string
	Type        string
	Name        string
	Version     string
	PURL        string
	CPE         string
	Description string
	Group       string
	Scope       string
	Supplier    string

	// Relationships
	Parent   *EnrichedComponent
	Children []*EnrichedComponent

	// Aggregated data
	Dependencies    []DependencyInfo
	Vulnerabilities []VulnerabilityInfo
	Compositions    []CompositionInfo
	Annotations     []AnnotationInfo
	Licenses        []LicenseInfo
	Hashes          []HashInfo
	Properties      []PropertyInfo

	// Metadata
	IslandID        int // 0 for main tree, >0 for islands
	IsPrimary       bool
	AssemblyCount   int
	DependencyCount int
	VulnCount       VulnerabilityStats
}

// DependencyInfo represents a dependency relationship
type DependencyInfo struct {
	BOMRef   string        `json:"bomRef,omitempty"`
	Name     string        `json:"name"`
	Version  string        `json:"version,omitempty"`
	Type     string        `json:"type,omitempty"`
	PURL     string        `json:"purl,omitempty"`
	Licenses []LicenseInfo `json:"licenses,omitempty"`
	Supplier string        `json:"supplier,omitempty"`
}

// VulnerabilityInfo represents a security finding
type VulnerabilityInfo struct {
	ID            string    `json:"id"`
	SourceName    string    `json:"sourceName,omitempty"`
	SourceURL     string    `json:"sourceUrl,omitempty"`
	AnalysisState string    `json:"analysisState,omitempty"`
	Severity      string    `json:"severity,omitempty"`
	Score         float64   `json:"score,omitempty"`
	Description   string    `json:"description,omitempty"`
	Published     time.Time `json:"published,omitempty"`
	Updated       time.Time `json:"updated,omitempty"`
}

// VulnerabilityStats aggregates vulnerability counts by severity
type VulnerabilityStats struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	None     int `json:"none"`
	Unknown  int `json:"unknown"`
}

// CompositionInfo describes constituent parts
type CompositionInfo struct {
	Aggregate    string   `json:"aggregate"`
	Assemblies   []string `json:"assemblies,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// AnnotationInfo represents notes about components
type AnnotationInfo struct {
	Text      string    `json:"text"`
	Annotator string    `json:"annotator,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	Subjects  []string  `json:"subjects,omitempty"`
}

// LicenseInfo represents licensing information
type LicenseInfo struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	URL        string `json:"url,omitempty"`
	Expression string `json:"expression,omitempty"`
}

// HashInfo represents a cryptographic hash
type HashInfo struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// PropertyInfo represents custom properties
type PropertyInfo struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ComponentGraph represents the hierarchical structure
type ComponentGraph struct {
	Primary   *EnrichedComponent
	RootNodes []*EnrichedComponent          // Primary + island roots
	Islands   [][]*EnrichedComponent        // Disconnected component groups
	AllNodes  map[string]*EnrichedComponent // BOMRef -> Component lookup
	DepGraph  map[string][]string           // BOMRef -> list of dependency BOMRefs
	Metadata  SBOMMetadata

	// Global SBOM-level data
	Annotations  []AnnotationInfo
	Compositions []CompositionInfo

	// Fallback lookup maps for components without bom-ref
	ByPURL        map[string]*EnrichedComponent   // PURL -> Component lookup
	ByCPE         map[string]*EnrichedComponent   // CPE -> Component lookup
	ByNameVersion map[string]*EnrichedComponent   // "name-version" -> Component lookup
	ByName        map[string][]*EnrichedComponent // name -> Components lookup (can have multiple versions)

	// Track fallback usage for warnings
	FallbackResolutions []FallbackResolution
}

// FallbackResolution tracks when fallback resolution was used
type FallbackResolution struct {
	SourceRef  string // The component that had the dependency
	TargetRef  string // The dependency reference that couldn't be resolved by bom-ref
	ResolvedBy string // How it was resolved: "purl", "cpe", "name-version", "name"
	ResolvedTo string // The component it was resolved to (bom-ref or identifier)
}

// SBOMMetadata contains high-level SBOM information
type SBOMMetadata struct {
	Format       string        `json:"format"`
	SpecVersion  string        `json:"specVersion"`
	SerialNumber string        `json:"serialNumber,omitempty"`
	Version      int           `json:"version"`
	Timestamp    time.Time     `json:"timestamp,omitempty"`
	Tools        []ToolInfo    `json:"tools,omitempty"`
	Authors      []string      `json:"authors,omitempty"`
	Supplier     string        `json:"supplier,omitempty"`
	Manufacturer string        `json:"manufacturer,omitempty"`
	Licenses     []LicenseInfo `json:"licenses,omitempty"`
}

// ToolInfo represents a tool used to create/modify the SBOM
type ToolInfo struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// DisplayConfig controls what and how to display
type DisplayConfig struct {
	// What to show
	ShowDependencies    bool
	ShowVulnerabilities bool
	ShowAnnotations     bool
	ShowCompositions    bool
	ShowProperties      bool
	ShowHashes          bool
	ShowLicenses        bool

	// Display preferences
	MaxDepth         int    // 0 = unlimited
	CollapseIslands  bool   // Hide islands by default
	VerboseOutput    bool   // Show all fields
	FilterByType     string // e.g., "library,container"
	OnlyPrimary      bool   // Only show primary component tree
	ShowOnlyLicenses bool   // Show only license information (minimal component details)

	// Vulnerability filters
	MinSeverity    string // "low", "medium", "high", "critical"
	OnlyUnresolved bool

	// Output format
	Format  string // "tree", "flat", "json"
	NoColor bool
	Output  string // File path or empty for stdout
}

// ViewOptions contains options for viewing SBOMs
type ViewOptions struct {
	Config DisplayConfig
}

// DefaultDisplayConfig returns sensible defaults
func DefaultDisplayConfig() DisplayConfig {
	return DisplayConfig{
		ShowDependencies:    true,
		ShowVulnerabilities: true,
		ShowAnnotations:     true,
		ShowCompositions:    false,
		ShowProperties:      false,
		ShowHashes:          false,
		ShowLicenses:        false,
		MaxDepth:            0,
		CollapseIslands:     false,
		VerboseOutput:       false,
		FilterByType:        "",
		OnlyPrimary:         false,
		MinSeverity:         "",
		OnlyUnresolved:      false,
		Format:              "tree",
		NoColor:             false,
		Output:              "",
	}
}

// Statistics aggregates overall SBOM stats
type Statistics struct {
	TotalComponents      int                `json:"totalComponents"`
	TotalDependencies    int                `json:"totalDependencies"`
	TotalVulnerabilities VulnerabilityStats `json:"totalVulnerabilities"`
	TotalAnnotations     int                `json:"totalAnnotations"`
	TotalCompositions    int                `json:"totalCompositions"`
	IslandCount          int                `json:"islandCount"`
	ComponentsByType     map[string]int     `json:"componentsByType"`
	MaxDepth             int                `json:"maxDepth"`
}

// JSONComponentGraph is a JSON-serializable version of ComponentGraph without circular references
type JSONComponentGraph struct {
	Primary    *JSONEnrichedComponent            `json:"primary,omitempty"`
	AllNodes   map[string]*JSONEnrichedComponent `json:"components"`
	DepGraph   map[string][]string               `json:"dependencies"`
	Islands    [][]string                        `json:"islands,omitempty"` // Array of arrays of BOMRefs
	Metadata   SBOMMetadata                      `json:"metadata"`
	Statistics Statistics                        `json:"statistics"`
}

// JSONEnrichedComponent is a JSON-serializable version without parent/children pointers
type JSONEnrichedComponent struct {
	// Core component info
	BOMRef      string `json:"bomRef"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	PURL        string `json:"purl,omitempty"`
	CPE         string `json:"cpe,omitempty"`
	Description string `json:"description,omitempty"`
	Group       string `json:"group,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Supplier    string `json:"supplier,omitempty"`

	// Relationships (as BOMRefs instead of pointers)
	ParentBOMRef string   `json:"parent,omitempty"`
	ChildBOMRefs []string `json:"children,omitempty"`

	// Aggregated data
	Dependencies    []DependencyInfo    `json:"dependencies,omitempty"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities,omitempty"`
	Compositions    []CompositionInfo   `json:"compositions,omitempty"`
	Annotations     []AnnotationInfo    `json:"annotations,omitempty"`
	Licenses        []LicenseInfo       `json:"licenses,omitempty"`
	Hashes          []HashInfo          `json:"hashes,omitempty"`
	Properties      []PropertyInfo      `json:"properties,omitempty"`

	// Metadata
	IslandID        int                `json:"islandId,omitempty"`
	IsPrimary       bool               `json:"isPrimary,omitempty"`
	AssemblyCount   int                `json:"assemblyCount,omitempty"`
	DependencyCount int                `json:"dependencyCount,omitempty"`
	VulnCount       VulnerabilityStats `json:"vulnerabilityStats,omitempty"`
}

// ToJSONComponentGraph converts a ComponentGraph to JSONComponentGraph for serialization
func ToJSONComponentGraph(graph *ComponentGraph) *JSONComponentGraph {
	jsonGraph := &JSONComponentGraph{
		AllNodes:   make(map[string]*JSONEnrichedComponent),
		DepGraph:   graph.DepGraph,
		Metadata:   graph.Metadata,
		Statistics: CalculateStatistics(graph),
	}

	// Convert all components to JSON-safe format
	for bomRef, comp := range graph.AllNodes {
		jsonGraph.AllNodes[bomRef] = toJSONEnrichedComponent(comp)
	}

	// Set primary component
	if graph.Primary != nil {
		jsonGraph.Primary = jsonGraph.AllNodes[graph.Primary.BOMRef]
	}

	// Convert islands to arrays of BOMRefs
	jsonGraph.Islands = make([][]string, len(graph.Islands))
	for i, island := range graph.Islands {
		jsonGraph.Islands[i] = make([]string, len(island))
		for j, comp := range island {
			jsonGraph.Islands[i][j] = comp.BOMRef
		}
	}

	return jsonGraph
}

// toJSONEnrichedComponent converts an EnrichedComponent to JSONEnrichedComponent
func toJSONEnrichedComponent(comp *EnrichedComponent) *JSONEnrichedComponent {
	jsonComp := &JSONEnrichedComponent{
		BOMRef:          comp.BOMRef,
		Type:            comp.Type,
		Name:            comp.Name,
		Version:         comp.Version,
		PURL:            comp.PURL,
		CPE:             comp.CPE,
		Description:     comp.Description,
		Group:           comp.Group,
		Scope:           comp.Scope,
		Supplier:        comp.Supplier,
		Dependencies:    comp.Dependencies,
		Vulnerabilities: comp.Vulnerabilities,
		Compositions:    comp.Compositions,
		Annotations:     comp.Annotations,
		Licenses:        comp.Licenses,
		Hashes:          comp.Hashes,
		Properties:      comp.Properties,
		IslandID:        comp.IslandID,
		IsPrimary:       comp.IsPrimary,
		AssemblyCount:   comp.AssemblyCount,
		DependencyCount: comp.DependencyCount,
		VulnCount:       comp.VulnCount,
	}

	// Convert parent pointer to BOMRef
	if comp.Parent != nil {
		jsonComp.ParentBOMRef = comp.Parent.BOMRef
	}

	// Convert children pointers to BOMRefs
	if len(comp.Children) > 0 {
		jsonComp.ChildBOMRefs = make([]string, len(comp.Children))
		for i, child := range comp.Children {
			jsonComp.ChildBOMRefs[i] = child.BOMRef
		}
	}

	return jsonComp
}
