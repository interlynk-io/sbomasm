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
	"os"
	"strings"
	"time"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
)

// Viewer is the main interface for SBOM viewing functionality
type Viewer interface {
	ParseAndEnrich(input io.Reader) (*ComponentGraph, error)
	Render(graph *ComponentGraph, config DisplayConfig, output io.Writer) error
}

// CycloneDXViewer implements Viewer for CycloneDX SBOMs
type CycloneDXViewer struct{}

// NewCycloneDXViewer creates a new CycloneDX viewer
func NewCycloneDXViewer() *CycloneDXViewer {
	return &CycloneDXViewer{}
}

// ParseAndEnrich loads a CycloneDX SBOM and creates enriched components
func (v *CycloneDXViewer) ParseAndEnrich(input io.Reader) (*ComponentGraph, error) {
	return v.ParseAndEnrichWithFormat(input, cydx.BOMFileFormatJSON)
}

// ParseAndEnrichWithFormat loads a CycloneDX SBOM with specific format and creates enriched components
func (v *CycloneDXViewer) ParseAndEnrichWithFormat(input io.Reader, format cydx.BOMFileFormat) (*ComponentGraph, error) {
	// Parse the BOM
	bom := new(cydx.BOM)
	decoder := cydx.NewBOMDecoder(input, format)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("failed to decode CycloneDX BOM: %w", err)
	}

	// Create the component graph
	graph := &ComponentGraph{
		AllNodes:            make(map[string]*EnrichedComponent),
		DepGraph:            make(map[string][]string),
		Metadata:            extractMetadata(bom),
		Annotations:         extractAnnotations(bom),
		Compositions:        extractCompositions(bom),
		ByPURL:              make(map[string]*EnrichedComponent),
		ByCPE:               make(map[string]*EnrichedComponent),
		ByNameVersion:       make(map[string]*EnrichedComponent),
		ByName:              make(map[string][]*EnrichedComponent),
		FallbackResolutions: make([]FallbackResolution, 0),
	}

	// Build vulnerability lookup map
	vulnMap := buildVulnerabilityMap(bom)
	
	// Build annotation lookup map (subject -> annotations)
	annotationMap := buildAnnotationMap(bom)
	
	// Build composition lookup map (assembly/dependency -> compositions)
	compositionMap := buildCompositionMap(bom)

	// Build dependency map
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if dep.Ref != "" && dep.Dependencies != nil {
				graph.DepGraph[dep.Ref] = *dep.Dependencies
			}
		}
	}

	// Process all components first (including nested ones)
	if bom.Components != nil {
		for _, comp := range *bom.Components {
			processComponentTree(&comp, nil, graph, vulnMap, annotationMap, compositionMap, 0)
		}
	}

	// Process primary component after all others are in the graph
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		primary := enrichComponent(bom.Metadata.Component, nil, vulnMap, annotationMap, compositionMap, graph.DepGraph, 0)
		primary.IsPrimary = true
		graph.Primary = primary
		if primary.BOMRef != "" {
			graph.AllNodes[primary.BOMRef] = primary
		} else if primary.Name != "" {
			graph.AllNodes[primary.Name] = primary
		}
		addToFallbackMaps(primary, graph)

		// NOTE: DO NOT link dependencies as children here!
		// Dependencies are logical relationships, not assembly (parent-child) relationships
		// Assembly relationships are built from components->components nesting in processComponentTree
	}

	return graph, nil
}

// processComponentTree recursively processes components and their children
func processComponentTree(comp *cydx.Component, parent *EnrichedComponent, graph *ComponentGraph, vulnMap map[string][]VulnerabilityInfo, annotationMap map[string][]AnnotationInfo, compositionMap map[string][]CompositionInfo, depth int) *EnrichedComponent {
	enriched := enrichComponent(comp, parent, vulnMap, annotationMap, compositionMap, graph.DepGraph, depth)

	// Add to primary lookup map
	// Use BOMRef if available, otherwise use name
	// AllNodes needs all components for statistics and iteration
	if enriched.BOMRef != "" {
		graph.AllNodes[enriched.BOMRef] = enriched
	} else if enriched.Name != "" {
		graph.AllNodes[enriched.Name] = enriched
	}

	// Always add to fallback lookup maps
	addToFallbackMaps(enriched, graph)

	// Link to parent
	if parent != nil {
		parent.Children = append(parent.Children, enriched)
		parent.AssemblyCount++
	}

	// Process nested components (assemblies)
	if comp.Components != nil {
		for i := range *comp.Components {
			child := (*comp.Components)[i]
			processComponentTree(&child, enriched, graph, vulnMap, annotationMap, compositionMap, depth+1)
		}
	}

	return enriched
}

// addToFallbackMaps adds a component to all applicable fallback lookup maps
func addToFallbackMaps(comp *EnrichedComponent, graph *ComponentGraph) {
	// Add by PURL
	if comp.PURL != "" {
		graph.ByPURL[comp.PURL] = comp
	}

	// Add by CPE
	if comp.CPE != "" {
		graph.ByCPE[comp.CPE] = comp
	}

	// Add by name-version
	if comp.Name != "" {
		nameVersion := comp.Name
		if comp.Version != "" {
			nameVersion = comp.Name + "-" + comp.Version
		}
		graph.ByNameVersion[nameVersion] = comp
	}

	// Add by name (can have multiple components with same name)
	if comp.Name != "" {
		graph.ByName[comp.Name] = append(graph.ByName[comp.Name], comp)
	}
}

// enrichComponent creates an EnrichedComponent from a CycloneDX component
func enrichComponent(comp *cydx.Component, parent *EnrichedComponent, vulnMap map[string][]VulnerabilityInfo, annotationMap map[string][]AnnotationInfo, compositionMap map[string][]CompositionInfo, depGraph map[string][]string, depth int) *EnrichedComponent {
	enriched := &EnrichedComponent{
		BOMRef:      comp.BOMRef,
		Type:        string(comp.Type),
		Name:        comp.Name,
		Version:     comp.Version,
		Description: comp.Description,
		Parent:      parent,
		Children:    make([]*EnrichedComponent, 0),
	}

	// Extract PURL
	if comp.PackageURL != "" {
		enriched.PURL = comp.PackageURL
	}

	// Extract CPE
	if comp.CPE != "" {
		enriched.CPE = comp.CPE
	}

	// Extract group
	if comp.Group != "" {
		enriched.Group = comp.Group
	}

	// Extract scope
	if comp.Scope != "" {
		enriched.Scope = string(comp.Scope)
	}

	// Extract supplier
	if comp.Supplier != nil && comp.Supplier.Name != "" {
		enriched.Supplier = comp.Supplier.Name
	}

	// Extract licenses
	if comp.Licenses != nil {
		enriched.Licenses = extractLicenses(comp.Licenses)
	}

	// Extract hashes
	if comp.Hashes != nil {
		enriched.Hashes = extractHashes(comp.Hashes)
	}

	// Extract properties
	if comp.Properties != nil {
		enriched.Properties = extractProperties(comp.Properties)
	}

	// Find vulnerabilities affecting this component
	if vulns, ok := vulnMap[comp.BOMRef]; ok {
		enriched.Vulnerabilities = vulns
		enriched.VulnCount = aggregateVulnStats(vulns)
	}
	
	// Attach annotations for this component
	if anns, ok := annotationMap[comp.BOMRef]; ok {
		enriched.Annotations = anns
	}
	
	// Attach compositions where this component is referenced
	if comps, ok := compositionMap[comp.BOMRef]; ok {
		enriched.Compositions = comps
	}

	// Find dependencies - check both BOMRef and Name
	depKey := comp.BOMRef
	if depKey == "" {
		depKey = comp.Name
	}
	if deps, ok := depGraph[depKey]; ok {
		enriched.DependencyCount = len(deps)
		// Note: Dependency details will be filled in by graph builder
	}

	return enriched
}

// buildAnnotationMap creates a map of subject BOMRef -> annotations
func buildAnnotationMap(bom *cydx.BOM) map[string][]AnnotationInfo {
	annMap := make(map[string][]AnnotationInfo)
	
	if bom.Annotations == nil {
		return annMap
	}
	
	for _, ann := range *bom.Annotations {
		info := AnnotationInfo{
			Text: ann.Text,
		}
		
		// Extract annotator information
		if ann.Annotator != nil {
			annotatorStr := ""
			if ann.Annotator.Organization != nil && ann.Annotator.Organization.Name != "" {
				annotatorStr = ann.Annotator.Organization.Name
			}
			if ann.Annotator.Individual != nil && ann.Annotator.Individual.Name != "" {
				if annotatorStr != "" {
					annotatorStr += " / "
				}
				annotatorStr += ann.Annotator.Individual.Name
			}
			if ann.Annotator.Component != nil && ann.Annotator.Component.Name != "" {
				if annotatorStr != "" {
					annotatorStr += " / "
				}
				annotatorStr += ann.Annotator.Component.Name
			}
			info.Annotator = annotatorStr
		}
		
		// Extract timestamp
		if ann.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339, ann.Timestamp); err == nil {
				info.Timestamp = t
			}
		}
		
		// Map to each subject
		if ann.Subjects != nil {
			for _, subj := range *ann.Subjects {
				subjRef := string(subj)
				annMap[subjRef] = append(annMap[subjRef], info)
			}
		}
	}
	
	return annMap
}

// buildCompositionMap creates a map of component BOMRef -> compositions
func buildCompositionMap(bom *cydx.BOM) map[string][]CompositionInfo {
	compMap := make(map[string][]CompositionInfo)
	
	if bom.Compositions == nil {
		return compMap
	}
	
	for _, comp := range *bom.Compositions {
		info := CompositionInfo{
			Aggregate: string(comp.Aggregate),
		}
		
		// Extract assemblies and dependencies as strings
		if comp.Assemblies != nil {
			for _, asm := range *comp.Assemblies {
				info.Assemblies = append(info.Assemblies, string(asm))
			}
		}
		if comp.Dependencies != nil {
			for _, dep := range *comp.Dependencies {
				info.Dependencies = append(info.Dependencies, string(dep))
			}
		}
		
		// Map composition to each assembly
		if comp.Assemblies != nil {
			for _, asm := range *comp.Assemblies {
				asmRef := string(asm)
				compMap[asmRef] = append(compMap[asmRef], info)
			}
		}
		
		// Also map to dependencies if needed
		// (This depends on how you want compositions displayed)
	}
	
	return compMap
}

// buildVulnerabilityMap creates a map of component BOMRef -> vulnerabilities
func buildVulnerabilityMap(bom *cydx.BOM) map[string][]VulnerabilityInfo {
	vulnMap := make(map[string][]VulnerabilityInfo)

	if bom.Vulnerabilities == nil {
		return vulnMap
	}

	for _, vuln := range *bom.Vulnerabilities {
		vulnInfo := VulnerabilityInfo{
			ID: vuln.ID,
		}

		// Extract source
		if vuln.Source != nil {
			vulnInfo.SourceName = vuln.Source.Name
			if vuln.Source.URL != "" {
				vulnInfo.SourceURL = vuln.Source.URL
			}
		}

		// Extract analysis state
		if vuln.Analysis != nil && vuln.Analysis.State != "" {
			vulnInfo.AnalysisState = string(vuln.Analysis.State)
		}

		// Extract ratings (use highest severity)
		if vuln.Ratings != nil {
			var maxScore float64
			for _, rating := range *vuln.Ratings {
				if rating.Severity != "" {
					vulnInfo.Severity = string(rating.Severity)
				}
				if rating.Score != nil && *rating.Score > maxScore {
					maxScore = *rating.Score
					vulnInfo.Score = maxScore
				}
			}
		}

		// Extract description
		if vuln.Description != "" {
			vulnInfo.Description = vuln.Description
		}

		// Extract timestamps
		if vuln.Published != "" {
			if t, err := time.Parse(time.RFC3339, vuln.Published); err == nil {
				vulnInfo.Published = t
			}
		}
		if vuln.Updated != "" {
			if t, err := time.Parse(time.RFC3339, vuln.Updated); err == nil {
				vulnInfo.Updated = t
			}
		}

		// Map to affected components
		if vuln.Affects != nil {
			for _, affect := range *vuln.Affects {
				if affect.Ref != "" {
					vulnMap[affect.Ref] = append(vulnMap[affect.Ref], vulnInfo)
				}
			}
		}
	}

	return vulnMap
}

// extractMetadata extracts SBOM-level metadata
func extractMetadata(bom *cydx.BOM) SBOMMetadata {
	metadata := SBOMMetadata{
		Format:      string(bom.BOMFormat),
		SpecVersion: specVersionToString(bom.SpecVersion),
	}

	if bom.SerialNumber != "" {
		metadata.SerialNumber = bom.SerialNumber
	}

	metadata.Version = bom.Version

	if bom.Metadata != nil {
		// Extract timestamp
		if bom.Metadata.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp); err == nil {
				metadata.Timestamp = t
			}
		}

		// Extract tools
		if bom.Metadata.Tools != nil && bom.Metadata.Tools.Tools != nil {
			for _, tool := range *bom.Metadata.Tools.Tools {
				metadata.Tools = append(metadata.Tools, ToolInfo{
					Vendor:  tool.Vendor,
					Name:    tool.Name,
					Version: tool.Version,
				})
			}
		}

		// Extract authors
		if bom.Metadata.Authors != nil {
			for _, author := range *bom.Metadata.Authors {
				if author.Name != "" {
					metadata.Authors = append(metadata.Authors, author.Name)
				}
			}
		}

		// Extract supplier
		if bom.Metadata.Supplier != nil && bom.Metadata.Supplier.Name != "" {
			metadata.Supplier = bom.Metadata.Supplier.Name
		}

		// Extract manufacturer
		if bom.Metadata.Manufacture != nil && bom.Metadata.Manufacture.Name != "" {
			metadata.Manufacturer = bom.Metadata.Manufacture.Name
		}

		// Extract licenses
		if bom.Metadata.Licenses != nil {
			metadata.Licenses = extractLicenses(bom.Metadata.Licenses)
		}
	}

	return metadata
}

// extractLicenses extracts license information
func extractLicenses(licenses *cydx.Licenses) []LicenseInfo {
	var result []LicenseInfo

	if licenses == nil {
		return result
	}

	for _, choice := range *licenses {
		var lic LicenseInfo

		if choice.License != nil {
			lic.ID = choice.License.ID
			lic.Name = choice.License.Name
			if choice.License.URL != "" {
				lic.URL = choice.License.URL
			}
		}

		if choice.Expression != "" {
			lic.Expression = choice.Expression
		}

		if lic.ID != "" || lic.Name != "" || lic.Expression != "" {
			result = append(result, lic)
		}
	}

	return result
}

// extractHashes extracts hash information
func extractHashes(hashes *[]cydx.Hash) []HashInfo {
	var result []HashInfo

	if hashes == nil {
		return result
	}

	for _, hash := range *hashes {
		result = append(result, HashInfo{
			Algorithm: string(hash.Algorithm),
			Value:     hash.Value,
		})
	}

	return result
}

// extractProperties extracts custom properties
func extractProperties(props *[]cydx.Property) []PropertyInfo {
	var result []PropertyInfo

	if props == nil {
		return result
	}

	for _, prop := range *props {
		result = append(result, PropertyInfo{
			Name:  prop.Name,
			Value: prop.Value,
		})
	}

	return result
}

// extractAnnotations extracts annotation information from the BOM
func extractAnnotations(bom *cydx.BOM) []AnnotationInfo {
	var result []AnnotationInfo

	if bom.Annotations == nil {
		return result
	}

	for _, ann := range *bom.Annotations {
		info := AnnotationInfo{
			Text: ann.Text,
		}

		// Extract annotator information
		if ann.Annotator != nil {
			annotatorStr := ""
			if ann.Annotator.Organization != nil && ann.Annotator.Organization.Name != "" {
				annotatorStr = ann.Annotator.Organization.Name
			}
			if ann.Annotator.Individual != nil && ann.Annotator.Individual.Name != "" {
				if annotatorStr != "" {
					annotatorStr += " / "
				}
				annotatorStr += ann.Annotator.Individual.Name
			}
			if ann.Annotator.Component != nil && ann.Annotator.Component.Name != "" {
				if annotatorStr != "" {
					annotatorStr += " / "
				}
				annotatorStr += ann.Annotator.Component.Name
			}
			info.Annotator = annotatorStr
		}

		// Extract timestamp
		if ann.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339, ann.Timestamp); err == nil {
				info.Timestamp = t
			}
		}

		// Extract subjects
		if ann.Subjects != nil {
			for _, subj := range *ann.Subjects {
				info.Subjects = append(info.Subjects, string(subj))
			}
		}

		result = append(result, info)
	}

	return result
}

// extractCompositions extracts composition information from the BOM
func extractCompositions(bom *cydx.BOM) []CompositionInfo {
	var result []CompositionInfo

	if bom.Compositions == nil {
		return result
	}

	for _, comp := range *bom.Compositions {
		info := CompositionInfo{
			Aggregate: string(comp.Aggregate),
		}

		// Extract assemblies
		if comp.Assemblies != nil {
			for _, asm := range *comp.Assemblies {
				info.Assemblies = append(info.Assemblies, string(asm))
			}
		}

		// Extract dependencies
		if comp.Dependencies != nil {
			for _, dep := range *comp.Dependencies {
				info.Dependencies = append(info.Dependencies, string(dep))
			}
		}

		result = append(result, info)
	}

	return result
}

// aggregateVulnStats aggregates vulnerability counts by severity
func aggregateVulnStats(vulns []VulnerabilityInfo) VulnerabilityStats {
	stats := VulnerabilityStats{
		Total: len(vulns),
	}

	for _, vuln := range vulns {
		switch strings.ToLower(vuln.Severity) {
		case "critical":
			stats.Critical++
		case "high":
			stats.High++
		case "medium":
			stats.Medium++
		case "low":
			stats.Low++
		case "none":
			stats.None++
		default:
			stats.Unknown++
		}
	}

	return stats
}

// specVersionToString converts a CycloneDX SpecVersion to a string
func specVersionToString(sv cydx.SpecVersion) string {
	switch sv {
	case cydx.SpecVersion1_0:
		return "1.0"
	case cydx.SpecVersion1_1:
		return "1.1"
	case cydx.SpecVersion1_2:
		return "1.2"
	case cydx.SpecVersion1_3:
		return "1.3"
	case cydx.SpecVersion1_4:
		return "1.4"
	case cydx.SpecVersion1_5:
		return "1.5"
	case cydx.SpecVersion1_6:
		return "1.6"
	default:
		return fmt.Sprintf("%d", sv)
	}
}

// LoadSBOM loads an SBOM from a file path
func LoadSBOM(path string) (*ComponentGraph, error) {
	// Detect the SBOM format
	spec, format, err := sbom.DetectSbom(path)
	if err != nil {
		return nil, fmt.Errorf("failed to detect SBOM format: %w", err)
	}

	// Only support CycloneDX
	if spec != sbom.SBOMSpecCDX {
		return nil, fmt.Errorf("unsupported SBOM spec: %s (only CycloneDX is supported)", spec)
	}

	// Open the file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Determine CycloneDX format
	var cdxFormat cydx.BOMFileFormat
	switch format {
	case sbom.FileFormatJSON:
		cdxFormat = cydx.BOMFileFormatJSON
	case sbom.FileFormatXML:
		cdxFormat = cydx.BOMFileFormatXML
	default:
		return nil, fmt.Errorf("unsupported CycloneDX format: %s", format)
	}

	viewer := NewCycloneDXViewer()
	return viewer.ParseAndEnrichWithFormat(file, cdxFormat)
}
