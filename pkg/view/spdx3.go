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

	spdx3 "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

// SPDX3Viewer implements Viewer for SPDX 3.0 JSON-LD SBOMs
type SPDX3Viewer struct{}

// NewSPDX3Viewer creates a new SPDX 3.0 viewer
func NewSPDX3Viewer() *SPDX3Viewer {
	return &SPDX3Viewer{}
}

// ParseAndEnrich loads an SPDX 3.0 SBOM and creates enriched components
func (v *SPDX3Viewer) ParseAndEnrich(input io.Reader) (*ComponentGraph, error) {
	reader := parse.NewReader()
	doc, err := reader.FromReader(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPDX 3.0 document: %w", err)
	}

	return buildSPDX3Graph(doc)
}

// buildSPDX3Graph creates a ComponentGraph from an SPDX 3.0 parsed document
func buildSPDX3Graph(doc *parse.Document) (*ComponentGraph, error) {
	graph := &ComponentGraph{
		AllNodes:            make(map[string]*EnrichedComponent),
		DepGraph:            make(map[string][]string),
		Metadata:            extractSPDX3Metadata(doc),
		ByPURL:              make(map[string]*EnrichedComponent),
		ByCPE:               make(map[string]*EnrichedComponent),
		ByNameVersion:       make(map[string]*EnrichedComponent),
		ByName:              make(map[string][]*EnrichedComponent),
		FallbackResolutions: make([]FallbackResolution, 0),
	}

	// Build dependency graph from dependsOn relationships
	for _, rel := range doc.Relationships {
		if rel.RelationshipType == spdx3.RelationshipTypeDependsOn {
			fromID := rel.From.GetSpdxID()
			for _, to := range rel.To {
				toID := to.GetSpdxID()
				if fromID != "" && toID != "" {
					graph.DepGraph[fromID] = append(graph.DepGraph[fromID], toID)
				}
			}
		}
	}

	// Process all packages
	for _, pkg := range doc.Packages {
		enriched := enrichSPDX3Package(doc, pkg)
		if enriched.BOMRef != "" {
			graph.AllNodes[enriched.BOMRef] = enriched
		}
		addToFallbackMaps(enriched, graph)
	}

	// Process all files
	for _, file := range doc.Files {
		enriched := enrichSPDX3File(doc, file)
		if enriched.BOMRef != "" {
			graph.AllNodes[enriched.BOMRef] = enriched
		}
		addToFallbackMaps(enriched, graph)
	}

	// Build assembly tree from contains relationships
	for _, rel := range doc.Relationships {
		if rel.RelationshipType == spdx3.RelationshipTypeContains {
			fromID := rel.From.GetSpdxID()
			for _, to := range rel.To {
				toID := to.GetSpdxID()
				if fromID != "" && toID != "" {
					if parent, ok := graph.AllNodes[fromID]; ok {
						if child, ok := graph.AllNodes[toID]; ok {
							parent.Children = append(parent.Children, child)
							child.Parent = parent
							parent.AssemblyCount++
						}
					}
				}
			}
		}
	}

	// Set primary component from SpdxDocument.rootElement
	if doc.SpdxDocument != nil && len(doc.SpdxDocument.RootElement) > 0 {
		rootID := doc.SpdxDocument.RootElement[0].GetSpdxID()
		if rootID != "" {
			if primary, ok := graph.AllNodes[rootID]; ok {
				primary.IsPrimary = true
				graph.Primary = primary
			}
		}
	}

	// Link dependency counts
	for _, comp := range graph.AllNodes {
		if deps, ok := graph.DepGraph[comp.BOMRef]; ok {
			comp.DependencyCount = len(deps)
		}
	}

	return graph, nil
}

// enrichSPDX3Package creates an EnrichedComponent from an SPDX 3.0 Package
func enrichSPDX3Package(doc *parse.Document, pkg *spdx3.Package) *EnrichedComponent {
	enriched := &EnrichedComponent{
		BOMRef:      pkg.GetSpdxID(),
		Type:        string(pkg.PrimaryPurpose),
		Name:        pkg.Name,
		Version:     pkg.PackageVersion,
		Description: pkg.Description,
		Children:    make([]*EnrichedComponent, 0),
	}

	// Extract PURL from externalIdentifier
	for _, ei := range pkg.ExternalIdentifier {
		if ei.ExternalIdentifierType == spdx3.ExternalIdentifierTypePackageUrl {
			enriched.PURL = ei.Identifier
			break
		}
	}

	// Extract CPE from externalIdentifier
	for _, ei := range pkg.ExternalIdentifier {
		if ei.ExternalIdentifierType == spdx3.ExternalIdentifierTypeCpe23 ||
			ei.ExternalIdentifierType == spdx3.ExternalIdentifierTypeCpe22 {
			enriched.CPE = ei.Identifier
			break
		}
	}

	// Extract supplier
	if pkg.SuppliedBy != nil {
		supplierID := pkg.SuppliedBy.GetSpdxID()
		if supplierID != "" {
			if org := doc.GetOrganizationByID(supplierID); org != nil {
				enriched.Supplier = org.Name
			} else if person := doc.GetPersonByID(supplierID); person != nil {
				enriched.Supplier = person.Name
			}
		}
	}

	// Extract author (originatedBy → Person)
	var authorNames []string
	for _, agent := range pkg.OriginatedBy {
		agentID := agent.GetSpdxID()
		if agentID != "" {
			if person := doc.GetPersonByID(agentID); person != nil {
				authorNames = append(authorNames, person.Name)
			} else if org := doc.GetOrganizationByID(agentID); org != nil {
				authorNames = append(authorNames, org.Name)
			}
		}
	}
	if len(authorNames) > 0 {
		enriched.Group = strings.Join(authorNames, ", ")
	}

	// Extract hashes from verifiedUsing
	enriched.Hashes = extractSPDX3Hashes(pkg.VerifiedUsing)

	// Extract licenses via relationships
	licInfo := doc.GetLicensesFor(pkg.GetSpdxID())
	if licInfo != nil {
		enriched.Licenses = spdx3LicensesToLicenseInfo(licInfo)
	}

	// Extract copyright
	enriched.Scope = pkg.CopyrightText

	return enriched
}

// enrichSPDX3File creates an EnrichedComponent from an SPDX 3.0 File
func enrichSPDX3File(doc *parse.Document, file *spdx3.File) *EnrichedComponent {
	enriched := &EnrichedComponent{
		BOMRef:      file.GetSpdxID(),
		Type:        "file",
		Name:        file.Name,
		Version:     "",
		Description: "",
		Children:    make([]*EnrichedComponent, 0),
	}

	// Extract hashes from verifiedUsing
	enriched.Hashes = extractSPDX3Hashes(file.VerifiedUsing)

	// Extract licenses via relationships
	licInfo := doc.GetLicensesFor(file.GetSpdxID())
	if licInfo != nil {
		enriched.Licenses = spdx3LicensesToLicenseInfo(licInfo)
	}

	// Extract copyright
	enriched.Scope = file.CopyrightText

	return enriched
}

// extractSPDX3Hashes converts verifiedUsing entries to HashInfo slice
func extractSPDX3Hashes(verifiedUsing []interface{}) []HashInfo {
	var result []HashInfo
	for _, vu := range verifiedUsing {
		switch h := vu.(type) {
		case *spdx3.Hash:
			result = append(result, HashInfo{
				Algorithm: string(h.Algorithm),
				Value:     h.HashValue,
			})
		case spdx3.Hash:
			result = append(result, HashInfo{
				Algorithm: string(h.Algorithm),
				Value:     h.HashValue,
			})
		}
	}
	return result
}

// spdx3LicensesToLicenseInfo converts spdx-zen LicenseInfo to view LicenseInfo
func spdx3LicensesToLicenseInfo(licInfo *parse.LicenseInfo) []LicenseInfo {
	var result []LicenseInfo
	seen := make(map[string]bool)

	addLicense := func(lic *spdx3.AnyLicenseInfo) {
		if lic == nil {
			return
		}
		name := spdx3LicenseDisplayName(lic)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		result = append(result, LicenseInfo{
			ID:   lic.SpdxID,
			Name: name,
		})
	}

	for _, lic := range licInfo.ConcludedLicenses {
		addLicense(lic)
	}
	for _, lic := range licInfo.DeclaredLicenses {
		addLicense(lic)
	}

	return result
}

// spdx3LicenseDisplayName returns a human-readable display name for a license
func spdx3LicenseDisplayName(lic *spdx3.AnyLicenseInfo) string {
	if lic == nil {
		return ""
	}
	if lic.Name != "" {
		return lic.Name
	}
	return lic.SpdxID
}

// extractSPDX3Metadata extracts SBOM-level metadata from SPDX 3.0 document
func extractSPDX3Metadata(doc *parse.Document) SBOMMetadata {
	metadata := SBOMMetadata{
		Format:      "SPDX-3.0",
		SpecVersion: "3.0.1",
	}

	if doc.SpdxDocument != nil {
		metadata.SerialNumber = doc.SpdxDocument.GetSpdxID()
		metadata.Version = 1
	}

	if doc.CreationInfo != nil {
		metadata.Timestamp = doc.CreationInfo.Created
		metadata.SpecVersion = string(doc.CreationInfo.SpecVersion)

		// Extract tools from createdUsing
		for _, tool := range doc.Tools {
			if tool != nil {
				metadata.Tools = append(metadata.Tools, ToolInfo{
					Name: tool.Name,
				})
			}
		}

		// Extract authors from createdBy
		for _, agent := range doc.CreationInfo.CreatedBy {
			agentID := agent.GetSpdxID()
			if agentID == "" {
				continue
			}
			if person := doc.GetPersonByID(agentID); person != nil {
				metadata.Authors = append(metadata.Authors, person.Name)
			} else if org := doc.GetOrganizationByID(agentID); org != nil {
				metadata.Authors = append(metadata.Authors, org.Name)
				metadata.Supplier = org.Name
			}
		}
	}

	return metadata
}
