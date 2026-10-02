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

package spdx3

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	spdx3model "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

type merge struct {
	settings      *MergeSettings
	out           *parse.Document
	in            []*parse.Document
	rootPackageID string
}

func newMerge(ms *MergeSettings) *merge {
	return &merge{
		settings:      ms,
		in:            []*parse.Document{},
		out:           &parse.Document{},
		rootPackageID: uuid.New().String(),
	}
}

func (m *merge) loadBoms() {
	for _, path := range m.settings.Input.Files {
		bom, err := loadBom(*m.settings.Ctx, path)
		if err != nil {
			panic(err) // TODO: return error instead of panic
		}
		m.in = append(m.in, bom)
	}
}

func (m *merge) combinedMerge() error {
	log := logger.FromContext(*m.settings.Ctx)
	log.Debugf("starting SPDX 3.0 merge with settings: %v", m.settings)

	var doc *parse.Document
	var ci *spdx3model.CreationInfo
	var primaryPkg *spdx3model.Package
	var err error

	isPrimaryMode := m.settings.Assemble.IsAssemblyMergeWithPrimary || m.settings.Assemble.IsFlatMergeWithPrimary

	if isPrimaryMode {
		return m.mergeWithPrimary()
	}

	// --- Non-primary mode ---
	doc, err = genSpdxDocumentMetadata(m)
	if err != nil {
		return err
	}

	log.Debugf("generated SPDX 3.0 document: %s", doc.SpdxDocument.Name)

	ci, err = genCreationInfo(m)
	if err != nil {
		return err
	}

	// Assign CreationInfo to the SpdxDocument element
	if doc.SpdxDocument != nil {
		doc.SpdxDocument.CreationInfo = *ci
	}
	doc.CreationInfo = ci

	log.Debugf("generated creation info with %d creators, created at %s", len(ci.CreatedBy), ci.Created.Format(time.RFC3339))

	primaryPkg, err = genPrimaryPackage(m)
	if err != nil {
		return err
	}
	primaryPkg.CreationInfo = *ci

	log.Debugf("generated primary package: %s, version: %s", primaryPkg.Name, primaryPkg.PackageVersion)

	// Merge all elements from input documents
	mergedPkgs, pkgMapper, err := genPackageList(m)
	if err != nil {
		return err
	}

	mergedFiles, fileMapper, err := genFileList(m)
	if err != nil {
		return err
	}

	mergedRels, err := genRelationshipList(m, pkgMapper, fileMapper)
	if err != nil {
		return err
	}

	mergedAgents, agentMapper, err := genAgentList(m)
	if err != nil {
		return err
	}

	// Build the output document
	doc.Packages = append([]*spdx3model.Package{primaryPkg}, mergedPkgs...)
	doc.Files = mergedFiles
	doc.Relationships = mergedRels
	doc.Organizations = mergedAgents.Organizations
	doc.Persons = mergedAgents.Persons
	doc.Tools = mergedAgents.Tools

	// Fix stale agent references after deduplication/rewriting
	fixStaleAgentRefs(doc, agentMapper)

	// Add top-level relationships
	topLevelRels := []*spdx3model.Relationship{}

	// Always add DESCRIBES relationship between document and primary package
	topLevelRels = append(topLevelRels, &spdx3model.Relationship{
		Element: spdx3model.Element{
			SpdxID:       fmt.Sprintf("https://interlynk.io/relationship/describes-%s", uuid.New().String()),
			Name:         "describes relationship",
			CreationInfo: *ci,
		},
		From:             spdx3model.Element{SpdxID: doc.SpdxDocument.SpdxID},
		To:               []spdx3model.Element{{SpdxID: primaryPkg.SpdxID}},
		RelationshipType: spdx3model.RelationshipTypeDescribes,
	})

	// Get described packages (primary packages from each input SBOM)
	describedPkgs := getDescribedPkgs(m)

	if m.settings.Assemble.FlatMerge {
		log.Debugf("flat merge is applied")

		// Add DEPENDS_ON from root to each input SBOM's primary component
		for _, dp := range describedPkgs {
			currentPkgID := pkgMapper[dp]
			topLevelRels = append(topLevelRels, &spdx3model.Relationship{
				Element: spdx3model.Element{
					SpdxID:       fmt.Sprintf("https://interlynk.io/relationship/depends-on-%s", uuid.New().String()),
					Name:         "depends_on relationship",
					CreationInfo: *ci,
				},
				From:             spdx3model.Element{SpdxID: primaryPkg.SpdxID},
				To:               []spdx3model.Element{{SpdxID: currentPkgID}},
				RelationshipType: spdx3model.RelationshipTypeDependsOn,
			})
		}
	} else if m.settings.Assemble.AssemblyMerge {
		log.Debugf("assembly merge is applied")

		// Add CONTAINS from root to each input SBOM's primary component
		for _, dp := range describedPkgs {
			currentPkgID := pkgMapper[dp]
			topLevelRels = append(topLevelRels, &spdx3model.Relationship{
				Element: spdx3model.Element{
					SpdxID:       fmt.Sprintf("https://interlynk.io/relationship/contains-%s", uuid.New().String()),
					Name:         "contains relationship",
					CreationInfo: *ci,
				},
				From:             spdx3model.Element{SpdxID: primaryPkg.SpdxID},
				To:               []spdx3model.Element{{SpdxID: currentPkgID}},
				RelationshipType: spdx3model.RelationshipTypeContains,
			})
		}
	} else {
		log.Debugf("hierarchical merge is applied")

		// Add DEPENDS_ON from root to each input SBOM's primary component
		for _, dp := range describedPkgs {
			currentPkgID := pkgMapper[dp]
			topLevelRels = append(topLevelRels, &spdx3model.Relationship{
				Element: spdx3model.Element{
					SpdxID:       fmt.Sprintf("https://interlynk.io/relationship/depends-on-%s", uuid.New().String()),
					Name:         "depends_on relationship",
					CreationInfo: *ci,
				},
				From:             spdx3model.Element{SpdxID: primaryPkg.SpdxID},
				To:               []spdx3model.Element{{SpdxID: currentPkgID}},
				RelationshipType: spdx3model.RelationshipTypeDependsOn,
			})
		}

		// Add nested hierarchy via CONTAINS for primary → non-primary packages
		hierarchicalContains := genHierarchicalContains(m, pkgMapper, ci)
		if len(hierarchicalContains) > 0 {
			topLevelRels = append(topLevelRels, hierarchicalContains...)
		}
	}

	// Add top-level relationships to document
	doc.Relationships = append(doc.Relationships, topLevelRels...)

	// Set root element
	if doc.SpdxDocument != nil {
		doc.SpdxDocument.RootElement = []spdx3model.Element{{SpdxID: primaryPkg.SpdxID}}
	}

	// Build indexes
	buildIndexes(doc)

	// Write the SBOM
	m.out = doc
	err = writeSBOM(doc, m)
	return err
}

// mergeWithPrimary handles flat-merge-with-primary and assembly-merge-with-primary.
func (m *merge) mergeWithPrimary() error {
	log := logger.FromContext(*m.settings.Ctx)
	log.Debugf("starting SPDX 3.0 merge with primary")

	primaryIdx, secondaryIdxs := findPrimaryAndSecondaryIndices(len(m.in))
	primaryDoc := m.in[primaryIdx]

	// Initialize document metadata from primary SBOM
	doc, err := initOutDocFromPrimarySBOM(m, primaryDoc)
	if err != nil {
		return err
	}

	// Initialize creation info from primary SBOM
	ci, err := initCreationInfoFromPrimarySBOM(m, primaryDoc)
	if err != nil {
		return err
	}
	if doc.SpdxDocument != nil {
		doc.SpdxDocument.CreationInfo = *ci
	}
	doc.CreationInfo = ci

	// Extract primary package from primary SBOM (via RootElement)
	primaryPkg, err := extractPrimaryPackage(primaryDoc)
	if err != nil {
		return err
	}
	primaryPkg.CreationInfo = *ci

	// Assign root package ID for consistent referencing
	primaryPkg.SpdxID = fmt.Sprintf("https://interlynk.io/package/root-%s", m.rootPackageID)

	log.Debugf("using primary package from primary SBOM: %s, version: %s", primaryPkg.Name, primaryPkg.PackageVersion)

	// Get secondary SBOMs' described packages for relationship generation
	secondaryDescribedPkgs := getSecondaryDescribedPkgs(m.in, secondaryIdxs)

	// Build root package info for genPackageList
	rootPkgInfo := &rootPackageInfo{
		DocSpdxID: primaryDoc.SpdxDocument.SpdxID,
		SpdxID:    getRootElementPkgID(primaryDoc),
	}

	// Merge packages
	pkgs, pkgMapper, err := genPackageListWithRoot(m, rootPkgInfo)
	if err != nil {
		return err
	}

	// Filter out the root package from pkgs since it's added separately as primaryPkg
	var filteredPkgs []*spdx3model.Package
	rootPkgIDStr := primaryPkg.SpdxID
	for _, pkg := range pkgs {
		if pkg.SpdxID != rootPkgIDStr {
			filteredPkgs = append(filteredPkgs, pkg)
		}
	}
	pkgs = filteredPkgs

	// Merge files
	files, fileMapper, err := genFileList(m)
	if err != nil {
		return err
	}

	// Merge relationships
	rels, err := genRelationshipList(m, pkgMapper, fileMapper)
	if err != nil {
		return err
	}

	// Merge agents
	mergedAgents, agentMapper, err := genAgentList(m)
	if err != nil {
		return err
	}

	// Build output document
	doc.Packages = append([]*spdx3model.Package{primaryPkg}, pkgs...)
	doc.Files = files
	doc.Relationships = rels
	doc.Organizations = mergedAgents.Organizations
	doc.Persons = mergedAgents.Persons
	doc.Tools = mergedAgents.Tools

	// Fix stale agent references after deduplication/rewriting
	fixStaleAgentRefs(doc, agentMapper)

	topLevelRels := []*spdx3model.Relationship{}

	// Always add DESCRIBES relationship between document and primary package
	topLevelRels = append(topLevelRels, &spdx3model.Relationship{
		Element: spdx3model.Element{
			SpdxID:       fmt.Sprintf("https://interlynk.io/relationship/describes-%s", uuid.New().String()),
			Name:         "describes relationship",
			CreationInfo: *ci,
		},
		From:             spdx3model.Element{SpdxID: doc.SpdxDocument.SpdxID},
		To:               []spdx3model.Element{{SpdxID: primaryPkg.SpdxID}},
		RelationshipType: spdx3model.RelationshipTypeDescribes,
	})

	if m.settings.Assemble.IsFlatMergeWithPrimary {
		log.Debugf("flat merge with primary is applied")

		// Add DEPENDS_ON from root to each secondary SBOM's primary component
		for _, dp := range secondaryDescribedPkgs {
			currentPkgID := pkgMapper[dp]

			// Skip self-reference
			if currentPkgID == primaryPkg.SpdxID {
				continue
			}

			topLevelRels = append(topLevelRels, &spdx3model.Relationship{
				Element: spdx3model.Element{
					SpdxID:       fmt.Sprintf("https://interlynk.io/relationship/depends-on-%s", uuid.New().String()),
					Name:         "depends_on relationship",
					CreationInfo: *ci,
				},
				From:             spdx3model.Element{SpdxID: primaryPkg.SpdxID},
				To:               []spdx3model.Element{{SpdxID: currentPkgID}},
				RelationshipType: spdx3model.RelationshipTypeDependsOn,
			})
		}
	} else if m.settings.Assemble.IsAssemblyMergeWithPrimary {
		log.Debugf("assembly merge with primary is applied")

		// Add CONTAINS from root to each secondary SBOM's primary component
		for _, dp := range secondaryDescribedPkgs {
			currentPkgID := pkgMapper[dp]

			// Skip self-reference
			if currentPkgID == primaryPkg.SpdxID {
				continue
			}

			topLevelRels = append(topLevelRels, &spdx3model.Relationship{
				Element: spdx3model.Element{
					SpdxID:       fmt.Sprintf("https://interlynk.io/relationship/contains-%s", uuid.New().String()),
					Name:         "contains relationship",
					CreationInfo: *ci,
				},
				From:             spdx3model.Element{SpdxID: primaryPkg.SpdxID},
				To:               []spdx3model.Element{{SpdxID: currentPkgID}},
				RelationshipType: spdx3model.RelationshipTypeContains,
			})
		}
	}

	// Add relationships to document
	doc.Relationships = append(doc.Relationships, topLevelRels...)

	// Set root element
	if doc.SpdxDocument != nil {
		doc.SpdxDocument.RootElement = []spdx3model.Element{{SpdxID: primaryPkg.SpdxID}}
	}

	// Build indexes
	buildIndexes(doc)

	// Write the SBOM
	m.out = doc
	err = writeSBOM(doc, m)
	return err
}

// agentCollection holds merged agents from all input documents.
type agentCollection struct {
	Organizations []*spdx3model.Organization
	Persons       []*spdx3model.Person
	Tools         []*spdx3model.Tool
}

// buildIndexes rebuilds all lookup maps for the output document.
func buildIndexes(doc *parse.Document) {
	doc.PackagesByID = make(map[string]*spdx3model.Package)
	for _, pkg := range doc.Packages {
		if pkg != nil && pkg.SpdxID != "" {
			doc.PackagesByID[pkg.SpdxID] = pkg
		}
	}

	doc.FilesByID = make(map[string]*spdx3model.File)
	for _, file := range doc.Files {
		if file != nil && file.SpdxID != "" {
			doc.FilesByID[file.SpdxID] = file
		}
	}

	doc.OrganizationsByID = make(map[string]*spdx3model.Organization)
	for _, org := range doc.Organizations {
		if org != nil && org.SpdxID != "" {
			doc.OrganizationsByID[org.SpdxID] = org
		}
	}

	doc.PersonsByID = make(map[string]*spdx3model.Person)
	for _, person := range doc.Persons {
		if person != nil && person.SpdxID != "" {
			doc.PersonsByID[person.SpdxID] = person
		}
	}

	doc.ToolsByID = make(map[string]*spdx3model.Tool)
	for _, tool := range doc.Tools {
		if tool != nil && tool.SpdxID != "" {
			doc.ToolsByID[tool.SpdxID] = tool
		}
	}

	doc.RelationshipsFromIndex = make(map[string][]*spdx3model.Relationship)
	doc.RelationshipsToIndex = make(map[string][]*spdx3model.Relationship)
	for _, rel := range doc.Relationships {
		if rel != nil {
			fromID := rel.From.SpdxID
			doc.RelationshipsFromIndex[fromID] = append(doc.RelationshipsFromIndex[fromID], rel)
			for _, to := range rel.To {
				doc.RelationshipsToIndex[to.SpdxID] = append(doc.RelationshipsToIndex[to.SpdxID], rel)
			}
		}
	}
}
