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

package spdx

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

type merge struct {
	settings      *MergeSettings
	out           *spdx.Document
	in            []*spdx.Document
	rootPackageID string
}

func newMerge(ms *MergeSettings) *merge {
	return &merge{
		settings:      ms,
		in:            []*spdx.Document{},
		out:           &spdx.Document{},
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
	log.Debugf("starting merge with settings: %v", m.settings)

	var doc *spdx.Document
	var ci *spdx.CreationInfo
	var primaryPkg *spdx.Package
	var err error
	var rootPkgInfo *rootPackageInfo

	isPrimaryMode := m.settings.Assemble.IsAssemblyMergeWithPrimary || m.settings.Assemble.IsFlatMergeWithPrimary

	if isPrimaryMode {
		primaryIdx, secondaryIdxs := findPrimaryAndSecondarySBOMIndices(len(m.in))
		primaryDoc := m.in[primaryIdx]

		// Initialize document metadata from primary SBOM
		doc, err = initOutDocFromPrimarySBOM(m, primaryDoc)
		if err != nil {
			return err
		}

		// Initialize creation info from primary SBOM
		ci, err = initCreationInfoFromPrimarySBOM(m, primaryDoc)
		if err != nil {
			return err
		}

		// Extract primary package from primary SBOM(via DESCRIBE)
		primaryPkg, err = extractPrimaryPackage(primaryDoc)
		if err != nil {
			return err
		}

		// Assign root package ID for consistent referencing
		primaryPkg.PackageSPDXIdentifier = common.ElementID(fmt.Sprintf("RootPackage-%s", m.rootPackageID))

		// Build root package info so genPackageList can assign the root ID to the primary package
		rootPkgInfo = &rootPackageInfo{
			DocNamespace: primaryDoc.DocumentNamespace,
			SPDXID:       string(getDescribedPkgID(primaryDoc)),
		}

		log.Debugf("using primary package from primary SBOM: %s, version: %s", primaryPkg.PackageName, primaryPkg.PackageVersion)

		// Get secondary SBOMs' described packages for relationship generation
		secondaryDescribedPkgs := getSecondaryDescribedPkgs(m.in, secondaryIdxs)

		doc.CreationInfo = ci

		doc.ExternalDocumentReferences = append(doc.ExternalDocumentReferences, externalDocumentRefs(m.in)...)

		log.Debugf("added %d external document references", len(doc.ExternalDocumentReferences))

		pkgs, pkgMapper, err := genPackageList(m, rootPkgInfo)
		if err != nil {
			return err
		}

		// Filter out the root package from pkgs since it's added separately as primaryPkg
		var filteredPkgs []*spdx.Package
		rootPkgIDStr := string(primaryPkg.PackageSPDXIdentifier)
		for _, pkg := range pkgs {
			if string(pkg.PackageSPDXIdentifier) != rootPkgIDStr {
				filteredPkgs = append(filteredPkgs, pkg)
			}
		}
		pkgs = filteredPkgs

		files, fileMapper, err := genFileList(m)
		if err != nil {
			return err
		}

		rels, err := genRelationships(m, pkgMapper, fileMapper)
		if err != nil {
			return err
		}

		otherLicenses := genOtherLicenses(m.in)

		// Add Packages to document
		doc.Packages = append(doc.Packages, primaryPkg)
		doc.Packages = append(doc.Packages, pkgs...)

		// Add Files to document
		doc.Files = append(doc.Files, files...)

		// Add OtherLicenses to document
		doc.OtherLicenses = append(doc.OtherLicenses, otherLicenses...)

		topLevelRels := []*spdx.Relationship{}

		// Always add DESCRIBES relationship between document and primary package
		topLevelRels = append(topLevelRels, &spdx.Relationship{
			RefA:                common.MakeDocElementID("", "DOCUMENT"),
			RefB:                common.MakeDocElementID("", string(primaryPkg.PackageSPDXIdentifier)),
			Relationship:        common.TypeRelationshipDescribe,
			RelationshipComment: "sbomasm created primary component relationship",
		})

		if m.settings.Assemble.IsFlatMergeWithPrimary {
			log.Debugf("flat merge with primary is applied")

			// Add DEPENDS_ON from root to each secondary SBOM's primary component
			for _, dp := range secondaryDescribedPkgs {
				currentPkgId := pkgMapper[dp]

				// Skip self-reference (can happen if primary and secondary primary were deduplicated)
				if currentPkgId == string(primaryPkg.PackageSPDXIdentifier) {
					continue
				}

				topLevelRels = append(topLevelRels, &spdx.Relationship{
					RefA:                common.MakeDocElementID("", string(primaryPkg.PackageSPDXIdentifier)),
					RefB:                common.MakeDocElementID("", currentPkgId),
					Relationship:        common.TypeRelationshipDependsOn,
					RelationshipComment: "sbomasm created depends_on relationship for flat merge with primary",
				})
			}
		} else if m.settings.Assemble.IsAssemblyMergeWithPrimary {
			log.Debugf("assembly merge with primary is applied")

			// Add CONTAINS from root to each secondary SBOM's primary component
			for _, dp := range secondaryDescribedPkgs {
				currentPkgId := pkgMapper[dp]

				// Skip self-reference
				if currentPkgId == string(primaryPkg.PackageSPDXIdentifier) {
					continue
				}

				topLevelRels = append(topLevelRels, &spdx.Relationship{
					RefA:                common.MakeDocElementID("", string(primaryPkg.PackageSPDXIdentifier)),
					RefB:                common.MakeDocElementID("", currentPkgId),
					Relationship:        common.TypeRelationshipContains,
					RelationshipComment: "sbomasm created contains relationship for assembly merge with primary",
				})
			}
		}

		// Add Relationships to document
		doc.Relationships = append(doc.Relationships, topLevelRels...)
		if len(rels) > 0 {
			doc.Relationships = append(doc.Relationships, rels...)
		}

		// Write the SBOM
		err = writeSBOM(doc, m)
		return err
	}

	// --- Existing non-primary mode behavior below ---
	doc, err = genSpdxDocumentMetadata(m)
	if err != nil {
		return err
	}

	log.Debugf("generated document: %s, with ID %s", doc.DocumentName, doc.SPDXIdentifier)

	ci, err = genCreationInfo(m)
	if err != nil {
		return err
	}
	doc.CreationInfo = ci

	log.Debugf("generated creation with %d creators, created_at %s and license version %s", len(ci.Creators), ci.Created, ci.LicenseListVersion)

	doc.ExternalDocumentReferences = append(doc.ExternalDocumentReferences, externalDocumentRefs(m.in)...)

	log.Debugf("added %d external document references", len(doc.ExternalDocumentReferences))

	primaryPkg, err = genPrimaryPackage(m)
	if err != nil {
		return err
	}

	log.Debugf("generated primary package: %s, version: %s", primaryPkg.PackageName, primaryPkg.PackageVersion)

	pkgs, pkgMapper, err := genPackageList(m, nil)
	if err != nil {
		return err
	}

	files, fileMapper, err := genFileList(m)
	if err != nil {
		return err
	}

	rels, err := genRelationships(m, pkgMapper, fileMapper)
	if err != nil {
		return err
	}

	otherLicenses := genOtherLicenses(m.in)

	describedPkgs := getDescribedPkgs(m)

	// Add Packages to document
	doc.Packages = append(doc.Packages, primaryPkg)
	doc.Packages = append(doc.Packages, pkgs...)

	// Add Files to document
	doc.Files = append(doc.Files, files...)

	// Add OtherLicenses to document
	doc.OtherLicenses = append(doc.OtherLicenses, otherLicenses...)

	topLevelRels := []*spdx.Relationship{}

	// always add describes relationship between document and primary package
	topLevelRels = append(topLevelRels, &spdx.Relationship{
		RefA:                common.MakeDocElementID("", "DOCUMENT"),
		RefB:                common.MakeDocElementID("", string(primaryPkg.PackageSPDXIdentifier)),
		Relationship:        common.TypeRelationshipDescribe,
		RelationshipComment: "sbomasm created primary component relationship",
	})

	if m.settings.Assemble.FlatMerge {
		log.Debugf("flat merge is applied")

		// Add DEPENDS_ON from root to each input SBOMs primary component
		for _, dp := range describedPkgs {
			currentPkgId := pkgMapper[dp]
			topLevelRels = append(topLevelRels, &spdx.Relationship{
				RefA:                common.MakeDocElementID("", string(primaryPkg.PackageSPDXIdentifier)),
				RefB:                common.MakeDocElementID("", currentPkgId),
				Relationship:        common.TypeRelationshipDependsOn,
				RelationshipComment: "sbomasm created depends_on relationship to support flat merge",
			})
		}
	} else if m.settings.Assemble.AssemblyMerge {
		log.Debugf("assembly merge is applied")

		// Add CONTAINS from root to each input SBOMs primary component
		for _, dp := range describedPkgs {
			currentPkgId := pkgMapper[dp]
			topLevelRels = append(topLevelRels, &spdx.Relationship{
				RefA:                common.MakeDocElementID("", string(primaryPkg.PackageSPDXIdentifier)),
				RefB:                common.MakeDocElementID("", currentPkgId),
				Relationship:        common.TypeRelationshipContains,
				RelationshipComment: "sbomasm created contains relationship to support assembly merge",
			})
		}
	} else {
		log.Debugf("hierarchical merge is applied")

		// Add DEPENDS_ON from root to each input SBOMs primary component
		for _, dp := range describedPkgs {
			currentPkgId := pkgMapper[dp]
			topLevelRels = append(topLevelRels, &spdx.Relationship{
				RefA:                common.MakeDocElementID("", string(primaryPkg.PackageSPDXIdentifier)),
				RefB:                common.MakeDocElementID("", currentPkgId),
				Relationship:        common.TypeRelationshipDependsOn,
				RelationshipComment: "sbomasm created depends_on relationship to support hierarchical merge",
			})
		}

		// Add nesteding hierarchy via CONTAINS relationshipType if not already present
		hierarchicalContains := genHierarchicalContains(m, pkgMapper, rels)
		if len(hierarchicalContains) > 0 {
			rels = append(rels, hierarchicalContains...)
		}
	}

	// Add Relationships to document
	doc.Relationships = append(doc.Relationships, topLevelRels...)
	if len(rels) > 0 {
		doc.Relationships = append(doc.Relationships, rels...)
	}

	// Write the SBOM
	err = writeSBOM(doc, m)

	return err
}
