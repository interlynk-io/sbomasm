// Copyright 2023 Interlynk.io
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
	"github.com/interlynk-io/sbomasm/pkg/logger"
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

	doc, err := genSpdxDocument(m)
	if err != nil {
		return err
	}

	log.Debugf("generated document: %s, with ID %s", doc.DocumentName, doc.SPDXIdentifier)

	ci, err := genCreationInfo(m)
	if err != nil {
		return err
	}
	doc.CreationInfo = ci

	log.Debugf("generated creation with %d creators, created_at %s and license version %s", len(ci.Creators), ci.Created, ci.LicenseListVersion)

	doc.ExternalDocumentReferences = append(doc.ExternalDocumentReferences, externalDocumentRefs(m.in)...)

	log.Debugf("added %d external document references", len(doc.ExternalDocumentReferences))

	primaryPkg, err := genPrimaryPackage(m)
	if err != nil {
		return err
	}

	log.Debugf("generated primary package: %s, version: %s", primaryPkg.PackageName, primaryPkg.PackageVersion)

	pkgs, pkgMapper, err := genPackageList(m)
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

	doc.Packages = removeDuplicates(doc.Packages)

	for _, p := range doc.Packages {
		fmt.Println("DOC PACKAGE NAME: ", p.PackageName)
		fmt.Println("DOC VERSION NAME: ", p.PackageVersion)
	}

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
		// we skip the contains relationship and remove all relationships except describes
		rels = []*spdx.Relationship{}
	} else if m.settings.Assemble.AssemblyMerge {
		log.Debugf("assembly merge is applied")
		// we retain all relationships but we will not add a contains relationship
	} else {
		log.Debugf("hierarchical merge is applied")
		// Default to hierarchical merge
		// Add relationships between primary package and described packages from merge sets
		for _, dp := range describedPkgs {
			currentPkgId := pkgMapper[dp]
			topLevelRels = append(topLevelRels, &spdx.Relationship{
				RefA:                common.MakeDocElementID("", string(primaryPkg.PackageSPDXIdentifier)),
				RefB:                common.MakeDocElementID("", currentPkgId),
				Relationship:        common.TypeRelationshipContains,
				RelationshipComment: "sbomasm created contains relationship to support hierarchical merge",
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
