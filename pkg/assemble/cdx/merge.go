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

package cdx

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	dtrack "github.com/DependencyTrack/client-go"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/samber/lo"
)

type merge struct {
	settings *MergeSettings
	out      *cydx.BOM
	in       []*cydx.BOM
}

func newMerge(ms *MergeSettings) *merge {
	return &merge{
		settings: ms,
		out:      cydx.NewBOM(),
		in:       []*cydx.BOM{},
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

func (m *merge) filterOutFinalSbomPC(priCompList []cydx.Component, cs *uniqueComponentService) ([]cydx.Component, error) {
	log := logger.FromContext(*m.settings.Ctx)

	primaryComp := m.out.Metadata.Component
	if primaryComp == nil {
		return nil, fmt.Errorf("primaryCompFile is missing a primary component")
	}

	primaryCompNameWithVersion := primaryComp.Name + primaryComp.Version
	var newPrimaryCompList []cydx.Component

	for _, b := range m.in {
		var oldPc *cydx.Component

		if b.Metadata != nil && b.Metadata.Component != nil {
			oldPc = b.Metadata.Component
		}

		if oldPc == nil {
			log.Error("flat merge: old product does not have any component.")
			oldPc = &cydx.Component{}
		}

		newPcId, _ := cs.ResolveDepID(oldPc.BOMRef)

		for _, pc := range priCompList {
			if pc.BOMRef == newPcId {
				if primaryCompNameWithVersion == pc.Name+pc.Version {
					continue
				}
				newPrimaryCompList = append(newPrimaryCompList, pc)
			}
		}
	}

	return newPrimaryCompList, nil
}

func (m *merge) handleFlatMerge(priCompList, compList []cydx.Component, depList []cydx.Dependency, cs *uniqueComponentService) error {
	log := logger.FromContext(*m.settings.Ctx)

	finalCompList := []cydx.Component{}

	if m.settings.Input.PrimaryCompFile != "" {
		log.Debugf("handling flat merge for PrimaryCompFile")

		// filter out final sbom primary comp element from primaryCompList --
		newPrimaryCompList, err := m.filterOutFinalSbomPC(priCompList, cs)
		if err != nil {
			return err
		}

		// -- to avoid final sbom primary comp writting itself to it's components section
		finalCompList = append(finalCompList, newPrimaryCompList...)
	} else {
		finalCompList = append(finalCompList, priCompList...)
	}

	// add all other components to the final sbom components section
	finalCompList = append(finalCompList, compList...)
	log.Debugf("flat merge: final component list: %d", len(finalCompList))

	m.out.Components = &finalCompList
	m.addDependencies(priCompList, depList)
	return m.processSBOM()
}

func (m *merge) handleAssemblyMerge(priCompList, compList []cydx.Component, depList []cydx.Dependency, cs *uniqueComponentService) error {
	log := logger.FromContext(*m.settings.Ctx)

	if m.settings.Input.PrimaryCompFile != "" {
		log.Debugf("handling assembly merge for PrimaryCompFile")

		// filter out final sbom primary comp element from primaryCompList --
		newPrimaryCompList, err := m.filterOutFinalSbomPC(priCompList, cs)
		if err != nil {
			return err
		}

		// -- to avoid final sbom primary comp writting itself under metadata.component.components section
		m.out.Metadata.Component.Components = &newPrimaryCompList
	} else {
		m.out.Metadata.Component.Components = &priCompList
	}

	m.out.Components = &compList
	m.out.Dependencies = &depList

	log.Debugf("assembly merge: final component list: %d", len(compList))
	return m.processSBOM()
}

func (m *merge) addDependencies(priCompList []cydx.Component, depList []cydx.Dependency) {
	priCompIds := lo.Map(priCompList, func(c cydx.Component, _ int) string {
		return c.BOMRef
	})
	depList = append(depList, cydx.Dependency{
		Ref:          m.out.Metadata.Component.BOMRef,
		Dependencies: &priCompIds,
	})
	m.out.Dependencies = &depList
}

func (m *merge) handleHierarchicalMerge(priCompList, compList []cydx.Component, depList []cydx.Dependency, cs *uniqueComponentService) error {
	log := logger.FromContext(*m.settings.Ctx)

	if m.settings.Input.PrimaryCompFile != "" {
		log.Debugf("handling hierarchical merge for PrimaryCompFile")
		return m.handlePrimaryCompFileHierarchicalMerge(priCompList, compList, depList, cs)
	} else {
		log.Debugf("handling standard hierarchical merge")
		return m.handleStandardHierarchicalMerge(priCompList, compList, depList, cs)
	}
}

// handle hierarchical merge for PrimaryCompFile
func (m *merge) handlePrimaryCompFileHierarchicalMerge(priCompList, compList []cydx.Component, depList []cydx.Dependency, cs *uniqueComponentService) error {
	log := logger.FromContext(*m.settings.Ctx)

	primaryComp := m.out.Metadata.Component
	if primaryComp == nil {
		return fmt.Errorf("primaryCompFile is missing a primary component")
	}
	primaryCompNameWithVersion := primaryComp.Name + primaryComp.Version

	finalComponents := []cydx.Component{}
	priCompIds := []string{}

	var primarCompFileRef string

	// Step 1: Identify the primary comp of final sbom and
	// get it's all components from corresponding sbom and
	// all those components in a flat manner.
	// similar to flat structure...
	for _, b := range m.in {
		var oldPc *cydx.Component

		if b.Metadata != nil && b.Metadata.Component != nil {
			oldPc = b.Metadata.Component
		}

		if oldPc == nil {
			log.Error("hierarchical merge: old product does not have any component.")
			continue
		}

		newPcId, _ := cs.ResolveDepID(oldPc.BOMRef)

		found := false
		for _, pc := range priCompList {
			if pc.BOMRef == newPcId {
				if primaryCompNameWithVersion == pc.Name+pc.Version {
					found = true
					primarCompFileRef = b.Metadata.Component.BOMRef
					break
				}
			}
		}

		// get all it's components and add it in a flat manner in the final sbom components section
		if found {
			for _, oldComp := range lo.FromPtr(b.Components) {
				newCompId, _ := cs.ResolveDepID(oldComp.BOMRef)
				for _, comp := range compList {
					if comp.BOMRef == newCompId {
						finalComponents = append(finalComponents, comp)
						break
					}
				}
			}
		}
	}

	// Step 2: Process remaining input SBOMs
	// And add input SBOMs components under their primary element.
	// And finally add the input SBOMs primary comp under the final SBOMs components section.
	// similar to hierarchy structure...
	for _, bom := range m.in {
		if bom.Metadata.Component.BOMRef == primarCompFileRef {
			continue
		}

		if bom.Metadata == nil || bom.Metadata.Component == nil {
			log.Error("input SBOM missing primary component.")
			continue
		}

		inputPrimaryComp := bom.Metadata.Component
		clonedPrimaryComp, _ := cs.StoreAndCloneWithNewID(inputPrimaryComp)
		priCompIds = append(priCompIds, clonedPrimaryComp.BOMRef)

		clonedPrimaryComp.Components = &[]cydx.Component{}
		for _, comp := range lo.FromPtr(bom.Components) {
			clonedSubComp, _ := cs.StoreAndCloneWithNewID(&comp)
			*clonedPrimaryComp.Components = append(*clonedPrimaryComp.Components, *clonedSubComp)
		}

		finalComponents = append(finalComponents, *clonedPrimaryComp)
	}

	depList = append(depList, cydx.Dependency{
		Ref:          primaryComp.BOMRef,
		Dependencies: &priCompIds,
	})

	m.out.Components = &finalComponents
	m.out.Dependencies = &depList
	return nil
}

// handle standard hierarchical merge (without PrimaryCompFile)
func (m *merge) handleStandardHierarchicalMerge(priCompList, compList []cydx.Component, depList []cydx.Dependency, cs *uniqueComponentService) error {
	log := logger.FromContext(*m.settings.Ctx)

	for _, b := range m.in {
		var oldPc *cydx.Component
		var newPc int

		if b.Metadata != nil && b.Metadata.Component != nil {
			oldPc = b.Metadata.Component
		}

		if oldPc == nil {
			log.Error("hierarchical merge: old product does not have any component.")
			oldPc = &cydx.Component{}
		}

		newPcId, _ := cs.ResolveDepID(oldPc.BOMRef)

		for i, pc := range priCompList {
			if pc.BOMRef == newPcId {
				newPc = i
				break
			}
		}

		// Initialize the components list for the primary component
		priCompList[newPc].Components = &[]cydx.Component{}

		for _, oldComp := range lo.FromPtr(b.Components) {
			newCompId, _ := cs.ResolveDepID(oldComp.BOMRef)
			for _, comp := range compList {
				if comp.BOMRef == newCompId {
					*priCompList[newPc].Components = append(*priCompList[newPc].Components, comp)
					break
				}
			}
		}

		log.Debugf("hierarchical merge: primary component %s has %d components", priCompList[newPc].BOMRef, len(*priCompList[newPc].Components))
	}

	m.out.Components = &priCompList

	priCompIds := lo.Map(priCompList, func(c cydx.Component, _ int) string {
		return c.BOMRef
	})
	depList = append(depList, cydx.Dependency{
		Ref:          m.out.Metadata.Component.BOMRef,
		Dependencies: &priCompIds,
	})
	m.out.Dependencies = &depList
	log.Debugf("hierarchical merge: final dependency list: %d", len(depList))
	return nil
}

func (m *merge) combinedMerge() error {
	log := logger.FromContext(*m.settings.Ctx)

	log.Debug("loading sboms")
	m.loadBoms()

	log.Debugf("initialize component service")
	// cs := newComponentService(*m.settings.Ctx)
	cs := newUniqueComponentService(*m.settings.Ctx)

	// Build primary component list from each sbom
	priCompList := buildPrimaryComponentList(m.in, cs)
	log.Debugf("build primary component list for each sbom found %d", len(priCompList))

	// Build a flat list of components from each sbom
	compList := buildComponentList(m.in, cs)
	log.Debugf("build a flat list of components from each sbom found %d", len(compList))

	// Build a flat list of dependencies from each sbom
	depList := buildDependencyList(m.in, cs)
	log.Debugf("build a flat list of dependencies from each sbom found %d", len(depList))

	// build a list of tools from each sbom
	toolsList := buildToolList(m.in)
	log.Debugf("build a list of tools from each sbom found comps: %d, service: %d", len(*toolsList.Components), len(*toolsList.Services))

	// Build the final sbom
	log.Debugf("generating output sbom")
	m.initOutBom()

	log.Debugf("generating primary component")
	m.out.Metadata.Component = m.setupPrimaryComp()

	log.Debugf("assign tools to metadata")
	m.out.Metadata.Tools = toolsList

	if m.settings.Assemble.FlatMerge {
		m.handleFlatMerge(priCompList, compList, depList, cs)
	} else if m.settings.Assemble.AssemblyMerge {
		m.handleAssemblyMerge(priCompList, compList, depList, cs)
	} else {
		m.handleHierarchicalMerge(priCompList, compList, depList, cs)
	}

	// Writes sbom to file or uploads
	log.Debugf("writing sbom")
	return m.processSBOM()
}

func (m *merge) initOutBom() {
	// log := logger.FromContext(*m.settings.Ctx)
	m.out.SerialNumber = newSerialNumber()

	m.out.Metadata = &cydx.Metadata{}
	m.out.Metadata.Timestamp = utcNowTime()

	if m.settings.App.Supplier.Name != "" || m.settings.App.Supplier.Email != "" {
		m.out.Metadata.Supplier = &cydx.OrganizationalEntity{}
		m.out.Metadata.Supplier.Name = m.settings.App.Supplier.Name
		if m.settings.App.Supplier.Email != "" {
			m.out.Metadata.Supplier.Contact = &[]cydx.OrganizationalContact{
				{Name: m.settings.App.Supplier.Name, Email: m.settings.App.Supplier.Email},
			}
		}
	}

	// Always add data sharing license.
	m.out.Metadata.Licenses = &cydx.Licenses{
		{
			License: &cydx.License{ID: "CC-BY-1.0"},
		},
	}

	if len(m.settings.App.Authors) > 0 {
		m.out.Metadata.Authors = &[]cydx.OrganizationalContact{}
		for _, author := range m.settings.App.Authors {
			*m.out.Metadata.Authors = append(*m.out.Metadata.Authors, cydx.OrganizationalContact{
				Name:  author.Name,
				Email: author.Email,
			})
		}
	}
}

func (m *merge) setupPrimaryComp() *cydx.Component {
	pc := cydx.Component{}

	pc.Name = m.settings.App.Name
	pc.Version = m.settings.App.Version
	pc.Type = cdx_strings_to_types[m.settings.App.PrimaryPurpose]
	pc.PackageURL = m.settings.App.Purl
	pc.CPE = m.settings.App.CPE
	pc.Description = m.settings.App.Description

	if len(m.settings.App.Authors) > 0 {
		pc.Author = m.settings.App.Authors[0].Name
	}

	if m.settings.App.License.Id != "" {
		pc.Licenses = &cydx.Licenses{
			{License: &cydx.License{ID: m.settings.App.License.Id}},
		}
	} else if m.settings.App.License.Expression != "" {
		pc.Licenses = &cydx.Licenses{
			{Expression: m.settings.App.License.Expression},
		}
	}

	if len(m.settings.App.Checksums) > 0 {
		pc.Hashes = &[]cydx.Hash{}
		for _, c := range m.settings.App.Checksums {
			if len(c.Value) == 0 {
				continue
			}
			*pc.Hashes = append(*pc.Hashes, cydx.Hash{
				Algorithm: cdx_hash_algos[c.Algorithm],
				Value:     c.Value,
			})
		}
	}

	if m.settings.App.Supplier.Name != "" || m.settings.App.Supplier.Email != "" {
		pc.Supplier = &cydx.OrganizationalEntity{}
		pc.Supplier.Name = m.settings.App.Supplier.Name
		if m.settings.App.Supplier.Email != "" {
			pc.Supplier.Contact = &[]cydx.OrganizationalContact{
				{Name: m.settings.App.Supplier.Name, Email: m.settings.App.Supplier.Email},
			}
		}
	}

	pc.BOMRef = newBomRef()
	return &pc
}

func (m *merge) processSBOM() error {
	var output io.Writer
	var sb strings.Builder

	log := logger.FromContext(*m.settings.Ctx)

	if m.settings.Output.Upload {
		output = &sb
	} else if m.settings.Output.File == "" {
		output = os.Stdout
	} else {
		f, err := os.Create(m.settings.Output.File)
		if err != nil {
			return err
		}
		defer f.Close()
		output = f
	}

	var encoder cydx.BOMEncoder
	switch m.settings.Output.FileFormat {
	case "xml":
		log.Debugf("writing sbom in xml format")
		encoder = cydx.NewBOMEncoder(output, cydx.BOMFileFormatXML)
	default:
		log.Debugf("writing sbom in json format")
		encoder = cydx.NewBOMEncoder(output, cydx.BOMFileFormatJSON)
	}

	encoder.SetPretty(true)
	encoder.SetEscapeHTML(true)

	var err error
	if m.settings.Output.SpecVersion == "" {
		err = encoder.Encode(m.out)
	} else {
		log.Debugf("writing sbom in version %s", m.settings.Output.SpecVersion)
		outputVersion := specVersionMap[m.settings.Output.SpecVersion]
		err = encoder.EncodeVersion(m.out, outputVersion)
	}

	if err != nil {
		return err
	}

	if m.settings.Output.Upload {
		return m.uploadToServer(sb.String())
	}

	return nil
}

func (m *merge) uploadToServer(bomContent string) error {
	log := logger.FromContext(*m.settings.Ctx)

	log.Debugf("uploading sbom to %s", m.settings.Output.Url)

	dTrackClient, err := dtrack.NewClient(m.settings.Output.Url,
		dtrack.WithAPIKey(m.settings.Output.ApiKey), dtrack.WithDebug(false))
	if err != nil {
		log.Fatalf("Failed to create Dependency-Track client: %s", err)
		return err
	}

	encodedBOM := base64.StdEncoding.EncodeToString([]byte(bomContent))
	bomUploadRequest := dtrack.BOMUploadRequest{
		ProjectUUID: &m.settings.Output.UploadProjectID,
		BOM:         encodedBOM,
	}

	token, err := dTrackClient.BOM.Upload(*m.settings.Ctx, bomUploadRequest)
	if err != nil {
		log.Fatalf("Failed to upload BOM: %s", err)
		return err
	}

	log.Debugf("bom upload token: %v", token)
	return nil
}
