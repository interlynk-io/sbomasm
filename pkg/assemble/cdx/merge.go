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

package cdx

import (
	"encoding/base64"
	"io"
	"os"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	dtrack "github.com/DependencyTrack/client-go"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
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

func (m *merge) combinedMerge() error {
	log := logger.FromContext(*m.settings.Ctx)

	log.Debug("loading sboms")
	m.loadBoms()

	log.Debugf("initialize component service")
	//cs := newComponentService(*m.settings.Ctx)
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

	// build a list of vulnerabilities from each sbom
	vulnList := buildVulnerabilityList(m.in, cs)
	log.Debugf("build a list of vulnerabilities from each sbom found %d", len(vulnList))

	//Build the final sbom
	log.Debugf("generating output sbom")
	m.initOutBom()

	log.Debugf("generating primary component")
	m.out.Metadata.Component = m.setupPrimaryComp()

	log.Debugf("assign tools to metadata")
	m.out.Metadata.Tools = toolsList

	if m.settings.Assemble.FlatMerge {
		finalCompList := []cydx.Component{}
		finalCompList = append(finalCompList, priCompList...)
		finalCompList = append(finalCompList, compList...)
		log.Debugf("flat merge: final component list: %d", len(finalCompList))
		m.out.Components = &finalCompList

		priCompIds := lo.Map(priCompList, func(c cydx.Component, _ int) string {
			return c.BOMRef
		})
		depList = append(depList, cydx.Dependency{
			Ref:          m.out.Metadata.Component.BOMRef,
			Dependencies: &priCompIds,
		})
		log.Debugf("flat merge: final dependency list: %d", len(depList))
		m.out.Dependencies = &depList
	} else if m.settings.Assemble.AssemblyMerge {
		// Add the sbom primary components to the new primary component
		m.out.Metadata.Component.Components = &priCompList
		m.out.Components = &compList
		m.out.Dependencies = &depList

		log.Debugf("assembly merge: final component list: %d", len(compList))
		log.Debugf("assembly merge: final dependency list: %d", len(depList))
	} else {
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

			//Initialize the components list for the primary component
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
	}

	// Assign vulnerabilities to output BOM
	if len(vulnList) > 0 {
		m.out.Vulnerabilities = &vulnList
		log.Debugf("assigned %d vulnerabilities to output sbom", len(vulnList))
	}

	// Writes sbom to file or uploads
	log.Debugf("writing sbom")
	return m.processSBOM()
}

func (m *merge) initOutBom() {
	//log := logger.FromContext(*m.settings.Ctx)
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
			// Skip authors with empty names (e.g., sanitized [OPTIONAL] values)
			if author.Name == "" {
				continue
			}
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
