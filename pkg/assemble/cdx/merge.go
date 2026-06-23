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
	"fmt"
	"io"
	"os"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	dtrack "github.com/DependencyTrack/client-go"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/samber/lo"
	"sigs.k8s.io/release-utils/version"
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
		normalizeBomRefs(bom)
		m.in = append(m.in, bom)
	}
}

func (m *merge) combinedMerge() error {
	log := logger.FromContext(*m.settings.Ctx)

	// For assembly merge with primary, pre-append primary file to input list
	// This ensures primary is at index 0, secondaries follow
	if m.settings.Assemble.IsAssemblyMergeWithPrimary {
		m.settings.Input.Files = append([]string{m.settings.Assemble.PrimaryFile}, m.settings.Input.Files...)
		log.Debugf("prepended primary file to input list: %s", m.settings.Assemble.PrimaryFile)
	}

	log.Debug("loading sboms")
	m.loadBoms()

	log.Debugf("initialize component service")
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

	if m.settings.Assemble.IsAssemblyMergeWithPrimary {
		// Assembly merge with primary: use existing primary as root, nest secondaries as sub-components
		if err := m.assemblyMergeWithPrimary(cs, compList, depList); err != nil {
			return err
		}
	} else if m.settings.Assemble.FlatMerge {
		finalCompList := []cydx.Component{}
		finalCompList = append(finalCompList, priCompList...)
		finalCompList = append(finalCompList, compList...)
		log.Debugf("flat merge: final component list: %d", len(finalCompList))
		m.out.Components = &finalCompList

		priCompIds := lo.FilterMap(priCompList, func(c cydx.Component, _ int) (string, bool) {
			return c.BOMRef, c.BOMRef != ""
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

			//Initialize the components list for the primary component (only once)
			if priCompList[newPc].Components == nil {
				priCompList[newPc].Components = &[]cydx.Component{}
			}

			// Track which components are already attached to avoid duplicates across BOMs
			seenComp := make(map[string]struct{})
			for _, comp := range *priCompList[newPc].Components {
				seenComp[comp.BOMRef] = struct{}{}
			}

			for _, oldComp := range lo.FromPtr(b.Components) {
				newCompId, _ := cs.ResolveDepID(oldComp.BOMRef)
				if _, exists := seenComp[newCompId]; exists {
					continue
				}
				for _, comp := range compList {
					if comp.BOMRef == newCompId {
						*priCompList[newPc].Components = append(*priCompList[newPc].Components, comp)
						seenComp[newCompId] = struct{}{}
						break
					}
				}
			}

			log.Debugf("hierarchical merge: primary component %s has %d components", priCompList[newPc].BOMRef, len(*priCompList[newPc].Components))
		}

		m.out.Components = &priCompList

		priCompIds := lo.FilterMap(priCompList, func(c cydx.Component, _ int) (string, bool) {
			return c.BOMRef, c.BOMRef != ""
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

	// Add document license if specified (default: CC0-1.0, can be overridden via --doc-license)
	// Use "none" or empty string to skip adding a license
	docLicense := m.settings.Assemble.DocLicense
	if docLicense == "" {
		docLicense = "CC0-1.0" // Default license
	}
	if strings.ToLower(docLicense) != "none" && docLicense != "" {
		m.out.Metadata.Licenses = &cydx.Licenses{
			{
				License: &cydx.License{ID: docLicense},
			},
		}
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

	pc.BOMRef = generateComponentBomRef(&pc)
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

// assemblyMergeWithPrimary implements the assembly merge with --primary flag logic
// Uses the primary SBOM's primary as the document root, nests secondary primaries as sub-components
func (m *merge) assemblyMergeWithPrimary(cs *uniqueComponentService, compList []cydx.Component, depList []cydx.Dependency) error {
	log := logger.FromContext(*m.settings.Ctx)

	// Find primary and secondary SBOM indices
	primaryIdx, secondaryIdxs := m.findPrimaryAndSecondaryIndices()
	if primaryIdx == -1 {
		return fmt.Errorf("primary SBOM file not found in input: %s", m.settings.Assemble.PrimaryFile)
	}

	log.Debugf("assembly merge with primary: primary index %d, secondary indices %v", primaryIdx, secondaryIdxs)

	// Get primary BOM
	primaryBom := m.in[primaryIdx]

	// Setup output BOM with primary's metadata
	m.initOutBomFromPrimary(primaryBom)

	// Setup primary component from primary SBOM (preserves all fields)
	m.out.Metadata.Component = m.extractPrimaryComponent(primaryBom)
	if m.out.Metadata.Component == nil {
		return fmt.Errorf("primary SBOM has no primary component")
	}

	log.Debugf("assembly merge with primary: using primary component %s", m.out.Metadata.Component.BOMRef)

	// Build sub-components list from secondary SBOMs' primaries
	var subComponents []cydx.Component
	secondaryPrimaryRefs := []string{}
	for _, idx := range secondaryIdxs {
		secBom := m.in[idx]
		if secBom.Metadata != nil && secBom.Metadata.Component != nil {
			secPrimary := m.extractPrimaryComponent(secBom)
			if secPrimary != nil {
				// Store and clone with new ID if needed for uniqueness
				newComp, _ := cs.StoreAndCloneWithNewID(secPrimary)
				subComponents = append(subComponents, *newComp)
				secondaryPrimaryRefs = append(secondaryPrimaryRefs, newComp.BOMRef)
				log.Debugf("assembly merge with primary: added secondary primary %s as sub-component", newComp.BOMRef)
			}
		}
	}

	// Set sub-components on primary
	if len(subComponents) > 0 {
		m.out.Metadata.Component.Components = &subComponents
		log.Debugf("assembly merge with primary: set %d sub-components", len(subComponents))
	}

	// Build component list excluding secondary primaries (they're in sub-components)
	// Use the already-built compList and filter out secondary primaries
	finalCompList := m.filterComponentList(compList, secondaryPrimaryRefs)
	m.out.Components = &finalCompList
	log.Debugf("assembly merge with primary: final component list: %d", len(finalCompList))

	// Build dependencies with primary's deps updated to include secondary primaries
	finalDepList := m.buildDependencyListWithPrimaryLinks(cs, primaryIdx, secondaryPrimaryRefs, depList)
	m.out.Dependencies = &finalDepList
	log.Debugf("assembly merge with primary: final dependency list: %d", len(finalDepList))

	// Build tools list preserving primary's tools and adding sbomasm
	toolsList := m.buildToolListWithPrimary(primaryBom)
	m.out.Metadata.Tools = toolsList
	log.Debugf("assembly merge with primary: tools list: %d components, %d services", len(*toolsList.Components), len(*toolsList.Services))

	return nil
}

// findPrimaryAndSecondaryIndices returns primary at index 0 and secondary indices (1+)
func (m *merge) findPrimaryAndSecondaryIndices() (int, []int) {
	primaryIdx := 0
	var secondaryIdxs []int

	for i := 1; i < len(m.in); i++ {
		secondaryIdxs = append(secondaryIdxs, i)
	}

	return primaryIdx, secondaryIdxs
}

// extractPrimaryComponent extracts the primary component from a BOM
func (m *merge) extractPrimaryComponent(bom *cydx.BOM) *cydx.Component {
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		// Clone the component to avoid modifying the original
		clonedComp, err := cloneComp(bom.Metadata.Component)
		if err != nil {
			// If cloning fails, return the original
			return bom.Metadata.Component
		}
		return clonedComp
	}
	return nil
}

// initOutBomFromPrimary initializes output BOM metadata from primary SBOM
// Preserves primary's identity (serial number) like augment merge, updates timestamp
func (m *merge) initOutBomFromPrimary(primaryBom *cydx.BOM) {
	// Preserve primary's serial number (maintains document identity)
	if primaryBom.SerialNumber != "" {
		m.out.SerialNumber = primaryBom.SerialNumber
	} else {
		m.out.SerialNumber = newSerialNumber()
	}

	m.out.Metadata = &cydx.Metadata{}

	// Update timestamp to reflect modification
	m.out.Metadata.Timestamp = utcNowTime()

	// Preserve primary's supplier if present
	if primaryBom.Metadata != nil && primaryBom.Metadata.Supplier != nil {
		m.out.Metadata.Supplier = primaryBom.Metadata.Supplier
	}

	// Preserve primary's licenses if present
	if primaryBom.Metadata != nil && primaryBom.Metadata.Licenses != nil {
		m.out.Metadata.Licenses = primaryBom.Metadata.Licenses
	} else {
		// Default license
		m.out.Metadata.Licenses = &cydx.Licenses{
			{
				License: &cydx.License{ID: "CC-BY-1.0"},
			},
		}
	}

	// Preserve primary's authors
	if primaryBom.Metadata != nil && primaryBom.Metadata.Authors != nil {
		m.out.Metadata.Authors = primaryBom.Metadata.Authors
	}
}

// filterComponentList filters out secondary primary components from the component list
func (m *merge) filterComponentList(compList []cydx.Component, secondaryRefs []string) []cydx.Component {
	secondarySet := make(map[string]bool)
	for _, ref := range secondaryRefs {
		secondarySet[ref] = true
	}

	var filtered []cydx.Component
	for _, comp := range compList {
		if !secondarySet[comp.BOMRef] {
			filtered = append(filtered, comp)
		}
	}
	return filtered
}

// buildDependencyListWithPrimaryLinks builds dependencies and adds links from primary to secondaries
func (m *merge) buildDependencyListWithPrimaryLinks(cs *uniqueComponentService, primaryIdx int, secondaryRefs []string, depList []cydx.Dependency) []cydx.Dependency {
	log := logger.FromContext(*m.settings.Ctx)

	// Get primary's bom-ref
	primaryRef := ""
	if m.in[primaryIdx].Metadata != nil && m.in[primaryIdx].Metadata.Component != nil {
		primaryRef = m.in[primaryIdx].Metadata.Component.BOMRef
		// Resolve to potentially updated ref
		if resolved, found := cs.ResolveDepID(primaryRef); found {
			primaryRef = resolved
		}
	}

	// Build dependency map for efficient lookup
	depMap := make(map[string]*cydx.Dependency)
	for i := range depList {
		dep := &depList[i]
		depMap[dep.Ref] = dep
	}

	// Update primary's dependency entry to include secondary primaries
	if primaryRef != "" && len(secondaryRefs) > 0 {
		if existingDep, exists := depMap[primaryRef]; exists {
			// Append secondary refs to existing dependencies
			existingDeps := lo.FromPtr(existingDep.Dependencies)
			mergedDeps := lo.Uniq(append(existingDeps, secondaryRefs...))
			existingDep.Dependencies = &mergedDeps
			log.Debugf("updated primary dependency %s with %d secondary refs", primaryRef, len(secondaryRefs))
		} else {
			// Create new dependency entry
			newDep := cydx.Dependency{
				Ref:          primaryRef,
				Dependencies: &secondaryRefs,
			}
			depList = append(depList, newDep)
			log.Debugf("created new primary dependency %s with %d secondary refs", primaryRef, len(secondaryRefs))
		}
	}

	return depList
}

// buildToolListWithPrimary builds tools list preserving primary's tools and adding sbomasm
func (m *merge) buildToolListWithPrimary(primaryBom *cydx.BOM) *cydx.ToolsChoice {
	tools := cydx.ToolsChoice{
		Components: &[]cydx.Component{},
		Services:   &[]cydx.Service{},
	}

	// Preserve primary's existing tools
	if primaryBom.Metadata != nil && primaryBom.Metadata.Tools != nil {
		// Copy old-format tools
		if primaryBom.Metadata.Tools.Tools != nil {
			for _, tool := range *primaryBom.Metadata.Tools.Tools {
				*tools.Components = append(*tools.Components, cydx.Component{
					Type:    cydx.ComponentTypeApplication,
					Name:    tool.Name,
					Version: tool.Version,
					Supplier: &cydx.OrganizationalEntity{
						Name: tool.Vendor,
					},
				})
			}
		}
		// Copy component-format tools
		if primaryBom.Metadata.Tools.Components != nil {
			for _, tool := range *primaryBom.Metadata.Tools.Components {
				comp, _ := cloneComp(&tool)
				*tools.Components = append(*tools.Components, *comp)
			}
		}
		// Copy services
		if primaryBom.Metadata.Tools.Services != nil {
			for _, service := range *primaryBom.Metadata.Tools.Services {
				serv, _ := cloneService(&service)
				*tools.Services = append(*tools.Services, *serv)
			}
		}
	}

	// Add sbomasm tool
	*tools.Components = append(*tools.Components, cydx.Component{
		Type:        cydx.ComponentTypeApplication,
		Name:        "sbomasm",
		Version:     version.GetVersionInfo().GitVersion,
		Description: "Assembler & Editor for your sboms",
		Supplier: &cydx.OrganizationalEntity{
			Name: "Interlynk",
			URL:  &[]string{"https://interlynk.io"},
			Contact: &[]cydx.OrganizationalContact{
				{Email: "support@interlynk.io"},
			},
		},
		Licenses: &cydx.Licenses{
			{License: &cydx.License{ID: "Apache-2.0"}},
		},
	})

	// Deduplicate tools by name-version
	uniqTools := lo.UniqBy(*tools.Components, func(c cydx.Component) string {
		return fmt.Sprintf("%s-%s", c.Name, c.Version)
	})
	uniqServices := lo.UniqBy(*tools.Services, func(s cydx.Service) string {
		return fmt.Sprintf("%s-%s", s.Name, s.Version)
	})

	tools.Components = &uniqTools
	tools.Services = &uniqServices

	return &tools
}
