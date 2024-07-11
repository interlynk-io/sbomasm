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
	"io"
	"os"

	cydx "github.com/CycloneDX/cyclonedx-go"
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

func (m *merge) initOutBom() {
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

	m.out.Metadata.Licenses = &cydx.Licenses{
		{License: &cydx.License{ID: "CC-BY-1.0"}},
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
	log := logger.FromContext(*m.settings.Ctx)
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
	}

	if m.settings.App.License.Expression != "" {
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

	pc.BOMRef = newBomRef(pc)
	log.Debugf("Primary component: %s", pc.BOMRef)

	return &pc
}

/*
Gatheres all the artifacts of the input BOMs into a single BOM.
as a flat list of components.
*/
func (m *merge) flatMerge() error {
	log := logger.FromContext(*m.settings.Ctx)
	cs := newComponentService(*m.settings.Ctx)

	log.Debug("Merging BOMs into a flat list")

	priComps := lo.Map(m.in, func(bom *cydx.BOM, _ int) *cydx.Component {
		if bom.Metadata != nil && bom.Metadata.Component != nil {
			return cs.StoreAndCloneWithNewID(bom.Metadata.Component)
		}
		return &cydx.Component{}
	})

	comps := lo.Flatten(lo.Map(m.in, func(bom *cydx.BOM, _ int) []cydx.Component {
		newComps := []cydx.Component{}
		for _, comp := range lo.FromPtr(bom.Components) {
			newComps = append(newComps, *cs.StoreAndCloneWithNewID(&comp))
		}
		return newComps
	}))

	deps := lo.Flatten(lo.Map(m.in, func(bom *cydx.BOM, _ int) []cydx.Dependency {
		newDeps := []cydx.Dependency{}
		for _, dep := range lo.FromPtr(bom.Dependencies) {
			nd := cydx.Dependency{}
			ref, found := cs.ResolveDepID(dep.Ref)
			if !found {
				log.Warnf("dependency %s not found", dep.Ref)
				continue
			}

			deps := cs.ResolveDepIDs(lo.FromPtr(dep.Dependencies))

			nd.Ref = ref
			nd.Dependencies = &deps
			newDeps = append(newDeps, nd)
		}
		return newDeps
	}))

	m.out.Metadata.Component = m.setupPrimaryComp()

	tools := getAllTools(m.in)
	m.out.Metadata.Tools = &cydx.ToolsChoice{
		Components: &[]cydx.Component{},
	}
	*m.out.Metadata.Tools.Components = append(*m.out.Metadata.Tools.Components, tools...)

	//Add the primary component to the list of components
	for _, c := range priComps {
		comps = append(comps, *c)
	}

	//Add depedencies between new primary component and old primary components
	priIds := lo.Map(priComps, func(c *cydx.Component, _ int) string {
		return c.BOMRef
	})

	deps = append(deps, cydx.Dependency{
		Ref:          m.out.Metadata.Component.BOMRef,
		Dependencies: &priIds,
	})

	if m.settings.Assemble.IncludeComponents {
		m.out.Components = &comps
	}

	if m.settings.Assemble.IncludeDependencyGraph {
		m.out.Dependencies = &deps
	}

	return m.writeSBOM()

}

func (m *merge) assemblyMerge() error {
	log := logger.FromContext(*m.settings.Ctx)
	cs := newComponentService(*m.settings.Ctx)

	log.Debug("Merging BOMs as an assembly")

	priComps := lo.Map(m.in, func(bom *cydx.BOM, _ int) *cydx.Component {
		if bom.Metadata != nil && bom.Metadata.Component != nil {
			pc := cs.StoreAndCloneWithNewID(bom.Metadata.Component)

			if pc.Components == nil {
				pc.Components = &[]cydx.Component{}
			}

			for _, c := range lo.FromPtr(bom.Components) {
				*pc.Components = append(*pc.Components, *cs.StoreAndCloneWithNewID(&c))
			}
			return pc
		}
		return &cydx.Component{}
	})

	deps := lo.Flatten(lo.Map(m.in, func(bom *cydx.BOM, _ int) []cydx.Dependency {
		newDeps := []cydx.Dependency{}
		for _, dep := range lo.FromPtr(bom.Dependencies) {
			nd := cydx.Dependency{}
			ref, found := cs.ResolveDepID(dep.Ref)
			if !found {
				log.Warnf("dependency %s not found", dep.Ref)
				continue
			}

			deps := cs.ResolveDepIDs(lo.FromPtr(dep.Dependencies))

			nd.Ref = ref
			nd.Dependencies = &deps
			newDeps = append(newDeps, nd)
		}
		return newDeps
	}))

	m.out.Metadata.Component = m.setupPrimaryComp()

	m.out.Metadata.Component.Components = &[]cydx.Component{}
	for _, c := range priComps {
		*m.out.Metadata.Component.Components = append(*m.out.Metadata.Component.Components, *c)
	}

	tools := getAllTools(m.in)
	m.out.Metadata.Tools = &cydx.ToolsChoice{
		Components: &[]cydx.Component{},
	}
	*m.out.Metadata.Tools.Components = append(*m.out.Metadata.Tools.Components, tools...)

	if m.settings.Assemble.IncludeComponents {
		m.out.Components = &[]cydx.Component{}
		for _, c := range priComps {
			*m.out.Components = append(*m.out.Components, *c)
		}
	}

	if m.settings.Assemble.IncludeDependencyGraph {
		m.out.Dependencies = &deps
	}

	return m.writeSBOM()
}

func (m *merge) hierarchicalMerge() error {
	log := logger.FromContext(*m.settings.Ctx)
	cs := newComponentService(*m.settings.Ctx)

	log.Debug("Merging BOMs hierarchically")

	priComps := lo.Map(m.in, func(bom *cydx.BOM, _ int) *cydx.Component {
		if bom.Metadata != nil && bom.Metadata.Component != nil {
			pc := cs.StoreAndCloneWithNewID(bom.Metadata.Component)

			if pc.Components == nil {
				pc.Components = &[]cydx.Component{}
			}

			for _, c := range lo.FromPtr(bom.Components) {
				*pc.Components = append(*pc.Components, *cs.StoreAndCloneWithNewID(&c))
			}
			return pc
		}
		return &cydx.Component{}
	})

	deps := lo.Flatten(lo.Map(m.in, func(bom *cydx.BOM, _ int) []cydx.Dependency {
		newDeps := []cydx.Dependency{}
		for _, dep := range lo.FromPtr(bom.Dependencies) {
			nd := cydx.Dependency{}
			ref, found := cs.ResolveDepID(dep.Ref)
			if !found {
				log.Warnf("dependency %s not found", dep.Ref)
				continue
			}

			deps := cs.ResolveDepIDs(lo.FromPtr(dep.Dependencies))

			nd.Ref = ref
			nd.Dependencies = &deps
			newDeps = append(newDeps, nd)
		}
		return newDeps
	}))

	m.out.Metadata.Component = m.setupPrimaryComp()

	tools := getAllTools(m.in)
	m.out.Metadata.Tools = &cydx.ToolsChoice{
		Components: &[]cydx.Component{},
	}
	*m.out.Metadata.Tools.Components = append(*m.out.Metadata.Tools.Components, tools...)

	//Add depedencies between new primary component and old primary components
	priIds := lo.Map(priComps, func(c *cydx.Component, _ int) string {
		return c.BOMRef
	})

	deps = append(deps, cydx.Dependency{
		Ref:          m.out.Metadata.Component.BOMRef,
		Dependencies: &priIds,
	})

	if m.settings.Assemble.IncludeComponents {
		m.out.Components = &[]cydx.Component{}
		for _, c := range priComps {
			*m.out.Components = append(*m.out.Components, *c)
		}
	}

	if m.settings.Assemble.IncludeDependencyGraph {
		m.out.Dependencies = &deps
	}

	return m.writeSBOM()
}

func (m *merge) writeSBOM() error {
	var f io.Writer

	if m.settings.Output.File == "" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.Create(m.settings.Output.File)
		if err != nil {
			return err
		}
	}

	var encoder cydx.BOMEncoder

	switch m.settings.Output.FileFormat {
	case "xml":
		encoder = cydx.NewBOMEncoder(f, cydx.BOMFileFormatXML)
	default:
		encoder = cydx.NewBOMEncoder(f, cydx.BOMFileFormatJSON)
	}

	encoder.SetPretty(true)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(m.out); err != nil {
		return err
	}

	return nil
}
