// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gsbom

import (
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	assemble "github.com/interlynk-io/sbomasm/v2/pkg/assemble/cdx"
	"sigs.k8s.io/release-utils/version"

	"io"
	"os"
)

func SerializeCycloneDX(bom *BOM, output string) error {
	out := cydx.NewBOM()
	out.SerialNumber = assemble.NewSerialNumber()

	// --- Metadata ---
	out.Metadata = &cydx.Metadata{}
	out.Metadata.Timestamp = assemble.UTCNowTime()
	out.Metadata.Tools = buildToolMetadata()
	out.Metadata.Component = buildPrimaryComponent(bom.Artifact)

	// --- Components ---
	var comps []cydx.Component

	for _, c := range bom.Components {
		comp := cydx.Component{
			Type:   mapComponentType(c.Type),
			BOMRef: getBomRef(c),
		}

		if c.Name != "" {
			comp.Name = c.Name
		}
		if c.Version != "" {
			comp.Version = c.Version
		}
		if c.PURL != "" {
			comp.PackageURL = c.PURL
		}
		if c.CPE != "" {
			comp.CPE = c.CPE
		}

		comp.Licenses = buildLicenses(c.License)  // Liceses
		comp.Supplier = buildSupplier(c.Supplier) // Supplier
		comp.Hashes = buildHashes(c.Hashes)       // Hashes

		comps = append(comps, comp)
	}

	out.Components = &comps

	// --- Dependencies ---
	var deps []cydx.Dependency

	compRefMap := make(map[string]string)
	for _, c := range bom.Components {
		compRefMap[componentKey(c)] = getBomRef(c)
	}

	// map root
	rootKey := componentKey(Component{
		Name:    bom.Artifact.Name,
		Version: bom.Artifact.Version,
	})

	rootRef := getBomRef(Component{
		Name:    bom.Artifact.Name,
		Version: bom.Artifact.Version,
		PURL:    bom.Artifact.PURL,
	})

	compRefMap[rootKey] = rootRef

	// 1. Parent -> children
	for parent, children := range bom.Dependencies {
		parentRef := compRefMap[parent]
		if parentRef == "" {
			parentRef = parent // fallback
		}

		var childRefs []string
		for _, c := range children {
			ref := compRefMap[c]
			if ref == "" {
				ref = c // fallback
			}
			childRefs = append(childRefs, ref)
		}

		if len(childRefs) == 0 {
			childRefs = []string{}
		}

		d := cydx.Dependency{
			Ref:          parentRef,
			Dependencies: &childRefs,
		}

		// d.Dependencies = &childRefs
		deps = append(deps, d)
	}

	// 2. Primary -? top-level components
	var topLevel []string
	for _, c := range bom.Components {
		if len(c.DependencyOf) == 0 {
			topLevel = append(topLevel, getBomRef(c))
		}
	}

	out.Dependencies = &deps

	// --- Write ---
	var writer io.Writer

	if output == "" {
		writer = os.Stdout
	} else {
		f, err := os.Create(output)
		if err != nil {
			return err
		}
		defer f.Close()
		writer = f
	}

	encoder := cydx.NewBOMEncoder(writer, cydx.BOMFileFormatJSON)
	encoder.SetPretty(true)

	return encoder.Encode(out)
}

func getBomRef(c Component) string {
	if c.PURL != "" {
		return c.PURL
	}
	return c.Name + "@" + c.Version
}

func buildToolMetadata() *cydx.ToolsChoice {
	return &cydx.ToolsChoice{
		Components: &[]cydx.Component{
			{
				Type:        cydx.ComponentTypeApplication,
				Name:        "sbomasm",
				Version:     version.GetVersionInfo().GitVersion,
				Description: "sbomasm: The Complete SBOM Management Toolkit",

				Supplier: &cydx.OrganizationalEntity{
					Name: "Interlynk",
					URL:  &[]string{"https://interlynk.io"},
					Contact: &[]cydx.OrganizationalContact{
						{Email: "support@interlynk.io"},
					},
				},

				Licenses: &cydx.Licenses{
					{
						License: &cydx.License{ID: "Apache-2.0"},
					},
				},
			},
		},
	}
}

func buildLicenses(license string) *cydx.Licenses {
	if license == "" {
		return nil
	}

	license = strings.TrimSpace(license)

	// detect expressions (e.g. "MIT OR Apache-2.0")
	if isLicenseExpression(license) {
		return &cydx.Licenses{
			{
				Expression: license,
			},
		}
	}

	// simple license ID
	return &cydx.Licenses{
		{
			License: &cydx.License{ID: license},
		},
	}
}

func isLicenseExpression(l string) bool {
	l = strings.ToUpper(l)

	return strings.Contains(l, " AND ") ||
		strings.Contains(l, " OR ") ||
		strings.Contains(l, " WITH ") ||
		strings.Contains(l, "(") ||
		strings.Contains(l, ")")
}

func buildHashes(hashes []Hash) *[]cydx.Hash {
	if len(hashes) == 0 {
		return nil
	}

	var out []cydx.Hash

	for _, h := range hashes {
		if h.Value == "" {
			continue
		}

		out = append(out, cydx.Hash{
			Algorithm: cydx.HashAlgorithm(h.Algorithm),
			Value:     h.Value,
		})
	}

	if len(out) == 0 {
		return nil
	}

	return &out
}

func buildPrimaryComponent(a Artifact) *cydx.Component {
	comp := cydx.Component{
		Type:   cydx.ComponentType(a.PrimaryPurpose),
		BOMRef: getBomRef(Component{Name: a.Name, Version: a.Version, PURL: a.PURL}),
	}

	if a.Name != "" {
		comp.Name = a.Name
	}
	if a.Version != "" {
		comp.Version = a.Version
	}
	if a.Description != "" {
		comp.Description = a.Description
	}
	if a.PURL != "" {
		comp.PackageURL = a.PURL
	}
	if a.CPE != "" {
		comp.CPE = a.CPE
	}

	// Supplier
	if a.Supplier.Name != "" || a.Supplier.Email != "" {
		s := cydx.OrganizationalEntity{
			Name: a.Supplier.Name,
		}
		if a.Supplier.Email != "" {
			s.Contact = &[]cydx.OrganizationalContact{
				{Email: a.Supplier.Email},
			}
		}
		comp.Supplier = &s
	}

	// License
	if a.LicenseID != "" {
		comp.Licenses = &cydx.Licenses{
			{License: &cydx.License{ID: a.LicenseID}},
		}
	}

	// Authors
	if len(a.Authors) > 0 {
		var authors []cydx.OrganizationalContact
		for _, au := range a.Authors {
			if au.Name == "" && au.Email == "" {
				continue
			}
			authors = append(authors, cydx.OrganizationalContact{
				Name:  au.Name,
				Email: au.Email,
			})
		}
		if len(authors) > 0 {
			comp.Authors = &authors
		}
	}

	// Copyright
	if a.Copyright != "" {
		comp.Copyright = a.Copyright
	}

	return &comp
}

func buildSupplier(s Supplier) *cydx.OrganizationalEntity {
	if s.Name == "" && s.Email == "" {
		return nil
	}

	entity := &cydx.OrganizationalEntity{}

	if s.Name != "" {
		entity.Name = s.Name
	}

	if s.Email != "" {
		entity.Contact = &[]cydx.OrganizationalContact{
			{Email: s.Email},
		}
	}

	return entity
}

func mapComponentType(t string) cydx.ComponentType {
	switch t {
	case "library":
		return cydx.ComponentTypeLibrary
	case "application":
		return cydx.ComponentTypeApplication
	case "framework":
		return cydx.ComponentTypeFramework
	case "container":
		return cydx.ComponentTypeContainer
	case "operating-system":
		return cydx.ComponentTypeOS
	case "file":
		return cydx.ComponentTypeFile
	case "device":
		return cydx.ComponentTypeDevice
	case "firmware":
		return cydx.ComponentTypeFirmware
	default:
		return cydx.ComponentType(cydx.ComponentDataTypeOther)
	}
}
