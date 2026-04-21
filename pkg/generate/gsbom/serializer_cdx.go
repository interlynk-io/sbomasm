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
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"sigs.k8s.io/release-utils/version"
)

var allowedHashes = map[string]bool{
	"SHA-1":   true,
	"SHA-256": true,
	"SHA-384": true,
	"SHA-512": true,
	"MD5":     true,
}

func SerializeCycloneDX(ctx context.Context, bom *BOM, output string, specVersion string) error {
	log := logger.FromContext(ctx)
	log.Debugf("serializing CycloneDX: output=%s, specVersion=%s, components=%d, dependencies=%d", output, specVersion, len(bom.Components), len(bom.Dependencies))

	out := cydx.NewBOM()
	out.SerialNumber = getSerialNumber(bom.Components)
	log.Debugf("generated serial number: %s", out.SerialNumber)

	// Build at latest version (1.6), then use EncodeVersion for conversion
	// This ensures proper field stripping for lower versions
	out.SpecVersion = cydx.SpecVersion1_6

	// Determine target version for encoding
	targetVersion := cydx.SpecVersion1_6
	if specVersion != "" {
		switch specVersion {
		case "1.4":
			targetVersion = cydx.SpecVersion1_4
			log.Debugf("targeting CycloneDX 1.4")
		case "1.5":
			targetVersion = cydx.SpecVersion1_5
			log.Debugf("targeting CycloneDX 1.5")
		case "1.6":
			targetVersion = cydx.SpecVersion1_6
			log.Debugf("targeting CycloneDX 1.6")
		default:
			log.Debugf("unknown spec version '%s', defaulting to 1.6", specVersion)
		}
	} else {
		log.Debugf("no spec version specified, defaulting to 1.6")
	}

	// --- Metadata ---
	out.Metadata = &cydx.Metadata{}
	out.Metadata.Timestamp = getTimestamp().Format(time.RFC3339)
	out.Metadata.Tools = buildToolMetadata()
	out.Metadata.Component = buildPrimaryComponent(bom.Artifact)
	out.Metadata.Lifecycles = buildLifecycles(bom.Artifact.Lifecycles)
	log.Debugf("metadata: artifact=%s@%s, primaryComponent=%s", bom.Artifact.Name, bom.Artifact.Version, out.Metadata.Component.BOMRef)

	// --- Components ---
	var comps []cydx.Component

	// Check for bom-ref collisions before building components
	bomRefSet := make(map[string]bool)
	for _, c := range bom.Components {
		bomRef := getBomRef(c)
		if bomRefSet[bomRef] {
			return fmt.Errorf("bom-ref collision: multiple components resolve to '%s'", bomRef)
		}
		bomRefSet[bomRef] = true
	}

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
		if c.Description != "" {
			comp.Description = c.Description
		}
		if c.PURL != "" {
			comp.PackageURL = c.PURL
		}
		if c.CPE != "" {
			comp.CPE = c.CPE
		}
		if c.Scope != "" {
			comp.Scope = cydx.Scope(c.Scope)
		}

		comp.Licenses = buildLicenses(c.License)
		comp.Supplier = buildSupplier(c.Supplier)
		comp.Hashes = buildHashes(c.Hashes)
		comp.ExternalReferences = buildExternalRefsCDX(c.ExternalRefs)
		comp.Pedigree = buildPedigree(c.Pedigree)

		comps = append(comps, comp)
		log.Debugf("added component: name=%s, version=%s, bomRef=%s", comp.Name, comp.Version, comp.BOMRef)
	}

	out.Components = &comps
	log.Debugf("total components: %d", len(comps))

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
	log.Debugf("root component mapped: key=%s, ref=%s", rootKey, rootRef)

	// 1. Parent -> children
	depCount := 0
	for parent, children := range bom.Dependencies {
		parentRef := compRefMap[parent]
		if parentRef == "" {
			log.Debugf("parent not found in ref map, using fallback: %s", parent)
			parentRef = parent // fallback
		}

		var childRefs []string
		for _, c := range children {
			ref := compRefMap[c]
			if ref == "" {
				log.Debugf("child not found in ref map, using fallback: %s", c)
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

		deps = append(deps, d)
		depCount += len(childRefs)
		log.Debugf("dependency: %s -> %v", parentRef, childRefs)
	}

	// 2. Primary -> top-level components (components with no parent in dependency graph)
	// These are components not referenced by any other component and have no depends-on
	var topLevel []string
	referenced := make(map[string]bool)

	// Find all components that are children of someone
	for _, children := range bom.Dependencies {
		for _, child := range children {
			referenced[child] = true
		}
	}

	// Add components that are not referenced by anyone and have no depends-on
	for _, c := range bom.Components {
		key := componentKey(c)
		if len(c.DependsOn) == 0 && !referenced[key] {
			topLevel = append(topLevel, getBomRef(c))
		}
	}

	// Add primary -> top-level dependencies if root doesn't already have dependencies
	if len(topLevel) > 0 && len(bom.Dependencies[rootKey]) == 0 {
		d := cydx.Dependency{
			Ref:          rootRef,
			Dependencies: &topLevel,
		}
		deps = append(deps, d)
		log.Debugf("added primary top-level dependencies: %s -> %d components", rootRef, len(topLevel))
	}

	out.Dependencies = &deps
	log.Debugf("total dependency entries: %d, total dependsOn relationships: %d", len(deps), depCount)

	// --- Write ---
	var writer io.Writer

	if output == "" {
		writer = os.Stdout
		log.Debugf("writing CycloneDX to stdout")
	} else {
		f, err := os.Create(output)
		if err != nil {
			log.Debugf("failed to create output file: %v", err)
			return err
		}
		defer f.Close()
		writer = f
		log.Debugf("writing CycloneDX to file: %s", output)
	}

	encoder := cydx.NewBOMEncoder(writer, cydx.BOMFileFormatJSON)
	encoder.SetPretty(true)

	// Use EncodeVersion to properly convert between spec versions
	// This strips fields not supported in the target version
	if err := encoder.EncodeVersion(out, targetVersion); err != nil {
		log.Debugf("failed to encode CycloneDX document: %v", err)
		return err
	}
	log.Debugf("successfully serialized CycloneDX document")
	return nil
}

func getBomRef(c Component) string {
	if c.PURL != "" {
		return c.PURL
	}
	return "pkg:generic/" + sanitizeName(c.Name) + "@" + c.Version
}

// sanitizeName sanitizes a component name for use in a bom-ref.
// Replaces spaces and special characters with hyphens.
func sanitizeName(name string) string {
	// Simple sanitization: replace spaces with hyphens
	// and remove any characters that aren't alphanumeric, hyphen, or dot
	result := strings.ReplaceAll(name, " ", "-")
	var sanitized []rune
	for _, r := range result {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' {
			sanitized = append(sanitized, r)
		} else {
			sanitized = append(sanitized, '-')
		}
	}
	return string(sanitized)
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

		algo := strings.ToUpper(strings.TrimSpace(h.Algorithm))

		if !allowedHashes[algo] {
			fmt.Printf("Warning: skipping unsupported hash algorithm: %s\n", h.Algorithm)
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
	if a.Supplier.Name != "" || a.Supplier.Email != "" || a.Supplier.URL != "" {
		s := cydx.OrganizationalEntity{
			Name: a.Supplier.Name,
		}
		if a.Supplier.URL != "" {
			s.URL = &[]string{a.Supplier.URL}
		}
		if a.Supplier.Email != "" {
			s.Contact = &[]cydx.OrganizationalContact{
				{Email: a.Supplier.Email},
			}
		}
		comp.Supplier = &s
	}

	// License
	if a.License != "" {
		comp.Licenses = &cydx.Licenses{
			{License: &cydx.License{ID: a.License}},
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

	// ExternalRefs
	comp.ExternalReferences = buildExternalRefsCDX(a.ExternalRefs)

	return &comp
}

func buildSupplier(s Supplier) *cydx.OrganizationalEntity {
	if s.Name == "" && s.Email == "" && s.URL == "" {
		return nil
	}

	entity := &cydx.OrganizationalEntity{}

	if s.Name != "" {
		entity.Name = s.Name
	}

	if s.URL != "" {
		entity.URL = &[]string{s.URL}
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

func buildExternalRefsCDX(refs []ExternalRef) *[]cydx.ExternalReference {
	if len(refs) == 0 {
		return nil
	}

	var out []cydx.ExternalReference

	for _, r := range refs {
		out = append(out, cydx.ExternalReference{
			Type:    cydx.ExternalReferenceType(r.Type),
			URL:     r.URL,
			Comment: r.Comment,
		})
	}

	return &out
}

func buildLifecycles(lifecycles []Lifecycle) *[]cydx.Lifecycle {
	if len(lifecycles) == 0 {
		return nil
	}

	var out []cydx.Lifecycle
	for _, l := range lifecycles {
		if l.Phase == "" {
			continue
		}
		out = append(out, cydx.Lifecycle{
			Phase: cydx.LifecyclePhase(l.Phase),
		})
	}

	if len(out) == 0 {
		return nil
	}

	return &out
}

func buildPedigree(p *Pedigree) *cydx.Pedigree {
	if p == nil {
		return nil
	}

	ped := &cydx.Pedigree{}

	// Ancestors
	for _, a := range p.Ancestors {
		if a.PURL != "" {
			comp := cydx.Component{PackageURL: a.PURL}
			if ped.Ancestors == nil {
				ped.Ancestors = &[]cydx.Component{}
			}
			*ped.Ancestors = append(*ped.Ancestors, comp)
		}
	}

	// Descendants
	for _, d := range p.Descendants {
		if d.PURL != "" {
			comp := cydx.Component{PackageURL: d.PURL}
			if ped.Descendants == nil {
				ped.Descendants = &[]cydx.Component{}
			}
			*ped.Descendants = append(*ped.Descendants, comp)
		}
	}

	// Variants
	for _, v := range p.Variants {
		if v.PURL != "" {
			comp := cydx.Component{PackageURL: v.PURL}
			if ped.Variants == nil {
				ped.Variants = &[]cydx.Component{}
			}
			*ped.Variants = append(*ped.Variants, comp)
		}
	}

	// Commits
	for _, c := range p.Commits {
		if c.UID != "" || c.URL != "" {
			commit := &cydx.Commit{
				UID: c.UID,
				URL: c.URL,
			}
			if ped.Commits == nil {
				ped.Commits = &[]cydx.Commit{}
			}
			*ped.Commits = append(*ped.Commits, *commit)
		}
	}

	// Patches
	for _, patch := range p.Patches {
		p := cydx.Patch{
			Type: cydx.PatchType(patch.Type),
		}

		// Diff
		if patch.Diff.Text != "" || patch.Diff.URL != "" {
			p.Diff = &cydx.Diff{
				URL: patch.Diff.URL,
			}
			if patch.Diff.Text != "" {
				p.Diff.Text = &cydx.AttachedText{
					Content: patch.Diff.Text,
				}
			}
		}

		// Resolves
		for _, r := range patch.Resolves {
			if r.Type != "" || r.Name != "" {
				issue := cydx.Issue{
					Type: cydx.IssueType(r.Type),
					Name: r.Name,
				}
				if p.Resolves == nil {
					p.Resolves = &[]cydx.Issue{}
				}
				*p.Resolves = append(*p.Resolves, issue)
			}
		}

		if ped.Patches == nil {
			ped.Patches = &[]cydx.Patch{}
		}
		*ped.Patches = append(*ped.Patches, p)
	}

	// Notes
	if p.Notes != "" {
		ped.Notes = p.Notes
	}

	// Return nil if pedigree is empty
	if (ped.Ancestors == nil || len(*ped.Ancestors) == 0) &&
		(ped.Descendants == nil || len(*ped.Descendants) == 0) &&
		(ped.Variants == nil || len(*ped.Variants) == 0) &&
		(ped.Commits == nil || len(*ped.Commits) == 0) &&
		(ped.Patches == nil || len(*ped.Patches) == 0) &&
		ped.Notes == "" {
		return nil
	}

	return ped
}
