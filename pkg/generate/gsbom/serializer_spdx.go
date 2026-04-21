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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"sigs.k8s.io/release-utils/version"
)

func SerializeSPDX(ctx context.Context, bom *BOM, output string, specVersion string) error {
	log := logger.FromContext(ctx)

	// Default to 2.3 if not specified
	if specVersion == "" {
		specVersion = "2.3"
	}
	log.Debugf("serializing SPDX: version=%s, output=%s, components=%d, dependencies=%d", specVersion, output, len(bom.Components), len(bom.Dependencies))

	if specVersion == "2.2" {
		return serializeSPDX22(ctx, bom, output)
	}
	return serializeSPDX23(ctx, bom, output)
}

func serializeSPDX22(ctx context.Context, bom *BOM, output string) error {
	log := logger.FromContext(ctx)
	log.Debugf("building SPDX 2.2 document: artifact=%s@%s", bom.Artifact.Name, bom.Artifact.Version)

	doc := v2_2.Document{}

	// --- Document ---
	doc.SPDXIdentifier = common.ElementID("DOCUMENT")
	doc.DocumentName = bom.Artifact.Name
	doc.DataLicense = v2_2.DataLicense
	doc.SPDXVersion = v2_2.Version
	doc.DocumentNamespace = getDocumentNamespace(bom.Artifact.Name, bom.Components)
	doc.CreationInfo = buildCreatorInfoToolV22()
	log.Debugf("document metadata: name=%s, namespace=%s", doc.DocumentName, doc.DocumentNamespace)

	// --- Primary Package ---
	primaryPkg, primarySPDXID := buildPrimaryPackageV22(bom.Artifact)
	doc.Packages = append(doc.Packages, primaryPkg)
	log.Debugf("primary package: spdxID=%s, name=%s", primarySPDXID, primaryPkg.PackageName)

	// --- Components as Packages ---
	compIDMap := make(map[string]string)

	for _, c := range bom.Components {
		pkg, spdxID := buildSPDXPackageV22(c)
		doc.Packages = append(doc.Packages, pkg)
		compIDMap[componentKey(c)] = spdxID
	}
	log.Debugf("added %d component packages", len(bom.Components))

	// Add primary component to map for dependency resolution
	rootKey := componentKey(Component{
		Name:    bom.Artifact.Name,
		Version: bom.Artifact.Version,
	})

	compIDMap[rootKey] = primarySPDXID

	// --- Relationships ---
	var rels []*v2_2.Relationship

	// 1. Document DESCRIBES primary
	rels = append(rels, &v2_2.Relationship{
		RefA:         common.MakeDocElementID("", "DOCUMENT"),
		RefB:         common.MakeDocElementID("", primarySPDXID),
		Relationship: common.TypeRelationshipDescribe,
	})
	log.Debugf("added DESCRIBES relationship: DOCUMENT -> %s", primarySPDXID)

	// 2. Component -> dependencies (includes primary -> top-level via attachOrphansToRoot)
	relCount := 0
	for parent, children := range bom.Dependencies {
		parentID := compIDMap[parent]
		if parentID == "" {
			log.Debugf("skipping dependency: parent '%s' not found in component map", parent)
			continue
		}

		for _, child := range children {
			childID := compIDMap[child]
			if childID == "" {
				log.Debugf("skipping dependency: child '%s' not found in component map", child)
				continue
			}

			rels = append(rels, &v2_2.Relationship{
				RefA:         common.MakeDocElementID("", parentID),
				RefB:         common.MakeDocElementID("", childID),
				Relationship: common.TypeRelationshipDependsOn,
			})
			relCount++
		}
	}
	doc.Relationships = rels
	log.Debugf("added %d DEPENDS_ON relationships", relCount)

	// --- Write ---
	var writer io.Writer

	if output == "" {
		writer = os.Stdout
		log.Debugf("writing SPDX 2.2 to stdout")
	} else {
		f, err := os.Create(output)
		if err != nil {
			log.Debugf("failed to create output file: %v", err)
			return err
		}
		defer f.Close()
		writer = f
		log.Debugf("writing SPDX 2.2 to file: %s", output)
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		log.Debugf("failed to encode SPDX document: %v", err)
		return err
	}
	log.Debugf("successfully serialized SPDX 2.2 document")
	return nil
}

func buildPrimaryPackageV22(a Artifact) (*v2_2.Package, string) {
	key := componentKey(Component{Name: a.Name, Version: a.Version})
	spdxID := makeSPDXID(key)

	pkg := &v2_2.Package{
		PackageSPDXIdentifier:   common.ElementID(spdxID),
		PackageDownloadLocation: "NOASSERTION",
	}

	if a.Name != "" {
		pkg.PackageName = a.Name
	}
	if a.Version != "" {
		pkg.PackageVersion = a.Version
	}
	if a.License != "" {
		pkg.PackageLicenseConcluded = a.License
	} else {
		pkg.PackageLicenseConcluded = "NOASSERTION"
	}

	// Supplier
	if a.Supplier.Name != "" {
		pkg.PackageSupplier = &common.Supplier{
			Supplier:     a.Supplier.Name,
			SupplierType: "Organization",
		}
	} else {
		pkg.PackageSupplier = &common.Supplier{
			Supplier: "NOASSERTION",
		}
	}

	// Authors -> use Originator (SPDX field), use first author if present
	if len(a.Authors) > 0 {
		first := a.Authors[0]
		if first.Name != "" {
			originator := first.Name
			if first.Email != "" {
				originator = fmt.Sprintf("%s (%s)", first.Name, first.Email)
			}
			pkg.PackageOriginator = &common.Originator{
				Originator:     originator,
				OriginatorType: "Person",
			}
		}
	}

	// Copyright
	pkg.PackageCopyrightText = buildCopyright(a.Copyright)

	// PURL and ExternalRefs
	pkg.PackageExternalReferences = buildExternalRefsPrimaryV22(a)

	// (Optional but good) Description -> comment
	if a.Description != "" {
		pkg.PackageDescription = a.Description
	}

	return pkg, spdxID
}

func buildSPDXPackageV22(c Component) (*v2_2.Package, string) {
	key := componentKey(c)
	spdxID := makeSPDXID(key)

	pkg := &v2_2.Package{
		PackageSPDXIdentifier:   common.ElementID(spdxID),
		PackageDownloadLocation: "NOASSERTION",
	}

	if c.Name != "" {
		pkg.PackageName = c.Name
	}
	if c.Version != "" {
		pkg.PackageVersion = c.Version
	}
	if c.License != "" {
		pkg.PackageLicenseConcluded = c.License
	}
	if c.Description != "" {
		pkg.PackageDescription = c.Description
	}

	pkg.PackageExternalReferences = buildExternalRefsSPDXV22(c)
	pkg.PackageChecksums = buildChecksumsV22(c.Hashes)

	return pkg, spdxID
}

func buildExternalRefsSPDXV22(c Component) []*v2_2.PackageExternalReference {
	var refs []*v2_2.PackageExternalReference

	// Add PURL if present
	if c.PURL != "" {
		refs = append(refs, &v2_2.PackageExternalReference{
			Category: "PACKAGE-MANAGER",
			RefType:  "purl",
			Locator:  c.PURL,
		})
	}

	// Add external references
	for _, r := range c.ExternalRefs {
		refs = append(refs, &v2_2.PackageExternalReference{
			Category: mapExternalRefCategory(r.Type),
			RefType:  r.Type,
			Locator:  r.URL,
		})
	}

	return refs
}

func buildExternalRefsPrimaryV22(a Artifact) []*v2_2.PackageExternalReference {
	var refs []*v2_2.PackageExternalReference

	// Add PURL if present
	if a.PURL != "" {
		refs = append(refs, &v2_2.PackageExternalReference{
			Category: "PACKAGE-MANAGER",
			RefType:  "purl",
			Locator:  a.PURL,
		})
	}

	// Add external references from artifact
	for _, r := range a.ExternalRefs {
		refs = append(refs, &v2_2.PackageExternalReference{
			Category: mapExternalRefCategory(r.Type),
			RefType:  r.Type,
			Locator:  r.URL,
		})
	}

	return refs
}

func buildChecksumsV22(hashes []Hash) []common.Checksum {
	var out []common.Checksum

	for _, h := range hashes {
		if h.Value == "" {
			continue
		}

		out = append(out, common.Checksum{
			Algorithm: common.ChecksumAlgorithm(normalizeHashAlgorithm(h.Algorithm)),
			Value:     h.Value,
		})
	}

	return out
}

func serializeSPDX23(ctx context.Context, bom *BOM, output string) error {
	log := logger.FromContext(ctx)
	log.Debugf("building SPDX 2.3 document: artifact=%s@%s", bom.Artifact.Name, bom.Artifact.Version)

	doc := v2_3.Document{}

	// --- Document ---
	doc.SPDXIdentifier = common.ElementID("DOCUMENT")
	doc.DocumentName = bom.Artifact.Name
	doc.DataLicense = v2_3.DataLicense
	doc.SPDXVersion = v2_3.Version
	doc.DocumentNamespace = getDocumentNamespace(bom.Artifact.Name, bom.Components)
	doc.CreationInfo = buildCreatorInfoToolV23()
	log.Debugf("document metadata: name=%s, namespace=%s", doc.DocumentName, doc.DocumentNamespace)

	// --- Primary Package ---
	primaryPkg, primarySPDXID := buildPrimaryPackage(bom.Artifact)
	doc.Packages = append(doc.Packages, primaryPkg)
	log.Debugf("primary package: spdxID=%s, name=%s", primarySPDXID, primaryPkg.PackageName)

	// --- Components as Packages ---
	compIDMap := make(map[string]string)

	for _, c := range bom.Components {
		pkg, spdxID := buildSPDXPackage(c)
		doc.Packages = append(doc.Packages, pkg)
		compIDMap[componentKey(c)] = spdxID
	}
	log.Debugf("added %d component packages", len(bom.Components))

	// Add primary component to map for dependency resolution
	rootKey := componentKey(Component{
		Name:    bom.Artifact.Name,
		Version: bom.Artifact.Version,
	})

	compIDMap[rootKey] = primarySPDXID

	// --- Relationships ---
	var rels []*v2_3.Relationship

	// 1. Document DESCRIBES primary
	rels = append(rels, &v2_3.Relationship{
		RefA:         common.MakeDocElementID("", "DOCUMENT"),
		RefB:         common.MakeDocElementID("", primarySPDXID),
		Relationship: common.TypeRelationshipDescribe,
	})
	log.Debugf("added DESCRIBES relationship: DOCUMENT -> %s", primarySPDXID)

	// 2. Component -> dependencies (includes primary -> top-level via attachOrphansToRoot)
	relCount := 0
	for parent, children := range bom.Dependencies {
		parentID := compIDMap[parent]
		if parentID == "" {
			log.Debugf("skipping dependency: parent '%s' not found in component map", parent)
			continue
		}

		for _, child := range children {
			childID := compIDMap[child]
			if childID == "" {
				log.Debugf("skipping dependency: child '%s' not found in component map", child)
				continue
			}

			rels = append(rels, &v2_3.Relationship{
				RefA:         common.MakeDocElementID("", parentID),
				RefB:         common.MakeDocElementID("", childID),
				Relationship: common.TypeRelationshipDependsOn,
			})
			relCount++
		}
	}
	doc.Relationships = rels
	log.Debugf("added %d DEPENDS_ON relationships", relCount)

	// --- Write ---
	var writer io.Writer

	if output == "" {
		writer = os.Stdout
		log.Debugf("writing SPDX 2.3 to stdout")
	} else {
		f, err := os.Create(output)
		if err != nil {
			log.Debugf("failed to create output file: %v", err)
			return err
		}
		defer f.Close()
		writer = f
		log.Debugf("writing SPDX 2.3 to file: %s", output)
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		log.Debugf("failed to encode SPDX document: %v", err)
		return err
	}
	log.Debugf("successfully serialized SPDX 2.3 document")
	return nil
}

func buildPrimaryPackage(a Artifact) (*spdx.Package, string) {
	key := componentKey(Component{Name: a.Name, Version: a.Version})
	spdxID := makeSPDXID(key)

	pkg := &spdx.Package{
		PackageSPDXIdentifier:   common.ElementID(spdxID),
		PackageDownloadLocation: "NOASSERTION",
	}

	if a.Name != "" {
		pkg.PackageName = a.Name
	}
	if a.Version != "" {
		pkg.PackageVersion = a.Version
	}
	if a.License != "" {
		pkg.PackageLicenseConcluded = a.License
	} else {
		pkg.PackageLicenseConcluded = "NOASSERTION"
	}

	// Supplier
	if a.Supplier.Name != "" {
		pkg.PackageSupplier = &common.Supplier{
			Supplier:     a.Supplier.Name,
			SupplierType: "Organization",
		}
	} else {
		pkg.PackageSupplier = &common.Supplier{
			Supplier: "NOASSERTION",
		}
	}

	// Authors -> use Originator (SPDX field), use first author if present
	if len(a.Authors) > 0 {
		first := a.Authors[0]
		if first.Name != "" {
			originator := first.Name
			if first.Email != "" {
				originator = fmt.Sprintf("%s (%s)", first.Name, first.Email)
			}
			pkg.PackageOriginator = &common.Originator{
				Originator:     originator,
				OriginatorType: "Person",
			}
		}
	}

	// Copyright
	pkg.PackageCopyrightText = buildCopyright(a.Copyright)

	// PURL and ExternalRefs
	pkg.PackageExternalReferences = buildExternalRefsPrimary(a)

	// (Optional but good) Description -> comment
	if a.Description != "" {
		pkg.PackageDescription = a.Description
	}

	return pkg, spdxID
}

func buildSPDXPackage(c Component) (*spdx.Package, string) {
	key := componentKey(c)
	spdxID := makeSPDXID(key)

	pkg := &spdx.Package{
		PackageSPDXIdentifier:   common.ElementID(spdxID),
		PackageDownloadLocation: "NOASSERTION",
	}

	if c.Name != "" {
		pkg.PackageName = c.Name
	}
	if c.Version != "" {
		pkg.PackageVersion = c.Version
	}
	if c.License != "" {
		pkg.PackageLicenseConcluded = c.License
	}
	if c.Description != "" {
		pkg.PackageDescription = c.Description
	}

	pkg.PackageExternalReferences = buildExternalRefsSPDX(c)
	pkg.PackageChecksums = buildChecksums(c.Hashes)

	return pkg, spdxID
}

func buildCreatorInfoToolV23() *v2_3.CreationInfo {
	ci := v2_3.CreationInfo{}
	ci.Created = getTimestamp().Format(time.RFC3339)
	ci.Creators = []common.Creator{
		{
			CreatorType: "Tool",
			Creator:     fmt.Sprintf("sbomasm-%s", version.GetVersionInfo().GitVersion),
		},
	}
	return &ci
}

func buildCreatorInfoToolV22() *v2_2.CreationInfo {
	ci := v2_2.CreationInfo{}
	ci.Created = getTimestamp().Format(time.RFC3339)
	ci.Creators = []common.Creator{
		{
			CreatorType: "Tool",
			Creator:     fmt.Sprintf("sbomasm-%s", version.GetVersionInfo().GitVersion),
		},
	}
	return &ci
}

func buildCopyright(copyright string) string {
	if copyright != "" {
		return copyright
	} else {
		return "NOASSERTION"
	}
}

func buildExternalRefsSPDX(c Component) []*spdx.PackageExternalReference {
	var refs []*spdx.PackageExternalReference

	// Add PURL if present
	if c.PURL != "" {
		refs = append(refs, &spdx.PackageExternalReference{
			Category: "PACKAGE-MANAGER",
			RefType:  "purl",
			Locator:  c.PURL,
		})
	}

	// Add external references
	for _, r := range c.ExternalRefs {
		refs = append(refs, &spdx.PackageExternalReference{
			Category: mapExternalRefCategory(r.Type),
			RefType:  r.Type,
			Locator:  r.URL,
		})
	}

	return refs
}

// buildExternalRefsPrimary builds external refs for primary package from PURL and external refs
func buildExternalRefsPrimary(a Artifact) []*spdx.PackageExternalReference {
	var refs []*spdx.PackageExternalReference

	// Add PURL if present
	if a.PURL != "" {
		refs = append(refs, &spdx.PackageExternalReference{
			Category: "PACKAGE-MANAGER",
			RefType:  "purl",
			Locator:  a.PURL,
		})
	}

	// Add external references from artifact
	for _, r := range a.ExternalRefs {
		refs = append(refs, &spdx.PackageExternalReference{
			Category: mapExternalRefCategory(r.Type),
			RefType:  r.Type,
			Locator:  r.URL,
		})
	}

	return refs
}

func mapExternalRefCategory(refType string) string {
	switch refType {
	case "vcs":
		return "PERSISTENT-ID"
	case "issue-tracker":
		return "SECURITY"
	case "distribution":
		return "PACKAGE-MANAGER"
	case "website", "documentation", "support", "release-notes", "advisories":
		return "OTHER"
	default:
		return "OTHER"
	}
}

// normalizeHashAlgorithm converts hash algorithm names to SPDX-compliant format
// e.g., "SHA-256" -> "SHA256", "SHA-1" -> "SHA1"
func normalizeHashAlgorithm(algo string) string {
	// Remove dashes from the algorithm name
	return strings.ReplaceAll(algo, "-", "")
}

func buildChecksums(hashes []Hash) []spdx.Checksum {
	var out []spdx.Checksum

	for _, h := range hashes {
		if h.Value == "" {
			continue
		}

		out = append(out, spdx.Checksum{
			Algorithm: common.ChecksumAlgorithm(normalizeHashAlgorithm(h.Algorithm)),
			Value:     h.Value,
		})
	}

	return out
}

func sanitizeSPDXID(s string) string {
	s = strings.ToLower(s)

	// replace illegal chars
	s = strings.ReplaceAll(s, "@", "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ":", "-")

	// keep only allowed chars
	reg := regexp.MustCompile(`[^a-z0-9.\-]`)
	s = reg.ReplaceAllString(s, "-")

	return s
}

func makeSPDXID(key string) string {
	return "SPDXRef-" + sanitizeSPDXID(key)
}
