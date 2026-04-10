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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	spdx_assemble "github.com/interlynk-io/sbomasm/v2/pkg/assemble/spdx"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"sigs.k8s.io/release-utils/version"
)

func SerializeSPDX(bom *BOM, output string) error {
	doc := v2_3.Document{}

	// --- Document ---
	doc.SPDXIdentifier = common.ElementID("DOCUMENT")
	doc.DocumentName = bom.Artifact.Name
	doc.DataLicense = v2_3.DataLicense
	doc.SPDXVersion = v2_3.Version
	doc.DocumentNamespace = spdx_assemble.ComposeNamespace(bom.Artifact.Name)
	doc.CreationInfo = buildCreatorInfoTool()

	// --- Primary Package ---
	primaryPkg, primaryID := buildPrimaryPackage(bom.Artifact)
	doc.Packages = append(doc.Packages, primaryPkg)

	// --- Components as Packages ---
	compIDMap := make(map[string]string)

	for _, c := range bom.Components {
		pkg, id := buildSPDXPackage(c)
		doc.Packages = append(doc.Packages, pkg)
		compIDMap[componentKey(c)] = id
	}

	// --- Relationships ---
	var rels []*spdx.Relationship

	// 1. Document DESCRIBES primary
	rels = append(rels, &spdx.Relationship{
		RefA:         common.MakeDocElementID("", "DOCUMENT"),
		RefB:         common.MakeDocElementID("", primaryID),
		Relationship: common.TypeRelationshipDescribe,
	})

	// 2. Primary -> top-level components
	for _, c := range bom.Components {
		if len(c.DependencyOf) == 0 {
			childID := compIDMap[componentKey(c)]

			rels = append(rels, &spdx.Relationship{
				RefA:         common.MakeDocElementID("", primaryID),
				RefB:         common.MakeDocElementID("", childID),
				Relationship: common.TypeRelationshipDependsOn,
			})
		}
	}

	// 3. Component -> dependencies
	for parent, children := range bom.Dependencies {
		parentID := compIDMap[parent]

		for _, child := range children {
			childID := compIDMap[child]

			rels = append(rels, &spdx.Relationship{
				RefA:         common.MakeDocElementID("", parentID),
				RefB:         common.MakeDocElementID("", childID),
				Relationship: common.TypeRelationshipDependsOn,
			})
		}
	}

	doc.Relationships = rels

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

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}

func buildCreatorInfoTool() *spdx.CreationInfo {
	ci := v2_3.CreationInfo{}
	ci.Created = time.Now().UTC().Format(time.RFC3339)
	ci.Creators = []common.Creator{
		{
			CreatorType: "Tool",
			Creator:     fmt.Sprintf("sbomasm-%s", version.GetVersionInfo().GitVersion),
		},
	}
	return &ci
}

func buildExternalRefs(purl string) []*spdx.PackageExternalReference {
	if purl == "" {
		return nil
	}

	return []*spdx.PackageExternalReference{
		{
			Category: "PACKAGE-MANAGER",
			RefType:  "purl",
			Locator:  purl,
		},
	}
}

func buildSPDXPackage(c Component) (*spdx.Package, string) {
	id := "SPDXRef-" + componentKey(c)

	pkg := &spdx.Package{
		PackageSPDXIdentifier: common.ElementID(id),
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

	pkg.PackageExternalReferences = buildExternalRefs(c.PURL)
	pkg.PackageChecksums = buildChecksums(c.Hashes)

	return pkg, id
}

func buildChecksums(hashes []Hash) []spdx.Checksum {
	var out []spdx.Checksum

	for _, h := range hashes {
		if h.Value == "" {
			continue
		}

		out = append(out, spdx.Checksum{
			Algorithm: common.ChecksumAlgorithm(h.Algorithm),
			Value:     h.Value,
		})
	}

	return out
}

func buildPrimaryPackage(a Artifact) (*spdx.Package, string) {
	id := "SPDXRef-" + componentKey(Component{
		Name:    a.Name,
		Version: a.Version,
		PURL:    a.PURL,
	})

	pkg := &spdx.Package{}

	pkg.PackageSPDXIdentifier = common.ElementID(id)

	if a.Name != "" {
		pkg.PackageName = a.Name
	}
	if a.Version != "" {
		pkg.PackageVersion = a.Version
	}
	if a.LicenseID != "" {
		pkg.PackageLicenseConcluded = a.LicenseID
	}

	// PURL → ExternalRef
	pkg.PackageExternalReferences = buildExternalRefs(a.PURL)

	// (Optional but good) Description → comment
	if a.Description != "" {
		pkg.PackageDescription = a.Description
	}

	return pkg, id
}
