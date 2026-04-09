package gsbom

import (
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

func SerializeSPDX(bom *BOM, output string) error {
	doc := &spdx.Document{}

	// --- Document ---
	doc.SPDXIdentifier = "SPDXRef-DOCUMENT"
	doc.DocumentName = bom.Artifact.Name
	doc.DataLicense = "CC0-1.0"

	doc.CreationInfo = &spdx.CreationInfo{
		Created: time.Now().Format(time.RFC3339),
		Creators: []common.Creator{
			{Creator: "Tool: sbomasm"},
		},
	}

	// --- Primary Package ---
	primaryID := "SPDXRef-" + componentKey(Component{
		Name:    bom.Artifact.Name,
		Version: bom.Artifact.Version,
	})

	primaryPkg := &spdx.Package{
		PackageName:             bom.Artifact.Name,
		PackageVersion:          bom.Artifact.Version,
		PackageSPDXIdentifier:   common.ElementID(primaryID),
		PackageDownloadLocation: "NOASSERTION",
	}

	doc.Packages = append(doc.Packages, primaryPkg)

	// --- Components as Packages ---
	compIDMap := make(map[string]string)

	for _, c := range bom.Components {
		id := "SPDXRef-" + componentKey(c)

		pkg := &spdx.Package{
			PackageName:             c.Name,
			PackageVersion:          c.Version,
			PackageSPDXIdentifier:   common.ElementID(id),
			PackageDownloadLocation: "NOASSERTION",
		}

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

	// 2. Primary → top-level components
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

	// 3. Component → dependencies
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
