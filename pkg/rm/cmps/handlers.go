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

package cmps

import (
	"context"
	"fmt"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
)

func SelectComponents(ctx context.Context, sbomDoc sbom.SBOMDocument, params *types.RmParams) ([]interface{}, error) {
	var selectedComponents []interface{}

	switch doc := sbomDoc.Raw().(type) {
	case *spdx.Document:
		for _, p := range doc.Packages {
			if shouldSelectSPDXComponent(*p, params) {
				selectedComponents = append(selectedComponents, *p)
			}
		}
	case *cydx.BOM:
		for _, component := range *doc.Components {
			if shouldSelectCDXComponent(&component, params) {
				selectedComponents = append(selectedComponents, component)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported SBOM format")
	}
	if len(selectedComponents) == 0 {
		return nil, fmt.Errorf("no components matched the selection criteria")
	}
	fmt.Printf("Selected %d components based on criteria: %+v\n", len(selectedComponents), params)
	fmt.Println("Selected components:", selectedComponents)
	return selectedComponents, nil
}

func shouldSelectSPDXComponent(pkg spdx.Package, params *types.RmParams) bool {
	// Case: specific name + version
	if params.ComponentName != "" && params.ComponentVersion != "" {
		return pkg.PackageName == params.ComponentName && pkg.PackageVersion == params.ComponentVersion
	}

	// Case: -a is true and no specific filters
	if params.All && params.Field == "" && params.Value == "" {
		return true
	}

	// Case: match field presence
	if params.Field != "" && params.Value == "" {
		return getSPDXPackageFieldValue(pkg, params.Field) != ""
	}

	// Case: match field + value
	if params.Field != "" && params.Value != "" {
		return getSPDXPackageFieldValue(pkg, params.Field) == params.Value
	}

	// Case: match value only (field unspecified)
	if params.Field == "" && params.Value != "" {
		return doesSPDXPackageContainValue(pkg, params.Value)
	}
	return true
}

func shouldSelectCDXComponent(comp *cydx.Component, params *types.RmParams) bool {
	// Case: specific name + version
	if params.ComponentName != "" && params.ComponentVersion != "" {
		return comp.Name == params.ComponentName && comp.Version == params.ComponentVersion
	}

	// Case: -a is true and no specific filters
	if params.All && params.Field == "" && params.Value == "" {
		return true
	}

	// Case: match field presence
	if params.Field != "" && params.Value == "" {
		return getCDXComponentFieldValue(*comp, params.Field) != ""
	}

	// Case: match field + value
	if params.Field != "" && params.Value != "" {
		return getCDXComponentFieldValue(*comp, params.Field) == params.Value
	}

	// Case: match value only (field unspecified)
	if params.Field == "" && params.Value != "" {
		return doesCDXComponentContainValue(*comp, params.Field, params.Value)
	}

	return false
}

func doesSPDXPackageContainValue(pkg spdx.Package, value string) bool {
	fieldValue := getSPDXPackageFieldValue(pkg, "name")

	values := strings.Split(fieldValue, ",")
	for _, v := range values {
		if strings.TrimSpace(v) == value {
			return true
		}
	}
	return false
}

func doesCDXComponentContainValue(comp cydx.Component, field, value string) bool {
	fieldValue := getCDXComponentFieldValue(comp, field)

	values := strings.Split(fieldValue, ",")
	for _, v := range values {
		if strings.TrimSpace(v) == value {
			return true
		}
	}
	return false
}

func getSPDXPackageFieldValue(pkg spdx.Package, field string) string {
	switch strings.ToLower(field) {
	case "name":
		return pkg.PackageName
	case "version":
		return pkg.PackageVersion
	case "description":
		return pkg.PackageDescription
	case "copyright":
		return pkg.PackageCopyrightText
	case "supplier":
		if pkg.PackageSupplier != nil {
			return pkg.PackageSupplier.Supplier
		}
	case "type":
		return string(pkg.PrimaryPackagePurpose)
	case "repository":
		return pkg.PackageDownloadLocation
	case "license":
		return string(pkg.PackageLicenseConcluded)
	case "purl":
		var purls []string
		for _, ref := range pkg.PackageExternalReferences {
			if ref.RefType == "purl" {
				purls = append(purls, ref.Locator)
			}
		}
		if len(purls) > 0 {
			return strings.Join(purls, ", ")
		}
	case "cpe":
		var cpes []string
		for _, ref := range pkg.PackageExternalReferences {
			if ref.RefType == "cpe23Type" {
				cpes = append(cpes, ref.Locator)
			}
		}
		if len(cpes) > 0 {
			return strings.Join(cpes, ", ")
		}
	case "hash":
		var hashes []string
		for _, ch := range pkg.PackageChecksums {
			hashes = append(hashes, fmt.Sprintf("%s (%s)", ch.Algorithm, ch.Value))
		}
		if len(hashes) > 0 {
			return strings.Join(hashes, ",")
		}
	}
	return ""
}

func getCDXComponentFieldValue(comp cydx.Component, field string) string {
	switch strings.ToLower(field) {
	case "name":
		return comp.Name
	case "version":
		return comp.Version
	case "description":
		return comp.Description
	case "copyright":
		return comp.Copyright
	case "supplier":
		if comp.Supplier != nil {
			return comp.Supplier.Name
		}
	case "author":
		var authors []string
		for _, a := range *comp.Authors {
			authors = append(authors, a.Name)
		}
		if len(authors) > 0 {
			return strings.Join(authors, ",")
		}
	case "type":
		return string(comp.Type)
	case "repository":
		var repos []string
		for _, ext := range *comp.ExternalReferences {
			if ext.Type == cydx.ERTypeVCS {
				repos = append(repos, ext.URL)
			}
		}
		if len(repos) > 0 {
			return strings.Join(repos, ",")
		}
	case "license":
		var licenses []string
		for _, l := range *comp.Licenses {
			if l.License != nil {
				licenses = append(licenses, l.License.ID)
			}
		}
		if len(licenses) > 0 {
			return strings.Join(licenses, ",")
		}
	case "purl":
		return comp.PackageURL
	case "cpe":
		return comp.CPE
	case "hash":
		var hashes []string
		for _, h := range *comp.Hashes {
			hashes = append(hashes, fmt.Sprintf("%s (%s)", h.Algorithm, h.Value))
		}
		if len(hashes) > 0 {
			return strings.Join(hashes, ",")
		}
	}
	return ""
}
