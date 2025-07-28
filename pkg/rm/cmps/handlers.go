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
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
	v2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func RemoveDependencies(ctx context.Context, sbomDoc sbom.SBOMDocument, selectedDependencies []interface{}) error {
	log := logger.FromContext(ctx)

	var totalSelectedDependencies int
	var totalRemovedDependencies int

	switch doc := sbomDoc.Raw().(type) {
	case *spdx.Document:

		toRemove := make(map[string]bool)
		for _, dep := range selectedDependencies {
			if depRef, ok := dep.(string); ok {
				toRemove[depRef] = true
			}
		}

		var filtered []*v2_3.Relationship
		for _, rel := range doc.Relationships {
			if !toRemove[string(rel.RefB.ElementRefID)] {
				filtered = append(filtered, rel)
			}
			totalRemovedDependencies++
		}
		doc.Relationships = filtered

	case *cydx.BOM:
		toRemove := make(map[string]bool)
		for _, dep := range selectedDependencies {
			depRef, ok := dep.(cydx.Dependency)

			if !ok {
				log.Debugf("Skipping non-CDX dependency: %T\n", dep)
				continue
			}

			totalSelectedDependencies++
			toRemove[depRef.Ref] = true
		}

		if doc.Dependencies == nil {
			return nil
		}
		var filtered []cydx.Dependency
		for _, dep := range *doc.Dependencies {
			if !toRemove[dep.Ref] {
				filtered = append(filtered, dep)
			}
			totalRemovedDependencies++
		}
		doc.Dependencies = &filtered

	default:
		return fmt.Errorf("unsupported SBOM format for dependency removal")
	}

	log.Debugf("Total selected dependencies: %d, Total removed dependencies: %d", totalSelectedDependencies, totalRemovedDependencies)
	return nil
}

func RemoveComponents(ctx context.Context, sbomDoc sbom.SBOMDocument, selectedComponents []interface{}) error {
	log := logger.FromContext(ctx)

	var totalSelectedComponents int
	var totalRemovedComponents int

	switch doc := sbomDoc.Raw().(type) {
	case *spdx.Document:
		var filtered []*v2_3.Package
		toRemove := make(map[string]bool)
		for _, comp := range selectedComponents {
			if pkg, ok := comp.(spdx.Package); ok {
				totalSelectedComponents++
				toRemove[string(pkg.PackageSPDXIdentifier)] = true
			}
		}
		for _, p := range doc.Packages {
			if !toRemove[string(p.PackageSPDXIdentifier)] {
				filtered = append(filtered, p)
			}
			totalRemovedComponents++
		}

		doc.Packages = filtered

	case *cydx.BOM:
		var filtered []cydx.Component
		toRemove := make(map[string]bool)
		for _, comp := range selectedComponents {
			totalSelectedComponents++
			if cdxComp, ok := comp.(cydx.Component); ok {
				toRemove[cdxComp.BOMRef] = true
			}
		}
		for _, c := range *doc.Components {
			if !toRemove[c.BOMRef] {
				filtered = append(filtered, c)
			}
			totalRemovedComponents++
		}
		if doc.Metadata != nil && doc.Metadata.Component != nil {
			metaRef := doc.Metadata.Component.BOMRef
			if _, ok := toRemove[metaRef]; ok {
				totalRemovedComponents++
				doc.Metadata.Component = nil
			}
		}
		doc.Components = &filtered

	default:
		return fmt.Errorf("unsupported SBOM format for component removal")
	}

	log.Debugf("Total selected components: %d, Total removed components: %d", totalSelectedComponents, totalRemovedComponents)
	return nil
}

func FindAllDependenciesForComponents(ctx context.Context, doc sbom.SBOMDocument, selectedComponents []interface{}) []interface{} {
	log := logger.FromContext(ctx)

	var totalDependencies int
	var totalSelectedDependencies int

	var dependencies []interface{}

	switch sbomDoc := doc.Raw().(type) {
	case *spdx.Document:

		pkgIDs := make(map[string]bool)
		for _, comp := range selectedComponents {
			if pkg, ok := comp.(spdx.Package); ok {
				pkgIDs[string(pkg.PackageSPDXIdentifier)] = true
			}
		}

		for _, rel := range sbomDoc.Relationships {
			totalDependencies++
			if pkgIDs[string(rel.RefA.ElementRefID)] && (rel.Relationship == "DEPENDS_ON" || rel.Relationship == "CONTAINS") {
				totalSelectedDependencies++
				dependencies = append(dependencies, string(rel.RefB.ElementRefID))
			}

			// remove describes relationships for primary components
			if rel.Relationship == "DESCRIBES" && pkgIDs[string(rel.RefB.ElementRefID)] {
				totalSelectedDependencies++
				dependencies = append(dependencies, string(rel.RefB.ElementRefID))
			}
		}
	case *cydx.BOM:

		compRefs := make(map[string]bool)
		for _, comp := range selectedComponents {
			if cdxComp, ok := comp.(cydx.Component); ok {
				compRefs[cdxComp.BOMRef] = true
			}
		}

		for _, dep := range *sbomDoc.Dependencies {
			totalDependencies++
			if compRefs[dep.Ref] {
				totalSelectedDependencies++
				dependencies = append(dependencies, dep)

				// for _, d := range *dep.Dependencies {
				// 	totalSelectedDependencies++
				// 	dependencies = append(dependencies, d)
				// }
			}
		}

	default:
		fmt.Println("Unsupported SBOM format")
	}

	log.Debugf("Total dependencies found: %d, Total selected dependencies: %d", totalDependencies, totalSelectedDependencies)

	return dependencies
}

func SelectComponents(ctx context.Context, sbomDoc sbom.SBOMDocument, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(ctx)

	var selectedComponents []interface{}
	var totalComponents int
	var totalSelectedComponents int

	switch doc := sbomDoc.Raw().(type) {
	case *spdx.Document:
		for _, p := range doc.Packages {
			totalComponents++
			if shouldSelectSPDXComponent(*p, params) {
				selectedComponents = append(selectedComponents, *p)
				totalSelectedComponents++
			}
		}
	case *cydx.BOM:
		for _, component := range *doc.Components {
			totalComponents++
			if shouldSelectCDXComponent(&component, params) {
				selectedComponents = append(selectedComponents, component)
				totalSelectedComponents++
			}
		}

		// Also check metadata.component
		if doc.Metadata != nil && doc.Metadata.Component != nil {
			totalComponents++
			if shouldSelectCDXComponent(doc.Metadata.Component, params) {
				totalSelectedComponents++
				selectedComponents = append(selectedComponents, *doc.Metadata.Component)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported SBOM format")
	}
	if len(selectedComponents) == 0 {
		return nil, fmt.Errorf("no components matched the selection criteria")
	}
	log.Infof("Total components: %d, Total selected components: %d", totalComponents, totalSelectedComponents)

	// fmt.Println("Selected components:", selectedComponents)
	return selectedComponents, nil
}

func shouldSelectSPDXComponent(pkg spdx.Package, params *types.RmParams) bool {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Checking component: %s@%s to be added to selection list", pkg.PackageName, pkg.PackageVersion)

	// Case: specific name + version
	if params.ComponentName != "" && params.ComponentVersion != "" {
		return pkg.PackageName == params.ComponentName && pkg.PackageVersion == params.ComponentVersion
	}

	// case: simply to remove all components
	if params.All && params.Field == "" && params.Value == "" {
		log.Debugf("Selecting all components from CycloneDX BOM")
		return true
	}

	// case: match field presence, key and value present
	// key is present when field is a key-value pair (e.g. field:supplier, key name, value "John Doe")
	if params.Field != "" && params.Key != "" && params.Value != "" {
		return getSPDXComponentFieldKeyValue(*params.Ctx, pkg, params.Field, params.Key) != ""
	}

	// Case: match field presence
	if params.Field != "" && params.Value == "" {
		return getSPDXPackageFieldValue(*params.Ctx, pkg, params.Field) != ""
	}

	// Case: match field + value
	if params.Field != "" && params.Value != "" {
		return strings.Contains(getSPDXPackageFieldValue(*params.Ctx, pkg, params.Field), params.Value)
	}

	// // Case: match value only (field unspecified)
	// if params.Field == "" && params.Value != "" {
	// 	return doesSPDXPackageContainValue(pkg, params.Value)
	// }
	return true
}

func shouldSelectCDXComponent(comp *cydx.Component, params *types.RmParams) bool {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Checking component: %s@%s to be added to selection list", comp.Name, comp.Version)

	// Case: to remove a single component with specific name + version
	if params.ComponentName != "" && params.ComponentVersion != "" {
		return comp.Name == params.ComponentName && comp.Version == params.ComponentVersion
	}

	// case: simply to remove all components
	if params.All && params.Field == "" && params.Value == "" {
		log.Debugf("Selecting all components from CycloneDX BOM")
		return true
	}

	// case: match field presence, key and value present
	// key is present when field is a key-value pair (e.g. field:supplier, key name, value "John Doe")
	if params.Field != "" && params.Key != "" && params.Value != "" {
		log.Debugf("Checking field presence for key and value for %s: %s", comp.Name, params.Field)
		return getCDXComponentFieldKeyValue(*params.Ctx, *comp, params.Field, params.Key) != ""
	}

	// Case: when field is present only
	if params.Field != "" && params.Value == "" {
		log.Debugf("Checking field presence for %s: %s", comp.Name, params.Field)
		return getCDXComponentFieldValue(*params.Ctx, *comp, params.Field) != ""
	}

	// Case: when field is present as well as it's direct value
	if params.Field != "" && params.Value != "" {
		log.Debugf("Checking field presence and it's value for %s: %s", comp.Name, params.Field)
		return strings.Contains(getCDXComponentFieldValue(*params.Ctx, *comp, params.Field), params.Value)
	}

	return false
}

func getSPDXPackageFieldValue(ctx context.Context, pkg spdx.Package, field string) string {
	log := logger.FromContext(ctx)
	log.Debugf("Checking field presence")

	switch strings.ToLower(field) {

	case "name":
		if pkg.PackageName != "" && pkg.PackageName != "NOASSERTION" {
			log.Debugf("Found name value for %s: %s", pkg.PackageName, pkg.PackageName)
			return pkg.PackageName
		}

	case "version":
		if pkg.PackageVersion != "" && pkg.PackageVersion != "NOASSERTION" {
			log.Debugf("Found version value for %s: %s", pkg.PackageName, pkg.PackageVersion)
			return pkg.PackageVersion
		}

	case "description":
		if pkg.PackageDescription != "" && pkg.PackageDescription != "NOASSERTION" {
			log.Debugf("Found description value for %s: %s", pkg.PackageName, pkg.PackageDescription)
			return pkg.PackageDescription
		}

	case "copyright":
		if pkg.PackageCopyrightText != "" && pkg.PackageCopyrightText != "NOASSERTION" {
			log.Debugf("Found copyright value for %s: %s", pkg.PackageName, pkg.PackageCopyrightText)
			return pkg.PackageCopyrightText
		}

	case "supplier":
		var values []string
		if pkg.PackageSupplier != nil && pkg.PackageSupplier.Supplier != "" && pkg.PackageSupplier.Supplier != "NOASSERTION" {
			values = append(values, pkg.PackageSupplier.Supplier)
		}
		if len(values) > 0 {
			log.Debugf("Found supplier values for %s: %s", pkg.PackageName, strings.Join(values, ","))
			return strings.Join(values, ",")
		}

	case "author":
		var values []string
		if pkg.PackageOriginator != nil && pkg.PackageOriginator.Originator != "" && pkg.PackageOriginator.Originator != "NOASSERTION" {
			values = append(values, pkg.PackageOriginator.Originator)
		}
		if len(values) > 0 {
			log.Debugf("Found author value for %s: %s", pkg.PackageName, strings.Join(values, ","))
			return strings.Join(values, ",")
		}

	case "type":
		if pkg.PrimaryPackagePurpose != "" && pkg.PrimaryPackagePurpose != "NOASSERTION" {
			log.Debugf("Found type value for %s: %s", pkg.PackageName, pkg.PrimaryPackagePurpose)
			return strings.ToLower(pkg.PrimaryPackagePurpose)
		}

	case "repository":
		if pkg.PackageDownloadLocation != "" && pkg.PackageDownloadLocation != "NOASSERTION" {
			log.Debugf("Found repository value for %s: %s", pkg.PackageName, pkg.PackageDownloadLocation)
			return pkg.PackageDownloadLocation
		}

	case "license":
		if pkg.PackageLicenseConcluded != "" && pkg.PackageLicenseConcluded != "NOASSERTION" {
			log.Debugf("Found license values for %s: %s", pkg.PackageName, pkg.PackageLicenseConcluded)
			return string(pkg.PackageLicenseConcluded)
		}

	case "purl":
		var values []string
		if pkg.PackageExternalReferences != nil {
			for _, ref := range pkg.PackageExternalReferences {
				if ref.RefType == "purl" && ref.Locator != "" && ref.Locator != "NOASSERTION" {
					values = append(values, ref.Locator)
				}
			}
		}
		if len(values) > 0 {
			log.Debugf("Found purl values for %s: %s", pkg.PackageName, strings.Join(values, ","))
			return strings.Join(values, ",")
		}

	case "cpe":
		var values []string
		if pkg.PackageExternalReferences != nil {
			for _, ref := range pkg.PackageExternalReferences {
				if ref.RefType == "cpe23Type" && ref.Locator != "" && ref.Locator != "NOASSERTION" {
					values = append(values, ref.Locator)
				}
			}
		}
		if len(values) > 0 {
			log.Debugf("Found CPE values for %s: %s", pkg.PackageName, strings.Join(values, ","))
			return strings.Join(values, ",")
		}

	case "hash":
		var values []string
		if pkg.PackageChecksums != nil {
			for _, ch := range pkg.PackageChecksums {
				if ch.Algorithm != "" && ch.Algorithm != "NOASSERTION" {
					values = append(values, string(ch.Algorithm))
				}
				if ch.Value != "" && ch.Value != "NOASSERTION" {
					values = append(values, ch.Value)
				}
			}
		}
		if len(values) > 0 {
			log.Debugf("Found hash values for %s: %s", pkg.PackageName, strings.Join(values, ","))
			return strings.Join(values, ",")
		}
	}
	return ""
}

func getSPDXComponentFieldKeyValue(ctx context.Context, pkg spdx.Package, field, key string) string {
	log := logger.FromContext(ctx)
	log.Debugf("Checking field presence for key and value")

	field = strings.ToLower(field)
	key = strings.ToLower(key)

	switch field {
	case "name":
		if key == "name" || key == "" {
			if pkg.PackageName != "" && pkg.PackageName != "NOASSERTION" {
				log.Debugf("Found name value for %s: %s", pkg.PackageName, pkg.PackageName)
				return pkg.PackageName
			}
		}

	case "version":
		if key == "version" || key == "" {
			if pkg.PackageVersion != "" && pkg.PackageVersion != "NOASSERTION" {
				log.Debugf("Found version value for %s: %s", pkg.PackageName, pkg.PackageVersion)
				return pkg.PackageVersion
			}
		}

	case "description":
		if key == "description" || key == "" {
			if pkg.PackageDescription != "" && pkg.PackageDescription != "NOASSERTION" {
				log.Debugf("Found description value for %s: %s", pkg.PackageName, pkg.PackageDescription)
				return pkg.PackageDescription
			}
		}

	case "copyright":
		if key == "copyright" || key == "" {
			if pkg.PackageCopyrightText != "" && pkg.PackageCopyrightText != "NOASSERTION" {
				log.Debugf("Found copyright value for %s: %s", pkg.PackageName, pkg.PackageCopyrightText)
				return pkg.PackageCopyrightText
			}
		}

	case "supplier":
		if key == "supplier" && pkg.PackageSupplier != nil && pkg.PackageSupplier.Supplier != "" && pkg.PackageSupplier.Supplier != "NOASSERTION" {
			log.Debugf("Found supplier values for %s: %s", pkg.PackageName, pkg.PackageSupplier.Supplier)
			return pkg.PackageSupplier.Supplier
		}

	case "author":
		if key == "originator" && pkg.PackageOriginator != nil && pkg.PackageOriginator.Originator != "" && pkg.PackageOriginator.Originator != "NOASSERTION" {
			log.Debugf("Found author value for %s: %s", pkg.PackageName, pkg.PackageOriginator.Originator)
			return pkg.PackageOriginator.Originator
		}

	case "type":
		if key == "type" || key == "" {
			if pkg.PrimaryPackagePurpose != "" && pkg.PrimaryPackagePurpose != "NOASSERTION" {
				log.Debugf("Found type value for %s: %s", pkg.PackageName, pkg.PrimaryPackagePurpose)
				return string(pkg.PrimaryPackagePurpose)
			}
		}

	case "repository":
		if key == "url" || key == "" {
			if pkg.PackageDownloadLocation != "" && pkg.PackageDownloadLocation != "NOASSERTION" {
				log.Debugf("Found repository value for %s: %s", pkg.PackageName, pkg.PackageDownloadLocation)
				return pkg.PackageDownloadLocation
			}
		}

	case "license":
		if key == "license" || key == "" {
			if pkg.PackageLicenseConcluded != "" && pkg.PackageLicenseConcluded != "NOASSERTION" {
				log.Debugf("Found license value for %s: %s", pkg.PackageName, pkg.PackageLicenseConcluded)
				return string(pkg.PackageLicenseConcluded)
			}
		}

	case "purl":
		if key == "purl" || key == "" {
			var values []string
			if pkg.PackageExternalReferences != nil {
				for _, ref := range pkg.PackageExternalReferences {
					if ref.RefType == "purl" && ref.Locator != "" && ref.Locator != "NOASSERTION" {
						log.Debugf("Found purl value for %s: %s", pkg.PackageName, ref.Locator)
						values = append(values, ref.Locator)
					}
				}
			}
			if len(values) > 0 {
				return strings.Join(values, ",")
			}
		}

	case "cpe":
		if key == "cpe" || key == "" {
			var values []string
			if pkg.PackageExternalReferences != nil {
				for _, ref := range pkg.PackageExternalReferences {
					if ref.RefType == "cpe23Type" && ref.Locator != "" && ref.Locator != "NOASSERTION" {
						log.Debugf("Found cpe value for %s: %s", pkg.PackageName, ref.Locator)
						values = append(values, ref.Locator)
					}
				}
			}
			if len(values) > 0 {
				return strings.Join(values, ",")
			}
		}

	case "hash":
		if pkg.PackageChecksums != nil {
			var values []string
			for _, ch := range pkg.PackageChecksums {
				if key == "alg" && ch.Algorithm != "" && ch.Algorithm != "NOASSERTION" {
					values = append(values, string(ch.Algorithm))
				}
				if key == "content" && ch.Value != "" && ch.Value != "NOASSERTION" {
					values = append(values, ch.Value)
				}
			}
			if len(values) > 0 {
				log.Debugf("Found hash values for %s: %s", pkg.PackageName, strings.Join(values, ","))
				return strings.Join(values, ",")
			}
		}
	}

	return ""
}

func getCDXComponentFieldKeyValue(ctx context.Context, comp cydx.Component, field, key string) string {
	log := logger.FromContext(ctx)
	log.Debugf("Getting field %s key %s value for %s", field, key, comp.BOMRef)

	field = strings.ToLower(field)
	key = strings.ToLower(key)

	switch field {
	case "name":
		if key == "name" || key == "" {
			log.Debugf("Found name value for %s: %s", comp.BOMRef, comp.Name)
			return comp.Name
		}

	case "version":
		if key == "version" || key == "" {
			log.Debugf("Found version value for %s: %s", comp.BOMRef, comp.Version)
			return comp.Version
		}

	case "description":
		if key == "description" || key == "" {
			log.Debugf("Found description value for %s: %s", comp.BOMRef, comp.Description)
			return comp.Description
		}

	case "copyright":
		if key == "copyright" || key == "" {
			log.Debugf("Found copyright value for %s: %s", comp.BOMRef, comp.Copyright)
			return comp.Copyright
		}

	case "supplier":
		if comp.Supplier != nil {
			switch key {
			case "name":
				log.Debugf("Found supplier name for %s: %s", comp.BOMRef, comp.Supplier.Name)
				return comp.Supplier.Name
			case "url":
				if comp.Supplier.URL != nil && len(*comp.Supplier.URL) > 0 {
					log.Debugf("Found supplier URL for %s: %s", comp.BOMRef, strings.Join(*comp.Supplier.URL, ","))
					return strings.Join(*comp.Supplier.URL, ",")
				}
			}
		}

	case "author":
		if comp.Authors != nil {
			var values []string
			for _, a := range *comp.Authors {
				switch key {
				case "name":
					if a.Name != "" {
						values = append(values, a.Name)
					}
				case "email":
					if a.Email != "" {
						values = append(values, a.Email)
					}
				}
			}
			if len(values) > 0 {
				log.Debugf("Found author values for %s: %s", comp.BOMRef, strings.Join(values, ","))
				return strings.Join(values, ",")
			}
		}

	case "type":
		if key == "type" || key == "" {
			log.Debugf("Found type value for %s: %s", comp.BOMRef, comp.Type)
			return string(comp.Type)
		}

	case "repository":
		if comp.ExternalReferences != nil {
			var values []string
			for _, ref := range *comp.ExternalReferences {
				if ref.Type == cydx.ERTypeVCS || ref.Type == cydx.ERTypeDistribution {
					if key == "url" && ref.URL != "" {
						values = append(values, ref.URL)
					}
				}
			}
			if len(values) > 0 {
				log.Debugf("Found repository values for %s: %s", comp.BOMRef, strings.Join(values, ","))
				return strings.Join(values, ",")
			}
		}

	case "license":
		if comp.Licenses != nil {
			var values []string
			for _, l := range *comp.Licenses {
				if l.License != nil {
					if key == "id" && l.License.ID != "" {
						values = append(values, l.License.ID)
					}
					if key == "name" && l.License.Name != "" {
						values = append(values, l.License.Name)
					}
				}
				if key == "expression" && l.Expression != "" {
					values = append(values, l.Expression)
				}
			}
			if len(values) > 0 {
				log.Debugf("Found license values for %s: %s", comp.BOMRef, strings.Join(values, ","))
				return strings.Join(values, ",")
			}
		}

	case "purl":
		if key == "purl" || key == "" {
			log.Debugf("Found purl value for %s: %s", comp.BOMRef, comp.PackageURL)
			return comp.PackageURL
		}

	case "cpe":
		if key == "cpe" || key == "" {
			log.Debugf("Found CPE value for %s: %s", comp.BOMRef, comp.CPE)
			return comp.CPE
		}

	case "hash":
		if comp.Hashes != nil {
			var values []string
			for _, h := range *comp.Hashes {
				if key == "alg" && h.Algorithm != "" {
					values = append(values, string(h.Algorithm))
				}
				if key == "content" && h.Value != "" {
					values = append(values, h.Value)
				}
			}
			if len(values) > 0 {
				log.Debugf("Found hash values for %s: %s", comp.BOMRef, strings.Join(values, ","))
				return strings.Join(values, ",")
			}
		}
	}

	return ""
}

func getCDXComponentFieldValue(ctx context.Context, comp cydx.Component, field string) string {
	log := logger.FromContext(ctx)

	switch strings.ToLower(field) {

	case "name":
		if comp.Name != "" {
			log.Debugf("Found name value for %s: %s", comp.BOMRef, comp.Name)
			return comp.Name
		}

	case "version":
		if comp.Version != "" {
			log.Debugf("Found version value for %s: %s", comp.BOMRef, comp.Version)
			return comp.Version
		}

	case "description":
		if comp.Description != "" {
			log.Debugf("Found description value for %s: %s", comp.BOMRef, comp.Description)
			return comp.Description
		}

	case "copyright":
		if comp.Copyright != "" {
			log.Debugf("Found copyright value for %s: %s", comp.BOMRef, comp.Copyright)
			return comp.Copyright
		}

	case "supplier":
		var values []string
		if comp.Supplier != nil {
			if comp.Supplier.Name != "" {
				values = append(values, comp.Supplier.Name)
			}
			if len(*comp.Supplier.URL) > 0 {
				values = append(values, (*comp.Supplier.URL)...)
			}
		}
		if len(values) > 0 {
			log.Debugf("Found supplier values for %s: %s", comp.BOMRef, strings.Join(values, ","))
			return strings.Join(values, ",")
		}

	case "author":
		var values []string
		if comp.Authors != nil {
			for _, a := range *comp.Authors {
				if a.Name != "" {
					values = append(values, a.Name)
				}
				if a.Email != "" {
					values = append(values, a.Email)
				}
			}
		}
		if len(values) > 0 {
			log.Debugf("Found author values for %s: %s", comp.BOMRef, strings.Join(values, ","))
			return strings.Join(values, ",")
		}

	case "type":
		if comp.Type != "" {
			log.Debugf("Found type value for %s: %s", comp.BOMRef, comp.Type)
			return string(comp.Type)
		}

	case "repository":
		var values []string
		if comp.ExternalReferences != nil {
			for _, ref := range *comp.ExternalReferences {
				if ref.Type == cydx.ERTypeVCS || ref.Type == cydx.ERTypeDistribution {
					if ref.URL != "" {
						values = append(values, ref.URL)
					}
				}
			}
		}
		if len(values) > 0 {
			log.Debugf("Found repository values for %s: %s", comp.BOMRef, strings.Join(values, ","))
			return strings.Join(values, ",")
		}

	case "license":
		var values []string
		if comp.Licenses != nil {
			for _, l := range *comp.Licenses {
				if l.License != nil {
					if l.License.ID != "" {
						values = append(values, l.License.ID)
					}
					if l.License.Name != "" {
						values = append(values, l.License.Name)
					}
				}
				if l.Expression != "" {
					values = append(values, l.Expression)
				}
			}
		}
		if len(values) > 0 {
			log.Debugf("Found license values for %s: %s", comp.BOMRef, strings.Join(values, ","))
			return strings.Join(values, ",")
		}

	case "purl":
		if comp.PackageURL != "" {
			log.Debugf("Found purl value for %s: %s", comp.BOMRef, comp.PackageURL)
			return comp.PackageURL
		}

	case "cpe":
		if comp.CPE != "" {
			log.Debugf("Found CPE value for %s: %s", comp.BOMRef, comp.CPE)
			return comp.CPE
		}

	case "hash":
		var values []string
		if comp.Hashes != nil {
			for _, h := range *comp.Hashes {
				if h.Algorithm != "" {
					values = append(values, string(h.Algorithm))
				}
				if h.Value != "" {
					values = append(values, h.Value)
				}
			}
		}
		if len(values) > 0 {
			log.Debugf("Found hash values for %s: %s", comp.BOMRef, strings.Join(values, ","))
			return strings.Join(values, ",")
		}
	}
	return ""
}
