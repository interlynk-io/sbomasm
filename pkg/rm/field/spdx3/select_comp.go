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

package spdx3

import (
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/rm/types"
	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

func componentPkg(comp interface{}) *spdx.Package {
	pkg, ok := comp.(*spdx.Package)
	if !ok {
		return nil
	}
	return pkg
}

func SelectHashFromComponent(doc *parse.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}

	for _, comp := range params.SelectedComponents {
		pkg := componentPkg(comp)
		if pkg == nil {
			continue
		}
		for _, vm := range pkg.VerifiedUsing {
			if hash, ok := vm.(*spdx.Hash); ok {
				selected = append(selected, ComponentHashEntry{Component: pkg, Hash: hash})
			} else if hash, ok := vm.(spdx.Hash); ok {
				selected = append(selected, ComponentHashEntry{Component: pkg, Hash: &hash})
			}
		}
	}

	log.Debugf("Selected %d hash entries from components", len(selected))
	return selected, nil
}

func SelectPurlFromComponent(doc *parse.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}

	for _, comp := range params.SelectedComponents {
		pkg := componentPkg(comp)
		if pkg == nil {
			continue
		}
		for i := range pkg.ExternalIdentifier {
			if pkg.ExternalIdentifier[i].ExternalIdentifierType == spdx.ExternalIdentifierTypePackageUrl {
				selected = append(selected, ComponentExternalIdentifierEntry{
					Component: pkg,
					ExtId:     &pkg.ExternalIdentifier[i],
				})
			}
		}
	}

	log.Debugf("Selected %d PURL entries from components", len(selected))
	return selected, nil
}

func SelectCpeFromComponent(doc *parse.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}

	for _, comp := range params.SelectedComponents {
		pkg := componentPkg(comp)
		if pkg == nil {
			continue
		}
		for i := range pkg.ExternalIdentifier {
			et := pkg.ExternalIdentifier[i].ExternalIdentifierType
			if et == spdx.ExternalIdentifierTypeCpe22 || et == spdx.ExternalIdentifierTypeCpe23 {
				selected = append(selected, ComponentExternalIdentifierEntry{
					Component: pkg,
					ExtId:     &pkg.ExternalIdentifier[i],
				})
			}
		}
	}

	log.Debugf("Selected %d CPE entries from components", len(selected))
	return selected, nil
}

func SelectRepoFromComponent(doc *parse.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}

	for _, comp := range params.SelectedComponents {
		pkg := componentPkg(comp)
		if pkg == nil {
			continue
		}
		for i := range pkg.ExternalRef {
			if pkg.ExternalRef[i].ExternalRefType == spdx.ExternalRefTypeVcs {
				selected = append(selected, ComponentExternalRefEntry{
					Component: pkg,
					ExtRef:    &pkg.ExternalRef[i],
				})
			}
		}
	}

	log.Debugf("Selected %d repository entries from components", len(selected))
	return selected, nil
}

func SelectLicenseFromComponent(doc *parse.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}

	for _, comp := range params.SelectedComponents {
		pkg := componentPkg(comp)
		if pkg == nil {
			continue
		}
		for _, rel := range doc.GetRelationshipsFrom(pkg.SpdxID) {
			if rel.IsConcludedLicense() {
				for _, to := range rel.To {
					lic := doc.GetAnyLicenseInfoByID(to.GetSpdxID())
					expr := ""
					if lic != nil {
						expr = lic.SpdxID
					}
					selected = append(selected, ComponentLicenseEntry{
						Component:    pkg,
						Relationship: rel,
						LicenseExpr:  expr,
					})
				}
			}
		}
	}

	log.Debugf("Selected %d license entries from components", len(selected))
	return selected, nil
}

func SelectTypeFromComponent(doc *parse.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}

	for _, comp := range params.SelectedComponents {
		pkg := componentPkg(comp)
		if pkg == nil {
			continue
		}
		for _, p := range pkg.AdditionalPurpose {
			selected = append(selected, ComponentTypeEntry{Component: pkg, Value: string(p)})
		}
		if pkg.PrimaryPurpose != "" {
			selected = append(selected, ComponentTypeEntry{Component: pkg, Value: string(pkg.PrimaryPurpose)})
		}
	}

	log.Debugf("Selected %d type entries from components", len(selected))
	return selected, nil
}

func SelectDescriptionFromComponent(doc *parse.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}

	for _, comp := range params.SelectedComponents {
		pkg := componentPkg(comp)
		if pkg == nil {
			continue
		}
		if pkg.Description != "" {
			selected = append(selected, ComponentDescriptionEntry{Component: pkg, Value: pkg.Description})
		}
	}

	log.Debugf("Selected %d description entries from components", len(selected))
	return selected, nil
}

func SelectCopyrightFromComponent(doc *parse.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}

	for _, comp := range params.SelectedComponents {
		pkg := componentPkg(comp)
		if pkg == nil {
			continue
		}
		if pkg.CopyrightText != "" {
			selected = append(selected, ComponentCopyrightEntry{Component: pkg, Value: pkg.CopyrightText})
		}
	}

	log.Debugf("Selected %d copyright entries from components", len(selected))
	return selected, nil
}

func SelectAuthorFromComponent(doc *parse.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}

	for _, comp := range params.SelectedComponents {
		pkg := componentPkg(comp)
		if pkg == nil {
			continue
		}
		for i := range pkg.OriginatedBy {
			spdxID := pkg.OriginatedBy[i].SpdxID
			if person := doc.GetPersonByID(spdxID); person != nil {
				selected = append(selected, ComponentAuthorEntry{
					Component: pkg,
					Person:    person,
					AgentIdx:  i,
				})
			}
		}
	}

	log.Debugf("Selected %d author entries from components", len(selected))
	return selected, nil
}

func SelectSupplierFromComponent(doc *parse.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}

	for _, comp := range params.SelectedComponents {
		pkg := componentPkg(comp)
		if pkg == nil {
			continue
		}
		if pkg.SuppliedBy != nil {
			spdxID := pkg.SuppliedBy.SpdxID
			if org := doc.GetOrganizationByID(spdxID); org != nil {
				selected = append(selected, ComponentSupplierEntry{
					Component: pkg,
					Org:       org,
				})
			}
		}
	}

	log.Debugf("Selected %d supplier entries from components", len(selected))
	return selected, nil
}
