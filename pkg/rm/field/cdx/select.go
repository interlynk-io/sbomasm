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
	"context"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

func SelectAuthorFromMetadata(ctx context.Context, bom *cydx.BOM) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Selecting authors from metadata")

	if bom.Metadata.Authors == nil || len(*bom.Metadata.Authors) == 0 {
		return nil, nil
	}
	log.Debugf("Selecting authors from metadata: %v", bom.Metadata.Authors)

	return []interface{}{*bom.Metadata.Authors}, nil
}

func SelectSupplierFromMetadata(ctx context.Context, bom *cydx.BOM) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Selecting supplier from metadata")

	if bom.Metadata.Supplier == nil {
		return nil, nil
	}
	log.Debugf("Selecting supplier from metadata: %v", bom.Metadata.Supplier)
	return []interface{}{*bom.Metadata.Supplier}, nil
}

func SelectTimestampFromMetadata(ctx context.Context, bom *cydx.BOM) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Selecting timestamp from metadata")

	if bom.Metadata.Timestamp == "" {
		return nil, nil
	}

	log.Debugf("Selecting timestamp from metadata: %v", bom.Metadata.Timestamp)
	return []interface{}{bom.Metadata.Timestamp}, nil
}

func SelectToolFromMetadata(ctx context.Context, bom *cydx.BOM) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Selecting tool from metadata")

	log.Debugf("Selecting tools from metadata")
	if bom.Metadata.Tools == nil {
		return nil, nil
	}

	if bom.Metadata.Tools.Components != nil {
		log.Debugf("Selected tools from metadata: %v", bom.Metadata.Tools.Components)
		return []interface{}{*bom.Metadata.Tools.Components}, nil
	}

	if bom.Metadata.Tools.Tools != nil {
		log.Debugf("Selected tools from metadata: %v", bom.Metadata.Tools.Tools)
		return []interface{}{*bom.Metadata.Tools.Tools}, nil
	}

	return nil, nil
}

func SelectLicenseFromMetadata(ctx context.Context, bom *cydx.BOM) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Selecting licenses from metadata")

	if bom.Metadata.Licenses == nil {
		return nil, nil
	}

	var selected []interface{}
	for _, licenseChoice := range *bom.Metadata.Licenses {
		selected = append(selected, licenseChoice)
	}

	log.Debugf("Selected licenses from metadata: %v", selected)
	return selected, nil
}

func SelectLifecycleFromMetadata(ctx context.Context, bom *cydx.BOM) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Selecting lifecycles from metadata")

	if bom.Metadata.Lifecycles == nil {
		return nil, nil
	}

	log.Debugf("Selected lifecycles from metadata: %v", *bom.Metadata.Lifecycles)
	return []interface{}{*bom.Metadata.Lifecycles}, nil
}

func SelectRepositoryFromMetadata(ctx context.Context, bom *cydx.BOM) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Selecting repository from metadata")

	if bom.ExternalReferences == nil || len(*bom.ExternalReferences) == 0 {
		return nil, nil
	}

	log.Debugf("Selected repositories from metadata: %v", bom.ExternalReferences)
	return []interface{}{*bom.ExternalReferences}, nil
}

func SelectAuthorFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Selecting authors from component")

	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Authors != nil {
			for _, author := range *c.Authors {
				log.Debugf("Selecting author from component: %s@%s, Author: %s (%s)", c.Name, c.Version, author.Name, author.Email)
				selected = append(selected, AuthorEntry{Component: c, Author: &author})
			}
		}
	}
	if len(selected) == 0 {
		log.Debugf("No author entries found in selected components")
	}
	log.Debugf("Selected authors from component: %v", selected)
	return selected, nil
}

func SelectSupplierFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Selecting suppliers from component")

	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Supplier != nil && c.Supplier.Name != "" {
			log.Debugf("Selecting supplier from component: %s@%s, Supplier: %s", c.Name, c.Version, c.Supplier.Name)
			selected = append(selected, SupplierEntry{Component: c, Value: c.Supplier})
		}
	}
	if len(selected) == 0 {
		log.Debugf("No supplier entries found in selected components")
	}

	log.Debugf("Selected suppliers from component: %v", selected)
	return selected, nil
}

func SelectCopyrightFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Selecting copyright from component")

	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Copyright != "" {
			log.Debugf("Selecting copyright from component: %s@%s, Copyright: %s", c.Name, c.Version, c.Copyright)
			selected = append(selected, CopyrightEntry{Component: c, Value: c.Copyright})
		}
	}
	if len(selected) == 0 {
		log.Debugf("No copyright entries found in selected components")
	}
	log.Debugf("Selected copyrights from component: %v", selected)
	return selected, nil
}

func SelectCpeFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Selecting CPEs from component")

	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}

		if c.CPE != "" {
			log.Debugf("Selecting CPE from component: %s@%s, CPE: %s", c.Name, c.Version, c.CPE)
			selected = append(selected, CpeEntry{Component: c, Ref: c.CPE})
		}
	}
	if len(selected) == 0 {
		log.Debugf("No CPE entries found in selected components")
	}
	log.Debugf("Selected CPEs from component: %v", selected)
	return selected, nil
}

func SelectDescriptionFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Selecting description from component")

	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Description != "" {
			log.Debugf("Selecting description from component: %s@%s, Description: %s", c.Name, c.Version, c.Description)
			selected = append(selected, DescriptionEntry{Component: c, Value: c.Description})
		}
	}
	if len(selected) == 0 {
		log.Debugf("No description entries found in selected components")
	}
	log.Debugf("Selected descriptions from component: %v", selected)
	return selected, nil
}

func SelectHashFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Selecting hash from component")

	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Hashes != nil {
			for i := range *c.Hashes {
				hash := &(*c.Hashes)[i]
				log.Debugf("Selecting hash from component: %s@%s, Hash: %s (%s)", c.Name, c.Version, hash.Algorithm, hash.Value)
				selected = append(selected, HashEntry{Component: c, Hash: hash})
			}
		}
	}
	if len(selected) == 0 {
		log.Debugf("No hash entries found in selected components")
	}
	log.Debugf("Selected hashes from component: %v", selected)
	return selected, nil
}

func SelectLicenseFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Selecting license from component")

	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Licenses != nil {
			for _, license := range *c.Licenses {
				licenseValue := license.License.ID
				field := "ID"
				if licenseValue == "" {
					licenseValue = license.License.Name
					field = "Name"
				}
				if licenseValue == "" {
					licenseValue = license.Expression
					field = "Expression"
				}
				if licenseValue != "" {
					log.Debugf("Selecting license from component: %s@%s, License: %s (Field: %s)",
						c.Name, c.Version, licenseValue, field)
					selected = append(selected, LicenseEntry{Component: c, Value: licenseValue})
				}
			}
		}
	}
	if len(selected) == 0 {
		log.Debugf("No license entries found in selected components")
	}

	log.Debugf("Selected licenses from component: %v", selected)
	return selected, nil
}

func SelectPurlFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Selecting PURLs from component")

	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.PackageURL != "" {
			log.Debugf("Selecting PURL from component: %s@%s, PURL: %s", c.Name, c.Version, c.PackageURL)
			selected = append(selected, PurlEntry{Component: c, Value: c.PackageURL})
		}

	}
	if len(selected) == 0 {
		log.Debugf("No PURL entries found in selected components")
	}

	log.Debugf("Selected PURLs from component: %v", selected)
	return selected, nil
}

func SelectRepoFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Selecting repository from component")

	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.ExternalReferences != nil {
			for _, ref := range *c.ExternalReferences {
				if ref.Type == cydx.ERTypeVCS || ref.Type == cydx.ERTypeDistribution {
					log.Debugf("Selecting repository from component: %s@%s, Repository: %s", c.Name, c.Version, ref.URL)
					selected = append(selected, RepositoryEntry{Component: c, Ref: &ref})
				}
			}
		}
	}
	if len(selected) == 0 {
		log.Debugf("No repository entries found in selected components")
	}

	log.Debugf("Selected repositories from component: %v", selected)
	return selected, nil
}

func SelectTypeFromComponent(doc *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("Selecting type from component")

	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		c, ok := comp.(*cydx.Component)
		if !ok {
			continue
		}
		if c.Type != "" {
			log.Debugf("Selecting type from component: %s@%s, Type: %s", c.Name, c.Version, c.Type)
			selected = append(selected, TypeEntry{Component: c, Value: c.Type})
		}
	}
	if len(selected) == 0 {
		log.Debugf("No type entries found in selected components")
	}

	log.Debugf("Selected types from component: %v", selected)
	return selected, nil
}
