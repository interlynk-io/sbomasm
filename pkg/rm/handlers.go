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

package rm

import (
	"context"
	"fmt"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/rm/cmps"
	cdxcomp "github.com/interlynk-io/sbomasm/pkg/rm/field/handler/cdx/comp"
	cdxmeta "github.com/interlynk-io/sbomasm/pkg/rm/field/handler/cdx/meta"
	spdxcomp "github.com/interlynk-io/sbomasm/pkg/rm/field/handler/spdx/comp"
	spdxmeta "github.com/interlynk-io/sbomasm/pkg/rm/field/handler/spdx/meta"

	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	spdxdoc "github.com/spdx/tools-golang/spdx"
)

var handlerRegistry = map[string]FieldHandler{}

func RegisterHandlers(bom *cydx.BOM, spdxDoc *spdxdoc.Document) {
	// CDX Document-level handlers
	handlerRegistry["cdx:document:author"] = &cdxmeta.CdxDocAuthorHandler{Bom: bom}
	handlerRegistry["cdx:document:supplier"] = &cdxmeta.CdxDocSupplierHandler{Bom: bom}
	handlerRegistry["cdx:document:tool"] = &cdxmeta.CdxDocToolHandler{Bom: bom}
	handlerRegistry["cdx:document:timestamp"] = &cdxmeta.CdxDocTimestampHandler{Bom: bom}
	handlerRegistry["cdx:document:repository"] = &cdxmeta.CdxDocRepoHandler{Bom: bom}
	handlerRegistry["cdx:document:license"] = &cdxmeta.CdxDocLicenseHandler{Bom: bom}
	handlerRegistry["cdx:document:lifecycle"] = &cdxmeta.CdxDocLifecycleHandler{Bom: bom}

	// CDX Component-level handlers
	handlerRegistry["cdx:component:author"] = &cdxcomp.CdxCompAuthorHandler{Bom: bom}
	handlerRegistry["cdx:component:supplier"] = &cdxcomp.CdxComponentSupplierHandler{Bom: bom}
	handlerRegistry["cdx:component:repository"] = &cdxcomp.CdxComponentRepoHandler{Bom: bom}
	handlerRegistry["cdx:component:license"] = &cdxcomp.CdxComponentLicenseHandler{Bom: bom}
	handlerRegistry["cdx:component:type"] = &cdxcomp.CdxComponentTypeHandler{Bom: bom}
	handlerRegistry["cdx:component:description"] = &cdxcomp.CdxComponentDescriptionHandler{Bom: bom}
	handlerRegistry["cdx:component:copyright"] = &cdxcomp.CdxComponentCopyrightHandler{Bom: bom}
	handlerRegistry["cdx:component:cpe"] = &cdxcomp.CdxComponentCpeHandler{Bom: bom}
	handlerRegistry["cdx:component:purl"] = &cdxcomp.CdxComponentPurlHandler{Bom: bom}
	handlerRegistry["cdx:component:hash"] = &cdxcomp.CdxComponentHashHandler{Bom: bom}

	// SPDX Document-level handlers
	handlerRegistry["spdx:document:author"] = &spdxmeta.SpdxDocAuthorHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:supplier"] = &spdxmeta.SpdxDocSupplierHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:tool"] = &spdxmeta.SpdxDocToolHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:timestamp"] = &spdxmeta.SpdxDocTimestampHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:repository"] = &spdxmeta.SpdxDocRepoHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:license"] = &spdxmeta.SpdxDocLicenseHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:lifecycle"] = &spdxmeta.SpdxDocLifecycleHandler{Doc: spdxDoc}

	// SPDX Component-level handlers
	handlerRegistry["spdx:component:author"] = &spdxcomp.SpdxComponentAuthorHandler{Doc: spdxDoc}
	handlerRegistry["spdx:component:supplier"] = &spdxcomp.SpdxComponentSupplierHandler{Doc: spdxDoc}
	handlerRegistry["spdx:component:repository"] = &spdxcomp.SpdxComponentRepoHandler{Doc: spdxDoc}
	handlerRegistry["spdx:component:license"] = &spdxcomp.SpdxComponentLicenseHandler{Doc: spdxDoc}
	handlerRegistry["spdx:component:type"] = &spdxcomp.SpdxComponentTypeHandler{Doc: spdxDoc}
	handlerRegistry["spdx:component:description"] = &spdxcomp.SpdxComponentDescriptionHandler{Doc: spdxDoc}
	handlerRegistry["spdx:component:copyright"] = &spdxcomp.SpdxComponentCopyrightHandler{Doc: spdxDoc}
	handlerRegistry["spdx:component:cpe"] = &spdxcomp.SpdxComponentCpeHandler{Doc: spdxDoc}
	handlerRegistry["spdx:component:purl"] = &spdxcomp.SpdxComponentPurlHandler{Doc: spdxDoc}
	handlerRegistry["spdx:component:hash"] = &spdxcomp.SpdxComponentHashHandler{Doc: spdxDoc}

	// Later: Component-scope or Dependency-scope handlers
}

func (c *ComponentsOperationEngine) selectComponents(ctx context.Context, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Initialized component selection process")

	selectedComponents, err := cmps.SelectComponents(ctx, c.doc, params)
	if err != nil {
		return nil, err
	}

	var listOfSelectedComponents []string
	for _, comp := range selectedComponents {
		switch c := comp.(type) {
		case spdxdoc.Package:
			listOfSelectedComponents = append(listOfSelectedComponents, fmt.Sprintf("%s@%s", c.PackageName, c.PackageVersion))
		case cydx.Component:
			listOfSelectedComponents = append(listOfSelectedComponents, fmt.Sprintf("%s@%s", c.Name, c.Version))
		default:
		}
	}

	strings.Split(strings.Join(listOfSelectedComponents, ", "), ", ")

	log.Debugf("Selected components: %s", strings.Join(listOfSelectedComponents, ", "))

	return selectedComponents, nil
}

func (c *ComponentsOperationEngine) findDependenciesForComponents(ctx context.Context, components []interface{}) ([]interface{}, error) {
	return cmps.FindAllDependenciesForComponents(ctx, c.doc, components), nil
}

func (c *ComponentsOperationEngine) removeComponents(ctx context.Context, components []interface{}) error {
	return cmps.RemoveComponents(ctx, c.doc, components)
}

func (c *ComponentsOperationEngine) removeDependencies(ctx context.Context, dependencies []interface{}) error {
	return cmps.RemoveDependencies(ctx, c.doc, dependencies)
}
