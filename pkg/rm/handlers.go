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

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/cmps"
	cdxmeta "github.com/interlynk-io/sbomasm/pkg/rm/field/handler/cdx/meta"
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

	// SPDX Document-level handlers
	handlerRegistry["spdx:document:author"] = &spdxmeta.SpdxDocAuthorHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:supplier"] = &spdxmeta.SpdxDocSupplierHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:tool"] = &spdxmeta.SpdxDocToolHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:timestamp"] = &spdxmeta.SpdxDocTimestampHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:repository"] = &spdxmeta.SpdxDocRepoHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:license"] = &spdxmeta.SpdxDocLicenseHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:lifecycle"] = &spdxmeta.SpdxDocLifecycleHandler{Doc: spdxDoc}

	// Later: Component-scope or Dependency-scope handlers
}

func (c *ComponentsOperationEngine) selectComponents(ctx context.Context, params *types.RmParams) ([]interface{}, error) {
	// TODO: Implement component selection logic
	selectedComponents, err := cmps.SelectComponents(ctx, c.doc, params)
	if err != nil {
		return nil, err
	}

	fmt.Println("Selected components:", selectedComponents)

	return selectedComponents, nil
}

func (c *ComponentsOperationEngine) findDependenciesForComponents(components []interface{}) ([]interface{}, error) {
	return cmps.FindAllDependenciesForComponents(c.doc, components), nil
}

func (c *ComponentsOperationEngine) removeComponents(components []interface{}) error {
	// TODO: Implement component removal logic
	return cmps.RemoveComponents(c.doc, components)
}

func (c *ComponentsOperationEngine) removeDependencies(dependencies []interface{}) error {
	// TODO: Implement dependency removal logic
	return cmps.RemoveDependencies(c.doc, dependencies)
}
