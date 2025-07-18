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
	"github.com/interlynk-io/sbomasm/pkg/rm/field/handler/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/handler/spdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	spdxdoc "github.com/spdx/tools-golang/spdx"
)

var handlerRegistry = map[string]FieldHandler{}

func RegisterHandlers(bom *cydx.BOM, spdxDoc *spdxdoc.Document) {
	// CDX Document-level handlers
	handlerRegistry["cdx:document:author"] = &cdx.CdxDocAuthorHandler{Bom: bom}
	handlerRegistry["cdx:document:supplier"] = &cdx.CdxDocSupplierHandler{Bom: bom}
	handlerRegistry["cdx:document:tool"] = &cdx.CdxDocToolHandler{Bom: bom}
	handlerRegistry["cdx:document:timestamp"] = &cdx.CdxDocTimestampHandler{Bom: bom}
	handlerRegistry["cdx:document:repository"] = &cdx.CdxDocRepoHandler{Bom: bom}
	handlerRegistry["cdx:document:license"] = &cdx.CdxDocLicenseHandler{Bom: bom}
	handlerRegistry["cdx:document:lifecycle"] = &cdx.CdxDocLifecycleHandler{Bom: bom}

	// SPDX Document-level handlers
	handlerRegistry["spdx:document:author"] = &spdx.SpdxDocAuthorHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:supplier"] = &spdx.SpdxDocSupplierHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:tool"] = &spdx.SpdxDocToolHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:timestamp"] = &spdx.SpdxDocTimestampHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:repository"] = &spdx.SpdxDocRepoHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:license"] = &spdx.SpdxDocLicenseHandler{Doc: spdxDoc}
	handlerRegistry["spdx:document:lifecycle"] = &spdx.SpdxDocLifecycleHandler{Doc: spdxDoc}

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

func (c *ComponentsOperationEngine) findDependenciesForComponents(components []interface{}) ([]string, error) {
	// TODO: Implement dependency finding logic
	return []string{}, nil
}

func (c *ComponentsOperationEngine) removeComponents(components []interface{}) error {
	// TODO: Implement component removal logic
	return nil
}

func (c *ComponentsOperationEngine) removeDependencies(dependencies []string) error {
	// TODO: Implement dependency removal logic
	return nil
}
