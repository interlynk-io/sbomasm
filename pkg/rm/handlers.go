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
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/handler/cdx"
	"github.com/spdx/tools-golang/spdx/common"
)

var handlerRegistry = map[string]FieldHandler{}

func RegisterHandlers(bom *cydx.BOM, spdxDoc common.AnyDocument) {
	// CDX Document-level handlers
	handlerRegistry["cdx:document:author"] = &cdx.CdxDocAuthorHandler{Bom: bom}
	handlerRegistry["cdx:document:supplier"] = &cdx.CdxDocSupplierHandler{Bom: bom}
	handlerRegistry["cdx:document:tool"] = &cdx.CdxDocToolHandler{Bom: bom}
	handlerRegistry["cdx:document:timestamp"] = &cdx.CdxDocTimestampHandler{Bom: bom}
	handlerRegistry["cdx:document:repository"] = &cdx.CdxDocRepoHandler{Bom: bom}
	handlerRegistry["cdx:document:license"] = &cdx.CdxDocLicenseHandler{Bom: bom}
	handlerRegistry["cdx:document:lifecycle"] = &cdx.CdxDocLifecycleHandler{Bom: bom}

	// // SPDX Document-level handlers
	// handlerRegistry["spdx:document:author"] = &spdx.SpdxDocAuthorHandler{spdxDoc}
	// handlerRegistry["spdx:document:creator"] = &spdx.SpdxDocCreatorHandler{spdxDoc}
	// handlerRegistry["spdx:document:license"] = &spdx.SpdxDocLicenseHandler{spdxDoc}

	// Later: Component-scope or Dependency-scope handlers
}
