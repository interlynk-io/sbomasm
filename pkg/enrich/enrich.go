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

package enrich

import (
	"context"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/enrich/clearlydef"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
)

// Enricher updates licenses in the SBOM
func Enricher(ctx context.Context, sbomDoc sbom.SBOMDocument, components []interface{}, responses map[interface{}]clearlydef.DefinitionResponse, force bool) sbom.SBOMDocument {
	for _, comp := range components {
		resp, ok := responses[comp]
		if !ok || resp.Licensed.Declared == "" {
			continue
		}
		switch c := comp.(type) {
		case *spdx.Package:
			if force || c.PackageLicenseConcluded == "" || c.PackageLicenseConcluded == "NOASSERTION" {
				c.PackageLicenseConcluded = resp.Licensed.Declared
			}
		case cydx.Component:
			if force || (c.Licenses == nil || len(*c.Licenses) == 0 || (*c.Licenses)[0].License.ID == "") {
				if c.Licenses == nil {
					c.Licenses = &cydx.Licenses{{License: &cydx.License{ID: resp.Licensed.Declared}}}
				} else {
					(*c.Licenses)[0].License.ID = resp.Licensed.Declared
				}
			}
		}
	}
	return sbomDoc
}

// func findComponentIndex(components []sbom.GetComponent, comp sbom.GetComponent) int {
// 	for i, c := range components {
// 		if c.GetID() == comp.GetID() {
// 			return i
// 		}
// 	}
// 	return -1
// }
