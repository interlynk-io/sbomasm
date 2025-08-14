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
	"fmt"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/enrich/clearlydef"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
)

func NewConfig() *Config {
	return &Config{}
}

// Enricher updates licenses in the SBOM
func Enricher(ctx context.Context, sbomDoc sbom.SBOMDocument, components []interface{}, responses map[interface{}]clearlydef.DefinitionResponse, force bool) sbom.SBOMDocument {
	log := logger.FromContext(ctx)
	log.Debug("enriching SBOM")

	for _, comp := range components {
		resp, ok := responses[comp]
		if !ok || resp.Licensed.Declared == "" {
			log.Debugf("skipping component: no response or license declared")
			continue
		}

		switch c := comp.(type) {

		case *spdx.Package:
			if force || c.PackageLicenseConcluded == "" || c.PackageLicenseConcluded == "NOASSERTION" {
				c.PackageLicenseConcluded = resp.Licensed.Declared
				log.Debugf("added license %s to SPDX package %s@%s", resp.Licensed.Declared, c.PackageName, c.PackageVersion)
			} else {
				log.Debugf("skipping SPDX package %s@%s: license already set (%s)", c.PackageName, c.PackageVersion, c.PackageLicenseConcluded)
			}

		case cydx.Component:

			var targetComp *cydx.Component
			doc, ok := sbomDoc.Document().(*cydx.BOM)
			if !ok {
				log.Warnf("invalid CycloneDX BOM for component %s@%s", c.Name, c.Version)
			}

			found := false
			if doc.Metadata != nil && doc.Metadata.Component != nil && doc.Metadata.Component.Name == c.Name && doc.Metadata.Component.Version == c.Version {
				// if doc.Metadata.Component.Name == c.Name && doc.Metadata.Component.Version == c.Version {
				targetComp = doc.Metadata.Component
				found = true
				// }
			} else if doc.Components != nil {
				for i := range *doc.Components {
					fmt.Println("found component:", (*doc.Components)[i].Name, (*doc.Components)[i].Version)
					if (*doc.Components)[i].Name == c.Name && (*doc.Components)[i].Version == c.Version {
						targetComp = &(*doc.Components)[i]
						found = true
						break
					}
				}
			}

			if !found {
				log.Warnf("component %s@%s not found in CycloneDX BOM", c.Name, c.Version)
				continue
			}

			// extract the component pointer in the document
			if force || (targetComp.Licenses == nil || len(*targetComp.Licenses) == 0 || (*targetComp.Licenses)[0].License.ID == "") {
				if targetComp.Licenses == nil {
					targetComp.Licenses = &cydx.Licenses{{License: &cydx.License{ID: resp.Licensed.Declared}}}
				} else {
					(*targetComp.Licenses)[0].License.ID = resp.Licensed.Declared
				}

				log.Debugf("added license %s to CycloneDX component %s@%s", resp.Licensed.Declared, targetComp.Name, targetComp.Version)
			} else {
				log.Debugf("skipping CycloneDX component %s@%s: license already set (%s)", targetComp.Name, targetComp.Version, (*targetComp.Licenses)[0].License.ID)
			}
		}
	}
	return sbomDoc
}
