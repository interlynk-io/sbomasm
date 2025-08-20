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

const (
	NO_LICENSE_DATA_FOUND      = "no license data found"
	NON_STANDARD_LICENSE_FOUND = "non-standard license found"
	LICENSE_ALREADY_EXISTS     = "license already exists"
)

func NewConfig() *Config {
	return &Config{}
}

// Enricher updates licenses in the SBOM
func Enricher(ctx context.Context, sbomDoc sbom.SBOMDocument, components []interface{}, responses map[interface{}]clearlydef.DefinitionResponse, force bool) (sbom.SBOMDocument, int, int, map[string]string, error) {
	log := logger.FromContext(ctx)
	log.Debug("enriching SBOM")

	var enrichedCount, skippedCount int
	skippedReasons := make(map[string]string)

	for _, comp := range components {
		resp, ok := responses[comp]
		purl := getPurl(comp)

		if !ok || resp.Licensed.Declared == "" {
			log.Debugf("No license data for component with PURL: %s; harvest queued", purl)
			skippedReasons[purl] = NO_LICENSE_DATA_FOUND

			skippedCount++
			continue
		}

		switch c := comp.(type) {

		case *spdx.Package:
			if force || c.PackageLicenseConcluded == "" || c.PackageLicenseConcluded == "NOASSERTION" {
				c.PackageLicenseConcluded = resp.Licensed.Declared
				enrichedCount++

				fmt.Printf("Enriched license %s to %s@%s\n", resp.Licensed.Declared, c.PackageName, c.PackageVersion)
			} else {
				skippedReasons[purl] = LICENSE_ALREADY_EXISTS
				fmt.Printf("Skipping %s@%s: license already exists (%s)\n", c.PackageName, c.PackageVersion, c.PackageLicenseConcluded)
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

			} else if doc.Components != nil {
				for i := range *doc.Components {
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
			if force || (targetComp.Licenses == nil || len(*targetComp.Licenses) == 0) {

				if targetComp.Licenses == nil {
					targetComp.Licenses = &cydx.Licenses{{License: &cydx.License{ID: resp.Licensed.Declared}}}
				} else {
					for _, lic := range *targetComp.Licenses {
						if lic.License != nil {
							(*targetComp.Licenses)[0].License.ID = resp.Licensed.Declared
						} else if lic.Expression != "" {
							(*targetComp.Licenses)[0].Expression = resp.Licensed.Declared
						}
					}
				}

				enrichedCount++

				fmt.Printf("Added license %s to %s@%s \n", resp.Licensed.Declared, c.Name, c.Version)
			} else {
				fmt.Printf("Skipping %s@%s, license already exists (%s) \n", c.Name, c.Version, resp.Licensed.Declared)
				skippedReasons[purl] = LICENSE_ALREADY_EXISTS
			}
		}
	}

	return sbomDoc, enrichedCount, skippedCount, skippedReasons, nil
}

// getPurl of a component
func getPurl(comp interface{}) string {
	var purls []string

	switch c := comp.(type) {
	case *cydx.Component:
		if c.PackageURL != "" {
			purls = append(purls, c.PackageURL)
		}

	case *spdx.Package:
		for _, ref := range c.PackageExternalReferences {
			if ref.RefType == "purl" {
				purls = append(purls, ref.Locator)
			}
		}
	}
	if len(purls) > 0 {
		return purls[0]
	}

	return ""
}
