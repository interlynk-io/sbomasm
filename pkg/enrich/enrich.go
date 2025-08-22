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
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cheggaaa/pb/v3"
	"github.com/interlynk-io/sbomasm/pkg/enrich/clearlydef"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/licenses"
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

// isSPDXLicenseID checks if the license is a valid SPDX ID
func isSPDXLicenseID(license string) bool {
	lic := licenses.LookupExpression(license, nil)
	if len(lic) > 1 || lic == nil || len(lic) == 0 {
		return false
	}

	return lic[0].Spdx()
}

// isLicenseExpression checks if the license contains operators indicating an expression
func isLicenseExpression(license string) bool {
	return strings.Contains(license, "+") ||
		strings.Contains(license, "WITH") ||
		strings.Contains(license, "AND") ||
		strings.Contains(license, "OR")
}

// Enricher updates licenses in the SBOM
func Enricher(ctx context.Context, sbomDoc sbom.SBOMDocument, components []interface{}, responses map[interface{}]clearlydef.DefinitionResponse, force bool) (sbom.SBOMDocument, int, int, map[string]string, error) {
	log := logger.FromContext(ctx)
	fmt.Printf("\nEnriching SBOM...\n")

	// Initialize progress bar
	totalComponents := len(components)
	bar := pb.StartNew(totalComponents)

	var enrichedCount, skippedCount int
	skippedReasons := make(map[string]string)

	for _, component := range components {
		purl := getPurl(component)

		compWithCorrespondingDefResponse, ok := responses[component]
		if !ok {
			log.Debugf("No license data for component with PURL: %s", purl)
			skippedReasons[purl] = NO_LICENSE_DATA_FOUND
			skippedCount++
			continue
		}

		switch c := component.(type) {

		case *spdx.Package:
			if force || c.PackageLicenseDeclared == "" || c.PackageLicenseDeclared == "NOASSERTION" {
				c.PackageLicenseDeclared = compWithCorrespondingDefResponse.Licensed.Declared
				enrichedCount++
				bar.Increment()

				log.Debugf("Enriched license %s to %s@%s\n", compWithCorrespondingDefResponse.Licensed.Declared, c.PackageName, c.PackageVersion)
			} else {
				skippedReasons[purl] = LICENSE_ALREADY_EXISTS
				log.Debugf("Skipping %s@%s: license already exists (%s)\n", c.PackageName, c.PackageVersion, c.PackageLicenseConcluded)
			}

		case cydx.Component:

			var targetComp *cydx.Component
			doc, ok := sbomDoc.Document().(*cydx.BOM)
			if !ok {
				log.Warnf("invalid CycloneDX BOM for component %s@%s", c.Name, c.Version)
			}

			found := false
			if doc.Metadata != nil && doc.Metadata.Component != nil && doc.Metadata.Component.Name == c.Name && doc.Metadata.Component.Version == c.Version {
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
				bar.Increment()
				continue
			}

			if force || (targetComp.Licenses == nil || len(*targetComp.Licenses) == 0) {
				if targetComp.Licenses == nil {
					targetComp.Licenses = &cydx.Licenses{}
				}

				addedLicenses := make(map[string]bool)
				declaredLicense := compWithCorrespondingDefResponse.Licensed.Declared
				discoverdLicense := compWithCorrespondingDefResponse.Licensed.Facets.Core.Discovered.Expressions
				log.Debugf("Declared license: %s", declaredLicense)
				log.Debugf("Discovered licenses: %v", discoverdLicense)

				if declaredLicense != "" && !addedLicenses[declaredLicense] {

					if isSPDXLicenseID(declaredLicense) {
						log.Debugf("SPDX ID detected: %s", declaredLicense)
						*targetComp.Licenses = append(*targetComp.Licenses, cydx.LicenseChoice{License: &cydx.License{ID: declaredLicense}})

					} else if isLicenseExpression(declaredLicense) {
						log.Debugf("License expression detected: %s", declaredLicense)
						*targetComp.Licenses = append(*targetComp.Licenses, cydx.LicenseChoice{Expression: declaredLicense})

					} else {
						log.Debugf("Custom license detected: %s", declaredLicense)
						*targetComp.Licenses = append(*targetComp.Licenses, cydx.LicenseChoice{License: &cydx.License{Name: declaredLicense}})
					}
					addedLicenses[declaredLicense] = true

					enrichedCount++
					bar.Increment()
					log.Debugf("Added declared license %s to %s@%s\n", compWithCorrespondingDefResponse.Licensed.Declared, c.Name, c.Version)
				}

				// Combine discovered expressions into a single expression with AND
				if len(discoverdLicense) > 0 {
					combinedExpression := strings.Join(discoverdLicense, " AND ")

					if !addedLicenses[combinedExpression] {
						if targetComp.Evidence == nil {
							targetComp.Evidence = &cydx.Evidence{
								Licenses: &cydx.Licenses{},
							}
						}
						*targetComp.Evidence.Licenses = append(*targetComp.Evidence.Licenses, cydx.LicenseChoice{Expression: combinedExpression})
						addedLicenses[combinedExpression] = true
						log.Debugf("Added discovered expression %s for %s@%s under Evidence.Licenses section\n", combinedExpression, c.Name, c.Version)
					}
				}

			} else {
				log.Debugf("Skipping %s@%s, license already exists (%s)\n", c.Name, c.Version, compWithCorrespondingDefResponse.Licensed.Declared)
				skippedReasons[purl] = LICENSE_ALREADY_EXISTS
			}
		}
	}

	// finish bar
	bar.Finish()
	// fmt.Printf("Enrichment complete: %d enriched, %d skipped\n", enrichedCount, skippedCount)

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
