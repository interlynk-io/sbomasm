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
	NO_PURL_FOUND              = "no PURL found"
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
func Enricher(ctx context.Context, sbomDoc sbom.SBOMDocument, components []interface{}, responses map[interface{}]clearlydef.DefinitionResponse, force bool, licenseExpJoinBy string) (sbom.SBOMDocument, int, int, map[string]string, error) {
	log := logger.FromContext(ctx)
	fmt.Printf("\nEnriching SBOM...\n")

	// Initialize progress bar
	totalComponents := len(components)
	bar := pb.StartNew(totalComponents)

	var enrichedCount, skippedCount int
	skippedReasons := make(map[string]string)

	for _, component := range components {
		purl := getPurl(component)
		if purl == "" {
			log.Debugf("component has no PURL")
			skippedReasons[purl] = NO_PURL_FOUND
			skippedCount++
			continue
		}

		compWithCorrespondingDefResponse, ok := responses[component]
		if !ok {
			log.Debugf("component has no Response")
			skippedReasons[purl] = NO_LICENSE_DATA_FOUND
			skippedCount++
			continue
		}

		if compWithCorrespondingDefResponse.Licensed.Declared == "NOASSERTION" || compWithCorrespondingDefResponse.Licensed.Declared == "OTHER" {
			log.Debugf("component has invalid license")
			skippedReasons[purl] = NON_STANDARD_LICENSE_FOUND
			skippedCount++
			continue
		}

		switch c := component.(type) {

		case *spdx.Package:
			if force || c.PackageLicenseDeclared == "" || c.PackageLicenseDeclared == "NOASSERTION" || c.PackageLicenseDeclared == "OTHER" {
				c.PackageLicenseDeclared = compWithCorrespondingDefResponse.Licensed.Declared
				enrichedCount++
				bar.Increment()
				log.Debugf("Enriched license %s to %s@%s\n", compWithCorrespondingDefResponse.Licensed.Declared, c.PackageName, c.PackageVersion)
			} else {
				skippedReasons[purl] = LICENSE_ALREADY_EXISTS
				skippedCount++
				log.Debugf("Skipping %s@%s: license already exists (%s)\n", c.PackageName, c.PackageVersion, c.PackageLicenseConcluded)
			}

		case cydx.Component:

			var targetComp *cydx.Component
			doc, ok := sbomDoc.Document().(*cydx.BOM)
			if !ok {
				log.Warnf("invalid CycloneDX BOM for component %s@%s", c.Name, c.Version)
			}

			specVersion := doc.SpecVersion
			isCDX_1_6_Version := specVersion == cydx.SpecVersion1_6

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

				log.Debugf("Declared license: %s", declaredLicense)

				if declaredLicense != "" && !addedLicenses[declaredLicense] {

					if isSPDXLicenseID(declaredLicense) {
						log.Debugf("SPDX ID detected: %s", declaredLicense)
						if isCDX_1_6_Version {
							*targetComp.Licenses = append(*targetComp.Licenses, cydx.LicenseChoice{License: &cydx.License{ID: declaredLicense, Acknowledgement: cydx.LicenseAcknowledgementDeclared}})
						} else {
							*targetComp.Licenses = append(*targetComp.Licenses, cydx.LicenseChoice{License: &cydx.License{ID: declaredLicense}})
						}

					} else if isLicenseExpression(declaredLicense) {
						log.Debugf("License expression detected: %s", declaredLicense)
						*targetComp.Licenses = append(*targetComp.Licenses, cydx.LicenseChoice{Expression: declaredLicense})

					} else {
						log.Debugf("Custom license detected: %s", declaredLicense)
						if isCDX_1_6_Version {
							*targetComp.Licenses = append(*targetComp.Licenses, cydx.LicenseChoice{License: &cydx.License{Name: declaredLicense, Acknowledgement: cydx.LicenseAcknowledgementDeclared}})
						} else {
							*targetComp.Licenses = append(*targetComp.Licenses, cydx.LicenseChoice{License: &cydx.License{Name: declaredLicense}})
						}
					}
					addedLicenses[declaredLicense] = true

					enrichedCount++
					bar.Increment()
					log.Debugf("Added declared license %s to %s@%s\n", compWithCorrespondingDefResponse.Licensed.Declared, c.Name, c.Version)
				}
			} else {
				log.Debugf("Skipping %s@%s, license already exists (%s)\n", c.Name, c.Version, compWithCorrespondingDefResponse.Licensed.Declared)
				skippedReasons[purl] = LICENSE_ALREADY_EXISTS
				skippedCount++
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
	case *spdx.Package:
		for _, ref := range c.PackageExternalReferences {
			if ref.RefType == "purl" {
				purls = append(purls, ref.Locator)
			}
		}

	case cydx.Component:
		if c.PackageURL != "" {
			purls = append(purls, c.PackageURL)
		}
	}

	if len(purls) == 0 || purls == nil {
		return ""
	}

	return purls[0]
}
